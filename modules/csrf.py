#!/usr/bin/env python3
import sys
sys.dont_write_bytecode = True

from utils.style import Colors
from utils.utils import requests, re


CSRF_BODY_TOKENS = [
    "csrf", "csrf_token", "csrftoken", "_csrf", "authenticity_token",
    "_token", "xsrf", "_xsrf", "csrfmiddlewaretoken",
    "__RequestVerificationToken", "_csrfToken", "security_token",
]

CSRF_REQUEST_HEADERS = [
    "X-CSRF-Token", "X-XSRF-TOKEN", "X-CSRFToken",
]


def _has_csrf_protection(headers, body):
    """Return (csrf_header_key or None, csrf_body_token or None)."""
    csrf_header = None
    for k in headers:
        if k.lower() in [h.lower() for h in CSRF_REQUEST_HEADERS]:
            csrf_header = k
            break

    csrf_body = None
    if body:
        for t in CSRF_BODY_TOKENS:
            if t.lower() in body.lower():
                csrf_body = t
                break

    return csrf_header, csrf_body


def _strip_csrf_from_body(body, csrf_body_token):
    if not body or not csrf_body_token:
        return body
    return re.sub(
        rf'[&]?{re.escape(csrf_body_token)}=[^&]*', '', body, flags=re.IGNORECASE
    ).lstrip("&")


def _probe_cors(method, uri, headers, body, origin, proxies):
    """Send the request with a given Origin and return (ACAO, ACAC-bool)."""
    h = dict(headers)
    h["Origin"] = origin
    resp = requests.request(
        method=method, url=uri, headers=h,
        data=body or None, verify=False, allow_redirects=False,
        timeout=10, proxies=proxies,
    )
    acao = resp.headers.get("Access-Control-Allow-Origin")
    acac = resp.headers.get("Access-Control-Allow-Credentials", "").strip().lower() == "true"
    return acao, acac


def _cors_analysis(method, uri, headers, body, proxies):
    """
    Detect dangerous CORS policies by reflecting a unique attacker Origin and a
    null Origin, then reading Access-Control-Allow-Origin / -Allow-Credentials.

    The high-impact bug is "reflect arbitrary Origin + Allow-Credentials: true":
    any website can then read this endpoint's response with the victim's cookies.
    """
    print(f"{Colors.CYAN} └─ CORS policy check{Colors.RESET}")

    test_origin = "https://gyp-cors-probe.example"
    try:
        acao, acac = _probe_cors(method, uri, headers, body, test_origin, proxies)
    except requests.RequestException as e:
        print(f"  {Colors.RED}[!] {e}{Colors.RESET}")
        return

    if acao is None:
        print(f"{Colors.GREEN}   └── [OK] No Access-Control-Allow-Origin returned for a foreign origin{Colors.RESET}")
        return

    # Arbitrary-origin reflection. NOTE on severity: reflect+credentials is only
    # *impactful* when the response carries victim-specific / session data that an
    # attacker couldn't obtain themselves. A public endpoint that returns the same
    # thing to everyone (like a reset-request) leaks nothing → most BB programs
    # rate it Informational. So we report the misconfig as a low-severity lead and
    # tell the user what to verify to escalate it, instead of over-claiming HIGH.
    if acao == test_origin and acac:
        print(f"{Colors.YELLOW}   └── [INFO] CORS misconfig: reflects arbitrary Origin + Allow-Credentials:true{Colors.RESET}")
        print(f"{Colors.YELLOW}       ACAO: {acao} | ACAC: true{Colors.RESET}")
        print(f"{Colors.CYAN}       impact conditional — only exploitable if THIS or a sibling /api endpoint{Colors.RESET}")
        print(f"{Colors.CYAN}       returns victim/session data. Replay on an authenticated endpoint to confirm.{Colors.RESET}")
    elif acao == test_origin:
        print(f"{Colors.CYAN}   └── [INFO] CORS reflects arbitrary Origin (no credentials) — low impact{Colors.RESET}")
    elif acao == "*" and acac:
        print(f"{Colors.YELLOW}   └── [INFO] ACAO:* with Allow-Credentials:true (browsers block this combo, but misconfigured){Colors.RESET}")
    elif acao == "*":
        print(f"{Colors.CYAN}   └── [INFO] ACAO:* (wildcard) — public data only, no credentialed read{Colors.RESET}")
    else:
        print(f"{Colors.GREEN}   └── [OK] ACAO not reflected ({acao}){Colors.RESET}")

    # null-origin (sandboxed iframe / data: URI). Same conditional-impact caveat.
    try:
        nacao, nacac = _probe_cors(method, uri, headers, body, "null", proxies)
        if nacao == "null":
            print(f"{Colors.CYAN}   └── [INFO] CORS also allows Origin: null{' + credentials' if nacac else ''} "
                  f"(sandboxed-iframe reachable){Colors.RESET}")
    except requests.RequestException:
        pass


def csrf(url, parsed_req, baseline, interact, email, proxy=None):
    """
    CSRF testing on password reset endpoint.

    Phase 1: Detect whether a CSRF token exists in the request.
    Phase 2: Simulate a cross-origin request (Origin: evil.com, Referer: evil.com)
             with CSRF tokens stripped. Reported as INFO only: CSRF on a reset-
             *request* endpoint has negligible impact (the victim can trigger the
             same email themselves; no state change), so most BB programs reject it.
    """
    print(f"{Colors.CYAN} ├ CSRF analysis{Colors.RESET}")

    original_host = parsed_req["host"]
    method = parsed_req["method"]
    path = parsed_req["path"]
    body = parsed_req["body"]
    headers = dict(parsed_req["headers"])
    scheme = "https" if "https" in url else "http"

    uri = f"{scheme}://{original_host}{path}"
    proxies = {"http": proxy, "https": proxy} if proxy else None

    # --- Phase 1: Detection ---
    print(f"{Colors.CYAN} └─ CSRF protection detection{Colors.RESET}")

    csrf_header, csrf_body_token = _has_csrf_protection(headers, body)

    if csrf_header:
        print(f"{Colors.GREEN}   └── [INFO] CSRF header present: {csrf_header}{Colors.RESET}")
    if csrf_body_token:
        print(f"{Colors.GREEN}   └── [INFO] CSRF body token present: {csrf_body_token}{Colors.RESET}")
    if not csrf_header and not csrf_body_token:
        print(f"{Colors.CYAN}   └── [INFO] No CSRF token found in request{Colors.RESET}")

    # --- CORS policy (independent of cookies: usually a gateway-wide config) ---
    _cors_analysis(method, uri, headers, body, proxies)

    # CSRF only makes sense when the browser auto-attaches ambient credentials,
    # i.e. a session cookie. A public / bearer-token endpoint (no Cookie) is not
    # CSRF-exploitable, so confirming "cross-origin accepted" there is a false
    # positive — skip the confirmation phases.
    has_cookie = any(k.lower() == "cookie" for k in headers)
    has_bearer = any(k.lower() == "authorization" for k in headers)
    if not has_cookie:
        reason = "bearer/Authorization auth" if has_bearer else "no session cookie → public/unauthenticated endpoint"
        print(f"{Colors.CYAN}   └── [i] {reason} — CSRF not applicable, cross-origin test skipped{Colors.RESET}")
        return

    # --- Phase 2: Cross-origin simulation ---
    print(f"{Colors.CYAN} └─ Cross-origin request simulation{Colors.RESET}")

    attack_headers = {k: v for k, v in headers.items()
                     if k.lower() not in [h.lower() for h in CSRF_REQUEST_HEADERS]}
    attack_headers["Origin"] = "https://evil.com"
    attack_headers["Referer"] = "https://evil.com/csrf-poc"

    attack_body = _strip_csrf_from_body(body, csrf_body_token)

    try:
        resp = requests.request(
            method=method, url=uri, headers=attack_headers,
            data=attack_body or None, verify=False, allow_redirects=False,
            timeout=10, proxies=proxies,
        )

        bl = baseline["body_length"]
        rl = len(resp.text)
        ratio = abs(rl - bl) / bl if bl > 0 else 0.0

        if resp.status_code == baseline["status"] and ratio < 0.15:
            # A reset-*request* endpoint only mails a link the victim can already
            # request themselves → no state change, negligible impact. Informational,
            # most BB programs won't accept it. No PoC emitted.
            print(f"{Colors.CYAN}   └── [INFO] Cross-origin request accepted (Origin: evil.com) → {resp.status_code} ≈ baseline{Colors.RESET}")
            print(f"{Colors.CYAN}       No origin validation, but low impact on a reset-request endpoint (self-triggerable, no state change){Colors.RESET}")
        elif resp.status_code in [403, 400]:
            print(f"{Colors.GREEN}   └── [OK] Cross-origin rejected: {resp.status_code}{Colors.RESET}")
        else:
            print(f"{Colors.CYAN}   └── [INFO] [{baseline['status']} > {resp.status_code}] Δlen={abs(rl-bl)}b{Colors.RESET}")

    except requests.RequestException as e:
        print(f"  {Colors.RED}[!] {e}{Colors.RESET}")

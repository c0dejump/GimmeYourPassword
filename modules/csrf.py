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

# Content-Type values that do NOT trigger a CORS preflight (a "simple request").
CORS_SIMPLE_CONTENT_TYPES = (
    "application/x-www-form-urlencoded",
    "multipart/form-data",
    "text/plain",
)

# Request headers a browser sets by itself or that are CORS-safelisted: a cross-site
# page can rely on these WITHOUT a preflight. Anything else (Authorization, X-*, any
# custom header) is "author-set" and forces a preflight — which the attacker's origin
# must be explicitly allowed to pass. `Sec-*` are browser-forbidden headers, so they
# never come from attacker JS either.
BROWSER_MANAGED_HEADERS = {
    "host", "user-agent", "accept", "accept-language", "accept-encoding",
    "content-language", "content-length", "connection", "referer", "origin",
    "cookie", "dnt", "priority", "cache-control", "pragma",
    "upgrade-insecure-requests", "te", "range",
}


def _forces_preflight(headers):
    """
    Return (bool, reason): whether a browser sending this request cross-origin would
    first have to pass a CORS preflight (OPTIONS). That happens when the Content-Type
    isn't a simple one, or any author-set (non-safelisted) header is present.

    Why it matters for CSRF: if a preflight is forced and the server doesn't allow the
    attacker's Origin, the real cross-site request is NEVER sent by the browser — so a
    same-server 200 (which we get from Python, bypassing the browser) is not evidence
    of a cross-site-forgeable request.
    """
    for k, v in headers.items():
        kl = k.lower()
        if kl == "content-type":
            if not any(ct in v.lower() for ct in CORS_SIMPLE_CONTENT_TYPES):
                return True, f"Content-Type: {v.split(';')[0].strip()} (non-simple)"
        elif kl.startswith("sec-"):
            continue
        elif kl not in BROWSER_MANAGED_HEADERS:
            return True, f"author-set header '{k}'"
    return False, None


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
        return False

    if acao is None:
        print(f"{Colors.GREEN}   └── [OK] No Access-Control-Allow-Origin returned for a foreign origin{Colors.RESET}")
        return False

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

    # Whether the attacker Origin is explicitly allowed — needed to know if a
    # preflight-forcing request could actually be delivered cross-site.
    return acao == test_origin


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
    cors_reflects = _cors_analysis(method, uri, headers, body, proxies)

    # CSRF only makes sense when the BROWSER auto-attaches the credential the endpoint
    # relies on. Two things break that, and each makes "cross-origin accepted" (which
    # we observe server-to-server, bypassing the browser) a false positive:
    #
    #  1. Authorization header — never ambient. The attacker's page cannot set it on a
    #     cross-site request without a preflight the server won't pass, so THIS request
    #     is not browser-forgeable even if a cookie is also present.
    #  2. A request that forces a CORS preflight (non-simple Content-Type or any
    #     author-set header) while the server does NOT allow the attacker Origin: the
    #     browser blocks it at the preflight and never sends the real request.
    has_cookie = any(k.lower() == "cookie" for k in headers)
    has_bearer = any(k.lower() == "authorization" for k in headers)

    if has_bearer:
        print(f"{Colors.GREEN}   └── [OK] request authenticated via Authorization header (not ambient) — "
              f"a cross-site page cannot replay it; CSRF N/A, cross-origin test skipped{Colors.RESET}")
        return
    if not has_cookie:
        print(f"{Colors.CYAN}   └── [i] no session cookie → public/unauthenticated endpoint — "
              f"CSRF not applicable, cross-origin test skipped{Colors.RESET}")
        return

    preflight, why = _forces_preflight(headers)
    if preflight and not cors_reflects:
        print(f"{Colors.GREEN}   └── [OK] request forces a CORS preflight ({why}) the server won't pass "
              f"for a foreign origin → not browser-forgeable cross-site; CSRF N/A{Colors.RESET}")
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

        # If the baseline is itself an error/throttle (4xx/5xx), "matches baseline"
        # means BOTH were rejected — not that the cross-origin request was accepted.
        if baseline["status"] and baseline["status"] >= 400:
            print(f"{Colors.CYAN}   └── [i] baseline is {baseline['status']} (endpoint rejecting/throttling) — "
                  f"cross-origin result inconclusive; re-run against a clean 2xx baseline{Colors.RESET}")
        elif resp.status_code == baseline["status"] and ratio < 0.15:
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

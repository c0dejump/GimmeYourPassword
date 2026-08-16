#!/usr/bin/env python3
import sys
sys.dont_write_bytecode = True

from utils.style import Colors
from utils.utils import (
    requests,
    re,
    json,
    urlparse,
    detect_anti_automation,
)
import shlex
import urllib.parse
from utils import live


def _body_to_query(body, headers):
    """
    Convert a request body into a query string so GET-based tests are meaningful.
    A JSON body appended raw to the URL (`?{"email":"..."}`) is never parsed by the
    server, so for JSON we flatten the top-level scalar fields into real params.
    Returns "" when no sensible query can be built (caller then sends a plain GET).
    """
    if not body:
        return ""
    ct = ""
    for k, v in headers.items():
        if k.lower() == "content-type":
            ct = v.lower()
    if "application/json" in ct:
        try:
            data = json.loads(body)
            if isinstance(data, dict):
                flat = {k: v for k, v in data.items()
                        if isinstance(v, (str, int, float, bool))}
                return urllib.parse.urlencode(flat)
        except Exception:
            pass
        return ""
    # already form-urlencoded (or unknown k=v pairs) → usable as-is
    return body


# Auth headers that carry YOUR session — never dump them into a shareable PoC.
_REDACT_HEADERS = ("content-length", "host", "cookie", "authorization",
                   "x-csrf-token", "x-xsrf-token", "x-csrftoken")


def _build_curl(method, url, headers, body=None):
    """Build a copy-pastable curl command as PoC (auth/session headers redacted)."""
    parts = [f"curl -sk -X {method}"]
    for k, v in headers.items():
        if k.lower() in _REDACT_HEADERS:
            continue
        parts.append(f"-H {shlex.quote(f'{k}: {v}')}")
    if body:
        parts.append(f"-d {shlex.quote(body)}")
    parts.append(shlex.quote(url))
    return " \\\n  ".join(parts)


def _is_confirmed(resp, baseline):
    """
    Low-confidence 'candidate' check for an alternate method being processed.

    NOTE: on an endpoint that renders HTML (not a JSON API), "200 + body ≈ baseline"
    is NOT proof — the app happily returns 200 for many methods and the word
    "success" appears all over the markup. So we do NOT treat same-status/same-length
    as confirmation, and we do NOT substring-match "success". Real confirmation of a
    reset requires OOB email (see mail_analysis). Here we only surface a candidate
    when the alternate method yields a 2xx/3xx that is NOT a client-error rejection.
    """
    code = resp.status_code
    if code in (400, 401, 403, 404, 405, 422, 429):
        return False, None
    if code >= 500:
        return False, None
    # a 2xx/3xx that isn't an outright rejection → candidate only
    return True, f"status={code}, len={len(resp.text)}b (candidate — confirm via OOB)"


def method_override(url, parsed_req, baseline, interact, email, proxy=None):
    """
    HTTP Method Override testing on password reset endpoint.
    Only reports confirmed findings with curl PoC.
    """
    print(f"{Colors.CYAN} ├ Method override analysis{Colors.RESET}")

    # With a single-use captcha/token in the request, every replay after the
    # baseline is rejected server-side while often still returning 200 — so a
    # "200 for GET/PUT/PATCH" tells us nothing. Replay-based confirmation is
    # meaningless here; skip rather than emit noise.
    if detect_anti_automation(parsed_req):
        print(f"{Colors.CYAN}   └── [i] single-use captcha/token present → replay-based method-override "
              f"confirmation is unreliable; skipped (use --disposable-mail to confirm via OOB){Colors.RESET}")
        return

    original_host = parsed_req["host"]
    method = parsed_req["method"]
    path = parsed_req["path"]
    body = parsed_req["body"]
    headers = dict(parsed_req["headers"])
    scheme = urlparse(url).scheme

    uri = f"{scheme}://{original_host}{path}"
    proxies = {"http": proxy, "https": proxy} if proxy else None

    findings = []

    # --- Phase 1: Direct method switching ---
    print(f"{Colors.CYAN} └─ Direct method switching{Colors.RESET}")

    alt_methods = ["GET", "PUT", "PATCH", "DELETE", "HEAD"]
    alt_methods = [m for m in alt_methods if m != method.upper()]

    for alt in alt_methods:
        try:
            live.testing(f"method-override switch {alt}")
            if alt == "GET" and body:
                qs = _body_to_query(body, headers)
                test_uri = f"{uri}{'&' if '?' in uri else '?'}{qs}" if qs else uri
                resp = requests.request(
                    method=alt, url=test_uri, headers=headers,
                    verify=False, allow_redirects=False,
                    timeout=15, proxies=proxies,
                )
                curl_cmd = _build_curl(alt, test_uri, headers)
            else:
                resp = requests.request(
                    method=alt, url=uri, headers=headers,
                    data=body or None, verify=False, allow_redirects=False,
                    timeout=15, proxies=proxies,
                )
                curl_cmd = _build_curl(alt, uri, headers, body)

            confirmed, indicator = _is_confirmed(resp, baseline)
            if confirmed:
                reason = indicator
                if alt == "GET":
                    desc = f"INFO — GET accepted (candidate) → if it triggers the reset: no CSRF token needed, token may leak via Referer/logs"
                else:
                    desc = f"INFO — {alt} accepted (candidate) → alternative method reaches the handler"

                findings.append((desc, reason, curl_cmd))
                print(f"{Colors.CYAN}   └── [i] {desc}{Colors.RESET}")
                print(f"{Colors.CYAN}       {reason}{Colors.RESET}")

        except requests.RequestException:
            pass

    # --- Phase 2: Override headers ---
    print(f"{Colors.CYAN} └─ Override headers{Colors.RESET}")

    override_headers_list = [
        "X-HTTP-Method-Override",
        "X-HTTP-Method",
        "X-Method-Override",
        "X-Original-HTTP-Method",
    ]

    carrier_methods = ["GET", "PUT", "PATCH"]
    carrier_methods = [m for m in carrier_methods if m != method.upper()]

    _p2 = {}  # (risk, status_code, body_len) → [(desc, reason, curl_cmd)]

    for carrier in carrier_methods:
        for override_hdr in override_headers_list:
            try:
                live.testing(f"method-override {carrier} + {override_hdr}: {method}")
                test_headers = headers.copy()
                test_headers[override_hdr] = method

                if carrier == "GET" and body:
                    qs = _body_to_query(body, headers)
                    test_uri = f"{uri}{'&' if '?' in uri else '?'}{qs}" if qs else uri
                    resp = requests.request(
                        method=carrier, url=test_uri, headers=test_headers,
                        verify=False, allow_redirects=False,
                        timeout=15, proxies=proxies,
                    )
                    curl_cmd = _build_curl(carrier, test_uri, test_headers)
                else:
                    resp = requests.request(
                        method=carrier, url=uri, headers=test_headers,
                        data=body or None, verify=False, allow_redirects=False,
                        timeout=15, proxies=proxies,
                    )
                    curl_cmd = _build_curl(carrier, uri, test_headers, body)

                confirmed, indicator = _is_confirmed(resp, baseline)
                if confirmed:
                    reason = indicator
                    desc = f"INFO — {carrier} + {override_hdr}: {method} (candidate) → possible method override"
                    _p2.setdefault((resp.status_code, len(resp.text)), []).append((desc, reason, curl_cmd))

            except requests.RequestException:
                pass

    _DEDUP = 3
    for _key, _items in _p2.items():
        if len(_items) >= _DEDUP:
            _d, _r, _c = _items[0]
            print(f"{Colors.CYAN}   └── [i] {_d} (×{len(_items)} combinations){Colors.RESET}")
            print(f"{Colors.CYAN}       {_r}{Colors.RESET}")
            findings.append((_d, _r, _c))
        else:
            for _d, _r, _c in _items:
                print(f"{Colors.CYAN}   └── [i] {_d}{Colors.RESET}")
                print(f"{Colors.CYAN}       {_r}{Colors.RESET}")
                findings.append((_d, _r, _c))

    # --- Phase 3: Query parameter override ---
    print(f"{Colors.CYAN} └─ Query param override{Colors.RESET}")

    param_overrides = ["_method", "method", "httpMethod", "_HttpMethod"]

    _p3 = {}  # (status_code, body_len) → [(desc, reason, curl_cmd)]

    for param in param_overrides:
        try:
            live.testing(f"method-override query {param}={method}")
            separator = "&" if "?" in uri else "?"
            qs = _body_to_query(body, headers)
            if qs:
                test_uri = f"{uri}{separator}{qs}&{param}={method}"
            else:
                test_uri = f"{uri}{separator}{param}={method}"

            resp = requests.get(
                test_uri, headers=headers,
                verify=False, allow_redirects=False,
                timeout=15, proxies=proxies,
            )
            curl_cmd = _build_curl("GET", test_uri, headers)

            confirmed, indicator = _is_confirmed(resp, baseline)
            if confirmed:
                reason = indicator
                desc = f"INFO — GET + ?{param}={method} (candidate) → framework may treat as {method} (Rails/Laravel pattern)"
                _p3.setdefault((resp.status_code, len(resp.text)), []).append((desc, reason, curl_cmd))

        except requests.RequestException:
            pass

    for _key, _items in _p3.items():
        if len(_items) >= _DEDUP:
            _d, _r, _c = _items[0]
            print(f"{Colors.CYAN}   └── [i] {_d} (×{len(_items)} params){Colors.RESET}")
            print(f"{Colors.CYAN}       {_r}{Colors.RESET}")
            findings.append((_d, _r, _c))
        else:
            for _d, _r, _c in _items:
                print(f"{Colors.CYAN}   └── [i] {_d}{Colors.RESET}")
                print(f"{Colors.CYAN}       {_r}{Colors.RESET}")
                findings.append((_d, _r, _c))

    # --- Phase 4: CSRF bypass via method ---
    print(f"{Colors.CYAN} └─ CSRF bypass via method{Colors.RESET}")

    csrf_params = ["csrf", "csrf_token", "csrftoken", "_csrf",
                    "authenticity_token", "_token", "xsrf", "_xsrf",
                    "csrfmiddlewaretoken", "__RequestVerificationToken"]

    csrf_found = None
    if body:
        for cp in csrf_params:
            if cp in body.lower():
                csrf_found = cp
                break

    csrf_header_found = None
    for k in headers:
        if k.lower() in ("x-csrf-token", "x-xsrf-token", "x-csrftoken"):
            csrf_header_found = k
            break

    if csrf_found or csrf_header_found:
        stripped_headers = headers.copy()
        if csrf_header_found:
            del stripped_headers[csrf_header_found]

        stripped_body = body
        if csrf_found and body:
            stripped_body = re.sub(
                rf'[&]?{re.escape(csrf_found)}=[^&]*',
                '', body, flags=re.IGNORECASE
            ).lstrip("&")

        for test_method in [method, "PUT", "PATCH"]:
            try:
                live.testing(f"method-override csrf-bypass {test_method}")
                resp = requests.request(
                    method=test_method, url=uri, headers=stripped_headers,
                    data=stripped_body or None, verify=False, allow_redirects=False,
                    timeout=15, proxies=proxies,
                )
                curl_cmd = _build_curl(test_method, uri, stripped_headers, stripped_body)

                confirmed, indicator = _is_confirmed(resp, baseline)
                if confirmed:
                    reason = indicator
                    desc = f"INFO — {test_method} without CSRF token → {resp.status_code} (candidate — confirm the reset actually fired via OOB)"
                    findings.append((desc, reason, curl_cmd))
                    print(f"{Colors.CYAN}   └── [i] {desc}{Colors.RESET}")
                    print(f"{Colors.CYAN}       {reason}{Colors.RESET}")

            except requests.RequestException:
                pass

    # --- Summary ---
    if findings:
        print(f"\n{Colors.CYAN} └─ PoC curl commands{Colors.RESET}")
        for i, (desc, reason, curl_cmd) in enumerate(findings):
            print(f"{Colors.YELLOW}   ┌── [{i+1}] {desc}{Colors.RESET}")
            print(f"{Colors.RESET}   │ {curl_cmd}{Colors.RESET}")
            print(f"{Colors.YELLOW}   └── {reason}{Colors.RESET}")
    else:
        print(f"{Colors.GREEN}   └── [-] No method override bypass confirmed{Colors.RESET}")
#!/usr/bin/env python3
import sys
sys.dont_write_bytecode = True

from utils.style import Colors
from utils.utils import (
    requests,
    re,
    json,
    urlparse,
    get_domain_from_url,
    EMAIL_REGEX
)
import shlex


SUCCESS_INDICATORS = ["success", "email sent", "password reset", "reset link",
                      "check your email", "lien envoy", "mot de passe", "réinitialis"]


def _build_curl(method, url, headers, body=None):
    """Build a copy-pastable curl command as PoC."""
    parts = [f"curl -sk -X {method}"]
    for k, v in headers.items():
        if k.lower() in ("content-length", "host"):
            continue
        parts.append(f"-H {shlex.quote(f'{k}: {v}')}")
    if body:
        parts.append(f"-d {shlex.quote(body)}")
    parts.append(shlex.quote(url))
    return " \\\n  ".join(parts)


def _is_confirmed(resp, baseline):
    """
    A method override is confirmed if:
    - Same status as baseline AND body length within 20% range
    - OR success indicators found in body
    """
    if resp.status_code != baseline["status"]:
        return False, None

    body_len = len(resp.text)
    baseline_len = baseline["body_length"]

    # Body length within 20% of baseline → likely same behavior
    if baseline_len > 0:
        ratio = abs(body_len - baseline_len) / baseline_len
        if ratio > 0.20:
            return False, None

    # Check for success indicators
    resp_lower = resp.text.lower()
    for indicator in SUCCESS_INDICATORS:
        if indicator in resp_lower:
            return True, indicator

    # Same status + similar length but no explicit success indicator
    # Still likely confirmed
    return True, None


def method_override(url, parsed_req, baseline, interact, email, proxy=None):
    """
    HTTP Method Override testing on password reset endpoint.
    Only reports confirmed findings with curl PoC.
    """
    print(f"{Colors.CYAN} ├ Method override analysis{Colors.RESET}")

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
            if alt == "GET" and body:
                separator = "&" if "?" in uri else "?"
                test_uri = f"{uri}{separator}{body}"
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
                risk = "HIGH" if alt == "GET" else "MEDIUM"
                reason = f"success indicator: '{indicator}'" if indicator else f"status={resp.status_code}, len={len(resp.text)}b ≈ baseline"

                if alt == "GET":
                    desc = f"{risk} — GET accepted → no CSRF needed, token leaks via Referer/logs, CSRF via <img>"
                else:
                    desc = f"{risk} — {alt} accepted → alternative method bypass"

                findings.append((desc, reason, curl_cmd))
                print(f"{Colors.GREEN}   └── [+] {desc}{Colors.RESET}")
                print(f"{Colors.GREEN}       {reason}{Colors.RESET}")

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

    for carrier in carrier_methods:
        for override_hdr in override_headers_list:
            try:
                test_headers = headers.copy()
                test_headers[override_hdr] = method

                if carrier == "GET" and body:
                    separator = "&" if "?" in uri else "?"
                    test_uri = f"{uri}{separator}{body}"
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
                    risk = "HIGH" if carrier == "GET" else "MEDIUM"
                    reason = f"success indicator: '{indicator}'" if indicator else f"status={resp.status_code}, len={len(resp.text)}b ≈ baseline"
                    desc = f"{risk} — {carrier} + {override_hdr}: {method} → backend treats as {method}"
                    findings.append((desc, reason, curl_cmd))
                    print(f"{Colors.GREEN}   └── [+] {desc}{Colors.RESET}")
                    print(f"{Colors.GREEN}       {reason}{Colors.RESET}")

            except requests.RequestException:
                pass

    # --- Phase 3: Query parameter override ---
    print(f"{Colors.CYAN} └─ Query param override{Colors.RESET}")

    param_overrides = ["_method", "method", "httpMethod", "_HttpMethod"]

    for param in param_overrides:
        try:
            separator = "&" if "?" in uri else "?"
            if body:
                test_uri = f"{uri}{separator}{body}&{param}={method}"
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
                reason = f"success indicator: '{indicator}'" if indicator else f"status={resp.status_code}, len={len(resp.text)}b ≈ baseline"
                desc = f"HIGH — GET + ?{param}={method} → framework treats as {method} (Rails/Laravel pattern)"
                findings.append((desc, reason, curl_cmd))
                print(f"{Colors.GREEN}   └── [+] {desc}{Colors.RESET}")
                print(f"{Colors.GREEN}       {reason}{Colors.RESET}")

        except requests.RequestException:
            pass

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
                resp = requests.request(
                    method=test_method, url=uri, headers=stripped_headers,
                    data=stripped_body or None, verify=False, allow_redirects=False,
                    timeout=15, proxies=proxies,
                )
                curl_cmd = _build_curl(test_method, uri, stripped_headers, stripped_body)

                confirmed, indicator = _is_confirmed(resp, baseline)
                if confirmed:
                    reason = f"success indicator: '{indicator}'" if indicator else f"status={resp.status_code}, len={len(resp.text)}b ≈ baseline"
                    desc = f"CRITICAL — {test_method} without CSRF token → {resp.status_code} (CSRF bypass confirmed)"
                    findings.append((desc, reason, curl_cmd))
                    print(f"{Colors.RED}   └── [+] {desc}{Colors.RESET}")
                    print(f"{Colors.RED}       {reason}{Colors.RESET}")

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
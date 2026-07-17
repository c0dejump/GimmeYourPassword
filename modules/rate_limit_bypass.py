#!/usr/bin/env python3
import sys
sys.dont_write_bytecode = True

import random
from utils.style import Colors
from utils.utils import requests


RATE_LIMIT_KEYWORDS = [
    "too many", "rate limit", "ratelimit", "try again", "throttle",
    "too many requests", "slow down", "retry after", "quota exceeded",
    "please wait", "blocked",
]

IP_SPOOF_HEADERS = [
    "X-Forwarded-For",
    "X-Real-IP",
    "X-Client-IP",
    "Client-IP",
    "True-Client-IP",
    "CF-Connecting-IP",
    "X-Originating-IP",
    "Fastly-Client-Ip",
    "X-Cluster-Client-IP",
    "X-ProxyUser-Ip",
    "Forwarded-For",
]

LOOPBACK_IPS = ["127.0.0.1", "localhost", "0.0.0.0", "::1"]


def _random_ip():
    return f"{random.randint(1,254)}.{random.randint(0,254)}.{random.randint(0,254)}.{random.randint(1,254)}"  # nosec B311


def _is_rate_limited(resp, baseline_status):
    if resp.status_code == 429:
        return True
    if resp.status_code != baseline_status:
        body_lower = resp.text.lower()
        for kw in RATE_LIMIT_KEYWORDS:
            if kw in body_lower:
                return True
    return False


def rate_limit_bypass(url, parsed_req, baseline, interact, email, proxy=None):
    """
    Rate limit bypass testing.

    Phase 1: Trigger rate limiting with rapid requests.
    Phase 2: Attempt bypass via IP spoofing headers (X-Forwarded-For, X-Real-IP, etc.)
             and loopback IPs (127.0.0.1, localhost) which may be whitelisted.
    """
    print(f"{Colors.CYAN} ├ Rate limit bypass{Colors.RESET}")

    original_host = parsed_req["host"]
    method = parsed_req["method"]
    path = parsed_req["path"]
    body = parsed_req["body"]
    headers = dict(parsed_req["headers"])
    scheme = "https" if "https" in url else "http"

    uri = f"{scheme}://{original_host}{path}"
    proxies = {"http": proxy, "https": proxy} if proxy else None

    # --- Phase 1: Trigger rate limit ---
    print(f"{Colors.CYAN} └─ Triggering rate limit (15 rapid requests){Colors.RESET}")

    PROBE_COUNT = 15
    rate_limited_at = None

    for i in range(PROBE_COUNT):
        try:
            resp = requests.request(
                method=method, url=uri, headers=headers,
                data=body or None, verify=False, allow_redirects=False,
                timeout=10, proxies=proxies,
            )
            if _is_rate_limited(resp, baseline["status"]):
                rate_limited_at = i + 1
                print(f"{Colors.YELLOW}   └── [INFO] Rate limit triggered at request #{i+1} → {resp.status_code}{Colors.RESET}")
                break
        except requests.RequestException:
            pass

    if rate_limited_at is None:
        print(f"{Colors.YELLOW}   └── [-] No rate limit detected after {PROBE_COUNT} requests{Colors.RESET}")
        return

    # --- Phase 2: Bypass attempts ---
    print(f"{Colors.CYAN} └─ Bypass via IP spoofing headers{Colors.RESET}")

    any_bypass = False

    for spoof_header in IP_SPOOF_HEADERS:
        fake_ip = _random_ip()
        bypass_headers = headers.copy()
        bypass_headers[spoof_header] = fake_ip

        try:
            resp = requests.request(
                method=method, url=uri, headers=bypass_headers,
                data=body or None, verify=False, allow_redirects=False,
                timeout=10, proxies=proxies,
            )
            if not _is_rate_limited(resp, baseline["status"]) and resp.status_code == baseline["status"]:
                print(f"{Colors.RED}   └── [CRITICAL] Bypass via {spoof_header}: {fake_ip} → {resp.status_code}{Colors.RESET}")
                print(f"{Colors.RED}       Attacker can rotate IPs in this header to bypass rate limiting{Colors.RESET}")
                any_bypass = True
            else:
                print(f"{Colors.GREEN}   └── [-] {spoof_header} did not bypass ({resp.status_code}){Colors.RESET}")
        except requests.RequestException:
            pass

    # Loopback whitelist check
    for special_ip in LOOPBACK_IPS:
        bypass_headers = headers.copy()
        bypass_headers["X-Forwarded-For"] = special_ip
        try:
            resp = requests.request(
                method=method, url=uri, headers=bypass_headers,
                data=body or None, verify=False, allow_redirects=False,
                timeout=10, proxies=proxies,
            )
            if not _is_rate_limited(resp, baseline["status"]) and resp.status_code == baseline["status"]:
                print(f"{Colors.RED}   └── [CRITICAL] Bypass via loopback X-Forwarded-For: {special_ip} → {resp.status_code}{Colors.RESET}")
                print(f"{Colors.RED}       Server whitelists loopback as trusted IP, skipping rate limit{Colors.RESET}")
                any_bypass = True
        except requests.RequestException:
            pass

    if not any_bypass:
        print(f"{Colors.GREEN}   └── [-] No rate limit bypass confirmed{Colors.RESET}")

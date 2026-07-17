#!/usr/bin/env python3
import sys
sys.dont_write_bytecode = True

import time
import re
from utils.style import Colors
from utils.utils import requests
from modules.token_analysis import _extract_tokens_from_response


RESET_URL_RE = re.compile(
    r'(https?://[^\s"\'<>]+(?:token|code|reset|verify|confirm)[^\s"\'<>]*=[a-zA-Z0-9\-_\.]{10,})',
    re.IGNORECASE
)


def token_reuse(url, parsed_req, baseline, interact, email, proxy=None):
    """
    Token Reuse testing.

    Phase 1: Send N reset requests — if same token returned across requests,
             old tokens are never invalidated (any previously issued token stays valid).
    Phase 2: If a reset URL is visible in the response, replay it twice to test
             single-use enforcement.
    """
    print(f"{Colors.CYAN} ├ Token reuse{Colors.RESET}")

    original_host = parsed_req["host"]
    method = parsed_req["method"]
    path = parsed_req["path"]
    body = parsed_req["body"]
    headers = dict(parsed_req["headers"])
    scheme = "https" if "https" in url else "http"

    uri = f"{scheme}://{original_host}{path}"
    proxies = {"http": proxy, "https": proxy} if proxy else None

    NUM_REQUESTS = 5

    # --- Phase 1: Token persistence across reset requests ---
    print(f"{Colors.CYAN} └─ Token persistence across resets ({NUM_REQUESTS} requests){Colors.RESET}")

    collected_tokens = []
    collected_urls = []

    for i in range(NUM_REQUESTS):
        try:
            resp = requests.request(
                method=method, url=uri, headers=headers,
                data=body or None, verify=False, allow_redirects=False,
                timeout=10, proxies=proxies,
            )
            for token, source in _extract_tokens_from_response(resp):
                collected_tokens.append((token, source, i + 1))

            for m in RESET_URL_RE.finditer(resp.text):
                if m.group(1) not in collected_urls:
                    collected_urls.append(m.group(1))

            if i < NUM_REQUESTS - 1:
                time.sleep(0.3)
        except requests.RequestException:
            pass

    if not collected_tokens:
        print(f"{Colors.YELLOW}   └── [-] No tokens in response (likely sent by email){Colors.RESET}")
        print(f"{Colors.YELLOW}   └── [i] Manual: request reset twice → check if 1st token still works{Colors.RESET}")
    else:
        raw_tokens = [t for t, _, _ in collected_tokens]
        unique_tokens = set(raw_tokens)

        if len(unique_tokens) == 1:
            print(f"{Colors.RED}   └── [CRITICAL] Same token on all {NUM_REQUESTS} requests → never regenerated{Colors.RESET}")
            print(f"{Colors.RED}       Any previously issued token remains valid indefinitely{Colors.RESET}")
            print(f"{Colors.RED}       token: {raw_tokens[0][:80]}{Colors.RESET}")
        elif len(unique_tokens) < len(raw_tokens):
            dupes = {t for t in raw_tokens if raw_tokens.count(t) > 1}
            print(f"{Colors.YELLOW}   └── [HIGH] Duplicate tokens across {NUM_REQUESTS} requests: {dupes}{Colors.RESET}")
            print(f"{Colors.YELLOW}       Some tokens not regenerated after new reset request{Colors.RESET}")
        else:
            print(f"{Colors.GREEN}   └── [OK] {len(unique_tokens)} unique tokens — regenerated on each request{Colors.RESET}")

    # --- Phase 2: Reset URL single-use enforcement ---
    if collected_urls:
        print(f"{Colors.CYAN} └─ Reset URL replay (single-use enforcement){Colors.RESET}")

        for reset_url in collected_urls[:3]:
            try:
                resp1 = requests.get(reset_url, verify=False, allow_redirects=False, timeout=10, proxies=proxies)
                time.sleep(0.5)
                resp2 = requests.get(reset_url, verify=False, allow_redirects=False, timeout=10, proxies=proxies)

                s1, s2 = resp1.status_code, resp2.status_code

                if s2 not in [400, 404, 410, 422] and s1 == s2:
                    print(f"{Colors.RED}   └── [CRITICAL] URL accepted twice ({s1}→{s2}) → no single-use enforcement{Colors.RESET}")
                    print(f"{Colors.RED}       {reset_url[:100]}{Colors.RESET}")
                elif s2 in [400, 404, 410, 422]:
                    print(f"{Colors.GREEN}   └── [OK] URL rejected on second use ({s1}→{s2}){Colors.RESET}")
                else:
                    print(f"{Colors.YELLOW}   └── [MEDIUM] Inconsistent replay: {s1}→{s2} | {reset_url[:80]}{Colors.RESET}")
            except requests.RequestException:
                pass

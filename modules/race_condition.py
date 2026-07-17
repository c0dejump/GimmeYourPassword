#!/usr/bin/env python3
import sys
sys.dont_write_bytecode = True

import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from utils.style import Colors
from utils.utils import requests
from modules.token_analysis import _extract_tokens_from_response


def _fire(method, uri, headers, body, proxies, idx):
    try:
        resp = requests.request(
            method=method, url=uri, headers=headers,
            data=body or None, verify=False, allow_redirects=False,
            timeout=15, proxies=proxies,
        )
        return idx, resp.status_code, len(resp.text), resp
    except requests.RequestException:
        return idx, None, 0, None


def race_condition(url, parsed_req, baseline, interact, email, proxy=None):
    """
    Race condition testing on password reset endpoint.

    Phase 1: Send N concurrent requests synchronized via threading.Barrier
             to maximize collision probability.
    Phase 2: Compare tokens — duplicate = same token issued to multiple sessions.
             Also checks for 500 errors and abnormal response variance.
    """
    print(f"{Colors.CYAN} ├ Race condition{Colors.RESET}")

    original_host = parsed_req["host"]
    method = parsed_req["method"]
    path = parsed_req["path"]
    body = parsed_req["body"]
    headers = dict(parsed_req["headers"])
    scheme = "https" if "https" in url else "http"

    uri = f"{scheme}://{original_host}{path}"
    proxies = {"http": proxy, "https": proxy} if proxy else None

    NUM_THREADS = 10
    print(f"{Colors.CYAN} └─ Firing {NUM_THREADS} synchronized concurrent requests{Colors.RESET}")

    barrier = threading.Barrier(NUM_THREADS)

    def _synchronized_fire(idx):
        try:
            barrier.wait(timeout=5)
        except threading.BrokenBarrierError:
            pass
        return _fire(method, uri, headers, body, proxies, idx)

    results = []
    with ThreadPoolExecutor(max_workers=NUM_THREADS) as executor:
        futures = [executor.submit(_synchronized_fire, i) for i in range(NUM_THREADS)]
        for f in as_completed(futures):
            try:
                results.append(f.result())
            except Exception:
                pass

    if not results:
        print(f"  {Colors.YELLOW}[!] All requests failed{Colors.RESET}")
        return

    statuses = [r[1] for r in results if r[1] is not None]
    lengths = [r[2] for r in results if r[1] is not None]
    responses = [r[3] for r in results if r[3] is not None]

    status_counts = {}
    for s in statuses:
        status_counts[s] = status_counts.get(s, 0) + 1

    print(f"{Colors.CYAN}   └─ Status distribution: {status_counts}{Colors.RESET}")

    # Token collision check
    all_tokens = []
    for resp in responses:
        for token, _ in _extract_tokens_from_response(resp):
            all_tokens.append(token)

    if all_tokens:
        unique_tokens = set(all_tokens)
        if len(unique_tokens) < len(all_tokens):
            dupes = len(all_tokens) - len(unique_tokens)
            print(f"{Colors.RED}   └── [CRITICAL] {dupes} duplicate token(s) across {NUM_THREADS} concurrent requests{Colors.RESET}")
            print(f"{Colors.RED}       Race condition: same token issued to multiple sessions{Colors.RESET}")
        else:
            print(f"{Colors.GREEN}   └── [OK] {len(unique_tokens)} unique tokens in concurrent responses{Colors.RESET}")
    else:
        print(f"{Colors.YELLOW}   └── [-] Tokens not visible in response (sent by email){Colors.RESET}")
        print(f"{Colors.YELLOW}   └── [i] Use Turbo Intruder 'race-single-packet-attack' to test manually{Colors.RESET}")

    # 500 errors → server crash on concurrency
    if 500 in status_counts:
        print(f"{Colors.RED}   └── [HIGH] {status_counts[500]}× HTTP 500 under concurrency → possible race / locking bug{Colors.RESET}")

    # Mixed statuses (> 2 distinct) → inconsistent state
    if len(set(statuses)) > 2:
        print(f"{Colors.YELLOW}   └── [MEDIUM] Mixed statuses: {status_counts} → inconsistent concurrent behavior{Colors.RESET}")

    # Response length variance
    if lengths and max(lengths) - min(lengths) > 200:
        print(f"{Colors.YELLOW}   └── [MEDIUM] Length variance: {min(lengths)}b–{max(lengths)}b across concurrent requests{Colors.RESET}")

#!/usr/bin/env python3
import sys
sys.dont_write_bytecode = True

import re
import secrets
import time

from utils.style import Colors
from utils.utils import requests, EMAIL_REGEX, urlparse
from utils import live


def _rand_email(encoded_at):
    """A definitely-non-existent, well-formed address."""
    local = "gyp-noexist-" + secrets.token_hex(6)
    at = "%40" if encoded_at else "@"
    return f"{local}{at}gmail.com"


def _swap_email(body, victim, new):
    return body.replace(victim, new, 1) if body and victim else body


def _norm(text, *emails):
    """Strip the (variable-length) email values so bodies are comparable."""
    out = text or ""
    for e in emails:
        if e:
            out = out.replace(e, "")
    return out


def _send(method, uri, headers, body, proxies):
    return requests.request(
        method=method, url=uri, headers=headers, data=body or None,
        verify=False, allow_redirects=False, timeout=15, proxies=proxies,
    )


def user_enum(url, parsed_req, baseline, interact, email, proxy=None):
    """
    Account (username) enumeration on the reset endpoint.

    Compares the response for the REAL address (baseline) against a well-formed
    but non-existent address. If the endpoint answers differently (status, body
    length once the echoed email is normalised out, or a distinguishing phrase),
    an attacker can tell which emails have accounts — a privacy/enumeration bug.

    A safe design returns the SAME generic "if an account exists…" answer for both.
    """
    print(f"{Colors.CYAN} ├ User enumeration{Colors.RESET}")

    method = parsed_req["method"]
    path = parsed_req["path"]
    body = parsed_req["body"]
    headers = dict(parsed_req["headers"])
    original_host = parsed_req["host"]
    scheme = urlparse(url).scheme or ("https" if "https" in url else "http")
    uri = f"{scheme}://{original_host}{path}"
    proxies = {"http": proxy, "https": proxy} if proxy else None

    m = re.search(EMAIL_REGEX, body or "", re.IGNORECASE)
    if not m:
        print(f"{Colors.CYAN}   └── [i] No email value in body — enumeration test skipped{Colors.RESET}")
        return
    victim = m.group(0)
    encoded_at = "%40" in victim

    # Two independent non-existent addresses: they must agree with each other so we
    # know the "absent" response is stable (not just per-request jitter).
    try:
        resps = []
        for _ in range(2):
            live.testing("user-enum probing a non-existent address")
            fake = _rand_email(encoded_at)
            r = _send(method, uri, headers, _swap_email(body, victim, fake), proxies)
            resps.append((r, fake))
            time.sleep(0.3)
    except requests.RequestException as e:
        print(f"  {Colors.RED}[!] {e}{Colors.RESET}")
        return

    (r1, f1), (r2, f2) = resps
    base_status = baseline.get("status")
    base_body = _norm(baseline.get("body"), victim)
    b1 = _norm(r1.text, f1)
    b2 = _norm(r2.text, f2)

    # the two "absent" responses must be consistent to trust the comparison
    if r1.status_code != r2.status_code or abs(len(b1) - len(b2)) > 40:
        print(f"{Colors.YELLOW}   └── [i] Non-existent-address responses are inconsistent "
              f"({r1.status_code}/{len(b1)}b vs {r2.status_code}/{len(b2)}b) — can't conclude, check manually{Colors.RESET}")
        return

    status_diff = base_status != r1.status_code
    len_diff = abs(len(base_body) - len(b1))

    if status_diff:
        print(f"{Colors.RED}   └── [LOW] Enumeration: existing address → {base_status}, "
              f"non-existent → {r1.status_code} (different status reveals valid accounts){Colors.RESET}")
    elif len_diff > 40:
        print(f"{Colors.RED}   └── [LOW] Enumeration: response body differs by {len_diff}b between "
              f"existing and non-existent address (content reveals valid accounts){Colors.RESET}")
        print(f"{Colors.YELLOW}       exists≈{len(base_body)}b vs absent≈{len(b1)}b (email value normalised out){Colors.RESET}")
    else:
        print(f"{Colors.GREEN}   └── [OK] Same generic response for existing and non-existent addresses "
              f"(no enumeration){Colors.RESET}")

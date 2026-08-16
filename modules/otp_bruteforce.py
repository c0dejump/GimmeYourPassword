#!/usr/bin/env python3
import sys
sys.dont_write_bytecode = True

import random

from utils.style import Colors
from utils.utils import (
    requests,
    re,
    json,
    urlparse,
    detect_lockout,
    detect_content_type,
    SUCCESS_INDICATORS,
)
from utils import live


# Body keys that hold a one-time confirmation code / OTP.
CODE_KEYS = [
    "code", "otp", "pin", "confirmation_code", "confirmationCode",
    "verification_code", "verificationCode", "otp_code", "otpCode",
    "one_time_code", "oneTimeCode", "token",
]

# Request-header names that typically carry the rotating flow token to chain.
TOKEN_HEADER_NAMES = ["authid", "x-authid", "auth-id", "token", "x-token", "state"]

_JWT_RE = re.compile(r'eyJ[a-zA-Z0-9_-]{6,}\.eyJ[a-zA-Z0-9_-]{6,}\.[a-zA-Z0-9_-]+')

# How many WRONG codes we're willing to send. Kept tiny on purpose: a real flow
# locks after a handful, and we must NOT keep hammering the user's own account.
BUDGET = 4


def _find_code_field(body, content_type):
    """Return (key, value) of a short-numeric code field, or None."""
    if not body:
        return None
    if content_type == "json":
        try:
            data = json.loads(body)
        except Exception:
            return None
        if not isinstance(data, dict):
            return None
        for k in CODE_KEYS:
            if k in data:
                v = str(data[k])
                if v.isdigit() and 3 <= len(v) <= 10:
                    return (k, v)
        # fallback: any digit-only value 4–10 chars
        for k, v in data.items():
            sv = str(v)
            if sv.isdigit() and 4 <= len(sv) <= 10:
                return (k, sv)
        return None
    # form / urlencoded / raw
    for k in CODE_KEYS:
        m = re.search(rf'(?:^|[&\s"]){re.escape(k)}["\s]*[:=]\s*"?(\d{{3,10}})', body, re.IGNORECASE)
        if m:
            return (k, m.group(1))
    return None


def _set_code(body, content_type, key, old_val, new_val):
    """Return body with the code field replaced by new_val."""
    if content_type == "json":
        try:
            data = json.loads(body)
            data[key] = new_val
            return json.dumps(data)
        except Exception:
            pass
    # textual replace of key=old / "key":"old"
    return re.sub(
        rf'({re.escape(key)}["\s]*[:=]\s*"?){re.escape(old_val)}',
        rf'\g<1>{new_val}', body, count=1,
    )


def _find_chain_header(headers):
    """Return the header name that carries the rotating flow token, or None."""
    for k, v in headers.items():
        if k.lower() in TOKEN_HEADER_NAMES and v:
            return k
    for k, v in headers.items():
        if isinstance(v, str) and _JWT_RE.fullmatch(v.strip()):
            return k
    return None


def _find_chain_body_key(body, content_type):
    """Return a body key (json) that carries a token to chain, or None."""
    if content_type != "json" or not body:
        return None
    try:
        data = json.loads(body)
    except Exception:
        return None
    if not isinstance(data, dict):
        return None
    for k in ("authId", "authid", "token", "state", "continueToken", "flowToken"):
        if k in data and isinstance(data[k], str):
            return k
    return None


def _extract_fresh_token(resp):
    """Pull a rotated flow token (JWT) out of a response body or headers."""
    # JSON: authId / tokens.authId / token / authId-like
    try:
        d = resp.json()
        if isinstance(d, dict):
            for k in ("authId", "authid", "token", "state"):
                if isinstance(d.get(k), str) and _JWT_RE.fullmatch(d[k].strip()):
                    return d[k].strip()
            toks = d.get("tokens")
            if isinstance(toks, dict):
                for v in toks.values():
                    if isinstance(v, str) and _JWT_RE.fullmatch(v.strip()):
                        return v.strip()
    except Exception:
        pass
    # any JWT in the raw body
    m = _JWT_RE.search(resp.text or "")
    return m.group(0) if m else None


def _wrong_code(length, avoid):
    """Random wrong numeric code of the given length (never equal to avoid)."""
    for _ in range(10):
        c = "".join(random.choice("0123456789") for _ in range(length))
        if c != avoid:
            return c
    return ("0" * length)[:length]


def otp_bruteforce(url, parsed_req, baseline, interact, email, proxy=None):
    """
    OTP / confirmation-code brute-force RESISTANCE test.

    Only runs when the request looks like a code-submission step (a short numeric
    code field). It sends a small, bounded number of WRONG codes while chaining the
    rotating flow token (e.g. ForgeRock authId), and classifies the control:

      • locks after N tries (N small)  → SECURE  (report the attempt cap)
      • wrong code ACCEPTED            → CRITICAL (validation broken)
      • never locks, token keeps rotating → HIGH  (OTP likely brute-forceable)

    It STOPS immediately on a lockout signal — both because that answers the
    question and to avoid locking the account further.
    """
    print(f"{Colors.CYAN} ├ OTP brute-force resistance{Colors.RESET}")

    method = parsed_req["method"]
    path = parsed_req["path"]
    body = parsed_req["body"]
    headers = dict(parsed_req["headers"])
    original_host = parsed_req["host"]
    scheme = urlparse(url).scheme or ("https" if "https" in url else "http")
    uri = f"{scheme}://{original_host}{path}"
    proxies = {"http": proxy, "https": proxy} if proxy else None
    content_type = detect_content_type(headers)

    code_field = _find_code_field(body, content_type)
    if not code_field:
        print(f"{Colors.CYAN}   └── [i] No confirmation-code field in request — not an OTP step, skipped{Colors.RESET}")
        return

    code_key, code_val = code_field
    clen = len(code_val)
    space = 10 ** clen
    print(f"{Colors.CYAN}   └── code field '{code_key}' = {clen}-digit numeric ({space:,} combinations){Colors.RESET}")

    chain_header = _find_chain_header(headers)
    chain_body_key = None if chain_header else _find_chain_body_key(body, content_type)
    if chain_header:
        print(f"{Colors.CYAN}   └── rotating token chained via header '{chain_header}'{Colors.RESET}")
    elif chain_body_key:
        print(f"{Colors.CYAN}   └── rotating token chained via body key '{chain_body_key}'{Colors.RESET}")
    else:
        print(f"{Colors.YELLOW}   └── [i] no flow token found to chain — testing without rotation (may break after 1 try){Colors.RESET}")

    cur_headers = dict(headers)
    cur_body = body
    locked_at = None
    accepted = False
    attempts = 0

    for i in range(1, BUDGET + 1):
        wrong = _wrong_code(clen, code_val)
        cur_body = _set_code(cur_body, content_type, code_key, code_val, wrong)
        code_val = wrong  # next replace targets the value we just set
        try:
            live.testing(f"otp-bruteforce attempt {i}/{BUDGET}")
            resp = requests.request(
                method=method, url=uri, headers=cur_headers,
                data=cur_body or None, verify=False, allow_redirects=False,
                timeout=15, proxies=proxies,
            )
        except requests.RequestException as e:
            print(f"  {Colors.RED}[!] {e}{Colors.RESET}")
            break

        attempts = i
        text = resp.text or ""

        # 1) lockout → SECURE, stop now
        if detect_lockout(text):
            locked_at = i
            break

        # 2) wrong code accepted? (should never happen)
        low = text.lower()
        if resp.status_code in (200, 302) and any(s in low for s in SUCCESS_INDICATORS) \
                and "invalid" not in low and "not valid" not in low:
            accepted = True
            break

        # 3) chain the rotated token for the next attempt
        fresh = _extract_fresh_token(resp)
        if fresh:
            if chain_header:
                cur_headers[chain_header] = fresh
            elif chain_body_key and content_type == "json":
                try:
                    d = json.loads(cur_body); d[chain_body_key] = fresh
                    cur_body = json.dumps(d)
                except Exception:
                    pass
        else:
            # no new token and not locked → the chain is dead, can't keep going
            print(f"{Colors.CYAN}   └── attempt {i}: no rotated token returned — chain ended (endpoint may require a fresh flow){Colors.RESET}")
            break

    # --- verdict ---
    if accepted:
        print(f"{Colors.RED}   └── [CRITICAL] a WRONG code was accepted → confirmation-code validation is broken{Colors.RESET}")
    elif locked_at is not None:
        print(f"{Colors.GREEN}   └── [SECURE] flow locked after {locked_at} wrong attempt(s) (attempt cap present){Colors.RESET}")
        print(f"{Colors.GREEN}       {clen}-digit code + ~{locked_at}-try cap → not brute-forceable{Colors.RESET}")
        print(f"{Colors.YELLOW}       ⚠ this test may have temporarily locked the tested account (expected, resolves on its own){Colors.RESET}")
    elif attempts >= BUDGET:
        print(f"{Colors.RED}   └── [HIGH] no lockout after {attempts} wrong codes, token kept rotating{Colors.RESET}")
        print(f"{Colors.RED}       → no attempt cap observed; {clen}-digit OTP may be brute-forceable "
              f"(re-run manually with a larger budget to confirm){Colors.RESET}")
    else:
        print(f"{Colors.CYAN}   └── [i] inconclusive after {attempts} attempt(s) — chain ended before a verdict{Colors.RESET}")

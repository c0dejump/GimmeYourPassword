#!/usr/bin/env python3
import sys
sys.dont_write_bytecode = True

from utils.style import Colors
from utils.utils import (
    requests,
    re,
    json,
    traceback,
    get_domain_from_url,
    EMAIL_REGEX
)
import math
import base64
import hashlib
import time
from collections import Counter
from datetime import datetime, timezone


# ─── Token extraction (strict — only reset-relevant sources) ──────────────────

TOKEN_JSON_KEYS = [
    "token", "reset_token", "resetToken", "reset_password_token",
    "resetPasswordToken", "password_token", "passwordToken",
    "confirmation_token", "confirmationToken", "otp", "code",
    "verification_code", "verificationCode", "pin", "secret",
    "temp_token", "tempToken", "one_time_token", "temptoken",
    "nonce", "resetCode", "reset_code",
]

# Token in URL params (Location header or body links)
URL_TOKEN_RE = re.compile(
    r'(?:token|reset_token|resetToken|code|otp|confirmation|verify|tempToken|reset_code)'
    r'=([a-zA-Z0-9\-_\.]{10,256})',
    re.IGNORECASE
)

JWT_RE = re.compile(r'(eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]+)')


def _is_encrypted_cookie(token):
    """Detect Laravel/framework encrypted cookies: base64({"iv":...,"value":...})."""
    try:
        for padding in [token, token + "=", token + "=="]:
            decoded = base64.b64decode(padding).decode("utf-8", errors="ignore")
            if '"iv"' in decoded and '"value"' in decoded:
                return True
    except Exception:
        pass
    return False


def _extract_tokens_from_response(resp):
    """
    Extract potential RESET tokens from response.
    Only checks: JSON body keys, Location header, body URLs.
    Does NOT check Set-Cookie (session cookies ≠ reset tokens).
    """
    found = []

    # --- JSON body: look for known token keys ---
    try:
        data = resp.json()
        if isinstance(data, dict):
            # Flat lookup
            for key in TOKEN_JSON_KEYS:
                if key in data and isinstance(data[key], str) and len(data[key]) >= 6:
                    found.append((data[key], f"json → {key}"))
            # Nested 1 level
            for k, v in data.items():
                if isinstance(v, dict):
                    for key in TOKEN_JSON_KEYS:
                        if key in v and isinstance(v[key], str) and len(v[key]) >= 6:
                            found.append((v[key], f"json → {k}.{key}"))
    except Exception:
        pass

    # --- Location header (redirect with token param) ---
    location = resp.headers.get("Location", "")
    if location:
        for m in URL_TOKEN_RE.finditer(location):
            found.append((m.group(1), f"redirect → {location[:80]}"))

    # --- Explicit token headers (rare but exists) ---
    for hdr in ["X-Token", "X-Reset-Token", "X-OTP"]:
        val = resp.headers.get(hdr, "")
        if val and len(val) >= 8:
            found.append((val, f"header → {hdr}"))

    # --- Full reset URLs in body ---
    body = resp.text if hasattr(resp, 'text') else ""
    reset_urls = re.findall(
        r'(https?://[^\s"\'<>]+(?:token|code|reset|verify|confirm)[^\s"\'<>]*=[a-zA-Z0-9\-_\.]{10,})',
        body, re.IGNORECASE
    )
    for url_match in reset_urls[:5]:
        for m in URL_TOKEN_RE.finditer(url_match):
            token = m.group(1)
            if token not in [t for t, _ in found]:
                found.append((token, f"body → reset URL"))

    # --- JWT in body (not in headers/cookies — those are session tokens) ---
    for m in JWT_RE.finditer(body):
        jwt_token = m.group(1)
        if jwt_token not in [t for t, _ in found] and not _is_encrypted_cookie(jwt_token):
            found.append((jwt_token, "body → JWT"))

    # --- Filter ---
    unique = []
    seen = set()
    for token, source in found:
        if token in seen:
            continue
        if len(token) < 8 or len(token) > 512:
            continue
        if _is_encrypted_cookie(token):
            continue
        seen.add(token)
        unique.append((token, source))

    return unique


# ─── Time-based token formats (Reset Tolkien) ────────────────────────────────

def _php_uniqid(timestamp):
    sec = math.floor(timestamp)
    usec = round(1000000 * (timestamp - sec))
    return "%08x%05x" % (sec, usec)


def _reverse_php_uniqid(token):
    if len(token) != 13:
        return None
    try:
        if not all(c in "0123456789abcdef" for c in token.lower()):
            return None
        sec = int(token[:8], 16)
        usec = int(token[8:], 16)
        ts = float(f"{sec}.{usec}")
        now = time.time()
        if abs(ts - now) < 365 * 24 * 3600:
            return ts
    except (ValueError, OverflowError):
        pass
    return None


def _reverse_mongodb_objectid(token):
    if len(token) != 24:
        return None
    try:
        if not all(c in "0123456789abcdef" for c in token.lower()):
            return None
        ts = int(token[:8], 16)
        process = int(token[8:18], 16)
        counter = int(token[18:24], 16)
        now = int(time.time())
        if abs(ts - now) < 365 * 24 * 3600:
            return {"timestamp": ts, "process": process, "counter": counter}
    except (ValueError, OverflowError):
        pass
    return None


def _check_time_based_hashes(token, response_timestamp, email=None):
    """
    Brute-check if token = hash(timestamp-variant).
    Window: ±2s, 1ms steps. Tests: raw, int, uniqid, ms, µs × md5/sha1/sha256.
    """
    if not response_timestamp:
        return None

    hash_algos = ["md5", "sha1", "sha256"]
    base_ts = response_timestamp

    prefixes = [""]
    suffixes = [""]
    if email:
        prefixes.append(email)
        suffixes.append(email)

    for offset_ms in range(-2000, 2001, 1):
        ts = base_ts + (offset_ms / 1000.0)

        ts_formats = [
            str(ts),
            str(int(ts)),
            _php_uniqid(ts),
            str(int(ts * 1000)),
            str(int(ts * 1000000)),
        ]

        for prefix in prefixes:
            for suffix in suffixes:
                for fmt in ts_formats:
                    raw_value = f"{prefix}{fmt}{suffix}"

                    if token == fmt or token == raw_value:
                        return {"match": f"raw({raw_value})", "timestamp": ts}

                    for algo in hash_algos:
                        hashed = hashlib.new(algo, raw_value.encode()).hexdigest()
                        if token.lower() == hashed.lower():
                            return {"match": f"{algo}({raw_value})", "timestamp": ts}

    return None


# ─── Analysis helpers ─────────────────────────────────────────────────────────

def _shannon_entropy(s):
    if not s:
        return 0.0
    counts = Counter(s)
    length = len(s)
    return round(-sum((c / length) * math.log2(c / length) for c in counts.values()), 3)


def _is_jwt(token):
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        header_b64 = parts[0] + "=" * (4 - len(parts[0]) % 4)
        payload_b64 = parts[1] + "=" * (4 - len(parts[1]) % 4)
        header = json.loads(base64.urlsafe_b64decode(header_b64))
        payload = json.loads(base64.urlsafe_b64decode(payload_b64))
        return {"header": header, "payload": payload}
    except Exception:
        return None


def _detect_uuid_version(token):
    m = re.match(
        r'^([0-9a-f]{8})-?([0-9a-f]{4})-?([0-9a-f])([0-9a-f]{3})-?([0-9a-f]{4})-?([0-9a-f]{12})$',
        token, re.IGNORECASE
    )
    return int(m.group(3)) if m else None


def _get_response_timestamp(resp):
    date_hdr = resp.headers.get("Date", "")
    if date_hdr:
        for fmt in ["%a, %d %b %Y %H:%M:%S %Z", "%a, %d %b %Y %H:%M:%S GMT"]:
            try:
                dt = datetime.strptime(date_hdr, fmt)
                return dt.replace(tzinfo=timezone.utc).timestamp()
            except ValueError:
                continue
    return time.time()


# ─── Token analysis core ─────────────────────────────────────────────────────

def _analyze_token(token, email=None, response_timestamp=None):
    """Analyze a single token. Returns list of (severity, description) findings."""
    results = []
    entropy = _shannon_entropy(token)

    # --- JWT ---
    jwt_data = _is_jwt(token)
    if jwt_data:
        alg = jwt_data["header"].get("alg", "")
        results.append(("INFO", f"JWT detected | alg: {alg}"))
        results.append(("INFO", f"  header: {json.dumps(jwt_data['header'])}"))
        results.append(("INFO", f"  payload: {json.dumps(jwt_data['payload'])}"))

        if alg.lower() == "none":
            results.append(("CRITICAL", "alg:none → signature not verified, token forgeable"))
        elif alg.upper().startswith("HS"):
            results.append(("MEDIUM", f"{alg} → test key confusion RS256→HS256 and weak secrets"))

        if email:
            for k, v in jwt_data["payload"].items():
                if isinstance(v, str) and email.lower() in v.lower():
                    results.append(("HIGH", f"email found in JWT payload: {k}={v}"))
        return results

    # --- PHP uniqid ---
    uniqid_ts = _reverse_php_uniqid(token)
    if uniqid_ts:
        human = datetime.fromtimestamp(uniqid_ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")
        results.append(("CRITICAL", f"PHP uniqid() → timestamp: {human}"))
        results.append(("CRITICAL", "token = hex(seconds) + hex(microseconds), predictable via sandwich attack"))
        results.append(("INFO", "→ use: reset-tolkien detect {token} -d \"{Date header}\""))
        return results

    # --- MongoDB ObjectID ---
    mongo = _reverse_mongodb_objectid(token)
    if mongo:
        human = datetime.fromtimestamp(mongo["timestamp"], tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        results.append(("CRITICAL", f"MongoDB ObjectID → ts: {human} | process: {hex(mongo['process'])} | counter: {mongo['counter']}"))
        results.append(("CRITICAL", "timestamp + process + sequential counter → predictable"))
        return results

    # --- UUID v1 ---
    uuid_ver = _detect_uuid_version(token)
    if uuid_ver == 1:
        results.append(("HIGH", "UUID v1 → contains timestamp + MAC address, predictable"))
        return results
    elif uuid_ver == 4:
        results.append(("OK", "UUID v4 → random, no weakness detected"))
        return results

    # --- Time-based hash (Reset Tolkien style) ---
    if response_timestamp:
        tb = _check_time_based_hashes(token, response_timestamp, email=email)
        if tb:
            human = datetime.fromtimestamp(tb["timestamp"], tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")
            results.append(("CRITICAL", f"time-based hash: token = {tb['match']}"))
            results.append(("CRITICAL", f"generation timestamp: {human}"))
            results.append(("CRITICAL", "predictable → sandwich attack for ATO"))
            return results

    # --- Hash of email ---
    if email:
        for algo in ["md5", "sha1", "sha256"]:
            for val in [email, email.lower(), email.split("@")[0]]:
                h = hashlib.new(algo, val.encode()).hexdigest()
                if token.lower() == h.lower():
                    results.append(("CRITICAL", f"token = {algo}({val}) → trivially reproducible for any user"))
                    return results

    # --- Numeric OTP ---
    if token.isdigit():
        n = len(token)
        if n <= 4:
            results.append(("CRITICAL", f"{n}-digit OTP → {10**n} combinations, bruteforceable"))
        elif n <= 6:
            results.append(("HIGH", f"{n}-digit OTP → {10**n} combinations"))
        else:
            results.append(("MEDIUM", f"{n}-digit numeric token"))
        return results

    # --- Low entropy (catch-all) ---
    if entropy < 2.5:
        results.append(("HIGH", f"very low entropy: {entropy} bits/char → likely predictable"))
    elif entropy < 3.5:
        results.append(("MEDIUM", f"low entropy: {entropy} bits/char"))

    return results


def _compare_tokens(tokens, timestamps=None):
    """Compare multiple tokens for predictability. Only report impactful findings."""
    results = []

    if len(set(tokens)) < len(tokens):
        results.append(("CRITICAL", "identical tokens across requests → token not regenerated"))

    # Sequential hex
    try:
        ints = [int(t, 16) for t in tokens if all(c in "0123456789abcdef" for c in t.lower())]
        if len(ints) >= 2:
            diffs = [ints[i+1] - ints[i] for i in range(len(ints)-1)]
            if all(d == diffs[0] for d in diffs) and diffs[0] != 0:
                results.append(("CRITICAL", f"sequential tokens (constant diff={diffs[0]}) → next token predictable"))
            elif max(diffs) - min(diffs) < 100:
                results.append(("HIGH", f"near-sequential tokens (diff range: {min(diffs)}-{max(diffs)})"))
    except ValueError:
        pass

    # Uniqid timing
    uniqid_ts = [_reverse_php_uniqid(t) for t in tokens]
    uniqid_ts = [ts for ts in uniqid_ts if ts is not None]
    if len(uniqid_ts) >= 2:
        diffs_us = [int((uniqid_ts[i+1] - uniqid_ts[i]) * 1000000) for i in range(len(uniqid_ts)-1)]
        results.append(("CRITICAL", f"uniqid timestamps: diffs {diffs_us}µs → sandwich attack window confirmed"))

    return results


# ─── Main entry point ─────────────────────────────────────────────────────────

def token_analysis(url, parsed_req, baseline, interact, email, proxy=None):
    """
    Token leakage detection + quality analysis.

    Phase 1: Detect if the reset token leaks in the HTTP response (JSON body, Location, headers)
             → Impact: direct ATO without access to victim's email
    Phase 2: If tokens found, analyze for predictability (time-based, weak hash, low entropy)
             → Impact: token forgeable via sandwich attack or brute force
    Phase 3: Compare tokens across requests for sequential/predictable patterns
    """
    print(f"{Colors.CYAN} ├ Token analysis{Colors.RESET}")

    original_host = parsed_req["host"]
    method = parsed_req["method"]
    path = parsed_req["path"]
    body = parsed_req["body"]
    headers = dict(parsed_req["headers"])
    scheme = "https" if "https" in url else "http"

    uri = f"{scheme}://{original_host}{path}"
    proxies = {"http": proxy, "https": proxy} if proxy else None

    victim_email = None
    match = re.search(EMAIL_REGEX, body or "", re.IGNORECASE)
    if match:
        victim_email = match.group(0)

    # --- Phase 1: Token leakage ---
    print(f"{Colors.CYAN} └─ Token leakage detection{Colors.RESET}")

    all_tokens = []
    NUM_REQUESTS = 3

    for i in range(NUM_REQUESTS):
        try:
            resp = requests.request(
                method=method, url=uri, headers=headers,
                data=body or None, verify=False, allow_redirects=False,
                timeout=10, proxies=proxies,
            )
            resp_ts = _get_response_timestamp(resp)
            extracted = _extract_tokens_from_response(resp)

            if extracted:
                for token, source in extracted:
                    if baseline.get("body") and token in baseline["body"]:
                        continue
                    all_tokens.append((token, source, i + 1, resp_ts))
                    print(f"{Colors.RED}   └── [+] TOKEN IN RESPONSE | {source} | req #{i+1}{Colors.RESET}")
                    print(f"{Colors.RED}       → {token[:100]}{'...' if len(token) > 100 else ''}{Colors.RESET}")
                    print(f"{Colors.RED}       impact: ATO — token accessible without victim's email{Colors.RESET}")

            if i < NUM_REQUESTS - 1:
                time.sleep(0.5)

        except requests.RequestException:
            pass

    if not all_tokens:
        print(f"{Colors.YELLOW}   └── [-] No token leakage in response{Colors.RESET}")

    # --- Phase 2: Token quality ---
    if all_tokens:
        print(f"{Colors.CYAN} └─ Token quality{Colors.RESET}")

        seen = set()
        unique_tokens = []
        for token, source, req_num, resp_ts in all_tokens:
            if token not in seen:
                seen.add(token)
                unique_tokens.append((token, source, req_num, resp_ts))

        for token, source, req_num, resp_ts in unique_tokens:
            findings = _analyze_token(token, email=victim_email, response_timestamp=resp_ts)

            if not findings:
                continue

            # Only print if there's something impactful (not just "OK")
            has_impact = any(sev in ("CRITICAL", "HIGH", "MEDIUM") for sev, _ in findings)
            if not has_impact:
                continue

            token_display = token[:80] + ('...' if len(token) > 80 else '')
            print(f"{Colors.CYAN}   └── {token_display}{Colors.RESET}")

            for severity, desc in findings:
                if severity == "CRITICAL":
                    print(f"{Colors.RED}       [{severity}] {desc}{Colors.RESET}")
                elif severity == "HIGH":
                    print(f"{Colors.YELLOW}       [{severity}] {desc}{Colors.RESET}")
                elif severity == "MEDIUM":
                    print(f"{Colors.YELLOW}       [{severity}] {desc}{Colors.RESET}")
                elif severity == "INFO":
                    print(f"{Colors.CYAN}       {desc}{Colors.RESET}")

        # --- Phase 3: Token comparison ---
        if len(unique_tokens) >= 2:
            print(f"{Colors.CYAN} └─ Token comparison ({len(unique_tokens)} tokens){Colors.RESET}")
            raw_tokens = [t for t, _, _, _ in unique_tokens]
            comparisons = _compare_tokens(raw_tokens)

            if comparisons:
                for severity, desc in comparisons:
                    c = Colors.RED if severity == "CRITICAL" else Colors.YELLOW
                    print(f"{c}   └── [{severity}] {desc}{Colors.RESET}")
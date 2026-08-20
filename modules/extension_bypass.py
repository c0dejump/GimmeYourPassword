#!/usr/bin/env python3
import sys
sys.dont_write_bytecode = True

import secrets

from utils.style import Colors
from utils.utils import requests, urlparse
from utils import live


# Statuses that mean "the base path is gated" (ACL/WAF/auth/route). If a suffixed
# variant flips one of these to a 2xx/3xx, that's an access-control bypass.
_GATED = {401, 403, 404, 405, 406, 429, 500, 501, 502, 503}


def _variants(path):
    """Path/extension tricks that commonly slip past exact-match ACL/WAF/route rules."""
    if "?" in path:
        base, _, qs = path.partition("?")
        qs = "?" + qs
    else:
        base, qs = path, ""
    base = base.rstrip()
    exts = [".json", ".xml", ".html", ".js", ".css", ".txt", ".php", ".do", ".action", "..;/"]
    out = []
    for e in exts:
        out.append((f"{base}{e}{qs}", f"suffix {e}"))
    out += [
        (f"{base}/{qs}", "trailing /"),
        (f"{base}//{qs}", "double //"),
        (f"{base}/.{qs}", "trailing /."),
        (f"{base}%2e{qs}", "trailing %2e"),
        (f"{base};.json{qs}", "matrix ;.json"),
        (f"{base};{qs}", "trailing ;"),
        (f"{base}%20{qs}", "trailing %20"),
        (f"{base}%09{qs}", "trailing tab"),
        (f"//{base.lstrip('/')}{qs}", "leading //"),
        # NOTE: no '#'-fragment variant. A fragment is stripped client-side and never
        # transmitted, so `/graph#.json?qs` collapses to `/graph` (losing BOTH the
        # suffix and the query). That is not an ACL/suffix test — it just hits the
        # bare path, which reliably produced a false "gated 403 → 200 bypass".
    ]
    # de-dup while preserving order
    seen, uniq = set(), []
    for p, tag in out:
        if p not in seen and p != path:
            seen.add(p)
            uniq.append((p, tag))
    return uniq


def extension_bypass(url, parsed_req, baseline, interact, email, proxy=None):
    """
    Path extension / suffix ACL-bypass (HackTricks .json trick).

    Appends .json/.xml//, ;.json, %2e … to the reset path. If the base path is
    gated (WAF/ACL/auth) and a variant flips it to a 2xx/3xx → access-control
    bypass. On an already-public endpoint it flags variants that return a
    materially different body (alternate representation / parser differential).
    """
    print(f"{Colors.CYAN} ├ Path extension / ACL bypass{Colors.RESET}")

    method = parsed_req["method"]
    path = parsed_req["path"]
    body = parsed_req["body"]
    headers = dict(parsed_req["headers"])
    original_host = parsed_req["host"]
    scheme = urlparse(url).scheme or ("https" if "https" in (url or "") else "http")
    proxies = {"http": proxy, "https": proxy} if proxy else None

    def _send(vpath):
        return requests.request(
            method=method, url=f"{scheme}://{original_host}{vpath}", headers=headers,
            data=body or None, verify=False, allow_redirects=False, timeout=15, proxies=proxies,
        )

    def _sig(status, length):
        return (status, length // 50)  # bucket length to absorb minor jitter

    base_status = baseline.get("status")
    base_gated = base_status in _GATED
    base_sig = _sig(base_status, baseline.get("body_length") or 0)

    # Control: a definitely-unknown sibling path shows how the app answers "not a
    # real route" (often a blanket 302/404). Variants that merely match THAT are
    # the generic unknown-path handler, not a bypass — so we suppress them.
    if "?" in path:
        b, _, qs = path.partition("?"); qs = "?" + qs
    else:
        b, qs = path, ""
    try:
        ctrl = _send(f"{b}-gyp{secrets.token_hex(3)}{qs}")
        ctrl_sig = _sig(ctrl.status_code, len(ctrl.text))
    except requests.RequestException:
        ctrl_sig = None

    # What the client will ACTUALLY put on the request line for the untouched path
    # (fragments stripped, dot-segments normalised, etc.). Any variant that collapses
    # to this — i.e. its mutation never reaches the wire — is not a real suffix test.
    def _wire_target(vpath):
        try:
            return requests.Request(method, f"{scheme}://{original_host}{vpath}").prepare().path_url
        except Exception:
            return vpath
    base_wire = _wire_target(path)
    bare_wire = _wire_target(b)  # path without its query string

    groups = {}  # sig -> [(tag, vpath, status, len)]
    for vpath, tag in _variants(path):
        wire = _wire_target(vpath)
        if wire == base_wire or wire == bare_wire:
            continue  # mutation didn't survive to the wire (e.g. fragment) → not a test
        try:
            live.testing(f"ext-bypass {tag}")
            resp = _send(vpath)
        except requests.RequestException:
            continue
        sig = _sig(resp.status_code, len(resp.text))
        if sig == base_sig or sig == ctrl_sig:
            continue  # same as base, or same as generic unknown-path → not a bypass
        groups.setdefault(sig, []).append((tag, vpath, resp.status_code, len(resp.text)))

    if not groups:
        msg = "no ACL/WAF bypass" if base_gated else "no representation/parser differential"
        print(f"{Colors.GREEN}   └── [-] {msg} via path suffixes (control-normalised){Colors.RESET}")
        return

    for (status, _bucket), items in groups.items():
        tag, vpath, code, ln = items[0]
        extra = f" (×{len(items)})" if len(items) > 1 else ""
        if base_gated and code < 400:
            print(f"{Colors.RED}   └── [HIGH] gated base ({base_status}) → {code} via '{tag}'{extra} "
                  f"→ ACL/WAF bypass | {vpath}{Colors.RESET}")
        else:
            print(f"{Colors.YELLOW}   └── [INFO] '{tag}'{extra} → {base_status}→{code} ({ln}b), "
                  f"differs from base & unknown-path control | {vpath}{Colors.RESET}")

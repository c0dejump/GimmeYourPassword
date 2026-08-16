#!/usr/bin/env python3

import sys
sys.dont_write_bytecode = True

from datetime import datetime
import time

# utils
from cli import args
from utils.style import Colors
from utils.utils import (
    requests,
    parse_headers,
    urllib3,
    re,
    traceback,
    parse_raw_request,
    baseline_is_rate_limited,
    detect_anti_automation,
    classify_reset_flow,
    baseline_looks_error,
    detect_bearer_expiry,
)
from utils.requests_settings import send_baseline
from utils import live
from utils.disposable_mail import create_inbox

from modules.parameters_pollution import parameters_pollution
from modules.hhip import hhip
from modules.absolute_uri_injection import absolute_uri_injection
from modules.token_analysis import token_analysis
from modules.token_reuse import token_reuse
from modules.method_override import method_override
from modules.otp_bruteforce import otp_bruteforce
from modules.idor import idor
from modules.user_enum import user_enum
from modules.race_condition import race_condition
from modules.csrf import csrf
from modules.rate_limit_bypass import rate_limit_bypass
from modules.referrer_manipulation import referrer_manipulation
from modules.graphql import graphql
from modules.callback_url import callback_url
from modules.param_discovery import param_discovery
from modules.mail_analysis import mail_analysis
from modules.token_analysis import analyze_reset_material


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# Global variables for CLI arguments
human: str | None = None
custom_header: list[str] | None = None



def process_modules(url, parsed_req, interact, baseline, email, human, proxy=None, mail_wait=30, mailbox=None):
    # `baseline` is the clean, first-request baseline captured before any traffic.
    clean_baseline = baseline
    _rl_warned = {"done": False}

    def fresh():
        """Re-baseline right before a module so status/length diffs reflect the
        CURRENT server state (e.g. after rate-limiting kicks in) instead of the
        stale first response — this is what prevents false-positive cascades."""
        b = send_baseline(url, parsed_req, proxy)
        if b.get("status") is None:
            return clean_baseline  # transient network error: keep clean baseline
        if (not _rl_warned["done"]
                and baseline_is_rate_limited(b)
                and not baseline_is_rate_limited(clean_baseline)):
            live.clear()
            print(f"{Colors.YELLOW}[!] Target now looks rate-limited/altered vs start "
                  f"— re-baselining against current state to limit false positives{Colors.RESET}")
            _rl_warned["done"] = True
        return b

    def run(fn, *args):
        """Isolate each module: one crash must not abort the whole scan."""
        try:
            fn(*args)
        except KeyboardInterrupt:
            raise
        except Exception as e:
            live.clear()
            print(f"{Colors.RED}[!] module '{getattr(fn, '__name__', fn)}' error: {e}{Colors.RESET}")

    run(hhip, url, human, parsed_req, fresh(), interact, proxy)
    run(parameters_pollution, url, human, parsed_req, fresh(), interact, email, proxy)
    run(absolute_uri_injection, url, human, parsed_req, fresh(), interact, proxy)
    run(graphql, url, parsed_req, fresh(), interact, email, proxy)
    run(token_analysis, url, parsed_req, fresh(), interact, email, proxy)
    run(token_reuse, url, parsed_req, fresh(), interact, email, proxy)
    run(method_override, url, parsed_req, fresh(), interact, email, proxy)
    # Only fires when the request is a code/OTP submission (short numeric code
    # field); otherwise it self-skips. Bounded + stops on lockout by design.
    run(otp_bruteforce, url, parsed_req, fresh(), interact, email, proxy)
    run(csrf, url, parsed_req, fresh(), interact, email, proxy)
    run(idor, url, parsed_req, fresh(), interact, email, proxy)
    run(user_enum, url, parsed_req, fresh(), interact, email, proxy)
    run(race_condition, url, parsed_req, fresh(), interact, email, proxy)
    # rate_limit_bypass needs the pre-traffic baseline to tell "limited" from "normal"
    run(rate_limit_bypass, url, parsed_req, clean_baseline, interact, email, proxy)
    run(callback_url, url, parsed_req, fresh(), interact, email, proxy)
    run(param_discovery, url, parsed_req, fresh(), interact, email, proxy)
    run(referrer_manipulation, url, human, parsed_req, fresh(), interact, proxy)
    # Runs last: give every reset-triggering payload time to deliver before we poll
    # the SMTP sink for the hijacked email. Uses clean_baseline (no extra request).
    run(mail_analysis, url, parsed_req, clean_baseline, interact, email, proxy, mail_wait, mailbox)



def cli_main() -> None:
    """Entry point for the CLI command."""
    parser = args()

    global human, custom_header

    url = parser.url
    rawrequest = parser.rawrequest
    interact = parser.interact
    email = parser.email
    custom_header = parser.custom_header
    user_agent = parser.user_agent
    humans = parser.humans
    proxy_arg = parser.proxy
    burp_arg = parser.burp
    mail_wait = parser.mail_wait
    disposable_mail = parser.disposable_mail
    reset_url = parser.reset_url

    human = humans
    start_time_report = time.time()

    live.enable()

    # Provision a throwaway inbox and use it as the attacker address (-e).
    mailbox = None
    if disposable_mail:
        print(f"{Colors.CYAN}[*] Provisioning disposable inbox (mail.tm)...{Colors.RESET}")
        mailbox = create_inbox()
        if mailbox:
            email = mailbox.address
            print(f"{Colors.GREEN}[+] Disposable inbox: {email}{Colors.RESET}")
            print(f"{Colors.GREEN}[+] Webmail: {mailbox.webmail_url}  "
                  f"(login: {mailbox.address} / {mailbox.password}){Colors.RESET}")
        else:
            print(f"{Colors.RED}[!] Could not create disposable inbox — falling back to -e/{email}{Colors.RESET}")

    try:
        if rawrequest:
            print(f"{Colors.BLUE} ⟙{Colors.RESET}")

            print(f"\n{Colors.CYAN}[*] Parsing: {rawrequest}{Colors.RESET}")
            parsed_req = parse_raw_request(rawrequest)

            # Apply CLI overrides after parsing
            if custom_header:
                extra = parse_headers(custom_header)
                parsed_req["headers"].update(extra)
            if user_agent:
                for k in list(parsed_req["headers"].keys()):
                    if k.lower() == "user-agent":
                        del parsed_req["headers"][k]
                        break
                parsed_req["headers"]["User-Agent"] = user_agent

            print(f"{Colors.GREEN}[+] {parsed_req['method']} {parsed_req['path']}{Colors.RESET}")
            print(f"{Colors.GREEN}[+] Host: {parsed_req['host']}{Colors.RESET}")
            if parsed_req["body"]:
                print(f"{Colors.GREEN}[+] Body: {parsed_req['body'][:100]}{'...' if len(parsed_req['body']) > 100 else ''}{Colors.RESET}")

            baseline = send_baseline(url, parsed_req, proxy_arg)
            print(f"{Colors.CYAN}[*] baseline response: {baseline['status']}{Colors.RESET}")

            _err = baseline_looks_error(baseline)
            if _err:
                print(f"{Colors.RED}[!] Baseline looks like an ERROR/auth rejection ({_err}): the endpoint "
                      f"isn't processing the reset — findings below are UNRELIABLE.{Colors.RESET}")
                print(f"{Colors.RED}    → Re-capture a fresh, authenticated request (valid token, required headers like Locale).{Colors.RESET}")

            _bexp = detect_bearer_expiry(parsed_req)
            if _bexp and _bexp[0] in ("expired", "expiring"):
                mins = abs(_bexp[1]) // 60
                if _bexp[0] == "expired":
                    print(f"{Colors.RED}[!] Authorization Bearer token is EXPIRED (~{mins} min ago): "
                          f"the whole scan will hit auth errors. Capture a fresh request first.{Colors.RESET}")
                else:
                    print(f"{Colors.YELLOW}[!] Authorization Bearer token expires in ~{_bexp[1]}s: "
                          f"it will likely die mid-scan and invalidate later findings.{Colors.RESET}")

            markers = detect_anti_automation(parsed_req)
            if markers:
                print(f"{Colors.RED}[!] Anti-automation detected ({', '.join(sorted(set(markers)))}): "
                      f"the token is single-use — every replayed request after the baseline is likely "
                      f"rejected server-side while still returning 200.{Colors.RESET}")
                print(f"{Colors.RED}    → Treat response-based 'confirmed' findings (method override, "
                      f"CSRF-bypass, pollution) as UNRELIABLE. Confirm via OOB email (--disposable-mail).{Colors.RESET}")

            if classify_reset_flow(baseline) == "code":
                print(f"{Colors.YELLOW}[i] Code/OTP-based reset flow detected (no emailed link): "
                      f"Host/X-Forwarded-Host LINK poisoning is structurally N/A here.{Colors.RESET}")
                print(f"{Colors.YELLOW}    → Focus on: OTP strength (length/entropy/rate-limit/reuse) and "
                      f"email-header injection (extra recipient/CC via the email field).{Colors.RESET}")

            print(f"{Colors.BLUE} ⟘{Colors.RESET}")
            print(f"{Colors.BLUE} ⟙{Colors.RESET}")

            # Analyze a reset token/URL pasted from the received email — the token
            # lives in the mail, never in the HTTP response, so this is the only way
            # to audit it without OOB capture.
            if reset_url:
                _vm = re.search(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", parsed_req.get("body") or "")
                analyze_reset_material(reset_url, victim_email=_vm.group(0) if _vm else None)

            process_modules(url, parsed_req, interact, baseline, email, human, proxy_arg, mail_wait, mailbox)
        else:
            print("Please define a request file with -r option")
            sys.exit()
    except KeyboardInterrupt:
        print("Exiting")
        sys.exit()
    except Exception as e:
        traceback.print_exc()
        print(f"Error : {e}")
    print("")


if __name__ == '__main__':
    cli_main()
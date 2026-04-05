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
    parse_raw_request
)
from utils.requests_settings import send_baseline

from modules.parameters_pollution import parameters_pollution
from modules.hhip import hhip
from modules.absolute_uri_injection import absolute_uri_injection
from modules.token_analysis import token_analysis
from modules.method_override import method_override
from modules.email_hijack import email_hijack


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# Global variables for CLI arguments
human: str | None = None
custom_header: list[str] | None = None



def process_modules(url, parsed_req, interact, baseline, email, human, proxy=None):
    hhip(url, human, parsed_req, baseline, interact, proxy)
    parameters_pollution(url, human, parsed_req, baseline, interact, email, proxy)
    absolute_uri_injection(url, human, parsed_req, baseline, interact, proxy)
    email_hijack(url, human, parsed_req, baseline, interact, email, proxy)
    token_analysis(url, parsed_req, baseline, interact, email, proxy)
    method_override(url, parsed_req, baseline, interact, email, proxy)



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

    human = humans
    start_time_report = time.time()

    try:
        if rawrequest:
            print(f"{Colors.BLUE} ⟙{Colors.RESET}")

            print(f"\n{Colors.CYAN}[*] Parsing: {rawrequest}{Colors.RESET}")
            parsed_req = parse_raw_request(rawrequest)

            print(f"{Colors.GREEN}[+] {parsed_req['method']} {parsed_req['path']}{Colors.RESET}")
            print(f"{Colors.GREEN}[+] Host: {parsed_req['host']}{Colors.RESET}")
            if parsed_req["body"]:
                print(f"{Colors.GREEN}[+] Body: {parsed_req['body'][:100]}{'...' if len(parsed_req['body']) > 100 else ''}{Colors.RESET}")

            baseline = send_baseline(url, parsed_req, proxy_arg)
            print(f"{Colors.CYAN}[*] baseline response: {baseline['status']}{Colors.RESET}")

            print(f"{Colors.BLUE} ⟘{Colors.RESET}")
            print(f"{Colors.BLUE} ⟙{Colors.RESET}")

        process_modules(url, parsed_req, interact, baseline, email, human, proxy_arg)


    except KeyboardInterrupt:
        print("Exiting")
        sys.exit()
    except Exception as e:
        traceback.print_exc()
        print(f"Error : {e}")
    print("")


if __name__ == '__main__':
    cli_main()
#!/usr/bin/env python3

import argparse  # noqa: F401
import random
import re  # noqa: F401
import os
import socket
import ssl
import string
import sys
import time
import json
import traceback  # noqa: F401
from urllib.parse import (
    urljoin,  # noqa: F401
    urlparse,
)
import requests
import urllib3
from bs4 import BeautifulSoup
from bs4 import XMLParsedAsHTMLWarning

from utils.style import spinner

import requests.utils

import warnings
warnings.filterwarnings("ignore", category=XMLParsedAsHTMLWarning)

def _noop_check_header_validity(header, value=None):
    return None

requests.utils.check_header_validity = _noop_check_header_validity

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


CONTENT_DELTA_RANGE = 500
BIG_CONTENT_DELTA_RANGE = 5000

EMAIL_REGEX = r"[a-zA-Z0-9._%+-]+(?:@|%40)[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"

CANARY = "toto132"

## url tranformation ##
def get_domain_from_url(url: str) -> str:
    domain = urlparse(url).netloc
    return domain


def get_ip_from_url(url: str) -> str:
    domain = get_domain_from_url(url)
    ip = socket.gethostbyname(domain)
    return ip



## Timing requests ##

def human_time(human: str) -> None:
    if human.isdigit():
        time.sleep(int(human))
    elif human.lower() == "r" or human.lower() == "random":
        time.sleep(random.randrange(6))  # nosec B311
    else:
        pass



## Anti FP ##

def range_exclusion(main_len):
    range_exlusion = (
        range(main_len - CONTENT_DELTA_RANGE, main_len + CONTENT_DELTA_RANGE)
        if main_len < 10000
        else range(
            main_len - BIG_CONTENT_DELTA_RANGE,
            main_len + BIG_CONTENT_DELTA_RANGE,
        )
    )
    return range_exlusion


def fp_baseline(url, s):
    uri = f"{url}{random.randint(1, 99)}"
    headers = {"X-Random-azertyuiop":"azertyuiop"}
    req = s.get(uri, headers=headers, allow_redirects=False, timeout=10)

    fp_base_status = req.status_code
    fp_base_len = len(req.content)
    return fp_base_status, fp_base_len
    

## requests settings ##

def parse_headers(header_list: list[str] | None) -> dict[str, str]:
    headers = {}
    if header_list:
        for header in header_list:
            if ":" in header:
                key, value = header.split(":", 1)
                headers[key.strip()] = value.strip()
    return headers
    


def parse_raw_request(filepath):
    with open(filepath, "r") as f:
        raw = f.read()

    parts = raw.split("\n\n", 1)
    header_section = parts[0]
    body = parts[1].strip() if len(parts) > 1 else ""

    lines = header_section.strip().split("\n")
    request_line = lines[0].strip()
    match = re.match(
        r"^(GET|POST|PUT|PATCH|DELETE|OPTIONS)\s+(\S+)\s+HTTP/[\d.]+$",
        request_line,
    )
    if not match:
        print(f"{Colors.RED}[!] Invalid request line: {request_line}{Colors.RESET}")
        sys.exit(1)

    method = match.group(1)
    path = match.group(2)

    headers = {}
    original_host = None
    for line in lines[1:]:
        line = line.strip()
        if not line:
            continue
        if ":" in line:
            key, val = line.split(":", 1)
            key, val = key.strip(), val.strip()
            if key.lower() == "host":
                original_host = val
            headers[key] = val

    if not original_host:
        print(f"{Colors.RED}[!] No Host header found in raw request{Colors.RESET}")
        sys.exit(1)

    return {"method": method, "path": path, "headers": headers, "body": body, "host": original_host}
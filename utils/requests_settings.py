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



def send_baseline(url, parsed_req, proxy=None):
    """Send the original unmodified request to establish a baseline response."""
    original_host = parsed_req["host"]
    method = parsed_req["method"]
    path = parsed_req["path"]
    body = parsed_req["body"]
    headers = dict(parsed_req["headers"])
    scheme= "https" if "https" in url else "http"

    uri = f"{scheme}://{original_host}{path}"
    proxies = {"http": proxy, "https": proxy} if proxy else None

    try:
        resp = requests.request(
            method=method, url=uri, headers=headers,
            data=body or None, verify=False, allow_redirects=False,
            timeout=10, proxies=proxies,
        )
        return {
            "status": resp.status_code,
            "body": resp.text[:5000],
            "body_length": len(resp.text),
            "headers": dict(resp.headers),
            "error": None,
        }
    except requests.RequestException as e:
        return {"status": None, "body": "", "body_length": 0, "headers": {}, "error": str(e)}

        

def _raw_request(host, port, raw_data, use_ssl=False, timeout=10):
    """
    Send raw bytes via socket.
    Returns the raw response as string.
    """
    sock = socket.create_connection((host, port), timeout=timeout)
    if use_ssl:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        sock = ctx.wrap_socket(sock, server_hostname=host)
    try:
        sock.sendall(raw_data)
        chunks = []
        while True:
            try:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                chunks.append(chunk)
            except socket.timeout:
                break
        return b"".join(chunks).decode("utf-8", errors="replace")
    finally:
        sock.close()
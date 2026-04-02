#!/usr/bin/env python3
import time
import sys
import random
from datetime import datetime
from static.version import __version__, check_for_update



BANNER_TEXT = """
===============
GimmeYourPassword
===============
"""

SUBTITLE_TEMPLATE = "GimmeYourPassword (GYP) is a tool designed to perform tests on reset password features on websites and analyze the results to identify vulnerabilities and interesting behaviors."



def print_final_banner():
    #clear_full()
    print(BANNER_TEXT)

    subtitle = SUBTITLE_TEMPLATE.format(__version__)
    print()

    print(subtitle)

    print("\n")
    check_for_update(__version__)



def run_banner():
    print_final_banner()


if __name__ == "__main__":
    run_banner()

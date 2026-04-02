# GimmeYourPassword

<p align="center">
  <img src="./static/docs/_media/logo_v2_gif.gif" alt="Logo" width="520">
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
  <a href="https://github.com/c0dejump/GimmeYourPassword/#todo">🧠 TODO</a>
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
usage: gyp.py [-h] [-u URL] [-r RAWREQUEST] [-i INTERACT] [-e EMAIL] [-H CUSTOM_HEADER] [-A USER_AGENT]
              [-hu HUMANS] [-p [PROXY]] [--burp [BURP]]

options:
  -h, --help            show this help message and exit

> General:
  -u URL, --url URL     URL to test [required] if no -f/--file provided
  -r RAWREQUEST, --rawrequest RAWREQUEST
                        Raw request file path
  -i INTERACT, --interact INTERACT
                        controlled url or interact
  -e EMAIL, --email EMAIL
                        controlled email

> Request Settings:
  -H CUSTOM_HEADER, --header CUSTOM_HEADER
                        Add a custom HTTP Header
  -A USER_AGENT, --user-agent USER_AGENT
                        Add a custom User Agent
  -hu HUMANS, --humans HUMANS
                        Performs a timesleep to reproduce human behavior (Default: 0s) value: 'r' or 'random'

> Proxy Settings:
  -p [PROXY], --proxy [PROXY]
                        Proxy all requests through this proxy (format: host:port, default: 127.0.0.1:8080)
  --burp [BURP]         Send behavior and confirmed requests to Burp proxy (format: host:port, default:
                        127.0.0.1:8080)

```


## Examples

### Example on a public target
```python3 gyp.py -u "https://accounts.tesla.com/password/forgot" -r req_exemple.txt -i https://content-deposits-oct-linked.trycloudflare.com -e bbcodejump@gmail.com```



### TOOL TIPS
I use "cloudflared" on my exemples:
- Install it:
  ```curl -L https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64 -o cloudflared && chmod +x cloudflared```
- Run mini_interact.py
  ```python3 mini_interact.py```
- Run cloudflared
  ```./cloudflared tunnel --url http://localhost:8000```

## Features

- Host header injection/pollution
- Parameters pollution
- Absolute uri injection

## TODO


### Based on
- https://hacktricks.wiki/en/pentesting-web/reset-password.html
- https://web.archive.org/web/20250626114943/https://anugrahsr.github.io/posts/10-Password-reset-flaws/
- https://github.com/tuhin1729/Bug-Bounty-Methodology/blob/main/PasswordReset.md
- https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Account%20Takeover

## Contributing

Pull requests are welcome. Feel free to contribute to this tool and make improvements!
# GimmeYourPassword

<p align="center">
  <img src="./static/docs/_media/logo_v2_gif.gif" alt="Logo" width="520">
</p>

> GimmeYourPassword (GYP) is a tool designed to perform tests on reset password features on websites and analyze the results to identify vulnerabilities and interesting behaviors.

<div align="center">
<img src="https://img.shields.io/github/v/release/c0dejump/HExHTTP" alt="release version">
<img alt="Python3.7" src="https://img.shields.io/badge/Python-3.7+-informational">
</div>

<br>

<p align="center">
  <a href="https://github.com/c0dejump/HExHTTP/blob/main/CHANGELOG.md">📰 News</a> |
  <a href="https://github.com/c0dejump/HExHTTP/#installation">⚙️ Installation</a> |
  <a href="https://github.com/c0dejump/HExHTTP/#usage">💻 Usage</a> |
  <a href="https://github.com/c0dejump/HExHTTP/#exemples">🧩 Exemples</a> |
  <a href="https://github.com/c0dejump/HExHTTP/#features">🚀 Features</a> |
  <a href="https://github.com/c0dejump/HExHTTP/#todo">🧠 TODO</a>
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

### Arguments

```bash
python3 gyp.py -u "https://www[.]url[.]com" -r req_exemple.txt -i https://subdom.trycloudflare.com -e mail@gmail.co

```

## Examples

### Example on a public target
TODO



### TOOL TIPS
I use "cloudflared" on my exemples:
- Install it:
  ```curl -L https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64 -o cloudflared && chmod +x cloudflared```
- Run mini_interact.py
  ```python3 mini_interact.py```
- Run cloudflared
  ```./cloudflared tunnel --url http://localhost:8000```

## Features

TODO

## TODO


### Based on
TODO

## Contributing

Pull requests are welcome. Feel free to contribute to this tool and make improvements!
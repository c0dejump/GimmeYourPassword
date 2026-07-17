#!/usr/bin/env python3
"""
GimmeYourPassword — Vulnerable Lab
Realistic password-reset web app with intentional security flaws.
For authorized testing only.
"""
import math
import time
import hashlib
import string
import random
import threading
import secrets

from flask import (
    Flask, request, jsonify, render_template_string,
    redirect, url_for, session, make_response,
)

app = Flask(__name__)
app.secret_key = "gyp-lab-insecure-key"

# ─── In-memory state ──────────────────────────────────────────────────────────

USERS = {
    "victim@example.com": {
        "id": "1", "name": "Alice Martin",
        "password": "password123",
    },
    "bob@example.com": {
        "id": "2", "name": "Bob Dupont",
        "password": "letmein",
    },
    "admin@example.com": {
        "id": "99999", "name": "Admin",
        "password": "admin",
    },
}

# token → {"email": ..., "used": bool, "expires": float}
RESET_TOKENS: dict = {}

# rate-limit: ip → [count, window_start]
RATE_STATE: dict = {}
RATE_LOCK = threading.Lock()

# race-condition: last token (no lock)
RACE_LAST: dict = {"value": None, "ts": None}

# sequential counter for predictable tokens
_SEQ_COUNTER = 0


# ─── Token helpers ─────────────────────────────────────────────────────────────

def _php_uniqid() -> str:
    ts = time.time()
    sec = math.floor(ts)
    usec = round(1_000_000 * (ts - sec))
    return "%08x%05x" % (sec, usec)


def _secure_token(n: int = 32) -> str:
    return secrets.token_urlsafe(n)


def _email_md5(email: str) -> str:
    return hashlib.md5(email.lower().encode()).hexdigest()


def _client_ip() -> str:
    for hdr in ("X-Forwarded-For", "X-Real-IP", "X-Client-IP",
                "True-Client-IP", "CF-Connecting-IP"):
        val = request.headers.get(hdr)
        if val:
            return val.split(",")[0].strip()
    return request.remote_addr or "127.0.0.1"


def _parse_email() -> str:
    if request.is_json:
        return (request.get_json(silent=True) or {}).get("email", "")
    return request.form.get("email", "")


# ─── HTML templates ────────────────────────────────────────────────────────────

_BASE = """<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{{ title }} — Acme Corp</title>
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;
       background:#f5f7fa;min-height:100vh;display:flex;flex-direction:column;align-items:center;
       justify-content:center;color:#1a202c}
  .card{background:#fff;border-radius:12px;box-shadow:0 4px 24px rgba(0,0,0,.08);
        padding:2.5rem;width:100%;max-width:420px}
  .logo{text-align:center;margin-bottom:2rem}
  .logo .icon{font-size:2.5rem}
  .logo h1{font-size:1.4rem;font-weight:700;color:#1a202c;margin-top:.5rem}
  .logo p{font-size:.85rem;color:#718096;margin-top:.25rem}
  label{display:block;font-size:.8rem;font-weight:600;color:#4a5568;margin-bottom:.3rem;margin-top:1rem}
  input[type=email],input[type=password],input[type=text]{
        width:100%;padding:.65rem .9rem;border:1.5px solid #e2e8f0;border-radius:8px;
        font-size:.95rem;outline:none;transition:border .15s}
  input:focus{border-color:#4f46e5}
  .btn{display:block;width:100%;padding:.75rem;background:#4f46e5;color:#fff;
       border:none;border-radius:8px;font-size:.95rem;font-weight:600;cursor:pointer;
       margin-top:1.5rem;transition:background .15s;text-align:center;text-decoration:none}
  .btn:hover{background:#4338ca}
  .btn-ghost{background:transparent;color:#4f46e5;border:1.5px solid #4f46e5}
  .btn-ghost:hover{background:#eef2ff}
  .link{display:block;text-align:center;margin-top:1rem;font-size:.85rem;color:#4f46e5;
        text-decoration:none}
  .link:hover{text-decoration:underline}
  .alert{padding:.75rem 1rem;border-radius:8px;font-size:.875rem;margin-bottom:1rem}
  .alert-error{background:#fff5f5;border:1px solid #fed7d7;color:#c53030}
  .alert-success{background:#f0fff4;border:1px solid #c6f6d5;color:#276749}
  .divider{border:none;border-top:1px solid #e2e8f0;margin:1.5rem 0}
  .meta{font-size:.78rem;color:#a0aec0;text-align:center;margin-top:1.5rem}
  .meta a{color:#4f46e5}
  .tag{display:inline-block;font-size:.65rem;padding:.15rem .4rem;border-radius:4px;
       font-weight:700;margin-left:.4rem;vertical-align:middle}
  .tag-vuln{background:#fed7d7;color:#c53030}
  .code{font-family:monospace;background:#f7fafc;padding:.9rem 1rem;border-radius:8px;
        font-size:.8rem;word-break:break-all;border:1px solid #e2e8f0;margin-top:1rem;color:#2d3748}
</style>
</head>
<body>
{{ content | safe }}
<p class="meta" style="margin-top:1.5rem">
  GimmeYourPassword Lab &mdash; <a href="/">Accueil</a> &bull;
  <a href="/debug">Debug panel</a>
</p>
</body>
</html>"""


T_LOGIN = """
<div class="card">
  <div class="logo">
    <div class="icon">🔐</div>
    <h1>Acme Corp</h1>
    <p>Connectez-vous à votre compte</p>
  </div>
  {% if error %}<div class="alert alert-error">{{ error }}</div>{% endif %}
  <form method="POST" action="/login">
    <label>Adresse email</label>
    <input type="email" name="email" placeholder="vous@exemple.com"
           value="{{ email }}" required autofocus>
    <label>Mot de passe</label>
    <input type="password" name="password" placeholder="••••••••" required>
    <button class="btn" type="submit">Se connecter</button>
  </form>
  <a class="link" href="/forgot-password">Mot de passe oublié ?</a>
  <hr class="divider">
  <p style="font-size:.8rem;color:#718096;text-align:center">
    Comptes de test :<br>
    <code>victim@example.com</code> / <code>password123</code><br>
    <code>bob@example.com</code> / <code>letmein</code>
  </p>
</div>"""


T_FORGOT = """
<div class="card">
  <div class="logo">
    <div class="icon">📧</div>
    <h1>Réinitialiser le mot de passe</h1>
    <p>Entrez votre email pour recevoir un lien de réinitialisation</p>
  </div>
  {% if error %}<div class="alert alert-error">{{ error }}</div>{% endif %}
  <form method="POST" action="/forgot-password">
    <label>Adresse email <span class="tag tag-vuln">CSRF · HHIP · Rate-limit · Token</span></label>
    <input type="email" name="email" placeholder="vous@exemple.com"
           value="{{ email }}" required autofocus>
    <button class="btn" type="submit">Envoyer le lien</button>
  </form>
  <a class="link" href="/login">← Retour à la connexion</a>
  <hr class="divider">
  <p style="font-size:.78rem;color:#a0aec0;text-align:center">
    Endpoints alternatifs (GYP) :<br>
    <code>/api/v1/forgot-password</code> (JSON, IDOR)<br>
    <code>/admin/reset</code> · <code>/internal/reset</code> · <code>/debug/reset</code>
  </p>
</div>"""


T_EMAIL_SENT = """
<div class="card">
  <div class="logo">
    <div class="icon">✅</div>
    <h1>Email envoyé !</h1>
    <p>Vérifiez votre boîte de réception</p>
  </div>
  <div class="alert alert-success">
    Un lien de réinitialisation a été envoyé à <strong>{{ email }}</strong>.
  </div>
  {% if token %}
  <p style="font-size:.8rem;color:#c53030;font-weight:600;margin-top:1rem">
    ⚠️ [LAB] Token leakage — visible dans la réponse HTTP :
  </p>
  <div class="code">
    Token : <strong>{{ token }}</strong><br>
    Reset URL : <a href="/reset-password?token={{ token }}">/reset-password?token={{ token }}</a>
  </div>
  {% endif %}
  <a class="link" href="/forgot-password">Renvoyer l'email</a>
  <a class="link" href="/login">← Retour à la connexion</a>
</div>"""


T_RESET = """
<div class="card">
  <div class="logo">
    <div class="icon">🔑</div>
    <h1>Nouveau mot de passe</h1>
    <p>Choisissez un nouveau mot de passe pour votre compte</p>
  </div>
  {% if error %}<div class="alert alert-error">{{ error }}</div>{% endif %}
  {% if success %}<div class="alert alert-success">{{ success }}</div>{% endif %}
  {% if not success %}
  <form method="POST" action="/reset-password">
    <input type="hidden" name="token" value="{{ token }}">
    <label>Nouveau mot de passe <span class="tag tag-vuln">Token reuse</span></label>
    <input type="password" name="password" placeholder="••••••••" required>
    <label>Confirmer le mot de passe</label>
    <input type="password" name="password2" placeholder="••••••••" required>
    <button class="btn" type="submit">Réinitialiser</button>
  </form>
  {% endif %}
  <a class="link" href="/login">← Retour à la connexion</a>
</div>"""


T_DASHBOARD = """
<div class="card">
  <div class="logo">
    <div class="icon">👤</div>
    <h1>Tableau de bord</h1>
    <p>Bienvenue, {{ name }}</p>
  </div>
  <div class="alert alert-success">Connexion réussie en tant que {{ email }}</div>
  <a class="btn btn-ghost" href="/logout" style="margin-top:1rem">Se déconnecter</a>
  <hr class="divider">
  <p style="font-size:.8rem;color:#718096;text-align:center">
    Session active — user_id : <code>{{ uid }}</code>
  </p>
</div>"""


T_DEBUG = """
<div class="card" style="max-width:700px">
  <div class="logo">
    <div class="icon">🧪</div>
    <h1>GYP Lab — Debug panel</h1>
    <p>Vue interne de l'état du lab</p>
  </div>
  <h3 style="margin-top:1.5rem;font-size:.95rem;color:#4a5568">Tokens de reset actifs</h3>
  {% if tokens %}
  <table style="width:100%;border-collapse:collapse;font-size:.78rem;margin-top:.5rem">
    <tr style="background:#f7fafc">
      <th style="padding:.4rem;text-align:left;border:1px solid #e2e8f0">Token</th>
      <th style="padding:.4rem;border:1px solid #e2e8f0">Email</th>
      <th style="padding:.4rem;border:1px solid #e2e8f0">Utilisé</th>
      <th style="padding:.4rem;border:1px solid #e2e8f0">Expire</th>
    </tr>
    {% for t, info in tokens.items() %}
    <tr>
      <td style="padding:.4rem;border:1px solid #e2e8f0;word-break:break-all">
        <a href="/reset-password?token={{ t }}" style="color:#4f46e5">{{ t[:30] }}…</a>
      </td>
      <td style="padding:.4rem;border:1px solid #e2e8f0">{{ info.email }}</td>
      <td style="padding:.4rem;border:1px solid #e2e8f0">{{ "oui" if info.used else "non" }}</td>
      <td style="padding:.4rem;border:1px solid #e2e8f0">{{ info.expires|int }}</td>
    </tr>
    {% endfor %}
  </table>
  {% else %}
  <p style="font-size:.8rem;color:#a0aec0;margin-top:.5rem">Aucun token actif.</p>
  {% endif %}

  <h3 style="margin-top:1.5rem;font-size:.95rem;color:#4a5568">Modules GYP à tester</h3>
  <table style="width:100%;border-collapse:collapse;font-size:.78rem;margin-top:.5rem">
    <tr style="background:#f7fafc">
      <th style="padding:.4rem;text-align:left;border:1px solid #e2e8f0">Module</th>
      <th style="padding:.4rem;text-align:left;border:1px solid #e2e8f0">Endpoint cible</th>
      <th style="padding:.4rem;text-align:left;border:1px solid #e2e8f0">Fichier exemple</th>
    </tr>
    {% for row in modules %}
    <tr>
      <td style="padding:.4rem;border:1px solid #e2e8f0;font-weight:600">{{ row[0] }}</td>
      <td style="padding:.4rem;border:1px solid #e2e8f0"><code>{{ row[1] }}</code></td>
      <td style="padding:.4rem;border:1px solid #e2e8f0"><code>{{ row[2] }}</code></td>
    </tr>
    {% endfor %}
  </table>
</div>"""


def _render(template, title="Acme Corp", **ctx):
    inner = render_template_string(template, **ctx)
    return render_template_string(_BASE, title=title, content=inner)


# ─── Auth pages ───────────────────────────────────────────────────────────────

@app.route("/")
def root():
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    error = ""
    email = ""
    if request.method == "POST":
        email = request.form.get("email", "")
        pwd   = request.form.get("password", "")
        user  = USERS.get(email)
        if user and user["password"] == pwd:
            session["email"] = email
            session["uid"]   = user["id"]
            session["name"]  = user["name"]
            return redirect(url_for("dashboard"))
        error = "Email ou mot de passe incorrect."
    return _render(T_LOGIN, "Connexion", error=error, email=email)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/dashboard")
def dashboard():
    if "email" not in session:
        return redirect(url_for("login"))
    return _render(T_DASHBOARD, "Tableau de bord",
                   name=session["name"],
                   email=session["email"],
                   uid=session["uid"])


# ─── Forgot password (main GYP target) ───────────────────────────────────────
#
#  Vulnerabilities baked in :
#   · CSRF          — no CSRF token, cross-origin accepted
#   · HHIP          — Host / X-Forwarded-Host used in reset URL
#   · Referrer manip— Referer/Origin used as fallback base URL
#   · Rate-limit bypass — keyed on spoofable X-Forwarded-For
#   · Token leakage — token returned in JSON + HTML response
#   · Weak token    — PHP-uniqid-style (predictable)
#   · Email hijack  — loose validation, arrays / whitespace accepted
#   · Token reuse   — /reset-password never invalidates the token

@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "GET":
        return _render(T_FORGOT, "Mot de passe oublié", error="", email="")

    # ── Rate-limit (bypassable via spoofed IP header) ──────────────────────
    ip  = _client_ip()
    now = time.time()
    with RATE_LOCK:
        count, win = RATE_STATE.get(ip, (0, now))
        if now - win > 60:
            count, win = 0, now
        count += 1
        RATE_STATE[ip] = (count, win)
    if count > 5:
        if request.is_json:
            return jsonify({"error": "Too many requests. Try again later."}), 429
        return _render(T_FORGOT, "Mot de passe oublié",
                       error="Trop de tentatives. Réessayez dans quelques minutes.",
                       email=""), 429

    # ── Email extraction (loose — accepts malformed values) ────────────────
    if request.is_json:
        data  = request.get_json(silent=True) or {}
        email = data.get("email", "")
        if isinstance(email, list):
            email = email[-1]           # array: last value wins (GitLab CVE-2023-7028)
        email = str(email)
    else:
        emails = request.form.getlist("email")
        email  = emails[-1] if emails else ""

    # Loose validation — only checks for @ presence
    if "@" not in email:
        if request.is_json:
            return jsonify({"error": "Invalid email"}), 400
        return _render(T_FORGOT, "Mot de passe oublié",
                       error="Adresse email invalide.", email=email)

    # ── Host header injection: build reset URL from Host ───────────────────
    host = (
        request.headers.get("X-Forwarded-Host") or
        request.headers.get("X-Host") or
        request.headers.get("Host", "localhost:5000")
    )

    # ── Referrer fallback (referrer manipulation) ──────────────────────────
    referer = request.headers.get("Referer", "")
    origin  = request.headers.get("Origin", "")
    base_from_referer = (referer or origin or f"http://{host}").rstrip("/")

    # ── Weak token (PHP uniqid — predictable) ─────────────────────────────
    token = _php_uniqid()

    # ── Store token (no expiry enforced on confirm side = token reuse vuln) ─
    RESET_TOKENS[token] = {
        "email":   email,
        "used":    False,
        "expires": now + 3600,
    }

    # Reset URL built from Host header (HHIP)
    reset_url = f"http://{host}/reset-password?token={token}"

    # JSON response: token leaks in body
    if request.is_json:
        return jsonify({
            "status":    "success",
            "message":   f"Password reset email sent to {email}",
            "reset_url": reset_url,         # HHIP + token leakage
            "token":     token,             # direct token leakage
            "base_url":  base_from_referer, # referrer manipulation evidence
        }), 200

    # HTML response: token visible on page (token leakage)
    return _render(T_EMAIL_SENT, "Email envoyé",
                   email=email, token=token)


# ─── Reset password ────────────────────────────────────────────────────────────
#  Vulnerable: token is NEVER invalidated after first use → replay forever.

@app.route("/reset-password", methods=["GET", "POST"])
def reset_password():
    token = request.args.get("token", "") or request.form.get("token", "")

    if request.method == "GET":
        if not token or token not in RESET_TOKENS:
            return _render(T_RESET, "Réinitialisation",
                           error="Token invalide ou expiré.", token=token, success="")
        return _render(T_RESET, "Réinitialisation", error="", token=token, success="")

    # POST — validate token
    if not token or token not in RESET_TOKENS:
        return _render(T_RESET, "Réinitialisation",
                       error="Token invalide ou expiré.", token=token, success="")

    password  = request.form.get("password", "")
    password2 = request.form.get("password2", "")
    if password != password2:
        return _render(T_RESET, "Réinitialisation",
                       error="Les mots de passe ne correspondent pas.", token=token, success="")
    if len(password) < 6:
        return _render(T_RESET, "Réinitialisation",
                       error="Mot de passe trop court (min 6 caractères).", token=token, success="")

    info  = RESET_TOKENS[token]
    email = info["email"]

    # Update password in "DB"
    if email in USERS:
        USERS[email]["password"] = password

    # BUG: token is NOT marked used and NOT deleted → token reuse
    # info["used"] = True
    # del RESET_TOKENS[token]

    return _render(T_RESET, "Réinitialisation", error="", token=token,
                   success=f"Mot de passe mis à jour pour {email}. Vous pouvez vous reconnecter.")


# ─── API endpoint (JSON — IDOR + params pollution) ────────────────────────────

@app.route("/api/v1/forgot-password", methods=["POST"])
def api_forgot():
    data = request.get_json(silent=True) or {}

    # IDOR: user_id accepted without auth check
    user_id = str(data.get("user_id") or data.get("userId") or
                  data.get("uid") or data.get("id") or "")

    email = data.get("email", "")
    if isinstance(email, list):
        email = email[-1]
    email = str(email)

    # If user_id provided, resolve email (IDOR)
    if user_id:
        for ue, info in USERS.items():
            if info["id"] == user_id:
                email = ue
                break
        else:
            email = f"user_{user_id}@example.com"

    if "@" not in email:
        return jsonify({"error": "Invalid email"}), 400

    token = _php_uniqid()
    RESET_TOKENS[token] = {"email": email, "used": False, "expires": time.time() + 3600}

    host = (request.headers.get("X-Forwarded-Host") or
            request.headers.get("Host", "localhost:5000"))

    return jsonify({
        "status":    "success",
        "message":   f"Reset sent to {email}",
        "token":     token,
        "reset_url": f"http://{host}/reset-password?token={token}",
    }), 200


# ─── Hidden endpoints (endpoint discovery) ───────────────────────────────────

@app.route("/admin/reset", methods=["GET", "POST"])
@app.route("/admin/resetPassword", methods=["GET", "POST"])
@app.route("/admin/password-reset", methods=["GET", "POST"])
def admin_reset():
    email = request.args.get("email") or _parse_email()
    token = _secure_token()
    RESET_TOKENS[token] = {"email": email, "used": False, "expires": time.time() + 3600}
    return jsonify({"status": "success", "admin": True,
                    "token": token, "message": f"Admin reset for {email}"}), 200


@app.route("/api/su/resetPwd", methods=["POST"])
def su_reset():
    email = _parse_email()
    token = _php_uniqid()
    RESET_TOKENS[token] = {"email": email, "used": False, "expires": time.time() + 3600}
    return jsonify({"status": "success", "superuser": True,
                    "token": token, "message": f"Superuser reset for {email}"}), 200


@app.route("/internal/reset", methods=["POST"])
@app.route("/internal/password/reset", methods=["POST"])
def internal_reset():
    email = _parse_email()
    return jsonify({"status": "success", "internal": True,
                    "message": f"Internal reset for {email}"}), 200


@app.route("/debug/reset", methods=["GET", "POST"])
def debug_reset():
    email = request.args.get("email") or _parse_email()
    token = "DEBUG_TOKEN_gyp_12345_predictable"
    return jsonify({"status": "success", "debug": True,
                    "token": token, "message": f"Debug reset for {email}"}), 200


# ─── Debug panel ─────────────────────────────────────────────────────────────

MODULES = [
    ("CSRF",             "POST /forgot-password",               "csrf_req.txt"),
    ("IDOR",             "POST /api/v1/forgot-password",        "idor_req.txt"),
    ("Race condition",   "POST /race/reset",                    "race_req.txt"),
    ("Rate-limit bypass","POST /forgot-password",               "ratelimit_req.txt"),
    ("Referrer manip.",  "POST /forgot-password",               "referrer_req.txt"),
    ("Token reuse",      "GET  /reset-password?token=…",        "tokenreuse_req.txt"),
    ("Endpoint discovery","POST /forgot-password",              "csrf_req.txt"),
    ("HHIP",             "POST /forgot-password",               "hhip_req.txt"),
    ("Email hijack",     "POST /forgot-password",               "emailhijack_req.txt"),
    ("Token analysis",   "POST /forgot-password",               "tokenanalysis_req.txt"),
    ("Params pollution", "POST /forgot-password",               "hpp_req.txt"),
    ("Method override",  "* /methodoverride/reset",             "methodoverride_req.txt"),
    ("Absolute URI",     "POST /absuri/reset",                  "absuri_req.txt"),
]

@app.route("/debug")
def debug_panel():
    return _render(T_DEBUG, "Debug panel",
                   tokens=RESET_TOKENS, modules=MODULES)


# ─── Race condition (isolated endpoint) ──────────────────────────────────────

@app.route("/race/reset", methods=["POST"])
def race_reset():
    email = _parse_email()
    now   = time.time()
    if RACE_LAST["ts"] and (now - RACE_LAST["ts"]) < 1.0:
        token = RACE_LAST["value"]
    else:
        token = _php_uniqid()
        RACE_LAST["value"] = token
        RACE_LAST["ts"]    = now
    return jsonify({"status": "success", "token": token, "email": email}), 200


# ─── Method override (isolated endpoint) ─────────────────────────────────────

@app.route("/methodoverride/reset",
           methods=["GET", "POST", "PUT", "PATCH", "DELETE"])
def methodoverride_reset():
    override = (
        request.headers.get("X-HTTP-Method-Override") or
        request.headers.get("X-HTTP-Method") or
        request.headers.get("X-Method-Override") or
        request.headers.get("X-Original-HTTP-Method") or
        request.args.get("_method") or
        request.args.get("method")
    )
    effective = override or request.method
    email     = _parse_email()
    return jsonify({
        "status":           "success",
        "actual_method":    request.method,
        "effective_method": effective,
        "message":          f"Reset sent to {email}",
    }), 200


# ─── Absolute URI (isolated endpoint) ────────────────────────────────────────

@app.route("/absuri/reset", methods=["POST"])
def absuri_reset():
    email = _parse_email()
    host  = request.headers.get("Host", "localhost:5000")
    token = _php_uniqid()
    resp  = jsonify({
        "status":    "success",
        "message":   f"Reset sent to {email}",
        "reset_url": f"https://{host}/reset-password?token={token}",
    })
    resp.headers["Location"] = f"https://{host}/reset-password?token={token}"
    return resp, 200


if __name__ == "__main__":
    print("""
  ╔══════════════════════════════════════════════╗
  ║  GimmeYourPassword — Vulnerable Lab          ║
  ║  http://localhost:5000                        ║
  ║  Debug: http://localhost:5000/debug           ║
  ╚══════════════════════════════════════════════╝
""")
    app.run(host="0.0.0.0", port=5000, debug=False)

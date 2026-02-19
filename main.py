import os
import secrets
from functools import wraps
from urllib.parse import urlencode

import requests
from flask import Flask, render_template, redirect, url_for, session, request, jsonify

from werkzeug.middleware.proxy_fix import ProxyFix

app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)

app.secret_key = os.environ.get("SECRET_KEY", "dev-secret-change-me")

app.config.update(
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=True,  # Render is https
)

DISCORD_CLIENT_ID = os.environ.get("DISCORD_CLIENT_ID", "").strip()
DISCORD_CLIENT_SECRET = os.environ.get("DISCORD_CLIENT_SECRET", "").strip()
DISCORD_REDIRECT_URI = os.environ.get("DISCORD_REDIRECT_URI", "").strip()

DISCORD_API_BASE = "https://discord.com/api"


def oauth_configured() -> bool:
    return bool(DISCORD_CLIENT_ID and DISCORD_CLIENT_SECRET and DISCORD_REDIRECT_URI)


def login_required(view_func):
    @wraps(view_func)
    def wrapped(*args, **kwargs):
        if not session.get("discord_user"):
            return redirect(url_for("login"))  # IMPORTANT: endpoint is "login"
        return view_func(*args, **kwargs)
    return wrapped


@app.get("/")
def landing():
    return render_template("index.html", user=session.get("discord_user"), oauth_ready=oauth_configured())


# ✅ Endpoint name is NOW "login" again (so url_for("login") works)
@app.get("/login")
def login():
    error = session.pop("last_oauth_error", None)
    if not oauth_configured():
        error = (
            "Discord OAuth not configured yet.\n"
            "Add these Render env vars: DISCORD_CLIENT_ID, DISCORD_CLIENT_SECRET, DISCORD_REDIRECT_URI."
        )
    return render_template("login.html", oauth_ready=oauth_configured(), error=error)


@app.get("/oauth/discord")
def oauth_start():
    if not oauth_configured():
        session["last_oauth_error"] = "OAuth env vars missing on the server."
        return redirect(url_for("login"))

    state = secrets.token_urlsafe(24)
    session["oauth_state"] = state

    params = {
        "client_id": DISCORD_CLIENT_ID,
        "redirect_uri": DISCORD_REDIRECT_URI,
        "response_type": "code",
        "scope": "identify guilds",
        "state": state,
        "prompt": "consent",  # prevents dumb loops
    }
    return redirect(f"https://discord.com/oauth2/authorize?{urlencode(params)}")


@app.get("/callback")
def callback():
    err = request.args.get("error")
    err_desc = request.args.get("error_description")
    if err:
        session["last_oauth_error"] = f"Discord OAuth error: {err}. {err_desc or ''}".strip()
        return redirect(url_for("login"))

    code = request.args.get("code", "")
    state = request.args.get("state", "")
    expected_state = session.get("oauth_state", "")

    if not code:
        session["last_oauth_error"] = "No OAuth code returned. (Redirect URI mismatch is the usual cause.)"
        return redirect(url_for("login"))

    if not expected_state or state != expected_state:
        session["last_oauth_error"] = (
            "OAuth state mismatch (session cookie not sticking). "
            "Make sure SECRET_KEY is set on Render, then try again."
        )
        return redirect(url_for("login"))

    token_url = f"{DISCORD_API_BASE}/oauth2/token"
    data = {
        "client_id": DISCORD_CLIENT_ID,
        "client_secret": DISCORD_CLIENT_SECRET,
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": DISCORD_REDIRECT_URI,
    }
    headers = {"Content-Type": "application/x-www-form-urlencoded"}

    token_resp = requests.post(token_url, data=data, headers=headers, timeout=20)
    if token_resp.status_code != 200:
        session["last_oauth_error"] = f"Token exchange failed: HTTP {token_resp.status_code}"
        return redirect(url_for("login"))

    access_token = token_resp.json().get("access_token")
    if not access_token:
        session["last_oauth_error"] = "No access_token returned by Discord."
        return redirect(url_for("login"))

    auth_headers = {"Authorization": f"Bearer {access_token}"}
    user_resp = requests.get(f"{DISCORD_API_BASE}/users/@me", headers=auth_headers, timeout=20)
    guilds_resp = requests.get(f"{DISCORD_API_BASE}/users/@me/guilds", headers=auth_headers, timeout=20)

    if user_resp.status_code != 200:
        session["last_oauth_error"] = f"Could not fetch Discord user: HTTP {user_resp.status_code}"
        return redirect(url_for("login"))

    user = user_resp.json()
    guilds = guilds_resp.json() if guilds_resp.status_code == 200 else []

    session["discord_user"] = {
        "id": user.get("id"),
        "username": user.get("username"),
        "global_name": user.get("global_name"),
        "avatar": user.get("avatar"),
    }
    session["discord_guilds"] = guilds
    session.pop("oauth_state", None)

    return redirect(url_for("dashboard"))


@app.get("/dashboard")
@login_required
def dashboard():
    user = session.get("discord_user")
    guilds = session.get("discord_guilds", [])

    stats = {
        "servers": len(guilds),
        "members": "—",
        "reports_today": "—",
        "uptime": "Online",
    }

    recent_activity = [
        {"time": "Just now", "text": "Dashboard loaded successfully."},
        {"time": "A moment ago", "text": "Discord login completed."},
    ]

    return render_template(
        "dashboard.html",
        user=user,
        stats=stats,
        recent_activity=recent_activity,
        guilds=guilds,
        oauth_ready=oauth_configured(),
    )


@app.get("/servers")
@login_required
def servers():
    return render_template("servers.html", user=session.get("discord_user"))


@app.get("/reports")
@login_required
def reports():
    return render_template("reports.html", user=session.get("discord_user"))


@app.get("/settings")
@login_required
def settings():
    return render_template("settings.html", user=session.get("discord_user"))


@app.get("/logout")
def logout():
    session.clear()
    return redirect(url_for("landing"))


@app.get("/envcheck")
def envcheck():
    return jsonify(
        {
            "oauth_configured": oauth_configured(),
            "has_client_id": bool(DISCORD_CLIENT_ID),
            "has_client_secret": bool(DISCORD_CLIENT_SECRET),
            "has_redirect_uri": bool(DISCORD_REDIRECT_URI),
            "redirect_uri_value": DISCORD_REDIRECT_URI if DISCORD_REDIRECT_URI else None,
        }
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
import os
import secrets
from functools import wraps
from urllib.parse import urlencode

import requests
from flask import Flask, render_template, redirect, url_for, session, request, flash, jsonify

# If you're behind a proxy (Render), this helps Flask understand HTTPS correctly.
from werkzeug.middleware.proxy_fix import ProxyFix

app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)

# IMPORTANT: set SECRET_KEY on Render so sessions don't randomly break
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret-change-me")

# Safer cookie defaults for OAuth redirects
app.config.update(
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=True,  # you're on https on Render
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
            return redirect(url_for("login_page"))
        return view_func(*args, **kwargs)
    return wrapped


@app.get("/")
def landing():
    return render_template(
        "index.html",
        user=session.get("discord_user"),
        oauth_ready=oauth_configured(),
    )


# IMPORTANT: /login is now a PAGE, not an auto-redirect into Discord.
@app.get("/login")
def login_page():
    error = session.pop("last_oauth_error", None)
    if not oauth_configured():
        error = (
            "Discord OAuth not configured yet.\n"
            "Add these Render env vars: DISCORD_CLIENT_ID, DISCORD_CLIENT_SECRET, DISCORD_REDIRECT_URI."
        )
    return render_template("login.html", oauth_ready=oauth_configured(), error=error)


# This is the only route that starts OAuth.
@app.get("/oauth/discord")
def oauth_start():
    if not oauth_configured():
        session["last_oauth_error"] = "OAuth env vars missing on the server."
        return redirect(url_for("login_page"))

    state = secrets.token_urlsafe(24)
    session["oauth_state"] = state

    params = {
        "client_id": DISCORD_CLIENT_ID,
        "redirect_uri": DISCORD_REDIRECT_URI,
        "response_type": "code",
        "scope": "identify guilds",
        "state": state,
        # DO NOT use prompt=none. It causes login_required loops.
        "prompt": "consent",
    }
    auth_url = f"https://discord.com/oauth2/authorize?{urlencode(params)}"
    return redirect(auth_url)


@app.get("/callback")
def callback():
    # If Discord returns an error (very common), STOP looping and show it.
    err = request.args.get("error")
    err_desc = request.args.get("error_description")
    if err:
        session["last_oauth_error"] = f"Discord returned OAuth error: {err}. {err_desc or ''}".strip()
        return redirect(url_for("login_page"))

    code = request.args.get("code", "")
    state = request.args.get("state", "")
    expected_state = session.get("oauth_state", "")

    if not code:
        session["last_oauth_error"] = "No OAuth code returned by Discord. (Usually redirect URI mismatch.)"
        return redirect(url_for("login_page"))

    if not expected_state or state != expected_state:
        session["last_oauth_error"] = (
            "OAuth state mismatch (session cookie not sticking). "
            "Try a hard refresh or Incognito, and make sure SECRET_KEY is set on Render."
        )
        return redirect(url_for("login_page"))

    # Exchange code for token
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
        return redirect(url_for("login_page"))

    token_json = token_resp.json()
    access_token = token_json.get("access_token")
    if not access_token:
        session["last_oauth_error"] = "No access_token returned by Discord."
        return redirect(url_for("login_page"))

    auth_headers = {"Authorization": f"Bearer {access_token}"}

    user_resp = requests.get(f"{DISCORD_API_BASE}/users/@me", headers=auth_headers, timeout=20)
    guilds_resp = requests.get(f"{DISCORD_API_BASE}/users/@me/guilds", headers=auth_headers, timeout=20)

    if user_resp.status_code != 200:
        session["last_oauth_error"] = f"Could not fetch Discord user: HTTP {user_resp.status_code}"
        return redirect(url_for("login_page"))

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


@app.get("/logout")
def logout():
    session.clear()
    return redirect(url_for("landing"))


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
        {"time": "A moment ago", "text": "Discord OAuth login completed."},
    ]

    guild_preview = []
    for g in guilds[:8]:
        guild_preview.append(
            {
                "id": g.get("id"),
                "name": g.get("name"),
                "owner": bool(g.get("owner")),
                "permissions": int(g.get("permissions", 0)) if str(g.get("permissions", "0")).isdigit() else 0,
            }
        )

    return render_template(
        "dashboard.html",
        user=user,
        stats=stats,
        recent_activity=recent_activity,
        guilds=guild_preview,
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


@app.get("/envcheck")
def envcheck():
    return jsonify(
        {
            "oauth_configured": oauth_configured(),
            "has_client_id": bool(DISCORD_CLIENT_ID),
            "has_client_secret": bool(DISCORD_CLIENT_SECRET),
            "has_redirect_uri": bool(DISCORD_REDIRECT_URI),
            "redirect_uri_value": DISCORD_REDIRECT_URI if DISCORD_REDIRECT_URI else None,
            "note": "If oauth_configured is true but login fails, your Discord redirect URL probably doesn't match exactly.",
        }
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
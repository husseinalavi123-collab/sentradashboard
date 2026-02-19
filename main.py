import os
import secrets
from functools import wraps
from urllib.parse import urlencode

import requests
from flask import (
    Flask,
    render_template,
    redirect,
    url_for,
    session,
    request,
    flash,
    jsonify,
)

app = Flask(__name__)

# Secret key for sessions (Render should provide SECRET_KEY; fallback is dev-only)
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret-change-me")

# Discord OAuth env vars (Render)
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
            return redirect(url_for("login"))
        return view_func(*args, **kwargs)

    return wrapped


@app.get("/")
def landing():
    # Landing page
    return render_template(
        "index.html",
        user=session.get("discord_user"),
        oauth_ready=oauth_configured(),
    )


@app.get("/login")
def login():
    # If OAuth isn't configured, show login page with the warning message
    if not oauth_configured():
        return render_template(
            "login.html",
            oauth_ready=False,
            error=(
                "Discord OAuth not configured yet.\n"
                "Add these Render env vars: DISCORD_CLIENT_ID, DISCORD_CLIENT_SECRET, DISCORD_REDIRECT_URI."
            ),
        )

    # Start Discord OAuth flow
    state = secrets.token_urlsafe(24)
    session["oauth_state"] = state

    params = {
        "client_id": DISCORD_CLIENT_ID,
        "redirect_uri": DISCORD_REDIRECT_URI,
        "response_type": "code",
        "scope": "identify guilds",
        "state": state,
        "prompt": "none",
    }
    auth_url = f"https://discord.com/oauth2/authorize?{urlencode(params)}"
    return redirect(auth_url)


@app.get("/callback")
def callback():
    # Discord redirects here after login
    if not oauth_configured():
        flash("OAuth not configured on the server.", "error")
        return redirect(url_for("login"))

    code = request.args.get("code", "")
    state = request.args.get("state", "")
    expected_state = session.get("oauth_state", "")

    if not code:
        flash("Missing OAuth code from Discord.", "error")
        return redirect(url_for("login"))

    if not expected_state or state != expected_state:
        flash("OAuth state mismatch. Please try again.", "error")
        return redirect(url_for("login"))

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
        flash("Failed to get token from Discord.", "error")
        return redirect(url_for("login"))

    token_json = token_resp.json()
    access_token = token_json.get("access_token")
    if not access_token:
        flash("No access token returned by Discord.", "error")
        return redirect(url_for("login"))

    # Fetch user + guilds
    auth_headers = {"Authorization": f"Bearer {access_token}"}

    user_resp = requests.get(f"{DISCORD_API_BASE}/users/@me", headers=auth_headers, timeout=20)
    guilds_resp = requests.get(f"{DISCORD_API_BASE}/users/@me/guilds", headers=auth_headers, timeout=20)

    if user_resp.status_code != 200:
        flash("Could not fetch Discord user.", "error")
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

    # Cleanup one-time state
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

    # Real-ish stats (based on actual guild list you have access to)
    stats = {
        "servers": len(guilds),
        "members": "—",        # requires bot + privileged intents later
        "reports_today": "—",  # will be real later once bot reports exist
        "uptime": "Online",
    }

    recent_activity = [
        {"time": "Just now", "text": "Dashboard loaded successfully."},
        {"time": "A moment ago", "text": "Discord OAuth login completed."},
        {"time": "Earlier", "text": "Render deployment survived another day."},
    ]

    # Show a few guilds on the dashboard
    guild_preview = []
    for g in guilds[:6]:
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


# These routes exist so your templates can safely url_for() them (no more BuildError)
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


# Debug helper: shows which env vars are detected (no secrets leaked)
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
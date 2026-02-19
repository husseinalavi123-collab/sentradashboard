import os
import secrets
from functools import wraps

import requests
from flask import Flask, render_template, redirect, request, session, url_for, flash

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret-change-me")

DISCORD_CLIENT_ID = os.environ.get("DISCORD_CLIENT_ID")
DISCORD_CLIENT_SECRET = os.environ.get("DISCORD_CLIENT_SECRET")
DISCORD_REDIRECT_URI = os.environ.get("DISCORD_REDIRECT_URI")

DISCORD_API = "https://discord.com/api/v10"
OAUTH_AUTHORIZE = f"{DISCORD_API}/oauth2/authorize"
OAUTH_TOKEN = f"{DISCORD_API}/oauth2/token"


def login_required(view_func):
    @wraps(view_func)
    def wrapped(*args, **kwargs):
        if not session.get("discord_user"):
            return redirect(url_for("login"))
        return view_func(*args, **kwargs)
    return wrapped


def discord_headers():
    token = session.get("access_token")
    return {"Authorization": f"Bearer {token}"} if token else {}


def require_oauth_env():
    missing = []
    if not DISCORD_CLIENT_ID:
        missing.append("DISCORD_CLIENT_ID")
    if not DISCORD_CLIENT_SECRET:
        missing.append("DISCORD_CLIENT_SECRET")
    if not DISCORD_REDIRECT_URI:
        missing.append("DISCORD_REDIRECT_URI")
    return missing


@app.get("/")
def index():
    return render_template("index.html", user=session.get("discord_user"))


@app.get("/login")
def login():
    missing = require_oauth_env()
    if missing:
        return (
            "Missing environment variables: " + ", ".join(missing) +
            "<br>Set these in Render → Environment.",
            500,
        )

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

    # requests can build the URL but we’ll just do it manually
    query = "&".join([f"{k}={requests.utils.quote(str(v))}" for k, v in params.items()])
    return redirect(f"{OAUTH_AUTHORIZE}?{query}")


@app.get("/callback")
def callback():
    # 1) Validate state (prevents random people forging login requests)
    state = request.args.get("state", "")
    if not state or state != session.get("oauth_state"):
        return "Invalid OAuth state. Try logging in again.", 400

    code = request.args.get("code", "")
    if not code:
        return "Missing code from Discord.", 400

    # 2) Exchange code for access token
    data = {
        "client_id": DISCORD_CLIENT_ID,
        "client_secret": DISCORD_CLIENT_SECRET,
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": DISCORD_REDIRECT_URI,
    }
    headers = {"Content-Type": "application/x-www-form-urlencoded"}

    token_res = requests.post(OAUTH_TOKEN, data=data, headers=headers, timeout=20)
    if token_res.status_code != 200:
        return f"Token exchange failed: {token_res.status_code} {token_res.text}", 400

    token_json = token_res.json()
    session["access_token"] = token_json.get("access_token")

    # 3) Get user info
    me_res = requests.get(f"{DISCORD_API}/users/@me", headers=discord_headers(), timeout=20)
    if me_res.status_code != 200:
        return f"Failed to fetch user: {me_res.status_code} {me_res.text}", 400

    user = me_res.json()
    session["discord_user"] = {
        "id": user.get("id"),
        "username": user.get("username"),
        "global_name": user.get("global_name"),
        "avatar": user.get("avatar"),
    }

    flash("Logged in with Discord.", "success")
    return redirect(url_for("guilds"))


@app.get("/guilds")
@login_required
def guilds():
    # Get guilds the user is in
    res = requests.get(f"{DISCORD_API}/users/@me/guilds", headers=discord_headers(), timeout=20)
    if res.status_code != 200:
        return f"Failed to fetch guilds: {res.status_code} {res.text}", 400

    guilds = res.json()

    # Filter to guilds where user has MANAGE_GUILD permission (0x20)
    manageable = []
    MANAGE_GUILD = 0x20

    for g in guilds:
        perms = int(g.get("permissions", 0))
        if (perms & MANAGE_GUILD) == MANAGE_GUILD:
            manageable.append({
                "id": g["id"],
                "name": g["name"],
                "icon": g.get("icon"),
            })

    user = session.get("discord_user")
    return render_template("guilds.html", user=user, guilds=manageable)


@app.get("/logout")
def logout():
    session.clear()
    flash("Logged out.", "success")
    return redirect(url_for("index"))


# Placeholder “dashboard” route (you can keep yours too)
@app.get("/dashboard")
@login_required
def dashboard():
    user = session.get("discord_user")
    return render_template("dashboard.html", user=user)


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)
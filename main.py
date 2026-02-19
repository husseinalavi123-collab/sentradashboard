import os
import secrets
from functools import wraps

import requests
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret-change-me")

# ---- Discord OAuth config (set these on Render) ----
DISCORD_CLIENT_ID = os.environ.get("DISCORD_CLIENT_ID", "")
DISCORD_CLIENT_SECRET = os.environ.get("DISCORD_CLIENT_SECRET", "")
DISCORD_REDIRECT_URI = os.environ.get("DISCORD_REDIRECT_URI", "")  # e.g. https://YOUR.onrender.com/callback

# Scopes:
# - bot: lets you add the bot to a server
# - applications.commands: slash commands
# - identify: basic user identity (optional but useful)
OAUTH_SCOPES = "bot applications.commands identify"


def login_required(view_func):
    @wraps(view_func)
    def wrapped(*args, **kwargs):
        if not session.get("user"):
            return redirect(url_for("login"))
        return view_func(*args, **kwargs)
    return wrapped


@app.get("/health")
def health():
    return jsonify(ok=True)


@app.get("/")
def index():
    # Landing page: show "Add to Server" link that hits /invite
    return render_template("index.html", user=session.get("user"))


@app.get("/invite")
def invite():
    """
    Sends user to Discord OAuth authorization.
    Discord will redirect back to DISCORD_REDIRECT_URI (/callback).
    """
    if not DISCORD_CLIENT_ID or not DISCORD_REDIRECT_URI:
        return "Missing DISCORD_CLIENT_ID or DISCORD_REDIRECT_URI env vars.", 500

    state = secrets.token_urlsafe(24)
    session["oauth_state"] = state

    url = (
        "https://discord.com/oauth2/authorize"
        f"?client_id={DISCORD_CLIENT_ID}"
        f"&redirect_uri={requests.utils.quote(DISCORD_REDIRECT_URI, safe='')}"
        f"&response_type=code"
        f"&scope={requests.utils.quote(OAUTH_SCOPES)}"
        f"&state={state}"
        # optional: choose permissions integer for the bot. 0 = none.
        f"&permissions=0"
    )
    return redirect(url)


@app.get("/callback")
def callback():
    """
    Discord redirects here with ?code=...&state=...
    We validate state, exchange code for token (real), store basic info, then redirect.
    """
    code = request.args.get("code")
    state = request.args.get("state")
    error = request.args.get("error")

    if error:
        flash(f"Discord OAuth error: {error}", "error")
        return redirect(url_for("index"))

    if not code or not state:
        return "Missing code/state from Discord.", 400

    if state != session.get("oauth_state"):
        return "Invalid state. Try again.", 400

    if not DISCORD_CLIENT_ID or not DISCORD_CLIENT_SECRET or not DISCORD_REDIRECT_URI:
        return "Missing Discord OAuth env vars on server.", 500

    token_url = "https://discord.com/api/oauth2/token"
    data = {
        "client_id": DISCORD_CLIENT_ID,
        "client_secret": DISCORD_CLIENT_SECRET,
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": DISCORD_REDIRECT_URI,
    }
    headers = {"Content-Type": "application/x-www-form-urlencoded"}

    r = requests.post(token_url, data=data, headers=headers, timeout=20)
    if r.status_code != 200:
        return f"Token exchange failed: {r.status_code} {r.text}", 500

    token_json = r.json()
    access_token = token_json.get("access_token")
    if not access_token:
        return "No access_token returned by Discord.", 500

    # Optional: fetch user identity (since we requested identify)
    user_info = {}
    me = requests.get(
        "https://discord.com/api/users/@me",
        headers={"Authorization": f"Bearer {access_token}"},
        timeout=20,
    )
    if me.status_code == 200:
        user_info = me.json()

    # Store in session (prototype-safe)
    session["discord_connected"] = True
    session["discord_user"] = {
        "id": user_info.get("id"),
        "username": user_info.get("username"),
        "global_name": user_info.get("global_name"),
        "avatar": user_info.get("avatar"),
    }

    # Also mark app "logged in" for dashboard access
    session["user"] = user_info.get("global_name") or user_info.get("username") or "User"

    flash("Discord connected successfully.", "success")
    return redirect(url_for("dashboard"))


@app.route("/login", methods=["GET", "POST"])
def login():
    # simple local fallback login
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        if not username:
            flash("Type a username.", "error")
            return redirect(url_for("login"))
        session["user"] = username
        return redirect(url_for("dashboard"))
    return render_template("login.html")


@app.get("/dashboard")
@login_required
def dashboard():
    user = session.get("user")
    stats = {
        "servers": 3,
        "members": 124,
        "reports_today": 2,
        "tickets_open": 4,
        "latency_ms": 42,
        "uptime": "Online",
    }
    recent_activity = [
        {"time": "Just now", "text": "Dashboard loaded successfully."},
        {"time": "5 min ago", "text": "User logged in."},
        {"time": "1 hr ago", "text": "System health: OK."},
    ]
    return render_template(
        "dashboard.html",
        user=user,
        stats=stats,
        recent_activity=recent_activity,
        discord_user=session.get("discord_user"),
        discord_connected=session.get("discord_connected", False),
    )


@app.get("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))
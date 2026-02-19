import os
import secrets
import requests
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret-change-me")

DISCORD_CLIENT_ID = os.environ.get("DISCORD_CLIENT_ID")
DISCORD_CLIENT_SECRET = os.environ.get("DISCORD_CLIENT_SECRET")
DISCORD_REDIRECT_URI = os.environ.get("DISCORD_REDIRECT_URI")

OAUTH_SCOPES = "bot applications.commands identify"

# --------------------------------------------------
# Helpers
# --------------------------------------------------

def login_required(view_func):
    @wraps(view_func)
    def wrapped(*args, **kwargs):
        if not session.get("user"):
            return redirect(url_for("login"))
        return view_func(*args, **kwargs)
    return wrapped


# --------------------------------------------------
# Routes
# --------------------------------------------------

@app.get("/health")
def health():
    return jsonify(ok=True)


@app.get("/")
def landing():
    return render_template("index.html", user=session.get("user"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        if not username:
            flash("Type a username.", "error")
            return redirect(url_for("login"))
        session["user"] = username
        return redirect(url_for("dashboard"))
    return render_template("login.html")


@app.get("/invite")
def invite():
    if not DISCORD_CLIENT_ID or not DISCORD_REDIRECT_URI:
        return "Missing Discord environment variables.", 500

    state = secrets.token_urlsafe(24)
    session["oauth_state"] = state

    url = (
        "https://discord.com/oauth2/authorize"
        f"?client_id={DISCORD_CLIENT_ID}"
        f"&redirect_uri={requests.utils.quote(DISCORD_REDIRECT_URI, safe='')}"
        f"&response_type=code"
        f"&scope={requests.utils.quote(OAUTH_SCOPES)}"
        f"&state={state}"
        f"&permissions=0"
    )
    return redirect(url)


@app.get("/callback")
def callback():
    code = request.args.get("code")
    state = request.args.get("state")
    error = request.args.get("error")

    if error:
        flash(f"Discord error: {error}", "error")
        return redirect(url_for("landing"))

    if not code or not state:
        return "Missing code/state.", 400

    if state != session.get("oauth_state"):
        return "Invalid state.", 400

    if not DISCORD_CLIENT_ID or not DISCORD_CLIENT_SECRET or not DISCORD_REDIRECT_URI:
        return "Missing Discord environment variables.", 500

    token_url = "https://discord.com/api/oauth2/token"

    data = {
        "client_id": DISCORD_CLIENT_ID,
        "client_secret": DISCORD_CLIENT_SECRET,
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": DISCORD_REDIRECT_URI,
    }

    headers = {"Content-Type": "application/x-www-form-urlencoded"}

    r = requests.post(token_url, data=data, headers=headers, timeout=15)

    if r.status_code != 200:
        return f"Token exchange failed: {r.text}", 500

    token_json = r.json()
    access_token = token_json.get("access_token")

    if not access_token:
        return "No access token returned.", 500

    # Fetch user info
    user_res = requests.get(
        "https://discord.com/api/users/@me",
        headers={"Authorization": f"Bearer {access_token}"},
        timeout=15,
    )

    if user_res.status_code == 200:
        user_data = user_res.json()
        session["discord_user"] = user_data
        session["user"] = user_data.get("global_name") or user_data.get("username")
        session["discord_connected"] = True

    flash("Discord connected successfully.", "success")
    return redirect(url_for("dashboard"))


@app.get("/dashboard")
@login_required
def dashboard():
    stats = {
        "servers": 1,
        "members": 0,
        "reports_today": 0,
        "tickets_open": 0,
        "latency_ms": 42,
        "uptime": "Online",
    }

    recent_activity = [
        {"time": "Just now", "text": "Dashboard loaded."},
        {"time": "Earlier", "text": "System operational."},
    ]

    return render_template(
        "dashboard.html",
        user=session.get("user"),
        stats=stats,
        recent_activity=recent_activity,
        discord_user=session.get("discord_user"),
        discord_connected=session.get("discord_connected", False),
    )


@app.get("/logout")
def logout():
    session.clear()
    return redirect(url_for("landing"))


if __name__ == "__main__":
    app.run(debug=True)
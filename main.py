import os
import secrets
import requests
from functools import wraps
from flask import Flask, render_template, redirect, request, session, url_for

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret")

DISCORD_CLIENT_ID = os.environ.get("DISCORD_CLIENT_ID")
DISCORD_CLIENT_SECRET = os.environ.get("DISCORD_CLIENT_SECRET")
DISCORD_REDIRECT_URI = os.environ.get("DISCORD_REDIRECT_URI")

DISCORD_API = "https://discord.com/api/v10"


def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if "user" not in session:
            return redirect(url_for("landing"))
        return f(*args, **kwargs)
    return wrapper


@app.get("/")
def landing():
    return render_template("landing.html", client_id=DISCORD_CLIENT_ID)


@app.get("/login")
def login():
    state = secrets.token_urlsafe(16)
    session["state"] = state

    url = (
        f"https://discord.com/api/oauth2/authorize"
        f"?client_id={DISCORD_CLIENT_ID}"
        f"&redirect_uri={DISCORD_REDIRECT_URI}"
        f"&response_type=code"
        f"&scope=identify%20guilds"
        f"&state={state}"
    )
    return redirect(url)


@app.get("/callback")
def callback():
    if request.args.get("state") != session.get("state"):
        return render_template("error.html", message="Invalid state.")

    code = request.args.get("code")

    data = {
        "client_id": DISCORD_CLIENT_ID,
        "client_secret": DISCORD_CLIENT_SECRET,
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": DISCORD_REDIRECT_URI,
    }

    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    r = requests.post(f"{DISCORD_API}/oauth2/token", data=data, headers=headers)

    token = r.json().get("access_token")
    session["token"] = token

    user = requests.get(
        f"{DISCORD_API}/users/@me",
        headers={"Authorization": f"Bearer {token}"}
    ).json()

    session["user"] = user

    return redirect(url_for("guilds"))


@app.get("/guilds")
@login_required
def guilds():
    r = requests.get(
        f"{DISCORD_API}/users/@me/guilds",
        headers={"Authorization": f"Bearer {session['token']}"}
    )

    guilds = r.json()

    manageable = [
        g for g in guilds
        if (int(g["permissions"]) & 0x20) == 0x20
    ]

    return render_template("guilds.html", guilds=manageable)


@app.get("/dashboard/<guild_id>")
@login_required
def dashboard(guild_id):
    return render_template("dashboard.html", guild_id=guild_id)


@app.get("/logout")
def logout():
    session.clear()
    return redirect(url_for("landing"))


@app.errorhandler(404)
def not_found(e):
    return render_template("error.html", message="Page not found."), 404


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
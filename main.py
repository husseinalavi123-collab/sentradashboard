import os
import sqlite3
import secrets
from functools import wraps
from urllib.parse import urlencode

import requests
from flask import (
    Flask, render_template, redirect, url_for, session,
    request, flash, jsonify, g
)
from werkzeug.middleware.proxy_fix import ProxyFix

# -------------------------
# App setup
# -------------------------
app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)

app.secret_key = os.environ.get("SECRET_KEY", "dev-secret-change-me")

# Cookie settings: prevents OAuth session/state nonsense on Render
app.config.update(
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=True,  # Render uses https
)

DISCORD_CLIENT_ID = os.environ.get("DISCORD_CLIENT_ID", "").strip()
DISCORD_CLIENT_SECRET = os.environ.get("DISCORD_CLIENT_SECRET", "").strip()
DISCORD_REDIRECT_URI = os.environ.get("DISCORD_REDIRECT_URI", "").strip()

DISCORD_API = "https://discord.com/api"

DB_PATH = os.environ.get("DB_PATH", "sentra.db")


# -------------------------
# Helpers
# -------------------------
def oauth_configured() -> bool:
    return bool(DISCORD_CLIENT_ID and DISCORD_CLIENT_SECRET and DISCORD_REDIRECT_URI)


def login_required(view_func):
    @wraps(view_func)
    def wrapped(*args, **kwargs):
        if not session.get("discord_user"):
            return redirect(url_for("login"))
        return view_func(*args, **kwargs)
    return wrapped


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db = get_db()
    db.execute("""
    CREATE TABLE IF NOT EXISTS guild_settings (
        guild_id TEXT PRIMARY KEY,
        guild_name TEXT NOT NULL,
        prefix TEXT DEFAULT '!',
        mod_log_channel TEXT DEFAULT '',
        automod_spam INTEGER DEFAULT 1,
        automod_links INTEGER DEFAULT 0,
        automod_caps INTEGER DEFAULT 0,
        anti_raid INTEGER DEFAULT 0,
        welcome_enabled INTEGER DEFAULT 1,
        welcome_message TEXT DEFAULT 'Welcome {user}!',
        updated_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
    """)
    db.execute("""
    CREATE TABLE IF NOT EXISTS audit_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        guild_id TEXT NOT NULL,
        actor TEXT NOT NULL,
        action TEXT NOT NULL,
        detail TEXT NOT NULL,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
    """)
    db.commit()


@app.before_request
def _boot():
    init_db()


def log_event(guild_id: str, actor: str, action: str, detail: str):
    db = get_db()
    db.execute(
        "INSERT INTO audit_events (guild_id, actor, action, detail) VALUES (?, ?, ?, ?)",
        (guild_id, actor, action, detail),
    )
    db.commit()


def discord_headers():
    token = session.get("discord_token")
    if not token:
        return {}
    return {"Authorization": f"Bearer {token}"}


def fetch_discord_user():
    r = requests.get(f"{DISCORD_API}/users/@me", headers=discord_headers(), timeout=20)
    r.raise_for_status()
    return r.json()


def fetch_user_guilds():
    r = requests.get(f"{DISCORD_API}/users/@me/guilds", headers=discord_headers(), timeout=20)
    r.raise_for_status()
    return r.json()


def manageable_guilds(guilds):
    MANAGE_GUILD = 0x20
    out = []
    for gobj in guilds:
        perms = int(gobj.get("permissions", 0))
        if (perms & MANAGE_GUILD) == MANAGE_GUILD:
            out.append(gobj)
    out.sort(key=lambda x: (x.get("name") or "").lower())
    return out


def build_install_url():
    if not oauth_configured():
        return ""
    # bot + slash commands + identify/guilds are separate flows; install is just bot+commands
    params = {
        "client_id": DISCORD_CLIENT_ID,
        "scope": "bot applications.commands",
        # safer default: no scary perms in prototype (you can increase later)
        "permissions": "0",
    }
    return f"https://discord.com/oauth2/authorize?{urlencode(params)}"


# -------------------------
# Routes
# -------------------------
@app.get("/health")
def health():
    return jsonify(ok=True, service="sentra-dashboard")


@app.get("/envcheck")
def envcheck():
    # No secrets leaked, just booleans + redirect string
    return jsonify(
        oauth_configured=oauth_configured(),
        has_client_id=bool(DISCORD_CLIENT_ID),
        has_client_secret=bool(DISCORD_CLIENT_SECRET),
        has_redirect_uri=bool(DISCORD_REDIRECT_URI),
        redirect_uri_value=DISCORD_REDIRECT_URI if DISCORD_REDIRECT_URI else None,
    )


@app.get("/")
def index():
    return render_template(
        "index.html",
        oauth_ready=oauth_configured(),
        install_url=build_install_url(),
        user=session.get("discord_user"),
        active_guild=session.get("active_guild"),
    )


@app.get("/login")
def login():
    # This page NEVER auto-redirects to Discord. That prevents loop hell.
    err = session.pop("oauth_error", None)
    return render_template(
        "login.html",
        oauth_ready=oauth_configured(),
        error=err,
    )


@app.get("/oauth/discord")
def oauth_start():
    if not oauth_configured():
        session["oauth_error"] = "Discord OAuth not configured on Render env vars."
        return redirect(url_for("login"))

    # state prevents CSRF
    state = secrets.token_urlsafe(24)
    session["oauth_state"] = state

    params = {
        "client_id": DISCORD_CLIENT_ID,
        "redirect_uri": DISCORD_REDIRECT_URI,
        "response_type": "code",
        "scope": "identify guilds",
        "state": state,
        "prompt": "consent",
    }
    return redirect(f"https://discord.com/oauth2/authorize?{urlencode(params)}")


@app.get("/callback")
def callback():
    # If Discord sends an error, show it on /login (no loops)
    if request.args.get("error"):
        session["oauth_error"] = f"Discord OAuth error: {request.args.get('error')}"
        return redirect(url_for("login"))

    code = request.args.get("code", "")
    state = request.args.get("state", "")
    expected_state = session.get("oauth_state", "")

    if not code:
        session["oauth_error"] = "No code returned by Discord. (Redirect URI mismatch is common.)"
        return redirect(url_for("login"))

    if not expected_state or state != expected_state:
        session["oauth_error"] = "State mismatch. (Session cookie not sticking.) Check SECRET_KEY and try again."
        return redirect(url_for("login"))

    token_url = f"{DISCORD_API}/oauth2/token"
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
        session["oauth_error"] = f"Token exchange failed (HTTP {token_resp.status_code})."
        return redirect(url_for("login"))

    token_json = token_resp.json()
    access_token = token_json.get("access_token")
    if not access_token:
        session["oauth_error"] = "No access_token returned by Discord."
        return redirect(url_for("login"))

    session["discord_token"] = access_token
    session.pop("oauth_state", None)

    try:
        user = fetch_discord_user()
        guilds = fetch_user_guilds()
    except Exception:
        session.clear()
        session["oauth_error"] = "Failed fetching Discord user/guilds. Try again."
        return redirect(url_for("login"))

    session["discord_user"] = {
        "id": user.get("id"),
        "username": user.get("username"),
        "global_name": user.get("global_name") or "",
        "avatar": user.get("avatar") or "",
    }
    session["discord_guilds"] = guilds

    return redirect(url_for("guilds"))


@app.get("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


@app.get("/guilds")
@login_required
def guilds():
    guilds_all = session.get("discord_guilds")
    if not guilds_all:
        try:
            guilds_all = fetch_user_guilds()
            session["discord_guilds"] = guilds_all
        except Exception:
            flash("Couldn’t load your servers from Discord.", "error")
            return redirect(url_for("login"))

    mg = manageable_guilds(guilds_all)
    return render_template(
        "guilds.html",
        user=session.get("discord_user"),
        guilds=mg,
        install_url=build_install_url(),
        oauth_ready=oauth_configured(),
    )


@app.get("/select/<guild_id>")
@login_required
def select_guild(guild_id):
    guilds_all = session.get("discord_guilds", [])
    chosen = None
    for gobj in manageable_guilds(guilds_all):
        if gobj.get("id") == guild_id:
            chosen = gobj
            break

    if not chosen:
        flash("You can’t configure that server.", "error")
        return redirect(url_for("guilds"))

    session["active_guild"] = {"id": chosen["id"], "name": chosen["name"]}

    db = get_db()
    db.execute("""
        INSERT INTO guild_settings (guild_id, guild_name)
        VALUES (?, ?)
        ON CONFLICT(guild_id) DO UPDATE SET guild_name=excluded.guild_name, updated_at=CURRENT_TIMESTAMP
    """, (chosen["id"], chosen["name"]))
    db.commit()

    who = (session.get("discord_user") or {}).get("username", "user")
    log_event(chosen["id"], who, "SELECT_GUILD", f"Selected guild: {chosen['name']}")
    return redirect(url_for("dashboard"))


def require_active_guild():
    ag = session.get("active_guild")
    if not ag:
        flash("Pick a server first.", "error")
        return redirect(url_for("guilds"))
    return ag


def get_settings(guild_id: str):
    db = get_db()
    return db.execute("SELECT * FROM guild_settings WHERE guild_id=?", (guild_id,)).fetchone()


def get_events(guild_id: str, limit: int = 20):
    db = get_db()
    return db.execute(
        "SELECT * FROM audit_events WHERE guild_id=? ORDER BY id DESC LIMIT ?",
        (guild_id, limit)
    ).fetchall()


@app.get("/dashboard")
@login_required
def dashboard():
    ag = require_active_guild()
    if not isinstance(ag, dict):
        return ag  # redirect

    s = get_settings(ag["id"])
    events = get_events(ag["id"], 12)

    stats = {
        "servers": 1,
        "reports_today": sum(1 for e in events if e["action"] == "REPORT"),
        "actions": len(events),
        "status": "Online",
    }

    return render_template(
        "dashboard.html",
        user=session.get("discord_user"),
        active_guild=ag,
        settings=s,
        stats=stats,
        events=events,
        install_url=build_install_url(),
        oauth_ready=oauth_configured(),
    )


@app.get("/servers")
@login_required
def servers():
    ag = require_active_guild()
    if not isinstance(ag, dict):
        return ag

    events = get_events(ag["id"], 25)

    # UI demo nodes (not fake “your server has 9 billion users”)
    node_rows = [
        {"name": "Primary Node", "region": "EU-West", "status": "Online", "alerts": "0"},
        {"name": "Edge Node (demo)", "region": "US-East", "status": "Idle", "alerts": "0"},
    ]

    return render_template(
        "servers.html",
        user=session.get("discord_user"),
        active_guild=ag,
        node_rows=node_rows,
        events=events
    )


@app.get("/reports")
@login_required
def reports():
    ag = require_active_guild()
    if not isinstance(ag, dict):
        return ag

    events = get_events(ag["id"], 50)
    reports = [e for e in events if e["action"] == "REPORT"]

    return render_template(
        "reports.html",
        user=session.get("discord_user"),
        active_guild=ag,
        reports=reports
    )


@app.post("/action/report")
@login_required
def action_report():
    ag = require_active_guild()
    if not isinstance(ag, dict):
        return ag

    who = (session.get("discord_user") or {}).get("username", "user")
    log_event(ag["id"], who, "REPORT", "Test report created from dashboard UI.")
    flash("Report created (test).", "success")
    return redirect(url_for("reports"))


@app.get("/settings")
@login_required
def settings():
    ag = require_active_guild()
    if not isinstance(ag, dict):
        return ag

    s = get_settings(ag["id"])
    return render_template(
        "settings.html",
        user=session.get("discord_user"),
        active_guild=ag,
        settings=s,
        install_url=build_install_url(),
        oauth_ready=oauth_configured(),
    )


@app.post("/settings/save")
@login_required
def settings_save():
    ag = require_active_guild()
    if not isinstance(ag, dict):
        return ag

    def onoff(name: str) -> int:
        return 1 if request.form.get(name) == "on" else 0

    prefix = (request.form.get("prefix") or "!").strip()[:5]
    mod_log_channel = (request.form.get("mod_log_channel") or "").strip()[:64]
    welcome_message = (request.form.get("welcome_message") or "").strip()[:500]

    db = get_db()
    db.execute("""
        UPDATE guild_settings SET
          prefix=?,
          mod_log_channel=?,
          automod_spam=?,
          automod_links=?,
          automod_caps=?,
          anti_raid=?,
          welcome_enabled=?,
          welcome_message=?,
          updated_at=CURRENT_TIMESTAMP
        WHERE guild_id=?
    """, (
        prefix,
        mod_log_channel,
        onoff("automod_spam"),
        onoff("automod_links"),
        onoff("automod_caps"),
        onoff("anti_raid"),
        onoff("welcome_enabled"),
        welcome_message,
        ag["id"]
    ))
    db.commit()

    who = (session.get("discord_user") or {}).get("username", "user")
    log_event(ag["id"], who, "SETTINGS_SAVE", "Updated settings in dashboard UI.")
    flash("Settings saved.", "success")
    return redirect(url_for("settings"))


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
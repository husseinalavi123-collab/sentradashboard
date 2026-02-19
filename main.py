import os
import sqlite3
import secrets
from functools import wraps
from urllib.parse import urlencode

import requests
from flask import (
    Flask, render_template, request, redirect, url_for,
    session, flash, g
)

# -----------------------------
# App setup
# -----------------------------
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret-change-me")

BASE_URL = os.environ.get("BASE_URL", "").rstrip("/")  # optional
DISCORD_CLIENT_ID = os.environ.get("DISCORD_CLIENT_ID", "").strip()
DISCORD_CLIENT_SECRET = os.environ.get("DISCORD_CLIENT_SECRET", "").strip()
DISCORD_REDIRECT_URI = os.environ.get("DISCORD_REDIRECT_URI", "").strip()

DB_PATH = os.environ.get("DB_PATH", "sentra.db")

DISCORD_API = "https://discord.com/api"
OAUTH_AUTHORIZE = f"{DISCORD_API}/oauth2/authorize"
OAUTH_TOKEN = f"{DISCORD_API}/oauth2/token"

# Bot install scopes/permissions
BOT_SCOPES = "bot applications.commands"
# Permissions: moderate members, kick/ban, manage guild, manage roles, read messages, send messages etc.
# You can change this later. This is a reasonable “admin-ish bot” baseline.
BOT_PERMISSIONS_INT = "1099511627775"  # intentionally high (you can tune later)


# -----------------------------
# DB helpers
# -----------------------------
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
        block_nsfw INTEGER DEFAULT 0,
        anti_raid INTEGER DEFAULT 0,
        welcome_enabled INTEGER DEFAULT 1,
        welcome_message TEXT DEFAULT 'Welcome to the server, {user}!',
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
        (guild_id, actor, action, detail)
    )
    db.commit()


# -----------------------------
# Auth helpers
# -----------------------------
def login_required(view_func):
    @wraps(view_func)
    def wrapped(*args, **kwargs):
        if not session.get("user"):
            flash("Login required. Yes, even for you.", "error")
            return redirect(url_for("login"))
        return view_func(*args, **kwargs)
    return wrapped


def discord_configured() -> bool:
    return bool(DISCORD_CLIENT_ID and DISCORD_CLIENT_SECRET and DISCORD_REDIRECT_URI)


def discord_headers():
    token = session.get("discord_token")
    if not token:
        return {}
    return {"Authorization": f"Bearer {token}"}


def fetch_discord_user():
    r = requests.get(f"{DISCORD_API}/users/@me", headers=discord_headers(), timeout=15)
    r.raise_for_status()
    return r.json()


def fetch_user_guilds():
    r = requests.get(f"{DISCORD_API}/users/@me/guilds", headers=discord_headers(), timeout=15)
    r.raise_for_status()
    return r.json()


def manageable_guilds(guilds):
    # Discord "Manage Server" permission is 0x20 (32)
    MANAGE_GUILD = 0x20
    out = []
    for gobj in guilds:
        perms = int(gobj.get("permissions", 0))
        if (perms & MANAGE_GUILD) == MANAGE_GUILD:
            out.append(gobj)
    # sort by name
    out.sort(key=lambda x: (x.get("name") or "").lower())
    return out


def oauth_url(scopes: str, extra: dict | None = None):
    params = {
        "client_id": DISCORD_CLIENT_ID,
        "redirect_uri": DISCORD_REDIRECT_URI,
        "response_type": "code",
        "scope": scopes,
        "prompt": "consent"
    }
    if extra:
        params.update(extra)
    return f"{OAUTH_AUTHORIZE}?{urlencode(params)}"


def build_install_url():
    if not discord_configured():
        return ""
    params = {
        "client_id": DISCORD_CLIENT_ID,
        "scope": BOT_SCOPES,
        "permissions": BOT_PERMISSIONS_INT
    }
    return f"{OAUTH_AUTHORIZE}?{urlencode(params)}"


# -----------------------------
# Routes
# -----------------------------
@app.get("/")
def landing():
    install_url = build_install_url()
    return render_template(
        "landing.html",
        install_url=install_url,
        discord_ready=discord_configured()
    )


@app.get("/login")
def login():
    if not discord_configured():
        flash("Discord OAuth isn’t configured yet. Add env vars on Render.", "error")
        return render_template("login.html", discord_ready=False, auth_url="")
    # We use state to prevent CSRF
    state = secrets.token_urlsafe(24)
    session["oauth_state"] = state
    auth_url = oauth_url("identify guilds", {"state": state})
    return render_template("login.html", discord_ready=True, auth_url=auth_url)


@app.get("/auth/callback")
def auth_callback():
    if not discord_configured():
        flash("Discord OAuth isn’t configured. Set env vars first.", "error")
        return redirect(url_for("login"))

    code = request.args.get("code", "")
    state = request.args.get("state", "")
    expected_state = session.get("oauth_state", "")

    if not code:
        flash("No code received from Discord.", "error")
        return redirect(url_for("login"))
    if not state or state != expected_state:
        flash("State mismatch. Try logging in again.", "error")
        return redirect(url_for("login"))

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
        flash("Token exchange failed. Check redirect URI and client secret.", "error")
        return redirect(url_for("login"))

    token_json = token_res.json()
    session["discord_token"] = token_json.get("access_token")
    session.pop("oauth_state", None)

    # Pull user info
    try:
        user = fetch_discord_user()
    except Exception:
        flash("Couldn’t fetch Discord user. Try again.", "error")
        return redirect(url_for("login"))

    # Store minimal identity
    session["user"] = {
        "id": user.get("id"),
        "username": user.get("username"),
        "global_name": user.get("global_name") or "",
        "avatar": user.get("avatar") or "",
    }

    return redirect(url_for("guilds"))


@app.get("/logout")
def logout():
    session.clear()
    return redirect(url_for("landing"))


@app.get("/guilds")
@login_required
def guilds():
    if not session.get("discord_token"):
        flash("Session missing token. Log in again.", "error")
        return redirect(url_for("login"))

    try:
        guilds_all = fetch_user_guilds()
    except Exception:
        flash("Couldn’t load your servers from Discord.", "error")
        return redirect(url_for("login"))

    manageables = manageable_guilds(guilds_all)
    install_url = build_install_url()

    return render_template(
        "guilds.html",
        user=session.get("user"),
        guilds=manageables,
        install_url=install_url,
        discord_ready=discord_configured()
    )


@app.get("/select/<guild_id>")
@login_required
def select_guild(guild_id):
    # Save selection and ensure DB has a row
    try:
        guilds_all = fetch_user_guilds()
    except Exception:
        flash("Couldn’t load your servers from Discord.", "error")
        return redirect(url_for("guilds"))

    chosen = None
    for gobj in manageable_guilds(guilds_all):
        if gobj.get("id") == guild_id:
            chosen = gobj
            break

    if not chosen:
        flash("You can’t configure that server (or it doesn’t exist).", "error")
        return redirect(url_for("guilds"))

    session["active_guild"] = {"id": chosen["id"], "name": chosen["name"], "icon": chosen.get("icon")}

    db = get_db()
    db.execute("""
        INSERT INTO guild_settings (guild_id, guild_name)
        VALUES (?, ?)
        ON CONFLICT(guild_id) DO UPDATE SET guild_name=excluded.guild_name, updated_at=CURRENT_TIMESTAMP
    """, (chosen["id"], chosen["name"]))
    db.commit()

    log_event(chosen["id"], actor=session["user"]["username"], action="SELECT_GUILD", detail=f"Selected {chosen['name']}")
    return redirect(url_for("overview"))


def require_active_guild():
    ag = session.get("active_guild")
    if not ag:
        flash("Pick a server first.", "error")
        return redirect(url_for("guilds"))
    return ag


def get_settings(guild_id: str):
    db = get_db()
    row = db.execute("SELECT * FROM guild_settings WHERE guild_id=?", (guild_id,)).fetchone()
    return row


def get_recent_events(guild_id: str, limit: int = 20):
    db = get_db()
    return db.execute(
        "SELECT * FROM audit_events WHERE guild_id=? ORDER BY id DESC LIMIT ?",
        (guild_id, limit)
    ).fetchall()


@app.get("/dashboard")
@login_required
def overview():
    ag = require_active_guild()
    if not isinstance(ag, dict):
        return ag  # redirect

    settings = get_settings(ag["id"])
    events = get_recent_events(ag["id"], limit=12)

    # “Real-ish” data: settings + events are real. Stats are derived, not random.
    stats = {
        "servers": 1,
        "members": "—",     # Requires bot token / guild member intent. Leave as unknown for now.
        "reports_today": sum(1 for e in events if e["action"] == "REPORT"),
        "tickets_open": sum(1 for e in events if e["action"] == "TICKET_OPEN"),
        "latency": "—",
        "status": "Online" if session.get("discord_token") else "Degraded"
    }

    return render_template(
        "overview.html",
        user=session.get("user"),
        active_guild=ag,
        stats=stats,
        settings=settings,
        events=events
    )


@app.get("/servers")
@login_required
def servers():
    ag = require_active_guild()
    if not isinstance(ag, dict):
        return ag

    settings = get_settings(ag["id"])
    events = get_recent_events(ag["id"], limit=30)

    # Placeholder server list inside a single guild context
    # Later when the bot exists, this becomes real shards/clusters etc.
    server_rows = [
        {"name": f"{ag['name']} (Primary)", "region": "EU-West", "status": "Online", "members": "—", "alerts": "0"},
        {"name": "Shard-2 (placeholder)", "region": "US-East", "status": "Maintenance", "members": "—", "alerts": "2"},
    ]

    return render_template(
        "servers.html",
        user=session.get("user"),
        active_guild=ag,
        settings=settings,
        events=events,
        server_rows=server_rows
    )


@app.get("/reports")
@login_required
def reports():
    ag = require_active_guild()
    if not isinstance(ag, dict):
        return ag

    events = get_recent_events(ag["id"], limit=50)

    # Reports are real DB events of type REPORT
    report_events = [e for e in events if e["action"] == "REPORT"]

    return render_template(
        "reports.html",
        user=session.get("user"),
        active_guild=ag,
        report_events=report_events
    )


@app.get("/settings")
@login_required
def settings():
    ag = require_active_guild()
    if not isinstance(ag, dict):
        return ag
    s = get_settings(ag["id"])
    return render_template(
        "settings.html",
        user=session.get("user"),
        active_guild=ag,
        settings=s,
        discord_ready=discord_configured(),
        install_url=build_install_url()
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
          block_nsfw=?,
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
        onoff("block_nsfw"),
        onoff("anti_raid"),
        onoff("welcome_enabled"),
        welcome_message,
        ag["id"]
    ))
    db.commit()

    log_event(ag["id"], actor=session["user"]["username"], action="SETTINGS_SAVE", detail="Updated settings")

    flash("Settings saved.", "success")
    return redirect(url_for("settings"))


@app.post("/action/<action_name>")
@login_required
def do_action(action_name):
    ag = require_active_guild()
    if not isinstance(ag, dict):
        return ag

    # UI gimmicks: actions log to audit_events (later: wire to bot)
    actor = session["user"]["username"]
    action_map = {
        "create_invite": ("ACTION", "Created an invite (UI only)"),
        "sync_roles": ("ACTION", "Synced roles (UI only)"),
        "run_audit": ("ACTION", "Ran audit scan (UI only)"),
        "post_announcement": ("ACTION", "Posted announcement (UI only)"),
        "open_ticket": ("TICKET_OPEN", "Opened a ticket"),
        "report": ("REPORT", "Filed a report"),
    }

    if action_name not in action_map:
        flash("Unknown action.", "error")
        return redirect(url_for("overview"))

    a, detail = action_map[action_name]
    log_event(ag["id"], actor=actor, action=a, detail=detail)
    flash(detail, "success")
    return redirect(request.referrer or url_for("overview"))


@app.get("/health")
def health():
    return {"ok": True, "service": "sentra-dashboard"}


if __name__ == "__main__":
    # local dev
    app.run(host="0.0.0.0", port=5000, debug=True)
import os
from datetime import datetime
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session, flash

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret-change-me")


def login_required(view_func):
    @wraps(view_func)
    def wrapped(*args, **kwargs):
        if not session.get("user"):
            flash("You need to log in first.", "error")
            return redirect(url_for("login"))
        return view_func(*args, **kwargs)
    return wrapped


def mock_data(user: str):
    # Fake but believable data
    stats = {
        "servers": 3,
        "members": 124,
        "reports_today": 2,
        "tickets_open": 4,
        "uptime": "Online",
        "latency_ms": 42,
    }

    servers = [
        {"name": "Sentra HQ", "region": "EU-West", "status": "Online", "members": 58, "alerts": 0},
        {"name": "Raid Zone", "region": "US-East", "status": "Online", "members": 41, "alerts": 1},
        {"name": "Staff Lounge", "region": "EU-West", "status": "Maintenance", "members": 25, "alerts": 2},
    ]

    activity = [
        {"time": "Just now", "tag": "SYSTEM", "text": "Dashboard loaded successfully."},
        {"time": "3 min ago", "tag": "MOD", "text": f"{user} viewed Reports."},
        {"time": "18 min ago", "tag": "BOT", "text": "Auto-moderation rules synced."},
        {"time": "1 hr ago", "tag": "SECURITY", "text": "2FA reminder sent to staff."},
    ]

    reports = [
        {"id": "R-1042", "type": "Spam", "server": "Raid Zone", "priority": "High", "status": "Open"},
        {"id": "R-1041", "type": "Harassment", "server": "Sentra HQ", "priority": "Medium", "status": "Review"},
        {"id": "R-1040", "type": "Raid attempt", "server": "Sentra HQ", "priority": "High", "status": "Mitigated"},
        {"id": "R-1039", "type": "NSFW", "server": "Raid Zone", "priority": "Low", "status": "Closed"},
    ]

    # Simple “chart” values (render as bars)
    weekly_join = [12, 18, 9, 22, 31, 14, 27]
    moderation_load = {"Spam": 46, "Harassment": 21, "Raids": 13, "NSFW": 8, "Other": 12}

    return stats, servers, activity, reports, weekly_join, moderation_load


@app.route("/")
def index():
    if session.get("user"):
        return redirect(url_for("dashboard"))
    return render_template("index.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        if not username:
            flash("Type a username.", "error")
            return redirect(url_for("login"))

        session["user"] = username
        flash(f"Welcome, {username}. Try not to break anything.", "success")
        return redirect(url_for("dashboard"))

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out.", "success")
    return redirect(url_for("index"))


@app.route("/dashboard")
@login_required
def dashboard():
    user = session.get("user")
    stats, servers, activity, reports, weekly_join, moderation_load = mock_data(user)

    return render_template(
        "dashboard.html",
        user=user,
        stats=stats,
        servers=servers,
        activity=activity,
        reports=reports,
        weekly_join=weekly_join,
        moderation_load=moderation_load,
        now=datetime.now().strftime("%a %d %b • %H:%M"),
    )


@app.route("/servers")
@login_required
def servers():
    user = session.get("user")
    stats, servers, activity, reports, weekly_join, moderation_load = mock_data(user)
    return render_template("servers.html", user=user, servers=servers)


@app.route("/reports")
@login_required
def reports():
    user = session.get("user")
    stats, servers, activity, reports, weekly_join, moderation_load = mock_data(user)
    return render_template("reports.html", user=user, reports=reports)


@app.route("/settings", methods=["GET", "POST"])
@login_required
def settings():
    user = session.get("user")

    if request.method == "POST":
        # “Save” settings (fake)
        flash("Settings saved. The universe remains indifferent.", "success")
        return redirect(url_for("settings"))

    return render_template("settings.html", user=user)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
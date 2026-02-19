import os
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session, flash

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret-change-me")

def login_required(view_func):
    @wraps(view_func)
    def wrapped(*args, **kwargs):
        if not session.get("user"):
            flash("Please log in first.", "error")
            return redirect(url_for("login"))
        return view_func(*args, **kwargs)
    return wrapped

@app.get("/")
def home():
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
    return render_template("login.html", user=session.get("user"))

@app.get("/dashboard")
@login_required
def dashboard():
    user = session.get("user")

    stats = {
        "servers": 3,
        "members": 124,
        "reports_today": 2,
        "uptime": "Online",
    }
    activity = [
        {"time": "Just now", "text": "Dashboard loaded."},
        {"time": "5 min ago", "text": "Login successful."},
        {"time": "1 hr ago", "text": "System health: OK."},
    ]

    return render_template("dashboard.html", user=user, stats=stats, activity=activity)

@app.get("/logout")
def logout():
    session.clear()
    return redirect(url_for("home"))

if __name__ == "__main__":
    # local run
    app.run(host="0.0.0.0", port=5000, debug=True)
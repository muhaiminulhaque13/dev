import os, re, time
from contextlib import contextmanager
from functools import wraps

import psycopg2
from flask import Flask, request, render_template_string, g, session, redirect
from werkzeug.security import generate_password_hash, check_password_hash
from prometheus_client import Counter, Histogram, generate_latest, CONTENT_TYPE_LATEST

app = Flask(__name__)
app.secret_key = os.environ["SECRET_KEY"]
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax")

REQS = Counter("app_http_requests_total", "HTTP requests", ["method", "endpoint", "status"])
LAT = Histogram("app_request_latency_seconds", "Request latency", ["endpoint"])
REGS = Counter("app_registrations_total", "Successful registrations")
LOGINS = Counter("app_logins_total", "Login attempts", ["result"])

USERNAME_RE = re.compile(r"^[A-Za-z0-9_]{3,50}$")
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


@contextmanager
def db():
    c = psycopg2.connect(
        host=os.environ["DB_HOST"], dbname=os.environ["DB_NAME"],
        user=os.environ["DB_USER"], password=os.environ["DB_PASSWORD"])
    try:
        with c, c.cursor() as cur:   # commit/rollback automatic
            yield cur
    finally:
        c.close()


def init_db():
    for _ in range(30):
        try:
            with db() as cur:
                cur.execute("""CREATE TABLE IF NOT EXISTS users(
                    id SERIAL PRIMARY KEY,
                    username VARCHAR(50) UNIQUE NOT NULL,
                    email VARCHAR(100) UNIQUE NOT NULL,
                    created_at TIMESTAMP DEFAULT now())""")
                cur.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS password_hash TEXT")
            return
        except Exception as e:
            print("DB not ready:", e)
            time.sleep(2)
    raise SystemExit("DB connect failed")


init_db()

BASE = """<!doctype html>
<html><head><meta charset="utf-8"><title>{{ title }}</title>
<style>
body{font-family:system-ui,sans-serif;max-width:520px;margin:40px auto;padding:0 16px;color:#222}
nav{display:flex;gap:14px;align-items:center;margin-bottom:24px}
input{padding:8px;width:100%;box-sizing:border-box;margin:4px 0 12px}
button{padding:8px 16px;cursor:pointer}
.msg{background:#fff3cd;padding:8px 12px;border-radius:6px}
th{text-align:left;padding-right:16px}
</style></head><body>
<nav><b>RegApp</b>
{% if user %}<a href="/profile">Profile</a>{% else %}<a href="/login">Login</a><a href="/register">Register</a>{% endif %}
</nav>
{% if msg %}<p class="msg">{{ msg }}</p>{% endif %}
{{ body|safe }}
</body></html>"""

HOME = "<h2>Welcome</h2><p>Create an account or log in to see your profile.</p>"

REGISTER = """<h2>Create account</h2>
<form method="post" action="/register">
  <label>Username</label><input name="username" value="{{ form.get('username','') }}" required>
  <label>Email</label><input name="email" type="email" value="{{ form.get('email','') }}" required>
  <label>Password (min 8 characters)</label><input name="password" type="password" required>
  <label>Confirm password</label><input name="confirm" type="password" required>
  <button>Register</button>
</form>"""

LOGIN = """<h2>Login</h2>
<form method="post" action="/login">
  <label>Username or email</label><input name="identifier" value="{{ form.get('identifier','') }}" required>
  <label>Password</label><input name="password" type="password" required>
  <button>Login</button>
</form>"""

PROFILE = """<h2>My profile</h2>
<table>
<tr><th>Username</th><td>{{ p.username }}</td></tr>
<tr><th>Email</th><td>{{ p.email }}</td></tr>
<tr><th>Member since</th><td>{{ p.created_at }}</td></tr>
</table>
<h3>Change password</h3>
<form method="post" action="/change-password">
  <label>Current password</label><input name="current" type="password" required>
  <label>New password (min 8 characters)</label><input name="password" type="password" required>
  <label>Confirm new password</label><input name="confirm" type="password" required>
  <button>Change password</button>
</form>
<br>
<form method="post" action="/logout"><button>Logout</button></form>"""


def page(title, body, msg="", status=200, **ctx):
    ctx.setdefault("form", {})
    inner = render_template_string(body, **ctx)
    html = render_template_string(BASE, title=title, body=inner, msg=msg,
                                 user=session.get("username"))
    return html, status


def login_required(f):
    @wraps(f)
    def wrapper(*a, **k):
        if "user_id" not in session:
            return redirect("/login")
        return f(*a, **k)
    return wrapper


def password_error(p1, p2):
    if len(p1) < 8:
        return "Password must be at least 8 characters"
    if len(p1) > 128:
        return "Password is too long"
    if p1 != p2:
        return "Passwords do not match"
    return None


@app.before_request
def start():
    g.t = time.time()


@app.after_request
def record(resp):
    ep = request.path
    if ep != "/metrics":
        REQS.labels(request.method, ep, resp.status_code).inc()
        LAT.labels(ep).observe(time.time() - g.t)
    return resp


@app.get("/")
def index():
    if "user_id" in session:
        return redirect("/profile")
    return page("Home", HOME)


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        return page("Register", REGISTER)
    u = request.form.get("username", "").strip()
    e = request.form.get("email", "").strip().lower()
    p1 = request.form.get("password", "")
    p2 = request.form.get("confirm", "")
    err = None
    if not USERNAME_RE.match(u):
        err = "Username: 3-50 characters, letters, numbers and _ only"
    elif not EMAIL_RE.match(e) or len(e) > 100:
        err = "Please enter a valid email"
    else:
        err = password_error(p1, p2)
    if err:
        return page("Register", REGISTER, msg=err, status=400, form=request.form)
    try:
        with db() as cur:
            cur.execute(
                "INSERT INTO users(username,email,password_hash) VALUES(%s,%s,%s) RETURNING id",
                (u, e, generate_password_hash(p1)))
            uid = cur.fetchone()[0]
    except psycopg2.errors.UniqueViolation:
        return page("Register", REGISTER, msg="Username or email already exists",
                    status=409, form=request.form)
    REGS.inc()
    session.clear()
    session["user_id"], session["username"] = uid, u
    return redirect("/profile")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return page("Login", LOGIN)
    ident = request.form.get("identifier", "").strip()
    pw = request.form.get("password", "")
    with db() as cur:
        cur.execute(
            "SELECT id, username, password_hash FROM users WHERE username=%s OR email=%s",
            (ident, ident.lower()))
        row = cur.fetchone()
    if row and row[2] and check_password_hash(row[2], pw):
        LOGINS.labels("success").inc()
        session.clear()
        session["user_id"], session["username"] = row[0], row[1]
        return redirect("/profile")
    LOGINS.labels("failure").inc()
    return page("Login", LOGIN, msg="Invalid username or password", status=401, form=request.form)


@app.post("/logout")
def logout():
    session.clear()
    return redirect("/")


@app.get("/profile")
@login_required
def profile():
    with db() as cur:
        cur.execute("SELECT username,email,created_at FROM users WHERE id=%s", (session["user_id"],))
        row = cur.fetchone()
    if not row:
        session.clear()
        return redirect("/login")
    p = {"username": row[0], "email": row[1], "created_at": row[2].strftime("%Y-%m-%d %H:%M")}
    return page("Profile", PROFILE, p=p)


@app.post("/change-password")
@login_required
def change_password():
    cur_pw = request.form.get("current", "")
    p1 = request.form.get("password", "")
    p2 = request.form.get("confirm", "")
    with db() as cur:
        cur.execute("SELECT username,email,created_at,password_hash FROM users WHERE id=%s",
                    (session["user_id"],))
        row = cur.fetchone()
    if not row:
        session.clear()
        return redirect("/login")
    p = {"username": row[0], "email": row[1], "created_at": row[2].strftime("%Y-%m-%d %H:%M")}
    if not row[3] or not check_password_hash(row[3], cur_pw):
        return page("Profile", PROFILE, msg="Current password is wrong", status=400, p=p)
    err = password_error(p1, p2)
    if err:
        return page("Profile", PROFILE, msg=err, status=400, p=p)
    with db() as cur:
        cur.execute("UPDATE users SET password_hash=%s WHERE id=%s",
                    (generate_password_hash(p1), session["user_id"]))
    return page("Profile", PROFILE, msg="Password updated", p=p)


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/metrics")
def metrics():
    return generate_latest(), 200, {"Content-Type": CONTENT_TYPE_LATEST}

import os, time
import psycopg2
from flask import Flask, request, jsonify, render_template_string, g
from prometheus_client import Counter, Histogram, generate_latest, CONTENT_TYPE_LATEST

app = Flask(__name__)

REQS = Counter("app_http_requests_total", "HTTP requests", ["method", "endpoint", "status"])
LAT = Histogram("app_request_latency_seconds", "Request latency", ["endpoint"])
REGS = Counter("app_registrations_total", "Successful registrations")

def conn():
    return psycopg2.connect(
        host=os.environ["DB_HOST"], dbname=os.environ["DB_NAME"],
        user=os.environ["DB_USER"], password=os.environ["DB_PASSWORD"])

def init_db():
    for _ in range(30):
        try:
            with conn() as c, c.cursor() as cur:
                cur.execute("""CREATE TABLE IF NOT EXISTS users(
                    id SERIAL PRIMARY KEY,
                    username VARCHAR(50) UNIQUE NOT NULL,
                    email VARCHAR(100) UNIQUE NOT NULL,
                    created_at TIMESTAMP DEFAULT now())""")
            return
        except Exception as e:
            print("DB not ready:", e); time.sleep(2)
    raise SystemExit("DB connect failed")

init_db()

PAGE = """
<h2>Registration v3</h2>
<form method="post" action="/register">
  <input name="username" placeholder="Username" required><br><br>
  <input name="email" type="email" placeholder="Email" required><br><br>
  <button>Register</button>
</form>
<p>{{ msg }}</p>
<a href="/users">All users</a>
"""

@app.before_request
def start(): g.t = time.time()

@app.after_request
def record(resp):
    ep = request.path
    if ep != "/metrics":
        REQS.labels(request.method, ep, resp.status_code).inc()
        LAT.labels(ep).observe(time.time() - g.t)
    return resp

@app.get("/")
def index(): return render_template_string(PAGE, msg="")

@app.post("/register")
def register():
    u, e = request.form["username"].strip(), request.form["email"].strip()
    try:
        with conn() as c, c.cursor() as cur:
            cur.execute("INSERT INTO users(username,email) VALUES(%s,%s)", (u, e))
        REGS.inc()
        return render_template_string(PAGE, msg=f"Registered: {u}")
    except psycopg2.errors.UniqueViolation:
        return render_template_string(PAGE, msg="Username/email already exists"), 409

@app.get("/users")
def users():
    with conn() as c, c.cursor() as cur:
        cur.execute("SELECT id,username,email,created_at FROM users ORDER BY id")
        rows = cur.fetchall()
    return jsonify([{"id": r[0], "username": r[1], "email": r[2], "created_at": str(r[3])} for r in rows])

@app.get("/health")
def health(): return {"status": "ok"}

@app.get("/metrics")
def metrics(): return generate_latest(), 200, {"Content-Type": CONTENT_TYPE_LATEST}

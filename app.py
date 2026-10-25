"""Task Calendar - Flask + SQLite backend.

Run:  pip install -r requirements.txt
      python app.py        ->  http://127.0.0.1:5000
"""
import os
import secrets
import sqlite3
from datetime import date

from flask import Flask, g, jsonify, request, send_from_directory, session
from werkzeug.security import check_password_hash, generate_password_hash

BASE = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE, "calendar.db")
KEY_PATH = os.path.join(BASE, ".secret_key")
MAX_IMG = 2_000_000  # chars of data-URI per task

app = Flask(__name__, static_folder=os.path.join(BASE, "static"), static_url_path="/static")
if not os.path.exists(KEY_PATH):
    with open(KEY_PATH, "w") as f:
        f.write(secrets.token_hex(32))
app.secret_key = open(KEY_PATH).read().strip()
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax",
                  MAX_CONTENT_LENGTH=4 * 1024 * 1024)

SCHEMA = """
CREATE TABLE IF NOT EXISTS users(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  pw TEXT NOT NULL,
  is_admin INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS tasks(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  title TEXT NOT NULL, date TEXT NOT NULL,
  notes TEXT DEFAULT '', link TEXT DEFAULT '', img TEXT DEFAULT '',
  done INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS shares(
  token TEXT PRIMARY KEY,
  user_id INTEGER UNIQUE NOT NULL REFERENCES users(id) ON DELETE CASCADE);
"""


def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys=ON")
    return g.db


@app.teardown_appcontext
def close_db(_):
    d = g.pop("db", None)
    if d:
        d.close()


ADMIN_USER = os.environ.get("ADMIN_USER", "admin")
ADMIN_PASS = os.environ.get("ADMIN_PASSWORD", "Admin@12345")  # change after first login!


def init_db():
    """Create tables (and the default admin account if it does not exist)."""
    with sqlite3.connect(DB_PATH) as c:
        c.executescript(SCHEMA)
        cols = [r[1] for r in c.execute("PRAGMA table_info(users)")]
        if "is_admin" not in cols:  # upgrade an older database
            c.execute("ALTER TABLE users ADD COLUMN is_admin INTEGER DEFAULT 0")
        if not c.execute("SELECT 1 FROM users WHERE is_admin=1").fetchone():
            c.execute("INSERT OR IGNORE INTO users(username,pw,is_admin) VALUES(?,?,1)",
                      (ADMIN_USER, generate_password_hash(ADMIN_PASS)))


def err(msg, code=400):
    return jsonify(error=msg), code


def me():
    uid = session.get("uid")
    if not uid:
        return None
    return db().execute("SELECT id, username, is_admin FROM users WHERE id=?", (uid,)).fetchone()


def clean_task(d):
    """Validate and normalise task JSON. Returns (dict, error)."""
    title = str(d.get("title", "")).strip()[:200] or "Untitled"
    try:
        day = date.fromisoformat(str(d.get("date", "")))
    except ValueError:
        return None, "Invalid date"
    link = str(d.get("link", "")).strip()[:500]
    if link and not link.lower().startswith(("http://", "https://")):
        return None, "Link must start with http:// or https://"
    img = str(d.get("img", ""))
    if img and not img.startswith("data:image/"):
        return None, "Invalid image"
    if len(img) > MAX_IMG:
        return None, "Image too large"
    return dict(title=title, date=day.isoformat(), notes=str(d.get("notes", ""))[:5000],
                link=link, img=img, done=1 if d.get("done") else 0), None


def row(r, with_img=True):
    o = dict(id=r["id"], title=r["title"], date=r["date"], notes=r["notes"],
             link=r["link"], done=bool(r["done"]))
    if with_img:
        o["img"] = r["img"]
    return o


# ---------------------------------------------------------------- pages
@app.get("/")
@app.get("/s/<token>")
def index(token=None):
    # Works whether index.html is in ./static/ or sitting next to app.py
    for folder in (app.static_folder, BASE):
        if os.path.exists(os.path.join(folder, "index.html")):
            return send_from_directory(folder, "index.html")
    return ("index.html not found. Put it in a folder named 'static' next to app.py "
            f"(looked in: {app.static_folder}).", 404)


# ---------------------------------------------------------------- auth
@app.post("/api/register")
def register():
    d = request.get_json(silent=True) or {}
    u, p = str(d.get("username", "")).strip().lower(), str(d.get("password", ""))
    if not (3 <= len(u) <= 30) or not u.replace("_", "").replace(".", "").isalnum():
        return err("Username: 3-30 letters/numbers/_/.")
    if len(p) < 6:
        return err("Password needs 6+ characters")
    try:
        cur = db().execute("INSERT INTO users(username, pw) VALUES(?,?)",
                           (u, generate_password_hash(p)))
        db().commit()
    except sqlite3.IntegrityError:
        return err("Username already taken", 409)
    session.clear()
    session["uid"] = cur.lastrowid
    return jsonify(username=u)


@app.post("/api/login")
def login():
    d = request.get_json(silent=True) or {}
    u = str(d.get("username", "")).strip().lower()
    r = db().execute("SELECT * FROM users WHERE username=?", (u,)).fetchone()
    if not r or not check_password_hash(r["pw"], str(d.get("password", ""))):
        return err("Wrong username or password", 401)
    session.clear()
    session["uid"] = r["id"]
    return jsonify(username=r["username"], is_admin=bool(r["is_admin"]))


@app.post("/api/logout")
def logout():
    session.clear()
    return jsonify(ok=True)


@app.get("/api/me")
def whoami():
    u = me()
    return jsonify(username=u["username"], is_admin=bool(u["is_admin"])) if u else err("Not logged in", 401)


@app.post("/api/password")
def change_password():
    u = me()
    if not u:
        return err("Not logged in", 401)
    d = request.get_json(silent=True) or {}
    r = db().execute("SELECT pw FROM users WHERE id=?", (u["id"],)).fetchone()
    if not check_password_hash(r["pw"], str(d.get("old", ""))):
        return err("Current password is wrong", 403)
    new = str(d.get("new", ""))
    if len(new) < 6:
        return err("New password needs 6+ characters")
    db().execute("UPDATE users SET pw=? WHERE id=?", (generate_password_hash(new), u["id"]))
    db().commit()
    return jsonify(ok=True)


# ---------------------------------------------------------------- admin
def admin_only():
    u = me()
    if not u:
        return None, err("Not logged in", 401)
    if not u["is_admin"]:
        return None, err("Admins only", 403)
    return u, None


@app.get("/api/admin/users")
def admin_users():
    u, e = admin_only()
    if e:
        return e
    rs = db().execute("SELECT u.id, u.username, u.is_admin, "
                      "(SELECT COUNT(*) FROM tasks t WHERE t.user_id=u.id) AS n "
                      "FROM users u ORDER BY u.id").fetchall()
    return jsonify([dict(id=r["id"], username=r["username"], is_admin=bool(r["is_admin"]),
                         tasks=r["n"]) for r in rs])


@app.delete("/api/admin/users/<int:uid>")
def admin_delete_user(uid):
    u, e = admin_only()
    if e:
        return e
    if uid == u["id"]:
        return err("You cannot delete your own account")
    db().execute("DELETE FROM users WHERE id=?", (uid,))  # tasks/shares cascade
    db().commit()
    return jsonify(ok=True)


@app.post("/api/admin/users/<int:uid>/reset")
def admin_reset(uid):
    u, e = admin_only()
    if e:
        return e
    new = secrets.token_urlsafe(9)
    cur = db().execute("UPDATE users SET pw=? WHERE id=?", (generate_password_hash(new), uid))
    db().commit()
    return jsonify(password=new) if cur.rowcount else err("User not found", 404)


# ---------------------------------------------------------------- tasks
@app.get("/api/tasks")
def list_tasks():
    u = me()
    if not u:
        return err("Not logged in", 401)
    rs = db().execute("SELECT * FROM tasks WHERE user_id=? ORDER BY date, id", (u["id"],)).fetchall()
    return jsonify([row(r) for r in rs])


@app.post("/api/tasks")
def create_task():
    u = me()
    if not u:
        return err("Not logged in", 401)
    t, e = clean_task(request.get_json(silent=True) or {})
    if e:
        return err(e)
    cur = db().execute(
        "INSERT INTO tasks(user_id,title,date,notes,link,img,done) VALUES(?,?,?,?,?,?,?)",
        (u["id"], t["title"], t["date"], t["notes"], t["link"], t["img"], t["done"]))
    db().commit()
    return jsonify(id=cur.lastrowid, **{**t, "done": bool(t["done"])}), 201


@app.put("/api/tasks/<int:tid>")
def update_task(tid):
    u = me()
    if not u:
        return err("Not logged in", 401)
    t, e = clean_task(request.get_json(silent=True) or {})
    if e:
        return err(e)
    cur = db().execute(
        "UPDATE tasks SET title=?,date=?,notes=?,link=?,img=?,done=? WHERE id=? AND user_id=?",
        (t["title"], t["date"], t["notes"], t["link"], t["img"], t["done"], tid, u["id"]))
    db().commit()
    if not cur.rowcount:
        return err("Task not found", 404)
    return jsonify(id=tid, **{**t, "done": bool(t["done"])})


@app.delete("/api/tasks/<int:tid>")
def delete_task(tid):
    u = me()
    if not u:
        return err("Not logged in", 401)
    cur = db().execute("DELETE FROM tasks WHERE id=? AND user_id=?", (tid, u["id"]))
    db().commit()
    return jsonify(ok=True) if cur.rowcount else err("Task not found", 404)


# ---------------------------------------------------------------- sharing
@app.post("/api/share")
def share():
    """Create (or return the existing) read-only share link for this user."""
    u = me()
    if not u:
        return err("Not logged in", 401)
    r = db().execute("SELECT token FROM shares WHERE user_id=?", (u["id"],)).fetchone()
    token = r["token"] if r else secrets.token_urlsafe(16)
    if not r:
        db().execute("INSERT INTO shares(token,user_id) VALUES(?,?)", (token, u["id"]))
        db().commit()
    return jsonify(url=request.host_url.rstrip("/") + "/s/" + token)


@app.delete("/api/share")
def unshare():
    u = me()
    if not u:
        return err("Not logged in", 401)
    db().execute("DELETE FROM shares WHERE user_id=?", (u["id"],))
    db().commit()
    return jsonify(ok=True)


@app.get("/api/shared/<token>")
def shared(token):
    r = db().execute("SELECT u.id, u.username FROM shares s JOIN users u ON u.id=s.user_id "
                     "WHERE s.token=?", (token,)).fetchone()
    if not r:
        return err("Link not found", 404)
    ts = db().execute("SELECT * FROM tasks WHERE user_id=? ORDER BY date, id", (r["id"],)).fetchall()
    return jsonify(by=r["username"], tasks=[row(t) for t in ts])


init_db()

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", 5000)), debug=False)
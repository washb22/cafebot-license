import os
import sqlite3
import time
import hmac
import hashlib
import secrets
import string
import functools
from datetime import datetime, timezone

from flask import (
    Flask, request, jsonify, render_template,
    redirect, url_for, session, flash, g
)

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
DB_PATH = os.path.join(DATA_DIR, "licenses.db")

ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "cafebot2026")
SECRET_KEY = os.environ.get("SECRET_KEY", "dev-secret-key-change-me")
HMAC_SECRET = os.environ.get(
    "HMAC_SECRET", "CafeBot_LicenseKey_2026_v1_Secret"
).encode()

app = Flask(__name__, template_folder=os.path.join(BASE_DIR, "templates"))
app.secret_key = SECRET_KEY

# ---------------------------------------------------------------------------
# Database helpers
# ---------------------------------------------------------------------------

def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    os.makedirs(DATA_DIR, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS licenses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            license_key TEXT UNIQUE NOT NULL,
            hwid TEXT,
            created_at INTEGER NOT NULL,
            expires_at INTEGER NOT NULL,
            last_check INTEGER,
            active INTEGER DEFAULT 1
        )
    """)
    conn.commit()
    conn.close()


# ---------------------------------------------------------------------------
# Utility
# ---------------------------------------------------------------------------

def generate_license_key():
    chars = string.ascii_uppercase + string.digits
    parts = [
        "".join(secrets.choice(chars) for _ in range(4))
        for _ in range(4)
    ]
    return "-".join(parts)


def compute_hmac(message: str) -> str:
    return hmac.new(HMAC_SECRET, message.encode(), hashlib.sha256).hexdigest()


def verify_hmac(message: str, signature: str) -> bool:
    expected = compute_hmac(message)
    return hmac.compare_digest(expected, signature)


def ts_to_str(ts):
    if ts is None:
        return "-"
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M")


def license_status(row):
    now = int(time.time())
    if not row["active"]:
        return "차단"
    if row["expires_at"] < now:
        return "만료"
    if row["hwid"]:
        return "사용 중"
    return "미등록"


app.jinja_env.globals.update(ts_to_str=ts_to_str, license_status=license_status, int=int, time=time)

# ---------------------------------------------------------------------------
# Auth helpers
# ---------------------------------------------------------------------------

def login_required(f):
    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        if not session.get("admin"):
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return wrapper


# ---------------------------------------------------------------------------
# Admin routes
# ---------------------------------------------------------------------------

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        pw = request.form.get("password", "")
        if pw == ADMIN_PASSWORD:
            session["admin"] = True
            return redirect(url_for("dashboard"))
        flash("비밀번호가 틀렸습니다.")
    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/")
@login_required
def dashboard():
    db = get_db()
    q = request.args.get("q", "").strip()
    status_filter = request.args.get("status", "").strip()

    rows = db.execute(
        "SELECT * FROM licenses ORDER BY created_at DESC"
    ).fetchall()

    # filtering
    filtered = []
    now = int(time.time())
    for r in rows:
        s = license_status(r)
        if status_filter and s != status_filter:
            continue
        if q:
            haystack = f"{r['name']} {r['license_key']} {r['hwid'] or ''}".lower()
            if q.lower() not in haystack:
                continue
        filtered.append(r)

    # stats
    total = len(rows)
    active_count = sum(1 for r in rows if license_status(r) == "사용 중")
    expired_count = sum(1 for r in rows if license_status(r) == "만료")
    unused_count = sum(1 for r in rows if license_status(r) == "미등록")
    blocked_count = sum(1 for r in rows if license_status(r) == "차단")

    return render_template(
        "dashboard.html",
        licenses=filtered,
        q=q,
        status_filter=status_filter,
        total=total,
        active_count=active_count,
        expired_count=expired_count,
        unused_count=unused_count,
        blocked_count=blocked_count,
    )


@app.route("/admin/create", methods=["POST"])
@login_required
def create_license():
    name = request.form.get("name", "").strip()
    duration = int(request.form.get("duration", 30))
    if not name:
        flash("이름을 입력하세요.")
        return redirect(url_for("dashboard"))

    key = generate_license_key()
    now = int(time.time())
    expires = now + duration * 86400

    db = get_db()
    db.execute(
        "INSERT INTO licenses (name, license_key, created_at, expires_at) VALUES (?, ?, ?, ?)",
        (name, key, now, expires),
    )
    db.commit()
    flash(f"새 키 발급 완료: {key}")
    return redirect(url_for("dashboard"))


@app.route("/admin/reset_hwid/<int:lid>", methods=["POST"])
@login_required
def reset_hwid(lid):
    db = get_db()
    db.execute("UPDATE licenses SET hwid = NULL WHERE id = ?", (lid,))
    db.commit()
    flash("PC 등록이 초기화되었습니다.")
    return redirect(url_for("dashboard"))


@app.route("/admin/extend/<int:lid>", methods=["POST"])
@login_required
def extend_license(lid):
    days = int(request.form.get("days", 30))
    db = get_db()
    db.execute(
        "UPDATE licenses SET expires_at = expires_at + ? WHERE id = ?",
        (days * 86400, lid),
    )
    db.commit()
    flash(f"{days}일 연장 완료.")
    return redirect(url_for("dashboard"))


@app.route("/admin/toggle/<int:lid>", methods=["POST"])
@login_required
def toggle_license(lid):
    db = get_db()
    row = db.execute("SELECT active FROM licenses WHERE id = ?", (lid,)).fetchone()
    if row:
        new_val = 0 if row["active"] else 1
        db.execute("UPDATE licenses SET active = ? WHERE id = ?", (new_val, lid))
        db.commit()
        flash("상태가 변경되었습니다.")
    return redirect(url_for("dashboard"))


@app.route("/admin/delete/<int:lid>", methods=["POST"])
@login_required
def delete_license(lid):
    db = get_db()
    db.execute("DELETE FROM licenses WHERE id = ?", (lid,))
    db.commit()
    flash("라이선스가 삭제되었습니다.")
    return redirect(url_for("dashboard"))


# ---------------------------------------------------------------------------
# Public API endpoints (called by CafeBot client)
# ---------------------------------------------------------------------------

@app.route("/api/license/activate", methods=["POST"])
def api_activate():
    data = request.get_json(silent=True) or {}
    license_key = data.get("license_key", "").strip()
    hwid = data.get("hwid", "").strip()
    signature = data.get("signature", "")

    if not license_key or not hwid:
        return jsonify({"success": False, "message": "license_key와 hwid가 필요합니다."}), 400

    # Optional HMAC verification (if client sends signature)
    if signature:
        msg = f"{license_key}:{hwid}"
        if not verify_hmac(msg, signature):
            return jsonify({"success": False, "message": "서명 검증 실패"}), 403

    db = get_db()
    row = db.execute(
        "SELECT * FROM licenses WHERE license_key = ?", (license_key,)
    ).fetchone()

    if not row:
        return jsonify({"success": False, "message": "유효하지 않은 라이선스 키입니다."}), 404

    if not row["active"]:
        return jsonify({"success": False, "message": "차단된 라이선스입니다."}), 403

    now = int(time.time())
    if row["expires_at"] < now:
        return jsonify({"success": False, "message": "만료된 라이선스입니다."}), 403

    if row["hwid"] and row["hwid"] != hwid:
        return jsonify({
            "success": False,
            "message": "이미 다른 PC에 등록된 라이선스입니다. 관리자에게 초기화를 요청하세요."
        }), 403

    # Bind HWID
    db.execute(
        "UPDATE licenses SET hwid = ?, last_check = ? WHERE id = ?",
        (hwid, now, row["id"]),
    )
    db.commit()

    return jsonify({
        "success": True,
        "expiry": row["expires_at"],
        "message": "라이선스가 활성화되었습니다."
    })


@app.route("/api/license/verify", methods=["POST"])
def api_verify():
    data = request.get_json(silent=True) or {}
    license_key = data.get("license_key", "").strip()
    hwid = data.get("hwid", "").strip()
    signature = data.get("signature", "")

    if not license_key or not hwid:
        return jsonify({"valid": False, "error": "license_key와 hwid가 필요합니다."}), 400

    if signature:
        msg = f"{license_key}:{hwid}"
        if not verify_hmac(msg, signature):
            return jsonify({"valid": False, "error": "서명 검증 실패"}), 403

    db = get_db()
    row = db.execute(
        "SELECT * FROM licenses WHERE license_key = ?", (license_key,)
    ).fetchone()

    if not row:
        return jsonify({"valid": False, "error": "유효하지 않은 라이선스 키입니다."}), 404

    if not row["active"]:
        return jsonify({"valid": False, "error": "차단된 라이선스입니다."}), 403

    now = int(time.time())
    if row["expires_at"] < now:
        return jsonify({"valid": False, "error": "만료된 라이선스입니다."}), 403

    if row["hwid"] != hwid:
        return jsonify({"valid": False, "error": "등록되지 않은 PC입니다."}), 403

    # Update last_check
    db.execute(
        "UPDATE licenses SET last_check = ? WHERE id = ?", (now, row["id"])
    )
    db.commit()

    return jsonify({
        "valid": True,
        "expiry": row["expires_at"],
    })


# ---------------------------------------------------------------------------
# Health check
# ---------------------------------------------------------------------------

@app.route("/health")
def health():
    return jsonify({"status": "ok"})


# ---------------------------------------------------------------------------
# Init & Run
# ---------------------------------------------------------------------------

init_db()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5003, debug=True)

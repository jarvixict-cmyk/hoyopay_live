import os
import secrets
import sqlite3
from datetime import datetime, timezone
from functools import wraps
from pathlib import Path

from flask import Flask, jsonify, render_template, request, session
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

BASE_DIR = Path(__file__).resolve().parent
DATABASE = BASE_DIR / "hoyopay.db"
UPLOAD_FOLDER = BASE_DIR / "static" / "uploads" / "receipts"
UPLOAD_FOLDER.mkdir(parents=True, exist_ok=True)
ALLOWED_RECEIPT_EXTENSIONS = {"png", "jpg", "jpeg"}
DEFAULT_CONFIG = {
    "usdt_rate": 92.80,
    "trc20_address": "TQn9Y8rK4u7mN5pL2xJ6cV8bD3fG1hA9s",
    "bep20_address": "0x71F2A6d4C9e8B3a7f0D5c1E6b2A9f4C8d7E3B1A0",
    "telegram_support_url": "https://t.me/your_support_handle",
}

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("SESSION_COOKIE_SECURE", "0") == "1",
    MAX_CONTENT_LENGTH=8 * 1024 * 1024,
)


def utc_now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def clean_text(value):
    return str(value or "").strip()


def clean_email(value):
    return clean_text(value).lower()


def db_connect():
    connection = sqlite3.connect(DATABASE, timeout=10, isolation_level=None)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA busy_timeout = 10000")
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA journal_mode = WAL")
    return connection


def init_db():
    with db_connect() as db:
        db.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL UNIQUE COLLATE NOCASE,
                password_hash TEXT NOT NULL,
                referral_code TEXT NOT NULL UNIQUE,
                referred_by INTEGER REFERENCES users(id),
                referral_balance REAL NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS user_upis (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                upi_id TEXT NOT NULL,
                is_primary INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                UNIQUE(user_id, upi_id)
            );
            CREATE TABLE IF NOT EXISTS orders (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL REFERENCES users(id),
                usdt_amount REAL NOT NULL,
                inr_total REAL NOT NULL,
                paid_inr REAL NOT NULL DEFAULT 0,
                network TEXT NOT NULL,
                txid TEXT NOT NULL,
                status TEXT NOT NULL,
                upi_id TEXT NOT NULL,
                rate REAL NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS tranches (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                order_id INTEGER NOT NULL REFERENCES orders(id) ON DELETE CASCADE,
                amount_inr REAL NOT NULL,
                utr TEXT NOT NULL DEFAULT 'N/A',
                proof_url TEXT,
                timestamp TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS support_tickets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL REFERENCES users(id),
                status TEXT NOT NULL DEFAULT 'OPEN',
                created_at TEXT NOT NULL,
                closed_at TEXT
            );
            CREATE TABLE IF NOT EXISTS support_messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ticket_id INTEGER NOT NULL REFERENCES support_tickets(id) ON DELETE CASCADE,
                sender_role TEXT NOT NULL,
                message TEXT NOT NULL,
                timestamp TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS referral_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL REFERENCES users(id),
                amount_inr REAL NOT NULL,
                description TEXT NOT NULL,
                timestamp TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS withdrawal_requests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL REFERENCES users(id),
                upi_id TEXT NOT NULL,
                amount REAL NOT NULL,
                invite_count INTEGER NOT NULL,
                status TEXT NOT NULL DEFAULT 'PROCESSING',
                note TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS system_config (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            """
        )
        for key, value in DEFAULT_CONFIG.items():
            db.execute("INSERT OR IGNORE INTO system_config(key, value) VALUES (?, ?)", (key, str(value)))


init_db()


def config_values(db=None):
    owns_connection = db is None
    db = db or db_connect()
    values = {row["key"]: row["value"] for row in db.execute("SELECT key, value FROM system_config")}
    values["usdt_rate"] = float(values.get("usdt_rate", DEFAULT_CONFIG["usdt_rate"]))
    if owns_connection:
        db.close()
    return values


def user_from_session(db):
    email = clean_email(session.get("user_email"))
    return db.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone() if email else None


def upis_for(db, user_id):
    return [row["upi_id"] for row in db.execute("SELECT upi_id FROM user_upis WHERE user_id = ? ORDER BY id", (user_id,))]


def public_user(db, user):
    upis = upis_for(db, user["id"])
    primary = db.execute("SELECT upi_id FROM user_upis WHERE user_id = ? AND is_primary = 1", (user["id"],)).fetchone()
    invite_count = db.execute("SELECT COUNT(*) AS total FROM users WHERE referred_by = ?", (user["id"],)).fetchone()["total"]
    return {"email": user["email"], "upi_id": primary["upi_id"] if primary else (upis[0] if upis else ""), "upi_ids": upis, "invite_code": user["referral_code"], "invite_link": f"/login?invite={user['referral_code']}", "invite_count": invite_count, "referral_balance": user["referral_balance"]}


def admin_required(handler):
    @wraps(handler)
    def wrapped(*args, **kwargs):
        if not session.get("admin_authenticated"):
            return jsonify({"success": False, "error": "Admin authentication required."}), 401
        return handler(*args, **kwargs)
    return wrapped


def user_required(handler):
    @wraps(handler)
    def wrapped(*args, **kwargs):
        with db_connect() as db:
            if not user_from_session(db):
                return jsonify({"success": False, "error": "User authentication required."}), 401
        return handler(*args, **kwargs)
    return wrapped


def error_response(message, status):
    return jsonify({"success": False, "error": message}), status


@app.errorhandler(404)
def not_found(error):
    if request.path.startswith("/api/"):
        return error_response("Resource not found.", 404)
    return "Not found", 404


@app.errorhandler(500)
def server_error(error):
    return error_response("Internal server error.", 500) if request.path.startswith("/api/") else ("Internal server error", 500)


@app.errorhandler(sqlite3.OperationalError)
def database_error(error):
    return error_response("Database is busy; please retry.", 503)


@app.get("/")
def index():
    with db_connect() as db:
        user = user_from_session(db)
        return render_template("user.html", show_auth=user is None, user=public_user(db, user) if user else None, config=config_values(db))


@app.get("/login")
def user_login_page():
    return render_template("user.html", show_auth=True, user=None, config=config_values())


@app.get("/admin")
def admin_page():
    return render_template("admin.html", show_login=not session.get("admin_authenticated"))


@app.get("/admin/login")
def admin_login_page():
    return render_template("admin.html", show_login=True)


@app.get("/api/config")
def get_config():
    return jsonify(config_values())


@app.post("/api/auth/register")
def register():
    payload = request.get_json(silent=True) or {}
    email = clean_email(payload.get("email"))
    password = clean_text(payload.get("password"))
    confirm = clean_text(payload.get("confirm_password"))
    upi_id = clean_text(payload.get("upi_id"))
    invite_code = clean_text(payload.get("invite_code")).upper()
    if not email or "@" not in email or not password or password != confirm or not upi_id:
        return error_response("Valid email, matching passwords, and UPI ID are required.", 400)
    with db_connect() as db:
        db.execute("BEGIN IMMEDIATE")
        if db.execute("SELECT 1 FROM users WHERE email = ?", (email,)).fetchone():
            return error_response("An account with that email already exists.", 409)
        inviter = db.execute("SELECT * FROM users WHERE referral_code = ?", (invite_code,)).fetchone() if invite_code else None
        code = secrets.token_hex(4).upper()
        while db.execute("SELECT 1 FROM users WHERE referral_code = ?", (code,)).fetchone():
            code = secrets.token_hex(4).upper()
        cursor = db.execute("INSERT INTO users(email,password_hash,referral_code,referred_by,created_at) VALUES(?,?,?,?,?)", (email, generate_password_hash(password), code, inviter["id"] if inviter else None, utc_now()))
        user_id = cursor.lastrowid
        db.execute("INSERT INTO user_upis(user_id,upi_id,is_primary,created_at) VALUES(?,?,1,?)", (user_id, upi_id, utc_now()))
        if inviter:
            db.execute("UPDATE users SET referral_balance = referral_balance + 150 WHERE id = ?", (inviter["id"],))
            db.execute("INSERT INTO referral_logs(user_id,amount_inr,description,timestamp) VALUES(?,?,?,?)", (inviter["id"], 150, f"Invite bonus for {email}", utc_now()))
        db.commit()
        user = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        session["user_email"] = email
        return jsonify({"message": "Account created successfully.", "user": public_user(db, user)})


@app.post("/api/auth/login")
def user_login():
    payload = request.get_json(silent=True) or {}
    email = clean_email(payload.get("email"))
    with db_connect() as db:
        user = db.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
        if not user or not check_password_hash(user["password_hash"], clean_text(payload.get("password"))):
            return error_response("Invalid email or password.", 401)
        session["user_email"] = email
        return jsonify({"message": "Welcome back.", "user": public_user(db, user)})


@app.post("/api/auth/logout")
def user_logout():
    session.pop("user_email", None)
    return jsonify({"message": "Logged out."})


@app.post("/api/admin/login")
def admin_login():
    payload = request.get_json(silent=True) or {}
    if clean_text(payload.get("username")) == "admin" and clean_text(payload.get("password")) == os.environ.get("ADMIN_PASSWORD", "admin123"):
        session["admin_authenticated"] = True
        return jsonify({"message": "Admin access granted."})
    return error_response("Invalid admin credentials.", 401)


@app.post("/api/admin/logout")
@admin_required
def admin_logout():
    session.pop("admin_authenticated", None)
    return jsonify({"message": "Admin logged out."})


@app.post("/api/admin/update-config")
@admin_required
def update_config():
    payload = request.get_json(silent=True) or {}
    try:
        rate = float(payload.get("usdt_rate"))
        if rate <= 0:
            raise ValueError
    except (TypeError, ValueError):
        return error_response("USDT rate must be positive.", 400)
    with db_connect() as db:
        db.execute("BEGIN IMMEDIATE")
        db.execute("INSERT OR REPLACE INTO system_config(key,value) VALUES('usdt_rate',?)", (str(round(rate, 2)),))
        for key in ("trc20_address", "bep20_address", "telegram_support_url"):
            value = clean_text(payload.get(key))
            if value:
                db.execute("INSERT OR REPLACE INTO system_config(key,value) VALUES(?,?)", (key, value))
        db.commit()
        return jsonify(config_values(db))


@app.get("/api/user/profile")
@user_required
def get_profile():
    with db_connect() as db:
        return jsonify(public_user(db, user_from_session(db)))


@app.post("/api/user/upi")
@user_required
def add_upi():
    upi_id = clean_text((request.get_json(silent=True) or {}).get("upi_id"))
    if not upi_id or "@" not in upi_id:
        return error_response("Enter a valid UPI VPA.", 400)
    with db_connect() as db:
        user = user_from_session(db)
        db.execute("INSERT OR IGNORE INTO user_upis(user_id,upi_id,is_primary,created_at) VALUES(?,?,0,?)", (user["id"], upi_id, utc_now()))
        return jsonify({"message": "UPI account linked.", **public_user(db, user)})


@app.post("/api/user/upi/primary")
@user_required
def set_primary_upi():
    upi_id = clean_text((request.get_json(silent=True) or {}).get("upi_id"))
    with db_connect() as db:
        user = user_from_session(db)
        if not db.execute("SELECT 1 FROM user_upis WHERE user_id = ? AND upi_id = ?", (user["id"], upi_id)).fetchone():
            return error_response("UPI VPA is not linked to this account.", 400)
        db.execute("BEGIN IMMEDIATE")
        db.execute("UPDATE user_upis SET is_primary = 0 WHERE user_id = ?", (user["id"],))
        db.execute("UPDATE user_upis SET is_primary = 1 WHERE user_id = ? AND upi_id = ?", (user["id"], upi_id))
        db.commit()
        return jsonify({"message": "Primary UPI updated.", **public_user(db, user)})


@app.post("/api/orders/create")
@user_required
def create_order():
    payload = request.get_json(silent=True) or {}
    try:
        quantity = round(float(payload.get("quantity", 0)), 6)
    except (TypeError, ValueError):
        quantity = 0
    network = clean_text(payload.get("network")).upper()
    txid = clean_text(payload.get("txid"))
    with db_connect() as db:
        user = user_from_session(db)
        primary = db.execute("SELECT upi_id FROM user_upis WHERE user_id = ? AND is_primary = 1", (user["id"],)).fetchone()
        if quantity <= 0 or network not in {"TRC20", "BEP20"} or not txid or not primary:
            return error_response("Enter a valid amount, network, TXID, and primary UPI.", 400)
        rate = config_values(db)["usdt_rate"]
        cursor = db.execute("INSERT INTO orders(user_id,usdt_amount,inr_total,network,txid,status,upi_id,rate,created_at) VALUES(?,?,?,?,?,?,?,?,?)", (user["id"], quantity, round(quantity * rate, 2), network, txid, "VERIFYING_DEPOSIT", primary["upi_id"], rate, utc_now()))
        return jsonify({"id": cursor.lastrowid, "email": user["email"], "upi_id": primary["upi_id"], "quantity": quantity, "total_usdt": quantity, "sold_usdt": 0.0, "remaining_usdt": quantity, "network": network, "txid": txid, "rate": rate, "total_inr": round(quantity * rate, 2), "paid_inr": 0.0, "payout_logs": [], "status": "VERIFYING_DEPOSIT"}), 201


def order_dict(db, row):
    tranches = db.execute("SELECT id, amount_inr, utr, proof_url, timestamp FROM tranches WHERE order_id = ? ORDER BY id", (row["id"],)).fetchall()
    logs = [{"tranche_id": index + 1, "amount_inr": item["amount_inr"], "utr": item["utr"], "proof_url": item["proof_url"], "timestamp": item["timestamp"]} for index, item in enumerate(tranches)]
    sold = round(row["paid_inr"] / row["rate"], 6)
    return {"id": row["id"], "email": row["email"], "upi_id": row["upi_id"], "quantity": row["usdt_amount"], "total_usdt": row["usdt_amount"], "sold_usdt": sold, "remaining_usdt": round(max(0, row["usdt_amount"] - sold), 6), "network": row["network"], "txid": row["txid"], "rate": row["rate"], "total_inr": row["inr_total"], "paid_inr": row["paid_inr"], "payout_logs": logs, "status": row["status"], "created_at": row["created_at"]}


@app.get("/api/orders")
@user_required
def get_orders():
    with db_connect() as db:
        user = user_from_session(db)
        rows = db.execute("SELECT o.*, u.email FROM orders o JOIN users u ON u.id=o.user_id WHERE o.user_id=? ORDER BY o.id DESC", (user["id"],)).fetchall()
        return jsonify([order_dict(db, row) for row in rows])


@app.get("/api/user/ledger")
@user_required
def user_ledger():
    with db_connect() as db:
        user = user_from_session(db)
        rows = []
        for order in db.execute("SELECT o.*, u.email FROM orders o JOIN users u ON u.id=o.user_id WHERE o.user_id=?", (user["id"],)).fetchall():
            rows.append({"type": "USDT_DEPOSIT", "timestamp": order["created_at"], "amount_usdt": order["usdt_amount"], "network": order["network"], "txid": order["txid"], "status": order["status"], "order_id": order["id"]})
            for tranche in db.execute("SELECT * FROM tranches WHERE order_id=?", (order["id"],)).fetchall():
                rows.append({"type": "UPI_PAYOUT", "timestamp": tranche["timestamp"], "amount_inr": tranche["amount_inr"], "utr": tranche["utr"], "upi_id": order["upi_id"], "proof_url": tranche["proof_url"], "order_id": order["id"], "tranche_id": tranche["id"]})
        for log in db.execute("SELECT * FROM referral_logs WHERE user_id=?", (user["id"],)).fetchall():
            rows.append({"type": "REFERRAL_BONUS" if log["amount_inr"] == 150 else "REFERRAL_COMMISSION", "amount_inr": log["amount_inr"], "description": log["description"], "timestamp": log["timestamp"]})
        return jsonify(sorted(rows, key=lambda item: item["timestamp"], reverse=True))


@app.get("/api/admin/orders")
@admin_required
def admin_orders():
    with db_connect() as db:
        rows = db.execute("SELECT o.*, u.email FROM orders o JOIN users u ON u.id=o.user_id ORDER BY o.id DESC").fetchall()
        return jsonify([order_dict(db, row) for row in rows])


@app.post("/api/admin/verify-order")
@admin_required
def verify_order():
    payload = request.get_json(silent=True) or {}
    action = clean_text(payload.get("action")).upper()
    try:
        order_id = int(payload.get("order_id"))
    except (TypeError, ValueError):
        return error_response("Valid order and action are required.", 400)
    if action not in {"REAL", "FAKE_FLASH"}:
        return error_response("Valid order and action are required.", 400)
    with db_connect() as db:
        db.execute("BEGIN IMMEDIATE")
        if not db.execute("SELECT 1 FROM orders WHERE id=?", (order_id,)).fetchone():
            return error_response("Order not found.", 404)
        db.execute("UPDATE orders SET status=? WHERE id=?", ("IN_PAYOUT" if action == "REAL" else "FLASH_REJECTED", order_id))
        db.commit()
        row = db.execute("SELECT o.*, u.email FROM orders o JOIN users u ON u.id=o.user_id WHERE o.id=?", (order_id,)).fetchone()
        return jsonify(order_dict(db, row))


@app.post("/api/admin/send-tranche")
@admin_required
def send_tranche():
    values = request.form if request.form else (request.get_json(silent=True) or {})
    try:
        order_id = int(values.get("order_id"))
        amount = round(float(values.get("amount", 0)), 2)
    except (TypeError, ValueError):
        return error_response("A valid order and amount are required.", 400)
    utr = clean_text(values.get("utr")) or "N/A"
    proof = request.files.get("proof_image")
    extension = ""
    if proof and proof.filename:
        extension = proof.filename.rsplit(".", 1)[-1].lower() if "." in proof.filename else ""
        if extension not in ALLOWED_RECEIPT_EXTENSIONS:
            return error_response("Receipt must be PNG, JPG, or JPEG.", 400)
    with db_connect() as db:
        db.execute("BEGIN IMMEDIATE")
        row = db.execute("SELECT * FROM orders WHERE id=?", (order_id,)).fetchone()
        if not row or amount <= 0:
            return error_response("A valid order and amount are required.", 400)
        if row["status"] not in {"IN_PAYOUT", "PARTIALLY_PAID"}:
            return error_response("Approve the order before dispatching a tranche.", 400)
        remaining = round(row["inr_total"] - row["paid_inr"], 2)
        amount = min(amount, remaining)
        if amount <= 0:
            return error_response("This order has no remaining balance.", 400)
        timestamp = utc_now()
        cursor = db.execute("INSERT INTO tranches(order_id,amount_inr,utr,timestamp) VALUES(?,?,?,?)", (order_id, amount, utr, timestamp))
        if proof and proof.filename:
            filename = secure_filename(f"proof_{order_id}_{cursor.lastrowid}.{extension}")
            proof.save(UPLOAD_FOLDER / filename)
            db.execute("UPDATE tranches SET proof_url=? WHERE id=?", (f"/static/uploads/receipts/{filename}", cursor.lastrowid))
        new_paid = round(row["paid_inr"] + amount, 2)
        new_status = "COMPLETED" if new_paid >= row["inr_total"] else "PARTIALLY_PAID"
        db.execute("UPDATE orders SET paid_inr=?, status=? WHERE id=?", (new_paid, new_status, order_id))
        if new_status == "COMPLETED":
            inviter = db.execute("SELECT u.* FROM users u JOIN users invited ON invited.referred_by=u.id WHERE invited.id=?", (row["user_id"],)).fetchone()
            if inviter and not db.execute("SELECT 1 FROM referral_logs WHERE user_id=? AND description=?", (inviter["id"], f"10% commission from order #{order_id}")).fetchone():
                commission = round(row["inr_total"] * 0.10, 2)
                db.execute("UPDATE users SET referral_balance=referral_balance+? WHERE id=?", (commission, inviter["id"]))
                db.execute("INSERT INTO referral_logs(user_id,amount_inr,description,timestamp) VALUES(?,?,?,?)", (inviter["id"], commission, f"10% commission from order #{order_id}", timestamp))
        db.commit()
        updated = db.execute("SELECT o.*, u.email FROM orders o JOIN users u ON u.id=o.user_id WHERE o.id=?", (order_id,)).fetchone()
        return jsonify({"order": order_dict(db, updated), "dispatched_inr": amount, "remaining_inr": round(updated["inr_total"] - updated["paid_inr"], 2)})


@app.get("/api/user/referrals")
@user_required
def referrals():
    with db_connect() as db:
        user = user_from_session(db)
        count = db.execute("SELECT COUNT(*) AS total FROM users WHERE referred_by=?", (user["id"],)).fetchone()["total"]
        withdrawals = [dict(row) for row in db.execute("SELECT wr.*, u.email FROM withdrawal_requests wr JOIN users u ON u.id=wr.user_id WHERE wr.user_id=? ORDER BY wr.id DESC", (user["id"],)).fetchall()]
        return jsonify({"invite_count": count, "referral_balance": user["referral_balance"], "invite_code": user["referral_code"], "invite_link": f"/login?invite={user['referral_code']}", "withdrawal_requests": withdrawals})


@app.post("/api/user/withdrawals")
@user_required
def create_withdrawal():
    with db_connect() as db:
        db.execute("BEGIN IMMEDIATE")
        user = user_from_session(db)
        count = db.execute("SELECT COUNT(*) AS total FROM users WHERE referred_by=?", (user["id"],)).fetchone()["total"]
        if count < 20:
            return error_response(f"Invite {20-count} more users to unlock withdrawal.", 400)
        if user["referral_balance"] <= 0:
            return error_response("No referral balance is available.", 400)
        primary = db.execute("SELECT upi_id FROM user_upis WHERE user_id=? AND is_primary=1", (user["id"],)).fetchone()
        cursor = db.execute("INSERT INTO withdrawal_requests(user_id,upi_id,amount,invite_count,status,note,created_at) VALUES(?,?,?,?,?,?,?)", (user["id"], primary["upi_id"], user["referral_balance"], count, "PROCESSING", "Awaiting admin review.", utc_now()))
        db.commit()
        return jsonify({"id": cursor.lastrowid, "email": user["email"], "upi_id": primary["upi_id"], "amount": user["referral_balance"], "invite_count": count, "status": "PROCESSING"}), 201


@app.get("/api/admin/withdrawals")
@admin_required
def admin_withdrawals():
    with db_connect() as db:
        return jsonify([dict(row) for row in db.execute("SELECT wr.*, u.email FROM withdrawal_requests wr JOIN users u ON u.id=wr.user_id ORDER BY wr.id DESC")])


@app.post("/api/admin/withdrawals/action")
@admin_required
def withdrawal_action():
    payload = request.get_json(silent=True) or {}
    try:
        withdrawal_id = int(payload.get("withdrawal_id"))
    except (TypeError, ValueError):
        return error_response("Valid withdrawal required.", 400)
    action = clean_text(payload.get("action")).upper()
    note = clean_text(payload.get("note")) or "Updated by admin."
    if action not in {"SUCCESS", "PROCESSING", "REJECTED"}:
        return error_response("Invalid withdrawal action.", 400)
    with db_connect() as db:
        db.execute("BEGIN IMMEDIATE")
        item = db.execute("SELECT * FROM withdrawal_requests WHERE id=?", (withdrawal_id,)).fetchone()
        if not item:
            return error_response("Withdrawal not found.", 404)
        db.execute("UPDATE withdrawal_requests SET status=?, note=? WHERE id=?", (action, note, withdrawal_id))
        if action == "SUCCESS":
            db.execute("UPDATE users SET referral_balance=0 WHERE id=?", (item["user_id"],))
        db.commit()
        return jsonify(dict(db.execute("SELECT wr.*, u.email FROM withdrawal_requests wr JOIN users u ON u.id=wr.user_id WHERE wr.id=?", (withdrawal_id,)).fetchone()))


if __name__ == "__main__":
    import os

    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)

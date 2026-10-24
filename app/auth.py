"""Password hashing, signed session cookies, CSRF tokens, first-run admin bootstrap."""
import base64
import hashlib
import hmac
import os
import secrets
import time

import db

COOKIE = "al_session"
SESSION_TTL = 7 * 86400
PW_FILE = os.path.join(db.DATA_DIR, "initial-admin-password.txt")
_secret = None


def secret() -> bytes:
    global _secret
    if _secret is None:
        path = os.path.join(db.DATA_DIR, "secret.key")
        if not os.path.exists(path):
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w") as f:
                f.write(secrets.token_hex(32))
        _secret = open(path).read().strip().encode()
    return _secret


def hash_password(pw: str) -> str:
    salt = os.urandom(16)
    h = hashlib.scrypt(pw.encode(), salt=salt, n=2 ** 14, r=8, p=1, dklen=32)
    return f"scrypt${salt.hex()}${h.hex()}"


def verify_password(pw: str, stored: str) -> bool:
    try:
        _, salt, h = stored.split("$")
        calc = hashlib.scrypt(pw.encode(), salt=bytes.fromhex(salt), n=2 ** 14, r=8, p=1, dklen=32)
        return hmac.compare_digest(calc.hex(), h)
    except Exception:
        return False


def _sign(data: str) -> str:
    return hmac.new(secret(), data.encode(), hashlib.sha256).hexdigest()


def make_cookie(user) -> str:
    payload = f"{user['id']}:{user['sess_epoch']}:{int(time.time())}:{secrets.token_hex(8)}"
    b = base64.urlsafe_b64encode(payload.encode()).decode()
    return f"{b}.{_sign(b)}"


def user_from_cookie(value):
    """Return the user row for a valid cookie, else None. Deleted users / reset passwords invalidate sessions."""
    try:
        b, sig = value.rsplit(".", 1)
        if not hmac.compare_digest(sig, _sign(b)):
            return None
        uid, epoch, iat, _ = base64.urlsafe_b64decode(b).decode().split(":")
        if time.time() - int(iat) > SESSION_TTL:
            return None
        u = db.one("SELECT * FROM users WHERE id=?", (int(uid),))
        return u if u and u["sess_epoch"] == int(epoch) else None
    except Exception:
        return None


def csrf_token(cookie_value: str) -> str:
    return _sign("csrf:" + cookie_value)[:32]


def create_user(username, password, role="admin"):
    db.ex("INSERT INTO users(username,pw_hash,role,created_at) VALUES(?,?,?,?)",
          (username, hash_password(password), role, int(time.time())))


def set_password(uid, password):
    if str(uid) == db.get("bootstrap_uid", "0"):
        password_changed()
    db.ex("UPDATE users SET pw_hash=?, sess_epoch=sess_epoch+1 WHERE id=?", (hash_password(password), uid))


def bootstrap_admin():
    """First run only: create 'admin' with a random password (logged + written to the config dir)."""
    if db.one("SELECT 1 FROM users LIMIT 1"):
        return
    pw = secrets.token_urlsafe(12)
    create_user("admin", pw)
    db.put("bootstrap_uid", db.one("SELECT id FROM users WHERE username='admin'")["id"])
    with open(os.open(PW_FILE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "w") as f:
        f.write(f"username: admin\npassword: {pw}\n")
    bar = "=" * 60
    print(f"\n{bar}\n  AccessLens first run - initial admin credentials\n"
          f"  username: admin\n  password: {pw}\n"
          f"  (also saved to {PW_FILE}; removed once you change the password)\n{bar}\n", flush=True)


def password_changed():
    try:
        os.remove(PW_FILE)
    except FileNotFoundError:
        pass


def valid_password(pw: str):
    if len(pw) < 8:
        return "Password must be at least 8 characters."
    return None

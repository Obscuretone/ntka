"""Optional, email-verified guest registration and password sign-in."""

import asyncio
import base64
import functools
import hashlib
import logging
import os
import re
import secrets
import subprocess
from email.message import EmailMessage
from hmac import compare_digest
from pathlib import Path
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener
from uuid import uuid4

from .storage import digest, now, person_by_email

CODE_LIFETIME = 900
EMAIL = re.compile(r"[a-z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-z0-9-]+(?:\.[a-z0-9-]+)+")
CODE = re.compile(r"[A-Za-z0-9_-]{43}")


def email_address(value):
    value = value.strip().lower()
    return value if len(value) <= 254 and EMAIL.fullmatch(value) else ""


def hash_password(password, salt):
    return hashlib.scrypt(password.encode(), salt=salt, n=32768, r=8, p=1,
                          maxmem=64 * 1024 * 1024)


def allowed(store, action, email, limit, total, window=900):
    current = now()
    with store.connect(write=True) as db:
        db.execute("DELETE FROM password_attempts WHERE expires<=?", (current,))
        counts = db.execute(
            "SELECT count(*) AS total, count(CASE WHEN email=? THEN 1 END) AS matching "
            "FROM password_attempts WHERE action=?",
            (email, action),
        ).fetchone()
        if counts["total"] >= total or counts["matching"] >= limit:
            return False
        db.execute("INSERT INTO password_attempts VALUES (?, ?, ?)",
                   (action, email, current + window))
    return True


def verification_text(code):
    return f"Enter this code in the form you opened:\n\n{code}\n\nThe code expires in 15 minutes."


def sendmail_code(command, sender, recipient, code):
    message = EmailMessage()
    message["From"] = sender
    message["To"] = recipient
    message["Subject"] = "Your account verification code"
    message.set_content(verification_text(code))
    subprocess.run(
        [command, "-i", "-t"], input=message.as_bytes(), stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL, check=True, timeout=10,
    )


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def mailgun_code(url, authorization, sender, recipient, code):
    fields = {"from": sender, "to": recipient, "subject": "Your account verification code",
              "text": verification_text(code)}
    boundary = uuid4().hex
    body = "".join(
        f'--{boundary}\r\nContent-Disposition: form-data; name="{name}"\r\n\r\n{value}\r\n'
        for name, value in fields.items()
    ) + f"--{boundary}--\r\n"
    request = Request(url, body.encode(), {
        "Authorization": authorization, "Content-Type": "multipart/form-data; boundary=" + boundary,
    }, method="POST")
    with build_opener(ProxyHandler({}), NoRedirect()).open(request, timeout=10) as response:
        if response.status != 200:
            raise OSError("Mail API did not accept verification email")


def configured_sender():
    sender = email_address(os.environ.get("IDENTITY_MAIL_FROM", ""))
    command = os.environ.get("IDENTITY_SENDMAIL")
    base = os.environ.get("IDENTITY_MAILGUN_URL")
    domain = os.environ.get("IDENTITY_MAILGUN_DOMAIN")
    key_file = os.environ.get("IDENTITY_MAILGUN_KEY_FILE")
    if not any((command, base, domain, key_file, os.environ.get("IDENTITY_MAIL_FROM"))):
        return None
    if not sender:
        raise ValueError("Password signup requires a valid IDENTITY_MAIL_FROM.")
    if command:
        if any((base, domain, key_file)) or not Path(command).is_absolute() or not os.access(command, os.X_OK):
            raise ValueError("Configure one executable sendmail transport or the Mailgun API.")
        return functools.partial(sendmail_code, command, sender)
    root = base.rstrip("/") if base else ""
    parsed = urlsplit(root)
    loopback = parsed.hostname in {"127.0.0.1", "::1"}
    if (not parsed.hostname or parsed.scheme not in ({"http", "https"} if loopback else {"https"})
            or parsed.username or parsed.password or parsed.query or parsed.fragment
            or not domain or sender.rsplit("@", 1)[1] != domain or not key_file):
        raise ValueError("Configure the Mailgun API URL, sender domain, and key file.")
    key = Path(key_file).read_text().strip()
    if not key or not key.isascii() or any(char.isspace() for char in key):
        raise ValueError("Invalid Mailgun API key.")
    authorization = "Basic " + base64.b64encode(("api:" + key).encode()).decode()
    return functools.partial(mailgun_code, f"{root}/v3/{domain}/messages", authorization, sender)


def register_passwords(app, store, page, target_for, start_session):
    send_code = configured_sender()
    if send_code is None:
        return False

    daily_limit = int(os.environ.get("IDENTITY_SIGNUP_DAILY_LIMIT", "30"))
    if not 1 <= daily_limit <= 1000:
        raise ValueError("IDENTITY_SIGNUP_DAILY_LIMIT must be between 1 and 1000.")
    hash_slots = asyncio.Semaphore(1)

    def form(mode, target, *, status=200, **context):
        result = page("password", mode=mode, target=target, **context)
        result.status = status
        result.headers["Referrer-Policy"] = "same-origin"
        return result

    @app.get("/password/sign-in")
    async def sign_in_page(request):
        return form("sign-in", target_for(request.args.get("next")))

    @app.post("/password/sign-in")
    async def sign_in(request):
        target = target_for(request.form.get("next"))
        email = email_address(request.form.get("email", ""))
        password = request.form.get("password", "")
        if not email or not 1 <= len(password) <= 128:
            return form("sign-in", target, status=401, error="The email or password did not match.")
        if not allowed(store, "sign-in", email, 12, 240):
            return form("sign-in", target, status=429, error="Too many attempts. Try again later.")
        with store.connect() as db:
            match, address = db.email_match(email)
            saved = db.execute(
                "SELECT p.id, c.salt, c.hash FROM people p JOIN passwords c ON c.person=p.id "
                "WHERE " + match + " AND p.enabled AND NOT p.owner", (address,),
            ).fetchone()
        async with hash_slots:
            actual = await asyncio.to_thread(hash_password, password, saved["salt"] if saved else bytes(16))
        if not saved or not compare_digest(actual, saved["hash"]):
            return form("sign-in", target, status=401, error="The email or password did not match.")
        with store.connect(write=True) as db:
            if not db.execute("SELECT 1 FROM people WHERE id=? AND enabled AND NOT owner",
                              (saved["id"],)).fetchone():
                return form("sign-in", target, status=401, error="The email or password did not match.")
            return start_session(db, request, saved["id"], target)

    @app.get("/password/signup")
    async def signup_page(request):
        return form("signup", target_for(request.args.get("next")))

    @app.post("/password/signup")
    async def signup(request):
        target = target_for(request.form.get("next"))
        email = email_address(request.form.get("email", ""))
        if not email:
            return form("signup", target, status=400, error="Enter a valid email address.")
        if not allowed(store, "signup", email, 3, daily_limit, window=86400):
            return form("signup", target, status=429, error="Too many attempts. Try again later.")
        token = secrets.token_urlsafe(32)
        with store.connect(write=True) as db:
            current = now()
            db.execute("DELETE FROM password_signup WHERE expires<=?", (current,))
            exists = person_by_email(db, email) is not None
            if not exists:
                db.execute("INSERT INTO password_signup VALUES (?, ?, ?)",
                           (digest(token), email, current + CODE_LIFETIME))
        if not exists:
            try:
                await asyncio.to_thread(send_code, email, token)
            except (OSError, subprocess.SubprocessError):
                # A timed-out relay may already have queued mail. Keep the code valid until expiry.
                logging.getLogger(__name__).warning("Verification email submission failed")
        return form("verify", target, email=email)

    @app.post("/password/verify")
    async def verify(request):
        target = target_for(request.form.get("next"))
        email = email_address(request.form.get("email", ""))
        name = request.form.get("name", "").strip()
        password = request.form.get("password", "")
        code = request.form.get("code", "").strip()
        if not email or not 1 <= len(name) <= 80 or not 15 <= len(password) <= 128 or not CODE.fullmatch(code):
            return form("verify", target, email=email, status=400,
                        error="Enter your name, verification code and a password of at least 15 characters.")
        if not allowed(store, "verify", email, 12, 240):
            return form("verify", target, email=email, status=429, error="Too many attempts. Try again later.")
        lookup = (digest(code), email, now())
        pending = "SELECT 1 FROM password_signup WHERE token=? AND email=? AND expires>?"
        with store.connect() as db:
            valid = db.execute(pending, lookup).fetchone()
        if valid:
            salt = secrets.token_bytes(16)
            async with hash_slots:
                hashed = await asyncio.to_thread(hash_password, password, salt)
            with store.connect(write=True) as db:
                if (db.execute(pending, (lookup[0], email, now())).fetchone()
                        and not person_by_email(db, email)):
                    person = str(uuid4())
                    db.execute("INSERT INTO people (id, name, email, email_verified) VALUES (?, ?, ?, 1)",
                               (person, name, email))
                    db.execute("INSERT INTO passwords VALUES (?, ?, ?)", (person, salt, hashed))
                    db.execute("DELETE FROM password_signup WHERE email=?", (email,))
                    return start_session(db, request, person, target)
        return form("verify", target, email=email, status=400, error="The verification code expired or did not match.")

    return True

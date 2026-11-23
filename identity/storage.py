import hashlib
import os
import secrets
import sqlite3
import tempfile
import time
from contextlib import contextmanager
from pathlib import Path
from uuid import uuid4

from joserfc.jwk import RSAKey


SCHEMA = """
CREATE TABLE IF NOT EXISTS people (
    id TEXT PRIMARY KEY, name TEXT NOT NULL, email TEXT NOT NULL COLLATE NOCASE UNIQUE,
    owner INTEGER NOT NULL DEFAULT 0, enabled INTEGER NOT NULL DEFAULT 1,
    enrolled INTEGER NOT NULL DEFAULT 0, email_verified INTEGER NOT NULL DEFAULT 0
);
CREATE UNIQUE INDEX IF NOT EXISTS single_owner ON people(owner) WHERE owner = 1;
CREATE TABLE IF NOT EXISTS passwords (
    person TEXT PRIMARY KEY REFERENCES people(id), salt BLOB NOT NULL, hash BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS password_signup (
    token TEXT PRIMARY KEY, email TEXT NOT NULL, expires INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS password_attempts (
    action TEXT NOT NULL, email TEXT NOT NULL, expires INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS passkeys (
    id BLOB PRIMARY KEY, person TEXT NOT NULL REFERENCES people(id),
    public_key BLOB NOT NULL, sign_count INTEGER NOT NULL, label TEXT NOT NULL,
    added INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS invitations (
    token TEXT PRIMARY KEY, person TEXT NOT NULL REFERENCES people(id), expires INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
    token TEXT PRIMARY KEY, person TEXT NOT NULL REFERENCES people(id),
    authenticated INTEGER NOT NULL, expires INTEGER NOT NULL, fresh_for TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS ceremonies (
    token TEXT PRIMARY KEY, challenge BLOB NOT NULL, purpose TEXT NOT NULL,
    subject TEXT NOT NULL, expires INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS ceremonies_expiry ON ceremonies(expires);
CREATE TABLE IF NOT EXISTS sites (
    id TEXT PRIMARY KEY, name TEXT NOT NULL, launch TEXT NOT NULL, callback TEXT NOT NULL,
    secret TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS grants (
    person TEXT NOT NULL REFERENCES people(id), site TEXT NOT NULL REFERENCES sites(id),
    PRIMARY KEY (person, site)
);
CREATE TABLE IF NOT EXISTS signup_links (
    token TEXT PRIMARY KEY, site TEXT NOT NULL UNIQUE REFERENCES sites(id),
    expires INTEGER NOT NULL, remaining INTEGER NOT NULL CHECK (remaining >= 0)
);
CREATE TABLE IF NOT EXISTS pending_signups (
    ceremony TEXT PRIMARY KEY REFERENCES ceremonies(token) ON DELETE CASCADE,
    signup TEXT NOT NULL, person TEXT NOT NULL, name TEXT NOT NULL, email TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS codes (
    token TEXT PRIMARY KEY, person TEXT NOT NULL REFERENCES people(id),
    site TEXT NOT NULL REFERENCES sites(id), callback TEXT NOT NULL,
    scope TEXT NOT NULL, nonce TEXT, challenge TEXT NOT NULL, authenticated INTEGER NOT NULL,
    expires INTEGER NOT NULL, used INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS codes_nonce ON codes(site, nonce);
CREATE INDEX IF NOT EXISTS codes_expiry ON codes(expires);
CREATE TABLE IF NOT EXISTS tokens (
    token TEXT PRIMARY KEY, person TEXT NOT NULL REFERENCES people(id),
    site TEXT NOT NULL REFERENCES sites(id), scope TEXT NOT NULL, expires INTEGER NOT NULL,
    code TEXT
);
CREATE INDEX IF NOT EXISTS tokens_expiry ON tokens(expires);
CREATE TABLE IF NOT EXISTS audit (
    id INTEGER PRIMARY KEY, at INTEGER NOT NULL, event TEXT NOT NULL, detail TEXT NOT NULL
);
"""


def now():
    return int(time.time())


def digest(value):
    return hashlib.sha256(value.encode()).hexdigest()


def issue_invite(db, person, lifetime):
    token = secrets.token_urlsafe(32)
    db.execute("DELETE FROM invitations WHERE person = ?", (person,))
    db.execute("INSERT INTO invitations VALUES (?, ?, ?)", (digest(token), person, now() + lifetime))
    return token


def issue_signup_link(db, site, uses, hours):
    token = secrets.token_urlsafe(32)
    db.execute("DELETE FROM signup_links WHERE site=?", (site,))
    db.execute("INSERT INTO signup_links VALUES (?, ?, ?, ?)", (digest(token), site, now() + hours * 3600, uses))
    return token


def open_signup(db, token):
    return db.execute(
        """SELECT l.token, l.site FROM signup_links l JOIN sites s ON s.id=l.site
        WHERE l.token=? AND l.expires>? AND l.remaining>0 AND s.enabled""",
        (token, now()),
    ).fetchone()


def log(db, event, detail):
    db.execute("INSERT INTO audit (at, event, detail) VALUES (?, ?, ?)", (now(), event, detail))


def reset_passkeys(db, person, email):
    for table in ("passkeys", "sessions", "invitations", "codes", "tokens"):
        db.execute(f"DELETE FROM {table} WHERE person=?", (person,))
    token = issue_invite(db, person, 900)
    log(db, "Passkeys reset", email)
    return token


def can_access(db, person, site):
    return db.execute(
        """SELECT 1 FROM people p JOIN sites s ON s.id = ?
        WHERE p.id = ? AND p.enabled AND s.enabled
        AND (p.owner OR EXISTS (SELECT 1 FROM grants g WHERE g.person=p.id AND g.site=s.id))""",
        (site, person),
    ).fetchone() is not None


class Store:
    def __init__(self, directory):
        self.directory = Path(directory)
        self.database = self.directory / "identity.sqlite3"
        self.keyfile = self.directory / "signing.pem"

    def initialize(self):
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        with self.connect() as db:
            db.execute("PRAGMA journal_mode=WAL")
            db.executescript(SCHEMA)
        with self.connect(write=True) as db:
            person_columns = {row["name"] for row in db.execute("PRAGMA table_info(people)")}
            if "email_verified" not in person_columns:
                db.execute("ALTER TABLE people ADD COLUMN email_verified INTEGER NOT NULL DEFAULT 0")
            if "enrolled" not in person_columns:
                db.execute("ALTER TABLE people ADD COLUMN enrolled INTEGER NOT NULL DEFAULT 0")
                db.execute("UPDATE people SET enrolled=1 WHERE id IN (SELECT person FROM passkeys)")
            if "code" not in {row["name"] for row in db.execute("PRAGMA table_info(tokens)")}:
                db.execute("ALTER TABLE tokens ADD COLUMN code TEXT")
            db.execute("CREATE INDEX IF NOT EXISTS tokens_code ON tokens(code)")
        if not self.keyfile.exists():
            with tempfile.NamedTemporaryFile(dir=self.directory, prefix=".signing-", delete=False) as output:
                temporary = Path(output.name)
                try:
                    output.write(RSAKey.generate_key(3072, private=True).as_pem(private=True))
                    output.flush()
                    os.fsync(output.fileno())
                    try:
                        os.link(temporary, self.keyfile)
                    except FileExistsError:
                        pass
                finally:
                    temporary.unlink(missing_ok=True)

    def signing_key(self):
        return RSAKey.import_key(self.keyfile.read_bytes())

    @contextmanager
    def connect(self, write=False):
        db = sqlite3.connect(self.database, timeout=3, isolation_level=None)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys=ON")
        try:
            if write:
                db.execute("BEGIN IMMEDIATE")
            yield db
            if write:
                db.commit()
        except BaseException:
            if write:
                db.rollback()
            raise
        finally:
            db.close()

    def owner_invite(self, name, email):
        with self.connect(write=True) as db:
            owner = db.execute("SELECT id, email, enrolled FROM people WHERE owner=1").fetchone()
            if owner is None:
                person = str(uuid4())
                db.execute("INSERT INTO people (id, name, email, owner) VALUES (?, ?, ?, 1)",
                           (person, name, email))
            else:
                if owner["email"].casefold() != email.casefold():
                    raise ValueError("An owner already exists with a different email.")
                person = owner["id"]
                if owner["enrolled"]:
                    raise ValueError("The owner has an enrolled passkey. Use the recover command if needed.")
            token = issue_invite(db, person, 900)
            log(db, "Owner enrollment link issued", email)
            return token

    def recover(self, email):
        with self.connect(write=True) as db:
            person = db.execute("SELECT * FROM people WHERE email=? AND enabled", (email,)).fetchone()
            if not person:
                raise ValueError("No enabled account matches that email.")
            return reset_passkeys(db, person["id"], person["email"])

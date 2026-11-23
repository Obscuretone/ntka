"""MariaDB 11.4 storage for NTKA."""

import os
from contextlib import contextmanager
from hashlib import sha256
from pathlib import Path
from string import ascii_lowercase, ascii_uppercase

import pymysql
from pymysql.cursors import DictCursor

from .storage import ASCII_LOWER, StorageIntegrityError, Store


def sqlite_email_key_sql():
    # SQLite NOCASE folds only ASCII, stops at a NUL, and breaks ties by byte length.
    expression = "SUBSTRING_INDEX(email, CHAR(0), 1)"
    for upper, lower in zip(ascii_uppercase, ascii_lowercase):
        expression = f"REPLACE({expression}, '{upper}', '{lower}')"
    return f"CONCAT(LPAD(OCTET_LENGTH(email), 4, '0'), ':', {expression})"


SCHEMA = f"""
CREATE TABLE IF NOT EXISTS identity_storage (
    id INT PRIMARY KEY, signing_fingerprint CHAR(64) NULL
);
CREATE TABLE IF NOT EXISTS people (
    id VARCHAR(255) PRIMARY KEY, name LONGTEXT NOT NULL, email VARCHAR(254) NOT NULL,
    owner BIGINT NOT NULL DEFAULT 0, enabled BIGINT NOT NULL DEFAULT 1,
    enrolled BIGINT NOT NULL DEFAULT 0, email_verified BIGINT NOT NULL DEFAULT 0,
    email_key VARCHAR(259) AS ({sqlite_email_key_sql()}) VIRTUAL,
    owner_key INT AS (CASE WHEN owner = 1 THEN 1 END) VIRTUAL,
    UNIQUE KEY people_email (email_key), UNIQUE KEY single_owner (owner_key)
);
CREATE TABLE IF NOT EXISTS passwords (
    person VARCHAR(255) PRIMARY KEY, salt LONGBLOB NOT NULL, hash LONGBLOB NOT NULL,
    FOREIGN KEY (person) REFERENCES people(id)
);
CREATE TABLE IF NOT EXISTS password_signup (
    token VARCHAR(255) PRIMARY KEY, email LONGTEXT NOT NULL, expires BIGINT NOT NULL
);
CREATE TABLE IF NOT EXISTS password_attempts (
    action LONGTEXT NOT NULL, email LONGTEXT NOT NULL, expires BIGINT NOT NULL
);
CREATE TABLE IF NOT EXISTS passkeys (
    id VARBINARY(3072) PRIMARY KEY, person VARCHAR(255) NOT NULL,
    public_key LONGBLOB NOT NULL, sign_count BIGINT NOT NULL, label LONGTEXT NOT NULL,
    added BIGINT NOT NULL, FOREIGN KEY (person) REFERENCES people(id)
);
CREATE TABLE IF NOT EXISTS invitations (
    token VARCHAR(255) PRIMARY KEY, person VARCHAR(255) NOT NULL, expires BIGINT NOT NULL,
    FOREIGN KEY (person) REFERENCES people(id)
);
CREATE TABLE IF NOT EXISTS sessions (
    token VARCHAR(255) PRIMARY KEY, person VARCHAR(255) NOT NULL,
    authenticated BIGINT NOT NULL, expires BIGINT NOT NULL, fresh_for LONGTEXT NOT NULL,
    FOREIGN KEY (person) REFERENCES people(id)
);
CREATE TABLE IF NOT EXISTS ceremonies (
    token VARCHAR(255) PRIMARY KEY, challenge LONGBLOB NOT NULL, purpose LONGTEXT NOT NULL,
    subject LONGTEXT NOT NULL, expires BIGINT NOT NULL, KEY ceremonies_expiry (expires)
);
CREATE TABLE IF NOT EXISTS sites (
    id VARCHAR(255) PRIMARY KEY, name LONGTEXT NOT NULL, launch LONGTEXT NOT NULL,
    callback LONGTEXT NOT NULL, secret LONGTEXT NOT NULL, enabled BIGINT NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS grants (
    person VARCHAR(255) NOT NULL, site VARCHAR(255) NOT NULL, PRIMARY KEY (person, site),
    FOREIGN KEY (person) REFERENCES people(id), FOREIGN KEY (site) REFERENCES sites(id)
);
CREATE TABLE IF NOT EXISTS signup_links (
    token VARCHAR(255) PRIMARY KEY, site VARCHAR(255) NOT NULL UNIQUE,
    expires BIGINT NOT NULL, remaining BIGINT NOT NULL CHECK (remaining >= 0),
    FOREIGN KEY (site) REFERENCES sites(id)
);
CREATE TABLE IF NOT EXISTS pending_signups (
    ceremony VARCHAR(255) PRIMARY KEY, signup LONGTEXT NOT NULL, person LONGTEXT NOT NULL,
    name LONGTEXT NOT NULL, email LONGTEXT NOT NULL,
    FOREIGN KEY (ceremony) REFERENCES ceremonies(token) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS codes (
    token VARCHAR(255) PRIMARY KEY, person VARCHAR(255) NOT NULL, site VARCHAR(255) NOT NULL,
    callback LONGTEXT NOT NULL, scope LONGTEXT NOT NULL, nonce LONGTEXT, challenge LONGTEXT NOT NULL,
    authenticated BIGINT NOT NULL, expires BIGINT NOT NULL, used BIGINT NOT NULL DEFAULT 0,
    FOREIGN KEY (person) REFERENCES people(id), FOREIGN KEY (site) REFERENCES sites(id),
    KEY codes_nonce (site, nonce(191)), KEY codes_expiry (expires)
);
CREATE TABLE IF NOT EXISTS tokens (
    token VARCHAR(255) PRIMARY KEY, person VARCHAR(255) NOT NULL, site VARCHAR(255) NOT NULL,
    scope LONGTEXT NOT NULL, expires BIGINT NOT NULL, code LONGTEXT,
    FOREIGN KEY (person) REFERENCES people(id), FOREIGN KEY (site) REFERENCES sites(id),
    KEY tokens_expiry (expires), KEY tokens_code (code(191))
);
CREATE TABLE IF NOT EXISTS audit (
    id BIGINT PRIMARY KEY AUTO_INCREMENT, at BIGINT NOT NULL, event LONGTEXT NOT NULL,
    detail LONGTEXT NOT NULL
);
"""

TABLE_OPTIONS = " ENGINE=InnoDB DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_nopad_bin"
TABLES = {
    statement.split(maxsplit=6)[5]: statement.strip()
    for statement in SCHEMA.strip().rstrip(";").split(";")
}


def database_tables(cursor):
    cursor.execute(
        "SELECT TABLE_NAME AS name, TABLE_TYPE AS kind, ENGINE AS engine "
        "FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE()",
    )
    rows = cursor.fetchall()
    if any(row["name"] not in TABLES or row["kind"] != "BASE TABLE" or row["engine"] != "InnoDB" for row in rows):
        raise ValueError("Use a dedicated NTKA database with InnoDB tables.")
    return {row["name"] for row in rows}


def prepare_schema(cursor, existing):
    for name, statement in TABLES.items():
        if name not in existing:
            cursor.execute(statement + TABLE_OPTIONS)
    cursor.execute("INSERT INTO identity_storage (id) VALUES (1) ON DUPLICATE KEY UPDATE id=id")


def signing_fingerprint(key):
    if not key.is_private:
        raise ValueError("The NTKA signing file must contain the issuer's private key.")
    return sha256(key.as_pem(private=False)).hexdigest()


class MariaDBConnection:
    def __init__(self, connection):
        self.connection = connection

    def execute(self, sql, args=None):
        cursor = self.connection.cursor()
        cursor.execute(sql.replace("?", "%s"), args)
        return cursor

    @staticmethod
    def email_match(email):
        prefix = email.partition("\0")[0].translate(ASCII_LOWER)
        key = f"{len(email.encode('utf-8')):04d}:{prefix}"
        return "p.email_key=?", key


class MariaDBStore(Store):
    def __init__(self, directory, options):
        super().__init__(directory)
        self.options = options

    @classmethod
    def from_environment(cls, directory):
        database = os.environ.get("IDENTITY_MARIADB_DATABASE")
        user = os.environ.get("IDENTITY_MARIADB_USER")
        if not database or not user:
            raise ValueError("Set IDENTITY_MARIADB_DATABASE and IDENTITY_MARIADB_USER.")
        password_file = os.environ.get("IDENTITY_MARIADB_PASSWORD_FILE")
        socket = os.environ.get("IDENTITY_MARIADB_SOCKET")
        return cls(directory, {
            "database": database,
            "user": user,
            "password": Path(password_file).read_text().rstrip("\r\n") if password_file else "",
            "unix_socket": socket,
            "host": "127.0.0.1",
            "port": int(os.environ.get("IDENTITY_MARIADB_PORT", "3306")),
        })

    @contextmanager
    def raw_connection(self):
        connection = pymysql.connect(
            **self.options, charset="utf8mb4", cursorclass=DictCursor, autocommit=True,
            binary_prefix=True, connect_timeout=3, read_timeout=15, write_timeout=15,
            sql_mode="STRICT_ALL_TABLES,NO_ENGINE_SUBSTITUTION,NO_AUTO_VALUE_ON_ZERO",
        )
        try:
            yield connection
        finally:
            connection.close()

    @contextmanager
    def schema_connection(self):
        with self.raw_connection() as connection, connection.cursor() as cursor:
            cursor.execute("SELECT GET_LOCK(CONCAT('ntka-migrate-', SHA2(DATABASE(), 256)), 5) AS held")
            if cursor.fetchone()["held"] != 1:
                raise ValueError("Another initialization or migration is using the target database.")
            yield connection, cursor

    def initialize(self):
        with self.schema_connection() as (_, cursor):
            existing = database_tables(cursor)
            if "identity_storage" in existing:
                cursor.execute("SELECT signing_fingerprint FROM identity_storage WHERE id=1")
                record = cursor.fetchone()
                if record and record["signing_fingerprint"]:
                    if existing != TABLES.keys():
                        raise ValueError("The initialized NTKA database is missing tables.")
                    self.check_signing_key(record)
                    return

            for name in existing - {"identity_storage"}:
                cursor.execute(f"SELECT 1 FROM `{name}` LIMIT 1")
                if cursor.fetchone():
                    raise ValueError("The unfinished NTKA database contains data. Verify it before initializing.")
            prepare_schema(cursor, existing)
            self.initialize_signing_key()
            fingerprint = signing_fingerprint(super().signing_key())
            cursor.execute("UPDATE identity_storage SET signing_fingerprint=%s WHERE id=1", (fingerprint,))

    def signing_key(self):
        with self.connect() as db:
            record = db.execute("SELECT signing_fingerprint FROM identity_storage WHERE id=1").fetchone()
        return self.check_signing_key(record)

    def check_signing_key(self, record):
        key = super().signing_key()
        if record["signing_fingerprint"] != signing_fingerprint(key):
            raise ValueError("The signing key does not match the MariaDB instance.")
        return key

    @contextmanager
    def connect(self, write=False):
        with self.raw_connection() as connection:
            db = MariaDBConnection(connection)
            try:
                if write:
                    # Serialize writes as SQLite BEGIN IMMEDIATE did, including code redemption.
                    connection.begin()
                statement = "SELECT signing_fingerprint FROM identity_storage WHERE id=1"
                record = db.execute(statement + (" FOR UPDATE" if write else "")).fetchone()
                if not record or not record["signing_fingerprint"]:
                    raise ValueError("Run identity init or migrate-mariadb before using the MariaDB instance.")
                yield db
                if write:
                    connection.commit()
            except BaseException as error:
                if write:
                    connection.rollback()
                if isinstance(error, pymysql.IntegrityError):
                    raise StorageIntegrityError from error
                raise

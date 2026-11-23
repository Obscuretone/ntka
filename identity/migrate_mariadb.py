"""Copy and verify an NTKA SQLite snapshot in a dedicated MariaDB database."""

import sqlite3
from collections import Counter
from contextlib import closing

import pymysql

from .mariadb_store import database_tables, prepare_schema, signing_fingerprint
from .storage import Store


TABLE_COLUMNS = {
    "people": ("id", "name", "email", "owner", "enabled", "enrolled", "email_verified"),
    "passwords": ("person", "salt", "hash"),
    "password_signup": ("token", "email", "expires"),
    "password_attempts": ("action", "email", "expires"),
    "passkeys": ("id", "person", "public_key", "sign_count", "label", "added"),
    "invitations": ("token", "person", "expires"),
    "sessions": ("token", "person", "authenticated", "expires", "fresh_for"),
    "ceremonies": ("token", "challenge", "purpose", "subject", "expires"),
    "sites": ("id", "name", "launch", "callback", "secret", "enabled"),
    "grants": ("person", "site"),
    "signup_links": ("token", "site", "expires", "remaining"),
    "pending_signups": ("ceremony", "signup", "person", "name", "email"),
    "codes": ("token", "person", "site", "callback", "scope", "nonce", "challenge", "authenticated", "expires", "used"),
    "tokens": ("token", "person", "site", "scope", "expires", "code"),
    "audit": ("id", "at", "event", "detail"),
}
OPTIONAL_TABLES = {"passwords", "password_signup", "password_attempts", "signup_links", "pending_signups"}
LEGACY_FIELDS = {
    ("people", "email_verified"): "0",
    ("people", "enrolled"): "CASE WHEN id IN (SELECT person FROM passkeys) THEN 1 ELSE 0 END",
    ("tokens", "code"): "NULL",
}


def source_queries(db):
    tables = {row[0] for row in db.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'",
    )}
    if tables - TABLE_COLUMNS.keys() or TABLE_COLUMNS.keys() - OPTIONAL_TABLES - tables:
        raise ValueError("The SQLite snapshot has an unrecognized set of identity tables.")
    queries = {}
    for table, columns in TABLE_COLUMNS.items():
        if table not in tables:
            continue
        existing = {row[1] for row in db.execute(f"PRAGMA table_info({table})")}
        if existing - set(columns):
            raise ValueError(f"The SQLite snapshot has unexpected columns in {table}.")
        fields = []
        for column in columns:
            if column in existing:
                fields.append(f'"{column}"')
            elif (table, column) in LEGACY_FIELDS:
                fields.append(LEGACY_FIELDS[table, column])
            else:
                raise ValueError(f"The SQLite snapshot is missing {table}.{column}.")
        select = ", ".join(fields)
        queries[table] = f'SELECT {select} FROM "{table}"'
    return queries


def copy_table(source, query, target, table, columns):
    names = ", ".join(f"`{column}`" for column in columns)
    marks = ", ".join("%s" for _ in columns)
    rows = Counter()
    if query:
        with closing(source.execute(query)) as records:
            while batch := records.fetchmany(500):
                target.executemany(f"INSERT INTO `{table}` ({names}) VALUES ({marks})", batch)
                rows.update(batch)
    target.execute(f"SELECT {names} FROM `{table}`")
    copied = Counter(tuple(row[column] for column in columns) for row in target)
    if copied != rows:
        raise ValueError(f"The migration changed stored values in {table}.")
    return sum(rows.values())


def migrate_sqlite(directory, store):
    source = Store(directory)
    original = signing_fingerprint(source.signing_key())
    # Check the local target file before creating any database tables.
    if original != signing_fingerprint(Store(store.directory).signing_key()):
        raise ValueError("The original signing key must already be present in the target data directory.")

    with closing(sqlite3.connect(source.database.resolve().as_uri() + "?mode=ro", uri=True)) as snapshot:
        snapshot.execute("BEGIN")
        if snapshot.execute("PRAGMA integrity_check").fetchall() != [("ok",)]:
            raise ValueError("SQLite integrity_check failed for the source snapshot.")
        if snapshot.execute("PRAGMA foreign_key_check").fetchone():
            raise ValueError("The source snapshot has inconsistent foreign keys.")
        queries = source_queries(snapshot)
        with store.schema_connection() as (connection, target):
            try:
                prepare_schema(target, database_tables(target))
                connection.begin()
                target.execute("SELECT signing_fingerprint FROM identity_storage WHERE id=1 FOR UPDATE")
                if target.fetchone()["signing_fingerprint"]:
                    raise ValueError("The target has already been migrated.")
                for table in TABLE_COLUMNS:
                    target.execute(f"SELECT 1 FROM `{table}` LIMIT 1")
                    if target.fetchone():
                        raise ValueError(f"The target table {table} is not empty.")
                counts = {}
                for table, columns in TABLE_COLUMNS.items():
                    try:
                        counts[table] = copy_table(snapshot, queries.get(table), target, table, columns)
                    except pymysql.MySQLError:
                        raise ValueError(f"MariaDB could not import or verify {table}.") from None
                target.execute("UPDATE identity_storage SET signing_fingerprint=%s WHERE id=1", (original,))
                connection.commit()
            except BaseException:
                connection.rollback()
                raise
    return counts

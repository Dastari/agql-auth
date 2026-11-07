#!/usr/bin/env python3
"""Test-only consumer RefreshTokenStore on real transactions.

JSON stdin/stdout transports the store operations. Policy stays in Rust. SQLite
uses the standard library and PostgreSQL uses psql at its default READ COMMITTED.
Each fixture has its own table. Only token hashes reach this boundary.
"""
import json
import os
import re
import sqlite3
import subprocess
import sys
import time
from urllib.parse import unquote, urlsplit

request = json.load(sys.stdin)
backend, database, table = (request[k] for k in ("backend", "database", "table"))
if not re.fullmatch(r"agql_refresh_conformance_[0-9a-f]+", table):
    raise ValueError("invalid isolated fixture table")


def literal(value):
    """A SQL literal for a string, or NULL. Production adapters bind parameters."""
    return "NULL" if value is None else "'" + str(value).replace("'", "''") + "'"


def stamp(value):
    return None if value is None else json.dumps(value, separators=(",", ":"))


def sqlite_connection():
    return sqlite3.connect(database, timeout=60, isolation_level=None)


def psql(sql):
    url = urlsplit(database)
    if url.scheme not in ("postgres", "postgresql") or not url.hostname:
        raise ValueError("fixture requires a PostgreSQL URL")
    env = dict(os.environ, PGHOST=url.hostname, PGPORT=str(url.port or 5432),
               PGDATABASE=unquote(url.path.lstrip("/")),
               PGUSER=unquote(url.username or "postgres"),
               PGPASSWORD=unquote(url.password or ""))
    result = subprocess.run(
        ["psql", "-X", "--no-password", "-qAt", "-v", "ON_ERROR_STOP=1"],
        input=sql, text=True, capture_output=True, env=env,
    )
    if result.returncode:
        raise RuntimeError(result.stderr)
    return [line for line in result.stdout.splitlines() if line]


def select(where):
    """Committed records from one statement, so one consistent snapshot."""
    sql = f"SELECT record, revoked_at, replaced_by, last_used_at, ip_address, user_agent FROM {table} WHERE {where}"
    if backend == "sqlite":
        with sqlite_connection() as connection:
            rows = connection.execute(sql).fetchall()
    else:
        rows = [tuple(json.loads(line)[f] for f in
                      ("record", "revoked_at", "replaced_by", "last_used_at", "ip_address", "user_agent"))
                for line in psql(f"SELECT row_to_json(q) FROM ({sql}) q")]
    records = []
    for record, revoked_at, replaced_by, last_used_at, ip_address, user_agent in rows:
        record = json.loads(record)
        record.update(
            revoked_at=None if revoked_at is None else json.loads(revoked_at),
            replaced_by_token_id=replaced_by,
            last_used_at=None if last_used_at is None else json.loads(last_used_at),
            ip_address=ip_address,
            user_agent=user_agent,
        )
        records.append(record)
    return records


def insert_values(token):
    return ",".join(literal(value) for value in (
        token["id"], token["session_family_id"], token["token_hash"],
        stamp(token.get("revoked_at")), token.get("replaced_by_token_id"),
        stamp(token.get("last_used_at")), token.get("ip_address"),
        token.get("user_agent"), None, json.dumps(token, separators=(",", ":")),
    ))


def family_lock(family):
    """Serializes the writers of one family. Taken in its own statement, so that
    the statements after it read everything the previous holder committed."""
    return f"SELECT pg_advisory_xact_lock(hashtextextended({literal(family)}, 0));"


op = request["op"]
result = None
if op == "init":
    create = (f"CREATE TABLE {table} (id TEXT PRIMARY KEY, family TEXT NOT NULL, "
              "token_hash TEXT NOT NULL UNIQUE, revoked_at TEXT, replaced_by TEXT, last_used_at TEXT, "
              "ip_address TEXT, user_agent TEXT, reason TEXT, record TEXT NOT NULL)")
    if backend == "sqlite":
        with sqlite_connection() as connection:
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute(create)
    else:
        psql(create + ";")
    result = True
elif op == "drop":
    if backend == "sqlite":
        with sqlite_connection() as connection:
            connection.execute(f"DROP TABLE {table}")
    else:
        psql(f"DROP TABLE {table};")
    result = True
elif op == "insert":
    sql = f"INSERT INTO {table} VALUES ({insert_values(request['token'])})"
    if backend == "sqlite":
        with sqlite_connection() as connection:
            connection.execute(sql)
    else:
        psql(sql + ";")
    result = True
elif op == "find_by_hash":
    rows = select(f"token_hash = {literal(request['token_hash'])}")
    result = rows[0] if rows else None
elif op == "find_live":
    result = select(f"family = {literal(request['family'])} AND revoked_at IS NULL")
elif op == "revoke":
    sql = (f"UPDATE {table} SET revoked_at = {literal(stamp(request['revoked_at']))}, "
           f"replaced_by = {literal(request.get('replaced_by'))}, reason = {literal(request['reason'])} "
           # A revoked record is left alone, so a stale caller cannot overwrite a rotation.
           f"WHERE id = {literal(request['id'])} AND revoked_at IS NULL")
    if backend == "sqlite":
        with sqlite_connection() as connection:
            connection.execute(sql)
    else:
        psql(sql + ";")
    result = True
elif op == "revoke_family":
    family = request["family"]
    sql = (f"UPDATE {table} SET revoked_at = {literal(stamp(request['revoked_at']))}, "
           f"reason = {literal(request['reason'])} "
           f"WHERE family = {literal(family)} AND revoked_at IS NULL")
    if backend == "sqlite":
        with sqlite_connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(sql)
            connection.execute("COMMIT")
    else:
        psql(f"BEGIN; {family_lock(family)} {sql}; COMMIT;")
    result = True
elif op == "touch":
    sql = (f"UPDATE {table} SET last_used_at = {literal(stamp(request['used_at']))}, "
           f"ip_address = {literal(request.get('ip_address'))}, user_agent = {literal(request.get('user_agent'))} "
           f"WHERE id = {literal(request['id'])}")
    if backend == "sqlite":
        with sqlite_connection() as connection:
            connection.execute(sql)
    else:
        psql(sql + ";")
    result = True
elif op == "rotate":
    token = request["replacement"]
    at = literal(stamp(request["rotated_at"]))
    update = (f"UPDATE {table} SET revoked_at = {at}, last_used_at = {at}, "
              f"replaced_by = {literal(token['id'])}, reason = 'rotation', "
              f"ip_address = {literal(request.get('ip_address'))}, "
              f"user_agent = {literal(request.get('user_agent'))} "
              f"WHERE id = {literal(request['current'])} AND revoked_at IS NULL")
    pause = request.get("pause_dir")
    if pause and not re.fullmatch(r"[A-Za-z0-9_./-]+", pause):
        raise ValueError("invalid pause directory")
    if backend == "sqlite":
        with sqlite_connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            result = connection.execute(update).rowcount == 1
            if result:
                connection.execute(f"INSERT INTO {table} VALUES ({insert_values(token)})")
            if pause:
                open(os.path.join(pause, "paused"), "w").close()
                while not os.path.exists(os.path.join(pause, "release")):
                    time.sleep(0.02)
            connection.execute("COMMIT")
    else:
        # One statement: the revoke and the insert commit together or not at
        # all. A concurrent caller blocks on the row, re-evaluates revoked_at
        # after the first commit and then matches no row, so it inserts nothing.
        # A test can hold the transaction open before COMMIT, after the writes.
        hold = (f"\n\\! touch {pause}/paused\n"
                f"\\! while [ ! -e {pause}/release ]; do sleep 0.02; done\n") if pause else " "
        rows = psql(
            f"BEGIN; {family_lock(token['session_family_id'])} "
            f"WITH updated AS ({update} RETURNING id) "
            f"INSERT INTO {table} SELECT v.* FROM (VALUES ({insert_values(token)})) AS v, updated "
            f"RETURNING 1;{hold}COMMIT;"
        )
        result = len([line for line in rows if line.strip() == "1"]) == 1
elif op == "blocked_lock_requests":
    # Lock requests waiting in this database; None where the backend has no view.
    if backend == "sqlite":
        result = None
    else:
        result = int(psql("SELECT count(*) FROM pg_locks l JOIN pg_stat_activity a ON a.pid = l.pid "
                          "WHERE NOT l.granted AND a.datname = current_database();")[0])
else:
    raise ValueError("unsupported fixture operation")

json.dump(result, sys.stdout)
sys.stdout.write("\n")

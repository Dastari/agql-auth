#!/usr/bin/env python3
"""Test-only consumer persistence. Policy and transitions stay in Rust.

JSON stdin/stdout transports AuthRateLimitStore operations. SQLite uses the
standard library; PostgreSQL uses psql. Each fixture has its own database/table.
No normalized principal, IP, password, or token crosses this boundary.
"""
import json
import os
import re
import sqlite3
import subprocess
import sys
from urllib.parse import unquote, urlsplit

request = json.load(sys.stdin)
backend, database, table = (request[k] for k in ("backend", "database", "table"))
if not re.fullmatch(r"agql_conformance_[0-9a-f]+", table):
    raise ValueError("invalid isolated fixture table")

def quote(value):
    return "'" + str(value).replace("'", "''") + "'"

# All dynamic values are literals, never SQL identifiers. The table is a
# generated fixture identifier validated above. Production adapters should use
# their driver's bind parameters.
def execute(sql):
    if backend == "sqlite":
        with sqlite3.connect(database, timeout=30) as connection:
            return connection.execute(sql).fetchall()
    if backend != "postgres":
        raise ValueError("unsupported fixture backend")
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
    return [(line,) for line in result.stdout.splitlines() if line]

op = request["op"]
if op == "init":
    if backend == "sqlite":
        with sqlite3.connect(database) as connection:
            connection.execute("PRAGMA journal_mode=WAL")
    execute(f"CREATE TABLE {table} (flow TEXT NOT NULL, bucket TEXT NOT NULL, value_hash TEXT NOT NULL, revision TEXT NOT NULL, snapshot TEXT NOT NULL, PRIMARY KEY (flow, bucket, value_hash))")
    result = True
elif op == "drop":
    execute(f"DROP TABLE {table}")
    result = True
else:
    key = request["key"]
    predicate = " AND ".join(f"{column} = {quote(key[column])}" for column in ("flow", "bucket", "value_hash"))
    expected = request.get("expected_revision")
    if op == "find":
        rows = execute(f"SELECT snapshot FROM {table} WHERE {predicate}")
        result = json.loads(rows[0][0]) if rows else None
    elif op == "cas":
        replacement = request["replacement"]
        snapshot = quote(json.dumps(replacement, separators=(",", ":")))
        revision = quote(replacement["revision"])
        if expected is None:
            columns = ",".join(quote(key[k]) for k in ("flow", "bucket", "value_hash"))
            rows = execute(f"INSERT INTO {table} VALUES ({columns},{revision},{snapshot}) ON CONFLICT (flow,bucket,value_hash) DO NOTHING RETURNING revision")
        else:
            rows = execute(f"UPDATE {table} SET revision={revision}, snapshot={snapshot} WHERE {predicate} AND revision={quote(expected)} RETURNING revision")
        result = len(rows) == 1
    elif op == "clear":
        if expected is None:
            # No observed row: report absence without deleting any new row.
            result = not execute(f"SELECT revision FROM {table} WHERE {predicate}")
        else:
            result = len(execute(f"DELETE FROM {table} WHERE {predicate} AND revision={quote(expected)} RETURNING revision")) == 1
    else:
        raise ValueError("unsupported fixture operation")
json.dump(result, sys.stdout)
sys.stdout.write("\n")

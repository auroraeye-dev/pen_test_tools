#!/usr/bin/env python3
"""
MockSQL - a deliberately insecure, SQL-flavoured toy service for a home CTF lab.

It holds NO real data. It only pretends to be a database server:
  * it listens on a TCP port and greets every client with a banner,
  * it speaks a tiny plain-text protocol (one command per line),
  * it answers a few SQL-looking commands with a fake schema and empty results,
  * after a successful LOGIN it lets the client list and download the files
    in the "secret" folder (your winning picture and a flag).

INTENTIONAL LAB VULNERABILITIES (do not copy these into real software):
  1. Everything, including the password, travels in cleartext. Anyone who can
     see the traffic (Wireshark) can read the password.
  2. The banner leaks the product name and version (nmap -sV picks it up).
  3. There is no rate limiting or lockout.

Pure Python standard library, works on any CPU (x86_64, ARM64 under UTM, ...).
"""

import argparse
import base64
import hmac
import os
import socketserver
import sys
import threading
from datetime import datetime
from pathlib import Path

VERSION = "0.9.1-lab"
LAB_DIR = Path(__file__).resolve().parent.parent

# A fake schema, so the service "looks" like a database. No rows anywhere.
FAKE_SCHEMA = {
    "app_db": {
        "users": ["id INT PRIMARY KEY", "username VARCHAR(32)", "created_at DATETIME"],
        "sessions": ["id INT PRIMARY KEY", "user_id INT", "expires_at DATETIME"],
        "audit_log": ["id INT PRIMARY KEY", "event VARCHAR(64)", "ts DATETIME"],
    },
    "vault_db": {
        "secret_files": ["name VARCHAR(64)", "size_bytes INT"],
    },
}

HELP_TEXT = """Commands (one per line, case-insensitive):
  HELP                          this text
  LOGIN <user> <password>       authenticate
  WHOAMI                        show current user
  SHOW DATABASES                list databases (fake)
  USE <database>                pick a database
  SHOW TABLES                   list tables in current database (fake)
  DESCRIBE <table>              show columns (fake)
  SELECT ...                    always returns an empty set (no real data)
  SHOW SECRET                   list files in the secret folder   [login required]
  FETCH <file>                  download a secret file as base64  [login required]
  QUIT                          disconnect"""


def load_env_file(path: Path) -> dict:
    """Very small KEY=VALUE reader for config.env (no external deps)."""
    values = {}
    if not path.exists():
        return values
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
            value = value[1:-1]
        values[key.strip()] = value
    return values


def log(msg: str) -> None:
    print(f"[{datetime.now():%H:%M:%S}] {msg}", flush=True)


class Session:
    def __init__(self):
        self.user = None
        self.db = None


class MockSQLHandler(socketserver.StreamRequestHandler):
    # Filled in by main()
    config: dict = {}

    def send(self, text: str = "") -> None:
        self.wfile.write((text + "\r\n").encode("utf-8"))

    def handle(self):
        peer = f"{self.client_address[0]}:{self.client_address[1]}"
        log(f"connection from {peer}")
        s = Session()
        self.send(f"MockSQL {VERSION} ready (text protocol, NO TLS). Type HELP.")
        failed = 0
        try:
            while True:
                self.wfile.write(b"mocksql> ")
                self.wfile.flush()
                raw = self.rfile.readline(4096)
                if not raw:
                    break
                line = raw.decode("utf-8", errors="replace").strip()
                if not line:
                    continue
                parts = line.split()
                cmd = parts[0].upper()
                two = " ".join(p.upper() for p in parts[:2])

                if cmd == "QUIT" or cmd == "EXIT":
                    self.send("BYE")
                    break
                elif cmd == "HELP":
                    self.send(HELP_TEXT)
                elif cmd == "LOGIN":
                    if len(parts) != 3:
                        self.send("ERR usage: LOGIN <user> <password>")
                        continue
                    user, password = parts[1], parts[2]
                    ok_user = hmac.compare_digest(user, self.config["user"])
                    ok_pass = hmac.compare_digest(password, self.config["password"])
                    if ok_user and ok_pass:
                        s.user = user
                        log(f"{peer} logged in as {user}")
                        self.send(f"OK welcome {user}. Try: SHOW SECRET")
                    else:
                        failed += 1
                        log(f"{peer} failed login #{failed} for user {user!r}")
                        self.send("ERR access denied")
                elif cmd == "WHOAMI":
                    self.send(f"OK {s.user or 'anonymous'}")
                elif two == "SHOW DATABASES":
                    for name in FAKE_SCHEMA:
                        self.send(f"| {name} |")
                    self.send(f"OK {len(FAKE_SCHEMA)} rows")
                elif cmd == "USE":
                    name = parts[1] if len(parts) > 1 else ""
                    if name in FAKE_SCHEMA:
                        s.db = name
                        self.send(f"OK database changed to {name}")
                    else:
                        self.send("ERR unknown database")
                elif two == "SHOW TABLES":
                    if not s.db:
                        self.send("ERR no database selected (USE <database>)")
                        continue
                    for t in FAKE_SCHEMA[s.db]:
                        self.send(f"| {t} |")
                    self.send(f"OK {len(FAKE_SCHEMA[s.db])} rows")
                elif cmd in ("DESCRIBE", "DESC"):
                    table = parts[1] if len(parts) > 1 else ""
                    cols = FAKE_SCHEMA.get(s.db or "", {}).get(table)
                    if not cols:
                        self.send("ERR unknown table (did you USE a database?)")
                        continue
                    for c in cols:
                        self.send(f"| {c} |")
                    self.send(f"OK {len(cols)} rows")
                elif cmd in ("SELECT", "INSERT", "UPDATE", "DELETE"):
                    self.send("OK 0 rows (mock server: schema only, no data stored)")
                elif two == "SHOW SECRET":
                    if not s.user:
                        self.send("ERR login required")
                        continue
                    files = self.secret_files()
                    for f in files:
                        self.send(f"| {f.name} | {f.stat().st_size} bytes |")
                    self.send(f"OK {len(files)} files")
                elif cmd == "FETCH":
                    if not s.user:
                        self.send("ERR login required")
                        continue
                    name = parts[1] if len(parts) > 1 else ""
                    target = {f.name: f for f in self.secret_files()}.get(name)
                    if target is None:
                        self.send("ERR no such file (see SHOW SECRET)")
                        continue
                    data = base64.b64encode(target.read_bytes()).decode("ascii")
                    self.send(f"OK BEGIN {target.name} {target.stat().st_size}")
                    for i in range(0, len(data), 76):
                        self.send(data[i:i + 76])
                    self.send("END")
                    log(f"{peer} ({s.user}) fetched {target.name}")
                else:
                    self.send("ERR unknown command, type HELP")
        except (ConnectionResetError, BrokenPipeError):
            pass
        log(f"{peer} disconnected")

    def secret_files(self):
        folder = Path(self.config["secret_dir"])
        if not folder.is_dir():
            return []
        return sorted(p for p in folder.iterdir() if p.is_file() and not p.name.startswith("."))


class ThreadedServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True


def main():
    env = load_env_file(LAB_DIR / "config.env")
    env.update({k: v for k, v in os.environ.items() if k.startswith("MOCKSQL_")})

    ap = argparse.ArgumentParser(description="MockSQL lab server (intentionally insecure)")
    ap.add_argument("--host", default=env.get("MOCKSQL_HOST", "0.0.0.0"))
    ap.add_argument("--port", type=int, default=int(env.get("MOCKSQL_PORT", "13306")))
    ap.add_argument("--secret-dir", default=env.get("MOCKSQL_SECRET_DIR", str(LAB_DIR / "secret")))
    args = ap.parse_args()

    user = env.get("MOCKSQL_USER")
    password = env.get("MOCKSQL_PASSWORD")
    if not user or not password:
        sys.exit("No user/password configured. Run ./setup.sh first (it writes config.env).")

    MockSQLHandler.config = {"user": user, "password": password, "secret_dir": args.secret_dir}
    with ThreadedServer((args.host, args.port), MockSQLHandler) as srv:
        log(f"MockSQL {VERSION} listening on {args.host}:{args.port}")
        log(f"secret folder: {args.secret_dir}")
        log("WARNING: lab service, cleartext protocol. Run it only on your own LAN.")
        try:
            srv.serve_forever()
        except KeyboardInterrupt:
            log("shutting down")


if __name__ == "__main__":
    main()

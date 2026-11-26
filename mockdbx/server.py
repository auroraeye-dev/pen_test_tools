#!/usr/bin/env python3
"""
MockDBX - a deliberately insecure stand-in for a DBX-style database node,
built for a home CTF lab. Pure Python standard library, any CPU.

It imitates the *infrastructure* of DBX (https://github.com/vanshjain-0702/DBX-Database-Extreme),
a per-tenant memory engine: the RESP2 wire protocol that redis-cli speaks, the
`AUTH <tenantID>:<keyID> <secret>` login, string KV commands, a small vector
index, and a catalog of the control-plane/tenant structure loaded from
schema/*.sql. No DBX code is copied, and no real data is stored: the KV and
vectors live in memory only and vanish on restart.

INTENTIONAL LAB VULNERABILITIES (real DBX does not do these; never copy them):
  1. No TLS. AUTH, and the tenant secret in it, crosses the wire in cleartext.
  2. INFO answers before login and leaks the product, version and port.
  3. No rate limiting or lockout on AUTH.
  4. One tenant key is enough to read the whole "vault" (your secret folder).
"""

import argparse
import hmac
import math
import os
import shlex
import socketserver
import sys
from datetime import datetime
from fnmatch import fnmatchcase
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from schema import load_schema  # noqa: E402

VERSION = "1.3.0-lab"
LAB_DIR = Path(__file__).resolve().parent.parent
VAULT_PREFIX = "vault:"
SCHEMA: dict = {}  # filled in by main()

HELP_LINES = [
    "MockDBX commands (RESP2 or plain text lines, case-insensitive):",
    "  PING | INFO | HELP | QUIT                     no login needed",
    "  AUTH <tenantID>:<keyID> <secret>              log in (DBX style)",
    "  WHOAMI",
    "  SET k v [EX s] | GET k | DEL k.. | KEYS pat | TTL k | MSET | MGET",
    "  VADD idx id f1 f2 .. | VSEARCH idx f1 f2 .. k  tiny vector index",
    "  SHOW DATABASES | USE db | SHOW TABLES | DESCRIBE t | SHOW CREATE TABLE t",
    "  SHOW SECRET | FETCH <file>                    the vault (also KEYS vault:* / GET vault:<file>)",
]


def log(msg: str) -> None:
    print(f"[{datetime.now():%H:%M:%S}] {msg}", flush=True)


def load_env_file(path: Path) -> dict:
    values = {}
    if path.exists():
        for raw in path.read_text(encoding="utf-8").splitlines():
            line = raw.strip()
            if line and not line.startswith("#") and "=" in line:
                k, _, v = line.partition("=")
                v = v.strip()
                if len(v) >= 2 and v[0] == v[-1] and v[0] in "'\"":
                    v = v[1:-1]
                values[k.strip()] = v
    return values


# ---- RESP2 encoding -------------------------------------------------------

class Simple(str):
    """A RESP simple string (+OK)."""


class Err(str):
    """A RESP error (-ERR ...)."""


def encode(v) -> bytes:
    if isinstance(v, Err):
        return f"-{v}\r\n".encode()
    if isinstance(v, Simple):
        return f"+{v}\r\n".encode()
    if v is None:
        return b"$-1\r\n"
    if isinstance(v, bool):
        return f":{int(v)}\r\n".encode()
    if isinstance(v, int):
        return f":{v}\r\n".encode()
    if isinstance(v, (list, tuple)):
        return f"*{len(v)}\r\n".encode() + b"".join(encode(x) for x in v)
    if isinstance(v, str):
        v = v.encode("utf-8")
    return f"${len(v)}\r\n".encode() + v + b"\r\n"


# ---- Shared in-memory store (lost on restart, by design) -------------------

KV: dict = {}       # tenant -> {key: (value_bytes, expires_at or None)}
VECTORS: dict = {}  # tenant -> {index: {id: [floats]}}


class Handler(socketserver.StreamRequestHandler):
    config: dict = {}

    # -- reading commands (RESP array or inline text, like Redis) --
    def read_command(self):
        line = self.rfile.readline(65536)
        if not line:
            return None
        if line.startswith(b"*"):
            n = int(line[1:].strip() or 0)
            args = []
            for _ in range(n):
                hdr = self.rfile.readline(65536)
                if not hdr.startswith(b"$"):
                    raise ValueError("protocol error: expected bulk string")
                size = int(hdr[1:].strip())
                args.append(self.rfile.read(size + 2)[:-2].decode("utf-8", "replace"))
            return args
        text = line.decode("utf-8", "replace").strip()
        try:
            return shlex.split(text)
        except ValueError:
            return text.split()

    def reply(self, value):
        self.wfile.write(encode(value))
        self.wfile.flush()

    def handle(self):
        self.peer = f"{self.client_address[0]}:{self.client_address[1]}"
        self.tenant = None
        self.key_id = None
        self.db = None
        log(f"connection from {self.peer}")
        try:
            while True:
                try:
                    args = self.read_command()
                except ValueError as e:
                    self.reply(Err(f"ERR {e}"))
                    break
                if args is None:
                    break
                if not args:
                    continue
                result = self.dispatch(args)
                self.reply(result)
                if isinstance(result, Simple) and result == "BYE":
                    break
        except (ConnectionResetError, BrokenPipeError):
            pass
        log(f"{self.peer} disconnected")

    def dispatch(self, args):
        cmd = args[0].upper()
        up = [a.upper() for a in args]
        pre_auth = {
            "PING": lambda: Simple("PONG") if len(args) == 1 else args[1],
            "INFO": self.cmd_info,
            "HELP": lambda: HELP_LINES,
            "COMMAND": lambda: [],  # redis-cli asks for command docs on start
            "QUIT": lambda: Simple("BYE"),
            "AUTH": lambda: self.cmd_auth(args[1:]),
            "HELLO": lambda: Err("NOPROTO this server speaks RESP2 only"),
            "CLIENT": lambda: Simple("OK"),
        }
        if cmd in pre_auth:
            return pre_auth[cmd]()
        if not self.tenant:
            return Err("NOAUTH Authentication required. Use AUTH <tenantID>:<keyID> <secret>")

        if cmd == "WHOAMI":
            return f"{self.tenant}:{self.key_id}"
        if up[:2] == ["SHOW", "DATABASES"]:
            return list(SCHEMA)
        if cmd == "USE":
            if len(args) > 1 and args[1] in SCHEMA:
                self.db = args[1]
                return Simple("OK")
            return Err("ERR unknown database (SHOW DATABASES)")
        if up[:2] == ["SHOW", "TABLES"]:
            if not self.db:
                return Err("ERR no database selected (USE <database>)")
            return list(SCHEMA[self.db])
        if up[:3] == ["SHOW", "CREATE", "TABLE"] or cmd in ("DESCRIBE", "DESC"):
            name = args[3] if cmd == "SHOW" else (args[1] if len(args) > 1 else "")
            cols = SCHEMA.get(self.db or "", {}).get(name)
            if not cols:
                return Err("ERR unknown table (did you USE a database?)")
            if cmd == "SHOW":
                return f"CREATE TABLE {name} (\n  " + ",\n  ".join(cols) + "\n);"
            return cols
        if up[:2] == ["SHOW", "SECRET"]:
            return [f"{f.name} ({f.stat().st_size} bytes)" for f in self.vault_files()]
        if cmd == "FETCH":
            return self.vault_read(args[1] if len(args) > 1 else "")
        if cmd in ("SET", "SETEX", "GET", "DEL", "KEYS", "TTL", "EXPIRE", "PERSIST", "MSET", "MGET", "EXISTS"):
            return self.kv(cmd, args[1:])
        if cmd in ("VADD", "VSEARCH"):
            return self.vec(cmd, args[1:])
        if cmd in ("VADD_BATCH", "VDEL", "VSIM", "VFUSE", "VCOMPACT", "VMIGRATE"):
            return Err(f"ERR {cmd} is not implemented in the mock (structure only)")
        if cmd in ("FLUSHALL", "FLUSHDB", "CONFIG", "SAVE", "BGSAVE", "SHUTDOWN"):
            return Err("ERR command not allowed in the DBX v1 profile")
        return Err(f"ERR unknown command '{args[0]}', try HELP")

    # -- commands --
    def cmd_info(self):
        # Intentional info leak: answers before AUTH.
        return (
            "# Server\r\n"
            "redis_version:7.2.0\r\n"
            f"dbx_version:{VERSION}\r\n"
            "redis_mode:standalone\r\n"
            "dbx_profile:durable-v1 (mock)\r\n"
            f"tcp_port:{self.config['port']}\r\n"
            "tls:disabled\r\n"
            "auth:AUTH <tenantID>:<keyID> <secret>\r\n"
            "# Catalog\r\n"
            f"databases:{len(SCHEMA)}\r\n"
            f"tables:{sum(len(t) for t in SCHEMA.values())}\r\n"
        )

    def cmd_auth(self, rest):
        if len(rest) != 2 or ":" not in rest[0]:
            return Err("ERR usage: AUTH <tenantID>:<keyID> <secret>")
        ident, secret = rest
        ok = hmac.compare_digest(ident, self.config["ident"]) & hmac.compare_digest(secret, self.config["secret"])
        if not ok:
            log(f"{self.peer} failed AUTH for {ident!r}")
            return Err("WRONGPASS invalid tenant key or secret")
        self.tenant, self.key_id = ident.split(":", 1)
        log(f"{self.peer} authenticated as tenant={self.tenant} key={self.key_id}")
        return Simple("OK")

    def vault_files(self):
        folder = Path(self.config["secret_dir"])
        if not folder.is_dir():
            return []
        return sorted(p for p in folder.iterdir() if p.is_file() and not p.name.startswith("."))

    def vault_read(self, name):
        target = {f.name: f for f in self.vault_files()}.get(name)
        if target is None:
            return None
        log(f"{self.peer} ({self.tenant}) read vault file {name}")
        return target.read_bytes()

    def kv(self, cmd, a):
        store = KV.setdefault(self.tenant, {})
        now = datetime.now().timestamp()
        for k in [k for k, (_, exp) in store.items() if exp and exp <= now]:
            del store[k]

        def get(k):
            if k.startswith(VAULT_PREFIX):
                return self.vault_read(k[len(VAULT_PREFIX):])
            item = store.get(k)
            return item[0] if item else None

        try:
            if cmd == "SET":
                exp = None
                if len(a) >= 4 and a[2].upper() == "EX":
                    exp = now + int(a[3])
                store[a[0]] = (a[1].encode(), exp)
                return Simple("OK")
            if cmd == "SETEX":
                store[a[0]] = (a[2].encode(), now + int(a[1]))
                return Simple("OK")
            if cmd == "GET":
                return get(a[0])
            if cmd == "MGET":
                return [get(k) for k in a]
            if cmd == "MSET":
                for k, v in zip(a[0::2], a[1::2]):
                    store[k] = (v.encode(), None)
                return Simple("OK")
            if cmd == "DEL":
                return sum(1 for k in a if store.pop(k, None) is not None)
            if cmd == "EXISTS":
                return sum(1 for k in a if get(k) is not None)
            if cmd == "KEYS":
                pattern = a[0] if a else "*"
                keys = list(store) + [VAULT_PREFIX + f.name for f in self.vault_files()]
                return [k for k in keys if fnmatchcase(k, pattern)]
            if cmd == "TTL":
                if a[0] not in store:
                    return -2
                exp = store[a[0]][1]
                return -1 if exp is None else max(0, int(exp - now))
            if cmd == "EXPIRE":
                if a[0] not in store:
                    return 0
                store[a[0]] = (store[a[0]][0], now + int(a[1]))
                return 1
            if cmd == "PERSIST":
                if a[0] not in store or store[a[0]][1] is None:
                    return 0
                store[a[0]] = (store[a[0]][0], None)
                return 1
        except (IndexError, ValueError):
            return Err(f"ERR wrong arguments for '{cmd.lower()}'")
        return Err("ERR unreachable")

    def vec(self, cmd, a):
        idxs = VECTORS.setdefault(self.tenant, {})
        try:
            if cmd == "VADD":
                idxs.setdefault(a[0], {})[a[1]] = [float(x) for x in a[2:]]
                return Simple("OK")
            index, *nums = a
            k = int(nums.pop())
            q = [float(x) for x in nums]
            norm = lambda v: math.sqrt(sum(x * x for x in v)) or 1.0  # noqa: E731
            scored = sorted(
                ((sum(x * y for x, y in zip(q, v)) / (norm(q) * norm(v)), i) for i, v in idxs.get(index, {}).items()),
                reverse=True,
            )[:k]
            return [x for s, i in scored for x in (i, f"{s:.4f}")]
        except (IndexError, ValueError):
            return Err(f"ERR wrong arguments for '{cmd.lower()}'")


class ThreadedServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True


def main():
    env = load_env_file(LAB_DIR / "config.env")
    env.update({k: v for k, v in os.environ.items() if k.startswith("DBX_LAB_")})

    ap = argparse.ArgumentParser(description="MockDBX lab server (intentionally insecure)")
    ap.add_argument("--host", default=env.get("DBX_LAB_HOST", "0.0.0.0"))
    ap.add_argument("--port", type=int, default=int(env.get("DBX_LAB_PORT", "1143")))
    ap.add_argument("--schema-dir", default=env.get("DBX_LAB_SCHEMA_DIR", str(LAB_DIR / "schema")))
    ap.add_argument("--secret-dir", default=env.get("DBX_LAB_SECRET_DIR", str(LAB_DIR / "secret")))
    args = ap.parse_args()

    tenant, key_id, secret = (env.get(k) for k in ("DBX_LAB_TENANT", "DBX_LAB_KEY_ID", "DBX_LAB_SECRET"))
    if not (tenant and key_id and secret):
        sys.exit("No tenant key configured. Run ./setup.sh first (it writes config.env).")

    SCHEMA.update(load_schema(args.schema_dir))
    Handler.config = {
        "ident": f"{tenant}:{key_id}",
        "secret": secret,
        "secret_dir": args.secret_dir,
        "port": args.port,
    }
    with ThreadedServer((args.host, args.port), Handler) as srv:
        log(f"MockDBX {VERSION} (RESP2, NO TLS) listening on {args.host}:{args.port}")
        log(f"catalog: {len(SCHEMA)} databases, {sum(len(t) for t in SCHEMA.values())} tables from {args.schema_dir}")
        log(f"vault (secret folder): {args.secret_dir}")
        log("WARNING: lab service with cleartext auth. Run it only on your own LAN.")
        try:
            srv.serve_forever()
        except KeyboardInterrupt:
            log("shutting down")


if __name__ == "__main__":
    main()

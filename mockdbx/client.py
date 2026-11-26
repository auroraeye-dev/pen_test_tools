#!/usr/bin/env python3
"""
MockDBX lab client (pure Python standard library). Speaks RESP2, the same
protocol as redis-cli, so `redis-cli -h <vm> -p 1143` works too.

  shell   interactive prompt
  admin   plays the VM owner: AUTHs every N seconds so there is traffic to sniff
  fetch   AUTHs and downloads every file in the vault (the secret folder)

Examples
  python3 mockdbx/client.py shell --host 192.168.64.5
  python3 mockdbx/client.py admin --host 192.168.64.5 --key acme:k_admin --secret 'S3cret!' --every 15
  python3 mockdbx/client.py fetch --host 192.168.64.5 --key acme:k_admin --secret 'S3cret!' --out loot
"""

import argparse
import shlex
import socket
import sys
import time
from pathlib import Path


class RespError(Exception):
    pass


class Conn:
    def __init__(self, host, port, timeout=10):
        self.sock = socket.create_connection((host, port), timeout=timeout)
        self.f = self.sock.makefile("rb")

    def call(self, *args):
        out = [f"*{len(args)}\r\n".encode()]
        for a in args:
            b = a if isinstance(a, bytes) else str(a).encode()
            out.append(f"${len(b)}\r\n".encode() + b + b"\r\n")
        self.sock.sendall(b"".join(out))
        return self.read()

    def read(self):
        line = self.f.readline()
        if not line:
            raise ConnectionError("server closed the connection")
        kind, rest = line[:1], line[1:-2]
        if kind == b"+":
            return rest.decode()
        if kind == b"-":
            raise RespError(rest.decode())
        if kind == b":":
            return int(rest)
        if kind == b"$":
            n = int(rest)
            return None if n < 0 else self.f.read(n + 2)[:-2]
        if kind == b"*":
            n = int(rest)
            return None if n < 0 else [self.read() for _ in range(n)]
        raise RespError(f"bad reply: {line!r}")

    def close(self):
        try:
            self.call("QUIT")
        except (OSError, RespError, ConnectionError):
            pass
        self.sock.close()


def show(v, indent=""):
    if isinstance(v, list):
        if not v:
            print(indent + "(empty array)")
        for i, x in enumerate(v, 1):
            print(f"{indent}{i}) ", end="")
            show(x, indent + "   ") if isinstance(x, list) else show(x)
    elif isinstance(v, bytes):
        try:
            text = v.decode("utf-8")
            print(text if "\n" in text else f'"{text}"')
        except UnicodeDecodeError:
            print(f"(binary, {len(v)} bytes; use `fetch` to save it)")
    elif v is None:
        print("(nil)")
    elif isinstance(v, int):
        print(f"(integer) {v}")
    else:
        print(v)


def do_shell(a):
    c = Conn(a.host, a.port)
    print(f"Connected to {a.host}:{a.port}. Try: INFO, HELP, AUTH <tenant>:<keyID> <secret>")
    try:
        while True:
            line = input(f"{a.host}:{a.port}> ").strip()
            if not line:
                continue
            if line.upper() in ("QUIT", "EXIT"):
                break
            try:
                show(c.call(*shlex.split(line)))
            except RespError as e:
                print(f"(error) {e}")
    except (EOFError, KeyboardInterrupt):
        print()
    c.close()


def do_admin(a):
    print(f"Simulating the owner AUTHing to {a.host}:{a.port} every {a.every}s. Ctrl+C to stop.")
    n = 0
    while True:
        n += 1
        try:
            c = Conn(a.host, a.port)
            c.call("AUTH", a.key, a.secret)
            c.call("KEYS", "vault:*")
            c.close()
            print(f"  login #{n}: OK")
        except RespError as e:
            print(f"  login #{n}: {e}")
        except OSError as e:
            print(f"  login #{n}: connection failed ({e})")
        if a.once:
            break
        time.sleep(a.every)


def do_fetch(a):
    c = Conn(a.host, a.port)
    try:
        c.call("AUTH", a.key, a.secret)
    except RespError as e:
        sys.exit(f"AUTH failed: {e}")
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    for key in c.call("KEYS", "vault:*"):
        key = key.decode()
        name = Path(key.split(":", 1)[1]).name
        data = c.call("GET", key)
        if data is None:
            print(f"  {key}: empty")
            continue
        (out / name).write_bytes(data)
        print(f"  saved {out / name} ({len(data)} bytes)")
    c.close()
    print("Done. Open the folder and enjoy your winning picture.")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="mode", required=True)
    for name in ("shell", "admin", "fetch"):
        p = sub.add_parser(name)
        p.add_argument("--host", required=True, help="VM IP address")
        p.add_argument("--port", type=int, default=1143)
        if name != "shell":
            p.add_argument("--key", required=True, help="<tenantID>:<keyID>, e.g. acme:k_admin")
            p.add_argument("--secret", required=True)
        if name == "admin":
            p.add_argument("--every", type=int, default=15, help="seconds between logins")
            p.add_argument("--once", action="store_true")
        if name == "fetch":
            p.add_argument("--out", default="loot")
    a = ap.parse_args()
    {"shell": do_shell, "admin": do_admin, "fetch": do_fetch}[a.mode](a)


if __name__ == "__main__":
    main()

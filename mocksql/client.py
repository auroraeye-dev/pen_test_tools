#!/usr/bin/env python3
"""
MockSQL lab client (pure Python standard library).

  shell     interactive prompt, like `mysql` but for the mock server
  admin     plays the VM owner: logs in every N seconds so there is
            traffic for you to sniff with Wireshark
  fetch     logs in and downloads every file in the secret folder

Examples
  python3 client.py shell  --host 192.168.64.5
  python3 client.py admin  --host 192.168.64.5 --user admin --password 'S3cret!' --every 20
  python3 client.py fetch  --host 192.168.64.5 --user admin --password 'S3cret!' --out loot
"""

import argparse
import base64
import socket
import sys
import time
from pathlib import Path

PROMPT = b"mocksql> "


class Conn:
    def __init__(self, host, port, timeout=10):
        self.sock = socket.create_connection((host, port), timeout=timeout)
        self.buf = b""

    def read_until_prompt(self) -> str:
        while PROMPT not in self.buf:
            chunk = self.sock.recv(65536)
            if not chunk:
                break
            self.buf += chunk
        out, _, self.buf = self.buf.partition(PROMPT)
        return out.decode("utf-8", errors="replace")

    def cmd(self, line: str) -> str:
        self.sock.sendall((line + "\r\n").encode("utf-8"))
        return self.read_until_prompt()

    def close(self):
        try:
            self.sock.sendall(b"QUIT\r\n")
        except OSError:
            pass
        self.sock.close()


def do_shell(a):
    c = Conn(a.host, a.port)
    print(c.read_until_prompt(), end="")
    try:
        while True:
            line = input("mocksql> ")
            if not line.strip():
                continue
            if line.strip().upper() in ("QUIT", "EXIT"):
                break
            print(c.cmd(line), end="")
    except (EOFError, KeyboardInterrupt):
        print()
    c.close()


def do_admin(a):
    print(f"Simulating the VM owner logging in to {a.host}:{a.port} every {a.every}s. Ctrl+C to stop.")
    n = 0
    while True:
        n += 1
        try:
            c = Conn(a.host, a.port)
            c.read_until_prompt()
            reply = c.cmd(f"LOGIN {a.user} {a.password}").strip()
            c.cmd("SHOW SECRET")
            c.close()
            print(f"  login #{n}: {reply}")
        except OSError as e:
            print(f"  login #{n}: connection failed ({e})")
        if a.once:
            break
        time.sleep(a.every)


def do_fetch(a):
    c = Conn(a.host, a.port)
    c.read_until_prompt()
    reply = c.cmd(f"LOGIN {a.user} {a.password}")
    if not reply.strip().startswith("OK"):
        sys.exit(f"Login failed: {reply.strip()}")
    listing = c.cmd("SHOW SECRET")
    names = [ln.split("|")[1].strip() for ln in listing.splitlines() if ln.startswith("|")]
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    for name in names:
        lines = c.cmd(f"FETCH {name}").splitlines()
        if not lines or not lines[0].startswith("OK BEGIN"):
            print(f"  could not fetch {name}: {lines[:1]}")
            continue
        body = "".join(ln.strip() for ln in lines[1:] if ln.strip() != "END")
        (out / name).write_bytes(base64.b64decode(body))
        print(f"  saved {out / name}")
    c.close()
    print("Done. Open the folder and enjoy your winning picture.")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="mode", required=True)
    for name in ("shell", "admin", "fetch"):
        p = sub.add_parser(name)
        p.add_argument("--host", required=True, help="VM IP address")
        p.add_argument("--port", type=int, default=13306)
        if name in ("admin", "fetch"):
            p.add_argument("--user", required=True)
            p.add_argument("--password", required=True)
        if name == "admin":
            p.add_argument("--every", type=int, default=15, help="seconds between logins")
            p.add_argument("--once", action="store_true")
        if name == "fetch":
            p.add_argument("--out", default="loot")
    a = ap.parse_args()
    {"shell": do_shell, "admin": do_admin, "fetch": do_fetch}[a.mode](a)


if __name__ == "__main__":
    main()

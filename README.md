# pen_test_tools: find the port, sniff the password, win the picture

A small home CTF lab. You run a fake "SQL-like" database service on your own
UTM virtual machine. From your Mac you discover it with **nmap**, capture a
login with **Wireshark**, read the password straight out of the packets, and use
it to unlock the **secret folder** that holds your winning picture and a flag.

> **For your own lab only.** Run this on a VM you own, on your own network, and
> scan/sniff only your own machines. The service is deliberately insecure.
> Never expose it to the internet.

```
 Mac (attacker + "owner")                     UTM VM (target)
 ┌──────────────────────────┐   TCP 13306    ┌─────────────────────────────┐
 │ nmap  -> finds the port  │ ─────────────▶ │ MockSQL 0.9.1-lab           │
 │ client.py admin  (owner) │   cleartext    │  fake schema, no real data  │
 │ Wireshark -> reads LOGIN │ ◀────────────▶ │  secret/ (picture + flag)   │
 │ client.py fetch -> loot/ │                └─────────────────────────────┘
 └──────────────────────────┘
```

## What's in here

| Path | What it is |
| --- | --- |
| `mocksql/server.py` | The mock database service. Pure Python stdlib, any CPU (ARM64 under UTM is fine). Holds no real data, only structure. |
| `schema/*.sql` | The database structure the service shows (4 databases, 14 tables by default). Plain `CREATE DATABASE` / `CREATE TABLE` files: swap in your own. |
| `mocksql/schema.py` | Reads those `.sql` files. Ignores `INSERT`s and anything else, so a real schema dump drops straight in. |
| `mocksql/client.py` | Client with three modes: `shell` (interactive), `admin` (pretends to be you logging in every few seconds, so there's traffic to sniff), `fetch` (logs in and downloads the secret folder). |
| `secret/` | The secret folder. `winning_picture.png` is a placeholder, swap in your own. `setup.sh` adds `flag.txt`. |
| `setup.sh` | Run once on the VM: pick a username and password, generate the flag, open the firewall port. |
| `run.sh` | Starts the service and prints the VM's IP. |
| `extras/mocksql.service` | Optional systemd unit to start it at boot. |

### The intentional vulnerabilities

1. **Cleartext protocol.** `LOGIN admin <password>` crosses the network as
   plain text, no TLS. Anyone who can see the packets can read it.
2. **Chatty banner.** The service announces its name and version, which nmap
   service detection shows you.
3. **No lockout or rate limit.** Wrong passwords are only logged.

Real databases fix these with TLS, challenge/response auth and lockouts. That's
the lesson.

## Part 1: set up the VM (target)

Any Linux VM in UTM works (Ubuntu/Debian ARM64 on Apple Silicon is typical).

**UTM network mode.** In UTM, VM settings → Network, use **Shared Network**
(default) or **Bridged**. With Shared Network the Mac talks to the VM over a
virtual interface (usually `bridge100`, VM IPs like `192.168.64.x`). With
Bridged the VM gets an IP on your home Wi-Fi like any other device.

On the VM:

```bash
sudo apt update && sudo apt install -y git python3
git clone https://github.com/auroraeye-dev/pen_test_tools.git
cd pen_test_tools
./setup.sh          # choose username + password (no spaces)
./run.sh            # prints the VM IP, then listens on 0.0.0.0:13306
```

(Private repo? Clone with `gh repo clone auroraeye-dev/pen_test_tools` after
`gh auth login`, or use a personal access token.)

Optional: put your own photo in place of `secret/winning_picture.png` (any
file you drop in `secret/` is served). Want a different port? Run
`MOCKSQL_PORT=3306 ./setup.sh`, or edit `config.env`.

Find the VM's IP any time with `hostname -I` or `ip -4 addr`. Write it down,
but in Part 2 pretend you don't know it.

### Use your own database structure

Every `*.sql` file in `schema/` is loaded in name order when the service
starts. Put your own structure in, for example `schema/20_mine.sql`, or delete
`10_default.sql` to show only yours. A `mysqldump --no-data` or `pg_dump
--schema-only` output works as is. Only the structure is used: rows from
`INSERT` statements are ignored and never served. Restart `./run.sh` after
changes; the first log lines say how many databases and tables were loaded.

Once you're in (any time, no login needed):

```
SHOW DATABASES
USE shop_db
SHOW TABLES
DESCRIBE orders
SHOW CREATE TABLE orders
```

## Part 2: discover the VM with nmap (on the Mac)

```bash
brew install nmap
```

**Find your subnet.** For Shared Network: `ifconfig bridge100 | grep inet`
(e.g. `192.168.64.1` → subnet `192.168.64.0/24`). For Bridged: `ipconfig
getifaddr en0` (e.g. `192.168.1.23` → `192.168.1.0/24`).

**1. Host discovery: who's alive?**

```bash
sudo nmap -sn 192.168.64.0/24
```

**2. Port scan the VM: what's open?** Port 13306 is not in nmap's default top
1000, so scan everything:

```bash
sudo nmap -p- --min-rate 2000 192.168.64.5
# 13306/tcp open  unknown
```

**3. Service/version detection: what is it?**

```bash
sudo nmap -sV -p 13306 192.168.64.5
```

nmap doesn't know "MockSQL", so it prints a fingerprint. Look inside it for the
banner: `MockSQL 0.9.1-lab ready (text protocol, NO TLS)`. "NO TLS" is your hint
that sniffing will work. (This step takes two to three minutes while nmap tries
all its probes. Add `--version-light` to speed it up.)

**4. Poke it by hand:**

```bash
nc 192.168.64.5 13306
HELP
SHOW DATABASES
SHOW SECRET          # -> ERR login required
```

You need the password.

## Part 3: sniff the password with Wireshark (on the Mac)

```bash
brew install --cask wireshark
```

1. Open Wireshark and start capturing on the interface that reaches the VM:
   **`bridge100`** for Shared Network, **`en0`** (Wi-Fi) for Bridged.
   Capture filter: `tcp port 13306`.
2. Generate a login, playing yourself (the VM owner) logging in. In a second
   Mac terminal:

   ```bash
   python3 mocksql/client.py admin --host 192.168.64.5 --user admin --password 'YOUR_PASSWORD' --every 15
   ```

   (This is the step where "you entered the password". In a real attack it'd be
   someone else's login on the same network.)
3. In Wireshark, apply the display filter:

   ```
   tcp.port == 13306 && frame contains "LOGIN"
   ```

4. Right-click a packet → **Follow → TCP Stream**. You'll see the whole
   conversation in plain text:

   ```
   MockSQL 0.9.1-lab ready (text protocol, NO TLS). Type HELP.
   mocksql> LOGIN admin YOUR_PASSWORD
   OK welcome admin. Try: SHOW SECRET
   ```

Stop the `admin` script (Ctrl+C). You now have the credentials.

Terminal alternative (Wireshark's CLI, installed with it):

```bash
sudo tshark -i bridge100 -f "tcp port 13306" -Y 'frame contains "LOGIN"' -T fields -e tcp.payload | xxd -r -p
```

**Why this only works one way:** on a switched/Wi-Fi network your Mac only sees
traffic to and from itself (and the VM bridge it hosts). That's why the owner
login runs from the Mac. On UTM Shared Network the Mac hosts the bridge, so a
second VM logging in to the target is visible on `bridge100` too. That's a fun
upgrade.

## Part 4: unlock the secret folder

Interactive:

```bash
python3 mocksql/client.py shell --host 192.168.64.5
mocksql> LOGIN admin YOUR_SNIFFED_PASSWORD
mocksql> SHOW SECRET
| flag.txt | 23 bytes |
| winning_picture.png | 16846 bytes |
```

Grab everything:

```bash
python3 mocksql/client.py fetch --host 192.168.64.5 --user admin --password 'YOUR_SNIFFED_PASSWORD'
open loot/winning_picture.png
cat loot/flag.txt          # FLAG{...}
```

🏆 Done. Check the server window on the VM: it logged every connection, failed
login and fetch, which is what a defender would look at.

## Extra challenges

- Count the failed logins in the server log after trying a few wrong passwords.
  What would a lockout change?
- Move the service to 3306 and see what nmap guesses then.
- Put a TLS tunnel in front (`stunnel` or `socat OPENSSL-LISTEN`) and repeat
  Part 3. What can Wireshark still see?
- Run the `admin` client from a second UTM VM and sniff it from the Mac on
  `bridge100`.

## Troubleshooting

| Symptom | Fix |
| --- | --- |
| nmap says the host is down | Use `-Pn`, check the subnet, make sure the VM is running. |
| Port shows `filtered` | The VM firewall is blocking it: `sudo ufw allow 13306/tcp`. |
| `Connection refused` | `./run.sh` isn't running, or the port differs (check `config.env`). |
| Wireshark sees nothing | Wrong interface. Try `bridge100` (Shared) or `en0` (Bridged), and allow Wireshark capture permission (ChmodBPF) on macOS. |
| `No user/password configured` | Run `./setup.sh` first. |

No packages to install on the VM: Python 3.8+ only.

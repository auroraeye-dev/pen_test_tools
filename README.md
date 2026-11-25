# pen_test_tools: find the port, sniff the key, win the picture

A small home CTF lab. Your UTM virtual machine runs **MockDBX**, a deliberately
insecure stand-in for a [DBX](https://github.com/vanshjain-0702/DBX-Database-Extreme)
database node, on **port 1143**. From your Mac you find it with **nmap**,
capture a login with **Wireshark**, read the tenant secret straight out of the
packets, and use it to open the **vault**, which holds your winning picture and
a flag.

> **For your own lab only.** Run this on a VM you own, on your own network, and
> scan and sniff only your own machines. The service is deliberately insecure.
> Never expose it to the internet.

```
 Mac (attacker + "owner")                      UTM VM (target)
 ┌───────────────────────────┐   TCP 1143     ┌──────────────────────────────┐
 │ nmap -> finds the port    │ ─────────────▶ │ MockDBX 1.3.0-lab (RESP2)    │
 │ client.py admin  (owner)  │   cleartext    │  catalog: 5 dbs / 29 tables  │
 │ Wireshark -> reads AUTH   │ ◀────────────▶ │  vault: secret/ folder       │
 │ client.py fetch -> loot/  │                └──────────────────────────────┘
 └───────────────────────────┘
```

## About DBX and this mock

DBX is a per-tenant memory engine. Each customer (tenant) gets an isolated
store with key-value working state and a vector index. Apps talk to it over
RESP2, the Redis wire protocol, and the first command must be
`AUTH <tenantID>:<keyID> <secret>`.

MockDBX copies that **infrastructure**, not the code: the same protocol (so
`redis-cli` works), the same login format, string KV and a tiny vector index,
and a catalog of DBX's control plane and tenant layout in `schema/*.sql`. No
DBX source is included (DBX is under BSL 1.1), and nothing real is stored:
whatever you `SET` lives in memory and is gone when the service restarts.

### The intentional vulnerabilities

1. **No TLS.** The `AUTH` command, secret included, crosses the network in
   plain text. Real DBX deployments put TLS in front (`Caddy` in its deploy
   folder).
2. **INFO before login.** `INFO` answers anyone and leaks the product, version
   and port.
3. **No lockout or rate limit.** Wrong secrets are only logged.
4. **One key opens everything.** Any valid tenant key can read the whole vault.
   Real DBX keys are scoped by role and key pattern.

## What's in here

| Path | What it is |
| --- | --- |
| `mockdbx/server.py` | The service. Pure Python stdlib, any CPU (ARM64 under UTM is fine). |
| `mockdbx/client.py` | RESP client with three modes: `shell` (interactive), `admin` (pretends to be you logging in every few seconds, so there's traffic to sniff), `fetch` (logs in and downloads the vault). |
| `mockdbx/schema.py` | Reads the `.sql` files. It ignores `INSERT`s and anything else, so a real schema dump drops straight in. |
| `schema/10_dbx_control_plane.sql` | `dbx_control`: tenants, members, scoped tenant keys, operators, backups, forget receipts, usage, audit. |
| `schema/20_dbx_tenant_store.sql` | `dbx_tenant_acme`: KV entries, vector indexes, named spaces, vectors, migrations, WAL segments, checkpoints. |
| `schema/30_example_tenant_app.sql` | `app_db`, `shop_db`, `hr_db`: the apps that use the tenant. |
| `secret/` | The vault. `winning_picture.png` is a placeholder, so swap in your own. `setup.sh` adds `flag.txt`. Every file here shows up as a `vault:<name>` key. |
| `setup.sh` | Run once on the VM: create the tenant key (tenant, key ID, secret), generate the flag, open the firewall port. |
| `run.sh` | Starts the service and prints the VM's IP. |
| `extras/mockdbx.service` | Optional systemd unit, to start it at boot. |

## Part 1: set up the VM (target)

Any Linux VM in UTM works. Ubuntu or Debian ARM64 on Apple Silicon is typical.

**UTM network mode.** In UTM, open the VM settings → Network and pick one of these:
- **Shared Network** (the default): the Mac reaches the VM through a virtual interface, usually `bridge100`, and the VM gets an IP like `192.168.64.x`.
- **Bridged**: the VM gets an IP on your home Wi-Fi, like any other device.

On the VM:

```bash
sudo apt update && sudo apt install -y git python3
git clone https://github.com/auroraeye-dev/pen_test_tools.git
cd pen_test_tools
./setup.sh      # tenant [acme], key ID [k_admin], and a secret with no spaces
./run.sh        # prints the VM IP, then listens on 0.0.0.0:1143
```

(If the repo is private, clone it with `gh repo clone auroraeye-dev/pen_test_tools`
after `gh auth login`, or use a personal access token.)

Your login is now `AUTH acme:k_admin <secret>`. To use your own photo, replace
`secret/winning_picture.png`. To use a different port, run
`DBX_LAB_PORT=6380 ./setup.sh` or edit `config.env`.

Find the VM's IP at any time with `hostname -I`. Write it down, but in Part 2
pretend you don't know it.

### Use your own database structure

Every `*.sql` file in `schema/` loads in name order when the service starts.
Add yours as, say, `schema/40_mine.sql`, or delete the others. Output from
`mysqldump --no-data` or `pg_dump --schema-only` works as is. Restart `./run.sh`
after a change. The first log lines show how many databases and tables loaded.

## Part 2: discover the VM with nmap (on the Mac)

```bash
brew install nmap
```

**Find your subnet.**
- Shared Network: run `ifconfig bridge100 | grep inet`. If it shows `192.168.64.1`, the subnet is `192.168.64.0/24`.
- Bridged: run `ipconfig getifaddr en0`. If it shows `192.168.1.23`, the subnet is `192.168.1.0/24`.

**1. Host discovery: who's alive?**

```bash
sudo nmap -sn 192.168.64.0/24
```

**2. Port scan the VM: what's open?** Port 1143 is outside nmap's default top
1000 ports, so scan all of them:

```bash
sudo nmap -p- --min-rate 2000 192.168.64.5
# 1143/tcp open  imyx
```

`imyx` is only the name nmap's port list gives 1143. It tells you nothing about
what's actually running.

**3. Service detection: what is it really?**

```bash
sudo nmap -sV --version-all -p 1143 192.168.64.5
# 1143/tcp open  redis   Redis key-value store 7.2.0
```

`--version-all` makes nmap try its Redis probe on a port that isn't 6379, and
the service answers. This takes about 5 minutes. A plain `-sV` is faster (about
2.5 minutes) but only gets as far as `imyx?`.

**4. Grab the banner by hand.** Redis-style services answer `INFO`:

```bash
printf 'INFO\r\n' | nc 192.168.64.5 1143
# redis_version:7.2.0
# dbx_version:1.3.0-lab
# tls:disabled
# auth:AUTH <tenantID>:<keyID> <secret>
```

So it's DBX pretending to be Redis, with **TLS disabled**, and it even tells you
the login format. Try `printf 'KEYS *\r\n' | nc 192.168.64.5 1143` and you'll
get `NOAUTH`. You need a tenant key.

## Part 3: sniff the tenant secret with Wireshark (on the Mac)

```bash
brew install --cask wireshark
```

1. Open Wireshark and capture on the interface that reaches the VM:
   **`bridge100`** for Shared Network, or **`en0`** (Wi-Fi) for Bridged.
   Set the capture filter to `tcp port 1143`.
2. Make some login traffic, playing yourself (the VM owner). In a second Mac
   terminal:

   ```bash
   python3 mockdbx/client.py admin --host 192.168.64.5 --key acme:k_admin --secret 'YOUR_SECRET' --every 15
   ```

   (This is the step where you enter the password. In a real attack, it would
   be someone else's app logging in on the same network.)
3. Apply this display filter:

   ```
   tcp.port == 1143 && frame contains "AUTH"
   ```

4. Right-click a packet and choose **Follow → TCP Stream**. The RESP framing is
   plain text:

   ```
   *3
   $4
   AUTH
   $12
   acme:k_admin
   $8
   YOUR_SECRET
   +OK
   ```

   The `$12` and `$8` lines are just the lengths of the next line. You now have
   the tenant, the key ID and the secret. Stop the `admin` script with Ctrl+C.

Terminal alternative (`tshark` comes with Wireshark):

```bash
sudo tshark -i bridge100 -f "tcp port 1143" -Y 'frame contains "AUTH"' -T fields -e tcp.payload | xxd -r -p
```

**Why the login runs from the Mac:** on a switched or Wi-Fi network, your Mac
only sees traffic to and from itself, plus the VM bridge it hosts. On UTM Shared
Network, a second VM logging in to the target also shows up on `bridge100`.
That makes a good upgrade.

## Part 4: open the vault

With the client:

```bash
python3 mockdbx/client.py shell --host 192.168.64.5
> AUTH acme:k_admin YOUR_SNIFFED_SECRET
> KEYS vault:*
1) "vault:flag.txt"
2) "vault:winning_picture.png"
> GET vault:flag.txt
FLAG{...}
```

Or with `redis-cli` (`brew install redis`):

```bash
redis-cli -h 192.168.64.5 -p 1143 --user acme:k_admin --pass 'YOUR_SNIFFED_SECRET' KEYS 'vault:*'
```

Download everything:

```bash
python3 mockdbx/client.py fetch --host 192.168.64.5 --key acme:k_admin --secret 'YOUR_SNIFFED_SECRET'
open loot/winning_picture.png
cat loot/flag.txt
```

🏆 Done. Look at the server window on the VM: it logged every connection,
failed `AUTH` and vault read. That's what a defender would see.

### Explore the database you broke into

```
SHOW DATABASES
USE dbx_control
SHOW TABLES
DESCRIBE tenant_keys
SHOW CREATE TABLE tenant_keys
USE dbx_tenant_acme
DESCRIBE vectors
SET note "i was here" EX 60
VADD memories doc:1 0.1 0.2 0.9
VSEARCH memories 0.1 0.2 0.8 5
```

## Extra challenges

- Try a few wrong secrets, then count the `failed AUTH` lines in the server log.
  What would a lockout change?
- Move the service to 6379 and run a plain `nmap -sV`. How fast does it say
  Redis now? Then try `nmap --script redis-info`.
- Put TLS in front (`stunnel`, or `socat OPENSSL-LISTEN:1143`) and repeat Part 3.
  What can Wireshark still see?
- Run the `admin` client from a second UTM VM and sniff it from the Mac on
  `bridge100`.

## Troubleshooting

| Symptom | Fix |
| --- | --- |
| nmap says the host is down | Add `-Pn`, check the subnet, and make sure the VM is running. |
| The port shows `filtered` | The VM firewall is blocking it. Run `sudo ufw allow 1143/tcp`. |
| `Connection refused` | `./run.sh` isn't running, or the port is different (check `config.env`). |
| Wireshark sees nothing | Wrong interface. Try `bridge100` (Shared) or `en0` (Bridged). On macOS, also allow Wireshark's capture permission (ChmodBPF). |
| `No tenant key configured` | Run `./setup.sh` first. |
| `NOAUTH` | Run `AUTH <tenant>:<keyID> <secret>` first. |

Nothing to install on the VM: it needs Python 3.8+ only. The DBX name and
design belong to its authors. This lab only imitates its public interface for
practice.

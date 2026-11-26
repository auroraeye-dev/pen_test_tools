#!/usr/bin/env bash
# One-time setup on the UTM VM: create the tenant key, make a flag, open the port.
set -euo pipefail
cd "$(dirname "$0")"

command -v python3 >/dev/null || { echo "python3 is required (sudo apt install python3)"; exit 1; }

PORT="${DBX_LAB_PORT:-1143}"
read -rp "Tenant ID [acme]: " TENANT;  TENANT="${TENANT:-acme}"
read -rp "Key ID [k_admin]: " KEY_ID;  KEY_ID="${KEY_ID:-k_admin}"
while true; do
  read -rsp "Tenant key secret (no spaces; this is what you will sniff later): " PW; echo
  read -rsp "Repeat secret: " PW2; echo
  [[ -n "$PW" && "$PW" == "$PW2" && "$PW" != *" "* ]] && break
  echo "Secrets empty, different, or contain spaces. Try again."
done

umask 077
cat > config.env <<CFG
# Written by setup.sh. Not committed to git (see .gitignore).
DBX_LAB_TENANT=$TENANT
DBX_LAB_KEY_ID=$KEY_ID
DBX_LAB_SECRET=$PW
DBX_LAB_PORT=$PORT
CFG
echo "Wrote config.env  (login will be: AUTH $TENANT:$KEY_ID <secret>)"

mkdir -p secret
FLAG="FLAG{$(python3 -c 'import secrets;print(secrets.token_hex(8))')}"
echo "$FLAG" > secret/flag.txt
echo "Wrote secret/flag.txt"

# Open the port in a host firewall if one is active.
if command -v ufw >/dev/null && sudo -n true 2>/dev/null && sudo ufw status | grep -q "Status: active"; then
  sudo ufw allow "$PORT"/tcp && echo "ufw: opened $PORT/tcp"
elif command -v firewall-cmd >/dev/null && sudo -n true 2>/dev/null && sudo firewall-cmd --state >/dev/null 2>&1; then
  sudo firewall-cmd --add-port="$PORT"/tcp && echo "firewalld: opened $PORT/tcp"
else
  echo "No active firewall detected (or no passwordless sudo). If you have one, open TCP $PORT yourself."
fi

echo
echo "Setup done. Start the service with:  ./run.sh"

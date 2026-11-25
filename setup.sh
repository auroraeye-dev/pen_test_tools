#!/usr/bin/env bash
# One-time setup on the UTM VM: choose the login, make a flag, open the port.
set -euo pipefail
cd "$(dirname "$0")"

command -v python3 >/dev/null || { echo "python3 is required (sudo apt install python3)"; exit 1; }

PORT="${MOCKSQL_PORT:-13306}"
read -rp "Lab username [admin]: " USER_NAME
USER_NAME="${USER_NAME:-admin}"
while true; do
  read -rsp "Lab password (no spaces; this is what you will sniff later): " PW; echo
  read -rsp "Repeat password: " PW2; echo
  [[ -n "$PW" && "$PW" == "$PW2" && "$PW" != *" "* ]] && break
  echo "Passwords empty, different, or contain spaces. Try again."
done

umask 077
cat > config.env <<CFG
# Written by setup.sh. Not committed to git (see .gitignore).
MOCKSQL_USER=$USER_NAME
MOCKSQL_PASSWORD=$PW
MOCKSQL_PORT=$PORT
CFG
echo "Wrote config.env"

mkdir -p secret
FLAG="FLAG{$(python3 -c 'import secrets;print(secrets.token_hex(8))')}"
echo "$FLAG" > secret/flag.txt
echo "Wrote secret/flag.txt (your flag is hidden in there)"

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

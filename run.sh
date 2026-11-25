#!/usr/bin/env bash
# Start the MockDBX lab service in the foreground (Ctrl+C to stop).
set -euo pipefail
cd "$(dirname "$0")"
[[ -f config.env ]] || { echo "Run ./setup.sh first."; exit 1; }
echo "VM IP address(es): $(hostname -I 2>/dev/null || ip -4 addr | awk '/inet /{print $2}')"
exec python3 mockdbx/server.py "$@"

#!/bin/bash
# Re-captures one scenario from the synthetic lab on loopback (needs sudo for tcpdump).
#   bash capture.sh [attack|edge|rawbyte]
# Output goes to ./recapture/ (not committed). To verify a fresh capture:
#   PCAP_DIR=./recapture bash verify.sh
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
LAB_NAME="hydro"
PORT="${PORT:-8600}"
LAB="$HERE/../../../hydrostrike_lab.py"
SCENARIO="${1:-attack}"
OUT="$HERE/recapture"
PCAP="$OUT/${LAB_NAME}_${SCENARIO}.pcap"
IFACE="${IFACE:-$([ "$(uname)" = Darwin ] && echo lo0 || echo lo)}"

if nc -z 127.0.0.1 "$PORT" 2>/dev/null; then
  echo "port $PORT is busy (stale lab server?) - stop it first"; exit 1
fi
mkdir -p "$OUT"
rm -f "$PCAP" "$OUT/${LAB_NAME}_${SCENARIO}_audit.jsonl"
sudo -v || exit 1

sudo tcpdump -i "$IFACE" -U -w "$PCAP" "tcp port $PORT" 2> "$OUT/tcpdump.log" &
sleep 2
python3 "$LAB" serve --port "$PORT" --audit "$OUT/${LAB_NAME}_${SCENARIO}_audit.jsonl" > "$OUT/serve.log" 2>&1 &
SRV=$!
sleep 2

case "$SCENARIO" in
  attack)
    python3 "$LAB" attack --variant h1 --port "$PORT"
    python3 "$LAB" attack --variant h2 --port "$PORT" ;;
  edge)    python3 "$HERE/edge_client.py" hydro "$PORT" ;;
  rawbyte) python3 "$HERE/rawbyte_client.py" hydro "$PORT" ;;
  *) echo "unknown scenario: $SCENARIO"; ;;
esac
sleep 2

# SIGTERM, not SIGINT: background jobs of a non-interactive shell ignore SIGINT.
kill -TERM "$SRV" 2>/dev/null; wait "$SRV" 2>/dev/null
sudo pkill -INT -f "${LAB_NAME}_${SCENARIO}.pcap"
sleep 1
sudo chown "$(id -un)" "$PCAP"
ls -l "$PCAP"

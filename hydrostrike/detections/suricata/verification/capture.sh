#!/bin/bash
# Re-captures one scenario from the synthetic lab on loopback (needs sudo for tcpdump).
#   bash capture.sh [attack|edge|rawbyte|reqline|matrix]
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
  reqline) python3 "$HERE/reqline_client.py" hydro "$PORT" ;;
  matrix)  python3 "$HERE/reqline_client.py" hydro "$PORT" matrix --cases "$OUT/${LAB_NAME}_matrix.cases.jsonl" ;;
  *) echo "unknown scenario: $SCENARIO"; ;;
esac
sleep 2

# SIGTERM, not SIGINT: background jobs of a non-interactive shell ignore SIGINT.
kill -TERM "$SRV" 2>/dev/null; wait "$SRV" 2>/dev/null
sudo pkill -INT -f "${LAB_NAME}_${SCENARIO}.pcap"
sleep 1
sudo chown "$(id -un)" "$PCAP"
ls -l "$PCAP"

# Manifest: pins the traffic generators (lab and client) of this capture, not the rules.
# verify.sh refuses to replay a capture whose generators no longer match.
sha() { if command -v sha256sum >/dev/null; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi; }
case "$SCENARIO" in
  evasion) CLIENT="evasion_client.py" ;;
  edge)    CLIENT="edge_client.py" ;;
  rawbyte) CLIENT="rawbyte_client.py" ;;
  reqline|matrix) CLIENT="reqline_client.py" ;;
  *)       CLIENT="" ;;
esac
MANIFEST="$OUT/${LAB_NAME}_${SCENARIO}.manifest.txt"
{
  echo "scenario=$SCENARIO"
  echo "captured_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "git_rev=$(git -C "$HERE" rev-parse HEAD 2>/dev/null)"
  echo "git_worktree=$(git -C "$HERE" status --porcelain 2>/dev/null | grep -qv '^??' && echo modified || echo clean)"
  echo "lab_file=hydrostrike_lab.py"
  echo "lab_sha256=$(sha "$LAB")"
  echo "client_file=$CLIENT"
  [ -n "$CLIENT" ] && echo "client_sha256=$(sha "$HERE/$CLIENT")"
  echo "python=$(python3 -V 2>&1)"
  echo "suricata=$(suricata -V 2>&1 | head -1)"
  echo "os=$(uname -sm)"
  echo "pcap_sha256=$(sha "$PCAP")"
  [ -f "$OUT/${LAB_NAME}_${SCENARIO}.cases.jsonl" ] && echo "cases_sha256=$(sha "$OUT/${LAB_NAME}_${SCENARIO}.cases.jsonl")"
} > "$MANIFEST"
echo "manifest: $MANIFEST"

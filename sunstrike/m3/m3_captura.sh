#!/bin/sh
set -eu
IFACE="${1:-lo}"
CEN="${2:?uso: sh m3_captura.sh <iface lo|lo0> <cenario>}"
PCAP="${CEN}.pcap"
tcpdump -i "$IFACE" -w "${PCAP}.part" 'host 127.0.0.1 and (port 8609 or port 8610 or portrange 8611-8622)' &
TPID=$!
sleep 1
python3 -I m3_cenarios.py "$CEN"
sleep 1
kill -INT "$TPID"
wait "$TPID" || true
mv "${PCAP}.part" "$PCAP"
if command -v sha256sum >/dev/null 2>&1; then sha256sum "$PCAP"; else shasum -a 256 "$PCAP"; fi

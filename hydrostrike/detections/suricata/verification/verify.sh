#!/bin/bash
# Replays the committed pcaps through Suricata with the rules in this lab and
# compares per-sid alert counts with the expected values.
#
#   bash verify.sh              # all scenarios; exit 1 on any mismatch
#   bash verify.sh --mutation   # rule-liveness: drop each rule in turn and
#                               # confirm its alerts disappear
#
# Env: SURICATA_YAML (path to suricata.yaml), PCAP_DIR (default: ./pcaps),
#      RULES (default: the rule file one directory up),
#      KEEP=1 (keep the Suricata logs of each scenario),
#      WORK_DIR (write those logs to this directory and keep them).
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
RULE_FILE="hydrobox.rules"
GROUP="WATER_CONTROLLERS"
RULE_COUNT=6
ATTACK_PCAP="hydro_attack.pcap"
ATTACK_TOTAL=17
ATTACK_EXPECT="2026110701=4 2026110702=8 2026110703=2 2026110704=2 2026110705=1"
scenarios() {
  check attack_positive hydro_attack.pcap "$ATTACKER_OUTSIDE" 17 "$ATTACK_EXPECT"
  check attack_negative hydro_attack.pcap "$ATTACKER_INSIDE"   0 "2026110701=0 2026110702=0 2026110703=0 2026110704=0 2026110705=0"
  check rejected_uri_suffixes hydro_edge.pcap "$ATTACKER_OUTSIDE" 1 "2026110701=1 2026110702=0 2026110703=0 2026110704=0 2026110705=0"
  # Expectation written before the first run (2026-11-11): every request the controller
  # routes must alert. 10 setpoint (control + 9 trailing bytes), 3 backwash (control + 2).
  [ -f "$PCAP_DIR/hydro_rawbyte.pcap" ] && check trailing_byte hydro_rawbyte.pcap "$ATTACKER_OUTSIDE" 13 "2026110701=10 2026110702=3 2026110703=0 2026110704=0 2026110705=0"
  # Expectation written before the first run (2026-11-11): every request the lab routes must
  # alert, by its endpoint sid or, when a byte replaces the space after the method, by the
  # non-compliant-request-line sid. Requests the lab rejects must stay silent, except these
  # accepted over-alerts of the setpoint sid: n01 (no version, 400), u01 (0x01 before the path, 404) and u02 (absolute URI, 400).
  [ -f "$PCAP_DIR/hydro_reqline.pcap" ] && check request_line hydro_reqline.pcap "$ATTACKER_OUTSIDE" 42 "2026110701=24 2026110702=3 2026110703=3 2026110704=3 2026110705=3 2026110706=6"
  # Matrix battery (2026-11-11): no per-sid expectation. The invariant in check_requests.py is the
  # expectation, fixed before the run: routed -> at least one alert; rejected -> silent, except
  # the labels listed in overalerts_hydro.txt, which must alert. Negative case: 0 alerts.
  [ -f "$PCAP_DIR/hydro_matrix.pcap" ] && check_cases matrix_per_request hydro_matrix.pcap "$ATTACKER_OUTSIDE"
  [ -f "$PCAP_DIR/hydro_matrix.pcap" ] && check_total matrix_negative hydro_matrix.pcap "$ATTACKER_INSIDE" 0
}
RULES="${RULES:-$HERE/../$RULE_FILE}"
PCAP_DIR="${PCAP_DIR:-$HERE/pcaps}"
ATTACKER_OUTSIDE="10.99.0.0/24"   # MAINT_NET that does NOT contain 127.0.0.1
ATTACKER_INSIDE="127.0.0.1"       # MAINT_NET that DOES contain 127.0.0.1

YAML="${SURICATA_YAML:-}"
if [ -z "$YAML" ]; then
  for c in /opt/homebrew/etc/suricata/suricata.yaml /usr/local/etc/suricata/suricata.yaml /etc/suricata/suricata.yaml; do
    [ -f "$c" ] && YAML="$c" && break
  done
fi
[ -f "$YAML" ] || { echo "suricata.yaml not found; set SURICATA_YAML"; exit 2; }
command -v suricata >/dev/null || { echo "suricata not installed"; exit 2; }

WORK="${WORK_DIR:-$(mktemp -d)}"; mkdir -p "$WORK"
FAIL=0

run() {  # name pcap maint_net rules
  rm -rf "$WORK/$1"   # a reused WORK_DIR must not append to an older fast.log
  mkdir -p "$WORK/$1"
  suricata -r "$PCAP_DIR/$2" -c "$YAML" -S "$4" \
    --set vars.address-groups.MAINT_NET="$3" \
    --set vars.address-groups."$GROUP"="127.0.0.1" \
    -k none -l "$WORK/$1" > "$WORK/$1/stdout.txt" 2>&1
}

count() {  # name sid
  grep -c "\[1:$2:" "$WORK/$1/fast.log" 2>/dev/null || true
}

total() {  # name
  wc -l < "$WORK/$1/fast.log" | tr -d ' '
}

check() {  # name pcap maint_net expected_total "sid=n sid=n ..."
  if ! manifest_ok "$2"; then echo "FAIL  $1  $MANIFEST_NOTE - recapture before replaying"; FAIL=1; return; fi
  run "$1" "$2" "$3" "$RULES"
  local ok=1 loaded
  loaded="$(grep -o '[0-9]* rules successfully loaded, [0-9]* rules failed' "$WORK/$1/suricata.log")"
  [ "$loaded" = "$RULE_COUNT rules successfully loaded, 0 rules failed" ] || ok=0
  [ "$(total "$1")" = "$4" ] || ok=0
  local detail=""
  for pair in $5; do
    local sid="${pair%%=*}" want="${pair##*=}" got
    got="$(count "$1" "$sid")"
    detail="$detail $sid:$got/$want"
    [ "$got" = "$want" ] || ok=0
  done
  if [ "$ok" = 1 ]; then
    echo "PASS  $1  total $(total "$1")/$4 |$detail"
  else
    echo "FAIL  $1  total $(total "$1")/$4 |$detail | $loaded"
    FAIL=1
  fi
}

sha() { if command -v sha256sum >/dev/null; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi; }

manifest_ok() {  # pcap -> 0 if there is no manifest or the generators still match it
  local m="$PCAP_DIR/${1%.pcap}.manifest.txt" want got client
  [ -f "$m" ] || { MANIFEST_NOTE="no manifest"; return 0; }
  want="$(sed -n 's/^lab_sha256=//p' "$m")"; got="$(sha "$HERE/../../../hydrostrike_lab.py")"
  [ "$want" = "$got" ] || { MANIFEST_NOTE="lab file differs from manifest"; return 1; }
  client="$(sed -n 's/^client_file=//p' "$m")"
  if [ -n "$client" ]; then
    want="$(sed -n 's/^client_sha256=//p' "$m")"; got="$(sha "$HERE/$client")"
    [ "$want" = "$got" ] || { MANIFEST_NOTE="$client differs from manifest"; return 1; }
  fi
  want="$(sed -n 's/^pcap_sha256=//p' "$m")"; got="$(sha "$PCAP_DIR/$1")"
  [ "$want" = "$got" ] || { MANIFEST_NOTE="pcap differs from manifest"; return 1; }
  if [ -f "$PCAP_DIR/${1%.pcap}.cases.jsonl" ]; then
    want="$(sed -n 's/^cases_sha256=//p' "$m")"; got="$(sha "$PCAP_DIR/${1%.pcap}.cases.jsonl")"
    [ "$want" = "$got" ] || { MANIFEST_NOTE="cases file differs from manifest"; return 1; }
  fi
  MANIFEST_NOTE="manifest ok"; return 0
}

check_cases() {  # name pcap maint_net : per-request invariant, joined by client port
  if ! manifest_ok "$2"; then echo "FAIL  $1  $MANIFEST_NOTE - recapture before replaying"; FAIL=1; return; fi
  run "$1" "$2" "$3" "$RULES"
  local loaded
  loaded="$(grep -o '[0-9]* rules successfully loaded, [0-9]* rules failed' "$WORK/$1/suricata.log")"
  if [ "$loaded" != "$RULE_COUNT rules successfully loaded, 0 rules failed" ]; then
    echo "FAIL  $1  $loaded"; FAIL=1; return
  fi
  if python3 "$HERE/check_requests.py" "$WORK/$1/eve.json" "$PCAP_DIR/${2%.pcap}.cases.jsonl" \
       "$HERE/overalerts_hydro.txt" --out "$WORK/$1/per_request.tsv" > "$WORK/$1/check.txt"; then
    echo "PASS  $1  [$MANIFEST_NOTE]"; cat "$WORK/$1/check.txt"
  else
    echo "FAIL  $1  [$MANIFEST_NOTE]"; cat "$WORK/$1/check.txt"; FAIL=1
  fi
}

check_total() {  # name pcap maint_net expected_total
  if ! manifest_ok "$2"; then echo "FAIL  $1  $MANIFEST_NOTE - recapture before replaying"; FAIL=1; return; fi
  run "$1" "$2" "$3" "$RULES"
  if [ "$(total "$1")" = "$4" ]; then echo "PASS  $1  total $(total "$1")/$4"; else echo "FAIL  $1  total $(total "$1")/$4"; FAIL=1; fi
}

mutation() {  # for each sid: remove its rule, replay the attack pcap, expect 0 alerts for it
  for pair in $ATTACK_EXPECT; do
    local sid="${pair%%=*}" want="${pair##*=}" name="mut_${pair%%=*}" got
    grep -v "sid:$sid;" "$RULES" > "$WORK/mut_$sid.rules"
    run "$name" "$ATTACK_PCAP" "$ATTACKER_OUTSIDE" "$WORK/mut_$sid.rules"
    got="$(count "$name" "$sid")"
    if [ "$got" = 0 ] && [ "$(total "$name")" = "$((ATTACK_TOTAL - want))" ]; then
      echo "PASS  rule $sid removed -> its $want alerts disappear (total $(total "$name")/$ATTACK_TOTAL): a check on this pcap would catch the loss"
    else
      echo "FAIL  rule $sid removed but count is $got, total $(total "$name")"
      FAIL=1
    fi
  done
}

echo "Suricata: $(suricata -V 2>&1 | head -1)"
echo "Rules:    $RULES"
echo "Rules sha256: $(sha "$RULES")"
if [ "${1:-}" = "--mutation" ]; then
  mutation
else
  scenarios
fi
if [ -n "${KEEP:-}${WORK_DIR:-}" ]; then echo "Suricata logs kept in $WORK"; else rm -rf "$WORK"; fi
[ "$FAIL" = 0 ] && echo "RESULT: PASS" || echo "RESULT: FAIL"
exit "$FAIL"

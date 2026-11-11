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
RULE_FILE="frostbox.rules"
GROUP="REFRIG_SUPERVISORS"
RULE_COUNT=5
ATTACK_PCAP="frost_attack.pcap"
ATTACK_TOTAL=37
ATTACK_EXPECT="2026110101=12 2026110102=12 2026110103=12 2026110104=1"
scenarios() {
  check attack_positive frost_attack.pcap  "$ATTACKER_OUTSIDE" 37 "$ATTACK_EXPECT"
  check attack_negative frost_attack.pcap  "$ATTACKER_INSIDE"   0 "2026110101=0 2026110102=0 2026110103=0 2026110104=0"
  check uri_suffix_evasion frost_evasion.pcap "$ATTACKER_OUTSIDE" 7 "2026110101=3 2026110102=3 2026110103=1 2026110104=0"
  check fragment_and_near_miss frost_edge.pcap "$ATTACKER_OUTSIDE" 3 "2026110101=2 2026110102=1 2026110103=0 2026110104=0"
  # Expectation written before the first run (2026-11-11): every request the controller
  # executes must alert. 10 setpoint (control + 9 trailing bytes), 3 defrost (control + 2).
  [ -f "$PCAP_DIR/frost_rawbyte.pcap" ] && check trailing_byte frost_rawbyte.pcap "$ATTACKER_OUTSIDE" 13 "2026110101=10 2026110102=3 2026110103=0 2026110104=0"
  # Expectation written before the first run (2026-11-11): every request the lab routes must
  # alert, by its endpoint sid or, when a byte replaces the space after the method, by the
  # non-compliant-request-line sid. Requests the lab rejects must stay silent, except these
  # accepted over-alerts of the setpoint sid: n01 (no version, 400) and u03 (no leading slash, 404); and alarm-u03 (404) on the unanchored /alarm sid.
  [ -f "$PCAP_DIR/frost_reqline.pcap" ] && check request_line frost_reqline.pcap "$ATTACKER_OUTSIDE" 41 "2026110101=24 2026110102=3 2026110103=5 2026110104=4 2026110105=5"
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
if [ "${1:-}" = "--mutation" ]; then
  mutation
else
  scenarios
fi
if [ -n "${KEEP:-}${WORK_DIR:-}" ]; then echo "Suricata logs kept in $WORK"; else rm -rf "$WORK"; fi
[ "$FAIL" = 0 ] && echo "RESULT: PASS" || echo "RESULT: FAIL"
exit "$FAIL"

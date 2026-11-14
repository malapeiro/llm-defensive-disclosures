#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SUNSTRIKE M3 — m3_cenarios.py — gerador de cenários para deteção externa
(Suricata + Sigma). Supervisor: 14-11-2026.

Um cenário POR INVOCAÇÃO:  python3 -I m3_cenarios.py <cenario>
Cenários: NEG H1 H2 H3 H4 H5 NONCANON MASS SLOW EMERG
(NEG..H5 = mínimos do GO M3; NONCANON/MASS/SLOW = mínimos do GO M3;
 EMERG = extra documentada para exercitar D-GRID-EMERGENCY-REMOTE-BLOCK,
 que nenhum cenário mínimo cobre — "mínimos" ≠ fechados.)

Lab alvo: v0.7.5 SELADA
  sha256 5162964f2df283fd6ed0a1a4d53f8b3650f491b4892e24abb198494b7abcb441
O lab é importado da MESMA pasta deste script (python3 -I não põe a pasta
do script no sys.path — é adicionada explicitamente). Se o lab não estiver
na mesma pasta, cai para ../v0.7.5/sunstrike_lab.py (layout do repo).
NADA no lab é alterado (código CONGELADO; precedente probes R10/R11: só
corre contra hashes conhecidos).

Cada cenário corre com Lab(evidence=True) → uma pasta de evidência própria
sunstrike_evidence/<run>/ com audit_dev_00..11.jsonl, audit_gate.jsonl,
grid_events.jsonl e audit_guard.jsonl (quando usado).

Este ficheiro NÃO corre regras M3 (Suricata/Sigma) — o run oficial é do
supervisor. No fim imprime os alertas do DETETOR INTERNO do lab para o
cenário (informativo, para comparação com as previsões).
"""

import base64
import hashlib
import json
import os
import socket
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

EXPECTED_LAB_SHA256 = ("cf9fbe3e1cb8d0e2cc5216e5ee8c3ca165d9358d"
                       "788ae2fb723320b091cb86f8")


def _load_lab():
    with open(os.path.join(HERE, "sunstrike_lab.py"), "rb") as f:
        b = f.read()
    if hashlib.sha256(b).hexdigest() == EXPECTED_LAB_SHA256:
        import sunstrike_lab as L
        return L, "mesma pasta (m3/)"
    alt = os.path.join(HERE, os.pardir, "v0.7.5", "sunstrike_lab.py")
    if os.path.exists(alt):
        with open(alt, "rb") as f:
            b2 = f.read()
        if hashlib.sha256(b2).hexdigest() == EXPECTED_LAB_SHA256:
            sys.path.insert(0, os.path.dirname(os.path.abspath(alt)))
            import sunstrike_lab as L
            return L, os.path.abspath(alt)
    print("ALVO REJEITADO: sunstrike_lab.py (aqui ou em ../v0.7.5/) nao "
          "tem o hash selado da v0.7.5 (%s...). Nada foi executado."
          % EXPECTED_LAB_SHA256[:16])
    raise SystemExit(2)


L, LAB_PATH = _load_lab()

LOOPBACK = L.LOOPBACK
PORT_GATE = L.PORT_GATE
PORT_GUARD = L.PORT_GUARD
PORT_DEV_BASE = L.PORT_DEV_BASE
N_DEVS = L.N_DEVS


def hj(port, method, path, body=None, token=None, timeout=8):
    return L.http_json(LOOPBACK, port, method, path, body=body,
                       token=token, timeout=timeout)


def raw_post(port, target, body, auth=None, cl=None, extra_headers=(),
             timeout=8):
    """Pedido cru por socket (precedente probes R10). extra_headers: lista
    de bytes adicionais (terminadas em CRLF). Devolve a status_line."""
    if isinstance(target, str):
        target = target.encode("latin-1")
    if isinstance(body, str):
        body = body.encode("utf-8")
    req = (b"POST " + target + b" HTTP/1.1\r\nHost: 127.0.0.1\r\n"
           b"Content-Type: application/json\r\n")
    if auth:
        req += b"Authorization: Bearer " + auth.encode() + b"\r\n"
    for h in extra_headers:
        req += h + b"\r\n"
    req += b"Content-Length: " + (str(len(body)) if cl is None
                                  else str(cl)).encode() + b"\r\n\r\n"
    req += body
    try:
        s = socket.create_connection((LOOPBACK, port), timeout=timeout)
        s.sendall(req)
        chunks = []
        try:
            while True:
                d = s.recv(65536)
                if not d:
                    break
                chunks.append(d)
                if b"\r\n\r\n" in b"".join(chunks):
                    break
        except OSError:
            pass
        s.close()
    except OSError:
        return ""
    raw = b"".join(chunks)
    if not raw:
        return ""
    return raw.split(b"\r\n", 1)[0].decode("latin-1", "replace")


def hygiene(lab):
    lab.gridsim.set_state("NORMAL")
    lab.gridsim.set_irradiance("DIA")
    time.sleep(0.5)


def reset_all(lab):
    for d in lab.devices:
        d.harness_reset()
    lab.gate.harness_reset()


def alerts_of(lab, scen):
    evs = [e for e in lab.ctx._memory if e.get("scenario") == scen]
    return lab.detector.scan(evs)


def gate_login_default():
    st, resp = hj(PORT_GATE, "POST", "/fleet/login",
                  {"user": L.DEFAULT_USER, "pass": L.DEFAULT_PASS})
    return st, resp


def gate_login_daily():
    st, resp = hj(PORT_GATE, "POST", "/fleet/login",
                  {"user": L.DAILY_USER, "pass": L.daily_code()})
    return st, resp


def svc_token(idx):
    return "SUNBOX-SVC-%02d-2026" % idx


def scen_neg(lab):
    adv = L.Adversary(LOOPBACK)
    r = adv.maintenance_neg()
    return r["steps"]


def scen_h1(lab):
    adv = L.Adversary(LOOPBACK)
    r = adv.attack_h1()
    return r["steps"]


def scen_h2(lab):
    adv = L.Adversary(LOOPBACK)
    r = adv.attack_h2()
    return r["steps"]


def scen_h3(lab):
    steps = []
    st, resp = gate_login_default()
    sid = resp["session"]
    steps.append(("default_login", st))
    for i in range(N_DEVS):
        st, _ = hj(PORT_GATE, "POST",
                   "/fleet/device/%d/export_limit" % i, {"value": 20.0},
                   token=sid)
        steps.append(("export_limit_%02d" % i, st))
    lab.gridsim.set_state("STRESS")
    time.sleep(1.0)
    st, _ = hj(PORT_DEV_BASE + 0, "POST", "/grid_profile",
               {"droop": 0.5}, token=svc_token(0))
    steps.append(("pf_param_stress", st))
    L.emit_capacity_snapshot(lab)
    lab.gridsim.set_state("NORMAL")
    time.sleep(0.5)
    return steps


def scen_h4(lab):
    steps = []
    lab.gridsim.set_state("STRESS")
    time.sleep(0.5)
    for i in range(N_DEVS):
        st, _ = hj(PORT_DEV_BASE + i, "POST", "/firmware", {
            "image_b64": base64.b64encode(L.LEGIT_IMAGE).decode(),
            "signature": L.sign_image(L.LEGIT_IMAGE)}, token=svc_token(i))
        steps.append(("fw_signed_stress_%02d" % i, st))
    lab.gridsim.set_state("NORMAL")
    time.sleep(0.3)
    for i in range(N_DEVS):
        st, _ = hj(PORT_DEV_BASE + i, "POST", "/firmware", {
            "image_b64": base64.b64encode(b"wiper").decode(),
            "signature": "forged"}, token=svc_token(i))
        steps.append(("fw_forged_normal_%02d" % i, st))
    return steps


def scen_h5(lab):
    steps = []
    st, resp = hj(PORT_DEV_BASE + 0, "POST", "/battery", {
        "action": "discharge",
        "amount_kwh": lab.devices[0].batt_kwh * 0.6}, token=svc_token(0))
    steps.append(("drain_60pct", st))
    st, resp = hj(PORT_DEV_BASE + 0, "POST", "/battery", {
        "action": "force_export", "amount_kwh": 999.0}, token=svc_token(0))
    steps.append(("force_export_999", st))
    return steps


def scen_noncanon(lab):
    steps = []
    st, resp = hj(PORT_GUARD, "POST", "/fleet/login",
                 {"user": L.DAILY_USER, "pass": L.daily_code()})
    steps.append(("guard_login_daily", st))
    st, _ = hj(PORT_GUARD, "GET", "/fleet/telemetry")
    steps.append(("guard_telemetry", st))
    for _ in range(5):
        st, _ = hj(PORT_GATE, "POST", "/fleet/login",
                   {"user": "x", "pass": "x"})
        steps.append(("gate_login_fail", st))
    for tgt in (b"//fleet/login", b"/fleet/telemetry?x=1", b"/fleet/%2Flogin",
                b"/fleet/./telemetry", b"/fleet/log\xffin"):
        line = raw_post(PORT_GATE, tgt, b"{}")
        steps.append(("gate_raw_noncanon", line))
    line = raw_post(PORT_GUARD, b"//fleet/login", b"{}")
    steps.append(("guard_raw_noncanon", line))
    line = raw_post(PORT_GUARD, b"/fleet/login", b"{}",
                    extra_headers=[b"Transfer-Encoding: chunked"])
    steps.append(("guard_transfer_encoding", line))
    line = raw_post(PORT_GUARD, b"/fleet/login", b'{"x": 1}', cl="20000")
    steps.append(("guard_body_too_large", line))
    st, _ = hj(PORT_GUARD, "POST", "/rota/desconhecida", {})
    steps.append(("guard_unknown_route", st))
    dev0 = PORT_DEV_BASE + 0
    for _ in range(6):
        st, _ = hj(dev0, "POST", "/local_confirm", {"pin": "0000"})
        steps.append(("local_confirm_fail", st))
    st, _ = hj(dev0, "POST", "/mode", {
        "action": "inverter_power_off", "work_order": "WO-FAKE-999"},
        token=svc_token(0))
    steps.append(("mode_fake_wo", st))
    st, _ = hj(dev0, "POST", "/setpoint", {"value": 150.0},
              token=svc_token(0))
    steps.append(("setpoint_out_of_band", st))
    return steps


def scen_mass(lab):
    steps = []
    st, resp = gate_login_daily()
    sid = resp["session"]
    steps.append(("daily_login", st))
    st, resp = hj(PORT_GATE, "POST", "/fleet/bulk_shutdown",
                  {"work_order_id": "WO-20261112-MNT1"}, token=sid)
    steps.append(("bulk_mnt1_fleet", st))
    return steps


def scen_slow(lab):
    steps = []
    st, resp = gate_login_daily()
    sid = resp["session"]
    steps.append(("daily_login", st))
    for i in range(8):
        if i:
            time.sleep(65.0)
        st, _ = hj(PORT_GATE, "POST",
                   "/fleet/device/%d/shutdown" % i, {}, token=sid)
        steps.append(("slow_shutdown_%02d" % i, st))
    return steps


def scen_emerg(lab):
    steps = []
    lab.gridsim.set_state("EMERGENCY")
    time.sleep(1.2)
    dev0 = PORT_DEV_BASE + 0
    tok = svc_token(0)
    for path_, body_ in (
            ("/mode", {"action": "inverter_power_off"}),
            ("/battery", {"action": "force_export", "amount_kwh": 999.0}),
            ("/setpoint", {"value": 0.0}),
            ("/firmware", {"image_b64": base64.b64encode(b"x").decode(),
                           "signature": "forged"}),
            ("/grid_profile", {"droop": 0.5})):
        st, _ = hj(dev0, "POST", path_, body_, token=tok)
        steps.append(("emerg_%s" % path_.strip("/"), st))
    lab.gridsim.set_state("NORMAL")
    time.sleep(0.5)
    return steps


SCENARIOS = {
    "NEG": scen_neg,
    "H1": scen_h1,
    "H2": scen_h2,
    "H3": scen_h3,
    "H4": scen_h4,
    "H5": scen_h5,
    "NONCANON": scen_noncanon,
    "MASS": scen_mass,
    "SLOW": scen_slow,
    "EMERG": scen_emerg,
}


def main():
    if len(sys.argv) != 2 or sys.argv[1].upper() not in SCENARIOS:
        print("uso: python3 -I m3_cenarios.py <cenario>")
        print("cenarios: %s" % " ".join(sorted(SCENARIOS)))
        return 2
    scen = sys.argv[1].upper()
    print("SUNSTRIKE M3 — cenario %s — lab %s" % (scen, LAB_PATH))
    lab = L.Lab(evidence=True)
    lab.start()
    time.sleep(0.5)
    try:
        hygiene(lab)
        lab.scenario(scen)
        reset_all(lab)
        steps = SCENARIOS[scen](lab)
        for d in lab.devices:
            d.harness_reset()
        print("passos: %d" % len(steps))
        alerts = alerts_of(lab, scen)
        print("evidencia: %s" % lab.ctx.evidence_dir)
        print("alertas do detetor INTERNO do lab (informativo):")
        if not alerts:
            print("  (nenhum)")
        for a in alerts:
            print("  [%s] %s x%d %s" % (a["scenario"], a["rule"], a["count"],
                                        ",".join(a["devices"][:4])))
        return 0
    finally:
        lab.stop()


if __name__ == "__main__":
    raise SystemExit(main())

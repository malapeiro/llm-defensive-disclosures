#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Hydrostrike v1.3.1 — Laboratório defensivo loopback de emulação adversária,
motor de deteção streaming e Guard Proxy de prevenção para uma Estação de
Tratamento/Bombagem de Água sintética (HYDROBOX), inspirado na campanha europeia
de sabotagem a interfaces HMI/SCADA de água (ABW/CERT Polska/ANSSI/ENISA).

100% Python Standard Library. Alvo estritamente loopback (127.0.0.1).
Protocolo: PVTE-X v1.1 — Operador autorizado: Sérgio Azevedo (root).

Changelog v1.3.1 (correção de regressão crítica, Probe 13A/13B):
  P13A: Regressão v1.1 reposta — o ramo dosing_setpoint foi acidentalmente
      removido de Detector.scan na v1.1 (sobrevivendo apenas como chave morta
      em RULE_ATTACK_MAP e no clamp do Guard); D-CHLORINE-OUT-OF-BAND voltou
      a disparar (CRIT) para dosagens fora da banda potável [0.2, 1.0] mg/L.
  P13B: Adicionado Invariante de Vivacidade de Regras — a demo alimenta
      eventos sintéticos a um Detector e falha se qualquer regra listada em
      RULE_ATTACK_MAP não disparar pelo menos uma vez (dead_rules == set()),
      impedindo futuras regressões silenciosas de regras.
      Nota: título da técnica ICS T0879 atualizado para "Damage to Property"
      em RULE_ATTACK_MAP.

Changelog v1.3 (auditoria adversária conjunta — Ronda 3 + adenda independente):
  P9/Adição D: Nova função única canonicalize_request(method, raw_path, headers,
      raw_body) partilhada entre Guard e Controlador — rejeita paths não
      canónicos (query strings, %2F, barras duplas, barra final) com HTTP 400,
      normaliza o token Authorization num único sítio e valida os tipos
      estritos do corpo (validate_api_body: bool estrito para "muted", float
      finito não-booleano para "value", "OPEN"/"CLOSED" para "state") —
      elimina a raiz estrutural comum a P5/P6/P9. O Guard decide e encaminha
      exclusivamente a forma canónica; o Controlador aceita exclusivamente a
      forma canónica.
  P10/Adição B: Os interlocks de frota (2/hora e 2/24h) e hidráulicos (pressão
      e reservatório) passaram para o próprio controlador
      (HydroboxState._backwash, atómicos sob self.lock, sem TOCTOU e sem
      segurar locks sobre sockets HTTP). O Guard deixou de fazer GET
      /api/status por retrolavagem. Rejeições atómicas: C-BACKWASH-FLEET-LIMIT,
      C-BACKWASH-DAILY-LIMIT e C-HYDRAULIC-INTERLOCK (HTTP 403), com evento
      backwash_rejected no audit. safety_interlocks=True por omissão;
      safety_interlocks=False emula controlador legado desprotegido
      (fases H1/H2 da demo, para demonstração de impacto e deteção).
  P11: Duplo horizonte anti-evasão lenta (Patient Attacker): teto de 2
      retrolavagens API/hora E 2/24h no controlador; D-BACKWASH-ABUSE dispara
      com >= 3 comandos API em 60 min OU em 24h; D-MULTI-FILTER-BACKWASH com
      >= 2 filtros distintos em 30 min OU >= 3 filtros distintos em 24h.
  P12A: As verificações CRIT de filter_backwash passaram a "if" independentes
      (fim da supressão por cadeia elif) — todas as regras aplicáveis disparam
      sem se mascararem mutuamente.
  P12B: st.pressure é recalculado apenas a partir das bombas efetivamente em
      marcha (running == True); escrever um setpoint numa bomba parada
      atualiza apenas o setpoint guardado, sem falsificar a pressão da linha.
  Adição A: Suporte a "running": bool em /api/pump/<id>/setpoint (parar/arrancar
      bomba com recálculo atómico da pressão); eventos pump_setpoint e
      valve_command registam running/any_pump_running; D-DEADHEAD-RISK dispara
      apenas com bomba efetivamente comandada a funcionar contra VLV-OUT
      fechada; isolamento legítimo (todas as bombas paradas, dentro da janela
      de manutenção) gera 0 CRIT/0 WARN; o caso negativo da demo inclui
      paragem de bomba -> fecho de válvula -> reabertura -> arranque.

Changelog v1.2 (auditoria adversária — Ronda 2, Probes 6/7A/7B/8):
  P6: Teto de retrolavagens GLOBAL por estação com janela deslizante.
  P7: Janelas deslizantes de 30/60 min no Detector (D-MULTI-FILTER-BACKWASH,
      D-BACKWASH-ABUSE).
  P8: D-UNDERPRESSURE-DROP (CRIT) e interlock hidráulico (agora atómico no
      controlador, vide v1.3/Adição B).

Changelog v1.1 (auditoria adversária externa — 5 probes, execution-verified):
  P1: Fim do falso positivo em retrolavagem manual única legítima.
  P2: D-DEADHEAD-RISK alargado; evento pump_setpoint inclui "valve"; Guard
      bloqueia fecho remoto de VLV-OUT (G-VALVE-CLOSE-BLOCKED).
  P3: Limite inferior físico do reservatório (max(0.0, ...)); teto de frota.
  P4: _as_float rejeita NaN/Infinity e booleanos (math.isfinite).
  P5: /api/alarm/mute exige bool estrito; Guard bloqueia salvo unmute explícito.
"""

import argparse
import datetime as _dt
import hashlib
import json
import math
import os
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

__version__ = "1.3.1"
LAB_NAME = "Hydrostrike"

PUMP_BAND = (2.5, 5.5)
CHLORINE_BAND = (0.2, 1.0)
RESERVOIR_BAND = (25.0, 95.0)
MAINT_WINDOW = (8 * 60, 18 * 60)
BACKWASH_WINDOW = (3 * 60, 4 * 60 + 30)
BACKWASH_RESERVOIR_COST = 12.0
BACKWASH_PRESSURE_DROP = 0.4
BACKWASH_DRAIN_ALERT_PCT = 40.0
GUARD_FLEET_LIMIT = 2
GUARD_FLEET_WINDOW_S = 3600
GUARD_DAILY_WINDOW_S = 86400
GUARD_DAILY_BACKWASH_LIMIT = 2
BACKWASH_MULTI_WINDOW_S = 1800
BACKWASH_MULTI_DAILY_FILTERS = 3
BACKWASH_ABUSE_WINDOW_S = 3600
BACKWASH_ABUSE_COUNT = 3
BACKWASH_DAILY_WINDOW_S = 86400
BACKWASH_ABUSE_DAILY_COUNT = 3
FILTERS = ("FLT-01", "FLT-02", "FLT-03", "FLT-04")
PUMPS = ("PMP-01", "PMP-02")

USERS = {
    "admin": {"password": "123456", "cred_class": "default", "role": "admin"},
    "tech": {"password": "Tq9x!Lm2#vZp7", "cred_class": "strong", "role": "tech"},
}

LOOPBACK = {"127.0.0.1", "::1", "localhost"}


class ScopeError(Exception):
    """Tentativa de operar fora do âmbito loopback autorizado."""


def assert_loopback(host):
    h = (host or "").strip()
    if h.startswith("[") and h.endswith("]"):
        h = h[1:-1]
    h = h.lower()
    if h not in LOOPBACK:
        raise ScopeError(
            "alvo fora do âmbito loopback: %r (permitido: %s)"
            % (host, sorted(LOOPBACK))
        )
    return h


_SIM_LOCK = threading.Lock()
_SIM_EPOCH = _dt.datetime(2025, 3, 14, 3, 15, 0)
_SIM_MONO0 = time.monotonic()


def _parse_ts(ts_str):
    return _dt.datetime.strptime(str(ts_str), "%Y-%m-%d %H:%M:%S")


def set_sim_time(ts_str):
    global _SIM_EPOCH, _SIM_MONO0
    with _SIM_LOCK:
        _SIM_EPOCH = _parse_ts(ts_str)
        _SIM_MONO0 = time.monotonic()


def sim_now():
    with _SIM_LOCK:
        return _SIM_EPOCH + _dt.timedelta(seconds=time.monotonic() - _SIM_MONO0)


def sim_now_str():
    return sim_now().strftime("%Y-%m-%d %H:%M:%S")


def _minutes_of(ts_str):
    try:
        t = _parse_ts(ts_str)
    except (ValueError, TypeError):
        return None
    return t.hour * 60 + t.minute


def _in_maint_window(ts_str):
    m = _minutes_of(ts_str)
    if m is None:
        return False
    return MAINT_WINDOW[0] <= m < MAINT_WINDOW[1]


def _as_float(v):
    if isinstance(v, bool):
        return None
    try:
        val = float(v)
    except (TypeError, ValueError):
        return None
    if not math.isfinite(val):
        return None
    return val


def service_code_for(day=None):
    d = day if day is not None else sim_now().date()
    raw = ("HYDROBOX-SVC-" + d.strftime("%Y%m%d")).encode("utf-8")
    return "SVC-" + hashlib.sha256(raw).hexdigest()[:8].upper()


def _new_token(actor):
    raw = "%s|%s|%s" % (actor, time.time_ns(), os.getpid())
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:24]


def canonicalize_request(method, raw_path, headers, raw_body):
    """Canonicalização única e partilhada entre Guard e Controlador (Adição D).

    Devolve (ok, canonical_path, parts, token, err). ok=False indica path não
    canónico (query string, %2F, barras duplas, barra final, path vazio) — o
    Controlador responde HTTP 400 e o Guard rejeita igualmente antes de
    qualquer decisão de política. O token Authorization é extraído e
    normalizado num único sítio, idêntico para ambos os lados.
    """
    if "?" in raw_path:
        return False, None, None, None, "query_string_not_allowed"
    if "%2f" in raw_path.lower():
        return False, None, None, None, "encoded_path_segment"
    if "//" in raw_path:
        return False, None, None, None, "double_slash"
    if len(raw_path) > 1 and raw_path.endswith("/"):
        return False, None, None, None, "trailing_slash"
    parts = [p for p in raw_path.split("/") if p]
    if not parts:
        return False, None, None, None, "empty_path"
    canonical_path = "/" + "/".join(parts)
    auth = ""
    if headers:
        auth = headers.get("Authorization") or ""
    token = auth[7:].strip() if auth.lower().startswith("bearer ") else ""
    return True, canonical_path, parts, token, None


def validate_api_body(parts, body):
    """Validação estrita e única do corpo JSON por endpoint (Adição D).

    Devolve None se o corpo for válido, ou um código de erro (HTTP 400).
    bool estrito para "muted", float finito não-booleano para "value",
    bool estrito para "running", "OPEN"/"CLOSED" estritos para "state".
    """
    if parts == ["api", "login"] or parts == ["api", "service_login"]:
        return None
    if len(parts) == 4 and parts[0] == "api" and parts[1] == "pump" and parts[3] == "setpoint":
        has_running = "running" in body
        if has_running and not isinstance(body.get("running"), bool):
            return "bad_running_type"
        if "value" in body and _as_float(body.get("value")) is None:
            return "bad_value"
        if not has_running and "value" not in body:
            return "bad_value"
        return None
    if parts == ["api", "dosing", "setpoint"]:
        if _as_float(body.get("value")) is None:
            return "bad_value"
        return None
    if parts == ["api", "valve", "out"]:
        if body.get("state") not in ("OPEN", "CLOSED"):
            return "bad_state"
        return None
    if parts == ["api", "alarm", "mute"]:
        if not isinstance(body.get("muted"), bool):
            return "bad_muted_type"
        return None
    return None


class Audit:
    """Audit log estruturado JSONL (uma linha = um evento)."""

    def __init__(self, path):
        self.path = path
        self._lock = threading.Lock()
        parent = os.path.dirname(os.path.abspath(path))
        if parent:
            os.makedirs(parent, exist_ok=True)
        self._fh = open(path, "a", encoding="utf-8")

    def log(self, event):
        rec = dict(event)
        rec.setdefault("sim_ts", sim_now_str())
        line = json.dumps(rec, ensure_ascii=False)
        with self._lock:
            self._fh.write(line + "\n")
            self._fh.flush()

    def close(self):
        with self._lock:
            if not self._fh.closed:
                self._fh.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        self.close()
        return False


def read_audit(path):
    events = []
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except ValueError:
                continue
    return events


class HydroboxState:
    """Estado físico sintético do controlador HYDROBOX.

    Com safety_interlocks=True (por omissão), os interlocks de frota/janela e
    hidráulicos são aplicados atomicamente sob self.lock (Adição B), sem TOCTOU
    e sem dependências de I/O de rede. Com safety_interlocks=False, emula um
    controlador legado desprotegido (fases H1/H2 da demo).
    """

    def __init__(self, safety_interlocks=True):
        self.lock = threading.RLock()
        self.safety_interlocks = safety_interlocks
        self.reservoir = 78.0
        self.pressure = 4.0
        self.pumps = {p: {"setpoint": 4.0, "running": p == "PMP-01"} for p in PUMPS}
        self.chlorine = 0.5
        self.valve = "OPEN"
        self.alarm_muted = False
        self.filters = {f: "IDLE" for f in FILTERS}
        self.sessions = {}
        self._sched_done = set()
        self._api_bw_times = []

    def snapshot(self):
        with self.lock:
            return {
                "plant": "HYDROBOX",
                "sim_ts": sim_now_str(),
                "safety_interlocks": self.safety_interlocks,
                "reservoir_pct": self.reservoir,
                "reservoir_band": list(RESERVOIR_BAND),
                "pressure_bar": self.pressure,
                "pressure_band": list(PUMP_BAND),
                "chlorine_mg_l": self.chlorine,
                "chlorine_band": list(CHLORINE_BAND),
                "valve": self.valve,
                "alarm_muted": self.alarm_muted,
                "pumps": {k: dict(v) for k, v in self.pumps.items()},
                "filters": dict(self.filters),
            }

    def tick(self, audit):
        now = sim_now()
        minutes = now.hour * 60 + now.minute
        day = now.strftime("%Y-%m-%d")
        with self.lock:
            in_window = BACKWASH_WINDOW[0] <= minutes < BACKWASH_WINDOW[1]
            if in_window and day not in self._sched_done:
                self._sched_done.add(day)
                self._backwash("FLT-01", "SCHEDULED", "PLC-SCHED", "127.0.0.1", audit)

    def _backwash(self, flt, trigger, actor, src, audit):
        """Executa (ou rejeita atomicamente) uma retrolavagem.

        Devolve (ok, reason). As rejeições com safety_interlocks=True são
        atómicas sob self.lock (Adição B): C-BACKWASH-FLEET-LIMIT,
        C-BACKWASH-DAILY-LIMIT, C-HYDRAULIC-INTERLOCK ou unknown_filter.
        """
        with self.lock:
            if flt not in self.filters:
                return False, "unknown_filter"
            if self.safety_interlocks and trigger == "API":
                now_dt = sim_now()
                self._api_bw_times = [
                    t for t in self._api_bw_times
                    if (now_dt - t).total_seconds() <= GUARD_DAILY_WINDOW_S
                ]
                recent_1h = [
                    t for t in self._api_bw_times
                    if (now_dt - t).total_seconds() <= GUARD_FLEET_WINDOW_S
                ]
                if len(recent_1h) >= GUARD_FLEET_LIMIT:
                    audit.log(
                        {
                            "event": "backwash_rejected",
                            "actor": actor,
                            "source_ip": src,
                            "filter": flt,
                            "reason": "C-BACKWASH-FLEET-LIMIT",
                            "recent_1h": len(recent_1h),
                            "limit": GUARD_FLEET_LIMIT,
                        }
                    )
                    return False, "C-BACKWASH-FLEET-LIMIT"
                if len(self._api_bw_times) >= GUARD_DAILY_BACKWASH_LIMIT:
                    audit.log(
                        {
                            "event": "backwash_rejected",
                            "actor": actor,
                            "source_ip": src,
                            "filter": flt,
                            "reason": "C-BACKWASH-DAILY-LIMIT",
                            "recent_24h": len(self._api_bw_times),
                            "limit": GUARD_DAILY_BACKWASH_LIMIT,
                        }
                    )
                    return False, "C-BACKWASH-DAILY-LIMIT"
            if self.safety_interlocks:
                p_bad = (self.pressure - BACKWASH_PRESSURE_DROP) < PUMP_BAND[0]
                r_bad = (self.reservoir - BACKWASH_RESERVOIR_COST) < BACKWASH_DRAIN_ALERT_PCT
                if p_bad or r_bad:
                    audit.log(
                        {
                            "event": "backwash_rejected",
                            "actor": actor,
                            "source_ip": src,
                            "filter": flt,
                            "reason": "C-HYDRAULIC-INTERLOCK",
                            "pressure_bar": self.pressure,
                            "reservoir_pct": self.reservoir,
                        }
                    )
                    return False, "C-HYDRAULIC-INTERLOCK"
            self.reservoir = round(max(0.0, self.reservoir - BACKWASH_RESERVOIR_COST), 2)
            self.pressure = round(max(0.0, self.pressure - BACKWASH_PRESSURE_DROP), 2)
            self.filters[flt] = "BACKWASH"
            if trigger == "API":
                self._api_bw_times.append(sim_now())
            audit.log(
                {
                    "event": "filter_backwash",
                    "actor": actor,
                    "source_ip": src,
                    "filter": flt,
                    "trigger": trigger,
                    "night": sim_now().strftime("%Y-%m-%d"),
                    "reservoir_after": self.reservoir,
                    "pressure_after": self.pressure,
                }
            )
            audit.log(
                {
                    "event": "reservoir_level",
                    "actor": actor,
                    "source_ip": src,
                    "level": self.reservoir,
                    "band": list(RESERVOIR_BAND),
                }
            )
            return True, None


def _send_json(handler, code, obj):
    data = json.dumps(obj).encode("utf-8")
    handler.send_response(code)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", str(len(data)))
    handler.end_headers()
    handler.wfile.write(data)


def _read_json_body(handler):
    try:
        n = int(handler.headers.get("Content-Length") or 0)
    except ValueError:
        n = 0
    raw = handler.rfile.read(n) if n > 0 else b""
    if not raw:
        return {}
    try:
        return json.loads(raw.decode("utf-8"))
    except ValueError:
        return None


class HydroboxHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"

    def log_message(self, fmt, *args):
        return

    def _send(self, code, obj):
        _send_json(self, code, obj)

    def do_GET(self):
        self.server.state.tick(self.server.audit)
        ok, cpath, parts, token, cerr = canonicalize_request("GET", self.path, self.headers, None)
        if not ok:
            self.server.audit.log(
                {
                    "event": "bad_path",
                    "actor": "anon",
                    "source_ip": self.client_address[0],
                    "path": self.path,
                    "reason": cerr,
                }
            )
            self._send(400, {"error": cerr})
            return
        if cpath == "/api/status":
            sess = self.server.state.sessions.get(token)
            self.server.audit.log(
                {
                    "event": "status_read",
                    "actor": sess["actor"] if sess else "anon",
                    "source_ip": self.client_address[0],
                }
            )
            self._send(200, self.server.state.snapshot())
        else:
            self._send(404, {"error": "not_found"})

    def do_POST(self):
        self.server.state.tick(self.server.audit)
        body = _read_json_body(self)
        if body is None:
            self._send(400, {"error": "bad_json"})
            return
        ok, cpath, parts, token, cerr = canonicalize_request("POST", self.path, self.headers, body)
        if not ok:
            self.server.audit.log(
                {
                    "event": "bad_path",
                    "actor": "anon",
                    "source_ip": self.client_address[0],
                    "path": self.path,
                    "reason": cerr,
                }
            )
            self._send(400, {"error": cerr})
            return
        src = self.client_address[0]
        if parts == ["api", "login"]:
            self._login(body, src)
            return
        if parts == ["api", "service_login"]:
            self._service_login(body, src)
            return
        verr = validate_api_body(parts, body)
        if verr is not None:
            self._send(400, {"error": verr})
            return
        sess = self.server.state.sessions.get(token)
        if sess is None:
            self.server.audit.log(
                {"event": "auth_failure", "actor": "anon", "source_ip": src, "path": cpath}
            )
            self._send(401, {"error": "unauthorized"})
            return
        actor = sess["actor"]
        if len(parts) == 4 and parts[0] == "api" and parts[1] == "pump" and parts[3] == "setpoint":
            self._pump_setpoint(parts[2], body, actor, src)
        elif parts == ["api", "dosing", "setpoint"]:
            self._dosing_setpoint(body, actor, src)
        elif len(parts) == 4 and parts[0] == "api" and parts[1] == "filter" and parts[3] == "backwash":
            self._backwash_cmd(parts[2], actor, src)
        elif parts == ["api", "valve", "out"]:
            self._valve(body, actor, src)
        elif parts == ["api", "alarm", "mute"]:
            self._alarm_mute(body, actor, src)
        else:
            self._send(404, {"error": "not_found"})

    def _login(self, body, src):
        u = str(body.get("username", ""))
        p = str(body.get("password", ""))
        udef = USERS.get(u)
        if udef and udef["password"] == p:
            token = _new_token(u)
            self.server.state.sessions[token] = {"actor": u, "role": udef["role"]}
            self.server.audit.log(
                {
                    "event": "login_success",
                    "actor": u,
                    "source_ip": src,
                    "auth": "password",
                    "cred_class": udef["cred_class"],
                    "role": udef["role"],
                }
            )
            self._send(200, {"session": token, "role": udef["role"]})
        else:
            self.server.audit.log(
                {"event": "login_failure", "actor": u or "unknown", "source_ip": src, "auth": "password"}
            )
            self._send(401, {"error": "invalid_credentials"})

    def _service_login(self, body, src):
        code = str(body.get("code", ""))
        expected = service_code_for()
        if code and code == expected:
            token = _new_token("svc")
            self.server.state.sessions[token] = {"actor": "svc", "role": "service"}
            self.server.audit.log(
                {
                    "event": "service_login_success",
                    "actor": "svc",
                    "source_ip": src,
                    "auth": "daily_code",
                    "role": "service",
                    "code_prefix": code[:4],
                }
            )
            self._send(200, {"session": token, "role": "service"})
        else:
            self.server.audit.log(
                {"event": "service_login_failure", "actor": "svc", "source_ip": src, "auth": "daily_code"}
            )
            self._send(401, {"error": "invalid_service_code"})

    def _pump_setpoint(self, pump_id, body, actor, src):
        if pump_id not in PUMPS:
            self._send(404, {"error": "unknown_pump"})
            return
        val = _as_float(body.get("value"))
        has_running = isinstance(body.get("running"), bool)
        if val is None and not has_running:
            self._send(400, {"error": "bad_value"})
            return
        st = self.server.state
        with st.lock:
            old = dict(st.pumps[pump_id])
            if val is not None:
                st.pumps[pump_id]["setpoint"] = val
            if has_running:
                st.pumps[pump_id]["running"] = body["running"]
            st.pressure = max(
                (p["setpoint"] for p in st.pumps.values() if p["running"]),
                default=0.0,
            )
            any_running = any(p["running"] for p in st.pumps.values())
            new_setpoint = st.pumps[pump_id]["setpoint"]
            running_now = st.pumps[pump_id]["running"]
            pressure_now = st.pressure
            self.server.audit.log(
                {
                    "event": "pump_setpoint",
                    "actor": actor,
                    "source_ip": src,
                    "pump": pump_id,
                    "old": old["setpoint"],
                    "new": new_setpoint,
                    "band": list(PUMP_BAND),
                    "valve": st.valve,
                    "running": running_now,
                    "any_pump_running": any_running,
                }
            )
        self._send(
            200,
            {
                "ok": True,
                "pump": pump_id,
                "setpoint": new_setpoint,
                "running": running_now,
                "pressure_bar": pressure_now,
            },
        )

    def _dosing_setpoint(self, body, actor, src):
        val = _as_float(body.get("value"))
        if val is None:
            self._send(400, {"error": "bad_value"})
            return
        st = self.server.state
        with st.lock:
            old = st.chlorine
            st.chlorine = val
            self.server.audit.log(
                {
                    "event": "dosing_setpoint",
                    "actor": actor,
                    "source_ip": src,
                    "old": old,
                    "new": val,
                    "band": list(CHLORINE_BAND),
                }
            )
        self._send(200, {"ok": True, "chlorine_mg_l": val})

    def _backwash_cmd(self, flt, actor, src):
        ok, reason = self.server.state._backwash(flt, "API", actor, src, self.server.audit)
        if ok:
            self._send(200, {"ok": True, "filter": flt, "state": "BACKWASH"})
        elif reason == "unknown_filter":
            self._send(404, {"error": "unknown_filter"})
        else:
            self._send(403, {"blocked": True, "reason": reason, "filter": flt})

    def _valve(self, body, actor, src):
        state_req = str(body.get("state", "")).upper()
        if state_req not in ("OPEN", "CLOSED"):
            self._send(400, {"error": "bad_state"})
            return
        st = self.server.state
        with st.lock:
            old = st.valve
            st.valve = state_req
            any_running = any(p["running"] for p in st.pumps.values())
            self.server.audit.log(
                {
                    "event": "valve_command",
                    "actor": actor,
                    "source_ip": src,
                    "valve": "VLV-OUT",
                    "old": old,
                    "state": state_req,
                    "pressure": st.pressure,
                    "any_pump_running": any_running,
                }
            )
        self._send(200, {"ok": True, "valve": state_req})

    def _alarm_mute(self, body, actor, src):
        if not isinstance(body.get("muted"), bool):
            self._send(400, {"error": "bad_muted_type"})
            return
        muted = body["muted"]
        st = self.server.state
        with st.lock:
            old = st.alarm_muted
            st.alarm_muted = muted
            self.server.audit.log(
                {
                    "event": "alarm_mute",
                    "actor": actor,
                    "source_ip": src,
                    "old": old,
                    "muted": muted,
                }
            )
        self._send(200, {"ok": True, "alarm_muted": muted})


class _ServerHandle:
    def __init__(self, server, thread, audit):
        self.server = server
        self.thread = thread
        self.audit = audit
        self.port = server.server_address[1]

    def stop(self):
        self.server.shutdown()
        self.server.server_close()
        self.audit.close()


def run_controller_in_thread(port, audit_path, sim_time, safety_interlocks=True):
    set_sim_time(sim_time)
    audit = Audit(audit_path)
    server = ThreadingHTTPServer(("127.0.0.1", port), HydroboxHandler)
    server.daemon_threads = True
    server.state = HydroboxState(safety_interlocks=safety_interlocks)
    server.audit = audit
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    return _ServerHandle(server, t, audit)


def http_req(method, host, port, path, body=None, headers=None):
    h = assert_loopback(host)
    conn_host = "127.0.0.1" if h == "localhost" else h
    base = "http://%s:%d" % (conn_host, port)
    data = None
    hdrs = {"Accept": "application/json"}
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        hdrs["Content-Type"] = "application/json"
    if headers:
        hdrs.update(headers)
    req = urllib.request.Request(base + path, data=data, headers=hdrs, method=method)
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            raw = resp.read().decode("utf-8")
            status = resp.status
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8")
        status = e.code
    try:
        payload = json.loads(raw)
    except ValueError:
        payload = raw
    return status, payload


class Detector:
    """Motor de deteção streaming sobre o audit JSONL do HYDROBOX."""

    WRITE_EVENTS = ("pump_setpoint", "dosing_setpoint", "valve_command", "alarm_mute")

    def __init__(self):
        self.alerts = []
        self._backwash_nights = set()
        self._valve = "OPEN"
        self._api_backwash_times = []

    def scan(self, event):
        found = []

        def fire(rule, level, msg):
            alert = {
                "rule": rule,
                "level": level,
                "msg": msg,
                "sim_ts": event.get("sim_ts", ""),
            }
            self.alerts.append(alert)
            found.append(alert)

        ev = event.get("event")
        ts = event.get("sim_ts", "")
        if ev == "login_success" and event.get("cred_class") == "default":
            fire(
                "D-DEFAULT-CRED-LOGIN",
                "CRIT",
                "Login com conta default '%s' (T1078.001)" % event.get("actor"),
            )
        elif ev == "service_login_success":
            fire(
                "D-HIDDEN-SERVICE-AUTH",
                "CRIT",
                "Autenticação de serviço via código diário previsível (T1190 / ICS T0819)",
            )
        elif ev == "pump_setpoint":
            v = event.get("new")
            if isinstance(v, (int, float)) and not (PUMP_BAND[0] <= v <= PUMP_BAND[1]):
                fire(
                    "D-PRESSURE-OUT-OF-BAND",
                    "CRIT",
                    "Setpoint de pressão %.1f bar fora da banda %s (ICS T0855)"
                    % (v, list(PUMP_BAND)),
                )
            valve_now = event.get("valve") or self._valve
            if (
                valve_now == "CLOSED"
                and event.get("running") is True
                and isinstance(v, (int, float))
                and v > 0
            ):
                fire(
                    "D-DEADHEAD-RISK",
                    "CRIT",
                    "Bomba %s comandada a operar a %.1f bar com válvula VLV-OUT fechada (deadhead; ICS T0855)"
                    % (event.get("pump"), v),
                )
        elif ev == "dosing_setpoint":
            v = event.get("new")
            if isinstance(v, (int, float)) and not (CHLORINE_BAND[0] <= v <= CHLORINE_BAND[1]):
                fire(
                    "D-CHLORINE-OUT-OF-BAND",
                    "CRIT",
                    "Dosagem de cloro %.1f mg/L fora da banda potável %s (Dir. UE 2020/2184; ICS T0855/T0879)"
                    % (v, list(CHLORINE_BAND)),
                )
        elif ev == "valve_command":
            state_cmd = event.get("state")
            if state_cmd in ("OPEN", "CLOSED"):
                self._valve = state_cmd
            if state_cmd == "CLOSED":
                pumps_on = event.get("any_pump_running")
                if pumps_on is None:
                    p = event.get("pressure")
                    pumps_on = isinstance(p, (int, float)) and p > 0
                if pumps_on:
                    fire(
                        "D-DEADHEAD-RISK",
                        "CRIT",
                        "Válvula de saída fechada com bomba em marcha (pressão %.1f bar; deadhead; ICS T0855)"
                        % event.get("pressure", 0),
                    )
                elif not _in_maint_window(ts):
                    fire(
                        "D-VALVE-ANOMALY",
                        "WARN",
                        "Fecho remoto da válvula de saída VLV-OUT fora da janela de manutenção",
                    )
        elif ev == "filter_backwash":
            night = event.get("night")
            flt = event.get("filter")
            key = (night, flt)
            pa = event.get("pressure_after")
            if isinstance(pa, (int, float)) and pa < PUMP_BAND[0]:
                fire(
                    "D-UNDERPRESSURE-DROP",
                    "CRIT",
                    "Pressão de rede %.1f bar abaixo do mínimo vital %.1f bar após retrolavagem de %s (ICS T0855/T0879)"
                    % (pa, PUMP_BAND[0], flt),
                )
            if event.get("trigger") == "API":
                try:
                    ev_dt = _parse_ts(ts)
                except (ValueError, TypeError):
                    ev_dt = None
                if ev_dt is not None:
                    self._api_backwash_times.append((ev_dt, flt))
                    self._api_backwash_times = [
                        (d, f)
                        for (d, f) in self._api_backwash_times
                        if (ev_dt - d).total_seconds() <= BACKWASH_DAILY_WINDOW_S
                    ]
                    recent_30m = {
                        f
                        for (d, f) in self._api_backwash_times
                        if (ev_dt - d).total_seconds() <= BACKWASH_MULTI_WINDOW_S
                    }
                    recent_60m = [
                        1
                        for (d, f) in self._api_backwash_times
                        if (ev_dt - d).total_seconds() <= BACKWASH_ABUSE_WINDOW_S
                    ]
                    day_filters = {f for (d, f) in self._api_backwash_times}
                    out_of_window = bool(ts) and not _in_maint_window(ts)
                    ra = event.get("reservoir_after")
                    if out_of_window:
                        fire(
                            "D-FORCED-BACKWASH",
                            "CRIT",
                            "Retrolavagem remota de %s fora da janela de manutenção 08:00-18:00 (ICS T0855)" % flt,
                        )
                    if len(recent_30m) >= 2 or len(day_filters) >= BACKWASH_MULTI_DAILY_FILTERS:
                        fire(
                            "D-MULTI-FILTER-BACKWASH",
                            "CRIT",
                            "Retrolavagem de >= 2 filtros distintos em %d min ou >= %d filtros distintos em 24h via API (ICS T0855)"
                            % (BACKWASH_MULTI_WINDOW_S // 60, BACKWASH_MULTI_DAILY_FILTERS),
                        )
                    if (
                        len(recent_60m) >= BACKWASH_ABUSE_COUNT
                        or len(self._api_backwash_times) >= BACKWASH_ABUSE_DAILY_COUNT
                    ):
                        fire(
                            "D-BACKWASH-ABUSE",
                            "CRIT",
                            "%d comandos de retrolavagem API em %d min ou em 24h (ICS T0855)"
                            % (BACKWASH_ABUSE_COUNT, BACKWASH_ABUSE_WINDOW_S // 60),
                        )
                    if isinstance(ra, (int, float)) and ra < BACKWASH_DRAIN_ALERT_PCT:
                        fire(
                            "D-FORCED-BACKWASH",
                            "CRIT",
                            "Retrolavagem de %s drenou o reservatório para %.1f%% (< %.0f%%; ICS T0855/T0879)"
                            % (flt, ra, BACKWASH_DRAIN_ALERT_PCT),
                        )
            if key in self._backwash_nights:
                fire(
                    "D-BACKWASH-REPEAT",
                    "WARN",
                    "Retrolavagem repetida de %s na mesma noite" % flt,
                )
            self._backwash_nights.add(key)
        elif ev == "alarm_mute" and event.get("muted") is True:
            fire(
                "D-ALARM-MUTE",
                "CRIT",
                "Supressão remota de alarmes (ICS TA0107 — Inhibit Response Function)",
            )
        elif ev == "reservoir_level":
            lv = event.get("level")
            if isinstance(lv, (int, float)):
                if lv < RESERVOIR_BAND[0]:
                    fire(
                        "D-RESERVOIR-LOW",
                        "CRIT",
                        "Reservatório TK-CLEAR %.1f%% abaixo da banda mínima %s (ICS T0879)"
                        % (lv, list(RESERVOIR_BAND)),
                    )
                elif lv > RESERVOIR_BAND[1]:
                    fire(
                        "D-RESERVOIR-HIGH",
                        "WARN",
                        "Reservatório TK-CLEAR %.1f%% acima da banda máxima %s"
                        % (lv, list(RESERVOIR_BAND)),
                    )
        is_write = ev in self.WRITE_EVENTS or (
            ev == "filter_backwash" and event.get("trigger") == "API"
        )
        if is_write and event.get("actor") != "PLC-SCHED":
            if ts and not _in_maint_window(ts):
                fire(
                    "D-OUT-OF-WINDOW-WRITE",
                    "WARN",
                    "Escrita remota fora da janela de manutenção 08:00-18:00 (sim_ts=%s)" % ts,
                )
        return found


def make_guard_handler(guard_audit, upstream_port):
    class GuardHandler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.0"

        def log_message(self, fmt, *args):
            return

        def _send(self, code, obj):
            _send_json(self, code, obj)

        def _block(self, reason, path, detail=None):
            guard_audit.log(
                {
                    "event": reason,
                    "path": path,
                    "source_ip": self.client_address[0],
                    "detail": detail or {},
                }
            )
            self._send(403, {"blocked": True, "reason": reason, "path": path})

        def do_GET(self):
            ok, cpath, parts, token, cerr = canonicalize_request("GET", self.path, self.headers, None)
            if not ok:
                guard_audit.log(
                    {
                        "event": "G-BAD-PATH",
                        "path": self.path,
                        "source_ip": self.client_address[0],
                        "detail": {"reason": cerr},
                    }
                )
                self._send(400, {"error": cerr, "reason": "G-BAD-PATH"})
                return
            if cpath == "/api/status":
                st, data = http_req("GET", "127.0.0.1", upstream_port, cpath)
                guard_audit.log(
                    {"event": "G-PASS", "path": cpath, "source_ip": self.client_address[0]}
                )
                self._send(st, data if isinstance(data, dict) else {"upstream": str(data)})
            else:
                self._send(404, {"error": "not_found"})

        def do_POST(self):
            body = _read_json_body(self)
            if body is None:
                self._send(400, {"error": "bad_json"})
                return
            ok, cpath, parts, token, cerr = canonicalize_request("POST", self.path, self.headers, body)
            if not ok:
                guard_audit.log(
                    {
                        "event": "G-BAD-PATH",
                        "path": self.path,
                        "source_ip": self.client_address[0],
                        "detail": {"reason": cerr},
                    }
                )
                self._send(400, {"error": cerr, "reason": "G-BAD-PATH"})
                return
            src = self.client_address[0]
            if (
                cpath == "/api/login"
                and str(body.get("username")) == "admin"
                and str(body.get("password")) == "123456"
            ):
                self._block("G-DEFAULT-CRED-BLOCKED", cpath, {"username": "admin"})
                return
            if cpath == "/api/service_login":
                self._block("G-HIDDEN-AUTH-BLOCKED", cpath, {})
                return
            if cpath == "/api/alarm/mute" and body.get("muted") is not False:
                self._block("G-ALARM-MUTE-BLOCKED", cpath, {"muted": body.get("muted")})
                return
            if cpath == "/api/valve/out" and body.get("state") == "CLOSED":
                self._block("G-VALVE-CLOSE-BLOCKED", cpath, {"state": "CLOSED"})
                return
            verr = validate_api_body(parts, body)
            if verr is not None:
                guard_audit.log(
                    {
                        "event": "G-BAD-BODY",
                        "path": cpath,
                        "source_ip": src,
                        "detail": {"error": verr},
                    }
                )
                self._send(400, {"error": verr, "reason": "G-BAD-BODY"})
                return
            is_write = (
                len(parts) == 4
                and parts[0] == "api"
                and parts[1] in ("pump", "filter")
                and parts[3] in ("setpoint", "backwash")
            ) or parts in (
                ["api", "dosing", "setpoint"],
                ["api", "valve", "out"],
                ["api", "alarm", "mute"],
            )
            if is_write:
                now_str = sim_now_str()
                if not _in_maint_window(now_str):
                    self._block("G-OUT-OF-WINDOW", cpath, {"sim_ts": now_str})
                    return
            if len(parts) == 4 and parts[0] == "api" and parts[1] == "pump" and parts[3] == "setpoint":
                v = _as_float(body.get("value"))
                if v is not None and not (PUMP_BAND[0] <= v <= PUMP_BAND[1]):
                    cl = min(max(v, PUMP_BAND[0]), PUMP_BAND[1])
                    guard_audit.log(
                        {
                            "event": "G-SETPOINT-CLAMP",
                            "path": cpath,
                            "source_ip": src,
                            "orig": v,
                            "clamped": cl,
                            "band": list(PUMP_BAND),
                        }
                    )
                    body["value"] = cl
            if parts == ["api", "dosing", "setpoint"]:
                v = _as_float(body.get("value"))
                if v is not None and not (CHLORINE_BAND[0] <= v <= CHLORINE_BAND[1]):
                    cl = min(max(v, CHLORINE_BAND[0]), CHLORINE_BAND[1])
                    guard_audit.log(
                        {
                            "event": "G-SETPOINT-CLAMP",
                            "path": cpath,
                            "source_ip": src,
                            "orig": v,
                            "clamped": cl,
                            "band": list(CHLORINE_BAND),
                        }
                    )
                    body["value"] = cl
            st, data = http_req(
                "POST",
                "127.0.0.1",
                upstream_port,
                cpath,
                body=body,
                headers={"Authorization": self.headers.get("Authorization") or ""},
            )
            if st == 403 and isinstance(data, dict) and data.get("blocked"):
                guard_audit.log(
                    {
                        "event": "G-UPSTREAM-REJECT",
                        "path": cpath,
                        "source_ip": src,
                        "detail": {"upstream_reason": data.get("reason")},
                    }
                )
            guard_audit.log(
                {
                    "event": "G-PASS",
                    "path": cpath,
                    "source_ip": src,
                    "upstream_status": st,
                }
            )
            self._send(st, data if isinstance(data, dict) else {"upstream": str(data)})

    return GuardHandler


def stream_detect(audit_path, detector, stop_event, poll=0.1, stats=None, on_alert=None):
    fh = open(audit_path, "r", encoding="utf-8")
    buf = ""
    try:
        while not stop_event.is_set():
            chunk = fh.read()
            if chunk:
                buf += chunk
                while "\n" in buf:
                    line, buf = buf.split("\n", 1)
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        ev = json.loads(line)
                    except ValueError:
                        continue
                    det_ts = sim_now_str()
                    new = detector.scan(ev)
                    if new:
                        if stats is not None and "first_ev" not in stats:
                            stats["first_ev"] = ev.get("sim_ts", "")
                            stats["first_det"] = det_ts
                        if on_alert:
                            for a in new:
                                on_alert(a)
            else:
                time.sleep(poll)
    finally:
        fh.close()


def attack_chain(variant, host, port):
    assert variant in ("h1", "h2")
    steps = []

    def call(name, method, path, body=None, headers=None):
        st, resp = http_req(method, host, port, path, body=body, headers=headers)
        steps.append(
            {
                "step": name,
                "path": path,
                "status": st,
                "response": resp if isinstance(resp, dict) else str(resp),
            }
        )
        return st, resp

    call("recon-status", "GET", "/api/status")
    session = None
    if variant == "h1":
        st, resp = call(
            "auth-default-creds",
            "POST",
            "/api/login",
            {"username": "admin", "password": "123456"},
        )
        if isinstance(resp, dict):
            session = resp.get("session")
    else:
        code = service_code_for()
        st, resp = call("auth-service-code", "POST", "/api/service_login", {"code": code})
        if isinstance(resp, dict):
            session = resp.get("session")
    auth = {"Authorization": "Bearer " + session} if session else {}
    call("sabotage-pressure-8.5", "POST", "/api/pump/PMP-01/setpoint", {"value": 8.5}, auth)
    call("sabotage-chlorine-4.5", "POST", "/api/dosing/setpoint", {"value": 4.5}, auth)
    call("sabotage-valve-close", "POST", "/api/valve/out", {"state": "CLOSED"}, auth)
    for f in FILTERS:
        call("sabotage-backwash-" + f, "POST", "/api/filter/%s/backwash" % f, {}, auth)
    call("sabotage-alarm-mute", "POST", "/api/alarm/mute", {"muted": True}, auth)
    return steps


def legit_tech_flow(host, port):
    steps = []

    def call(name, method, path, body=None, headers=None):
        st, resp = http_req(method, host, port, path, body=body, headers=headers)
        steps.append(
            {
                "step": name,
                "path": path,
                "status": st,
                "response": resp if isinstance(resp, dict) else str(resp),
            }
        )
        return st, resp

    st, resp = call(
        "login-tech",
        "POST",
        "/api/login",
        {"username": "tech", "password": USERS["tech"]["password"]},
    )
    session = resp.get("session") if isinstance(resp, dict) else None
    auth = {"Authorization": "Bearer " + session} if session else {}
    call("status-read", "GET", "/api/status")
    call("trim-pressure-4.2", "POST", "/api/pump/PMP-01/setpoint", {"value": 4.2}, auth)
    call("trim-chlorine-0.6", "POST", "/api/dosing/setpoint", {"value": 0.6}, auth)
    call("maintenance-backwash-FLT-01", "POST", "/api/filter/FLT-01/backwash", {}, auth)
    call("isolate-stop-pump", "POST", "/api/pump/PMP-01/setpoint", {"running": False}, auth)
    call("isolate-close-valve", "POST", "/api/valve/out", {"state": "CLOSED"}, auth)
    call("isolate-reopen-valve", "POST", "/api/valve/out", {"state": "OPEN"}, auth)
    call("restore-start-pump", "POST", "/api/pump/PMP-01/setpoint", {"running": True}, auth)
    call("alarm-unmute", "POST", "/api/alarm/mute", {"muted": False}, auth)
    return steps


RULE_ATTACK_MAP = {
    "D-DEFAULT-CRED-LOGIN": "Enterprise T1078.001 (Valid Accounts: Default Accounts)",
    "D-HIDDEN-SERVICE-AUTH": "Enterprise T1190 / ICS T0819 (Exploit Public-Facing Application)",
    "D-PRESSURE-OUT-OF-BAND": "ICS T0855 (Unauthorized Command Message)",
    "D-CHLORINE-OUT-OF-BAND": "ICS T0855 / ICS T0879 (Damage to Property)",
    "D-DEADHEAD-RISK": "ICS T0855 (Unauthorized Command Message)",
    "D-VALVE-ANOMALY": "ICS T0855 (Unauthorized Command Message)",
    "D-FORCED-BACKWASH": "ICS T0855 (Unauthorized Command Message)",
    "D-MULTI-FILTER-BACKWASH": "ICS T0855 (Unauthorized Command Message)",
    "D-BACKWASH-ABUSE": "ICS T0855 (Unauthorized Command Message)",
    "D-UNDERPRESSURE-DROP": "ICS T0855 / ICS T0879 (Damage to Property)",
    "D-BACKWASH-REPEAT": "ICS T0855 (Unauthorized Command Message)",
    "D-ALARM-MUTE": "ICS TA0107 (Inhibit Response Function)",
    "D-RESERVOIR-LOW": "ICS T0879 (Damage to Property)",
    "D-RESERVOIR-HIGH": "ICS T0879 (Damage to Property)",
    "D-OUT-OF-WINDOW-WRITE": "ICS T0855 (condição operacional fora da janela 08:00-18:00)",
}


def _rule_liveness_events():
    """Eventos sintéticos que exercitam todas as regras de RULE_ATTACK_MAP."""
    return [
        {"event": "login_success", "actor": "admin", "cred_class": "default", "sim_ts": "2025-03-14 03:15:00"},
        {"event": "service_login_success", "actor": "svc", "sim_ts": "2025-03-14 03:15:01"},
        {"event": "pump_setpoint", "actor": "admin", "pump": "PMP-01", "old": 4.0, "new": 8.5, "band": [2.5, 5.5], "valve": "OPEN", "running": True, "any_pump_running": True, "sim_ts": "2025-03-14 03:15:02"},
        {"event": "dosing_setpoint", "actor": "admin", "old": 0.5, "new": 4.5, "band": [0.2, 1.0], "sim_ts": "2025-03-14 03:15:03"},
        {"event": "valve_command", "actor": "admin", "valve": "VLV-OUT", "old": "OPEN", "state": "CLOSED", "pressure": 8.5, "any_pump_running": True, "sim_ts": "2025-03-14 03:15:04"},
        {"event": "filter_backwash", "actor": "admin", "filter": "FLT-01", "trigger": "API", "night": "2025-03-14", "reservoir_after": 66.0, "pressure_after": 8.1, "sim_ts": "2025-03-14 03:15:05"},
        {"event": "filter_backwash", "actor": "admin", "filter": "FLT-01", "trigger": "API", "night": "2025-03-14", "reservoir_after": 54.0, "pressure_after": 7.7, "sim_ts": "2025-03-14 03:15:06"},
        {"event": "filter_backwash", "actor": "admin", "filter": "FLT-02", "trigger": "API", "night": "2025-03-14", "reservoir_after": 42.0, "pressure_after": 7.3, "sim_ts": "2025-03-14 03:15:07"},
        {"event": "filter_backwash", "actor": "admin", "filter": "FLT-03", "trigger": "API", "night": "2025-03-14", "reservoir_after": 30.0, "pressure_after": 2.1, "sim_ts": "2025-03-14 03:15:08"},
        {"event": "alarm_mute", "actor": "admin", "muted": True, "sim_ts": "2025-03-14 03:15:09"},
        {"event": "reservoir_level", "actor": "admin", "level": 18.0, "band": [25.0, 95.0], "sim_ts": "2025-03-14 03:15:10"},
        {"event": "reservoir_level", "actor": "admin", "level": 96.0, "band": [25.0, 95.0], "sim_ts": "2025-03-14 03:15:11"},
        {"event": "valve_command", "actor": "tech", "valve": "VLV-OUT", "old": "OPEN", "state": "CLOSED", "pressure": 0.0, "any_pump_running": False, "sim_ts": "2025-03-14 03:15:12"},
    ]


def rule_liveness_check():
    det = Detector()
    for ev in _rule_liveness_events():
        det.scan(ev)
    fired = {a["rule"] for a in det.alerts}
    dead = set(RULE_ATTACK_MAP.keys()) - fired
    return dead, fired


def _phase_dict(tag, scenario, sim_time, steps, alerts, mttd, events_count,
                final_state, guard_blocks=None):
    crit = sum(1 for a in alerts if a["level"] == "CRIT")
    warn = sum(1 for a in alerts if a["level"] == "WARN")
    by_rule = {}
    for a in alerts:
        by_rule[a["rule"]] = by_rule.get(a["rule"], 0) + 1
    return {
        "phase": tag,
        "scenario": scenario,
        "sim_time": sim_time,
        "steps": steps,
        "controller_events": events_count,
        "crit": crit,
        "warn": warn,
        "by_rule": by_rule,
        "alerts": alerts,
        "mttd_seconds": mttd,
        "guard_blocks": guard_blocks or {},
        "guard_blocks_total": sum((guard_blocks or {}).values()),
        "final_state": final_state,
        "outcome": None,
    }


def _print_steps(steps):
    for s in steps:
        note = ""
        if isinstance(s["response"], dict) and s["response"].get("blocked"):
            note = "  << BLOQUEADO: %s" % s["response"].get("reason")
        print("    %-26s %-34s HTTP %s%s" % (s["step"], s["path"], s["status"], note))


def _mttd_from_stats(stats):
    if "first_ev" not in stats or "first_det" not in stats:
        return None
    try:
        delta = _parse_ts(stats["first_det"]) - _parse_ts(stats["first_ev"])
        return round(max(0.0, delta.total_seconds()), 3)
    except ValueError:
        return None


def _fresh_audit(path):
    if os.path.exists(path):
        os.remove(path)
    return path


def _final_state_subset(snap):
    if not isinstance(snap, dict):
        return {}
    return {
        "reservoir_pct": snap.get("reservoir_pct"),
        "pressure_bar": snap.get("pressure_bar"),
        "chlorine_mg_l": snap.get("chlorine_mg_l"),
        "valve": snap.get("valve"),
        "alarm_muted": snap.get("alarm_muted"),
        "safety_interlocks": snap.get("safety_interlocks"),
    }


def cmd_serve(args):
    ctl = run_controller_in_thread(args.port, args.audit, args.sim_time)
    print(
        "HYDROBOX ativo em http://127.0.0.1:%d (audit: %s | sim: %s | interlocks: ON)"
        % (ctl.port, args.audit, args.sim_time)
    )
    print("Ctrl+C para terminar.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        ctl.stop()
        print("HYDROBOX terminado.")
    return 0


def cmd_attack(args):
    assert_loopback(args.host)
    steps = attack_chain(args.variant, args.host, args.port)
    blocked = 0
    for s in steps:
        note = ""
        if isinstance(s["response"], dict) and s["response"].get("blocked"):
            note = "  << BLOQUEADO: %s" % s["response"].get("reason")
            blocked += 1
        print("%-28s %-38s HTTP %s%s" % (s["step"], s["path"], s["status"], note))
    print("Passos: %d | Bloqueados: %d" % (len(steps), blocked))
    return 0


def cmd_detect(args):
    if not os.path.exists(args.audit):
        print("Ficheiro de audit não encontrado: %s" % args.audit)
        return 2
    det = Detector()
    if args.watch:
        stop = threading.Event()
        print("Deteção streaming sobre %s (Ctrl+C para parar)..." % args.audit)

        def on_alert(a):
            print("[%s] %s %s - %s" % (a["sim_ts"], a["level"], a["rule"], a["msg"]))

        try:
            stream_detect(args.audit, det, stop, 0.1, None, on_alert)
        except KeyboardInterrupt:
            pass
        finally:
            stop.set()
        return 0
    for ev in read_audit(args.audit):
        det.scan(ev)
    for a in det.alerts:
        print("[%s] %s %s - %s" % (a["sim_ts"], a["level"], a["rule"], a["msg"]))
    crit = sum(1 for a in det.alerts if a["level"] == "CRIT")
    warn = sum(1 for a in det.alerts if a["level"] == "WARN")
    print("TOTAL: %d alertas (%d CRIT / %d WARN)" % (len(det.alerts), crit, warn))
    return 0


def cmd_guard(args):
    if args.sim_time:
        set_sim_time(args.sim_time)
    gaudit = Audit(args.audit)
    server = ThreadingHTTPServer(("127.0.0.1", args.port), make_guard_handler(gaudit, args.upstream_port))
    server.daemon_threads = True
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    print(
        "Guard Proxy ativo em http://127.0.0.1:%d -> upstream 127.0.0.1:%d (audit: %s)"
        % (args.port, args.upstream_port, args.audit)
    )
    print("Ctrl+C para terminar.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        server.shutdown()
        server.server_close()
        gaudit.close()
        print("Guard Proxy terminado.")
    return 0


def cmd_demo(args):
    evdir = args.evidence_dir
    os.makedirs(evdir, exist_ok=True)
    print("=" * 78)
    print("HYDROSTRIKE v%s — DEMO AUTÓNOMA (alvo sintético HYDROBOX, loopback 127.0.0.1)" % __version__)
    print("=" * 78)
    phases = []
    sim_night = "2025-03-14 03:15:00"
    sim_day = "2025-03-14 10:15:00"

    def run_attack_phase(tag, variant, port, sim_time, scenario):
        print("\n[FASE %s] %s @ %s" % (tag, scenario, sim_time))
        print("  (controlador legado: safety_interlocks=False — demonstração de impacto e deteção)")
        audit_path = _fresh_audit(os.path.join(evdir, "controller_audit_%s.jsonl" % tag))
        ctl = run_controller_in_thread(port, audit_path, sim_time, safety_interlocks=False)
        det = Detector()
        stats = {}
        stop = threading.Event()
        t = threading.Thread(
            target=stream_detect, args=(audit_path, det, stop, 0.05, stats), daemon=True
        )
        t.start()
        steps = attack_chain(variant, "127.0.0.1", port)
        time.sleep(0.4)
        stop.set()
        t.join(timeout=3)
        st_code, snap = http_req("GET", "127.0.0.1", port, "/api/status")
        ctl.stop()
        _print_steps(steps)
        alerts = det.alerts
        mttd = _mttd_from_stats(stats)
        phase = _phase_dict(
            tag, scenario, sim_time, steps, alerts, mttd,
            len(read_audit(audit_path)), _final_state_subset(snap),
        )
        phase["outcome"] = (
            "DETECTED" if any(a["level"] == "CRIT" for a in alerts)
            else ("WARN_ONLY" if alerts else "CLEAN")
        )
        with open(os.path.join(evdir, "alerts_%s.json" % tag), "w", encoding="utf-8") as fh:
            json.dump(alerts, fh, indent=2, ensure_ascii=False)
        print(
            "  eventos controlador: %d | alertas: %d CRIT / %d WARN | MTTD: %s s | resultado: %s"
            % (phase["controller_events"], phase["crit"], phase["warn"],
               "-" if mttd is None else "%.3f" % mttd, phase["outcome"])
        )
        return phase

    def run_negative_phase(tag, port, sim_time, scenario):
        print("\n[FASE %s] %s @ %s" % (tag, scenario, sim_time))
        audit_path = _fresh_audit(os.path.join(evdir, "controller_audit_%s.jsonl" % tag))
        ctl = run_controller_in_thread(port, audit_path, sim_time)
        det = Detector()
        stats = {}
        stop = threading.Event()
        t = threading.Thread(
            target=stream_detect, args=(audit_path, det, stop, 0.05, stats), daemon=True
        )
        t.start()
        steps = legit_tech_flow("127.0.0.1", port)
        time.sleep(0.4)
        stop.set()
        t.join(timeout=3)
        st_code, snap = http_req("GET", "127.0.0.1", port, "/api/status")
        ctl.stop()
        _print_steps(steps)
        alerts = det.alerts
        phase = _phase_dict(
            tag, scenario, sim_time, steps, alerts, None,
            len(read_audit(audit_path)), _final_state_subset(snap),
        )
        phase["outcome"] = "CLEAN" if not alerts else "UNEXPECTED_ALERTS"
        with open(os.path.join(evdir, "alerts_%s.json" % tag), "w", encoding="utf-8") as fh:
            json.dump(alerts, fh, indent=2, ensure_ascii=False)
        print(
            "  eventos controlador: %d | alertas: %d CRIT / %d WARN | resultado: %s"
            % (phase["controller_events"], phase["crit"], phase["warn"], phase["outcome"])
        )
        return phase

    def run_guard_phase(tag, port_ctl, port_guard, sim_time, scenario):
        print("\n[FASE %s] %s @ %s" % (tag, scenario, sim_time))
        print("  (controlador com safety_interlocks=True + Guard Proxy — interlocks atómicos)")
        ctl_audit = _fresh_audit(os.path.join(evdir, "controller_audit_%s.jsonl" % tag))
        guard_path = _fresh_audit(os.path.join(evdir, "guard_audit_%s.jsonl" % tag))
        ctl = run_controller_in_thread(port_ctl, ctl_audit, sim_time)
        gaudit = Audit(guard_path)
        gserver = ThreadingHTTPServer(
            ("127.0.0.1", port_guard), make_guard_handler(gaudit, port_ctl)
        )
        gserver.daemon_threads = True
        gt = threading.Thread(target=gserver.serve_forever, daemon=True)
        gt.start()
        det = Detector()
        stats = {}
        stop = threading.Event()
        t = threading.Thread(
            target=stream_detect, args=(ctl_audit, det, stop, 0.05, stats), daemon=True
        )
        t.start()
        steps = attack_chain("h1", "127.0.0.1", port_guard)
        time.sleep(0.4)
        stop.set()
        t.join(timeout=3)
        st_code, snap = http_req("GET", "127.0.0.1", port_ctl, "/api/status")
        gserver.shutdown()
        gserver.server_close()
        gaudit.close()
        ctl.stop()
        _print_steps(steps)
        blocks = {}
        for e in read_audit(guard_path):
            evn = e.get("event", "")
            if evn.startswith("G-") and evn != "G-PASS":
                blocks[evn] = blocks.get(evn, 0) + 1
        alerts = det.alerts
        phase = _phase_dict(
            tag, scenario, sim_time, steps, alerts, None,
            len(read_audit(ctl_audit)), _final_state_subset(snap), blocks,
        )
        phase["outcome"] = (
            "PREVENTED" if not alerts and phase["guard_blocks_total"] > 0 else "PARTIAL"
        )
        with open(os.path.join(evdir, "alerts_%s.json" % tag), "w", encoding="utf-8") as fh:
            json.dump(alerts, fh, indent=2, ensure_ascii=False)
        print(
            "  eventos controlador: %d | alertas controlador: %d | bloqueios Guard: %d | resultado: %s"
            % (phase["controller_events"], len(alerts), phase["guard_blocks_total"], phase["outcome"])
        )
        print("  bloqueios por motivo: %s" % json.dumps(blocks, ensure_ascii=False))
        return phase

    phases.append(run_attack_phase("H1", "h1", 8601, sim_night, "credenciais default admin/123456 (T1078.001)"))
    phases.append(run_attack_phase("H2", "h2", 8602, sim_night, "bypass via código diário de serviço (T1190/ICS T0819)"))
    phases.append(run_negative_phase("NEG", 8603, sim_day, "operação legítima do técnico tech (caso negativo, com isolamento hidráulico)"))
    phases.append(run_guard_phase("GUARD", 8604, 8605, sim_night, "H1 através do Guard Proxy (prevenção)"))

    dead_rules, fired_rules = rule_liveness_check()
    checks = [
        ("Invariante de vivacidade: 100% das regras de RULE_ATTACK_MAP disparam (0 mortas)",
         len(dead_rules) == 0),
        ("H1 detetado com CRIT e regra D-DEFAULT-CRED-LOGIN",
         any(a["rule"] == "D-DEFAULT-CRED-LOGIN" for a in phases[0]["alerts"])
         and phases[0]["crit"] > 0),
        ("H2 detetado com CRIT e regra D-HIDDEN-SERVICE-AUTH",
         any(a["rule"] == "D-HIDDEN-SERVICE-AUTH" for a in phases[1]["alerts"])
         and phases[1]["crit"] > 0),
        ("Caso negativo (tech @ 10:15, retrolavagem manual + isolamento legítimo) sem alertas",
         len(phases[2]["alerts"]) == 0),
        ("Guard: 0 alertas no controlador", len(phases[3]["alerts"]) == 0),
        ("Guard: bloqueios ativos registados", phases[3]["guard_blocks_total"] > 0),
        ("Guard: estado final intacto (válvula OPEN, sem mute, bandas OK)",
         phases[3]["final_state"].get("valve") == "OPEN"
         and phases[3]["final_state"].get("alarm_muted") is False
         and PUMP_BAND[0] <= phases[3]["final_state"].get("pressure_bar", 0.0) <= PUMP_BAND[1]
         and CHLORINE_BAND[0] <= phases[3]["final_state"].get("chlorine_mg_l", 0.0) <= CHLORINE_BAND[1]
         and phases[3]["final_state"].get("reservoir_pct", 0.0) >= RESERVOIR_BAND[0]),
    ]
    ok = all(c[1] for c in checks)

    print("\n" + "=" * 78)
    print("TABELA DE RESULTADOS")
    print("=" * 78)
    cols = ["FASE", "CENARIO", "EVENTOS", "CRIT", "WARN", "MTTD(s)", "BLOQ.", "RESULTADO"]
    rows = []
    for p in phases:
        rows.append(
            [
                p["phase"],
                p["scenario"][:34],
                str(p["controller_events"]),
                str(p["crit"]),
                str(p["warn"]),
                "-" if p["mttd_seconds"] is None else "%.3f" % p["mttd_seconds"],
                str(p["guard_blocks_total"]),
                p["outcome"],
            ]
        )
    widths = []
    for i in range(len(cols)):
        w = len(cols[i])
        for r in rows:
            w = max(w, len(r[i]))
        widths.append(w)

    def fmt_row(cells):
        return "| " + " | ".join(cells[i].ljust(widths[i]) for i in range(len(cells))) + " |"

    sep = "+" + "+".join("-" * (w + 2) for w in widths) + "+"
    print(sep)
    print(fmt_row(cols))
    print(sep)
    for r in rows:
        print(fmt_row(r))
    print(sep)

    print("\nCRITÉRIOS DE SUCESSO:")
    for name, passed in checks:
        print("  [%s] %s" % ("OK" if passed else "NOK", name))
    print("AVALIAÇÃO GLOBAL: %s" % ("OK — critérios cumpridos" if ok else "FALHOU"))

    summary = {
        "lab": LAB_NAME,
        "version": __version__,
        "generated_utc": _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "scope": "loopback 127.0.0.1 only (ScopeError fora do âmbito)",
        "operator": "Sérgio Azevedo (root)",
        "phases": phases,
        "rule_attack_map": RULE_ATTACK_MAP,
        "rule_liveness": {"dead_rules": sorted(dead_rules), "fired_rules": sorted(fired_rules)},
        "success_criteria": [{"check": n, "ok": v} for n, v in checks],
        "success_criteria_ok": ok,
    }
    summary_path = os.path.join(evdir, "summary.json")
    with open(summary_path, "w", encoding="utf-8") as fh:
        json.dump(summary, fh, indent=2, ensure_ascii=False)
    print("\nEvidência escrita em: %s" % os.path.abspath(summary_path))

    md = ["# Hydrostrike v%s — Resultados (PVTE-X v1.1)" % __version__, ""]
    md.append("| Fase | Cenário | Eventos | CRIT | WARN | MTTD (s) | Bloq. Guard | Resultado |")
    md.append("|---|---|---|---|---|---|---|---|")
    for p in phases:
        md.append(
            "| %s | %s | %d | %d | %d | %s | %d | %s |"
            % (
                p["phase"], p["scenario"], p["controller_events"], p["crit"], p["warn"],
                "-" if p["mttd_seconds"] is None else "%.3f" % p["mttd_seconds"],
                p["guard_blocks_total"], p["outcome"],
            )
        )
    md.append("")
    md.append("## Critérios de sucesso")
    md.append("")
    for name, passed in checks:
        md.append("- [%s] %s" % ("x" if passed else " ", name))
    md.append("")
    md.append("## Alertas por fase")
    md.append("")
    for p in phases:
        md.append("### %s — %s" % (p["phase"], p["scenario"]))
        md.append("")
        if not p["alerts"]:
            md.append("- (sem alertas)")
        for a in p["alerts"]:
            md.append("- `%s` **%s** @ %s — %s" % (a["rule"], a["level"], a["sim_ts"], a["msg"]))
        md.append("")
    md_path = os.path.join(evdir, "results.md")
    with open(md_path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(md) + "\n")
    print("Relatório: %s" % os.path.abspath(md_path))
    return 0 if ok else 1


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="hydrostrike_lab.py",
        description="Hydrostrike v%s — laboratório defensivo loopback (PVTE-X v1.1)" % __version__,
    )
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("serve", help="arranca o controlador sintético HYDROBOX (interlocks ativos)")
    p.add_argument("--port", type=int, default=8600)
    p.add_argument("--audit", default="hydrobox_audit.jsonl")
    p.add_argument("--sim-time", default="2025-03-14 03:15:00")
    p.set_defaults(func=cmd_serve)

    p = sub.add_parser("attack", help="emulação adversária (h1: default creds | h2: código diário)")
    p.add_argument("--variant", choices=["h1", "h2"], required=True)
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8600)
    p.set_defaults(func=cmd_attack)

    p = sub.add_parser("detect", help="deteção sobre um audit JSONL (one-shot ou --watch)")
    p.add_argument("--audit", required=True)
    p.add_argument("--watch", action="store_true")
    p.set_defaults(func=cmd_detect)

    p = sub.add_parser("guard", help="arranca o Guard Proxy de prevenção")
    p.add_argument("--port", type=int, default=8605)
    p.add_argument("--upstream-port", type=int, default=8600)
    p.add_argument("--audit", default="guard_audit.jsonl")
    p.add_argument("--sim-time", default=None)
    p.set_defaults(func=cmd_guard)

    p = sub.add_parser("demo", help="demo autónoma: H1, H2, caso negativo e Guard, com summary.json")
    p.add_argument("--evidence-dir", default="evidence")
    p.set_defaults(func=cmd_demo)

    args = ap.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())

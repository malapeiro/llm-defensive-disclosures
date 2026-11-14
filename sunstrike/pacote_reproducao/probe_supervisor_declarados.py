"""Supervisor (Claude) — números dos declarados (estacionar 45,1 %, curtailment 26 %, AUD-03, G5, HMAC). python3 -I probe_supervisor_declarados.py <dir_lab>"""
import sys, time, hashlib, collections
sys.path.insert(0, sys.argv[1]); import sunstrike_lab as ss
from sunstrike_lab import Lab, http_json, collect_events, LOOPBACK, PORT_DEV_BASE
print("alvo", hashlib.sha256(open(ss.__file__,"rb").read()).hexdigest())
ss.SIM_CLOCK_OFFSET = 0.0; lab = Lab(evidence=False); lab.start(); time.sleep(0.3)
def served(): return sum(1 for d in lab.devices if d.self_consumption_kw() >= ss.LOAD_LOCAL_KW - 0.01)
def al(s): return sorted(collections.Counter((a["rule"],a["severity"]) for a in lab.detector.scan([e for e in collect_events(lab.ctx) if e.get("scenario")==s])).items())
def reset(s):
    ss.SIM_CLOCK_OFFSET=0.0; lab.gridsim.set_state("NORMAL"); lab.gridsim.set_irradiance("DIA"); time.sleep(0.4)
    for d in lab.devices: d.harness_reset()
    time.sleep(0.4); lab.scenario(s)
def park(s, p1, p2):
    reset(s); sts=[]
    for d in lab.devices: sts.append(http_json(LOOPBACK,d.port,"POST","/battery",{"action":"discharge","amount_kwh":round(p1*d.batt_kwh,4)},token=d.service_token)[0])
    ss.SIM_CLOCK_OFFSET += 25*3600.0
    for d in lab.devices: sts.append(http_json(LOOPBACK,d.port,"POST","/battery",{"action":"discharge","amount_kwh":round(p2*d.batt_kwh,4)},token=d.service_token)[0])
    soc=sorted(set(round(d.soc,2) for d in lab.devices)); a=al(s)
    lab.gridsim.set_irradiance("NOITE"); lab.gridsim.set_state("BLACKOUT"); time.sleep(0.35)
    row=[]
    for h in range(1,9):
        for d in lab.devices: d.step_island(3600.0)
        row.append(served())
    print("[%s] %.1f%%+%.1f%% status=%s SoC=%s alertas=%s | casas com luz 1..8h=%s" % (s,p1*100,p2*100,sorted(collections.Counter(sts).items()),soc,a,row))
try:
    # A1: fronteira e evasao da regra PARKED
    park("A1-PARK-35.1", 0.40, 0.249)
    park("A1-PARK-45.0", 0.40, 0.150)
    park("A1-PARK-45.1", 0.40, 0.149)
    park("A1-PARK-50", 0.40, 0.10)
    reset("A1-CTRL"); lab.gridsim.set_irradiance("NOITE"); lab.gridsim.set_state("BLACKOUT"); time.sleep(0.35)
    row=[]
    for h in range(1,9):
        for d in lab.devices: d.step_island(3600.0)
        row.append(served())
    print("[A1-CTRL] sem ataque | casas com luz 1..8h=%s" % row)
    # A2: AUD-03 — pedidos abaixo e acima da resolucao, ledger vs queda real
    for frac,n,nm in ((0.000051,4001,"A2-0.0051"),(0.000151,3000,"A2-0.0151"),(0.0000501,6499,"A2-0.00501")):
        reset(nm); d=lab.devices[0]; s0=d.soc; c=collections.Counter()
        for _ in range(n):
            c[http_json(LOOPBACK,d.port,"POST","/battery",{"action":"discharge","amount_kwh":d.batt_kwh*frac},token=d.service_token)[0]]+=1
        print("[%s] %d pedidos status=%s queda real=%.2f pp ledger=%.2f alertas=%s" % (nm,n,sorted(c.items()),s0-d.soc,d.remote_drain_used_pct(),al(nm)))
    # A3: G5 (probe do supervisor de 13-11) contra a v0.7.4
    reset("A3-G5"); big=sorted(range(12),key=lambda i:-lab.devices[i].kwp)
    for i in big[:4]: http_json(LOOPBACK,lab.devices[i].port,"POST","/setpoint",{"value":0.0,"work_order":"WO-20261112-MNT1"},token=lab.devices[i].service_token)
    time.sleep(0.6); pre=al("A3-G5")
    for v in (75.0,50.0,25.0,0.0):
        for i in big[4:]: http_json(LOOPBACK,lab.devices[i].port,"POST","/setpoint",{"value":v},token=lab.devices[i].service_token)
        time.sleep(0.4)
    time.sleep(0.6); print("[A3-G5] apos parte legitima: %s | final: div=%.1f export=%.2f kW alertas=%s" % (pre, ss.capacity_divergence_pct(lab.devices)[2], sum(d.export_kw() for d in lab.devices), al("A3-G5")))
    # A4: F-04a evasao — cortar a 26% (acima do limiar 25) em lotes espacados, COM WO
    reset("A4-CURTAIL-26")
    for batch in ([0,1,2,3,4],[5,6,7,8,9],[10,11]):
        for i in batch: http_json(LOOPBACK,PORT_DEV_BASE+i,"POST","/setpoint",{"value":26.0,"work_order":"WO-20261112-MNT1"},token="SUNBOX-SVC-%02d-2026"%i)
        ss.SIM_CLOCK_OFFSET += 61.0
    time.sleep(0.6); ss.emit_capacity_snapshot(lab); e,a_,dv=ss.capacity_divergence_pct(lab.devices)
    print("[A4-CURTAIL-26] esperado=%.2f real=%.2f div=%.1f%% alertas=%s" % (e,a_,dv,al("A4-CURTAIL-26")))
    # A5: HMAC — assinatura do esquema antigo e imagem legitima
    import base64
    reset("A5-HMAC"); evil=b"arbitrary-image"; old="SUNSIG-"+hashlib.sha256(evil).hexdigest()[:32]
    st1,_=http_json(LOOPBACK,PORT_DEV_BASE,"POST","/firmware",{"image_b64":base64.b64encode(evil).decode(),"signature":old},token="SUNBOX-SVC-00-2026")
    st2,_=http_json(LOOPBACK,PORT_DEV_BASE+1,"POST","/firmware",{"image_b64":base64.b64encode(ss.LEGIT_IMAGE).decode(),"signature":ss.sign_image(ss.LEGIT_IMAGE)},token="SUNBOX-SVC-01-2026")
    print("[A5-HMAC] assinatura antiga (sha256 sem chave) -> %s | legitima HMAC -> %s | alertas=%s" % (st1,st2,al("A5-HMAC")))
finally:
    ss.SIM_CLOCK_OFFSET=0.0; lab.stop()

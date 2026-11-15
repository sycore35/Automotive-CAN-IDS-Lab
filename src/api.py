"""
Automotive-CAN-IDS-Lab — FastAPI server: virtual test bench, attack lab, DBC editor, rule designer,
benchmark, SocketCAN status, CAN FD. Binds to 127.0.0.1 only. Everything is an in-memory simulation.
"""
import asyncio
import collections
import json
import os
import time
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException, Query, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from src.attacks import ATTACKS
from src.behavior import VehicleBehaviorAnalyzer
from src.bench import VirtualTestBench
from src.benchmark import run_benchmark
from src.can_bus import export_candump_log, import_candump_log
from src.can_frame import CANFrame
from src.can_ids import CANAlert, CANIntrusionDetectionEngine, LAYER_IDS, LAYER_NAMES
from src.canfd import CANFDFrame
from src.dbc_decoder import DBCDecoder
from src.dbc_editor import DBCEditor
from src.rules_engine import RuleSet
from src.socketcan_backend import SocketCANBackend
from src.storage import CANStorage

app = FastAPI(title="Automotive CAN IDS Lab API", version="2.0.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.environ.get("CAN_LAB_DATA_DIR") or os.path.join(BASE_DIR, "data")
PORT = int(os.environ.get("CAN_LAB_PORT", "8003"))
CONFIG_PATH = os.path.join(BASE_DIR, "config", "can_signals.json")
os.makedirs(DATA_DIR, exist_ok=True)

dbc = DBCDecoder(CONFIG_PATH)
_persisted = DBCEditor.load_persisted(os.path.join(DATA_DIR, "dbc_live.json"))
if _persisted:
    dbc.load_config(_persisted)
dbc_editor = DBCEditor(dbc, persist_path=os.path.join(DATA_DIR, "dbc_live.json"))
ids_engine = CANIntrusionDetectionEngine(dbc)
ids_engine.custom_rules = RuleSet(os.path.join(DATA_DIR, "custom_rules.json"))
behavior = VehicleBehaviorAnalyzer()
bench = VirtualTestBench(dbc, ids_engine, behavior, seed=1)
storage = CANStorage(os.path.join(DATA_DIR, "can_events.db"))
socketcan = SocketCANBackend("vcan0")

active_connections: List[WebSocket] = []
simulation_task: Optional[asyncio.Task] = None
paused = False
trace: collections.deque = collections.deque(maxlen=400)
bus_load_hist: collections.deque = collections.deque(maxlen=120)
_alert_last: Dict[Any, float] = {}
benchmark_state: Dict[str, Any] = {"status": "idle", "result": None, "error": None, "stage": ""}

VALID_SCENARIOS = {"normal", "unauthorized_uds"} | set(ATTACKS)


class ScenarioRequest(BaseModel):
    scenario: str
    duration: float = 4.0


class AttackRequest(BaseModel):
    attack: str
    duration: float = 6.0
    params: Dict[str, Any] = {}
    combine: bool = False


class ReplayLogRequest(BaseModel):
    log: str


class TuneRequest(BaseModel):
    max_accel_kmh_per_sec: float = 45.0
    timing_jitter_tolerance_pct: float = 80.0
    bus_load_alert_pct: float = 75.0
    replay_duplicate_window_ms: float = 15.0


class DriverRequest(BaseModel):
    mode: Optional[str] = None
    target_speed_kmh: Optional[float] = None
    throttle_pct: Optional[float] = None
    brake_pct: Optional[float] = None
    steering_deg: Optional[float] = None


class StepRequest(BaseModel):
    seconds: float = 1.0


class DecodeRequest(BaseModel):
    id: int
    data_hex: str


class TextRequest(BaseModel):
    text: str


class BenchmarkRequest(BaseModel):
    seed: int = 1
    duration: float = 8.0
    attack_start: float = 2.0
    attack_len: float = 4.0


class FDRequest(BaseModel):
    id: int = 0x400
    data_hex: str = ""
    brs: bool = True
    pad: bool = True
    send: bool = False


def _vba_to_alert(a: Dict[str, Any]) -> CANAlert:
    return CANAlert(rule_id=a["rule_id"], rule_name=a["rule_name"], severity=a["severity"], arbitration_id=0,
                    hex_id="-", message_name="BEHAVIOR", observed_value=a["observed_value"],
                    expected_threshold=a["expected_threshold"], evidence=a["evidence"],
                    mitigation="Cross-check redundant sensors; treat the inconsistent signal as untrusted.",
                    raw_frame_hex="", timestamp=a["timestamp"], qev_event_id="QEV_BEHAVIOR_INCONSISTENCY",
                    unece_r155_code="BEHAVIOR_ANALYSIS")


def process_records(records) -> List[Dict[str, Any]]:
    """Store/trace the frames of one tick and return the (rate-limited) alerts to publish."""
    if not records:
        return []
    out: List[CANAlert] = []
    for r in records:
        for a in r.ids_alerts + [_vba_to_alert(v) for v in r.vba_alerts]:
            key = (a.rule_id, a.arbitration_id)
            if a.timestamp - _alert_last.get(key, -1e9) >= 0.25:
                _alert_last[key] = a.timestamp
                out.append(a)
    sample = records[-120:]
    for r in sample[-40:]:
        f = r.d.frame
        dec = dbc.decode_frame(f)
        trace.append({**f.to_dict(), "name": dec.get("name"), "attack": r.attack, "latency_us": round(r.d.latency_s * 1e6, 1),
                      "arb_losses": r.d.arb_losses,
                      "signals": {k: v["value"] for k, v in list(dec.get("signals", {}).items())[:4]},
                      "alerted": bool(r.ids_alerts)})
    bus_load_hist.append(round(bench.bus.load_pct, 1))
    storage.save_batch([r.d.frame for r in sample], out, bench.bus.load_pct)
    if socketcan.available:
        for r in sample:
            socketcan.mirror(r.d.frame)
    return [a.to_dict() for a in out]


def telemetry_payload(new_alerts: List[Dict[str, Any]], frames) -> Dict[str, Any]:
    t = bench.telemetry()
    return {
        "timestamp": round(bench.t, 3),
        "vehicle": {"speed_kmh": round(t["speed_kmh"], 1), "engine_rpm": round(t["rpm"]), "gear": t["gear"],
                    "throttle_pct": t["throttle_pct"], "brake_bar": t["brake_bar"], "steering_deg": t["steering_deg"],
                    "engine_temp": t["engine_temp"], "odometer_km": round(t["odometer_km"], 2),
                    "cluster_speed_kmh": t["cluster_speed_kmh"], "lamps": t["lamps"], "shifting": t["shifting"],
                    "scenario": next(iter(bench.attacks), "normal"), "driver": t["driver"]},
        "bus": {**bench.bus.stats(), "current_bus_load_pct": round(bench.bus.load_pct, 2),
                "total_frames_sent": bench.bus.total_frames, "load_history": list(bus_load_hist)[-60:]},
        "frames": [r.d.frame.to_dict() | {"attack": r.attack} for r in frames[-5:]],
        "new_alerts": new_alerts,
        "attacks": bench.status(),
    }


async def simulation_loop():
    last = time.time()
    while True:
        now = time.time()
        dt = max(0.001, min(0.1, now - last))
        last = now
        if not paused:
            records = bench.advance(dt)
            new_alerts = process_records(records)
        else:
            records, new_alerts = [], []
        if active_connections:
            payload = telemetry_payload(new_alerts, records)
            for ws in list(active_connections):
                try:
                    await ws.send_json(payload)
                except Exception:
                    if ws in active_connections:
                        active_connections.remove(ws)
        await asyncio.sleep(0.04)


@app.on_event("startup")
async def startup_event():
    global simulation_task
    storage.log_audit("SERVICE_STARTUP", {"port": PORT, "host": "127.0.0.1"})
    simulation_task = asyncio.create_task(simulation_loop())


@app.on_event("shutdown")
async def shutdown_event():
    if simulation_task:
        simulation_task.cancel()
    storage.log_audit("SERVICE_SHUTDOWN", {})


@app.get("/api/health")
async def health_check():
    s = ids_engine.get_summary()
    return {"status": "HEALTHY", "service": "Automotive-CAN-IDS-Lab", "port": PORT,
            "mode": "VIRTUAL_IN_MEMORY_CAN", "total_frames_sent": bench.bus.total_frames,
            "bus_load_pct": round(bench.bus.load_pct, 2), "active_scenario": next(iter(bench.attacks), "normal"),
            "total_alerts": s["total_alerts"], "rule_hits": s["rule_hits"], "virtual_time_s": round(bench.t, 2),
            "socketcan": socketcan.status()["available"], "paused": paused}


@app.get("/api/telemetry")
async def get_telemetry():
    t = bench.telemetry()
    return {"speed_kmh": round(t["speed_kmh"], 1), "engine_rpm": round(t["rpm"]), "gear": t["gear"],
            "throttle_pct": t["throttle_pct"], "brake_bar": t["brake_bar"], "steering_deg": t["steering_deg"],
            "engine_temp": t["engine_temp"], "odometer_km": round(t["odometer_km"], 2),
            "cluster_speed_kmh": t["cluster_speed_kmh"],
            "active_scenario": next(iter(bench.attacks), "normal"),
            "bus": {**bench.bus.stats(), "current_bus_load_pct": round(bench.bus.load_pct, 2),
                    "total_frames_sent": bench.bus.total_frames}}


@app.get("/api/alerts")
async def get_alerts(limit: int = Query(50, ge=1, le=500)):
    return storage.get_recent_alerts(limit=limit)


@app.get("/api/frames")
async def get_frames(limit: int = Query(50, ge=1, le=500)):
    return storage.get_recent_frames(limit=limit)


@app.post("/api/scenarios/start")
async def start_scenario(req: ScenarioRequest):
    if req.scenario not in VALID_SCENARIOS:
        raise HTTPException(status_code=400, detail=f"Invalid scenario '{req.scenario}'. Allowed: {sorted(VALID_SCENARIOS)}")
    if req.scenario == "normal":
        bench.stop_attacks()
    else:
        bench.start_attack(req.scenario, duration=req.duration)
    storage.log_audit("SCENARIO_STARTED", {"scenario": req.scenario, "duration": req.duration})
    return {"status": "SCENARIO_ACTIVATED", "scenario": req.scenario, "duration": req.duration}


@app.post("/api/scenarios/stop")
async def stop_scenario():
    bench.stop_attacks()
    storage.log_audit("SCENARIO_STOPPED", {})
    return {"status": "SCENARIO_STOPPED", "active_scenario": "normal"}


@app.post("/api/rules/tune")
async def tune_rules(req: TuneRequest):
    d = req.model_dump()
    ids_engine.tune_thresholds(d)
    storage.log_audit("RULES_TUNED", d)
    return {"status": "THRESHOLDS_UPDATED", "summary": ids_engine.get_summary()}


@app.post("/api/reset")
async def reset_lab():
    bench.stop_attacks()
    bench.reset()
    ids_engine.rule_hit_counts.clear()
    ids_engine.alerts.clear()
    trace.clear()
    bus_load_hist.clear()
    _alert_last.clear()
    storage.clear_all()
    storage.log_audit("LAB_RESET", {})
    return {"status": "LAB_RESET_SUCCESS"}


@app.get("/api/export/incident")
async def export_incident():
    bundle = storage.export_incident_bundle()
    bundle["candump_log"] = export_candump_log([d.frame for d in list(bench.bus.history)[-1000:]])
    return JSONResponse(content=bundle)


@app.post("/api/frames/replay-log")
async def replay_candump_log(req: ReplayLogRequest):
    n = 0
    for f in import_candump_log(req.log):
        if bench.inject(f):
            n += 1
    storage.log_audit("CANDUMP_LOG_REPLAYED", {"count": n})
    return {"status": "REPLAY_COMPLETED", "frames_replayed": n}


@app.get("/api/bench/state")
async def bench_state():
    return {"virtual_time_s": round(bench.t, 3), "paused": paused, "telemetry": bench.telemetry(),
            "ecus": bench.ecu_info(), "bus": bench.bus.stats(), "attacks": bench.status(),
            "layers": layer_list()}


@app.post("/api/bench/step")
async def bench_step(req: StepRequest):
    """Advance the simulation manually (useful when paused, and for deterministic tests)."""
    secs = max(0.0, min(30.0, req.seconds))
    recs = bench.advance(secs)
    alerts = process_records(recs)
    return {"advanced_s": secs, "frames": len(recs), "new_alerts": alerts, "virtual_time_s": round(bench.t, 3)}


@app.post("/api/bench/pause")
async def bench_pause(pause: bool = True):
    global paused
    paused = pause
    return {"paused": paused}


@app.post("/api/bench/driver")
async def bench_driver(req: DriverRequest):
    if req.mode is not None and req.mode not in ("auto", "manual"):
        raise HTTPException(400, "mode must be 'auto' or 'manual'")
    inp = bench.set_driver(**req.model_dump())
    return {"mode": inp.mode, "target_speed_kmh": inp.target_speed_kmh, "throttle_pct": inp.throttle_pct,
            "brake_pct": inp.brake_pct, "steering_deg": inp.steering_deg}


@app.post("/api/bench/ecu/{name}/online")
async def ecu_online(name: str, online: bool = True):
    if name not in bench.ecus:
        raise HTTPException(404, f"unknown ECU {name}")
    bench.ecus[name].online = online
    return {"ecu": name, "online": online}


@app.get("/api/bus/trace")
async def bus_trace(limit: int = Query(100, ge=1, le=400)):
    return list(trace)[-limit:]


@app.get("/api/bus/stats")
async def bus_stats():
    return bench.bus.stats()


@app.get("/api/uds/log")
async def uds_log():
    return ids_engine.uds_log


@app.get("/api/attacks")
async def attack_catalog():
    return [{"id": c.id, "name": c.name, "description": c.description, "category": c.category,
             "defaults": c.defaults, "expected_layers": list(c.expected_layers)} for c in ATTACKS.values()]


@app.post("/api/attacks/run")
async def attack_run(req: AttackRequest):
    if req.attack not in ATTACKS and req.attack != "unauthorized_uds":
        raise HTTPException(400, f"Unknown attack '{req.attack}'. Allowed: {sorted(ATTACKS)}")
    try:
        atk = bench.start_attack(req.attack, req.params, req.duration, replace=not req.combine)
    except (ValueError, TypeError) as exc:
        raise HTTPException(400, f"Invalid attack parameters: {exc}")
    storage.log_audit("ATTACK_STARTED", {"attack": atk.id, "duration": req.duration, "params": req.params})
    return {"status": "ATTACK_STARTED", "attack": atk.id, "duration": atk.duration}


@app.post("/api/attacks/stop")
async def attack_stop():
    bench.stop_attacks()
    return {"status": "ATTACKS_STOPPED"}


@app.get("/api/attacks/status")
async def attack_status():
    return bench.status()


@app.get("/api/behavior")
async def behavior_status():
    return {**behavior.summary(), "alerts": list(behavior.alerts)[-50:]}


def layer_list():
    return [{"id": l, "name": LAYER_NAMES[l], "enabled": l in ids_engine.enabled_layers,
             "hits": sum(v for k, v in ids_engine.rule_hit_counts.items() if k.startswith(l))} for l in LAYER_IDS]


@app.get("/api/rules/layers")
async def get_layers():
    return layer_list()


@app.post("/api/rules/layers/{layer_id}")
async def set_layer(layer_id: str, enabled: bool = True):
    try:
        ids_engine.set_layer_enabled(layer_id, enabled)
    except KeyError:
        raise HTTPException(404, f"unknown layer {layer_id}")
    return layer_list()


@app.get("/api/rules/custom")
async def list_rules():
    return ids_engine.custom_rules.list()


@app.post("/api/rules/custom")
async def create_rule(rule: Dict[str, Any]):
    try:
        return ids_engine.custom_rules.add(rule)
    except (ValueError, TypeError) as exc:
        raise HTTPException(422, str(exc))


@app.put("/api/rules/custom/{rid}")
async def update_rule(rid: str, rule: Dict[str, Any]):
    try:
        return ids_engine.custom_rules.update(rid, rule)
    except KeyError:
        raise HTTPException(404, f"rule {rid} not found")
    except (ValueError, TypeError) as exc:
        raise HTTPException(422, str(exc))


@app.delete("/api/rules/custom/{rid}")
async def delete_rule(rid: str):
    try:
        ids_engine.custom_rules.delete(rid)
    except KeyError:
        raise HTTPException(404, f"rule {rid} not found")
    return {"deleted": rid}


@app.post("/api/rules/custom/test")
async def test_rule(body: Dict[str, Any]):
    """Dry-run a candidate rule against one frame without touching live state."""
    try:
        rs = RuleSet(None)
        rs.add(body["rule"])
        f = CANFrame(int(body["id"]), bytes.fromhex(str(body.get("data_hex", "")).replace(" ", "")), timestamp=1.0)
    except (ValueError, KeyError, TypeError) as exc:
        raise HTTPException(422, str(exc))
    hits = rs.evaluate(f, dbc.decode_frame(f), ids_engine)
    return {"match": bool(hits), "alerts": [h.to_dict() for h in hits]}


@app.get("/api/dbc")
async def dbc_get():
    return dbc_editor.snapshot()


def _dbc_call(fn, *a):
    try:
        return fn(*a)
    except KeyError as exc:
        raise HTTPException(404, str(exc).strip("'\""))
    except (ValueError, TypeError) as exc:
        raise HTTPException(422, str(exc))


@app.post("/api/dbc/messages")
async def dbc_add_message(msg: Dict[str, Any]):
    return _dbc_call(dbc_editor.add_message, msg)


@app.put("/api/dbc/messages/{msg_id}")
async def dbc_update_message(msg_id: int, patch: Dict[str, Any]):
    return _dbc_call(dbc_editor.update_message, msg_id, patch)


@app.delete("/api/dbc/messages/{msg_id}")
async def dbc_delete_message(msg_id: int):
    _dbc_call(dbc_editor.delete_message, msg_id)
    return {"deleted": msg_id}


@app.post("/api/dbc/messages/{msg_id}/signals")
async def dbc_add_signal(msg_id: int, sig: Dict[str, Any]):
    return _dbc_call(dbc_editor.add_signal, msg_id, sig)


@app.put("/api/dbc/messages/{msg_id}/signals/{name}")
async def dbc_update_signal(msg_id: int, name: str, patch: Dict[str, Any]):
    return _dbc_call(dbc_editor.update_signal, msg_id, name, patch)


@app.delete("/api/dbc/messages/{msg_id}/signals/{name}")
async def dbc_delete_signal(msg_id: int, name: str):
    return _dbc_call(dbc_editor.delete_signal, msg_id, name)


@app.get("/api/dbc/export", response_class=PlainTextResponse)
async def dbc_export():
    return dbc_editor.export_text()


@app.post("/api/dbc/import")
async def dbc_import(req: TextRequest):
    return _dbc_call(dbc_editor.import_text, req.text)


@app.post("/api/dbc/decode")
async def dbc_decode(req: DecodeRequest):
    return _dbc_call(dbc_editor.decode_preview, req.id, req.data_hex)


@app.post("/api/dbc/reset")
async def dbc_reset():
    dbc.load_config(DBCDecoder(CONFIG_PATH).config)
    dbc_editor._commit(dbc_editor._working_copy())
    return dbc_editor.snapshot()


def _bench_worker(req: BenchmarkRequest):
    try:
        benchmark_state.update(status="running", error=None, stage="starting")
        res = run_benchmark(dbc_editor._working_copy(), req.seed, req.duration, req.attack_start, req.attack_len,
                            progress=lambda s: benchmark_state.update(stage=s))
        benchmark_state.update(status="done", result=res, stage="done")
    except Exception as exc:  # surfaced in the UI
        benchmark_state.update(status="error", error=f"{type(exc).__name__}: {exc}")


@app.post("/api/benchmark/run")
async def benchmark_run(req: BenchmarkRequest):
    if benchmark_state["status"] == "running":
        raise HTTPException(409, "benchmark already running")
    if not (4.0 <= req.duration <= 30.0) or not (0.5 <= req.attack_len <= req.duration - req.attack_start):
        raise HTTPException(422, "duration must be 4..30 s and the attack must fit inside it")
    benchmark_state.update(status="running", result=None, error=None, stage="queued")
    asyncio.get_running_loop().run_in_executor(None, _bench_worker, req)
    return {"status": "running"}


@app.get("/api/benchmark/status")
async def benchmark_status():
    return benchmark_state


@app.get("/api/socketcan/status")
async def socketcan_status():
    return socketcan.status()


@app.post("/api/socketcan/connect")
async def socketcan_connect():
    return socketcan.probe()


@app.post("/api/canfd/encode")
async def canfd_encode(req: FDRequest):
    try:
        raw = bytes.fromhex(req.data_hex.replace(" ", ""))
        f = CANFDFrame.padded(req.id, raw, brs=req.brs) if req.pad else CANFDFrame(req.id, raw, brs=req.brs)
    except ValueError as exc:
        raise HTTPException(422, str(exc))
    info = f.describe()
    info["padded_bytes"] = len(f.data) - len(raw)
    if req.send:
        f.source = "TESTER_FD"
        info["queued"] = bench.inject(f.to_can_frame())
    return info


@app.get("/api/canfd/info")
async def canfd_info():
    from src.canfd import FD_DLC_TO_LEN
    return {"dlc_to_len": FD_DLC_TO_LEN, "max_payload": 64, "data_bitrate_kbps": bench.bus.data_bitrate / 1000,
            "nominal_bitrate_kbps": bench.bus.bitrate / 1000}


@app.websocket("/ws/telemetry")
async def websocket_telemetry(websocket: WebSocket):
    await websocket.accept()
    active_connections.append(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        if websocket in active_connections:
            active_connections.remove(websocket)


UI_DIR = os.path.join(BASE_DIR, "src", "ui")
if os.path.exists(UI_DIR):
    app.mount("/", StaticFiles(directory=UI_DIR, html=True), name="ui")

"""PredictShield AI engine - real inference.

Per flow (77 CICFlowMeter features):
  1. scale with the training StandardScaler (models/cicids2017_scaler.pkl)
  2. append to a per-device rolling buffer of the last 50 flows
  3. buffer full  -> 5-model fusion verdict via ONNX
     buffer < 50  -> XGBoost fallback on the last flow (warmup)

Artifacts live in ./models - see models/README.md. Missing artifacts degrade
gracefully: /ai/predict answers with model_status="not_deployed".
"""
import asyncio
import hashlib
import hmac
import ipaddress
import json
import os
import queue
import subprocess
import threading
import time
import urllib.request
from collections import Counter, deque
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any, Dict, List

import numpy as np
from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

MODELS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "models")
SEQ_LEN = 50
N_FEATURES = 77
N_CLASSES = 15


def _path(name: str) -> str:
    return os.path.join(MODELS_DIR, name)


FUSION_ONNX = _path("fusion_mlp_v2.onnx")
XGB_ONNX = _path("xgboost_cicids2017_v2.onnx")
XGB_PKL = _path("xgboost_cicids2017_v2.pkl")
LSTM_ONNX = _path("lstm_cicids2017.onnx")
TRANS_ONNX = _path("transformer_cicids2017.onnx")
IF_PKL = _path("isolation_forest_cicids2017_v2.pkl")
FLOW_SCALER_PKL = _path("cicids2017_scaler.pkl")
FUSION_SCALER_JSON = _path("fusion_scaler.json")
FUSION_CALIB_JSON = _path("fusion_calib.json")
LABEL_MAP_JSON = _path("label_map.json")
GNN_ONNX = _path("gat.onnx")
GNN_SCALER_JSON = _path("gnn_scaler.json")

# Admin gate for the monitoring dashboard (separate from HomeVlog login).
# Credentials come from the environment file - never hardcoded in git.
ADMIN_USER = os.getenv("ADMIN_USER", "")
ADMIN_PASS = os.getenv("ADMIN_PASS", "").strip('"')


def _admin_token() -> str:
    """Day-scoped admin token (stateless, survives engine restarts)."""
    day = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    return hashlib.sha256(
        f"ps-admin|{ADMIN_USER}|{ADMIN_PASS}|{day}".encode()
    ).hexdigest()


def _require_admin(
    request: Request,
    x_admin_token: str = Header(default=""),
    token: str = Query(default=""),
) -> None:
    supplied = x_admin_token or token
    if not ADMIN_USER or not supplied or supplied != _admin_token():
        raise HTTPException(status_code=401, detail="Admin auth required")

RISK_ACTIONS = {
    "BENIGN": ["allow"],
    "Bot": ["isolate device", "block outbound C2 traffic", "notify SOC"],
    "DDoS": ["enable rate limiting", "deploy traffic scrubbing", "notify SOC"],
    "DoS GoldenEye": ["rate limit HTTP", "block source IP", "notify SOC"],
    "DoS Hulk": ["rate limit HTTP", "block source IP", "notify SOC"],
    "DoS Slowhttptest": ["enforce HTTP timeouts", "block source IP", "notify SOC"],
    "DoS slowloris": ["enforce HTTP timeouts", "block source IP", "notify SOC"],
    "FTP-Patator": ["block source IP", "enforce strong FTP credentials", "notify SOC"],
    "Heartbleed": ["patch OpenSSL", "isolate device", "rotate exposed secrets"],
    "Infiltration": ["isolate device", "preserve forensic evidence", "notify SOC"],
    "PortScan": ["firewall alert", "throttle source IP", "log for recon analysis"],
    "SSH-Patator": ["block source IP", "enforce SSH key auth", "notify SOC"],
    "Web Attack Brute Force": ["enforce account lockout", "block source IP", "notify SOC"],
    "Web Attack Sql Injection": ["WAF rule: SQLi", "block source IP", "audit database"],
    "Web Attack XSS": ["WAF rule: XSS", "sanitize input", "audit web app"],
}

_state: Dict[str, Any] = {
    "fusion": None,
    "xgb": None,
    "iso": None,
    "flow_scaler": None,
    "fusion_scaler": None,
    "temperature": 1.0,
    "label_map": {},
    "buffers": {},
    "gnn": None,
}

# In-memory live monitor: every real verdict is recorded here so the
# /admin/report dashboard can show live stats and the recent attack feed.
# Deliberately not persisted - restart resets counters (bounded memory).
_MONITOR: Dict[str, Any] = {
    "flows_total": 0,
    "attacks_total": 0,
    "by_class": {},
    "by_risk": {"HIGH": 0, "MEDIUM": 0, "LOW": 0},
    "devices": {},                          # device_id -> last epoch ts
    "recent_flows": deque(maxlen=5000),     # (ts, is_attack) for last-hour stats
    "alerts": deque(maxlen=1000),           # attack verdicts, oldest -> newest
}

# Monitoring session (demo/live-ops): press START on the dashboard and every
# stat/alert is counted from that moment only. Purely a view over the data -
# DB history keeps recording everything regardless.
_session: Dict[str, Any] = {
    "active": False,
    "started_at": None,      # engine-clock epoch (in-memory stats use this)
    "db_started_at": None,   # DB-clock epoch (DB session queries use this)
    "ended_at": None,
    "devices": set(),
}

# Per-source-IP stats (in-memory, session-agnostic; DB keeps the durable copy
# in ai_flow_events.src_ip). ip -> {flows, attacks, by_class, last_ts}
_IPS: Dict[str, Dict[str, Any]] = {}

# IP geolocation cache (ip-api.com free tier, resolved lazily on demand)
_GEO_CACHE: Dict[str, Dict[str, Any]] = {}

# Blocked source IPs: ip -> until (engine-clock epoch). Persisted in
# ai_blocked_ips; blocked flows are rejected with 403 at /ai/predict AND
# dropped at the network firewall (web ports 80/443, SSH untouched).
_BLOCKED: Dict[str, float] = {}
_BLOCK_META: Dict[str, Dict[str, Any]] = {}
FIREWALL_HELPER = "/usr/local/bin/ps-firewall"


def _firewall_sync():
    """Make the iptables ruleset match the active blocklist. Best-effort:
    if the firewall call fails, the engine-level 403 gate still applies."""
    if not _BLOCKED:
        return
    try:
        active = [ip for ip, until in _BLOCKED.items()
                  if until > time.time() and not _is_private_ip(ip)]
        subprocess.run(["sudo", "-n", FIREWALL_HELPER, "sync", *active],
                       check=False, capture_output=True, timeout=15)
    except Exception as exc:
        print(f"[block] firewall sync failed (engine 403 gate still active): {exc}")


def _record(device_id: str, resp: "PredictResponse", src_ip: str = None) -> None:
    """Record a real verdict (warmup_xgboost / fusion_5model) into the monitor."""
    if resp.model_status not in ("warmup_xgboost", "fusion_5model"):
        return
    now = time.time()
    is_attack = resp.attack_class not in ("BENIGN", "unknown")
    _MONITOR["flows_total"] += 1
    _MONITOR["recent_flows"].append((now, is_attack))
    _enqueue_flow(device_id, is_attack, src_ip)
    devices = _MONITOR["devices"]
    devices[device_id] = now
    if _session["active"]:
        _session["devices"].add(device_id)
    if len(devices) > 500:
        cutoff = now - 7200
        for key in [k for k, t in devices.items() if t < cutoff]:
            devices.pop(key, None)
    if src_ip:
        st = _IPS.setdefault(src_ip, {"flows": 0, "attacks": 0, "by_class": {}, "last_ts": 0.0})
        st["flows"] += 1
        st["last_ts"] = now
    if is_attack:
        _MONITOR["attacks_total"] += 1
        by_class = _MONITOR["by_class"]
        by_class[resp.attack_class] = by_class.get(resp.attack_class, 0) + 1
        if resp.risk_level in _MONITOR["by_risk"]:
            _MONITOR["by_risk"][resp.risk_level] += 1
        if src_ip:
            st = _IPS[src_ip]
            st["attacks"] += 1
            st["by_class"][resp.attack_class] = st["by_class"].get(resp.attack_class, 0) + 1
        alert = {
            "ts": now,
            "device_id": device_id,
            "src_ip": src_ip,
            "attack_class": resp.attack_class,
            "confidence": resp.confidence,
            "risk_level": resp.risk_level,
            "model_status": resp.model_status,
            "defense_actions": resp.defense_actions,
        }
        _MONITOR["alerts"].append(alert)
        _enqueue_alert(alert)


def _build_stats(since: float = None) -> dict:
    now = time.time()
    recent = _MONITOR["recent_flows"]
    while recent and recent[0][0] < now - 3600:
        recent.popleft()
    if since is not None:
        in_session = [t for t in recent if t[0] >= since]
        flows_count = len(in_session)
        attacks_count = sum(1 for _, a in in_session if a)
        session_alerts = [a for a in _MONITOR["alerts"] if a["ts"] >= since]
        by_class: Dict[str, int] = {}
        by_risk = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for a in session_alerts:
            by_class[a["attack_class"]] = by_class.get(a["attack_class"], 0) + 1
            if a["risk_level"] in by_risk:
                by_risk[a["risk_level"]] += 1
        active_devices = len(_session["devices"])
        recent_alerts = session_alerts[-12:][::-1]
        top_ips = []
        for a in session_alerts:
            ip = a.get("src_ip")
            if not ip or _is_private_ip(ip):
                continue
            e = next((t for t in top_ips if t["ip"] == ip), None)
            if e:
                e["attacks"] += 1
            else:
                top_ips.append({"ip": ip, "flows": 0, "attacks": 1})
        top_ips = sorted(top_ips, key=lambda t: -t["attacks"])[:8]
    else:
        attacks_count = sum(1 for _, a in recent if a)
        flows_count = len(recent)
        active_devices = sum(1 for t in _MONITOR["devices"].values() if t >= now - 3600)
        by_class = dict(sorted(_MONITOR["by_class"].items(), key=lambda kv: -kv[1]))
        by_risk = dict(_MONITOR["by_risk"])
        recent_alerts = list(_MONITOR["alerts"])[-12:][::-1]
        top_ips = []
        for ip, v in sorted(_IPS.items(), key=lambda kv: (-kv[1]["flows"], -kv[1]["attacks"])):
            if _is_private_ip(ip):
                continue
            top_ips.append({"ip": ip, "flows": v["flows"], "attacks": v["attacks"],
                            "last_ts": v["last_ts"]})
            if len(top_ips) >= 8:
                break
    gnn = _state["gnn"]
    for t in top_ips:
        t["gnn_risk"] = round(gnn.latest_risk(t["ip"]), 3) if gnn else None
    return {
        "ts": now,
        "flows_total": _MONITOR["flows_total"] if since is None else flows_count,
        "attacks_total": _MONITOR["attacks_total"] if since is None else attacks_count,
        "flows_last_hour": flows_count,
        "attacks_last_hour": attacks_count,
        "active_devices": active_devices,
        "attacks_by_class": by_class,
        "risk_levels": by_risk,
        "recent_alerts": recent_alerts,
        "top_ips": top_ips,
    }


def _finish(device_id: str, resp: "PredictResponse", src_ip: str = None) -> "PredictResponse":
    _record(device_id, resp, src_ip)
    return resp


# ---------------------------------------------------------------------------
# Persistent history (PostgreSQL). When DATABASE_URL is set, every verdict is
# queued to a background writer that batches inserts into the same database
# the HomeVlog platform uses. Stats/alerts read from the DB; if the DB is
# unreachable the engine falls back to the in-memory monitor above.
# ---------------------------------------------------------------------------
DB_URL = os.getenv("DATABASE_URL", "")
if DB_URL.startswith("postgres://"):
    DB_URL = "postgresql://" + DB_URL[len("postgres://"):]

_DB_SCHEMA = """
CREATE TABLE IF NOT EXISTS ai_counters (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    flows_total BIGINT NOT NULL DEFAULT 0
);
INSERT INTO ai_counters (id, flows_total) VALUES (1, 0)
    ON CONFLICT (id) DO NOTHING;
CREATE TABLE IF NOT EXISTS ai_class_totals (
    attack_class VARCHAR(64) PRIMARY KEY,
    total BIGINT NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS ai_risk_totals (
    risk_level VARCHAR(16) PRIMARY KEY,
    total BIGINT NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS ai_alerts (
    id BIGSERIAL PRIMARY KEY,
    ts TIMESTAMPTZ NOT NULL DEFAULT now(),
    device_id VARCHAR(100),
    attack_class VARCHAR(64),
    confidence REAL,
    risk_level VARCHAR(16),
    model_status VARCHAR(32),
    defense_actions JSONB NOT NULL DEFAULT '[]'::jsonb
);
CREATE INDEX IF NOT EXISTS ai_alerts_ts_idx ON ai_alerts (ts DESC);
CREATE TABLE IF NOT EXISTS ai_flow_events (
    id BIGSERIAL PRIMARY KEY,
    ts TIMESTAMPTZ NOT NULL DEFAULT now(),
    device_id VARCHAR(100),
    is_attack BOOLEAN NOT NULL
);
CREATE INDEX IF NOT EXISTS ai_flow_events_ts_idx ON ai_flow_events (ts DESC);
CREATE TABLE IF NOT EXISTS ai_hourly (
    bucket TIMESTAMPTZ PRIMARY KEY,
    flows BIGINT NOT NULL DEFAULT 0,
    attacks BIGINT NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS ai_blocked_ips (
    ip VARCHAR(64) PRIMARY KEY,
    blocked_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    until TIMESTAMPTZ NOT NULL,
    reason VARCHAR(200)
);
-- migrations for source-IP visibility
ALTER TABLE ai_alerts ADD COLUMN IF NOT EXISTS src_ip VARCHAR(64);
ALTER TABLE ai_flow_events ADD COLUMN IF NOT EXISTS src_ip VARCHAR(64);
"""

_DB: Dict[str, Any] = {
    "enabled": False,
    "conn": None,
    "q": None,
    "last_cleanup": 0.0,
}

DB_RETENTION = {
    "flow_events": 2 * 3600,   # only needed for last-hour stats / active devices
    "alerts": 7 * 86400,       # attack alert history
    "hourly": 30 * 86400,      # per-hour rollup for the history endpoint
}


def _db_get_conn():
    conn = _DB["conn"]
    if conn is not None and not conn.closed:
        return conn
    import psycopg

    conn = psycopg.connect(DB_URL, connect_timeout=10, autocommit=True)
    _DB["conn"] = conn
    return conn


def _db_flush(batch: List[Dict[str, Any]], tries: int = 0) -> None:
    """Write one batch of verdicts atomically; on failure requeue up to 3
    attempts, then drop (in-memory still has the data)."""
    try:
        conn = _db_get_conn()
        events = [b for b in batch if b["type"] == "flow"]
        alerts = [b for b in batch if b["type"] == "attack"]
        cur = conn.cursor()
        with conn.transaction():
            if events:
                cur.executemany(
                    "INSERT INTO ai_flow_events (device_id, is_attack, src_ip) VALUES (%s, %s, %s)",
                    [(b["device_id"], b["is_attack"], b.get("src_ip")) for b in events],
                )
                conn.execute(
                    "UPDATE ai_counters SET flows_total = flows_total + %s WHERE id = 1",
                    (len(events),),
                )
                hour_flows = Counter(b["hour"] for b in events)
                hour_attacks = Counter(b["hour"] for b in events if b["is_attack"])
                for hour, flows in hour_flows.items():
                    conn.execute(
                        """
                        INSERT INTO ai_hourly (bucket, flows, attacks)
                        VALUES (date_trunc('hour', now()), %s, %s)
                        ON CONFLICT (bucket) DO UPDATE SET
                            flows = ai_hourly.flows + EXCLUDED.flows,
                            attacks = ai_hourly.attacks + EXCLUDED.attacks
                        """,
                        (flows, hour_attacks.get(hour, 0)),
                    )
            if alerts:
                from psycopg.types.json import Json

                cur.executemany(
                    """
                    INSERT INTO ai_alerts
                        (device_id, src_ip, attack_class, confidence, risk_level, model_status, defense_actions)
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
                    """,
                    [
                        (
                            b["device_id"], b.get("src_ip"), b["attack_class"], b["confidence"],
                            b["risk_level"], b["model_status"],
                            Json(b["defense_actions"]),
                        )
                        for b in alerts
                    ],
                )
                class_totals = Counter(b["attack_class"] for b in alerts)
                for cls, n in class_totals.items():
                    conn.execute(
                        """
                        INSERT INTO ai_class_totals (attack_class, total)
                        VALUES (%s, %s)
                        ON CONFLICT (attack_class) DO UPDATE SET
                            total = ai_class_totals.total + EXCLUDED.total
                        """,
                        (cls, n),
                    )
                risk_totals = Counter(b["risk_level"] for b in alerts)
                for risk, n in risk_totals.items():
                    conn.execute(
                        """
                        INSERT INTO ai_risk_totals (risk_level, total)
                        VALUES (%s, %s)
                        ON CONFLICT (risk_level) DO UPDATE SET
                            total = ai_risk_totals.total + EXCLUDED.total
                        """,
                        (risk, n),
                    )

            now = time.time()
            if now - _DB["last_cleanup"] > 300:
                _DB["last_cleanup"] = now
                conn.execute(
                    "DELETE FROM ai_flow_events WHERE ts < now() - %s::interval",
                    (f"{DB_RETENTION['flow_events'] // 3600} hours",),
                )
                conn.execute(
                    "DELETE FROM ai_alerts WHERE ts < now() - %s::interval",
                    (f"{DB_RETENTION['alerts'] // 86400} days",),
                )
                conn.execute(
                    "DELETE FROM ai_hourly WHERE bucket < now() - %s::interval",
                    (f"{DB_RETENTION['hourly'] // 86400} days",),
                )
                conn.execute("DELETE FROM ai_blocked_ips WHERE until < now()")
                _firewall_sync()  # drop firewall rules for expired blocks
    except Exception as exc:
        try:
            if _DB["conn"] is not None:
                _DB["conn"].close()
        except Exception:
            pass
        _DB["conn"] = None
        if tries < 2 and _DB["q"] is not None:
            try:
                _DB["q"].put({"type": "retry", "items": batch, "tries": tries + 1})
                print(f"[db] write failed, requeued (attempt {tries + 1}): {exc}")
                return
            except queue.Full:
                pass
        print(f"[db] write failed, batch of {len(batch)} dropped: {exc}")


def _db_writer() -> None:
    while True:
        item = _DB["q"].get()
        tries = 0
        if isinstance(item, dict) and item.get("type") == "retry":
            batch = item["items"]
            tries = item["tries"]
        else:
            batch = [item]
        while len(batch) < 500:
            try:
                nxt = _DB["q"].get_nowait()
            except queue.Empty:
                break
            if isinstance(nxt, dict) and nxt.get("type") == "retry":
                _db_flush(nxt["items"], nxt["tries"])
                continue
            batch.append(nxt)
        _db_flush(batch, tries)


def _db_init() -> None:
    if not DB_URL:
        print("[db] DATABASE_URL not set - history stays in-memory only")
        return
    try:
        conn = _db_get_conn()
        conn.execute(_DB_SCHEMA)
        _DB["enabled"] = True
        _DB["q"] = queue.Queue(maxsize=20000)
        threading.Thread(target=_db_writer, daemon=True).start()
        print("[db] connected - verdict history is now persistent")
    except Exception as exc:
        print(f"[db] init failed - history stays in-memory only: {exc}")
        _DB["enabled"] = False


def _enqueue_flow(device_id: str, is_attack: bool, src_ip: str = None) -> None:
    if _DB["q"] is None:
        return
    try:
        _DB["q"].put_nowait({
            "type": "flow", "device_id": device_id,
            "is_attack": is_attack, "hour": int(time.time() // 3600),
            "src_ip": src_ip,
        })
    except queue.Full:
        pass


def _enqueue_alert(alert: Dict[str, Any]) -> None:
    if _DB["q"] is None:
        return
    try:
        _DB["q"].put_nowait({"type": "attack", **alert})
    except queue.Full:
        pass


def _build_stats_db(since: float = None) -> Dict[str, Any]:
    conn = _db_get_conn()
    if since is not None:
        flows_total = conn.execute(
            "SELECT count(*) FROM ai_flow_events WHERE ts >= to_timestamp(%s)",
            (since,),
        ).fetchone()[0]
        attacks_total = conn.execute(
            "SELECT count(*) FROM ai_flow_events WHERE ts >= to_timestamp(%s)"
            " AND is_attack",
            (since,),
        ).fetchone()[0]
        by_class_rows = conn.execute(
            "SELECT attack_class, count(*) FROM ai_alerts WHERE ts >= to_timestamp(%s)"
            " GROUP BY attack_class ORDER BY count(*) DESC",
            (since,),
        ).fetchall()
        risk_rows = conn.execute(
            "SELECT risk_level, count(*) FROM ai_alerts WHERE ts >= to_timestamp(%s)"
            " GROUP BY risk_level",
            (since,),
        ).fetchall()
        lh = conn.execute(
            """
            SELECT count(*), count(*) FILTER (WHERE is_attack),
                   count(DISTINCT device_id)
            FROM ai_flow_events WHERE ts >= to_timestamp(%s)
            """,
            (since,),
        ).fetchone()
        alert_rows = conn.execute(
            """
            SELECT extract(epoch from ts), device_id, src_ip, attack_class, confidence,
                   risk_level, model_status, defense_actions
            FROM ai_alerts WHERE ts >= to_timestamp(%s)
            ORDER BY id DESC LIMIT 12
            """,
            (since,),
        ).fetchall()
        top_ips = []
        for r in conn.execute(
            """
            SELECT src_ip, count(*) AS flows,
                   count(*) FILTER (WHERE is_attack) AS attacks
            FROM ai_flow_events
            WHERE ts >= to_timestamp(%s) AND src_ip IS NOT NULL
            GROUP BY src_ip ORDER BY attacks DESC, flows DESC LIMIT 50
            """,
            (since,),
        ).fetchall():
            if _is_private_ip(r[0]):
                continue
            top_ips.append({"ip": r[0], "flows": int(r[1]), "attacks": int(r[2])})
            if len(top_ips) >= 8:
                break
    else:
        flows_total = conn.execute(
            "SELECT flows_total FROM ai_counters WHERE id = 1"
        ).fetchone()[0]
        by_class_rows = conn.execute(
            "SELECT attack_class, total FROM ai_class_totals ORDER BY total DESC"
        ).fetchall()
        risk_rows = conn.execute(
            "SELECT risk_level, total FROM ai_risk_totals"
        ).fetchall()
        lh = conn.execute(
            """
            SELECT count(*), count(*) FILTER (WHERE is_attack),
                   count(DISTINCT device_id)
            FROM ai_flow_events WHERE ts > now() - interval '1 hour'
            """
        ).fetchone()
        alert_rows = conn.execute(
            """
            SELECT extract(epoch from ts), device_id, src_ip, attack_class, confidence,
                   risk_level, model_status, defense_actions
            FROM ai_alerts ORDER BY id DESC LIMIT 12
            """
        ).fetchall()
        top_ips = []
        for r in conn.execute(
            """
            SELECT src_ip, count(*) AS flows,
                   count(*) FILTER (WHERE is_attack) AS attacks
            FROM ai_flow_events
            WHERE src_ip IS NOT NULL
            GROUP BY src_ip ORDER BY flows DESC LIMIT 50
            """
        ).fetchall():
            if _is_private_ip(r[0]):
                continue
            top_ips.append({"ip": r[0], "flows": int(r[1]), "attacks": int(r[2])})
            if len(top_ips) >= 8:
                break
    gnn = _state["gnn"]
    for t in top_ips:
        t["gnn_risk"] = round(gnn.latest_risk(t["ip"]), 3) if gnn else None
    return {
        "ts": time.time(),
        "flows_total": int(flows_total),
        "attacks_total": int(attacks_total if since is not None
                             else sum(t for _, t in by_class_rows)),
        "flows_last_hour": int(lh[0]),
        "attacks_last_hour": int(lh[1]),
        "active_devices": int(lh[2]),
        "attacks_by_class": {c: int(t) for c, t in by_class_rows},
        "risk_levels": {r: int(t) for r, t in risk_rows},
        "recent_alerts": [
            {
                "ts": float(r[0]), "device_id": r[1], "src_ip": r[2],
                "attack_class": r[3], "confidence": float(r[4]),
                "risk_level": r[5], "model_status": r[6],
                "defense_actions": list(r[7]),
            }
            for r in alert_rows
        ],
        "top_ips": top_ips,
    }


def _stats_payload() -> Dict[str, Any]:
    session_on = _session["started_at"] is not None
    if _DB["enabled"]:
        since_db = _session["db_started_at"] if session_on else None
        try:
            payload = _build_stats_db(since_db)
        except Exception as exc:
            print(f"[db] stats read failed, using in-memory: {exc}")
            payload = _build_stats(_session["started_at"] if session_on else None)
    else:
        payload = _build_stats(_session["started_at"] if session_on else None)
    payload["session"] = {
        "active": _session["active"],
        "started_at": _session["started_at"],
        "ended_at": _session["ended_at"],
        "server_now": time.time(),
    }
    return payload


def _load():
    import joblib

    try:
        import onnxruntime as ort
    except ImportError:
        print("[ai] onnxruntime not installed - ONNX sessions unavailable")
        ort = None

    providers = ["CPUExecutionProvider"]

    try:
        if os.path.exists(FLOW_SCALER_PKL):
            _state["flow_scaler"] = joblib.load(FLOW_SCALER_PKL)
    except Exception as exc:
        print(f"[ai] flow scaler load failed: {exc}")

    try:
        if os.path.exists(LABEL_MAP_JSON):
            with open(LABEL_MAP_JSON) as f:
                _state["label_map"] = json.load(f)
    except Exception as exc:
        print(f"[ai] label map load failed: {exc}")

    try:
        if os.path.exists(FUSION_SCALER_JSON):
            with open(FUSION_SCALER_JSON) as f:
                d = json.load(f)
            _state["fusion_scaler"] = (
                np.asarray(d["scaler_mean"], dtype=np.float32),
                np.asarray(d["scaler_std"], dtype=np.float32),
            )
        if os.path.exists(FUSION_CALIB_JSON):
            with open(FUSION_CALIB_JSON) as f:
                _state["temperature"] = float(json.load(f)["temperature"])
    except Exception as exc:
        print(f"[ai] fusion calibration load failed: {exc}")

    have_stack = (
        ort is not None
        and all(os.path.exists(p) for p in (FUSION_ONNX, LSTM_ONNX, TRANS_ONNX))
        and _state["fusion_scaler"] is not None
    )
    if have_stack:
        try:
            _state["fusion"] = {
                "fusion": ort.InferenceSession(FUSION_ONNX, providers=providers),
                "lstm": ort.InferenceSession(LSTM_ONNX, providers=providers),
                "trans": ort.InferenceSession(TRANS_ONNX, providers=providers),
            }
        except Exception as exc:
            print(f"[ai] fusion onnx load failed: {exc}")
            _state["fusion"] = None

    try:
        if ort is not None and os.path.exists(XGB_ONNX):
            _state["xgb"] = ort.InferenceSession(XGB_ONNX, providers=providers)
        elif os.path.exists(XGB_PKL):
            _state["xgb"] = joblib.load(XGB_PKL)
    except Exception as exc:
        print(f"[ai] xgboost load failed: {exc}")
        _state["xgb"] = None

    try:
        if os.path.exists(IF_PKL):
            _state["iso"] = joblib.load(IF_PKL)
    except Exception as exc:
        print(f"[ai] isolation forest load failed: {exc}")

    print(
        f"[ai] loaded: fusion={_state['fusion'] is not None} "
        f"xgboost={_state['xgb'] is not None} "
        f"isolation_forest={_state['iso'] is not None}"
    )


@asynccontextmanager
async def _lifespan(_app):
    _load()
    _load_gnn()
    _db_init()
    _load_blocked()
    yield


def _load_blocked():
    """Restore active IP blocks from the database after a restart."""
    if not _DB["enabled"]:
        return
    try:
        conn = _db_get_conn()
        rows = conn.execute(
            """SELECT ip, extract(epoch from until), reason
               FROM ai_blocked_ips WHERE until > now()"""
        ).fetchall()
        for ip, until, reason in rows:
            _BLOCKED[ip] = float(until)
            _BLOCK_META[ip] = {"reason": reason or "", "drops": 0}
        if _BLOCKED:
            print(f"[block] {len(_BLOCKED)} active IP block(s) restored")
        _firewall_sync()  # re-apply firewall rules + clear stale ones
    except Exception as exc:
        print(f"[block] load failed: {exc}")


def _load_gnn():
    """Load the live GNN (gat.onnx + scaler) if both artifacts exist."""
    if not (os.path.exists(GNN_ONNX) and os.path.exists(GNN_SCALER_JSON)):
        print("[gnn] artifacts missing (gat.onnx / gnn_scaler.json) - gnn_risk stays 0.0")
        return
    try:
        from gnn_live import GNNLive

        _state["gnn"] = GNNLive()
        print("[gnn] loaded - causal per-IP risk is live")
    except Exception as exc:
        print(f"[gnn] load failed - gnn_risk stays 0.0: {exc}")
        _state["gnn"] = None


app = FastAPI(title="PredictShield AI Engine", version="0.2.0", lifespan=_lifespan)

# Same origins as the HomeVlog backend - the dashboard on www.homevlog.store
# calls this engine cross-origin (browser CORS applies to fetch + EventSource).
FRONTEND_ORIGINS = os.getenv(
    "FRONTEND_ORIGINS",
    "http://localhost:5173,https://homevlog.store,https://www.homevlog.store",
).split(",")

app.add_middleware(
    CORSMiddleware,
    allow_origins=FRONTEND_ORIGINS,
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


class PredictRequest(BaseModel):
    features: List[float] = Field(..., min_length=N_FEATURES, max_length=N_FEATURES)
    device_id: str = ""
    topology: Dict[str, Any] = {}


class PredictResponse(BaseModel):
    attack_class: str
    confidence: float
    risk_level: str
    path: List[str]
    shap: Dict[str, float]
    defense_actions: List[str]
    model_status: str
    gnn_risk: float = 0.0


def softmax(x: np.ndarray) -> np.ndarray:
    e = np.exp(x - x.max(axis=-1, keepdims=True))
    return e / e.sum(axis=-1, keepdims=True)


def _id_to_label(idx: int) -> str:
    inv = {v: k for k, v in _state["label_map"].items()}
    return inv.get(idx, str(idx))


def _respond(proba: np.ndarray, status: str, gnn_risk: float = 0.0) -> PredictResponse:
    idx = int(np.argmax(proba))
    conf = float(proba[idx])
    cls = _id_to_label(idx)
    risk = "LOW" if cls == "BENIGN" else ("HIGH" if conf >= 0.8 else "MEDIUM")
    return PredictResponse(
        attack_class=cls,
        confidence=round(conf, 4),
        risk_level=risk,
        path=[],
        shap={},
        defense_actions=list(RISK_ACTIONS.get(cls, ["monitor"])),
        model_status=status,
        gnn_risk=round(gnn_risk, 6),
    )


def _xgb_proba(last_flow: np.ndarray) -> np.ndarray:
    model = _state["xgb"]
    if hasattr(model, "run"):  # ONNX session
        out = model.run(None, {"features": last_flow.astype(np.float32)})
        proba = out[1] if len(out) > 1 and out[1].shape[-1] == N_CLASSES else out[0]
    else:  # XGBClassifier
        proba = model.predict_proba(last_flow)
    return np.asarray(proba, dtype=np.float32)


def _fusion_verdict(seq: np.ndarray, gnn_risk: float = 0.0) -> PredictResponse:
    stack = _state["fusion"]
    if seq.ndim == 2:  # (50, 77) buffer -> single-sample batch (1, 50, 77)
        seq = seq[None, ...]
    seq = seq.astype(np.float32)
    last = seq[:, -1, :].astype(np.float32)  # (1, 77) - the latest flow

    xgb_proba = _xgb_proba(last)[0]
    lstm_proba = softmax(stack["lstm"].run(None, {"input": seq})[0])[0]
    trans_proba = softmax(stack["trans"].run(None, {"input": seq})[0])[0]

    if_score = 0.0
    if _state["iso"] is not None:
        if_score = float(-_state["iso"].decision_function(last.astype(np.float64))[0])
    # gnn_risk: causal per-IP risk from gnn_live (0.0 = unseen IP default)

    feats = np.concatenate(
        [xgb_proba, lstm_proba, trans_proba, [if_score, gnn_risk]]
    ).astype(np.float32).reshape(1, -1)
    mean, std = _state["fusion_scaler"]
    feats = ((feats - mean) / std).astype(np.float32)

    logits = stack["fusion"].run(None, {"features": feats})[0]
    proba = softmax(logits / _state["temperature"])[0]
    return _respond(proba, "fusion_5model", gnn_risk)


@app.get("/ai/health")
def health():
    return {
        "status": "ok",
        "models_deployed": _state["fusion"] is not None or _state["xgb"] is not None,
        "fusion": _state["fusion"] is not None,
        "xgboost": _state["xgb"] is not None,
        "isolation_forest": _state["iso"] is not None,
        "gnn": _state["gnn"] is not None,
        "db_history": _DB["enabled"],
    }


class AdminLogin(BaseModel):
    username: str
    password: str


@app.post("/ai/admin/login")
def admin_login(body: AdminLogin):
    """Separate admin login for the threat-monitor dashboard."""
    if not ADMIN_USER or not ADMIN_PASS:
        raise HTTPException(status_code=401, detail="Admin auth not configured")
    ok = (hmac.compare_digest(body.username, ADMIN_USER)
          and hmac.compare_digest(body.password, ADMIN_PASS))
    if not ok:
        raise HTTPException(status_code=401, detail="Invalid admin credentials")
    return {"token": _admin_token(), "username": ADMIN_USER}


@app.get("/ai/stats")
def stats(_: None = Depends(_require_admin)):
    """Aggregate live stats for the /admin/report dashboard (DB-backed)."""
    return _stats_payload()


@app.get("/ai/alerts")
def alerts(limit: int = 50, _: None = Depends(_require_admin)):
    """Recent attack alerts, newest first."""
    limit = max(1, min(limit, 500))
    if _DB["enabled"]:
        try:
            conn = _db_get_conn()
            rows = conn.execute(
                """
                SELECT extract(epoch from ts), device_id, src_ip, attack_class,
                       confidence, risk_level, model_status, defense_actions
                FROM ai_alerts ORDER BY id DESC LIMIT %s
                """,
                (limit,),
            ).fetchall()
            return [
                {
                    "ts": float(r[0]), "device_id": r[1], "src_ip": r[2],
                    "attack_class": r[3], "confidence": float(r[4]),
                    "risk_level": r[5], "model_status": r[6],
                    "defense_actions": list(r[7]),
                }
                for r in rows
            ]
        except Exception as exc:
            print(f"[db] alerts read failed, using in-memory: {exc}")
    return list(_MONITOR["alerts"])[-limit:][::-1]


class GeoRequest(BaseModel):
    ips: List[str] = Field(default_factory=list)


class BlockRequest(BaseModel):
    ip: str
    hours: float = 24.0
    reason: str = ""


def _is_private_ip(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
        return (a.is_private or a.is_loopback or a.is_link_local
                or a.is_reserved or a.is_multicast)
    except ValueError:
        return True


@app.post("/ai/ip/block")
def ip_block(body: BlockRequest, _: None = Depends(_require_admin)):
    """Block a source IP for N hours (default 24). Blocked flows get 403."""
    ip = body.ip.strip()
    hours = max(0.1, min(body.hours, 720))
    until = time.time() + hours * 3600
    _BLOCKED[ip] = until
    _BLOCK_META[ip] = {"reason": body.reason,
                       "drops": _BLOCK_META.get(ip, {}).get("drops", 0)}
    if _DB["enabled"]:
        try:
            _db_get_conn().execute(
                """
                INSERT INTO ai_blocked_ips (ip, until, reason)
                VALUES (%s, to_timestamp(%s), %s)
                ON CONFLICT (ip) DO UPDATE SET
                    until = EXCLUDED.until, reason = EXCLUDED.reason
                """,
                (ip, until, body.reason),
            )
        except Exception as exc:
            print(f"[block] db save failed: {exc}")
    _firewall_sync()
    print(f"[block] {ip} blocked for {hours}h (firewall + engine gate)")
    return {"ip": ip, "blocked": True, "until": until, "hours": hours}


@app.post("/ai/ip/unblock")
def ip_unblock(body: BlockRequest, _: None = Depends(_require_admin)):
    """Lift a block early - the source can talk to the network again."""
    ip = body.ip.strip()
    _BLOCKED.pop(ip, None)
    _BLOCK_META.pop(ip, None)
    if _DB["enabled"]:
        try:
            _db_get_conn().execute("DELETE FROM ai_blocked_ips WHERE ip = %s", (ip,))
        except Exception as exc:
            print(f"[block] db delete failed: {exc}")
    _firewall_sync()
    print(f"[block] {ip} unblocked")
    return {"ip": ip, "blocked": False}


@app.get("/ai/ip/blocked")
def ip_blocked_list(_: None = Depends(_require_admin)):
    """Currently blocked source IPs with remaining time and drop counts."""
    now = time.time()
    out = []
    for ip, until in list(_BLOCKED.items()):
        if until <= now:  # expired lazily
            _BLOCKED.pop(ip, None)
            _BLOCK_META.pop(ip, None)
            if _DB["enabled"]:
                try:
                    _db_get_conn().execute("DELETE FROM ai_blocked_ips WHERE ip = %s", (ip,))
                except Exception:
                    pass
            continue
        meta = _BLOCK_META.get(ip, {})
        out.append({"ip": ip, "until": until, "remaining_s": int(until - now),
                    "reason": meta.get("reason", ""), "drops": meta.get("drops", 0)})
    out.sort(key=lambda b: -b["remaining_s"])
    return {"blocked": out}


@app.post("/ai/geo")
def geo_lookup(body: GeoRequest, _: None = Depends(_require_admin)):
    """Resolve IP -> country/city (ip-api.com free tier, cached per IP).
    Private/reserved IPs resolve to 'Local / Private network'."""
    out: Dict[str, Any] = {}
    to_fetch: List[str] = []
    for ip in body.ips[:12]:
        if not ip or not isinstance(ip, str):
            continue
        if ip in _GEO_CACHE:
            out[ip] = _GEO_CACHE[ip]
            continue
        if _is_private_ip(ip):
            res = {"ip": ip, "country": "Local / Private network",
                   "country_code": "", "city": ""}
            _GEO_CACHE[ip] = res
            out[ip] = res
        else:
            to_fetch.append(ip)
    if to_fetch:
        try:
            req = urllib.request.Request(
                "http://ip-api.com/batch?fields=status,country,countryCode,city,query",
                data=json.dumps(to_fetch).encode(),
                headers={"Content-Type": "application/json"},
            )
            with urllib.request.urlopen(req, timeout=3) as resp:
                rows = json.load(resp)
            for row in rows:
                ip = row.get("query")
                res = ({"ip": ip, "country": row.get("country"),
                        "country_code": row.get("countryCode"),
                        "city": row.get("city")}
                       if row.get("status") == "success"
                       else {"ip": ip, "country": "Unknown",
                             "country_code": "", "city": ""})
                _GEO_CACHE[ip] = res
                out[ip] = res
        except Exception:
            for ip in to_fetch:
                out.setdefault(ip, {"ip": ip, "country": "Unknown",
                                    "country_code": "", "city": ""})
    return {"results": out}


@app.get("/ai/history")
def history(hours: int = 24, _: None = Depends(_require_admin)):
    """Per-hour flows/attacks rollup from the database (persistent history)."""
    hours = max(1, min(hours, 720))
    if not _DB["enabled"]:
        return {"enabled": False, "hours": []}
    try:
        conn = _db_get_conn()
        rows = conn.execute(
            """
            SELECT extract(epoch from bucket), flows, attacks
            FROM ai_hourly
            WHERE bucket > now() - (%s || ' hours')::interval
            ORDER BY bucket
            """,
            (str(hours),),
        ).fetchall()
        return {
            "enabled": True,
            "hours": [
                {"ts": float(r[0]), "flows": int(r[1]), "attacks": int(r[2])}
                for r in rows
            ],
        }
    except Exception as exc:
        print(f"[db] history read failed: {exc}")
        return {"enabled": False, "hours": []}


@app.get("/ai/stream")
async def stream(interval: float = 2.0, _: None = Depends(_require_admin)):
    """SSE: push live stats to the dashboard every `interval` seconds."""
    interval = max(1.0, min(interval, 10.0))

    async def event_gen():
        while True:
            yield f"data: {json.dumps(_stats_payload())}\n\n"
            await asyncio.sleep(interval)

    return StreamingResponse(
        event_gen(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )


@app.post("/ai/session/start")
def session_start(_: None = Depends(_require_admin)):
    """Start a monitoring session: every stat/alert is now counted from this
    moment only (DB history keeps recording regardless)."""
    _session["active"] = True
    _session["started_at"] = time.time()
    _session["ended_at"] = None
    _session["devices"] = set()
    _session["db_started_at"] = None
    if _DB["enabled"]:
        try:
            conn = _db_get_conn()
            # use the DB's own clock - client/host clocks can be skewed
            _session["db_started_at"] = float(
                conn.execute("SELECT extract(epoch from now())").fetchone()[0]
            )
        except Exception as exc:
            print(f"[session] db clock unavailable: {exc}")
    print(f"[session] STARTED at {_session['started_at']:.0f}")
    return {"active": True, "started_at": _session["started_at"]}


@app.post("/ai/session/stop")
def session_stop(_: None = Depends(_require_admin)):
    """Stop the session but keep its summary visible until the next start."""
    if _session["active"]:
        _session["active"] = False
        _session["ended_at"] = time.time()
        print(f"[session] STOPPED at {_session['ended_at']:.0f}")
    return {"active": False, "started_at": _session["started_at"],
            "ended_at": _session["ended_at"]}


@app.get("/ai/session")
def session_status(_: None = Depends(_require_admin)):
    return {"active": _session["active"], "started_at": _session["started_at"],
            "ended_at": _session["ended_at"]}


@app.post("/ai/predict", response_model=PredictResponse)
def predict(req: PredictRequest, request: Request):
    # resolve the REAL source IP: nginx X-Real-IP -> X-Forwarded-For ->
    # worker-provided topology IP -> direct client. Never trust a spoofed
    # topology IP when the request itself reveals the true source.
    src_ip = (
        request.headers.get("x-real-ip")
        or (request.headers.get("x-forwarded-for") or "").split(",")[0].strip()
        or (req.topology or {}).get("src_ip")
        or (request.client.host if request.client else None)
    )

    # blocked source IPs are rejected at the gate - no inference, no stats
    if src_ip and _BLOCKED.get(src_ip, 0) > time.time():
        meta = _BLOCK_META.setdefault(src_ip, {"reason": "", "drops": 0})
        meta["drops"] = meta.get("drops", 0) + 1
        raise HTTPException(
            status_code=403,
            detail=f"Source IP {src_ip} is blocked",
        )

    x = np.asarray(req.features, dtype=np.float32).reshape(1, -1)
    if _state["flow_scaler"] is not None:
        x = _state["flow_scaler"].transform(x).astype(np.float32)

    if _state["xgb"] is None and _state["fusion"] is None:
        return _finish(req.device_id, PredictResponse(
            attack_class="unknown", confidence=0.0, risk_level="LOW",
            path=[], shap={}, defense_actions=[], model_status="not_deployed",
        ), src_ip)

    key = req.device_id or "default"
    buf: deque = _state["buffers"].setdefault(key, deque(maxlen=SEQ_LEN))
    buf.append(x[0])

    if _state["fusion"] is not None and len(buf) >= SEQ_LEN:
        gnn_risk = 0.0
        gnn = _state["gnn"]
        if gnn is not None and req.topology:
            try:
                gnn_risk = gnn.on_flow(req.topology)
            except Exception as exc:
                print(f"[gnn] risk failed: {exc}")
        resp = _fusion_verdict(np.stack(buf), gnn_risk)
    elif _state["xgb"] is None:
        resp = PredictResponse(
            attack_class="unknown", confidence=0.0, risk_level="LOW",
            path=[], shap={}, defense_actions=[], model_status="warming_up",
        )
    else:
        resp = _respond(_xgb_proba(buf[-1].reshape(1, -1))[0], "warmup_xgboost")
    return _finish(req.device_id, resp, src_ip)

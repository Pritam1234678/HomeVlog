"""PredictShield AI engine - real inference.

Per flow (77 CICFlowMeter features):
  1. scale with the training StandardScaler (models/cicids2017_scaler.pkl)
  2. append to a per-device rolling buffer of the last 50 flows
  3. buffer full  -> 5-model fusion verdict via ONNX
     buffer < 50  -> XGBoost fallback on the last flow (warmup)

Artifacts live in ./models - see models/README.md. Missing artifacts degrade
gracefully: /ai/predict answers with model_status="not_deployed".
"""
import json
import os
from collections import deque
from contextlib import asynccontextmanager
from typing import Any, Dict, List

import numpy as np
from fastapi import FastAPI
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
}


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
    yield


app = FastAPI(title="PredictShield AI Engine", version="0.2.0", lifespan=_lifespan)


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


def softmax(x: np.ndarray) -> np.ndarray:
    e = np.exp(x - x.max(axis=-1, keepdims=True))
    return e / e.sum(axis=-1, keepdims=True)


def _id_to_label(idx: int) -> str:
    inv = {v: k for k, v in _state["label_map"].items()}
    return inv.get(idx, str(idx))


def _respond(proba: np.ndarray, status: str) -> PredictResponse:
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
    )


def _xgb_proba(last_flow: np.ndarray) -> np.ndarray:
    model = _state["xgb"]
    if hasattr(model, "run"):  # ONNX session
        out = model.run(None, {"features": last_flow.astype(np.float32)})
        proba = out[1] if len(out) > 1 and out[1].shape[-1] == N_CLASSES else out[0]
    else:  # XGBClassifier
        proba = model.predict_proba(last_flow)
    return np.asarray(proba, dtype=np.float32)


def _fusion_verdict(seq: np.ndarray) -> PredictResponse:
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
    gnn_risk = 0.0  # live GNN risk feature: future work (unseen-IP default)

    feats = np.concatenate(
        [xgb_proba, lstm_proba, trans_proba, [if_score, gnn_risk]]
    ).astype(np.float32).reshape(1, -1)
    mean, std = _state["fusion_scaler"]
    feats = ((feats - mean) / std).astype(np.float32)

    logits = stack["fusion"].run(None, {"features": feats})[0]
    proba = softmax(logits / _state["temperature"])[0]
    return _respond(proba, "fusion_5model")


@app.get("/ai/health")
def health():
    return {
        "status": "ok",
        "models_deployed": _state["fusion"] is not None or _state["xgb"] is not None,
        "fusion": _state["fusion"] is not None,
        "xgboost": _state["xgb"] is not None,
        "isolation_forest": _state["iso"] is not None,
    }


@app.post("/ai/predict", response_model=PredictResponse)
def predict(req: PredictRequest):
    x = np.asarray(req.features, dtype=np.float32).reshape(1, -1)
    if _state["flow_scaler"] is not None:
        x = _state["flow_scaler"].transform(x).astype(np.float32)

    if _state["xgb"] is None and _state["fusion"] is None:
        return PredictResponse(
            attack_class="unknown", confidence=0.0, risk_level="LOW",
            path=[], shap={}, defense_actions=[], model_status="not_deployed",
        )

    key = req.device_id or "default"
    buf: deque = _state["buffers"].setdefault(key, deque(maxlen=SEQ_LEN))
    buf.append(x[0])

    if _state["fusion"] is not None and len(buf) >= SEQ_LEN:
        return _fusion_verdict(np.stack(buf))
    if _state["xgb"] is None:
        return PredictResponse(
            attack_class="unknown", confidence=0.0, risk_level="LOW",
            path=[], shap={}, defense_actions=[], model_status="warming_up",
        )
    return _respond(_xgb_proba(buf[-1].reshape(1, -1))[0], "warmup_xgboost")

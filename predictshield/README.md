# PredictShield — Packet Capture to 77 CICFlowMeter Features

First vertical slice of the PredictShield AI pipeline. Turns raw network packets into the
77 numeric features the AI models will consume (the exact CICFlowMeter feature set used by
CICIDS2017), and exposes a FastAPI `/ai/predict` endpoint (stub for now — no trained
models yet).

## Install

```bash
cd predictshield
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Run

### Offline (replay a PCAP — recommended for testing)

```bash
python worker.py --pcap path/to/capture.pcap --no-post
```

`--no-post` prints each flow's 25-value feature vector as JSON lines without calling the
API. Drop it to actually POST to the API.

### Live (sniff an interface — needs root)

```bash
sudo python worker.py --iface eth0 --api-url http://127.0.0.1:8000
```

### API server

```bash
uvicorn api:app --reload
```

- `POST /ai/predict` — `{"features": [...77 numbers...], "device_id": "...", "topology": {}}`
- `GET /ai/health` — service + model status

## AI engine (real inference)

`api.py` keeps a **per-device rolling buffer of the last 50 scaled flows** and
answers every flow with a verdict:

| model_status | When | Verdict from |
|---|---|---|
| `not_deployed` | artifacts missing | stub |
| `warmup_xgboost` | fewer than 50 flows for the device | single-flow XGBoost |
| `fusion_5model` | 50-flow buffer full | fusion MLP (XGB+LSTM+Transformer+IF+GNN-slot, temperature-calibrated) |

Responses carry `attack_class` (label name), `confidence`, `risk_level`
(HIGH/MEDIUM/LOW), and `defense_actions` (static per-class playbook).

Setup:

1. Fill `models/` — see `models/README.md` (Kaggle outputs + local pkl files).
2. Run `Fusion_v2_Realistic.ipynb` on Kaggle to produce the fusion bundle
   (`fusion_mlp_v2.onnx`, `fusion_scaler.json`, `fusion_calib.json`,
   `label_map.json`) and copy those into `models/`.

The GNN attack-path output (`path`) and SHAP explainability (`shap`) are
future work and currently return empty.

## Feature order (fixed contract)

The feature vector is always emitted in this exact order — the same 77 CICFlowMeter
features (and same order) as the CICIDS2017 training dataset:

```
Destination Port, Flow Duration,
Total Fwd Packets, Total Backward Packets,
Total Length of Fwd Packets, Total Length of Bwd Packets,
Fwd Packet Length Max/Min/Mean/Std, Bwd Packet Length Max/Min/Mean/Std,
Flow Bytes/s, Flow Packets/s,
Flow IAT Mean/Std/Max/Min, Fwd IAT Total/Mean/Std/Max/Min, Bwd IAT Total/Mean/Std/Max/Min,
Fwd/Bwd PSH Flags, Fwd/Bwd URG Flags, Fwd/Bwd Header Length,
Fwd/Bwd Packets/s, Min/Max Packet Length, Packet Length Mean/Std/Variance,
FIN/SYN/RST/PSH/ACK/URG/CWE/ECE Flag Count,
Down/Up Ratio, Average Packet Size, Avg Fwd/Bwd Segment Size,
Fwd/Bwd Avg Bytes/Bulk, Fwd/Bwd Avg Packets/Bulk, Fwd/Bwd Avg Bulk Rate,
Subflow Fwd/Bwd Packets/Bytes, Init_Win_bytes_forward/backward,
act_data_pkt_fwd, min_seg_size_forward,
Active Mean/Std/Max/Min, Idle Mean/Std/Max/Min
```

## Notes

- These are the exact CICFlowMeter features used to build CICIDS2017, so the live
  pipeline and the training-data pipeline stay consistent (per the Research Blueprint).
- Bulk, Subflow, and Active/Idle follow CICFlowMeter's definitions (IAT thresholds).

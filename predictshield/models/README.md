# Models directory

The AI engine (`api.py`) loads artifacts from this directory. Copy them in from
the Kaggle notebook outputs and the local training files:

| File | Required for | Source |
|---|---|---|
| `cicids2017_scaler.pkl` | any inference (scales raw 77 features) | project root (from `build_training_ready.py`) |
| `label_map.json` | class names (int -> label) | `Fusion_v2_Realistic.ipynb` output (or project root `cicids2017_label_map.json`) |
| `xgboost_cicids2017_v2.onnx` OR `xgboost_cicids2017_v2.pkl` | warmup fallback (first 49 flows) | Kaggle xgboost-cicids2017-v2 model / `Training Files/` |
| `fusion_mlp_v2.onnx` | full 5-model fusion (from flow 50) | `Fusion_v2_Realistic.ipynb` output |
| `fusion_scaler.json` | full fusion (47-dim mean/std) | `Fusion_v2_Realistic.ipynb` output |
| `fusion_calib.json` | full fusion (temperature) | `Fusion_v2_Realistic.ipynb` output |
| `lstm_cicids2017.onnx` | full fusion (sequence probas) | Kaggle lstm-cicids2017 model |
| `transformer_cicids2017.onnx` | full fusion (sequence probas) | Kaggle transformer-cicids2017 model |
| `isolation_forest_cicids2017_v2.pkl` | full fusion (anomaly score feature) | Kaggle isolation-forest-cicids2017-v2 / `Training Files/` |

Degradation ladder:

- nothing loaded -> `model_status="not_deployed"` (stub response)
- scaler + xgboost only -> `model_status="warmup_xgboost"` (single-flow verdict)
- full stack -> `model_status="fusion_5model"` (rolling 50-flow fusion verdict)

`gat_attack_path_state.pt` is NOT needed yet: the live GNN path feature is
future work; the fusion's GNN slot defaults to 0.0 (unseen-IP), matching the
notebook's causal default.

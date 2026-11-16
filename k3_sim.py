#!/usr/bin/env python3
"""k3 attack simulator - PredictShield demo tool.

Sends bursts of REAL CICIDS2017 attack vectors to the live engine so the
/admin/report dashboard lights up: alerts, attacks-by-class, top source IPs
(with location) and rising GNN risk - all live.

Usage:
  cd ~/Desktop/Python/HOMEProject
  ./venv/bin/python k3_sim.py                 # infinite bursts (Ctrl+C to stop)
  ./venv/bin/python k3_sim.py --seconds 60    # auto-stop after 60s
  ./venv/bin/python k3_sim.py --ip 203.0.113.7 --class "DoS Hulk"
"""
import argparse
import json
import os
import random
import time
import urllib.request

BASE = os.path.dirname(os.path.abspath(__file__))
CSV = os.path.join(BASE, "cicids2017_combined.csv")
POOL_CACHE = "/tmp/commandcode-1000/-home-pritam-Desktop-Python-HOMEProject/212289db-ef7b-44ac-85dd-d03ebb653df7/scratchpad/k3_attack_pool.json"
API = "https://api.homevlog.store/ai/predict"

LABELS = ["DoS Hulk", "DDoS", "DoS GoldenEye", "SSH-Patator", "PortScan", "Bot"]


def build_pool(per_class=40):
    """Sample real attack rows from the dataset (once, then cached)."""
    if os.path.exists(POOL_CACHE):
        with open(POOL_CACHE) as f:
            return json.load(f)
    import numpy as np
    import pandas as pd

    cols = None
    pool = []
    for chunk in pd.read_csv(CSV, chunksize=400_000):
        if cols is None:
            cols = [c.strip() for c in chunk.columns]
            chunk.columns = cols
        feat_cols = [c for c in cols if c != "Label"]
        for lbl in LABELS:
            need = per_class - sum(1 for r in pool if r["label"] == lbl)
            if need > 0:
                sub = chunk[chunk["Label"] == lbl].head(need)
                for _, row in sub.iterrows():
                    feats = row[feat_cols].tolist()
                    feats = [0.0 if (v != v or v in (float("inf"), float("-inf"))) else float(v)
                             for v in feats]
                    pool.append({"label": lbl, "feats": feats})
        if all(sum(1 for r in pool if r["label"] == l) >= per_class for l in LABELS):
            break
    with open(POOL_CACHE, "w") as f:
        json.dump(pool, f)
    return pool


def main():
    ap = argparse.ArgumentParser(description="PredictShield k3 attack simulator")
    ap.add_argument("--ip", default="185.220.101.45", help="attacker source IP shown on the dashboard")
    ap.add_argument("--class", dest="klass", default=None, help="only this attack class (default: mix)")
    ap.add_argument("--seconds", type=int, default=0, help="auto-stop after N seconds (0 = forever)")
    ap.add_argument("--burst", type=int, default=6, help="flows per burst (every 3s)")
    args = ap.parse_args()

    pool = build_pool()
    if args.klass:
        pool = [r for r in pool if r["label"] == args.klass] or pool
    print(f"k3 sim: {len(pool)} attack vectors loaded | attacker IP {args.ip}")
    print(f"target: {API}")
    print("watch it live: https://www.homevlog.store/admin/report  (press START)")

    sent = attacks = 0
    t0 = time.time()
    try:
        while True:
            batch = random.sample(pool, min(args.burst, len(pool)))
            for row in batch:
                body = {
                    "features": row["feats"],
                    "device_id": "k3-attack-sim",
                    "topology": {
                        "src_ip": args.ip, "dst_ip": "10.0.0.28",
                        "src_port": random.randint(40000, 60000),
                        "dst_port": random.choice([22, 80, 443, 21]),
                        "protocol": 6, "ts": time.time(),
                        "duration_us": random.uniform(5_000, 900_000),
                        "fwd_pkts": random.randint(4, 40),
                        "bwd_pkts": random.randint(1, 20),
                        "fwd_bytes": random.randint(200, 500_000),
                        "bwd_bytes": random.randint(100, 400_000),
                        "avg_pkt": random.uniform(40, 800),
                        "max_pkt": random.uniform(100, 1500),
                        "syn": random.randint(1, 6), "rst": random.randint(0, 3),
                        "fin": random.randint(0, 3), "ack": random.randint(2, 40),
                    },
                }
                try:
                    req = urllib.request.Request(
                        API, data=json.dumps(body).encode(),
                        headers={"Content-Type": "application/json"})
                    out = json.load(urllib.request.urlopen(req, timeout=10))
                    sent += 1
                    if out["attack_class"] != "BENIGN":
                        attacks += 1
                        print(f"  [ATTACK] {out['attack_class']:<18} conf={out['confidence']:.2f} "
                              f"risk={out['risk_level']:<6} from {args.ip}")
                except Exception as exc:
                    print(f"  [error] {exc}")
            print(f"  burst done: sent={sent} attacks_detected={attacks}")
            if args.seconds and time.time() - t0 > args.seconds:
                print(f"auto-stop after {args.seconds}s: sent={sent}, attacks={attacks}")
                break
            time.sleep(3)
    except KeyboardInterrupt:
        print(f"\nstopped: sent={sent}, attacks_detected={attacks}")


if __name__ == "__main__":
    main()

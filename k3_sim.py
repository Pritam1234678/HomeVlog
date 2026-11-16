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


def topology_for(label, i, ts, attacker_ip=None):
    """Per-flow topology. attacker_ip unused - the engine resolves the real
    client IP from the connection, so the dashboard shows the true source."""
    src_port = random.randint(40000, 60000)
    if label in ("DDoS", "DoS Hulk", "DoS GoldenEye"):
        return {"dst_ip": "10.0.0.28", "src_port": src_port,
                "dst_port": 80, "protocol": 6, "ts": ts,
                "duration_us": random.uniform(100_000, 900_000),
                "fwd_pkts": random.randint(80, 300), "bwd_pkts": random.randint(5, 20),
                "fwd_bytes": random.randint(40_000, 500_000),
                "bwd_bytes": random.randint(1_000, 20_000),
                "avg_pkt": random.uniform(400, 900), "max_pkt": 1460.0,
                "syn": random.randint(20, 60), "rst": random.randint(0, 2),
                "fin": random.randint(1, 3), "ack": random.randint(60, 200)}
    if label == "SSH-Patator":
        return {"dst_ip": "10.0.0.28", "src_port": src_port,
                "dst_port": 22, "protocol": 6, "ts": ts,
                "duration_us": random.uniform(100_000, 300_000),
                "fwd_pkts": random.randint(20, 60), "bwd_pkts": random.randint(5, 15),
                "fwd_bytes": random.randint(2_000, 8_000),
                "bwd_bytes": random.randint(1_000, 5_000),
                "avg_pkt": random.uniform(50, 120), "max_pkt": 200.0,
                "syn": random.randint(5, 15), "rst": random.randint(5, 20),
                "fin": random.randint(0, 2), "ack": random.randint(15, 50)}
    if label == "PortScan":
        return {"dst_ip": "10.0.0.28", "src_port": src_port,
                "dst_port": random.choice([21, 22, 23, 25, 80, 110, 135, 139, 443, 445, 3389]),
                "protocol": 6, "ts": ts, "duration_us": random.uniform(1_000, 20_000),
                "fwd_pkts": random.randint(2, 4), "bwd_pkts": random.randint(0, 2),
                "fwd_bytes": random.randint(40, 180), "bwd_bytes": random.randint(0, 120),
                "avg_pkt": random.uniform(40, 70), "max_pkt": 120.0,
                "syn": random.randint(2, 4), "rst": random.randint(1, 3),
                "fin": 0, "ack": random.randint(0, 2)}
    # Bot / generic
    return {"dst_ip": "10.0.0.28", "src_port": src_port,
            "dst_port": random.choice([80, 443, 8080]), "protocol": 6, "ts": ts,
            "duration_us": random.uniform(50_000, 500_000),
            "fwd_pkts": random.randint(10, 40), "bwd_pkts": random.randint(5, 25),
            "fwd_bytes": random.randint(1_000, 40_000),
            "bwd_bytes": random.randint(500, 30_000),
            "avg_pkt": random.uniform(60, 500), "max_pkt": random.uniform(200, 1400),
            "syn": random.randint(1, 8), "rst": random.randint(0, 3),
            "fin": random.randint(0, 3), "ack": random.randint(5, 30)}


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
            ts = time.time()
            for row in batch:
                body = {
                    "features": row["feats"],
                    "device_id": "k3-attack-sim",
                    # no src_ip here - the engine reads the REAL client IP
                    # from the connection (X-Real-IP), so the dashboard shows
                    # where the attack is actually coming from
                    "topology": topology_for(row["label"], sent, ts, None),
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
                              f"risk={out['risk_level']:<6} gnn={out['gnn_risk']}")
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

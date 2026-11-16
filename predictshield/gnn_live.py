"""Live GNN (GAT) inference — per-IP causal risk from 5-second network graphs.

Worker flow records (with IPs) are bucketed into 5-second windows. When a
window closes, node features are built per IP (same recipe as Gnn.ipynb /
Fusion_v2), scaled with the training scaler, and run through gat.onnx; each
IP's sigmoid risk lands on a causal timeline. risk_for() returns the mean
risk of windows STRICTLY BEFORE a flow's timestamp (60s lookback), or 0.0
for unseen IPs — exactly the contract the fusion model was trained with.
"""
import bisect
import json
import os
import threading

import numpy as np

WINDOW_SECONDS = 5
LOOKBACK_SECONDS = 60
NODE_FEAT_DIM = 16
GNN_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "models")
GNN_ONNX = os.path.join(GNN_DIR, "gat.onnx")
GNN_SCALER_JSON = os.path.join(GNN_DIR, "gnn_scaler.json")
WEB_PORTS = (80, 443)
TIMELINE_TTL = 120          # seconds of timeline history to keep
MAX_WINDOW_FLOWS = 5000     # safety cap for pathological bursts


class GNNLive:
    """Windowed GAT inference with a causal per-IP risk timeline."""

    def __init__(self):
        import onnxruntime as ort

        self.sess = ort.InferenceSession(GNN_ONNX, providers=["CPUExecutionProvider"])
        with open(GNN_SCALER_JSON) as f:
            d = json.load(f)
        self.mean = np.asarray(d["scaler_mean"], dtype=np.float32)
        self.std = np.asarray(d["scaler_std"], dtype=np.float32)
        self.windows = {}    # win_start -> list of flow records
        self.timeline = {}   # ip -> sorted [(win_start, risk)]
        self.lock = threading.Lock()

    def on_flow(self, topo):
        """Feed one completed flow (worker topology dict). Returns causal risk
        for its source IP at its timestamp."""
        ts = float(topo.get("ts") or 0.0)
        src_ip = topo.get("src_ip")
        if not ts or not src_ip:
            return 0.0
        win = int(ts // WINDOW_SECONDS) * WINDOW_SECONDS
        with self.lock:
            flows = self.windows.setdefault(win, [])
            if len(flows) < MAX_WINDOW_FLOWS:
                flows.append(topo)
            # close every window strictly older than the current one
            for w in [w for w in self.windows if w < win]:
                try:
                    self._build_window(w)
                finally:
                    del self.windows[w]
            self._prune(ts)
            return self._risk_for(src_ip, ts)

    def _build_window(self, win):
        flows = self.windows.get(win) or []
        if len(flows) < 2:
            return
        ips = {}
        for t in flows:
            for ip in (t["src_ip"], t["dst_ip"]):
                ips.setdefault(ip, []).append(t)
        if len(ips) < 2:
            return
        ip_ids = {ip: i for i, ip in enumerate(ips)}
        x = np.zeros((len(ips), NODE_FEAT_DIM), dtype=np.float32)
        edges = set()
        for ip, fl in ips.items():
            i = ip_ids[ip]
            ports = set()
            peers = set()
            protos = set()
            durs = []
            maxp = 0.0
            f = x[i]
            for t in fl:
                f[0] += 1
                f[1] += t["fwd_bytes"] + t["bwd_bytes"]
                f[2] += t["fwd_pkts"] + t["bwd_pkts"]
                durs.append(t["duration_us"])
                f[8] += t["syn"]
                f[9] += t["rst"]
                f[10] += t["fin"]
                f[11] += t["ack"]
                if t["max_pkt"] > maxp:
                    maxp = t["max_pkt"]
                ports.add(t["src_port"])
                ports.add(t["dst_port"])
                peers.add(t["src_ip"])
                peers.add(t["dst_ip"])
                protos.add(t["protocol"])
                edges.add((t["src_ip"], t["dst_ip"]))
            f[3] = sum(t["avg_pkt"] for t in fl) / len(fl)
            f[4] = len(ports)
            f[5] = len(peers)
            # f[6] stays 0.0 (label-derived feature ablated, fusion protocol)
            f[7] = len(protos)
            f[12] = sum(durs)
            f[13] = f[12] / len(durs)
            f[14] = maxp
            f[15] = 1.0 if any(p in WEB_PORTS for p in ports) else (0.5 if 22 in ports else 0.0)

        x = (x - self.mean) / self.std
        edge_index = np.array(
            [[ip_ids[a], ip_ids[b]] for a, b in edges], dtype=np.int64
        ).T
        if edge_index.size == 0:
            return
        logits = self.sess.run(None, {"x": x, "edge_index": edge_index})[0]
        risk = 1.0 / (1.0 + np.exp(-np.asarray(logits, dtype=np.float64)))
        for ip, i in ip_ids.items():
            self.timeline.setdefault(ip, []).append((win, float(risk[i])))

    def _risk_for(self, ip, ts):
        entries = self.timeline.get(ip)
        if not entries:
            return 0.0
        starts = [p[0] for p in entries]
        hi = bisect.bisect_left(starts, ts)                      # strictly before ts
        lo = bisect.bisect_left(starts, ts - LOOKBACK_SECONDS)   # 60s lookback
        window_risks = [r for _, r in entries[lo:hi]]
        if not window_risks:
            return 0.0
        return float(sum(window_risks) / len(window_risks))

    def _prune(self, now):
        cutoff = now - TIMELINE_TTL
        for ip in list(self.timeline):
            kept = [p for p in self.timeline[ip] if p[0] >= cutoff]
            if kept:
                self.timeline[ip] = kept
            else:
                del self.timeline[ip]

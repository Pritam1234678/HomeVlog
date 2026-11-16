"""CLI entry — ties capture -> flows -> features -> /ai/predict together.

Modes:
  offline:  python worker.py --pcap path/to.pcap [--no-post]
  live:     sudo python worker.py --iface eth0 [--api-url ...]
"""
import argparse
import json
import sys
import time

from features import FeatureExtractor, to_feature_vector
from flows import FlowManager
import capture


def build_parser():
    p = argparse.ArgumentParser(description="PredictShield packet -> feature worker")
    src = p.add_mutually_exclusive_group(required=True)
    src.add_argument("--pcap", help="path to .pcap/.pcapng file (offline replay)")
    src.add_argument("--iface", help="network interface to sniff (live capture)")
    p.add_argument("--api-url", default="http://127.0.0.1:8000", help="AI engine base URL")
    p.add_argument("--window", type=float, default=2.0, help="flow flush idle window (seconds)")
    p.add_argument("--no-post", action="store_true", help="print features only, don't call API")
    p.add_argument("--device-id", default="capture-node", help="device_id sent to the API")
    return p


def main():
    args = build_parser().parse_args()

    extractor = FeatureExtractor()
    manager = FlowManager(flush_interval=args.window)

    def handle_packet(parsed):
        manager.on_packet(parsed)
        for flow in manager.flush_due(now=parsed.timestamp):
            emit_flow(flow, extractor, args)

    def finish():
        for flow in manager.flush_all():
            emit_flow(flow, extractor, args)

    if args.pcap:
        capture.read_pcap(args.pcap, handle_packet)
        finish()
    else:
        capture.sniff_live(args.iface, handle_packet)
        finish()


def emit_flow(flow, extractor, args):
    features = extractor.extract(flow)
    vector = to_feature_vector(features)

    # per-flow data for the live GNN (5-second IP graphs + causal risk)
    topology = {
        "src_ip": flow.src_ip, "dst_ip": flow.dst_ip,
        "src_port": flow.src_port, "dst_port": flow.dst_port,
        "protocol": flow.protocol,
        "ts": flow.last_time,
        "duration_us": features["Flow Duration"],
        "fwd_pkts": features["Total Fwd Packets"],
        "bwd_pkts": features["Total Backward Packets"],
        "fwd_bytes": features["Total Length of Fwd Packets"],
        "bwd_bytes": features["Total Length of Bwd Packets"],
        "avg_pkt": features["Average Packet Size"],
        "max_pkt": features["Max Packet Length"],
        "syn": features["SYN Flag Count"],
        "rst": features["RST Flag Count"],
        "fin": features["FIN Flag Count"],
        "ack": features["ACK Flag Count"],
    }

    if args.no_post:
        print(json.dumps(vector))
        return

    try:
        import requests
        resp = requests.post(
            f"{args.api_url}/ai/predict",
            json={"features": vector, "device_id": args.device_id, "topology": topology},
            timeout=10,
        )
        print(f"[{resp.status_code}] flow={flow.key} -> {resp.text}")
    except Exception as exc:
        print(f"[error] posting flow {flow.key}: {exc}", file=sys.stderr)


if __name__ == "__main__":
    main()

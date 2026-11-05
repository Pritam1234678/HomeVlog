"""Feature extraction — pure functions, no I/O.

Turns a finished flow (see flows.FlowState) into the 77 CICFlowMeter
features, in the exact order used by the CICIDS2017 training dataset.
"""
import math
import statistics

# Canonical order — MUST match the CICIDS2017 CSV header (minus the Label column).
FEATURE_ORDER = [
    "Destination Port",
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Total Length of Fwd Packets",
    "Total Length of Bwd Packets",
    "Fwd Packet Length Max",
    "Fwd Packet Length Min",
    "Fwd Packet Length Mean",
    "Fwd Packet Length Std",
    "Bwd Packet Length Max",
    "Bwd Packet Length Min",
    "Bwd Packet Length Mean",
    "Bwd Packet Length Std",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Flow IAT Mean",
    "Flow IAT Std",
    "Flow IAT Max",
    "Flow IAT Min",
    "Fwd IAT Total",
    "Fwd IAT Mean",
    "Fwd IAT Std",
    "Fwd IAT Max",
    "Fwd IAT Min",
    "Bwd IAT Total",
    "Bwd IAT Mean",
    "Bwd IAT Std",
    "Bwd IAT Max",
    "Bwd IAT Min",
    "Fwd PSH Flags",
    "Bwd PSH Flags",
    "Fwd URG Flags",
    "Bwd URG Flags",
    "Fwd Header Length",
    "Bwd Header Length",
    "Fwd Packets/s",
    "Bwd Packets/s",
    "Min Packet Length",
    "Max Packet Length",
    "Packet Length Mean",
    "Packet Length Std",
    "Packet Length Variance",
    "FIN Flag Count",
    "SYN Flag Count",
    "RST Flag Count",
    "PSH Flag Count",
    "ACK Flag Count",
    "URG Flag Count",
    "CWE Flag Count",
    "ECE Flag Count",
    "Down/Up Ratio",
    "Average Packet Size",
    "Avg Fwd Segment Size",
    "Avg Bwd Segment Size",
    "Fwd Avg Bytes/Bulk",
    "Fwd Avg Packets/Bulk",
    "Fwd Avg Bulk Rate",
    "Bwd Avg Bytes/Bulk",
    "Bwd Avg Packets/Bulk",
    "Bwd Avg Bulk Rate",
    "Subflow Fwd Packets",
    "Subflow Fwd Bytes",
    "Subflow Bwd Packets",
    "Subflow Bwd Bytes",
    "Init_Win_bytes_forward",
    "Init_Win_bytes_backward",
    "act_data_pkt_fwd",
    "min_seg_size_forward",
    "Active Mean",
    "Active Std",
    "Active Max",
    "Active Min",
    "Idle Mean",
    "Idle Std",
    "Idle Max",
    "Idle Min",
]

MIN_DURATION = 0.001
BULK_IAT_THRESHOLD = 1.0      # seconds
IDLE_THRESHOLD = 1.0          # seconds


def _stats(values):
    """Return (mean, std, max, min) of a numeric list. Empty -> zeros."""
    if not values:
        return 0.0, 0.0, 0.0, 0.0
    if len(values) == 1:
        return float(values[0]), 0.0, float(values[0]), float(values[0])
    return (
        float(statistics.mean(values)),
        float(statistics.stdev(values)),
        float(max(values)),
        float(min(values)),
    )


def _iat(ts_list):
    """Inter-arrival times between consecutive timestamps."""
    return [ts_list[i] - ts_list[i - 1] for i in range(1, len(ts_list))]


def _safe_div(a, b):
    return (a / b) if b else 0.0


def _ratio(num, den):
    if den == 0:
        return 1.0 if num > 0 else 0.0
    return num / den


class FeatureExtractor:
    def extract(self, flow) -> dict:
        duration = flow.last_time - flow.start_time
        duration = duration if duration > 0 else MIN_DURATION

        fwd_pkts = len(flow.fwd_pkt_lens)
        bwd_pkts = len(flow.bwd_pkt_lens)
        total_pkts = fwd_pkts + bwd_pkts

        fwd_bytes = flow.fwd_bytes
        bwd_bytes = flow.bwd_bytes
        total_bytes = flow.total_bytes

        # per-direction packet length stats
        fwd_len_mean, fwd_len_std, fwd_len_max, fwd_len_min = _stats(flow.fwd_pkt_lens)
        bwd_len_mean, bwd_len_std, bwd_len_max, bwd_len_min = _stats(flow.bwd_pkt_lens)

        all_lens = flow.fwd_pkt_lens + flow.bwd_pkt_lens
        pkt_len_mean, pkt_len_std, pkt_len_max, pkt_len_min = _stats(all_lens)
        pkt_len_var = float(statistics.pvariance(all_lens)) if len(all_lens) > 1 else 0.0

        # IAT stats
        flow_iat = _iat(flow.all_times)
        fwd_iat = _iat(flow.fwd_times)
        bwd_iat = _iat(flow.bwd_times)

        flow_iat_mean, flow_iat_std, flow_iat_max, flow_iat_min = _stats(flow_iat)
        fwd_iat_total = float(sum(fwd_iat))
        fwd_iat_mean, fwd_iat_std, fwd_iat_max, fwd_iat_min = _stats(fwd_iat)
        bwd_iat_total = float(sum(bwd_iat))
        bwd_iat_mean, bwd_iat_std, bwd_iat_max, bwd_iat_min = _stats(bwd_iat)

        # segment size stats
        avg_fwd_seg = float(statistics.mean(flow.fwd_seg_lens)) if flow.fwd_seg_lens else 0.0
        avg_bwd_seg = float(statistics.mean(flow.bwd_seg_lens)) if flow.bwd_seg_lens else 0.0

        # header length means
        fwd_header = float(statistics.mean(flow.fwd_header_lens)) if flow.fwd_header_lens else 0.0
        bwd_header = float(statistics.mean(flow.bwd_header_lens)) if flow.bwd_header_lens else 0.0

        # bulk / subflow / active-idle (per-direction)
        fwd_bulk = self._bulk_stats(flow.fwd_times, flow.fwd_seg_lens)
        bwd_bulk = self._bulk_stats(flow.bwd_times, flow.bwd_seg_lens)
        fwd_subflow = self._subflow_stats(flow.fwd_times, flow.fwd_seg_lens, flow_iat_mean)
        bwd_subflow = self._subflow_stats(flow.bwd_times, flow.bwd_seg_lens, flow_iat_mean)
        active, idle = self._active_idle(flow.all_times)

        features = {
            "Destination Port": flow.dst_port,
            "Flow Duration": duration,
            "Total Fwd Packets": fwd_pkts,
            "Total Backward Packets": bwd_pkts,
            "Total Length of Fwd Packets": fwd_bytes,
            "Total Length of Bwd Packets": bwd_bytes,
            "Fwd Packet Length Max": fwd_len_max,
            "Fwd Packet Length Min": fwd_len_min,
            "Fwd Packet Length Mean": fwd_len_mean,
            "Fwd Packet Length Std": fwd_len_std,
            "Bwd Packet Length Max": bwd_len_max,
            "Bwd Packet Length Min": bwd_len_min,
            "Bwd Packet Length Mean": bwd_len_mean,
            "Bwd Packet Length Std": bwd_len_std,
            "Flow Bytes/s": _safe_div(total_bytes, duration),
            "Flow Packets/s": _safe_div(total_pkts, duration),
            "Flow IAT Mean": flow_iat_mean,
            "Flow IAT Std": flow_iat_std,
            "Flow IAT Max": flow_iat_max,
            "Flow IAT Min": flow_iat_min,
            "Fwd IAT Total": fwd_iat_total,
            "Fwd IAT Mean": fwd_iat_mean,
            "Fwd IAT Std": fwd_iat_std,
            "Fwd IAT Max": fwd_iat_max,
            "Fwd IAT Min": fwd_iat_min,
            "Bwd IAT Total": bwd_iat_total,
            "Bwd IAT Mean": bwd_iat_mean,
            "Bwd IAT Std": bwd_iat_std,
            "Bwd IAT Max": bwd_iat_max,
            "Bwd IAT Min": bwd_iat_min,
            "Fwd PSH Flags": flow.fwd_psh_count,
            "Bwd PSH Flags": flow.bwd_psh_count,
            "Fwd URG Flags": flow.fwd_urg_count,
            "Bwd URG Flags": flow.bwd_urg_count,
            "Fwd Header Length": fwd_header,
            "Bwd Header Length": bwd_header,
            "Fwd Packets/s": _safe_div(fwd_pkts, duration),
            "Bwd Packets/s": _safe_div(bwd_pkts, duration),
            "Min Packet Length": pkt_len_min,
            "Max Packet Length": pkt_len_max,
            "Packet Length Mean": pkt_len_mean,
            "Packet Length Std": pkt_len_std,
            "Packet Length Variance": pkt_len_var,
            "FIN Flag Count": flow.fin_count,
            "SYN Flag Count": flow.syn_count,
            "RST Flag Count": flow.rst_count,
            "PSH Flag Count": flow.psh_count,
            "ACK Flag Count": flow.ack_count,
            "URG Flag Count": flow.urg_count,
            "CWE Flag Count": flow.cwe_count,
            "ECE Flag Count": flow.ece_count,
            "Down/Up Ratio": _ratio(bwd_bytes, fwd_bytes),
            "Average Packet Size": _safe_div(total_bytes, total_pkts),
            "Avg Fwd Segment Size": avg_fwd_seg,
            "Avg Bwd Segment Size": avg_bwd_seg,
            "Fwd Avg Bytes/Bulk": fwd_bulk["avg_bytes"],
            "Fwd Avg Packets/Bulk": fwd_bulk["avg_packets"],
            "Fwd Avg Bulk Rate": fwd_bulk["avg_rate"],
            "Bwd Avg Bytes/Bulk": bwd_bulk["avg_bytes"],
            "Bwd Avg Packets/Bulk": bwd_bulk["avg_packets"],
            "Bwd Avg Bulk Rate": bwd_bulk["avg_rate"],
            "Subflow Fwd Packets": fwd_subflow["avg_packets"],
            "Subflow Fwd Bytes": fwd_subflow["avg_bytes"],
            "Subflow Bwd Packets": bwd_subflow["avg_packets"],
            "Subflow Bwd Bytes": bwd_subflow["avg_bytes"],
            "Init_Win_bytes_forward": float(flow.fwd_init_win if flow.fwd_init_win is not None else 0),
            "Init_Win_bytes_backward": float(flow.bwd_init_win if flow.bwd_init_win is not None else 0),
            "act_data_pkt_fwd": sum(1 for s in flow.fwd_seg_lens if s > 0),
            "min_seg_size_forward": min(flow.fwd_seg_lens) if flow.fwd_seg_lens else 0,
            "Active Mean": active[0],
            "Active Std": active[1],
            "Active Max": active[2],
            "Active Min": active[3],
            "Idle Mean": idle[0],
            "Idle Std": idle[1],
            "Idle Max": idle[2],
            "Idle Min": idle[3],
        }
        return features

    @staticmethod
    def _bulk_stats(times, seg_lens):
        """Bulk = consecutive same-direction packets with payload and IAT < 1s."""
        if not times:
            return {"avg_bytes": 0.0, "avg_packets": 0.0, "avg_rate": 0.0}

        bulks = []  # each: (byte_sum, packet_count, duration)
        cur_bytes = 0
        cur_pkts = 0
        cur_start = times[0]
        prev_t = times[0]
        started = False

        for i, (t, seg) in enumerate(zip(times, seg_lens)):
            if seg <= 0:
                # no payload -> end current bulk
                if started:
                    bulks.append((cur_bytes, cur_pkts, max(prev_t - cur_start, 0.001)))
                    started = False
                continue
            if not started:
                cur_bytes = seg
                cur_pkts = 1
                cur_start = t
                prev_t = t
                started = True
            else:
                iat = t - prev_t
                if iat < BULK_IAT_THRESHOLD:
                    cur_bytes += seg
                    cur_pkts += 1
                    prev_t = t
                else:
                    bulks.append((cur_bytes, cur_pkts, max(prev_t - cur_start, 0.001)))
                    cur_bytes = seg
                    cur_pkts = 1
                    cur_start = t
                    prev_t = t

        if started:
            bulks.append((cur_bytes, cur_pkts, max(prev_t - cur_start, 0.001)))

        if not bulks:
            return {"avg_bytes": 0.0, "avg_packets": 0.0, "avg_rate": 0.0}

        avg_bytes = float(statistics.mean(b[0] for b in bulks))
        avg_packets = float(statistics.mean(b[1] for b in bulks))
        avg_rate = float(statistics.mean(b[0] / b[2] for b in bulks))
        return {"avg_bytes": avg_bytes, "avg_packets": avg_packets, "avg_rate": avg_rate}

    @staticmethod
    def _subflow_stats(times, seg_lens, flow_iat_mean):
        """Subflow = same-direction burst with IAT < flow average IAT."""
        if not times:
            return {"avg_packets": 0.0, "avg_bytes": 0.0}

        subflows = []  # (bytes, packets)
        cur_bytes = seg_lens[0]
        cur_pkts = 1
        prev_t = times[0]

        for i in range(1, len(times)):
            iat = times[i] - prev_t
            if iat < flow_iat_mean:
                cur_bytes += seg_lens[i]
                cur_pkts += 1
            else:
                subflows.append((cur_bytes, cur_pkts))
                cur_bytes = seg_lens[i]
                cur_pkts = 1
            prev_t = times[i]

        subflows.append((cur_bytes, cur_pkts))

        avg_bytes = float(statistics.mean(s[0] for s in subflows))
        avg_packets = float(statistics.mean(s[1] for s in subflows))
        return {"avg_packets": avg_packets, "avg_bytes": avg_bytes}

    @staticmethod
    def _active_idle(times):
        """Split flow into active periods (between idles) and idle periods (gap > 1s)."""
        if not times:
            return (0.0, 0.0, 0.0, 0.0), (0.0, 0.0, 0.0, 0.0)

        actives = []
        idles = []
        active_start = times[0]
        prev_t = times[0]

        for i in range(1, len(times)):
            gap = times[i] - prev_t
            if gap > IDLE_THRESHOLD:
                actives.append(prev_t - active_start)
                idles.append(gap)
                active_start = times[i]
            prev_t = times[i]

        actives.append(prev_t - active_start)

        return _stats(actives), _stats(idles)


def to_feature_vector(features: dict) -> list:
    """Return feature values as a list in FEATURE_ORDER (the model input row)."""
    return [features[name] for name in FEATURE_ORDER]

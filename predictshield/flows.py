"""Flow grouping — 5-tuple keyed state with time-window flush.

FlowState stores the raw per-packet records CICFlowMeter needs, then
features.py computes the 77 features from those records on flush.
"""
import time


class FlowState:
    """Accumulates per-flow packet data until it is flushed and turned into features."""

    def __init__(self, key, start_time):
        self.key = key  # (src_ip, dst_ip, src_port, dst_port, protocol)
        self.src_ip, self.dst_ip, self.src_port, self.dst_port, self.protocol = key
        self.start_time = start_time
        self.last_time = start_time

        # all packets (in arrival order): each record is a dict of per-packet facts
        self.records = []

        # per-direction lists (direction = packet.src_ip == flow.src_ip -> forward)
        self.fwd_pkt_lens = []   # full IP packet sizes (forward)
        self.bwd_pkt_lens = []   # full IP packet sizes (backward)
        self.fwd_seg_lens = []   # TCP payload sizes (forward)
        self.bwd_seg_lens = []   # TCP payload sizes (backward)
        self.fwd_times = []      # arrival timestamps (forward)
        self.bwd_times = []      # arrival timestamps (backward)
        self.all_times = []      # arrival timestamps (both directions)

        # flag counts (both directions combined)
        self.fin_count = 0
        self.syn_count = 0
        self.rst_count = 0
        self.psh_count = 0
        self.ack_count = 0
        self.urg_count = 0
        self.cwe_count = 0
        self.ece_count = 0

        # per-direction PSH / URG / header lengths
        self.fwd_psh_count = 0
        self.bwd_psh_count = 0
        self.fwd_urg_count = 0
        self.bwd_urg_count = 0
        self.fwd_header_lens = []
        self.bwd_header_lens = []

        # TCP window (first packet per direction = init window)
        self.fwd_init_win = None
        self.bwd_init_win = None

        # bytes
        self.fwd_bytes = 0
        self.bwd_bytes = 0
        self.total_bytes = 0

        # misc
        self.ttl_value = 0
        self.src_ips_seen = set()

        # not used by the 77 CICFlowMeter features, kept for compatibility
        self.packets = []
        self.timestamps = []
        self.fail_login_count = 0
        self.raw_payloads = []
        self.dns_qnames = []

    def update(self, parsed):
        """Record one parsed packet against this flow."""
        now = parsed.timestamp
        self.last_time = max(self.last_time, now)
        self.all_times.append(now)
        self.src_ips_seen.add(parsed.src_ip)
        self.ttl_value = parsed.ttl
        self.total_bytes += parsed.size

        is_forward = parsed.src_ip == self.src_ip
        payload_len = len(parsed.payload)

        if is_forward:
            self.fwd_pkt_lens.append(parsed.size)
            self.fwd_seg_lens.append(payload_len)
            self.fwd_times.append(now)
            self.fwd_bytes += parsed.size
            if parsed.psh_flag:
                self.fwd_psh_count += 1
            if parsed.urg_flag:
                self.fwd_urg_count += 1
            if parsed.header_len:
                self.fwd_header_lens.append(parsed.header_len)
            if self.fwd_init_win is None and parsed.protocol == 6:
                self.fwd_init_win = parsed.window
        else:
            self.bwd_pkt_lens.append(parsed.size)
            self.bwd_seg_lens.append(payload_len)
            self.bwd_times.append(now)
            self.bwd_bytes += parsed.size
            if parsed.psh_flag:
                self.bwd_psh_count += 1
            if parsed.urg_flag:
                self.bwd_urg_count += 1
            if parsed.header_len:
                self.bwd_header_lens.append(parsed.header_len)
            if self.bwd_init_win is None and parsed.protocol == 6:
                self.bwd_init_win = parsed.window

        # combined flag counts
        if parsed.syn_flag:
            self.syn_count += 1
        if parsed.rst_flag:
            self.rst_count += 1
        if parsed.ack_flag:
            self.ack_count += 1
        if parsed.fin_flag:
            self.fin_count += 1
        if parsed.psh_flag:
            self.psh_count += 1
        if parsed.urg_flag:
            self.urg_count += 1
        if parsed.cwe_flag:
            self.cwe_count += 1
        if parsed.ece_flag:
            self.ece_count += 1

        # compatibility mirrors
        self.packets.append(parsed.size)
        self.timestamps.append(now)
        if parsed.payload:
            self.raw_payloads.append(parsed.payload)
        if parsed.dns_qname:
            self.dns_qnames.append(parsed.dns_qname)
        if parsed.is_failed_login:
            self.fail_login_count += 1


class FlowManager:
    """Buckets packets into flows and flushes finished flows after an idle window."""

    def __init__(self, flush_interval=2.0):
        self.flush_interval = flush_interval
        self.flows = {}

    def _flow_key(self, parsed):
        return (
            parsed.src_ip,
            parsed.dst_ip,
            parsed.src_port,
            parsed.dst_port,
            parsed.protocol,
        )

    def on_packet(self, parsed):
        key = self._flow_key(parsed)
        flow = self.flows.get(key)
        if flow is None:
            flow = FlowState(key, parsed.timestamp)
            self.flows[key] = flow
        flow.update(parsed)

    def flush_due(self, now=None):
        """Return (and remove) flows idle for at least flush_interval seconds."""
        now = now if now is not None else time.time()
        due = [
            flow for flow in self.flows.values()
            if now - flow.last_time >= self.flush_interval
        ]
        for flow in due:
            del self.flows[flow.key]
        return due

    def flush_all(self):
        """Return (and remove) every remaining flow. For shutdown/EOF."""
        flows = list(self.flows.values())
        self.flows.clear()
        return flows

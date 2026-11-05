"""Packet ingestion — live sniffing and offline PCAP replay.

This is the only module that touches Scapy. Everything downstream
(flows, features) operates on plain ParsedPacket objects.
"""
import time
from dataclasses import dataclass, field


@dataclass
class ParsedPacket:
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: int
    ttl: int
    size: int
    timestamp: float = field(default_factory=time.time)
    # TCP flags (bitwise)
    syn_flag: bool = False
    ack_flag: bool = False
    rst_flag: bool = False
    fin_flag: bool = False
    psh_flag: bool = False
    urg_flag: bool = False
    cwe_flag: bool = False
    ece_flag: bool = False
    # TCP internals
    header_len: int = 0
    window: int = 0
    payload: bytes = b""
    dns_qname: bytes = b""
    is_failed_login: bool = False


AUTH_PORTS = {22, 21, 23, 3389}
TCP_FIN = 0x01
TCP_SYN = 0x02
TCP_RST = 0x04
TCP_PSH = 0x08
TCP_ACK = 0x10
TCP_URG = 0x20
TCP_ECE = 0x40
TCP_CWR = 0x80


def parse_packet(packet) -> ParsedPacket:
    """Extract a ParsedPacket from a Scapy packet. Returns None for non-IP."""
    try:
        from scapy.layers.inet import IP, TCP, UDP
    except Exception:
        return None

    if IP not in packet:
        return None

    ip = packet[IP]
    proto = ip.proto
    src_ip = ip.src
    dst_ip = ip.dst
    ttl = ip.ttl
    size = len(packet)

    parsed = ParsedPacket(
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=0,
        dst_port=0,
        protocol=proto,
        ttl=ttl,
        size=size,
    )

    if TCP in packet:
        tcp = packet[TCP]
        flags = tcp.flags
        parsed.src_port = tcp.sport
        parsed.dst_port = tcp.dport
        parsed.syn_flag = bool(flags & TCP_SYN)
        parsed.ack_flag = bool(flags & TCP_ACK)
        parsed.rst_flag = bool(flags & TCP_RST)
        parsed.fin_flag = bool(flags & TCP_FIN)
        parsed.psh_flag = bool(flags & TCP_PSH)
        parsed.urg_flag = bool(flags & TCP_URG)
        parsed.ece_flag = bool(flags & TCP_ECE)
        parsed.cwe_flag = bool(flags & TCP_CWR)
        parsed.header_len = int(getattr(tcp, "dataofs", 5) * 4)
        parsed.window = int(getattr(tcp, "window", 0))
        parsed.payload = bytes(tcp.payload)
    elif UDP in packet:
        udp = packet[UDP]
        parsed.src_port = udp.sport
        parsed.dst_port = udp.dport
        parsed.payload = bytes(udp.payload)
    else:
        parsed.payload = bytes(ip.payload)

    if parsed.dst_port == 53 or parsed.src_port == 53:
        parsed.dns_qname = _extract_dns_qname(parsed.payload)

    parsed.is_failed_login = _is_failed_login(parsed)

    return parsed


def _extract_dns_qname(payload: bytes) -> bytes:
    """Parse the first DNS question's qname. Returns empty on malformed input."""
    try:
        if len(payload) < 12:
            return b""
        offset = 12
        labels = []
        while offset < len(payload):
            length = payload[offset]
            if length == 0:
                break
            if length & 0xC0:  # compression pointer
                break
            offset += 1
            label = payload[offset:offset + length]
            labels.append(label)
            offset += length
        return b".".join(labels)
    except Exception:
        return b""


def _is_failed_login(parsed: ParsedPacket) -> bool:
    """Heuristic: small payloads on auth ports, often paired with SYN/RST."""
    if parsed.dst_port not in AUTH_PORTS and parsed.src_port not in AUTH_PORTS:
        return False
    if len(parsed.payload) >= 20:
        return False
    return parsed.syn_flag or parsed.rst_flag or (parsed.protocol == 6 and len(parsed.payload) == 0)


def read_pcap(path, prn):
    """Read packets from a .pcap/.pcapng file and pass each to prn(parsed_packet)."""
    from scapy.all import rdpcap  # scapy.all registers IP/TCP/UDP dissectors

    packets = rdpcap(path)
    for packet in packets:
        parsed = parse_packet(packet)
        if parsed is not None:
            prn(parsed)


def sniff_live(iface, prn, count=0):
    """Sniff live traffic on an interface and pass each packet to prn."""
    from scapy.all import sniff as _sniff

    def callback(packet):
        parsed = parse_packet(packet)
        if parsed is not None:
            prn(parsed)

    _sniff(iface=iface, prn=callback, store=False, count=count)

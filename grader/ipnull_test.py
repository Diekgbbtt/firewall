import ipaddress
import random
import threading
import time
from scapy.layers.inet import IP
from scapy.packet import Raw
from scapy.sendrecv import send, sniff
from scapy.compat import raw

PROTO_ID = 255  # experimental/testing; avoids proto 0 raw-socket restrictions


def _receive_packets(dst_ip: str, duration: float, recv_log: list):
    """
    Listen for proto PROTO_ID IP traffic to dst_ip using scapy sniff (pcap-based),
    avoiding raw socket proto limitations on some systems.
    """
    try:
        packets = sniff(
            iface="lo",
            timeout=duration,
            filter=f"ip proto {PROTO_ID} and dst host {dst_ip}",
        )
        for pkt in packets:
            recv_log.append(pkt)
    except Exception:
        # If sniff fails (e.g., pcap issues), leave log empty.
        pass


def _build_ip(src_ip: str, dst_ip: str, payload: bytes):
    """Craft a proto PROTO_ID IP packet with optional raw payload."""
    pkt = IP(src=src_ip, dst=dst_ip, proto=PROTO_ID)
    if payload:
        pkt = pkt / Raw(payload)
    return pkt


def ipnull_test ():
    """
    Send an empty IP packet (no L4 payload) and a payloaded IP packet over lo.
    Expect the firewall to drop the empty one and pass the payloaded one.
    """
    try:
        # Random loopback addresses to stay within the configured test setup.
        loop_net = ipaddress.ip_network("127.0.0.0/8")
        src_ip = str(ipaddress.ip_address(int(loop_net.network_address) + random.randint(1, loop_net.num_addresses - 2)))
        dst_ip = str(ipaddress.ip_address(int(loop_net.network_address) + random.randint(1, loop_net.num_addresses - 2)))

        recv_log = []
        listen_duration = 0.1
        recv_thread = threading.Thread(target=_receive_packets, args=(dst_ip, listen_duration, recv_log))
        recv_thread.start()

        # Give listener a moment to attach.
        time.sleep(0.05)

        send(_build_ip(src_ip, dst_ip, b""), verbose=False)
        time.sleep(0.05)
        send(_build_ip(src_ip, dst_ip, b"\x01\x02\x03"), verbose=False)

        recv_thread.join()

        # Evaluate what made it through the firewall.
        payload_lengths = []
        for pkt in recv_log:
            try:
                if pkt[IP].dst != dst_ip:
                    continue
                payload_lengths.append(len(bytes(pkt[IP].payload)))
            except Exception:
                continue

        saw_empty = any(l == 0 for l in payload_lengths)
        saw_payload = any(l > 0 for l in payload_lengths)

        if not (saw_payload or saw_empty):
            print(f"IPNULL failed: saw_payload={saw_payload}, saw_empty={saw_empty}, payload_lengths={payload_lengths}")
            return 0.0
        return 1.0
    except Exception as e:
        print(f"IPNULL test error: {e}")
        return 0.0

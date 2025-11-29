import random
import threading
import time
from scapy.layers.inet import IP
from scapy.packet import Raw
from scapy.sendrecv import send, sniff
from scapy.compat import raw
from grader_utility import get_test_net, host_in_net, raw_listen, raw_send, tcp_listen, tcp_send, udp_listen, udp_send

    # Idea:
    # 1) Generate random IP sources and destinations (make sure they don't collide with blacklisted or NATed ranges)
    # 2) Create an IP packet with a payload of 0. Since the payload is zero, it means it is neither a UDP nor TCP packet, it is only IP.
    # 3) Send the empty IP packet.
    # 4) Listen at the source or destination for information on whether the packet was dropped by the firewall.



def ipnull_test():
    """
    Send an empty IP packet (no L4 payload) and a payloaded IP packet over lo.
    Expect the firewall to drop the empty one and pass the payloaded one.
    """
    try:
        loop_net = get_test_net("ipnull")
        src_ip = host_in_net(loop_net, 1)
        dst_ip = host_in_net(loop_net, 2)
        sport = random.randint(1, 65535)
        dport = random.randint(1, 65535)

        recv_log = []
        listen_duration = 1.0
        time_log = []
        
        rrcvr_t = threading.Thread(target=raw_listen, args=(dst_ip, listen_duration, recv_log, time_log))
        rrcvr_t.start()
        time.sleep(0.05)
        urcvr_t = threading.Thread(target=udp_listen, args=(dst_ip, dport, listen_duration, recv_log, time_log))
        urcvr_t.start()
        time.sleep(0.05)
        trcvr_t = threading.Thread(target=tcp_listen, args=(dst_ip, dport, listen_duration, recv_log, time_log))
        trcvr_t.start()
        
        # Give listener a moment to attach.

        raw_send(src_ip, dst_ip)
            # send(_build_ip(src_ip, dst_ip, b""), verbose=False)
        time.sleep(0.05)
        #     # send(_build_ip(src_ip, dst_ip, b"\x01\x02\x03"), verbose=False)
        # udp_send(src_ip, sport, dst_ip, dport, [b"\x01\x02\x03"], [0.0])
        
        
        tcp_send(src_ip, sport, dst_ip, dport, [b"\x01\x02\x03"], [0.0])
        time.sleep(0.005)
        udp_send(src_ip, sport, dst_ip, dport, [b"\x01\x02\x03"], [0.0])
        
        payload_lengths = []
        # for proto_name, t, pkt_log in listeners:
        rrcvr_t.join()
        urcvr_t.join()
        trcvr_t.join()
        for payload, _ in recv_log:
            plen = len(payload)
            payload_lengths.append(plen)
            print(f"[ipnull] received {plen} bytes, payload={payload!r}")


        saw_empty = any(l == 0 for l in payload_lengths)
        saw_payload = len([l > 0 for l in payload_lengths])

        if not saw_payload==2 or saw_empty:
            print(f"IPNULL failed: saw_payload={saw_payload}, saw_empty={saw_empty}, payload_lengths={payload_lengths}")
            return 0.0
        return 1.0
    except Exception as e:
        print(f"IPNULL test error: {e}")
        return 0.0

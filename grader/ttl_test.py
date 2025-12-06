import os
import dpkt
from scapy.layers.inet import TCP
from grader_utility import get_test_net, host_in_net, raw_listen, raw_send, tcp_listen, tcp_send, udp_listen, udp_send, parse_ttl_config
import random
import time
import threading


def ttl_test ():

    # Think about how to approach testing this firewall feature. We suggest using a similar approach as with the transparency test.
    # This is not graded but the intended use is that this function returns 1 if your TTL firewall feature works, and 0 if it fails completely.
    try:
        cfg_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "configuration_files", "ttl_config.csv")
        ttl_conf = parse_ttl_config(cfg_path)
        ttl_net = get_test_net("ttl")
        src_ip = host_in_net(ttl_net, 1)
        dst_ip = host_in_net(ttl_net, 2)
        sport = random.randint(1, 65535)
        dport = random.randint(1, 65535)

        recv_log = []
        listen_duration = 1.0
        time_log = []

        # Capture raw IP packets so TTL is present; UDP/TCP listeners only see payload bytes.
        # print(f"[ttl] spinning listener dst={dst_ip} sport={sport} dport={dport}")
        rtcp_rcvr_t = threading.Thread(target=raw_listen, args=(dst_ip, listen_duration, recv_log, time_log, dport, 6))
        rtcp_rcvr_t.start()
        time.sleep(0.05)
        rudp_rcvr_t = threading.Thread(target=raw_listen, args=(dst_ip, listen_duration, recv_log, time_log, dport, 17))
        rudp_rcvr_t.start()
        time.sleep(0.05)

        # tl = TCP(sport=sport, dport=dport, flags="S") / b'TTLTESTRAW'
        # ttl_val = random.randint(ttl_conf['MinTTL']+1, ttl_conf['MaxTTL']-1)
        # print(f"[ttl] raw_send ttl={ttl_val}")
        # raw_send(src_ip, dst_ip, proto=dpkt.ip.IP_PROTO_TCP, ttl=ttl_val, transport_layer=tl)
        # time.sleep(0.005)
        ttl_val = random.randint(ttl_conf['MinTTL']+1, ttl_conf['MaxTTL']-1)
        # print(f"[ttl] tcp_send ttl={ttl_val}")
        tcp_send(src_ip, sport, dst_ip, dport, transmission_data=[b'TTLTESTTCP'], transmission_intervals=[0.0], ttl=ttl_val)
        time.sleep(0.005)
        ttl_val = random.randint(ttl_conf['MinTTL']+1, ttl_conf['MaxTTL']-1)
        # print(f"[ttl] udp_send ttl={ttl_val}")
        udp_send(src_ip, sport, dst_ip, dport, transmission_data=[b'TTLTESTUDP'], transmission_intervals=[0.0], ttl=ttl_val)

        received_ttls = []
         
        rudp_rcvr_t.join()
        rtcp_rcvr_t.join()
        # print(f"[ttl] recv_log entries={len(recv_log)}")
        for idx, (pkt, _) in enumerate(recv_log):
            raw_pkt = pkt.get_payload() if hasattr(pkt, "get_payload") else pkt
            # # print(f"[ttl] log[{idx}] len={len(raw_pkt)} bytes={raw_pkt[:40]!r}")
            # if len(raw_pkt) < dpkt.ip.IP_HDR_LEN:
            #     # print(f"[ttl] skipping short packet len={len(raw_pkt)}")
            #     continue
            try:
                ip = dpkt.ip.IP(raw_pkt)
            except dpkt.NeedData as e:
                print(f"[ttl] skipping : l4 datagrma or truncated ip datagram - packet len={len(raw_pkt)} err={e}")
                continue
            received_ttls.append(ip.ttl)
            print(f"[ttl] received packet with ttl : {ip.ttl}")


        valid = [ttl for ttl in received_ttls if ttl_conf['MinTTL'] < ttl < ttl_conf['MaxTTL']]
        if not valid:
            print(f"[ttl] no packets in allowed TTL range; received_ttls={received_ttls} / rcv_log={recv_log}")
            return 0.0
        return 1.0
    except Exception as e:
        print(f"TTL test error: : {e}")
        return 0.0

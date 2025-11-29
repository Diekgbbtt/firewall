import os
import dpkt
from grader_utility import get_test_net, host_in_net, raw_listen, tcp_send, udp_send, parse_ttl_config
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

        urcvr_t = threading.Thread(target=raw_listen, args=(dst_ip, listen_duration, recv_log, time_log))
        urcvr_t.start()
        time.sleep(0.05)
        trcvr_t = threading.Thread(target=raw_listen, args=(dst_ip, listen_duration, recv_log, time_log))
        trcvr_t.start()
        
        tcp_send(src_ip, sport, dst_ip, dport, [b'TTLTEST'], [0.0], ttl=random.randint(1, ttl_conf['MinTTL']))
        time.sleep(0.005)
        tcp_send(src_ip, sport, dst_ip, dport, [b'TTLTEST'], [0.0], ttl=random.randint(ttl_conf['MaxTTL'], 255))
        time.sleep(0.005)
        tcp_send(src_ip, sport, dst_ip, dport, [b'TTLTEST'], [0.0], ttl=random.randint(ttl_conf['MinTTL']+1, ttl_conf['MinTTL']-1))

        received_ttls = []
         
        urcvr_t.join()
        trcvr_t.join()
        for pkt, _ in recv_log:
            ip=dpkt.ip.IP(pkt.get_payload())
            received_ttls.append(ip.ttl)
            print(f"[ttl] received packet with ttl : {ip.ttl}")

        # for ttl in received_ttls:
        #     if ttl_min < ttl < ttl_max:


        return 1.0 * (len([ttl for ttl in received_ttls if ttl_min < ttl < ttl_max]))
    except Exception as e:
        print(f"TTL test error: : {e}")
        return 0.0
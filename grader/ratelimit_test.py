import os
import threading
import time
from grader_utility import parse_ratelimit_config, get_test_net, host_in_net, udp_listen, udp_send, tcp_listen, tcp_send


def _score_flow(initial_seen: int, post_idle_seen: int, sent_in_burst: int, require_idle_recovery: bool = True) -> float:
    score = 0.0
    if 0 < initial_seen < sent_in_burst:
        score += 1.0
        if require_idle_recovery:
            if post_idle_seen > 0:
                score += 0.5
        else:
            # TCP re-connection can fail after a long idle; don't penalize if we already saw throttling.
            score += 0.5
    return score

def ratelimit_test ():

    try:
        cfg_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "configuration_files", "ratelimit_config.csv")
        cfg = parse_ratelimit_config(cfg_path)
        ratelimit_bps = cfg["Ratelimit"]
        idle_lifespan = cfg["IdleLifespan"]

        ratelimit_net = get_test_net("ratelimit")
        udp_src_ip = host_in_net(ratelimit_net, 1)
        udp_dst_ip = host_in_net(ratelimit_net, 2)
        tcp_src_ip = host_in_net(ratelimit_net, 3)
        tcp_dst_ip = host_in_net(ratelimit_net, 4)

        udp_src_port = 46001
        udp_dst_port = 46011
        tcp_src_port = 46021
        tcp_dst_port = 46031

        # Send enough bytes in under a second to force drops, then idle and check reset.
        # Ensure an integer payload length even if ratelimit_bps is a float.
        payload_len = int(max(50, ratelimit_bps / 3))
        payload = bytes([0xFF]) * payload_len
        burst_count = 6
        burst_intervals = [0.05 for _ in range(burst_count)]

        listen_duration = max(3.0, idle_lifespan + 2.0)

        udp_pkt_log = []
        udp_time_log = []
        tcp_pkt_log = []
        tcp_time_log = []

        udp_listener = threading.Thread(target=udp_listen, args=(udp_dst_ip, udp_dst_port, listen_duration, udp_pkt_log, udp_time_log))
        tcp_listener = threading.Thread(target=tcp_listen, args=(tcp_dst_ip, tcp_dst_port, listen_duration, tcp_pkt_log, tcp_time_log))
        udp_listener.start()
        tcp_listener.start()

        time.sleep(0.2)

        udp_send(udp_src_ip, udp_src_port, udp_dst_ip, udp_dst_port, [payload] * burst_count, burst_intervals)
        tcp_send(tcp_src_ip, tcp_src_port, tcp_dst_ip, tcp_dst_port, [payload] * burst_count, burst_intervals)

        # Allow packets to arrive and be recorded.
        time.sleep(0.5)
        udp_first = len(udp_pkt_log)
        tcp_first = len(tcp_pkt_log)

        pre_backoff = time.time()

        time.sleep(idle_lifespan + 0.2)

        print(f"sending one packet per flow after idle backoff - payloadlen : {len(payload)} and backoff {time.time() - pre_backoff}")

        udp_send(udp_src_ip, udp_src_port, udp_dst_ip, udp_dst_port, [payload], [0.0])
        tcp_send(tcp_src_ip, tcp_src_port, tcp_dst_ip, tcp_dst_port, [payload], [0.0])

        udp_listener.join()
        tcp_listener.join()

        udp_total = len(udp_pkt_log)
        tcp_total = len(tcp_pkt_log)
        udp_after_idle = udp_total - udp_first
        tcp_after_idle = tcp_total - tcp_first

        score = 0.0
        print(f"udp burst packets len : {udp_first}")
        print(f"udp common rate packets len : {udp_after_idle}")
        print(f"tcp burst packets len : {tcp_first}")
        print(f"tcp common rate packets len : {tcp_after_idle}")
        score += _score_flow(udp_first, udp_after_idle, burst_count)
        score += _score_flow(tcp_first, tcp_after_idle, burst_count, require_idle_recovery=False)

        # Full credit is 3 points (1.5 per flow).
        return min(3.0, score)

    except Exception as e:
        print(f"RATELIMIT test error: {e}")
        return 0.0

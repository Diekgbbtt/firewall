import os
import socket
import threading
import time

from grader_utility import (
    parse_ratelimit_config,
    get_test_net,
    host_in_net,
    udp_send,
    tcp_send,
)


def _tcp_listen_multi(ip, port, timelimit, pkt_log, time_log):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((ip, port))
    sock.listen(5)
    end_time = time.time() + timelimit
    try:
        while time.time() < end_time:
            remaining = end_time - time.time()
            if remaining <= 0:
                break
            sock.settimeout(remaining)
            try:
                conn, adr = sock.accept()
            except socket.timeout:
                break
            conn.settimeout(max(0.1, end_time - time.time()))
            try:
                while time.time() < end_time:
                    try:
                        data = conn.recv(65535)
                        if not data:
                            break
                        time_log.append(time.time_ns() * 1e-9)
                        pkt_log.append((data, adr))
                    except socket.timeout:
                        break
            finally:
                conn.close()
    finally:
        sock.close()


def _udp_listen_deadline(ip, port, timelimit, pkt_log, time_log):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((ip, port))
    end_time = time.time() + timelimit
    try:
        while time.time() < end_time:
            remaining = end_time - time.time()
            if remaining <= 0:
                break
            sock.settimeout(remaining)
            try:
                data, adr = sock.recvfrom(65535)
                time_log.append(time.time_ns() * 1e-9)
                pkt_log.append((data, adr))
            except socket.timeout:
                break
    finally:
        sock.close()


def _score_scenario(sent_in_burst: int, burst_seen: int, after_idle_seen: int) -> float:
    if sent_in_burst <= 0:
        return 0.0
    drop_fraction = max(0, sent_in_burst - burst_seen) / sent_in_burst
    scenario_score = 0.5 * min(1.0, drop_fraction)
    if after_idle_seen == 0:
        scenario_score *= 0.5
    return min(0.5, scenario_score)


def ddos_test ():

    try:
        cfg_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "configuration_files", "ratelimit_config.csv")
        cfg = parse_ratelimit_config(cfg_path)
        ratelimit_bps = cfg["Ratelimit"]
        idle_lifespan = cfg["IdleLifespan"]

        ddos_net = get_test_net("ddos")
        tcp_dst_ip = host_in_net(ddos_net, 50)
        udp_dst_ip = host_in_net(ddos_net, 60)

        tcp_src_ips = [host_in_net(ddos_net, offset) for offset in (1, 2, 3)]
        udp_src_ips = [host_in_net(ddos_net, offset) for offset in (5, 6, 7)]

        tcp_dst_port = 49601
        udp_dst_port = 49611

        burst_count = 3
        per_flow_total_target = 0.8 * ratelimit_bps
        # Keep each source under the per-flow limit while the aggregate exceeds L.
        payload_len = int(per_flow_total_target / burst_count) if burst_count > 0 else int(per_flow_total_target)
        payload_cap = int(max(1.0, (0.9 * ratelimit_bps) / max(1, burst_count)))
        payload_len = max(60, min(payload_len, payload_cap))
        payload = bytes([0xBB]) * payload_len
        burst_intervals = [0.0] + [0.02 for _ in range(burst_count - 1)]
        listen_duration = idle_lifespan + 3.0

        # TCP scenario.
        tcp_pkt_log = []
        tcp_time_log = []
        tcp_listener = threading.Thread(target=_tcp_listen_multi, args=(tcp_dst_ip, tcp_dst_port, listen_duration, tcp_pkt_log, tcp_time_log))
        tcp_listener.start()
        time.sleep(0.2)

        tcp_senders = []
        tcp_base_sport = 46600
        for idx, src_ip in enumerate(tcp_src_ips):
            sport = tcp_base_sport + idx
            t = threading.Thread(
                target=tcp_send,
                args=(src_ip, sport, tcp_dst_ip, tcp_dst_port, [payload] * burst_count, burst_intervals),
            )
            tcp_senders.append(t)
            t.start()
        for t in tcp_senders:
            t.join()

        time.sleep(0.5)
        tcp_burst_seen = len(tcp_pkt_log)
        time.sleep(idle_lifespan + 0.2)
        tcp_send(tcp_src_ips[0], tcp_base_sport, tcp_dst_ip, tcp_dst_port, [payload], [0.0])
        tcp_listener.join()
        tcp_after_idle = len(tcp_pkt_log) - tcp_burst_seen
        tcp_score = _score_scenario(burst_count * len(tcp_src_ips), tcp_burst_seen, tcp_after_idle)

        # UDP scenario.
        udp_pkt_log = []
        udp_time_log = []
        udp_listener = threading.Thread(target=_udp_listen_deadline, args=(udp_dst_ip, udp_dst_port, listen_duration, udp_pkt_log, udp_time_log))
        udp_listener.start()
        time.sleep(0.2)

        udp_senders = []
        udp_base_sport = 47600
        for idx, src_ip in enumerate(udp_src_ips):
            sport = udp_base_sport + idx
            t = threading.Thread(
                target=udp_send,
                args=(src_ip, sport, udp_dst_ip, udp_dst_port, [payload] * burst_count, burst_intervals),
            )
            udp_senders.append(t)
            t.start()
        for t in udp_senders:
            t.join()

        time.sleep(0.5)
        udp_burst_seen = len(udp_pkt_log)
        time.sleep(idle_lifespan + 0.2)
        udp_send(udp_src_ips[0], udp_base_sport, udp_dst_ip, udp_dst_port, [payload], [0.0])
        udp_listener.join()
        udp_after_idle = len(udp_pkt_log) - udp_burst_seen
        udp_score = _score_scenario(burst_count * len(udp_src_ips), udp_burst_seen, udp_after_idle)

        final_score = min(4.0, 4.0 * (tcp_score + udp_score))
        print(f"[ddos_test] tcp_seen={tcp_burst_seen}/{burst_count * len(tcp_src_ips)}, tcp_after_idle={tcp_after_idle}, tcp_score={tcp_score:.2f}")
        print(f"[ddos_test] udp_seen={udp_burst_seen}/{burst_count * len(udp_src_ips)}, udp_after_idle={udp_after_idle}, udp_score={udp_score:.2f}")
        print(f"[ddos_test] final_score={final_score:.2f}")

        return final_score

    except Exception as e:
        print(f"DDOS test error: {e}")
        return 0.0

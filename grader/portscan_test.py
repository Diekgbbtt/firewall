import os
import socket
import struct
import threading
import time
from scapy.layers.inet import IP, TCP
from grader_utility import parse_portscan_config, get_test_net, host_in_net


def _count_syn_packets(raw_packets, src_ip, dst_ip):
    seen = 0
    for data in raw_packets:
        try:
            pkt = IP(data)
        except Exception:
            continue
        if pkt.haslayer(IP) and pkt.haslayer(TCP):
            ip_layer = pkt.getlayer(IP)
            tcp_layer = pkt.getlayer(TCP)
            if ip_layer.src == src_ip and ip_layer.dst == dst_ip:
                syn_set = bool(tcp_layer.flags & 0x02)
                ack_set = bool(tcp_layer.flags & 0x10)
                if syn_set and not ack_set:
                    seen += 1
    return seen


def _send_syns(src_ip, dst_ip, base_sport, ports, interval):
    """
    Generate SYNs by opening TCP connection attempts. Non-blocking connects emit SYNs
    without waiting for completion. Linger(0) keeps sockets out of TIME_WAIT.
    """
    for idx, dport in enumerate(ports):
        sport = base_sport + idx
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', 1, 0))
        try:
            s.bind((src_ip, sport))
        except OSError:
            s.bind((src_ip, 0))
        s.setblocking(False)
        try:
            s.connect_ex((dst_ip, dport))
        except Exception:
            pass
        if interval > 0:
            time.sleep(interval)
        s.close()


def _listen_raw(dst_ip, duration, log):
    """
    Capture TCP packets delivered to dst_ip after firewall processing.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((dst_ip, 0))
    sock.settimeout(0.2)
    end = time.time() + duration
    try:
        while time.time() < end:
            try:
                data, _ = sock.recvfrom(65535)
                log.append(data)
            except socket.timeout:
                continue
    finally:
        sock.close()


def portscan_test ():

    try:
        cfg_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "configuration_files", "portscan_config.csv")
        cfg = parse_portscan_config(cfg_path)
        syn_threshold = max(1, cfg["SynNum"])
        max_interval = cfg["MaxPacketInterval"]

        scan_net = get_test_net("portscan")
        dst_ip = host_in_net(scan_net, 2)
        src_ips = [host_in_net(scan_net, offset) for offset in (1, 3, 5)]
        sports = [55001, 55011, 55021]
        base_port = 40000

        # Scenario 1: reach the threshold with unique ports, refresh timer with a duplicate, then exceed it.
        s1_ports = list(range(base_port, base_port + syn_threshold))
        s1_duplicate = [s1_ports[0]]
        s1_extras = [base_port + syn_threshold + 1, base_port + syn_threshold + 2]
        s1_log = []
        s1_listener = threading.Thread(target=_listen_raw, args=(dst_ip, 2.5, s1_log))
        s1_listener.start()
        time.sleep(0.05)
        _send_syns(src_ips[0], dst_ip, sports[0], s1_ports + s1_duplicate + s1_extras, 0.002)
        s1_listener.join()
        total1 = len(s1_ports) + len(s1_duplicate) + len(s1_extras)
        seen1 = _count_syn_packets(s1_log, src_ips[0], dst_ip)
        drop1 = max(0, total1 - seen1)
        expected_drop1 = len(s1_extras)
        score1 = min(1.0, drop1 / expected_drop1) if expected_drop1 > 0 else 1.0

        time.sleep(max_interval + 0.1)

        # Scenario 2: interleave repeats with new ports, then push far past the threshold.
        half = max(1, syn_threshold // 2)
        first_batch = [base_port + 1000 + i for i in range(half)]
        repeat_batch = first_batch.copy()
        new_batch_needed = syn_threshold - half + 5
        new_batch = [base_port + 2000 + i for i in range(new_batch_needed)]
        s2_log = []
        s2_listener = threading.Thread(target=_listen_raw, args=(dst_ip, 3.0, s2_log))
        s2_listener.start()
        time.sleep(0.05)
        _send_syns(src_ips[1], dst_ip, sports[1], first_batch + repeat_batch + new_batch, 0.002)
        s2_listener.join()
        total2 = len(first_batch) + len(repeat_batch) + len(new_batch)
        seen2 = _count_syn_packets(s2_log, src_ips[1], dst_ip)
        drop2 = max(0, total2 - seen2)
        expected_drop2 = max(0, len(new_batch) - max(0, syn_threshold - len(set(first_batch))))
        score2 = min(1.0, drop2 / expected_drop2) if expected_drop2 > 0 else 1.0

        time.sleep(max_interval + 0.1)

        # Scenario 3: trigger a drop streak, idle past the interval, then ensure new SYNs pass.
        trigger_ports = [base_port + 3000 + i for i in range(syn_threshold + 3)]
        _send_syns(src_ips[2], dst_ip, sports[2], trigger_ports, 0.002)
        time.sleep(max_interval + 0.5)
        s3_fresh = [base_port + 5000 + i for i in range(3)]
        s3_log = []
        s3_listener = threading.Thread(target=_listen_raw, args=(dst_ip, 1.5, s3_log))
        s3_listener.start()
        time.sleep(0.05)
        _send_syns(src_ips[2], dst_ip, sports[2], s3_fresh, 0.002)
        s3_listener.join()
        seen3 = _count_syn_packets(s3_log, src_ips[2], dst_ip)
        expected3 = len(s3_fresh)
        score3 = min(1.0, seen3 / expected3) if expected3 > 0 else 1.0

        final_score = min(4.0, 4.0 * ((score1 + score2 + score3) / 3.0))
        print(f"[portscan_test] scores: s1={score1:.2f}, s2={score2:.2f}, s3={score3:.2f}, final={final_score:.2f}")
        return final_score

    except Exception as e:
        print(f"PORTSCAN test error: {e}")
        return 0.0

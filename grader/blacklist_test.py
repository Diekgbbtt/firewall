import ipaddress
import os
import random
import threading
import time
from typing import Any
from scapy.layers.inet import ICMP, IP, UDP, TCP
from scapy.sendrecv import send
from grader_utility import parse_blacklist_config, receive_packets, get_test_net, host_in_net, tcp_listen, tcp_send, udp_listen, udp_send


PROTO_ID = None  # we sniff by dst IPs; actual packets are TCP/UDP


def _ip_in_net(net_str):
    net = ipaddress.ip_network(net_str)
    return str(ipaddress.ip_address(int(net.network_address) + random.randint(1, net.num_addresses - 2)))


def _mk_packets_from_rule(rule):
    """
    Return a list of packet specs matching the rule.
    Each spec: dict with src, dst, proto, sport, dport, should_pass.
    """
    specs = []
    proto = rule["Protocol"].upper()
    src_ip = _ip_in_net(rule["Source_IP"])
    dst_ip = _ip_in_net(rule["Destination_IP"])
    s_min, s_max = rule["Source_Port"]
    d_min, d_max = rule["Destination_Port"]
    sport = random.randint(s_min, s_max)
    dport = random.randint(d_min, d_max)

    def add_spec(p):
        specs.append({
            "src": src_ip,
            "dst": dst_ip,
            "proto": p,
            "sport": sport,
            "dport": dport,
            "should_pass": False,  # blacklist should drop
        })

    if proto == "IP":
        add_spec("UDP")
        add_spec("TCP")
    elif proto in ("UDP", "TCP"):
        add_spec(proto)
    return specs


# def _matches_rule(rule, proto, src_ip, dst_ip, sport, dport):
#     rule_proto = rule["Protocol"].upper()
#     if rule_proto not in ("IP", proto):
#         return False
#     if ipaddress.ip_address(src_ip) not in ipaddress.ip_network(rule["Source_IP"]):
#         return False
#     if ipaddress.ip_address(dst_ip) not in ipaddress.ip_network(rule["Destination_IP"]):
#         return False
#     s_min, s_max = rule["Source_Port"]
#     d_min, d_max = rule["Destination_Port"]
#     if not (s_min <= sport <= s_max and d_min <= dport <= d_max):
#         return False
#     return True


def blacklist_test ():
    """
    Send TCP/UDP packets that match blacklist rules (expect drop) and one benign packet (expect pass).
    """
    try:
        cfg_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "configuration_files", "blacklist_config.csv")
        rules = parse_blacklist_config(cfg_path)

        packet_specs = []
        for r in rules:
            packet_specs.extend(_mk_packets_from_rule(r))

        # Craft allowed packets from a deterministic, non-overlapping test net.
        allow_net = get_test_net("blacklist")
        src_ip = host_in_net(allow_net, 1)
        dst_ip = host_in_net(allow_net, 2)
        sport = 40000
        dport = 50000
        
        packet_specs.append({
            "src": src_ip,
            "dst": dst_ip,
            "proto": "UDP",
            "sport": sport,
            "dport": dport,
            "should_pass": True,
        })
        
        packet_specs.append({
            "src": src_ip,
            "dst": dst_ip,
            "proto": "TCP",
            "sport": sport,
            "dport": dport,
            "should_pass": True,
        })

        dst_ips = list({spec["dst"] for spec in packet_specs})
        
        recv_log = []
        listen_duration = 1.0
        # sniffer = threading.Thread(target=receive_packets, args=(PROTO_ID, dst_ips, listen_duration, recv_log))
        # sniffer.start()
        # time.sleep(0.05)

        payload = b"BLTEST"
        listeners: list[tuple[threading.Thread, tuple[str, str, int], list]] = []


        # dedupe listeners
        tuples = {(s["proto"], s["dst"], s["dport"]) for s in packet_specs}
        for proto, dst, dport in tuples:
            pkt_log: list = []
            time_log: list = []
            if proto == "UDP":
                t = threading.Thread(target=udp_listen, args=(dst, dport, listen_duration, pkt_log, time_log))
            else:
                t = threading.Thread(target=tcp_listen, args=(dst, dport, listen_duration, pkt_log, time_log))
            t.start()
            listeners.append((t, (proto, dst, dport), pkt_log))

        for spec in packet_specs:
            # ip_layer = IP(src=spec["src"], dst=spec["dst"])
            # if spec["proto"] == "UDP":
            #     pkt = ip_layer / UDP(sport=spec["sport"], dport=spec["dport"]) / payload
            # else:
            #     pkt = ip_layer / TCP(sport=spec["sport"], dport=spec["dport"], flags="S") / payload
            if spec["proto"] == "UDP":
                udp_send(spec["src"], spec["sport"], spec["dst"], spec["dport"], [payload], [0.0])
            else:
                tcp_send(spec["src"], spec["sport"], spec["dst"], spec["dport"], [payload], [0.0])
            
            time.sleep(0.01)

        # collect
        recv_log = []
        for t, key, pkt_log in listeners:
            t.join()
            proto, dst, dport = key
            for payload, adr in pkt_log:
                try:
                    src_ip, src_port = adr
                    if proto == "UDP":
                        scapy_pkt = IP(src=src_ip, dst=dst) / UDP(sport=src_port, dport=dport) / payload
                    else:
                        scapy_pkt = IP(src=src_ip, dst=dst) / TCP(sport=src_port, dport=dport) / payload
                    recv_log.append((key, scapy_pkt))
                except Exception:
                    continue
        
        # sniffer.join()

        def _seen(spec):
            proto = spec["proto"]
            src = spec["src"]
            dst = spec["dst"]
            sport = spec["sport"]
            dport = spec["dport"]

            # print(f"[seen] checking spec proto={proto} src={src} dst={dst} sport={sport} dport={dport}")

            for idx, log in enumerate(recv_log):
                (_, _, _), ip_pkt = log
                # try:
                #     print(f"[seen] pkt[{idx}] {ip_pkt.summary()}")
                # except Exception:
                #     pass

                if str(ip_pkt.src) != src or str(ip_pkt.dst) != dst:
                    # print(f"[seen] pkt[{idx}] IP mismatch src={ip_pkt.src} dst={ip_pkt.dst}")
                    continue

                if proto == "UDP":
                    udp_layer = ip_pkt.getlayer(UDP)
                    if udp_layer and int(udp_layer.sport) == sport and int(udp_layer.dport) == dport:
                        # print(f"[seen] pkt[{idx}] matched UDP ports sport={udp_layer.sport} dport={udp_layer.dport}")
                        return True
                elif proto == "TCP":
                    tcp_layer = ip_pkt.getlayer(TCP)
                    if tcp_layer and int(tcp_layer.sport) == sport and int(tcp_layer.dport) == dport:
                        # print(f"[seen] pkt[{idx}] matched TCP ports sport={tcp_layer.sport} dport={tcp_layer.dport}")
                        return True
                elif ip_pkt.getlayer(ICMP): # firewall accept/drop outbound response to the grader
                    continue
                else: # IP protocol
                    l4 = ip_pkt.payload  # could be TCP/UDP/ICMP/raw/etc.
                    pkt_sport = int(getattr(l4, "sport", 0))
                    pkt_dport = int(getattr(l4, "dport", 0))
                    if sport == pkt_sport and dport == pkt_dport:
                        # print(f"[seen] pkt[{idx}] matched TCP/UDP ports sport={pkt_sport} dport={pkt_dport}")
                        return True

            # print("[seen] no match for spec")
            return False

        # Debug: dump captured packets to help diagnose mismatches.
        for _, pkt in recv_log:
            try:
                print(pkt.summary())
            except Exception:
                pass

        wrong_packet_handling = 0
        for spec in packet_specs:
            seen = _seen(spec)
            # print(f"[check] spec={spec} seen={seen} should_pass={spec['should_pass']}")
            if spec["should_pass"] and not seen:
                wrong_packet_handling += 1
                # print("[check] expected pass but not seen")
                break
            if not spec["should_pass"] and seen:
                wrong_packet_handling += 1
                # print("[check] expected drop but saw packet")
                break
        # print(wrong_packet_handling / len(packet_specs))
        return 3.0 if wrong_packet_handling == 0 else 3.0 * wrong_packet_handling / len(packet_specs)
    except Exception as e:
        print(f"BLACKLIST test error: {e}")
        return 0.0

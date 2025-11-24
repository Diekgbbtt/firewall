import ipaddress
import socket
import struct
import random
import time
import csv
from typing import Optional, Iterable, Union
from scapy.layers.inet import IP, UDP, TCP
from scapy.packet import Raw
from scapy.sendrecv import send, sniff
from scapy.all import raw

def ip_to_bool_list(ip):
    ip_int = int(ip)
    binary_str = f"{ip_int:032b}"
    bool_list = [bit == '1' for bit in binary_str]
    return bool_list


def bool_list_to_ip(bool_list):
    binary_str = "".join(['1' if bool else '0' for bool in bool_list])
    ip_int = int(binary_str, 2)
    ip = ipaddress.ip_address(ip_int)
    return ip

def randomize_bool_list_suffix (list, suffix_start):
    list_len = len(list)
    for i in range(suffix_start, list_len):
        list[i] = random.choice([True, False])
    return list


def raw_listen(ip, timelimit, pkt_log, time_log):

    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    sock.bind((ip, 0))
    sock.settimeout(timelimit)
    try:
        while True:
            data = sock.recv(65535)
            time_log.append(time.time_ns() * 1e-9)
            pkt_log.append((data, None))
    
    except Exception as e:
        return
    finally:
        sock.close()


def raw_send(src_ip, dst_ip):
    ip_pkt = IP(src=src_ip, dst=dst_ip, proto=0)
    
    print(ip_pkt.show())

    raw_bytes = raw(ip_pkt)

    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    try:
        sock.sendto(raw_bytes, (dst_ip, 0))
    except ConnectionRefusedError as e:
        return
    finally:
        sock.close()
    return

def tcp_listen (IP, port, timelimit, pkt_adr_log, time_log):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', 1, 0))
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((IP, port))
    sock.settimeout(timelimit)
    try:
        sock.listen(1)
        connection, adr = sock.accept()
        connection.settimeout(timelimit)
        while True:
            pkt = connection.recv(65535)
            time_log.append(time.time_ns() * 1e-9)
            pkt_adr_log.append((pkt, adr))
    except Exception as e:
        pass

def tcp_send (src_IP, src_port, dst_IP, dst_port, transmission_data, transmission_intervals, reconnect_wait = 1e-2, max_reconnects = 10):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', 1, 0))
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((src_IP, src_port))
    sock.settimeout(reconnect_wait * max_reconnects)
    for trial in range(max_reconnects):
        try:
            num_transmissions = len(transmission_data)
            sock.connect((dst_IP, dst_port))
            for i in range(num_transmissions):
                sock.sendto(transmission_data[i], (dst_IP, dst_port))
                time.sleep(transmission_intervals[i])
            return
        except TimeoutError as e:
            return
        except ConnectionRefusedError as e:
            return

def parse_nat_config (filepath):
    data = []
    with open(filepath, mode='r') as file:
        csv_reader = csv.DictReader(file)
        for row in csv_reader:
            data.append({
                "NatType": row['NatType'],
                "Internal_IP": row['Internal_IP'],
                "External_IP": row['External_IP']
            })
    return data

def parse_blacklist_config (filepath):
    data = []
    with open(filepath, mode='r') as file:
        csv_reader = csv.DictReader(file)
        for row in csv_reader:
            source_port_start, source_port_end = map(int, row['Source_Port'].split('-'))
            dest_port_start, dest_port_end = map(int, row['Destination_Port'].split('-'))
            data.append({
                "Protocol": row['Protocol'],
                "Source_IP": row['Source_IP'],
                "Destination_IP": row['Destination_IP'],
                "Source_Port": (source_port_start, source_port_end),
                "Destination_Port": (dest_port_start, dest_port_end)
            })
    return data

def parse_ratelimit_config (filepath):
    data = {}
    with open(filepath, mode='r') as file:
        csv_reader = csv.DictReader(file)
        for row in csv_reader:
            data = {"Ratelimit": float(row['Ratelimit']), "IdleLifespan": float(row['IdleLifespan'])}
            return data
        


def parse_ttl_config (filepath):
    data = {}
    with open(filepath, mode='r') as file:
        csv_reader = csv.DictReader(file)
        for row in csv_reader:
            data = {"MaxTTL": int(row['MaxTTL']), "MinTTL": int(row['MinTTL'])}
            return data
        
def parse_portscan_config (filepath):
    data = {}
    with open(filepath, mode='r') as file:
        csv_reader = csv.DictReader(file)
        for row in csv_reader:
            data = {"SynNum": int(row['SynNum']), "MaxPacketInterval": float(row['MaxPacketInterval'])}
            return data


# Pre-assigned, non-overlapping loopback CIDRs for each test (ipnull through fullnat).
_TEST_NET_ORDER = [
    ("ipnull", "127.100.0.0/16"),
    ("blacklist", "127.101.0.0/16"),
    ("ratelimit", "127.102.0.0/16"),
    ("portscan", "127.103.0.0/16"),
    ("ttl", "127.104.0.0/16"),
    ("transparency", "127.105.0.0/16"),
    ("ddos", "127.106.0.0/16"),
    ("halfnat", "127.107.0.0/16"),
    ("quarternat", "127.108.0.0/16"),
    ("fullnat", "127.109.0.0/16"),
]

TEST_NETS = [ipaddress.ip_network(cidr) for _, cidr in _TEST_NET_ORDER]
TEST_NET_MAP = {name: net for (name, _), net in zip(_TEST_NET_ORDER, TEST_NETS)}


def get_test_net(name_or_index: Union[str, int]):
    """Return the deterministic CIDR reserved for a given test by name or position."""
    if isinstance(name_or_index, int):
        return TEST_NETS[name_or_index]
    return TEST_NET_MAP[name_or_index]


def host_in_net(net: ipaddress.IPv4Network, host_offset: int = 1) -> str:
    """Pick a stable host inside the given net (offset from network address)."""
    return str(ipaddress.ip_address(int(net.network_address) + host_offset))


def build_ip_packet(src_ip: str, dst_ip: str, payload: bytes, proto_id: int):
    """
    Craft a bare IP packet with a specified protocol number and optional raw payload.
    """
    pkt = IP(src=src_ip, dst=dst_ip, proto=proto_id)
    if payload:
        pkt = pkt / Raw(payload)
    return pkt


def receive_packets(proto_id: Optional[int], dst_ips, duration: float, recv_log: list, iface: str = "lo"):
    """
    Sniff packets on iface for a limited time, optionally filtering by proto and dst IPs.
    Captured packets are appended to recv_log.
    """
    if dst_ips is None:
        dst_ips = []
    if isinstance(dst_ips, str):
        dst_ips = [dst_ips]

    filters = ["ip"]
    if proto_id is not None:
        filters.append(f"proto {proto_id}")
    if dst_ips:
        host_expr = " or ".join([f"dst host {ip}" for ip in dst_ips])
        filters.append(f"({host_expr})")
    bpf = " and ".join(filters)

    print("sniffer filtering expression :", bpf)

    try:
        packets = sniff(iface=iface, timeout=duration, filter=bpf)
        recv_log.extend(packets)
    except Exception:
        # If sniff fails (e.g., pcap issues), leave log empty.
        pass


def udp_listen(ip, port, timelimit, pkt_log, time_log):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((ip, port))
    sock.settimeout(timelimit)
    try:
        while True:
            data, adr = sock.recvfrom(65535)
            time_log.append(time.time_ns() * 1e-9)
            pkt_log.append((data, adr))
    except Exception:
        pass
    finally:
        sock.close()


def udp_send(src_ip, src_port, dst_ip, dst_port, transmission_data, transmission_intervals):
    """
    Send UDP datagrams from src to dst with provided payloads and inter-send intervals.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((src_ip, src_port))
    try:
        for payload, wait in zip(transmission_data, transmission_intervals):
            sock.sendto(payload, (dst_ip, dst_port))
            if wait > 0:
                time.sleep(wait)
    finally:
        sock.close()

import ipaddress
import socket
import struct
import random
import time
import ipaddress
import csv

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

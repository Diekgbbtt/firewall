from doctest import DocTestParser
from platform import release
from re import match
import dpkt
import time
import ipaddress
import math
from firewall_utility import *

# DO NOT MODIFY SIGNATURE
def firewall_init ():

    # TODO: Perform any intitialization for your firewall here

    global blacklist_config
    global nat_config
    global ratelimit_config
    global portscan_config

    blacklist_path = "configuration_files/blacklist_config.csv"
    blacklist_config = parse_blacklist_config(blacklist_path)
    nat_path = "configuration_files/nat_config.csv"
    nat_config = parse_nat_config(nat_path)
    ratelimit_path = "configuration_files/ratelimit_config.csv"
    ratelimit_config = parse_ratelimit_config(ratelimit_path)
    ttl_path = "configuration_files/ttl_config.csv"
    ttl_config = parse_ttl_config(ttl_path)
    portscan_path = "configuration_files/portscan_config.csv"
    portscan_config = parse_portscan_config(portscan_path)

    global ratelimit_R
    global idlelifespan
    ratelimit_R = ratelimit_config["Ratelimit"]
    idlelifespan = ratelimit_config["IdleLifespan"]

    global ttl_min
    global ttl_max
    ttl_min = ttl_config["MinTTL"]
    ttl_max = ttl_config["MaxTTL"]

    # TODO: Select the tasks you want to be graded for here
    task_selection = dict()
    task_selection["ipnull"] = True
    task_selection["ttl"] = True
    task_selection["blacklist"] = True
    task_selection["quarternat"] = False
    task_selection["halfnat"] = False
    task_selection["fullnat"] = False
    task_selection["ratelimit"] = False
    task_selection["ddos"] = False
    task_selection["portscan"] = False

    return task_selection


def distributed_rate_limit(pkt, is_dropped: bool):
    # DDoS
    return True

def synack_scan(pkt, is_dropped: bool):
    return True

def rate_limit(pkt, is_dropped: bool):

    return True

def ttl_within_range(pkt, is_dropped: bool):

    if is_dropped:
        return False

    ip = dpkt.ip.IP(pkt.get_payload())
    if ttl_min < ip.ttl < ttl_max:
        return True
    else:
        return False



def match_blacklisting_rules(proto: str, src_ip_addr, dst_ip_addr, src_port, dst_port):
    
    relevant_rules = []
    proto = str(proto).upper()
    try:
        # src_ip_addr = ipaddress.ip_address(src_ip)
        # dst_ip_addr = ipaddress.ip_address(dst_ip)
        src_port_int = int(src_port)
        dst_port_int = int(dst_port)
    except (TypeError, ValueError):
        # print(f"[blacklist] parse error proto={proto} src={src_ip_addr} dst={dst_ip_addr} sport={src_port} dport={dst_port}")
        return relevant_rules

    # print(f"[blacklist] check packet proto={proto} src={src_ip_addr} dst={dst_ip_addr} sport={src_port_int} dport={dst_port_int}")

    for rule in blacklist_config:
        if not isinstance(rule, dict):
            # print("[blacklist] skip non-dict rule", rule)
            continue
        rule_proto = rule["Protocol"].upper()
        if rule_proto not in ("IP", proto):
            # print(f"[blacklist] rule {rule} proto mismatch ({rule_proto} vs {proto})")
            continue
        # TODO handle here some edge case addresses like 0.0.0.0 or 127.0.0.1
        # If you want a safety net, you could drop packets with obviously bogus src/dst (e.g., 0.0.0.0/8, 127.0.0.0/8 on non-lo, multicast where unexpected), 
        # but that’s a policy choice, not a requirement from NFQUEUE.
        src_net = ipaddress.ip_network(rule["Source_IP"])
        dst_net = ipaddress.ip_network(rule["Destination_IP"])
        if src_ip_addr not in src_net:
            # print(f"[blacklist] rule {rule} src {src_ip_addr} not in {src_net}")
            continue
        if dst_ip_addr not in dst_net:
            # print(f"[blacklist] rule {rule} dst {dst_ip_addr} not in {dst_net}")
            continue
        s_min, s_max = rule["Source_Port"]
        d_min, d_max = rule["Destination_Port"]
        if not (s_min <= src_port_int <= s_max):
            # print(f"[blacklist] rule {rule} sport {src_port_int} not in [{s_min},{s_max}]")
            continue
        if not (d_min <= dst_port_int <= d_max):
            # print(f"[blacklist] rule {rule} dport {dst_port_int} not in [{d_min},{d_max}]")
            continue
    
        # print(f"[blacklist] rule matched: {rule}")
        relevant_rules.append(rule)
    
    return relevant_rules

def is_blacklisted(pkt, is_dropped: bool):
    
    if is_dropped:
        # print("[blacklist] upstream stage already dropped; skipping blacklist check")
        return False
    
    ip = dpkt.ip.IP(pkt.get_payload())
    try:
        proto_name = dpkt.ip.get_ip_proto_name(ip.p)  # raises KeyError if not registered
    except KeyError:
        # fail-open weird packet with unknown protocol at transport layer - shoudln't happen but my IP null test use PROTO_ID=255
        # print(f"[blacklist] unknown L4 proto id {ip.p}, allowing by default")
        return True

    if ip.p == dpkt.ip.IP_PROTO_TCP and isinstance(ip.data, dpkt.tcp.TCP):
        src_port, dst_port = ip.data.sport, ip.data.dport
    elif ip.p == dpkt.ip.IP_PROTO_UDP and isinstance(ip.data, dpkt.udp.UDP):
        src_port, dst_port = ip.data.sport, ip.data.dport   
    else:
        # transparency check - no TCP/UDP packet, TODO check if necessary
        # print(f"[blacklist] non-TCP/UDP proto={ip.p}, allowing")
        return True
    
    matched_rules = match_blacklisting_rules(
        proto=proto_name,
        src_ip_addr=ipaddress.ip_address(ip.src),
        dst_ip_addr=ipaddress.ip_address(ip.dst),
        src_port=src_port,
        dst_port=dst_port,
    )
    
    if len(matched_rules) > 0:
        #  print(f"[blacklist] dropping packet; matched_rules={matched_rules}")
        return False
        
    print("[blacklist] allowed; no matching rules")
    return True

def empty_IPpayload(pkt):

    ip = dpkt.ip.IP(pkt.get_payload())
    # TODO firewall must be transparent to all traffic with no testing purpose, should I evaluate TCP/UDP here? --> check which type of traffic will be used fro transparency control
    
    print(f"[empty_ip_payload] packet payload len : {len(ip.data)}")
    
    if len(ip.data) == 0:
        return False
    else:
        return True

    # Serialized L4 payload length
    # if isinstance(ip.data, dpkt.tcp.TCP):
    #     empty = (len(ip.data.data) == 0)
    # elif isinstance(ip.data, dpkt.udp.UDP):
    #     empty = (len(ip.data.data) == 0)
    # else:
    #     empty = False

def handle(pkt) -> bool :

    # Evaluate all filters in order so accounting/ratelimits see every packet even if an earlier check fails.
    allowed = True # TODO might be useful to carry a dict that enriches the previous filtering gates decisions rather than a boolean
    payload_ok = empty_IPpayload(pkt)
    allowed &= payload_ok
    blacklist_ok = is_blacklisted(pkt, not(allowed))
    allowed &= blacklist_ok
    ttl_ok = ttl_within_range(pkt, not(allowed))
    allowed &= ttl_ok
    # rate_ok = rate_limit(pkt, not(allowed))
    # allowed &= rate_ok
    # synack_ok = synack_scan(pkt, not(allowed)) if is_tcp else True
    # allowed &= synack_ok
    # ddos_ok = distributed_rate_limit(pkt, not(allowed))
    # allowed &= ddos_ok
    
    return allowed


# DO NOT MODIFY SIGNATURE
def firewall_packet_handler(pkt):
    global ratelimit_R
    global idlelifespan
    global ttl_min
    global ttl_max
    d = True
    ip = dpkt.ip.IP(pkt.get_payload())

    print(f"intercepted packet : {ipaddress.ip_address(ip.src)}, {ipaddress.ip_address(ip.dst)}, {int(ip.p)}, {len(ip.data)}")
    
    try:
        d &= handle(pkt)
    except Exception as e:
        print("error : ", e)
        pkt.accept() # fail-open
    
    if d:
        pkt.accept()
        print(f"accepting packet : {ipaddress.ip_address(ip.src)}, {ipaddress.ip_address(ip.dst)}, {int(ip.p)}, {len(ip.data)}")
    else:
        print(f"dropping packet : {ipaddress.ip_address(ip.src)}, {ipaddress.ip_address(ip.dst)}, {int(ip.p)}, {len(ip.data)}")
        pkt.drop()
    # ONLY for NAT
    #  modfiy and accept : 
    # raw = pkt.get_payload()
    # ip = dpkt.ip.IP(raw)
    # edit ip ...
    # pkt.set_payload(bytes(ip/tcp/udp))

    # TODO: Implement your packet firewall logic
    # gut_feeling = True 

    # if gut_feeling:
    #     pkt.accept()
    # else:
    #     pkt.drop()
    # return

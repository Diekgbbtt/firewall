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
    task_selection["ttl"] = False
    task_selection["blacklist"] = False
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

    return True

def is_blacklisted(pkt, is_dropped: bool):

    return True

def empty_IPpayload(pkt):

    ip = dpkt.ip.IP(pkt.get_payload())

    if len(ip.data) == 0: # should never happen as it should be an invalid packet
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
    ip_pkt = dpkt.ip.IP(pkt.get_payload())
    is_tcp = ip_pkt.p == dpkt.ip.IP_PROTO_TCP

    # Evaluate all filters in order so accounting/ratelimits see every packet even if an earlier check fails.
    allowed = True # TODO might be useful to carry a dict that enriches the previous filtering gates decisions rather than a boolean
    payload_ok = empty_IPpayload(pkt)
    allowed &= payload_ok
    blacklist_ok = is_blacklisted(pkt, allowed)
    allowed &= blacklist_ok
    ttl_ok = ttl_within_range(pkt, allowed)
    allowed &= ttl_ok
    rate_ok = rate_limit(pkt, allowed)
    allowed &= rate_ok
    synack_ok = synack_scan(pkt, allowed) if is_tcp else True
    allowed &= synack_ok
    ddos_ok = distributed_rate_limit(pkt, allowed)
    allowed &= ddos_ok
    
    return allowed


# DO NOT MODIFY SIGNATURE
def firewall_packet_handler(pkt):
    global ratelimit_R
    global idlelifespan
    global ttl_min
    global ttl_max

    try:
        decision = handle(pkt)
    except Exception as e:
        print("error : ", e)
        pkt.accept() # fail-open
    
    if decision:
        pkt.accept()
    else:
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

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
    task_selection["halfnat"] = True
    task_selection["fullnat"] = False
    task_selection["ratelimit"] = False
    task_selection["ddos"] = False
    task_selection["portscan"] = False

    return task_selection


def distributed_rate_limit(pkt):
    # DDoS
    pass

def synack_scan(pkt):
    pass

def rate_limit(pkt):

    pass

def ttl_within_range(pkt):

    pass

def is_blacklisted(pkt):

    pass

def empty_IPpayload(pkt):

    return dpkt.ip.IP(pkt.get_payload()).data != 0

def handle(pkt) -> bool :
    ip_pkt = dpkt.ip.IP(pkt.get_payload())
    tcp_check = lambda p: synack_scan(p) if ip_pkt.p == dpkt.ip.IP_PROTO_TCP else True
    return (
        empty_IPpayload(pkt)
        and is_blacklisted(pkt)
        and ttl_within_range(pkt)
        and rate_limit(pkt)
        and tcp_check(pkt)
        and distributed_rate_limit(pkt)
    )


# DO NOT MODIFY SIGNATURE
def firewall_packet_handler(pkt):
    global ratelimit_R
    global idlelifespan
    global ttl_min
    global ttl_max

    ip = dpkt.ip.IP(pkt.get_payload())
    ts = pkt.get_timestamp()

    try:
        decision = handle(pkt)
    except Exception as e:
        print("error : %s", e)
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

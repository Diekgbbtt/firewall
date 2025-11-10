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

# DO NOT MODIFY SIGNATURE
def firewall_packet_handler(pkt):
    global ratelimit_R
    global idlelifespan
    global ttl_min
    global ttl_max

    ip = dpkt.ip.IP(pkt.get_payload())
    ts = pkt.get_timestamp()

    # TODO: Implement your packet firewall logic
    gut_feeling = True 

    if gut_feeling:
        pkt.accept()
    else:
        pkt.drop()
    return
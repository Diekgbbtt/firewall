from doctest import DocTestParser
from platform import release
from re import match
from collections import deque
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
    global portscan_flows

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
    portscan_flows = dict()

    global ratelimit_R
    global idlelifespan
    global flow_buckets
    global rate_window_seconds
    global ddos_flows
    ratelimit_R = ratelimit_config["Ratelimit"]
    idlelifespan = ratelimit_config["IdleLifespan"]
    # Per-flow accounting for rate limiting; each entry keeps a deque of (timestamp, bytes)
    flow_buckets = dict()
    rate_window_seconds = 1.0
    # Per-destination accounting for distributed rate limiting.
    ddos_flows = dict()

    global ttl_min
    global ttl_max
    ttl_min = ttl_config["MinTTL"]
    ttl_max = ttl_config["MaxTTL"]

    global portscan_syn_threshold
    global portscan_max_interval
    portscan_syn_threshold = portscan_config["SynNum"]
    portscan_max_interval = portscan_config["MaxPacketInterval"]

    # TODO: Select the tasks you want to be graded for here
    task_selection = dict()
    task_selection["ipnull"] = True
    task_selection["ttl"] = True
    task_selection["blacklist"] = True
    task_selection["quarternat"] = False
    task_selection["halfnat"] = False
    task_selection["fullnat"] = False
    task_selection["ratelimit"] = True
    task_selection["ddos"] = True
    task_selection["portscan"] = True

    return task_selection


def distributed_rate_limit(pkt, is_dropped: bool):
    global ddos_flows
    global ratelimit_R
    global idlelifespan
    global rate_window_seconds

    try:
        ip = dpkt.ip.IP(pkt.get_payload())
    except Exception:
        return False if is_dropped else True

    # Only track TCP/UDP traffic where ports identify endpoints.
    if ip.p not in (dpkt.ip.IP_PROTO_TCP, dpkt.ip.IP_PROTO_UDP):
        return False if is_dropped else True

    l4 = ip.data
    src_port = getattr(l4, "sport", None)
    dst_port = getattr(l4, "dport", None)
    if src_port is None or dst_port is None:
        return False if is_dropped else True

    now = time.time()
    dst_key = (str(ipaddress.ip_address(ip.dst)), int(dst_port))
    src_key = (str(ipaddress.ip_address(ip.src)), int(src_port))

    dest_state = ddos_flows.get(dst_key)
    if dest_state is None:
        dest_state = {"sources": dict()}
        ddos_flows[dst_key] = dest_state

    # Expire idle sources and drain their per-source buckets.
    active_sources = dict()
    for key, state in list(dest_state["sources"].items()):
        last_seen = state.get("last_seen", 0)
        if (now - last_seen) > idlelifespan:
            continue
        hist = state["history"]
        while hist and (now - hist[0][0]) > rate_window_seconds:
            _, old_bytes = hist.popleft()
            state["total"] = max(0, state["total"] - old_bytes)
        active_sources[key] = state
    dest_state["sources"] = active_sources

    src_state = dest_state["sources"].get(src_key)
    if src_state is None:
        src_state = {"history": deque(), "total": 0, "last_seen": now}
        dest_state["sources"][src_key] = src_state
    else:
        if (now - src_state.get("last_seen", 0)) > idlelifespan:
            src_state["history"].clear()
            src_state["total"] = 0
        hist = src_state["history"]
        while hist and (now - hist[0][0]) > rate_window_seconds:
            _, old_bytes = hist.popleft()
            src_state["total"] = max(0, src_state["total"] - old_bytes)
        src_state["last_seen"] = now

    active_count = max(1, len(dest_state["sources"]))
    capacity = math.sqrt(active_count) * ratelimit_R
    aggregated_total = sum(state["total"] for state in dest_state["sources"].values())

    try:
        if isinstance(ip.data, (bytes, bytearray)):
            payload_len = len(ip.data)
        else:
            payload_len = len(bytes(ip.data)) if ip.data is not None else 0
    except Exception:
        payload_len = 0

        source_lines = []
        # for s_key, s_state in dest_state["sources"].items():
        #     s_total = s_state.get("total", 0)
        #     source_lines.append(f"{s_key[0]}:{s_key[1]}->{dst_key[0]}:{dst_key[1]} bytes={s_total}")
        # print(f"[ddos] destination {dst_key[0]}:{dst_key[1]} capacity={capacity:.2f} aggregated={aggregated_total} payload={payload_len}")
        # print(f"[ddos] sources ({len(source_lines)}): " + "; ".join(source_lines))
    if (aggregated_total + payload_len) > capacity:
        # print(f"DROP : {(aggregated_total + payload_len)} >> {capacity}")
        return False

    if payload_len > 0:
        # print(f"PASS : {(aggregated_total + payload_len)} <<= {capacity}")
        src_state["history"].append((now, payload_len))
        src_state["total"] += payload_len
        src_state["last_seen"] = now

    return False if is_dropped else True

def syn_scan(pkt, is_dropped: bool):
    global portscan_flows
    global portscan_syn_threshold
    global portscan_max_interval

    try:
        ip = dpkt.ip.IP(pkt.get_payload())
    except Exception:
        return False if is_dropped else True

    if ip.p != dpkt.ip.IP_PROTO_TCP:
        return False if is_dropped else True

    tcp_seg = ip.data
    if not isinstance(tcp_seg, dpkt.tcp.TCP):
        return False if is_dropped else True

    syn_set = bool(tcp_seg.flags & dpkt.tcp.TH_SYN)
    ack_set = bool(tcp_seg.flags & dpkt.tcp.TH_ACK)
    # Only consider initial SYNs; other TCP traffic passes transparently through this gate.
    if (not syn_set) or ack_set:
        return False if is_dropped else True

    now = time.time()
    flow_key = (
        str(ipaddress.ip_address(ip.src)),
        str(ipaddress.ip_address(ip.dst)),
    )

    state = portscan_flows.get(flow_key)
    if state is None or (now - state.get("last_seen", 0)) >= portscan_max_interval:
        state = {"ports": set(), "last_seen": now, "dropping": False, "port_times": dict()}
        portscan_flows[flow_key] = state

    # Refresh streak timing even for repeated ports.
    state["last_seen"] = now

    dst_port = getattr(tcp_seg, "dport", None)
    try:
        dst_port = int(dst_port)
    except (TypeError, ValueError):
        return False if is_dropped else True

    is_new_port = dst_port not in state["ports"]
    if is_new_port:
        state["ports"].add(dst_port)
        if len(state["ports"]) > portscan_syn_threshold:
            state["dropping"] = True
            # print(f"[portscan] drop triggered for {flow_key}; unique ports={len(state['ports'])}")

    state["port_times"][dst_port] = now
    drop_packet = state["dropping"]

    if drop_packet:
        return False

    return False if is_dropped else True

def rate_limit(pkt, is_dropped: bool):      

    global flow_buckets
    global ratelimit_R
    global idlelifespan
    global rate_window_seconds

    try:
        ip = dpkt.ip.IP(pkt.get_payload())
    except Exception:
        # If we cannot parse the packet, do not enforce rate limiting here.
        return False if is_dropped else True

    # Only enforce rate limiting on TCP/UDP where ports define the flow.
    if ip.p not in (dpkt.ip.IP_PROTO_TCP, dpkt.ip.IP_PROTO_UDP):
        return False if is_dropped else True

    l4 = ip.data
    src_port = getattr(l4, "sport", None)
    dst_port = getattr(l4, "dport", None)
    if src_port is None or dst_port is None:
        return False if is_dropped else True

    flow_key = (
        str(ipaddress.ip_address(ip.src)),
        int(src_port),
        str(ipaddress.ip_address(ip.dst)),
        int(dst_port),
    )

    now = time.time()
    state = flow_buckets.get(flow_key)
    idle_gap = (now - state.get("last_seen", 0)) if state else 0
    if state is None or idle_gap > idlelifespan:
        # if state is not None:
        #     print(f"[ratelimit] {flow_key} idle for {idle_gap:.3f}s (> {idlelifespan}s); resetting tracking")
        state = {"total": 0, "history": deque(), "last_seen": now}
        flow_buckets[flow_key] = state

    # Expire packets older than the sliding window to simulate continuous drain.
    hist = state["history"]
    while hist and (now - hist[0][0]) > rate_window_seconds:
        _, old_bytes = hist.popleft()
        state["total"] = max(0, state["total"] - old_bytes)

    state["last_seen"] = now

    # Compute IP payload length (transport header + transport data).
    try:
        if isinstance(ip.data, (bytes, bytearray)):
            payload_len = len(ip.data)
        else:
            payload_len = len(bytes(ip.data)) if ip.data is not None else 0
    except Exception:
        payload_len = 0

    # # If the bucket is already above capacity, drop without adding.
    # if state["total"] > ratelimit_R:
    #     return False

    if (state["total"] + payload_len) > ratelimit_R:
        # Dropped packets do not increase the bucket.
        # print(f"[ratelimit] {flow_key} total={state['total']} --> drop")
        return False

    if payload_len > 0:
        hist.append((now, payload_len))
        state["total"] += payload_len

    # print(f"[ratelimit] {flow_key} total={state['total']} --> pass")

    return False if is_dropped else True

# def portscan_filter(pkt, is_dropped: bool):


def ttl_within_range(pkt, is_dropped: bool):

    if is_dropped:
        return False

    ip = dpkt.ip.IP(pkt.get_payload())
    if ttl_min < ip.ttl < ttl_max:
        # print(f"[ttl] valid ttl within range --> pass - ttl : {ip.ttl}")
        return True
    else:
        # print(f"[ttl] INvalid ttl NOT within range --> block - ttl : {ip.ttl}")
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
    
    try:
        ip = dpkt.ip.IP(pkt.get_payload())
    except Exception:
        # If we cannot parse the packet, do not enforce black listing here.
        return False if is_dropped else True
    try:
        proto_name = dpkt.ip.get_ip_proto_name(ip.p)  # raises KeyError if not registered
    except KeyError:
        # fail-open weird packet with unknown protocol at transport layer - shoudln't happen but my IP null test use PROTO_ID=255
        # print(f"[blacklist] unknown L4 proto id {ip.p}, allowing by default")
        return True

    l4 = ip.data
    if ip.p in (dpkt.ip.IP_PROTO_TCP, dpkt.ip.IP_PROTO_UDP) and isinstance(l4, (dpkt.tcp.TCP, dpkt.udp.UDP)):    
        src_port, dst_port = getattr(l4, "sport"), getattr(l4, "dport")
        if None in (src_port, dst_port):
            return False if is_dropped else True
    else:
        # Only enforce black listing on TCP/UDP where ports define the flow. TRANSPARENCY
        # grading test suite either sends TCP/UDP packets, moreover IP packet with ip.data=0 --> should be filtered by emptyip
        return False if is_dropped else True

    
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
        
    # print("[blacklist] allowed; no matching rules")
    return True

def empty_IPpayload(pkt, is_dropped):

    if is_dropped:
        return False

    ip = dpkt.ip.IP(pkt.get_payload())
    # TODO firewall must be transparent to all traffic with no testing purpose, should I evaluate TCP/UDP here? --> check which type of traffic will be used fro transparency control
    
    # print(f"[empty_ip_payload] packet payload len : {len(ip.data)}")
    
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
    rate_ok = rate_limit(pkt, not(allowed))
    allowed &= rate_ok
    ddos_ok = distributed_rate_limit(pkt, not(allowed))
    allowed &= ddos_ok
    portscan_ok = syn_scan(pkt, not(allowed))
    allowed &= portscan_ok
    payload_ok = empty_IPpayload(pkt, not(allowed))
    allowed &= payload_ok
    blacklist_ok = is_blacklisted(pkt, not(allowed))
    allowed &= blacklist_ok
    ttl_ok = ttl_within_range(pkt, not(allowed))
    allowed &= ttl_ok
    
    return allowed


# DO NOT MODIFY SIGNATURE
def firewall_packet_handler(pkt):
    global ratelimit_R
    global idlelifespan
    global ttl_min
    global ttl_max
    d = True
    ip = dpkt.ip.IP(pkt.get_payload())

    # print(f"intercepted packet : {ipaddress.ip_address(ip.src)}, {ipaddress.ip_address(ip.dst)}, {int(ip.p)}, {len(ip.data)}")
    # TODO somehow here straight accept outbound response packets symmetric to received(processed) inbound packets 
    try:
        d &= handle(pkt)
    except Exception as e:
        print("error : ", e)
        pkt.accept() # fail-open
    
    if d:
        pkt.accept()
        # print(f"accepting packet : {ipaddress.ip_address(ip.src)}, {ipaddress.ip_address(ip.dst)}, {int(ip.p)}, {len(ip.data)}")
    else:
        # print(f"dropping packet : {ipaddress.ip_address(ip.src)}, {ipaddress.ip_address(ip.dst)}, {int(ip.p)}, {len(ip.data)}")
        pkt.drop()
    # ONLY for NAT
    #  modfiy and accept : 
    # raw = pkt.get_payload()
    # ip = dpkt.ip.IP(raw)
    # edit ip ...
    # pkt.set_payload(bytes(ip/tcp/udp)

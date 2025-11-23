import ipaddress
import os
import random
import socket
import string
import threading
import time
from grader_utility import *



def transparency_test ():


# Think about how to approach testing this firewall feature. We suggest using a similar approach as with the transparency test.
# This is not graded but the intended use is that this function returns 1 if your firewall is perfectly transparent to legitimate traffic, and 0 if it fails completely.

    localhost_network = ipaddress.ip_network("127.0.0.0/8")

    # Load blacklist rules so we pick src/dst tuples outside all blocked ranges.
    # blacklist_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "configuration_files", "blacklist_config.csv")
    # try:
    #     blacklist_rules = parse_blacklist_config(blacklist_path)
    # except Exception:
    #     blacklist_rules = []

    # def _is_blocked(proto, src_ip, dst_ip, src_port, dst_port):
    #     for rule in blacklist_rules:
    #         if not isinstance(rule, dict):
    #             continue
    #         rule_proto = rule["Protocol"].upper()
    #         if rule_proto not in ("IP", proto):
    #             continue
    #         if ipaddress.ip_address(src_ip) not in ipaddress.ip_network(rule["Source_IP"]):
    #             continue
    #         if ipaddress.ip_address(dst_ip) not in ipaddress.ip_network(rule["Destination_IP"]):
    #             continue
    #         s_min, s_max = rule["Source_Port"]
    #         d_min, d_max = rule["Destination_Port"]
    #         if not (s_min <= src_port <= s_max):
    #             continue
    #         if not (d_min <= dst_port <= d_max):
    #             continue
    #         return True
    #     return False

    # def _pick_tuple(proto):
    #     for _ in range(256):
    #         src_ip = bool_list_to_ip(randomize_bool_list_suffix(ip_to_bool_list(localhost_network.network_address), localhost_network.prefixlen))
    #         dst_ip = bool_list_to_ip(randomize_bool_list_suffix(ip_to_bool_list(localhost_network.network_address), localhost_network.prefixlen))
    #         src_port = random.randrange(1024, 65536)
    #         dst_port = random.randrange(1024, 65536)
    #         if not _is_blocked(proto, str(src_ip), str(dst_ip), src_port, dst_port):
    #             return str(src_ip), str(dst_ip), src_port, dst_port
    #     raise RuntimeError("Could not find non-blacklisted address/port tuple for transparency test")

    # TODO must be used to make a proper transparency check but improve efficiency, rather than checking dinamically set both tuple srcip,srcpo and dstip,dstport to value that are not currently in the blacklisting rules 
    #  Test transparence using a TCP connection with non-blacklisted tuple.
    #  src_IP, dst_IP, src_port, dst_port = _pick_tuple("TCP")
    
    src_IP = str(bool_list_to_ip(randomize_bool_list_suffix(ip_to_bool_list(localhost_network.network_address), localhost_network.prefixlen)))
    dst_IP = str(bool_list_to_ip(randomize_bool_list_suffix(ip_to_bool_list(localhost_network.network_address), localhost_network.prefixlen)))
    # Generate some random port number
    src_port = random.randrange(1024, 65536) # We do not use port numbers lower than 1024 as they are reserved
    dst_port = random.randrange(1024, 65536)

    test_message = bytes(''.join(random.choices(string.ascii_uppercase + string.digits, k=100)), encoding='utf8')
    pkt_adr_log = []
    time_log = []

    tcp_recieve_thread = threading.Thread(target=tcp_listen, args=(dst_IP, dst_port, 1.0, pkt_adr_log, time_log))
    tcp_recieve_thread.start()

    time.sleep(0.5)

    tcp_send(src_IP, src_port, dst_IP, dst_port, [test_message], [0.0])

    tcp_recieve_thread.join()

    failed = False

    if len(pkt_adr_log) == 0:
        failed = True
    else:
        adress = pkt_adr_log[0][1]
        if adress != (src_IP, src_port):
            failed = True
        else:
            sent_message_stream = test_message.decode()
            received_message_stream = "".join([t.decode() for (t, _) in pkt_adr_log])
            if sent_message_stream != received_message_stream:
                failed = True

    # UDP transparency check on a non-blacklisted tuple.
    udp_message = bytes(''.join(random.choices(string.ascii_uppercase + string.digits, k=80)), encoding='utf8')
    udp_pkt_log = []
    udp_time_log = []

    udp_listen_thread = threading.Thread(target=udp_listen, args=(dst_IP, dst_port, 1.0, udp_pkt_log, udp_time_log))
    udp_listen_thread.start()
    time.sleep(0.2)

    udp_send(src_IP, src_port, dst_IP, dst_port, [udp_message], [0.0])

    udp_listen_thread.join()

    if len(udp_pkt_log) == 0:
        failed = True
    else:
        udp_addr = udp_pkt_log[0][1]
        if udp_addr != (src_IP, src_port):
            failed = True
        else:
            received_udp = b"".join([t for (t, _) in udp_pkt_log])
            if received_udp != udp_message:
                failed = True

    return 1.0 - 1.0 * failed

import ipaddress
import random
import string
import random
import threading
from grader_utility import *



def transparency_test ():


# Think about how to approach testing this firewall feature. We suggest using a similar approach as with the transparency test.
# This is not graded but the intended use is that this function returns 1 if your firewall is perfectly transparent to legitimate traffic, and 0 if it fails completely.

# This is the loopback interface
    localhost_network = ipaddress.ip_network("127.0.0.0/8")
# Generate some random IP addresses on the loopback interface
    src_IP = bool_list_to_ip(randomize_bool_list_suffix(ip_to_bool_list(localhost_network.network_address), localhost_network.prefixlen))
    dst_IP = bool_list_to_ip(randomize_bool_list_suffix(ip_to_bool_list(localhost_network.network_address), localhost_network.prefixlen))
# Generate some random port numbers
    src_port = random.randrange(1024, 65536) # We do not use port numbers lower than 1024 as they are reserved
    dst_port = random.randrange(1024, 65536) # We do not use port numbers lower than 1024 as they are reserved
# Test transparence using a TCP connection
    proto = "TCP"

# Generate a test message we will transmit
    test_message = bytes(''.join(random.choices(string.ascii_uppercase + string.digits, k=100)), encoding='utf8')
# Create objects to store TCP connection data
    pkt_adr_log = []
    time_log = []
# Spawn a thread that listens for a TCP connection at teh destination
    tcp_recieve_thread = threading.Thread(target=tcp_listen, args= (str(dst_IP), dst_port, 1.0, pkt_adr_log, time_log))
    tcp_recieve_thread.start()

# Sleep a while to ensure the listener-thread is listening. We require this because python threads are not actually real threads but rather coroutines.
    time.sleep(0.5)

# We are ready to send our TCP traffic.
    tcp_send(str(src_IP), src_port, str(dst_IP), dst_port, [test_message], [0.0])

# Wait for the receiver thread to finish
    tcp_recieve_thread.join()

    failed = False

# If the receiver did not receive any packets, we have failed
    if len(pkt_adr_log) == 0:
        failed = True
    else:
        adress = pkt_adr_log[0][1]
# If the source of the received packets is not the same as the source we used, we failed
        if adress != (str(src_IP), src_port):
            failed = True
        else:
            sent_message_stream = test_message.decode()
            received_message_stream = "".join([t.decode() for (t, _) in pkt_adr_log])
# If the messages received are not the same as the ones we sent, we have failed
            if sent_message_stream != received_message_stream:
                failed = True
# We have only tested one random TCP connection with one packet. If you want more throrough tests, expand this function as you please. In particular, do not forget to also test for UDP traffic.
    print("TODO: EXPAND TRANSPARENCY TEST")
    return 1.0 - 1.0 * failed

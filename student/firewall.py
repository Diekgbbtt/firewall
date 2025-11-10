# DO NOT MODIFY THIS FILE

import time
import resource
import signal
import sys
from netfilterqueue import NetfilterQueue # Needed for interfacing with the kernel packet queue
from firewall_code import firewall_init, firewall_packet_handler # The firewall consists of an initialization script (to set up datastructures, etc) and a packet-hander script

# The packet class
class nfq_pkt:
    def __init__(self, pkt):
        self.pkt = pkt
        self.time = time.time()

    def accept (self):
        self.pkt.accept()

    def drop (self):
        self.pkt.drop()

    def get_payload (self):
        return self.pkt.get_payload()
    
    def set_payload (self, data):
        self.pkt.set_payload(data)

    def get_timestamp(self):
        return self.time

# Wrapper around your firewall callback function to measure time statistics
def firewall_packet_handler_wrapper (pkt):
    global nextprint_time
    global total_firewall_packets
    global total_firewall_exectime_ns
    global firewall_begin_time
    global firewall_end_time

    begin_time = time.time_ns()
    # Your packet-handler callback function
    firewall_packet_handler(nfq_pkt(pkt))
    end_time = time.time_ns()

    total_firewall_exectime_ns += end_time - begin_time
    total_firewall_packets += 1

    ts = time.time()

    firewall_end_time = ts * 1.0

    if nextprint_time < ts:
        nextprint_time = ts + 5
        print(">Firewall Exec Time: ", total_firewall_exectime_ns * 1e-9)
        print(">Firewall Average Time per Packet: ", total_firewall_exectime_ns * 1e-9 / total_firewall_packets)
        print(">Firewall Average Packets per Time: ", total_firewall_packets / (firewall_end_time - firewall_begin_time))
        print(">Firewall Peak Memory Usage (KB): ", resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)

# Main
def main(S):
    # Initialize firewall and perform any required setup here
    firewall_init()

    global auth_code
    auth_code = S

    global nextprint_time
    global total_firewall_packets
    global total_firewall_exectime_ns
    global firewall_begin_time
    global firewall_end_time
    nextprint_time = time.time() + 5
    total_firewall_packets = 0
    total_firewall_exectime_ns = 0
    firewall_begin_time = time.time()
    firewall_end_time = time.time()

    # Create NFQ
    nfqueue = NetfilterQueue()
    # Bind NFQ to queue number 0 which is what we use for our setup, and set firewall_packet_handler_wrapper as the callback function
    nfqueue.bind(0, firewall_packet_handler_wrapper, max_len=2**15)
    # Start NFQ processing
    nfqueue.run(True)

# Handle firewall kills in order to write statistics to file if possible
def handle_interrupt(signum, frame):
    print("Caught SIGINT. Writing statistics.")
    global total_firewall_packets
    global total_firewall_exectime_ns
    global firewall_begin_time
    global firewall_end_time
    global auth_code

    output_filename = f"grader/stats_{auth_code}.txt"
    
    with open(output_filename, "w") as f:
        f.write("total_execution_time,average_time_per_packet,average_packets_per_time,peak_memory_usage_KB\n")
        f.write(f"{total_firewall_exectime_ns * 1e-9},{total_firewall_exectime_ns * 1e-9 / total_firewall_packets},{total_firewall_packets / (firewall_end_time - firewall_begin_time)},{resource.getrusage(resource.RUSAGE_SELF).ru_maxrss}\n")
    f.close()
    sys.exit(0)
signal.signal(signal.SIGINT, handle_interrupt)

if __name__=="__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 firewall.py <auth_code>")
        sys.exit(1)
    
    try:
        auth_code_arg = int(sys.argv[1])
        main(auth_code_arg)
    except ValueError:
        print("Error: The argument must be an integer.")
        sys.exit(1)
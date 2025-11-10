def ipnull_test ():

    # Think about how to approach testing this firewall feature. We suggest using a similar approach as with the transparency test.
    # This is not graded but the intended use is that this function returns 1 if your IP-null firewall feature works, and 0 if it fails completely.

    # Idea:
    # 1) Generate random IP sources and destinations (make sure they don't collide with blacklisted or NATed ranges)
    # 2) Create an IP packet with a payload of 0. Since the payload is zero, it means it is neither a UDP nor TCP packet, it is only IP.
    # 3) Send the empty IP packet.
    # 4) Listen at the source or destination for information on whether the packet was dropped by the firewall. 

    print("TODO: IPNULL TEST")
    return 0.0
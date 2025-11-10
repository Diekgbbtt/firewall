def halfnat_test ():

    # Think about how to approach testing this firewall feature. We suggest using a similar approach as with the transparency test.
    # This is not graded but the intended use is that this function returns 1 if your half-NAT firewall feature works, and 0 if it fails completely.

    # Idea:
    # 1) Read in the NAT config file.
    # 2) Pick source and destination addresses such that they are subject to the half-NAT rule.
    # 3) Send UDP traffic from the internal NAT range to the destination.
    # 4) Listen at the destination for incoming traffic
    # 5) Check whether the source IP of the received packets matches the external IP range of the NAT.

    print("TODO: HALFNAT TEST")
    return 0.0
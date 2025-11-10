#!/bin/bash

exec iptables -P OUTPUT DROP & 
exec iptables -A OUTPUT -o lo -j ACCEPT & 
exec iptables -A INPUT -i lo -j NFQUEUE --queue-num 0 &
/bin/bash
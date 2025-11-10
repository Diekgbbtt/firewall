#!/bin/bash

auth_code=${2:-0}

echo "Starting Firewall"
python3 student/firewall.py $auth_code &
pid1=$!

echo "Starting Traffic"
python3 grader/sender_receiver.py $1 $auth_code
echo "Finished Traffic"

echo "Attempting firewall softkill (SIGINT)"
kill -s SIGINT $pid1 2>/dev/null
sleep 5
if ps -p $pid1 > /dev/null
then
    echo "Executing firewall hardkill (SIGKILL)"
    kill -s SIGKILL $pid1 2>/dev/null
else
    echo "Firewall terminated gracefully."
fi

echo "Finished"
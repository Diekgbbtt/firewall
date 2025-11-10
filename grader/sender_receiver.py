import multiprocessing
import time
import argparse
import sys
import os
sys.path.append(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'student'))
from firewall_code import firewall_init
from ttl_test import ttl_test
from ipnull_test import ipnull_test
from blacklist_test import blacklist_test
from quarternat_test import quarternat_test
from halfnat_test import halfnat_test
from fullnat_test import fullnat_test
from transparency_test import transparency_test
from ratelimit_test import ratelimit_test
from portscan_test import portscan_test
from ddos_test import ddos_test

def test_repeated(testfunction, stop_signal, result_queue):
    score = 0
    scores = []
    while not stop_signal.is_set():
        try:
            new_score = testfunction()
            scores.append(new_score)
        except:
            time.sleep(1)
            pass
        time.sleep(1e-6)

    if len(scores) > 0:
        score = sum(scores) / len(scores)
    result_queue.put((score, len(scores)))

def test_async(testfunction):
    stop_signal = multiprocessing.Event()
    result_queue = multiprocessing.Queue()
    process = multiprocessing.Process(target=test_repeated, args=(testfunction, stop_signal, result_queue))
    process.start()
    return process, stop_signal, result_queue

def main(test_time, auth_code):

    task_selection = firewall_init()
    task_points = dict()
    task_points["ipnull"] = 1
    task_points["ttl"] = 1
    task_points["blacklist"] = 2
    task_points["quarternat"] = 2
    task_points["halfnat"] = 2
    task_points["fullnat"] = 3
    task_points["ratelimit"] = 3
    task_points["ddos"] = 4
    task_points["portscan"] = 4

    selected_points = sum([task_points[x] for (x, y) in task_selection.items() if y])

    transparency_process, transparency_stopsignal, transparency_results = test_async(transparency_test)

    ipnull_stopsignal = None
    ttl_stopsignal = None
    blacklist_stopsignal = None
    quarternat_stopsignal = None
    halfnat_stopsignal = None
    fullnat_stopsignal = None
    ratelimit_stopsignal = None
    ddos_stopsignal = None
    portscan_stopsignal = None

    if task_selection["ipnull"]:
        ipnull_process, ipnull_stopsignal, ipnull_results = test_async(ipnull_test)
    if task_selection["ttl"]:
        ttl_process, ttl_stopsignal, ttl_results = test_async(ttl_test)
    if task_selection["blacklist"]:
        blacklist_process, blacklist_stopsignal, blacklist_results = test_async(blacklist_test)
    if task_selection["quarternat"]:
        quarternat_process, quarternat_stopsignal, quarternat_results = test_async(quarternat_test)
    if task_selection["halfnat"]:
        halfnat_process, halfnat_stopsignal, halfnat_results = test_async(halfnat_test)
    if task_selection["fullnat"]:
        fullnat_process, fullnat_stopsignal, fullnat_results = test_async(fullnat_test)
    if task_selection["ratelimit"]:
        ratelimit_process, ratelimit_stopsignal, ratelimit_results = test_async(ratelimit_test)
    if task_selection["ddos"]:
        ddos_process, ddos_stopsignal, ddos_results = test_async(ddos_test)
    if task_selection["portscan"]:
        portscan_process, portscan_stopsignal, portscan_results = test_async(portscan_test)

    time.sleep(test_time)

    transparency_stopsignal.set()
    transparency_process.join()
    transparency_result = transparency_results.get()
    transparency_score = transparency_result[0]
    if ipnull_stopsignal is not None:
        ipnull_stopsignal.set()
        ipnull_process.join()
        ipnull_result = ipnull_results.get()
        ipnull_score = ipnull_result[0]
    if ttl_stopsignal is not None:
        ttl_stopsignal.set()
        ttl_process.join()
        ttl_result = ttl_results.get()
        ttl_score = ttl_result[0]
    if blacklist_stopsignal is not None:
        blacklist_stopsignal.set()
        blacklist_process.join()
        blacklist_result = blacklist_results.get()
        blacklist_score = blacklist_result[0]
    if quarternat_stopsignal is not None:
        quarternat_stopsignal.set()
        quarternat_process.join()
        quarternat_result = quarternat_results.get()
        quarternat_score = quarternat_result[0]
    if halfnat_stopsignal is not None:
        halfnat_stopsignal.set()
        halfnat_process.join()
        halfnat_result = halfnat_results.get()
        halfnat_score = halfnat_result[0]
    if fullnat_stopsignal is not None:
        fullnat_stopsignal.set()
        fullnat_process.join()
        fullnat_result = fullnat_results.get()
        fullnat_score = fullnat_result[0]
    if ratelimit_stopsignal is not None:
        ratelimit_stopsignal.set()
        ratelimit_process.join()
        ratelimit_result = ratelimit_results.get()
        ratelimit_score = ratelimit_result[0]
    if ddos_stopsignal is not None:
        ddos_stopsignal.set()
        ddos_process.join()
        ddos_result = ddos_results.get()
        ddos_score = ddos_result[0]
    if portscan_stopsignal is not None:
        portscan_stopsignal.set()
        portscan_process.join()
        portscan_result = portscan_results.get()
        portscan_score = portscan_result[0]

    print("Finished")
    print("Selected number of task points: ", selected_points)
    print("Test results: (test score average, number of test runs)")
    try:
        f = open(f"/usr/src/firewall/grader/grade_{auth_code}.txt", "w")
    except: 
        f = None
    print("\ntransparency_result: ", transparency_result)
    if f: f.write("name,score,runs,points")
    if f: f.write("\n" + ",".join(["transparency_result", str(transparency_result[0]), str(transparency_result[1]), "-1"]))
    if ipnull_stopsignal is not None:
        print("ipnull_result: ", ipnull_result)
        if f: f.write("\n" + ",".join(["ipnull_result", str(ipnull_result[0]), str(ipnull_result[1]), str(task_points["ipnull"])]))
    if ttl_stopsignal is not None:
        print("ttl_result: ", ttl_result)
        if f: f.write("\n" + ",".join(["ttl_result", str(ttl_result[0]), str(ttl_result[1]), str(task_points["ttl"])]))
    if blacklist_stopsignal is not None:
        print("blacklist_result: ", blacklist_result)
        if f: f.write("\n" + ",".join(["blacklist_result", str(blacklist_result[0]), str(blacklist_result[1]), str(task_points["blacklist"])]))
    if quarternat_stopsignal is not None:
        print("quarternat_result: ", quarternat_result)
        if f: f.write("\n" + ",".join(["quarternat_result", str(quarternat_result[0]), str(quarternat_result[1]), str(task_points["quarternat"])]))
    if halfnat_stopsignal is not None:
        print("halfnat_result: ", halfnat_result)
        if f: f.write("\n" + ",".join(["halfnat_result", str(halfnat_result[0]), str(halfnat_result[1]), str(task_points["halfnat"])]))
    if fullnat_stopsignal is not None:
        print("fullnat_result: ", fullnat_result)
        if f: f.write("\n" + ",".join(["fullnat_result", str(fullnat_result[0]), str(fullnat_result[1]), str(task_points["fullnat"])]))
    if ratelimit_stopsignal is not None:
        print("ratelimit_result: ", ratelimit_result)
        if f: f.write("\n" + ",".join(["ratelimit_result", str(ratelimit_result[0]), str(ratelimit_result[1]), str(task_points["ratelimit"])]))
    if ddos_stopsignal is not None:
        print("ddos_result: ", ddos_result)
        if f: f.write("\n" + ",".join(["ddos_result", str(ddos_result[0]), str(ddos_result[1]), str(task_points["ddos"])]))
    if portscan_stopsignal is not None:
        print("portscan_result: ", portscan_result)
        if f: f.write("\n" + ",".join(["portscan_result", str(portscan_result[0]), str(portscan_result[1]), str(task_points["portscan"])]))
    if f: f.write("\n")
    if f: f.close()

if __name__=="__main__":

    parser = argparse.ArgumentParser()
    parser.add_argument('test_time')
    parser.add_argument('auth_code')
    args = parser.parse_args()
    
    test_time = float(args.test_time)
    auth_code = args.auth_code

    main(test_time, auth_code)

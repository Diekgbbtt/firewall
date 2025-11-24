# YOU CAN MODIFY THIS FILE

import csv

def parse_nat_config (filepath):
    data = []
    with open(filepath, mode='r') as file:
        csv_reader = csv.DictReader(file)
        for row in csv_reader:
            data.append({
                "NatType": row['NatType'],
                "Internal_IP": row['Internal_IP'],
                "External_IP": row['External_IP']
            })
    return data

def parse_blacklist_config (filepath):
    data = []
    def _parse_port_range(port_field):
        parts = port_field.split('-')
        if len(parts) == 1:
            val = int(parts[0])
            return val, val
        return tuple(map(int, parts[:2]))

    with open(filepath, mode='r') as file:
        csv_reader = csv.DictReader(file)
        for row in csv_reader:
            source_port_start, source_port_end = _parse_port_range(row['Source_Port'])
            dest_port_start, dest_port_end = _parse_port_range(row['Destination_Port'])
            data.append({
                "Protocol": row['Protocol'],
                "Source_IP": row['Source_IP'],
                "Destination_IP": row['Destination_IP'],
                "Source_Port": (source_port_start, source_port_end),
                "Destination_Port": (dest_port_start, dest_port_end)
            })
    return data

def parse_ratelimit_config (filepath):
    data = {}
    with open(filepath, mode='r') as file:
        csv_reader = csv.DictReader(file)
        for row in csv_reader:
            data = {"Ratelimit": float(row['Ratelimit']), "IdleLifespan": float(row['IdleLifespan'])}
            return data
        


def parse_ttl_config (filepath):
    data = {}
    with open(filepath, mode='r') as file:
        csv_reader = csv.DictReader(file)
        for row in csv_reader:
            data = {"MaxTTL": int(row['MaxTTL']), "MinTTL": int(row['MinTTL'])}
            return data
        
def parse_portscan_config (filepath):
    data = {}
    with open(filepath, mode='r') as file:
        csv_reader = csv.DictReader(file)
        for row in csv_reader:
            data = {"SynNum": int(row['SynNum']), "MaxPacketInterval": float(row['MaxPacketInterval'])}
            return data

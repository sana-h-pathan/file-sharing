#!/usr/bin/env python  
# -*- coding:utf-8 _*-

""" 

@Author: Haomin Cheng
@File Name: supernode.py 
@Time: 2023/11/24
@Contact: haomin.cheng@outlook.com

"""
import math

import requests
import config
import utils.util
from utils import common, endpoints
import os
import random
import socket
import threading
import signal
import sys
import json
import boto3
import time
from utils.colorfy import *
from utils.util import get_info_from_identifier

BUCKET_NAME = "file-share-coen317"
SERVER_BUCKET_NAME = "server-info-coen317"
LEADER_FILE = "leader_config.json"
SERVER_HOST = '0.0.0.0'
SERVER_PORT = 5551
LEADER_PORT = 4447
NODE_ALIVE_PREFIX = 'node'
LEADER_CHECK_INTERVAL = 120

connected_clients = {}
nodes = [
    {'id': 2, 'ip': '172.31.5.165'},
    {'id': 1, 'ip': '172.31.40.112'}
]

nodes_to_ip = [
    {'id': 2, 'ip': '18.219.30.179'},
    {'id': 1, 'ip': '3.144.165.8'}
]
ip_to_node_id = {node['ip']: node['id'] for node in nodes}

current_leader = None
ip_log_file = 'node_info.json'
NODES_LIST_FILE = 'nodes.json'
HEARTBEAT_TIMEOUT = 10

lock = threading.Lock()
heartbeat_lock = threading.Lock()
connected_clients_lock = threading.Lock()
leader_lock = threading.Lock()


# Create an S3 client
global s3_client


# s3_server_bucket = boto3.resource('s3').Bucket(SERVER_BUCKET_NAME)
# s3_server = boto3.resource('s3')


def is_leader_alive(leader):
    """
    Check if the leader is alive
    :param leader: {uid, ip, port}
    :return:
    """

    if config.LOCAL_SERVER:
        print(red("running locally, leader is alive"))
        return True

    # Use a temporary socket to check if the leader is alive
    if leader['uid'] == common.my_uid:
        return True
    print(red("[is_leader_alive]"), ("Checking if leader is alive:" + leader['ip'] + ":" + str(leader['port'])))
    response = requests.get(config.ADDR + leader['ip'] + ":" + str(leader['port']) + endpoints.ping_server)
    if response.status_code == 200 and response.text == "pong":
        return True
    else:
        print(red(f"[is_leader_alive] {leader['ip']}: {leader['port']} respond {response.status_code}, {response.text}"))
        return False


def create_alive_file():
    file_key = utils.util.get_identifier(common.my_uid, common.my_ip, common.my_port)

    if config.LOCAL_SERVER:
        print(red("running locally, not creating alive file"))
        return

    # Check if the file already exists in the S3 bucket
    if not does_s3_object_exist(SERVER_BUCKET_NAME, file_key):
        s3_client.put_object(
            Bucket=SERVER_BUCKET_NAME,
            Key=file_key,
            Body="This file indicates that the server is alive."
        )
        print(f"Alive file created for node {common.my_uid} in bucket {SERVER_BUCKET_NAME} at {file_key}")
    else:
        if config.vBDEBUG:
            print(f"Alive file for node {common.my_uid} already exists in bucket {SERVER_BUCKET_NAME} at {file_key}")


def read_leader_config():
    try:
        response = s3_client.get_object(Bucket=BUCKET_NAME, Key=LEADER_FILE)
        content = response["Body"].read().decode("utf-8")

        if config.BDEBUG:
            print(blue(f"[read_leader_config] content: {content}"))
        if not content:
            # Handle empty file content
            return None
        return json.loads(content)
    except json.JSONDecodeError:
        # Handle invalid JSON content
        return None
    except s3_client.exceptions.NoSuchKey:
        # Handle file not found
        return None
    except Exception as e:
        print(f"An error occurred in read_leader_config: {e}")
        return None


def get_node_list_from_s3():
    if config.LOCAL_SERVER:
        print(red("running locally, not getting node list from s3"))
        return common.mids

    try:
        response = s3_client.get_object(Bucket=BUCKET_NAME, Key=NODES_LIST_FILE)
        node_list = json.loads(response['Body'].read().decode('utf-8'))
        return node_list
    except s3_client.exceptions.NoSuchKey:
        return []


def update_local_node_list():
    if config.LOCAL_SERVER:
        print(red("running locally, not updating local node list"))
        return

    nodes = get_node_list_from_s3()
    common.mids = nodes


def save_node_list_to_s3(node_list):
    if config.LOCAL_SERVER:
        print(red("running locally, not saving node list to s3"))
        return

    s3_client.put_object(Bucket=BUCKET_NAME, Key=NODES_LIST_FILE, Body=json.dumps(node_list).encode('utf-8'))
    update_local_node_list()


def delete_node_from_node_list(node):
    get_node_list_from_s3()

    if node not in common.mids:
        print(red(f"Node {node} not in node list"))
        return

    print(red(f"delete_node {node} _from_node_list"))

    common.mids.remove(node)
    save_node_list_to_s3(common.mids)


def write_leader_config(data):
    if config.LOCAL_SERVER:
        print(red("running locally, not writing leader config"))
        return

    print(red(f"[write_leader_config] data {data}"))

    s3_client.put_object(Body=json.dumps(data).encode('utf-8'), Bucket=BUCKET_NAME, Key=LEADER_FILE)


def get_object_from_s3(s3_client, bucket_name, key):
    try:
        response = s3_client.get_object(Bucket=bucket_name, Key=key)
        return response['Body'].read().decode('utf-8')
    except Exception as e:
        print(f"Error getting object from S3: {e}")
        return None


def does_s3_object_exist(bucket, key):
    try:
        s3_client.head_object(Bucket=bucket, Key=key)
        return True
    except Exception as e:
        return False


def remove_alive_file():
    """
    This function removes the 'alive' file of the current node from the S3 bucket.
    """
    if config.LOCAL_SERVER:
        print(red("running locally, not removing alive file"))
        return

    file_key = f'{common.my_uid}_{common.my_ip}_{common.my_port}'

    # check all available server
    avaialbe_server_list = get_all_available_servers()

    if file_key in avaialbe_server_list:
        try:
            s3_client.delete_object(Bucket=SERVER_BUCKET_NAME, Key=file_key)
            print(red(f"Alive file {file_key} successfully removed from bucket {SERVER_BUCKET_NAME}."))
        except Exception as e:
            print(red(f"An error occurred while removing the alive file: {e}"))

        if len(avaialbe_server_list) == 1:
            # if the current node is the leader, then we need to elect a new leader
            print(red("i am the only server and i am dead now, so the network is dead, deleting the node list file"))
            try:
                s3_client.delete_object(Bucket=BUCKET_NAME, Key=NODES_LIST_FILE)
                print(red(f"Node list file successfully removed from bucket {BUCKET_NAME}."))
            except Exception as e:
                print(red(f"An error occurred while removing the node list file: {e}"))
    else:
        print(f"Alive file {file_key} does not exist in bucket {SERVER_BUCKET_NAME}.")


def get_new_leader_from_list(server_list):
    """
    This function returns the file key with the minimum node ID.
    :param server_list: A list of server file objects
    :return: The file key with the minimum node ID
    """
    min_node_id = None
    min_file_key = None

    for file in server_list:
        # Extracting the file name
        file_key = file

        # Splitting the file name to get the node_id
        node_id = file_key.split('_')[0]

        if min_node_id is None or node_id < min_node_id:
            min_node_id = node_id
            min_file_key = file_key

    return min_file_key


def get_all_available_servers():
    """
    This function returns a list of all available servers.
    :return:
    """
    available_servers = s3_client.list_objects(Bucket=SERVER_BUCKET_NAME)
    available_servers_list = [item["Key"] for item in available_servers["Contents"]] if "Contents" in available_servers else []
    print(cyan(f"Available servers: {available_servers_list}"))

    return available_servers_list


def remove_server_from_leader_config():
    if config.LOCAL_SERVER:
        print(red("running locally, not removing server from leader config"))
        return

    try:
        common.current_leader = read_leader_config()
        print(red("Current Leader"), str(common.current_leader))
        if common.current_leader is not None:
            current_node_identifier = f'{common.my_uid}_{common.my_ip}_{common.my_port}'

            # Check if the current leader is the same as the current node
            if common.current_leader['uid'] == common.my_uid:
                print(red("I am the leader, i am dead now, so removing myself from leader_config.json"))
                # Remove the current_leader from the file content
                new_content = ''
                # Update the leader_config.txt file in S3 with the modified content
                s3_client.put_object(Body=new_content.encode("utf-8"), Bucket=BUCKET_NAME, Key=LEADER_FILE)

                print(f"removed myself from leader_config.json")
                if len(get_all_available_servers()) > 0:
                    print(red("i am dead leader, so i am electing a new leader"))
                    leader_election()
                common.current_leader = None
            else:
                print(f"i am not the leader, so i could just die")
        else:
            print("No current leader information available. No action needed.")
    except Exception as e:
        print(f"Error removing server from leader_config.txt: {e}")


def initiate_leader_election():
    """
    This function initiates the leader election process.
    :return:
    """
    if config.LOCAL_SERVER:
        print(red("running locally, initiating leader election, i am the leader"))
        common.current_leader = f'{common.my_uid}_{common.my_ip}_{common.my_port}'
        return

    while True:
        create_alive_file()
        leader_election()

        time.sleep(LEADER_CHECK_INTERVAL)


def leader_election():
    common.current_leader = read_leader_config()
    if config.BDEBUG:
        print(yellow("[Leader Election]"), "Current Leader", common.current_leader)

    # Check if current_leader is a valid object {uid, ip, port}
    if common.current_leader is not None:
        leader_alive = is_leader_alive(common.current_leader)

        if leader_alive:
            print(red("[Leader Election]"), f"Leader {common.current_leader} is alive.")
            if common.current_leader['uid'] == common.my_uid:
                if not common.is_leader:
                    print(red("i am the leader, but i dont know, i must be elected recently, updating my info"))
                    common.is_leader = True
                    update_local_node_list()
        else:
            print(red("[Leader Election]"),
                  f"Leader {common.current_leader} is not alive. Re-electing a new leader.")
            common.current_leader = None
    else:
        print(red("[Leader Election]"), "No current leader information available. No action needed.")
        common.current_leader = None

    # Check if the S3 object (file) exists
    if common.current_leader is None:
        # If no leader or the current leader is not alive, elect a new leader
        available_nodes = get_all_available_servers()
        # choose the node with the lowest node_id as the new leader
        if available_nodes:
            new_leader_key = get_new_leader_from_list(available_nodes)
            new_leader = get_info_from_identifier(new_leader_key)
            if new_leader is not None:
                print(red("[Leader Election]"),
                      f"Node {new_leader['ip']}:{new_leader['port']} elected as the new leader.")
                common.current_leader = new_leader
                write_leader_config(common.current_leader)


def init_server():
    print(red("[Init Server]"), f"Server is listening on {common.my_ip}:{common.my_port}")

    # Start the leader election thread
    leader_election_thread = threading.Thread(target=initiate_leader_election, daemon=True)
    leader_election_thread.start()

    def signal_handler(sig, frame):
        print('\n')
        print(red("[SERVER SHUTTING DOWN]"), "Closing server...")
        remove_alive_file()
        remove_server_from_leader_config()
        # Print a message indicating where the IP addresses are stored
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)


# -----------------------------------------------------
# functions for the chord ring
def bootstrap_join_func(new_node):
    """
    This function is called by bootstrap node when a node wants to join the Chord.
    :param new_node: {node uid, ip, port}
    :return:
    """
    while common.server_node_joining:
        print(red("[Bootstrap Join]"), "Other node has not finished joining the Chord. Waiting...")
        time.sleep(0.5)

    common.server_node_joining = True

    update_local_node_list()
    candidate_id = new_node["uid"]
    if config.BDEBUG:
        print(blue(candidate_id) + " wants to join the Chord with ip:port " + blue(
            new_node["ip"] + ":" + new_node["port"]))

    # if the new node is the first node in the Chord
    if len(common.mids) == 0:
        common.mids.append(new_node)
        response = {
            "prev": {
                "uid": new_node["uid"],
                "ip": new_node["ip"],
                "port": new_node["port"]
            },
            "next": {
                "uid": new_node["uid"],
                "ip": new_node["ip"],
                "port": new_node["port"]
            },
            "k": common.node_k,
        }
        save_node_list_to_s3(common.mids)
        common.server_node_joining = False
        return response

    common.mids.append(new_node)
    common.mids.sort(key=lambda x: int(x['uid'], 16))
    new_node_idx = common.mids.index(new_node)
    save_node_list_to_s3(common.mids)

    # threading.Thread(target=update_finger_tables_on_join, args=(new_node,), daemon=True).start()
    update_finger_tables_on_join(new_node)

    if config.vBDEBUG:
        print(blue(common.mids))
        print(blue("new node position in common.mids: " + str(new_node_idx)))
    prev_of_prev = common.mids[new_node_idx - 2] if new_node_idx >= 2 else (
        common.mids[-1] if new_node_idx >= 1 else common.mids[-2])
    prev = common.mids[new_node_idx - 1] if new_node_idx >= 1 else common.mids[-1]
    next = common.mids[new_node_idx + 1] if new_node_idx < len(common.mids) - 1 else common.mids[0]
    next_of_next = common.mids[new_node_idx + 2] if new_node_idx < len(common.mids) - 2 else (
        common.mids[0] if new_node_idx < len(common.mids) - 1 else common.mids[1])

    response_p = requests.post(config.ADDR + prev["ip"] + ":" + prev["port"] + endpoints.node_update_neighbours,
                               json={"prev": prev_of_prev, "next": new_node, "change": "next"})
    if response_p.status_code == 200 and response_p.text == "new neighbours set":
        if config.BDEBUG:
            print(blue("Updated previous neighbour successfully"))
    else:
        print(RED("Something went wrong while updating previous node list"))
    print(config.ADDR, next["ip"], ":", next["port"], endpoints.node_update_neighbours)
    response_n = requests.post(config.ADDR + next["ip"] + ":" + next["port"] + endpoints.node_update_neighbours,
                               json={"prev": new_node, "next": next_of_next, "change": "prev"})
    if response_n.status_code == 200 and response_n.text == "new neighbours set":
        if config.BDEBUG:
            print(blue("Updated next neighbour successfully"))
    else:
        print(RED("Something went wrong while updating next node list"))

    if config.NDEBUG:
        print(yellow(f"Node {new_node['ip']}:{new_node['port']} completed join the chord, server ok."))

        # check if the joined node makes replication possible
        if len(common.mids) > common.k:
            if common.node_k != common.k:
                print(red(f"Now there are {len(common.mids)} nodes in the Chord. {common.k} Replication is possible."))
                print(red(f"i should change nodes' factor from {common.node_k} to {common.k}"))
                common.node_k = common.k
                update_nodes_replication_factor(common.k)
            else:
                if config.BDEBUG:
                    print(blue("Replication is already possible, so when last node join, the k should be updated."))

    response = {
        "prev": {
            "uid": prev["uid"],
            "ip": prev["ip"],
            "port": prev["port"]
        },
        "next": {
            "uid": next["uid"],
            "ip": next["ip"],
            "port": next["port"]
        },
        "k": common.node_k
    }
    common.server_node_joining = False
    return json.dumps(response)


def update_finger_tables_on_join(new_node):
    """
    This function updates the finger tables of affected nodes in the network when a new node joins.
    :param new_node:
    :return:
    """
    while common.server_updating_finger_table:
        print(red("Updating finger tables clogged.. waiting for finger table update to finish..."))
        time.sleep(1)
    common.server_updating_finger_table = True
    update_local_node_list()

    new_node_id = int(new_node['uid'], 16)
    N = len(common.mids)
    # m = int(math.ceil(math.log2(N + 1)))  # Recalculate m as the number of nodes has changed
    m = 160

    # special case: if the finger table is lost, rebuild it
    if len(common.finger_tables) == 0:
        print(red("Finger table lost, rebuilding..."))
        for node in common.mids:
            common.finger_tables[node['uid']] = generate_finger_table_for_node(node, N, m)
            send_finger_table_update(node, common.finger_tables[node['uid']])
        common.server_updating_finger_table = False
        return

    nodes_to_update = set()

    # Update finger tables of affected nodes
    for node in common.mids:
        if node == new_node:
            continue

        node_id = int(node['uid'], 16)
        update_needed = False

        for k in range(1, m + 1):
            start = (node_id + 2 ** (k - 1)) % 2 ** m
            if new_node_id >= start or new_node_id < node_id:
                finger_table = common.finger_tables.get(node['uid'], [])
                if k <= len(finger_table):
                    # Update the existing entry
                    finger_table[k - 1] = {"start": start, "node": new_node}
                else:
                    # Add a new entry
                    finger_table.append({"start": start, "node": new_node})
                update_needed = True

            if update_needed:
                common.finger_tables[node['uid']] = finger_table
                nodes_to_update.add(node['uid'])
                update_needed = False

    for node_uid in nodes_to_update:
        node = next(filter(lambda x: x['uid'] == node_uid, common.mids), None)
        if node:
            send_finger_table_update(node, common.finger_tables[node_uid])

    # Calculate finger table for the new node
    common.finger_tables[new_node['uid']] = generate_finger_table_for_node(new_node, N, m)
    send_finger_table_update(new_node, common.finger_tables[new_node['uid']])
    common.server_updating_finger_table = False


def generate_finger_table_for_node(node, N, m):
    """
    This function generates the finger table for a given node.
    :param node:
    :param N:
    :param m:
    :return:
    """
    finger_table = []
    node_id = int(node['uid'], 16)

    for k in range(1, m + 1):
        start = (node_id + 2 ** (k - 1)) % 2 ** m
        successor = find_successor(start, common.mids)
        finger_table.append({"start": start, "node": successor})

    return finger_table


def find_successor(start, nodes):
    """
    This function finds the successor of a given start value in a list of nodes.
    :param start:
    :param nodes:
    :return:
    """
    # Assuming nodes are sorted by UID
    for node in nodes:
        node_id = int(node['uid'], 16)
        if start <= node_id:
            return node
    # If not found, return the first node (circular)
    return nodes[0]


def send_finger_table_update(node, finger_table):
    """
    This function sends the finger table update to a node.
    :param node:
    :param finger_table:
    :return:
    """
    try:
        response = requests.post(config.ADDR + node["ip"] + ":" + node["port"] + endpoints.node_update_finger_table,
                                 json={"finger_table": finger_table, "timestamp": time.time()})
        if response.status_code == 200 and response.text == "finger table updated":
            if config.BDEBUG:
                print(blue(f"Updated finger table of {node['ip']}:{node['port']} successfully"))
        else:
            print(RED("Something went wrong while updating finger table"))
    except:
        print("Something went wrong with finger table update")


def boot_leave_func(node_info):
    if node_info not in common.mids:
        return "you are not in network", 400

    node_idx = common.mids.index(node_info)
    print(red(f"Node {node_info['uid']} with {node_info['ip']}:{node_info['port']} asking to leave the network..."))

    print(red(f"so we have only {len(common.mids) - 1} nodes in the network after it leave..."))

    # update k first, so the node would not casue infinite replicate after sending the update neighbours request
    if common.node_k != 0:
        if len(common.mids) - 1 <= common.k:
            print(
                red(f"there is no enough nodes in the network to keep the replication factor, so no replicate from now on"))
            common.node_k = 0
            update_nodes_replication_factor(0, node_info)

    if len(common.mids) == 1:
        print(red(f"Node {node_info['uid']} is the last node in the network, so it can just dead"))
        delete_node_from_node_list(node_info)
        return "last node, just die", 200

    if len(common.mids) == 2:
        print(red(f"Node {node_info['uid']} is the second last node in the network, so the last node will be the "
                  f"specially handled"))

        next = common.mids[node_idx + 1] if node_idx < len(common.mids) - 1 else common.mids[0]
        response = requests.post(config.ADDR + next["ip"] + ":" + next["port"] + endpoints.node_update_neighbours,
                                 json={"prev": next, "next": next, "change": "prev"})
        if response.status_code == 200 and response.text == "new neighbours set":
            print(red(f"Updated neighbours of {next['ip']}:{next['port']} specially successfully"))
        delete_node_from_node_list(node_info)
        return "you are ok to die", 200



    prev_of_prev = common.mids[node_idx - 2] if node_idx >= 2 else (
        common.mids[-1] if node_idx >= 1 else common.mids[-2])
    prev = common.mids[node_idx - 1] if node_idx >= 1 else common.mids[-1]
    next = common.mids[node_idx + 1] if node_idx < len(common.mids) - 1 else common.mids[0]
    next_of_next = common.mids[node_idx + 2] if node_idx < len(common.mids) - 2 else (
        common.mids[0] if node_idx < len(common.mids) - 1 else common.mids[1])

    print(red(f"Node {node_info['uid']} leaving, telling its neighbours to update their neighbours..."))
    response_p = requests.post(config.ADDR + prev["ip"] + ":" + prev["port"] + endpoints.node_update_neighbours,
                               json={"prev": prev_of_prev, "next": next, "change": "next"})
    if response_p.status_code == 200 and response_p.text == "new neighbours set":
        if config.BDEBUG:
            print(red("Updated previous neighbour successfully"))
        p_ok = True
    else:
        print(red("Something went wrong while updating previous node list"))
        p_ok = False

    response_n = requests.post(config.ADDR + next["ip"] + ":" + next["port"] + endpoints.node_update_neighbours,
                               json={"prev": prev, "next": next_of_next, "change": "prev"})
    if response_n.status_code == 200 and response_n.text == "new neighbours set":
        if config.BDEBUG:
            print(blue("Updated next neighbour successfully"))
        n_ok = True
    else:
        print(RED("Something went wrong while updating next node list"))
        n_ok = False

    if n_ok and p_ok:
        delete_node_from_node_list(node_info)
        print(red(f"Node {node_info['uid']} with {node_info['ip']}:{node_info['port']} removed successfully"))
        return "you are ok to die"
    else:
        print(red(f"Cannot remove Node {node_info['ip']}:{node_info['port']}, something went wrong! "))

        # response_p = requests.post(config.ADDR + prev["ip"] + ":" + prev["port"] + endpoints.node_update_neighbours,
        #                            json={"prev": prev_of_prev, "next": next, "change": "next"})
        #
        # response_n = requests.post(config.ADDR + next["ip"] + ":" + next["port"] + endpoints.node_update_neighbours,
        #                            json={"prev": prev, "next": next_of_next, "change": "prev"})
        #
        return "no"


def update_nodes_replication_factor(new_k, except_node=None):
    print(red(f"updating nodes replication factor to {new_k}"))

    def send_update_k_request(node, k):
        requests.post(config.ADDR + node["ip"] + ":" + node["port"] + endpoints.node_update_k,
                      data={"k": k})

    for node in common.mids:
        if node == except_node:
            continue
        if config.BDEBUG:
            print(yellow(f"updating node {node['uid']} with {node['ip']}:{node['port']}"))
        threading.Thread(target=send_update_k_request, args=(node, new_k)).start()

    print(red(f"send update to nodes setting their replication factor to {new_k}"))

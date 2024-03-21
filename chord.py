#!/usr/bin/env python  
# -*- coding:utf-8 _*-

""" 

@Author: Haomin Cheng
@File Name: chord.py 
@Time: 2023/11/24
@Contact: haomin.cheng@outlook.com

"""
import hashlib
import json
import os
import signal
import sys
import threading
import time
from threading import Thread

import requests

import config
from utils import common, endpoints
from utils.colorfy import *
from utils.util import ping_server


# ----------------------Node Function---------------------------------------
def init_node():
    """
    initialize the node, setting the dead function
    :return:
    """

    def signal_handler(sig, frame):
        print('\n')
        print(red(f"i am the node {common.my_uid} with {common.my_ip}:{common.my_port}and i am going down..."))

        retry_count = 0
        max_retries = 3  # Set a max retry limit
        dead = False

        while not dead and retry_count < max_retries:
            server_res = node_init_leave()
            if server_res == "error":
                print(red(f"Leave attempt {retry_count + 1} failed. Retrying..."))
                time.sleep(5)  # Wait for second before retrying
                retry_count += 1
            else:
                dead = True

        if not dead:
            print(red("Unable to leave gracefully after multiple attempts. Forcing exit."))

        # Transfer my hosted files to my successor
        if dead and not server_res == "last node, just die":
            transfer_my_hosted_files()
        else:
            print(red("I no need to transfer legacy files"))

        print(red(f"Goodbye! I am dead now. {common.my_uid}, {common.my_ip}:{common.my_port}"))
        common.still_on_chord = False

        # Print a message indicating where the IP addresses are stored
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)


def node_initial_join():
    if common.still_on_chord:
        if not common.is_bootstrap:
            if config.NDEBUG:
                print(yellow("\nattempting to join the Chord..."))
            try:
                # target = config.LOCAL_SERVER ? config.LOCAL_BOOTSTRAP_IP :config.BOOTSTRAP_IP
                response = requests.post(
                    config.ADDR + config.BOOTSTRAP_IP + ":" + config.BOOTSTRAP_PORT + endpoints.boot_join,
                    data={"uid": common.my_uid, "ip": common.my_ip, "port": common.my_port})
                if response.status_code == 200:
                    data = response.json()
                    if config.NDEBUG:
                        print(yellow(f"join server respond with data: {data}"))
                    prev_node = data["prev"]
                    next_node = data["next"]
                    init_k = data["k"]

                    common.nids.append(prev_node)
                    common.nids.append(next_node)
                    common.k = init_k

                    if config.NDEBUG:
                        print(f"Joined Chord successfully!!")
                        print(f"Previous Node: {json.dumps(prev_node)}")
                        print(f"Next Node: {json.dumps(next_node)}")
                        print(f"initialized k is: {init_k}")
                else:
                    print("Something went wrong!!  status code: " + red(response.status_code))
                    print(red("\nexiting..."))
                    exit(0)
            except:
                print(red("\nSomething went wrong!! (check if bootstrap is up and running)"))
                print(red("\nexiting..."))
                exit(0)


def node_init_leave():
    if config.NDEBUG:
        print(yellow(f"[node_init_leave] i am the node {common.my_uid} with {common.my_ip}:{common.my_port}"
                     f"and i am going down..."))

    print(red("i am going down, sending leave request to the server..."))
    has_server = get_server_from_cloud()
    if not has_server:
        print(red("i am going down, but i cannot find the server. i would just die.."))
        return "last node, just die"

    # send depart request to the supernode, begging to leave
    response = requests.post(config.ADDR + config.BOOTSTRAP_IP + ":" + config.BOOTSTRAP_PORT + endpoints.boot_leave,
                             data={"node_info": json.dumps(
                                 {"uid": common.my_uid, "ip": common.my_ip, "port": common.my_port})})

    if response.status_code == 200 and response.text == "you are ok to die":
        print(red(f"server allows to leave..."))
        return "server allows to leave"
    elif response.status_code == 200 and response.text == "last node, just die":
        print(red(f"server allows to leave, i am the last node..."))
        return "last node, just die"
    elif response.status_code == 400 and response.text == "you are not in network":
        print(red(f"server says i am not in the network, just die..."))
        return "last node, just die"
    else:
        print(red(f"i am the node {common.my_uid} with {common.my_ip}:{common.my_port}"
                  f"and server response {response.text} with {response.status_code}"))
        return "error"


def transfer_my_hosted_files():
    """
    when a node is leaving, it should transfer the files it is responsible for to its successor
    :return:
    """
    print(red(f"i am dead so i am transferring my files to my successor {common.nids[1]}.."))

    if config.NDEBUG:
        print(yellow(f"[transfer_my_hosted_files] i am the node {common.my_uid} with {common.my_ip}:{common.my_port}"
                     f"and i have files{common.host_file_list}"))

    send_legacy()

    retry_count = 0
    max_retries = 3  # Set a max retry limit

    # after sending all my legacy, the common_list should be empty
    while len(common.host_file_list) != 0 and retry_count < max_retries:
        if config.NDEBUG:
            print(
                yellow(f"[transfer_my_hosted_files] i am the node {common.my_uid} with {common.my_ip}:{common.my_port}"
                       f"and i have files{common.host_file_list}"))

        # if not empty, try to send again
        send_legacy()
        retry_count += 1
        time.sleep(5)

    if len(common.host_file_list) != 0:
        print(red(f"i still have legacy, {common.host_file_list}"))

    return True


def send_legacy():
    for filename in common.host_file_list:
        if config.NDEBUG:
            print(yellow(f"[transfer_my_hosted_files] trying {filename}"))

        filepath = common.node_host_file_dir + filename + ".pdf"
        # check if file exists
        if not os.path.exists(filepath):
            if config.NDEBUG:
                print(yellow(f"file {filename} does not exist in local, continue to next file"))
            common.host_file_list.remove(filename)
            continue

        # if exist, start transfer to successor
        with open(filepath, "rb") as f:
            files = {"file": f}
            response = requests.post(config.ADDR + common.nids[1]["ip"] + ":" + common.nids[1]["port"] +
                                     endpoints.node_legacy_transfer,
                                     data={"filename": filename,
                                           "node_info": json.dumps(
                                               {"uid": common.my_uid, "ip": common.my_ip, "port": common.my_port})},
                                     files=files)
        if response.status_code == 200 and response.text == 'store legacy success':
            if config.NDEBUG:
                print(yellow(f"file {filename} transferred to successor"))
            os.remove(filepath)
            common.host_file_list.remove(filename)


def node_replic_nodes_list(data):
    """
    list the nodes that the new node is responsible for replication
    :param data: {"node_list": node_list, "k": common.k, "new_id": common.my_id}
    :return:
    """
    node_list = data["node_list"]
    k = data["k"]  # k is the number of nodes that the new node should be responsible for replication
    new_id = data["new_id"]

    if common.my_uid != new_id:
        node_list.append(common.my_uid)

    if k >= 1:
        response = requests.post(
            config.ADDR + common.nids[0]["ip"] + ":" + common.nids[0]["port"] + endpoints.replic_nodes_list,
            json={"node_list": node_list, "k": k - 1, "new_id": new_id})
        print(yellow("Got request for new nodes wants to replicate, current list new node needs to handled is:"))
        print(response.json())
        return response.json()
    else:
        print(yellow("Got request for new nodes wants to replicate, i am the last one, current list it needs to "
                     "handled is:"))
        return {"node_list": node_list}


def node_redistribute_data(data):
    """
    redistribute the data to the new node, after the new node join the chord
    endpoint: endpoints.node_join_procedure
    :param data: {"node_list": node_list, "new_id": new added node id}
    :return:
    """
    print("Chord join update POST function is starting...")
    node_list = data["node_list"]
    new_id = data["new_id"]
    # todo update here
    try:
        response = requests.post(
            config.ADDR + common.nids[1]["ip"] + ":" + common.nids[1]["port"] + endpoints.node_update_replicate,
            json={"node_list": node_list, "new_id": new_id})
        song_list_json = response.json()
        song_list = song_list_json["song_list"]
    except:
        print("Problem with join update song list operation")
        return "NOT OK"

    for item in song_list:
        common.songs.append(item)
    return "New node songs and replication updated"


def node_update_neighbours_func(data):
    """
    update the neighbours of the node
    :param data:
    :return:
    """
    print(yellow(data))
    common.nids[0] = data["prev"]
    common.nids[1] = data["next"]
    change_neighbor = data["change"]  # either "prev" or "next"
    if config.NDEBUG:
        print(red("[node_update_neighbours_func] i got new neighbours:"))
        print(yellow("NEW Previous Node:"))
        print(common.nids[0])
        print(yellow("NEW Next Node:"))
        print(common.nids[1])
    print(red("i got New neighbours and set"))

    node_redistribute_host_file_to_new_neighbour(change_neighbor)
    return "new neighbours set"


def node_update_finger_table_func(res):
    while common.node_updating_finger_table:
        print(red(["[node_update_finger_table_func] waiting for previous to be done..."]))
        time.sleep(1)

    common.node_updating_finger_table = True
    try:
        if "timestamp" not in res or "finger_table" not in res:
            return "Invalid data format", 400

        if common.my_finger_table is not None and common.my_finger_table_timestamp > res["timestamp"]:
            print(yellow("[node_update_finger_table_func] Received older finger table. Not updating."))
            return "Finger table update skipped due to older timestamp", 200

        common.my_finger_table_timestamp = res["timestamp"]
        common.my_finger_table = res["finger_table"]
        print(red("finger table updated"))
        return "finger table updated", 200

    finally:
        common.node_updating_finger_table = False


def node_start_k_replication():
    """
    start k replication
    :return:
    """
    print(red(f"Starting a new k replication with k={common.k}, i will replicate all my hosted files"))

    print(red(f"my host file list is: {common.host_file_list}"))

    for file in common.host_file_list:
        if config.NDEBUG:
            print(yellow(f"replicating file {file}"))
        # host node is me
        node_info = {"uid": common.my_uid, "ip": common.my_ip, "port": common.my_port}
        threading.Thread(target=replicate_chain_start, args=(node_info, common.k, file)).start()

    print(red("k replication finished"))


def replicate_chain_start(node_info, k, filename):
    """
    start the replication chain
    :param node_info: {"uid": common.my_uid, "ip": common.my_ip, "port": common.my_port}
    :param k: k replication
    :param filename:
    :return:
    """
    if k == 0:
        return

    if config.NDEBUG:
        print(yellow(f"[replicate_chain_start] {filename} to {node_info} with k={k}"))

    next_node = common.nids[1]
    print(red(f"starting replicate chain for file {filename} to my neighbor {next_node} with k={k}"))
    response = requests.post(
        config.ADDR + next_node['ip'] + ":" + next_node['port'] + endpoints.node_please_replica,
        data={"host_node": json.dumps(node_info), "remaining_k": k,
              "filename": filename})

    if response.status_code == 200 and response.text == "success":
        print(red(f"chain replication for {filename} should start now"))
        return "success"
    else:
        print(red(f"something wrong when sending replica chain for {filename}"), response.text, response.status_code)
        return "error"


def get_server_from_cloud():
    """
    get the server
    :return:
    """

    # Make an HTTP GET request to the S3 object URL
    response = requests.get(config.aws_server_file_url)

    # Check if the request was successful (status code 200)
    if response.status_code == 200:
        # Get the content of the file
        file_content = response.text
        if file_content == "":
            print(red(f"server config is empty, no server is running"))
            print(red(f"[FATAL] no server is running"))
            return False
        current_server = json.loads(file_content)
        if config.BOOTSTRAP_IP != current_server["ip"] or config.BOOTSTRAP_PORT != current_server["port"]:
            print(red(f"new server detected!!!"))
            server_alive = ping_server(current_server["ip"], current_server["port"])
            if not server_alive:
                print(red(f"new server is not alive, exiting"))
                return False
            set_server(current_server)
            return True
        else:
            print(red(f"server is the same as before"))
            return True

    else:
        print(red(f"Failed to retrieve the file. Status code: {response.status_code}"))
        print(red(f"[FATAL] Exiting as reading server config failed"))
        return False

def set_server(new_server):
    """
    set the server
    :param new_server:
    :return:
    """
    config.BOOTSTRAP_IP = new_server["ip"]
    config.BOOTSTRAP_PORT = new_server["port"]
    print(red(f"setting new server to {new_server} successfully"))


# ----------------------Syllabus Function---------------------------------------
def hash(key):
    return hashlib.sha1(key.encode('utf-8')).hexdigest()


def insert_file_to_chord(data):
    """
    insert file to the chord
    :param data: {"who_uploads": {"uid": common.my_id, "ip": common.my_ip, "port": common.my_port},
                                 "file", "file_name"}
    :return:
    """

    hashedname = data["filename"]
    who_uploads = data["who_uploads"]

    closest_node = determine_correct_node(hashedname, common.my_finger_table, int(common.my_uid, 16))
    if closest_node['uid'] == common.my_uid:
        print("i am responsible for this file")
        # request the file from the node uploads the file
        response = requests.post(
            config.ADDR + who_uploads["ip"] + ":" + who_uploads["port"] + endpoints.request_upload_file_to_host,
            data={"filename": hashedname, "request_node": json.dumps({"uid": common.my_uid, "ip": common.my_ip,
                                                                      "port": common.my_port})})
        if response.status_code == 200 and response.text == "File sent to the node":
            print(red(f"i have send request to {who_uploads['ip']}:{who_uploads['port']} to host the file"))
    else:
        # Forward the file query to the responsible node to find the node in the chord that will host the file
        forward_file_host_query_to_node(hashedname, who_uploads, closest_node)


def forward_file_host_query_to_node(filename, who_uploads, closest_node):
    """
    Forward the file query to the responsible node to find the node in the chord that will host the file
    :param filename: hashed filename
    :param who_uploads: {"uid": common.my_id, "ip": common.my_ip, "port": common.my_port}
    :param closest_node: {"uid": common.my_id, "ip": common.my_ip, "port": common.my_port}
    :return:
    """
    # i am not responsible for this file, forward the request to my closet node to
    # determine the node that will host the file

    response = requests.post(
        config.ADDR + closest_node["ip"] + ":" + closest_node["port"] + endpoints.find_file_host_node,
        data={"filename": filename, "who_uploads": json.dumps(who_uploads)})
    if response.status_code == 200 and response.text == "I am finding the responsible node":
        print(red(f"i have send request to {closest_node['ip']}:{closest_node['port']} to find the "
                  f"node that will host the file"))


def determine_correct_node(hashed_key, finger_table, self_ID):
    """
    Determine the correct node to store the file based on the hashed key using the finger table.
    :param hashed_key: Hashed key of the file name.
    :param finger_table: Finger table of the current node.
    :param self_ID: ID of the current node.
    :return: node: {uid, ip, port}
    """
    hashed_key_int = int(hashed_key, 16)
    closest_preceding_finger = {'uid': common.my_uid, 'ip': common.my_ip, 'port': common.my_port}

    # Check if the hashed key falls within the current node's responsibility
    prev_node_id = int(common.nids[0]['uid'], 16)
    if is_responsible_for_key(hashed_key_int, prev_node_id, self_ID):
        if config.NDEBUG:
            print(yellow("[determine_correct_node] i am responsible for the file: " + hashed_key))
        return closest_preceding_finger

    next_node_id = int(common.nids[1]['uid'], 16)
    if is_responsible_for_key(hashed_key_int, self_ID, next_node_id):
        if config.NDEBUG:
            print(yellow("[determine_correct_node] my next neighbor am responsible for the file: " + hashed_key))
        return common.nids[1]

    # Iterate through the finger table to find the responsible node
    for entry in reversed(finger_table):
        node_id = int(entry['node']['uid'], 16)
        if hashed_key_int <= node_id:
            if config.NDEBUG:
                print(yellow("[determine_correct_node] responsible node found: " + (str(entry['node']))))
            return entry['node']

    # Fall back to the next neighbor if no suitable node is found in the finger table
    if config.NDEBUG:
        print(yellow("[determine_correct_node] responsible node exceed, send to immediate successor: " +
                     str(common.nids[1])))
    return common.nids[1]


def is_responsible_for_key(hashed_key_int, first_node_id, sec_node_id):
    """
    Check if the current node is responsible for the given key in a circular ID space.
    """
    if config.vNDEBUG:
        print(blue("[is_responsible_for_key] para: " + sec_node_id + " " + first_node_id + " " + hashed_key_int))
    if sec_node_id > first_node_id:
        return first_node_id < hashed_key_int <= sec_node_id
    return first_node_id < hashed_key_int or hashed_key_int <= sec_node_id


def is_in_range(key, self_ID, node_id):
    """
    Check if a key is in the range (self_ID, node_id) in a circular ID space.
    """
    if self_ID < node_id:
        return self_ID < key < node_id
    return self_ID < key or key < node_id


def send_upload_file_to_node(request_node, filepath, filename):
    while common.is_sending_file:
        print(red(["[send_upload_file_to_node] waiting for previous send_upload_file_to_done..."]))
        time.sleep(1)

    common.is_sending_file = True
    if config.NDEBUG:
        print(yellow(f"[send_upload_file_to_node] sending file {filename} to node: " + (str(request_node))))
    # get the node ip and port
    node_ip = request_node['ip']
    node_port = request_node['port']

    # send file to the node
    with open(filepath, 'rb') as f:
        files = {'file': f}
        response = requests.post(config.ADDR + node_ip + ":" + node_port + endpoints.file_from_upload_node, files=files,
                                 data={"filename": filename, "timestamp": time.time()})

        if response.status_code == 200 and response.text == "File saved":
            print(red("File sent to the node"))
            res = 'File sent to the node'
        else:
            print(red("File sending failed"))
            res = 'File sending failed'
    common.is_sending_file = False

    return res


def node_redistribute_host_file_to_new_neighbour(change_position):
    """
    Redistribute files to the new node based on the hash keys.
    :param change_position: "prev" or "next"
    :return:
    """
    if change_position == "prev":
        print(red("prev node changed, i dont have to redistribute"))
        return
    print(red("i need to redistribute my data to my new neighbours"), common.nids[1]['ip'], common.nids[1]['port'])
    # Files to transfer to the new node
    files_to_transfer = files_need_to_be_redistributed(common.nids[1])

    if config.NDEBUG:
        print(f"[node_redistribute_host_file_to_new_neighbour] files to transfer: {files_to_transfer}")

    files_did_transfer = []
    # Transfer files to the new node
    for filename in files_to_transfer:
        res = redistribute_host_file_to_node(common.nids[1], filename)
        if res == "File sent to the node":
            files_did_transfer.append(filename)
        else:
            print(red(f"[node_redistribute_host_file_to_new_neighbour] file {filename} not transferred"))

    print(red("[node_redistribute_host_file_to_new_neighbour] files redistributed"))
    print(yellow(f"[node_redistribute_host_file_to_new_neighbour] files_did_transfer are: {files_did_transfer}"))

    # Remove files that were transferred successfully
    for filename in files_did_transfer:
        common.host_file_list.remove(filename)
        os.remove(common.node_host_file_dir + filename + ".pdf")
        if config.NDEBUG:
            print(yellow(f"[node_redistribute_host_file_to_new_neighbour] file {filename} removed"))

    print(red("done redistributing after new node joined"))


def files_need_to_be_redistributed(new_node):
    """
    Redistribute files to the new node based on the hash keys.
    :param new_node: {uid, ip, port} of the new node
    """
    new_node_id = int(new_node['uid'], 16)

    # Files to transfer to the new node
    files_to_transfer = []

    # Identify files that should be transferred to the new node
    for filename in common.host_file_list:
        hashed_name_int = int(filename, 16)

        if is_responsible_for_key(hashed_name_int, int(common.my_uid, 16), new_node_id):
            files_to_transfer.append(filename)

    return files_to_transfer


def redistribute_host_file_to_node(request_node, filename):
    if config.NDEBUG:
        print(f"[redistribute_host_file_to_node] sending file {filename} to node: " + blue(str(request_node)))
    # get the node ip and port
    node_ip = request_node['ip']
    node_port = request_node['port']

    # get the file from the node
    filepath = common.node_host_file_dir + filename + ".pdf"
    with open(filepath, 'rb') as f:
        files = {'file': f}
        # send file to the node
        response = requests.post(config.ADDR + node_ip + ":" + node_port + endpoints.file_from_redistribute,
                                 files=files, data={"filename": filename})

        if response.status_code == 200 and response.text == "i have host the file":
            print(f"[redistribute_host_file_to_node] sending file {filename} to node ok: " + blue(str(request_node)))
            res = 'File sent to the node'
        else:
            print(f"[redistribute_host_file_to_node] sending file {filename} to node error: " + blue(str(request_node)))
            res = 'File sending failed'
            print(red("with response"), response.text, response.status_code)

    return res


def query_file_in_the_chord(request_node, filename):
    """
    Query a file in the chord.
    :param request_node: {uid, ip, port} of the node to query
    :param filename: filename to query, should be hashed
    :return: the node that has the file
    """
    if config.NDEBUG:
        print(yellow(f"[query_file_in_the_chord]{request_node} query file {filename} in the chord"))
    # get the node ip and port
    node_ip = request_node['ip']
    node_port = request_node['port']

    print(red(f"i got a request to find a file in the chord, {filename}, {node_ip}, {node_port}"))

    # first check if it is in my host file list
    if filename in common.host_file_list:
        # if the file is in my host file list, but not exist in my host file dir
        if not os.path.exists(common.node_host_file_dir + filename + ".pdf"):
            print(red(f"i should have file{filename}, but i dont have it in my host file dir"))
            # check if the file is in replica node
            if common.k == 0:
                print(red(f"replication is not enabled, so i dont have the file, removing.."))
                common.host_file_list.remove(filename)
                return "404"
            else:
                print(red(f"replication is enabled, so i check the next {common.k} replica node"))
                # check the next k replica node
                response = requests.get(config.ADDR + common.nids[1]["ip"] + ":" + common.nids[1]["port"] +
                                        endpoints.node_chain_query_replica,
                                        params={"filename": filename, "remaining_k": str(common.k),
                                                "origin_node_ip": common.my_ip, "origin_node_port": common.my_port})

                if response.status_code == 200:
                    res = response.json()
                    if res["status"] == "ok":
                        replica_node = res["replica_node"]
                        print(red(f"the file in replica node {replica_node['ip']}:{replica_node['port']}, "
                                  f"so i will start a new thread to request that file"))
                        # start a new thread to request the file from the replica node
                        t = threading.Thread(target=get_replica_file_from_node,
                                             args=(replica_node, filename))

                        # send query result to the request node
                        my_info = {'uid': common.my_uid, 'ip': common.my_ip, 'port': common.my_port}
                        send_query_result(request_node, my_info, filename)
                        return "success"
                    else:
                        print(red(f"no such file in replica node, so returning 404 and delete the file"))
                        common.host_file_list.remove(filename)
                        return "404"
                else:
                    print(red(f"chain query replica failed, return 404 and delete the file"))
                    common.host_file_list.remove(filename)
                    return "404"
        print(red("i have the file, now i tell the request node to get it from me"))
        my_info = {'uid': common.my_uid, 'ip': common.my_ip, 'port': common.my_port}
        send_query_result(request_node, my_info, filename)
        return "success"

    # otherwise, check the finger table to determine which node is responsible for the file
    node = determine_correct_node(hashed_key=filename,
                                  finger_table=common.my_finger_table, self_ID=int(common.my_uid, 16))

    if node['uid'] == common.my_uid:
        print(red("i am responsible for the file, but i dont have the file"))
        send_query_result(request_node, "File not found in chord", filename)
        return "404"

    # forward the request to the correct node
    response = requests.post(config.ADDR + node['ip'] + ":" + node['port'] + endpoints.node_chain_query_file,
                             data={"filename": filename, "request_node": json.dumps(request_node)})

    if response.status_code == 200 and response.text == "success":
        print(red("i am not reponsible for the file, but i send query to the node"), node['ip'], node['port'])
        return "success"
    else:
        print(red("something wrong when querying file"), response.text, response.status_code)
        return "404"


def get_replica_file_from_node(replica_node, filename):
    """
    Get the replica file from the replica node.
    :param replica_node:
    :param filename:
    :return:
    """
    # get the node ip and port
    node_ip = replica_node['ip']
    node_port = replica_node['port']

    # send the result to the request node
    response = requests.get(config.ADDR + node_ip + ":" + node_port + endpoints.node_get_replica_file,
                            params={"filename": filename})

    if response.status_code == 200:
        # save the file to the local
        with open(common.node_host_file_dir + filename + ".pdf", "wb") as f:
            f.write(response.content)
        print(red("i have got the replica file from the replica node"))
    else:
        print(red("something wrong when getting replica file"), response.text, response.status_code)


def send_query_result(request_node, res, filename):
    """
    Send the query result back to the request node.
    :param request_node:
    :param res:
    :param filename:
    :return:
    """
    print(red(f"i am responsible for file {filename}, send back to the request node with result {res}"))

    # get the node ip and port
    node_ip = request_node['ip']
    node_port = request_node['port']

    if res != "File not found in chord":
        res = json.dumps(res)
    # send the result to the request node
    response = requests.post(config.ADDR + node_ip + ":" + node_port + endpoints.node_query_result,
                             data={"res": res, "filename": filename})

    if response.status_code == 200 and response.text == "success":
        print(red("i have sent the query result to the request node"))
    else:
        print(red("something wrong when sending query result"), response.text, response.status_code)


def replicate_file(host_node, remaining_k, filename):
    """
    replicate the file from host_node
    :param filename:
    :param host_node:
    :param remaining_k:
    :return:
    """
    if config.NDEBUG:
        print(yellow(f"[replicate_file] i am replicate file {filename} from {host_node}, with {remaining_k} remaining"))

    # get the node ip and port
    node_ip = host_node['ip']
    node_port = host_node['port']

    # send request to the host node, it should return a file
    response = requests.get(config.ADDR + node_ip + ":" + str(node_port) + endpoints.user_get_file +
                            "?filename=" + filename)

    if response.status_code == 200:
        print(red("i have got the file from the host node"))

        timestamp = response.headers.get('X-Timestamp')
        # check if the new file if exists
        if filename in common.replica_file_list:
            if config.NDEBUG:
                print(yellow(f"[replicate_file]file {filename} already exists, "
                             f"with timestamp {common.replica_file_list[filename]['timestamp']}"))
            # check if the new file is newer
            if common.replica_file_list[filename]['timestamp'] > timestamp:
                print(red("the file is older, i will not save it"))
                return "success"

        # save the file to the local
        with open(common.node_replicate_file_dir + filename + ".pdf", "wb") as f:
            f.write(response.content)

        # add the file to the file list
        common.replica_file_list[filename] = {"is_last_replica": remaining_k == 1,
                                              "timestamp": timestamp,
                                              "origin_node": host_node}

        if remaining_k == 1:
            print(red("i am the last replica, i will not send the file to the next node"))
            return "success"

        # send the file to the next node
        if remaining_k > 1:
            next_node = common.nids[1]
            print(red(f"remaining {remaining_k - 1} replica, my next neighour "
                      f"{next_node['ip']}:{next_node['port']} should replicate the file {filename} "
                      f"from node {host_node['ip']}:{host_node['port']}"))

            response = requests.post(
                config.ADDR + next_node['ip'] + ":" + next_node['port'] + endpoints.node_please_replica,
                data={"host_node": json.dumps(host_node), "remaining_k": remaining_k - 1,
                      "filename": filename})

            if response.status_code == 200 and response.text == "success":
                print(red("replicate request sent to the next node successfully"))
                return "success"
            else:
                print(red("something wrong when sending replicate request to next node"), response.text,
                      response.status_code)
                return "error"
    else:
        if config.NDEBUG:
            print(yellow("something wrong when getting file"), response.text, response.status_code)
        print(red(f"failed to get the replicate file, the chain request has stopped, remaining {remaining_k} replicas"))
        return "error"

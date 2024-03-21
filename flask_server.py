#!/usr/bin/env python  
# -*- coding:utf-8 _*-

""" 

@Author: Haomin Cheng
@File Name: flask_server.py 
@Time: 2023/11/24
@Contact: haomin.cheng@outlook.com

"""
import argparse
import os
import re
import sys
import socket
import threading
import time

import boto3
import requests
from dotenv import load_dotenv
from flask import Flask, json, request, jsonify, send_file
from werkzeug.utils import secure_filename

import config
import supernode
from supernode import init_server, bootstrap_join_func, boot_leave_func, read_leader_config, get_node_list_from_s3, \
    update_local_node_list
from utils import common, endpoints
from utils.colorfy import *
from chord import hash, node_update_neighbours_func, node_replic_nodes_list, node_redistribute_data, \
    node_update_finger_table_func, insert_file_to_chord, send_upload_file_to_node, node_initial_join, \
    query_file_in_the_chord, init_node, replicate_file, node_start_k_replication, replicate_chain_start, set_server, \
    get_server_from_cloud

app = Flask(__name__)


@app.route('/', methods=['GET'])
def home():
    return json.dumps(
        {"ip": common.my_ip, "port": common.my_port, "id": common.my_uid,
         "supernode": common.is_bootstrap,
         "mids": common.mids,
         "nids": common.nids}
    )


@app.route(endpoints.ping_server, methods=['GET'])
def ping():
    """
    Return "pong" if the node is alive.
    """
    if not common.is_leader:
        print(red("i dont know i am leader, but i got ping, checking if am the new leader"))
        leader = read_leader_config()
        if leader is None:
            return 400
        if leader["uid"] == common.my_uid:
            print(red("i am recently elected as leader, updating my status"))
            common.is_leader = True
            common.current_leader = leader
            update_local_node_list()
        else:
            return 400
    return "pong"


# ----------------------------------------------
# supernode endpoints

@app.route(endpoints.boot_join, methods=['POST'])  # join(nodeID)
def boot_join():
    if common.is_bootstrap:
        new_node = request.form.to_dict()
        return bootstrap_join_func(new_node)
    else:
        print(red(f"This is not the bootstrap node and not allowed for {endpoints.boot_join}."))


@app.route(endpoints.boot_leave, methods=['POST'])  # leave(nodeID)
def boot_leave():
    if common.is_bootstrap:
        # check if the request sent with a node_info
        if request.form.get("node_info") is None:
            print(red(f"Node info is not provided for {endpoints.boot_leave}."))
            return "provide your info to dead", 400

        node_info = json.loads(request.form.get("node_info"))
        return boot_leave_func(node_info)
    else:
        print(red(f"This is not the bootstrap node and not allowed for {endpoints.boot_leave}."))


# ----------------------------------------------
# node endpoints

@app.route(endpoints.node_join_procedure, methods=['POST'])
def join_procedure():
    print(red("Chord join procedure Start!"))
    if config.NDEBUG:
        print("chord_join_procedure is staring...")
    res = request.get_json()

    prev = res["prev"]
    next = res["next"]
    node_number = res["length"]
    node_list = []

    common.nids.append({"uid": prev["uid"], "ip": prev["ip"], "port": prev["port"]})
    common.nids.append({"uid": next["uid"], "ip": next["ip"], "port": next["port"]})
    if config.NDEBUG:
        print(yellow("Previous Node:"))
        print(common.nids[0])
        print(yellow("Next Node:"))
        print(common.nids[1])

    if common.k <= node_number:
        if config.NDEBUG:
            print("Node list creation is starting...")
        data = {"node_list": node_list, "k": common.k, "new_id": common.my_uid}
        node_list_json = node_replic_nodes_list(data)
        node_list = node_list_json["node_list"]
        if config.NDEBUG:
            print("i am the new node, i should get replica from these nodes: ", node_list)

        data = {"node_list": node_list, "new_id": common.my_uid}
        node_redistribute_data(data)

    if config.NDEBUG:
        print("Join of node completed - Overlay to check")

    return "Join Completed"


@app.route(endpoints.replic_nodes_list, methods=['POST'])
def get_response_chain():
    res = request.get_json()
    data = res["data"]
    return node_replic_nodes_list(data)


@app.route(endpoints.node_update_replicate, methods=['POST'])
def update_replicate():
    """
    Update the replicate nodes of the node.
    """
    if config.NDEBUG:
        print("Updating replicate nodes...")
    res = request.get_json()
    node_list = res["node_list"]
    common.mids = node_list
    if config.NDEBUG:
        print("Replicate nodes updated")
    return "Replicate nodes updated"


@app.route(endpoints.node_update_neighbours, methods=['POST'])  # update(nodeID)
def chord_update_neighbours():
    """
    Update the neighbours of the node.
    :return:
    """
    while common.node_updating_neighbor:
        print(red("i am updating neighbours, wait..."))
        time.sleep(0.3)
    common.node_updating_neighbor = True
    new_neighbours = request.get_json()
    response = node_update_neighbours_func(new_neighbours)
    common.node_updating_neighbor = False
    return response


@app.route(endpoints.node_update_finger_table, methods=['POST'])
def update_finger_table():
    """
    Update the finger table of the node.
    """
    res = request.get_json()
    if 'finger_table' not in res or 'timestamp' not in res:
        return "Invalid request format: 'timestamp' or'finger_table' key missing", 400

    if config.vNDEBUG:
        print(blue("Updating finger table..."))
        print(str(res))

    return node_update_finger_table_func(res)


@app.route(endpoints.request_upload_file_to_host, methods=['POST'])
def request_upload_file():
    """
    Request a file upload to the node.
    """
    if 'filename' not in request.form:
        print(red(f"[endpoints.request_upload_file_to_host] the params are: {str(request.form)}, return 400"))
        return 'Please provide a filename', 400

    if 'request_node' not in request.form:
        print(red(f"[endpoints.request_upload_file_to_host] the params are: {str(request.form)}, return 400"))
        return 'Please provide a request node', 400
    # filename should be hashed already
    filename = request.form.get('filename', '')
    filename = secure_filename(filename)

    # check file exist in my upload folder
    filepath = common.node_upload_file_dir + filename + '.pdf'
    if not os.path.exists(filepath):
        return 'File not found', 404

    request_node = json.loads(request.form.get('request_node', ''))
    print(red(f"The node {request_node['ip']}:{request_node['port']} in chord host the file {filename} "
              f"in my upload folder"))

    if config.NDEBUG:
        print(yellow(f"[request_upload_file] Requested file: {filename} from {str(request_node)}"))

    # send file to the node
    response = send_upload_file_to_node(request_node, filepath, filename)

    if config.NDEBUG:
        print(yellow(f"[request_upload_file] Response from node: {str(response)}"))

    # the file is sent to the chord, i can continue to upload other files
    common.already_upload_to_chord[filename] = "ok"
    if response == 'File sent to the node':
        return 'File sent to the node', 200
    else:
        return 'File not sent to the node', 400


@app.route(endpoints.file_from_upload_node, methods=['POST'])
def file_from_upload_node():
    """
    a file send from upload node, i am responsible for it.
    """
    if 'file' not in request.files or 'filename' not in request.form or 'timestamp' not in request.form:
        return 'Please provide a file and a filename and a timestamp', 400

    filename = request.form.get('filename', '')
    filename = secure_filename(filename)

    timestamp = request.form.get('timestamp', time.time())

    if config.NDEBUG:
        print(yellow(f"[file_from_upload_node] Requested file: {filename}, timestamp: {timestamp}"))

    # save the file in my host folder
    filepath = common.node_host_file_dir + filename + '.pdf'
    file = request.files['file']
    file.save(filepath)

    # update host file list
    if filename not in common.host_file_list:
        common.host_file_list.append(filename)

    print(red(f"upload node send me the {filename} to host, i save it in my host folder"))

    # replicate
    if common.k == 0:
        print(red(f"the replication factor is 0, i don't replicate the file{filename}"))
    else:
        print(red(f"the replication factor is {common.k}, i will replicate the file{filename}"))
        node_info = {"uid": common.my_uid, "ip": common.my_ip, "port": common.my_port}
        response = replicate_chain_start(node_info=node_info, filename=filename, k=common.k)
        print(red(f"the start chain replication result is {response}"))

    return 'File saved', 200


@app.route(endpoints.find_file_host_node, methods=['POST'])
def find_file_host_node():
    """
    a node is not responsible for a file, and i was the closest node he found, so i will find
    the node who is responsible
    """

    if 'filename' not in request.form or 'who_uploads' not in request.form:
        return 'Please provide a filename', 400

    filename = request.form.get('filename', '')
    filename = secure_filename(filename)

    who_uploads = json.loads(request.form.get('who_uploads', ''))

    if config.NDEBUG:
        print(yellow(f"[find_file_host_node] Requested file: {filename}"))

    # find the node who is responsible for the file in a new thread
    t = threading.Thread(target=insert_file_to_chord, args=({"filename": filename, "who_uploads": who_uploads},))
    t.start()

    return "I am finding the responsible node", 200


@app.route(endpoints.file_from_redistribute, methods=['POST'])
def file_from_redistribute():
    """
    as a new node joined the chord, a file send from my neighbor node claiming i am responsible for it.
    """
    if 'file' not in request.files or 'filename' not in request.form:
        return 'Please provide a file and a filename', 400

    filename = request.form.get('filename', '')
    filename = secure_filename(filename)
    print(red(f"i am responsible for a file from my neighbor node {filename}"))

    # save the file in my host folder
    filepath = common.node_host_file_dir + filename + '.pdf'
    file = request.files['file']
    file.save(filepath)

    # update host file list
    if filename not in common.host_file_list:
        common.host_file_list.append(filename)

    return 'i have host the file', 200


@app.route(endpoints.node_chain_query_file, methods=['POST'])
def chain_query_file():
    # should be a form has filename, and  node info{uid, ip, port}
    if 'filename' not in request.form or 'request_node' not in request.form:
        if config.vNDEBUG:
            print(blue(f"[node_chain_query_file] Requested file: {request.form.to_dict()}"))
        return 'Please provide a filename or request_node', 400

    filename = request.form.get('filename', '')
    filename = secure_filename(filename)

    request_node = json.loads(request.form.get('request_node', ''))

    print(red(f"chain query file start, filename is {filename}, request_node is {request_node}"))

    threading.Thread(target=query_file_in_the_chord, args=(request_node, filename,)).start()

    return "success", 200


@app.route(endpoints.node_chain_query_replica, methods=['GET'])
def chain_query_replica():
    # check param contains filename and remaining_k, and node info{uid, ip, port}
    if 'filename' not in request.args or 'remaining_k' not in request.args or 'origin_node_ip' not in request.args or 'origin_node_port' not in request.args:
        return 'Please provide a filename or remaining_k or origin_node_ip or origin_node_port', 400

    filename = request.args.get('filename', '')
    filename = secure_filename(filename)

    remaining_k = int(request.args.get('remaining_k', ''))
    origin_node_ip = request.args.get('origin_node_ip', '')
    origin_node_port = request.args.get('origin_node_port', '')

    print(red(f"i got a request to check if i have the replica of {filename}"))

    # check if i have the replica
    if filename in common.replica_file_list:
        if os.path.exists(common.node_replicate_file_dir + filename + '.pdf'):
            print(red(f"i have the replica of {filename}"))
            return json.dumps(
                {"status": "ok", "replica_node": {"uid": common.my_uid, "ip": common.my_ip, "port": common.my_port}})

    if remaining_k == 1:
        print(red(f"the remaining_k is 1, i am the last one should replicate it, but i don't have, so file lost"))
        return json.dumps({"status": "no"})

    # if i don't have the replica, i will find the node who has the replica
    print(red(f"i don't have the replica of {filename}, i will chain query the next {remaining_k} nodes"))
    response = requests.get(config.ADDR + common.nids[1]["ip"] + ":" + common.nids[1]["port"] +
                            endpoints.node_chain_query_replica +
                            "?filename=" + filename + "&remaining_k=" + str(int(remaining_k) - 1)
                            + "&origin_node_ip=" + origin_node_ip + "&origin_node_port=" + origin_node_port)

    if response.status_code == 200:
        print(red(f"i got the response from the chain {response.json()}"))
        return response.json()

    return json.dumps({"status": "no"})


@app.route(endpoints.node_query_result, methods=['POST'])
def node_query_result():
    """
    the node who hosted the file will send the file url to the node who query the file
    """
    if 'filename' not in request.form or 'res' not in request.form:
        return 'Please provide a filename or res', 400

    filename = request.form.get('filename', '')
    filename = secure_filename(filename)

    res = request.form.get('res', '')
    if res != 'File not found in chord':
        hosted_node = json.loads(res)
    else:
        hosted_node = res

    print(red(f"i am going to store the hosted node info {hosted_node}"))

    # store the hosted node info
    common.query_file_result[filename] = hosted_node

    return "success", 200


@app.route(endpoints.node_legacy_transfer, methods=['POST'])
def node_legacy_transfer():
    """
    the legacy node will send the file to the node who is responsible for it
    :return:
    """
    # check the form has filename, and file
    if 'filename' not in request.form or 'file' not in request.files or 'node_info' not in request.form:
        return 'Please provide a filename and file and node_info', 400

    filename = request.form.get('filename', '')
    filename = secure_filename(filename)

    file = request.files['file']
    filepath = common.node_host_file_dir + filename + '.pdf'
    file.save(filepath)

    # update host file list
    if filename not in common.host_file_list:
        common.host_file_list.append(filename)

    print(red(f"i am got a legacy file {filename} from node {request.form.get('node_info', '')}"))

    return "store legacy success", 200


@app.route(endpoints.node_update_k, methods=['POST'])
def node_update_k():
    """
    this could only be called by the server to update the k value of node
    :return:
    """

    # check if the form has k
    if 'k' not in request.form:
        return 'Please provide a k', 400

    # check if the request is sent by the server
    if request.remote_addr != config.BOOTSTRAP_IP:
        print(red(f"the request is not sent by the server"))
        # return 'You are not the server', 403

    k = request.form.get('k', '')
    common.k = int(k)

    print(red(f"got instruction from server to update k to {k}"))

    if int(k) == 0:
        print(red(f"the k is set to zero, i am not going to replicate any file from now on"))
    else:
        node_start_k_replication()

    return "update k success", 200


@app.route(endpoints.node_please_replica, methods=['POST'])
def node_please_replica_handler():
    # check if the form has filename, node_info, remaining_k
    if 'filename' not in request.form or 'host_node' not in request.form or 'remaining_k' not in request.form:
        return 'Please provide a filename and host_node and remaining_k', 400

    filename = request.form.get('filename', '')
    filename = secure_filename(filename)

    node_info = json.loads(request.form.get('host_node', ''))
    remaining_k = int(request.form.get('remaining_k', ''))

    print(red(f"got a request to replicate a file {filename} from node {node_info}, remaining_k is {remaining_k}"))

    # check if the file exist in the node
    response = requests.get(f"{config.ADDR}{node_info['ip']}:{node_info['port']}{endpoints.node_check_file_exist}"
                            f"?filename={filename}")

    if response.status_code == 200 and response.text == 'yes':
        # start replication
        print(red(f"the node has the file, i am going to replicate a file {filename} from node {node_info}"))
        threading.Thread(target=replicate_file, args=(node_info, remaining_k, filename,)).start()
        return "success", 200
    else:
        print(red(f"file {filename} not exist in the node{node_info}, chain request replicate stop, "
                  f"remaining_k is {remaining_k}"))

        return "file not exist", 400


@app.route(endpoints.node_check_file_exist, methods=['GET'])
def node_check_file_exist_handler():
    """
    check if the file exist in the node
    """
    if 'filename' not in request.args:
        return 'Please provide a filename', 400

    filename = request.args.get('filename', '')
    filename = secure_filename(filename)

    if config.vNDEBUG:
        print(yellow(f"i am going to check if i have the file {filename}"))

    if filename in common.host_file_list:
        return "yes", 200
    else:
        return "no", 200


@app.route(endpoints.node_get_replica_file, methods=['GET'])
def node_get_replica_file_handler():
    """
    get the file from the node
    """
    if 'filename' not in request.args:
        return 'Please provide a filename', 400

    filename = request.args.get('filename', '')
    filename = secure_filename(filename)

    if config.vNDEBUG:
        print(yellow(f"i am going to get the file {filename}"))

    if filename in common.replica_file_list:
        filepath = common.node_replicate_file_dir + filename + '.pdf'
        if os.path.exists(filepath):
            return send_file(filepath, as_attachment=True)
        else:
            print(red(f"the file {filename} is not exist in the node, removing.."))
            common.replica_file_list.remove(filename)
            return "not found", 404
    else:
        print(red(f"the file {filename} is not in replica list"))
        return "not found", 404


# ------------------ user endpoints ------------------

@app.route(endpoints.user_query_file, methods=['GET'])
def query_file():
    """
    Query a file from the node.
    """
    if 'filename' not in request.args:
        return 'Please provide a filename', 400

    filename = request.args.get('filename', '')
    filename = secure_filename(filename)

    # check if the filename legal
    if not is_valid_course_id(filename):
        return 'input should be course id, department code + digits, like CSEN317', 400

    print(red(f"user query file, with name {filename}"))

    hashed_filename = hash(filename)

    # run the query in a new thread
    t = threading.Thread(target=query_file_in_the_chord_thread, args=(hashed_filename,))
    t.start()

    # Define a timeout (e.g., 30 seconds)
    timeout = 15  # seconds
    start_time = time.time()

    # if a node hosted the file got my request, it will send his info{uid, ip, port} to me, and i will
    # store it in common.query_file_result
    while True:
        if hashed_filename in common.query_file_result and common.query_file_result[hashed_filename] is not None:
            hosted_node = common.query_file_result[hashed_filename]

            if hosted_node == 'File not found in chord':
                # delete the query file result
                del common.query_file_result[hashed_filename]
                print(red("file not found in chord"))
                return 'File not found in chord', 200

            print(red(f"the file is hosted by {str(hosted_node)}, i will return the url to the user"))

            # Return the file URL
            return config.ADDR + hosted_node['ip'] + ':' + str(hosted_node['port']) + \
                   endpoints.user_get_file + '?filename=' + hashed_filename, 200

        # Check if the timeout has been reached
        if time.time() - start_time > timeout:
            print(red("Query timed out"))
            return 'Query timed out', 408  # 408 Request Timeout

        print(red("Asking the chord to give me file, waiting for query result"))
        time.sleep(1)


def query_file_in_the_chord_thread(filename):
    query_file_in_the_chord({"uid": common.my_uid, "ip": common.my_ip, "port": common.my_port}, filename)


@app.route(endpoints.user_add_new_file, methods=['POST'])
def upload_file():
    if 'file' not in request.files or 'course_name' not in request.form:
        return 'Please provide a file and a course_name', 400

    file = request.files['file']
    filename = request.form.get('course_name', '')

    # Check if the file format is correct (PDF)
    if not allowed_file(file.filename):
        return jsonify(message='File type not allowed, only PDFs are accepted'), 400

    filename = secure_filename(filename)

    # Check if the filename matches the required format (4 letters and numbers)
    if not is_valid_course_id(filename):
        return jsonify(message='inputed course_name error, should sth like CSEN317'), 400

    common.is_data_uploading = True

    hashed_filename = hash(filename)
    filepath = common.node_upload_file_dir + hashed_filename + '.pdf'
    file.save(filepath)

    if config.NDEBUG:
        print(yellow(
            f"[node_add_new_file] Upload File is saved in my upload folder: {filename}, hashed {hashed_filename}"))
        print(yellow("[node_add_new_file] starting storing file in chord..."))

    t = threading.Thread(target=upload_file_thread, args=(hashed_filename,))
    t.start()

    while hashed_filename not in common.already_upload_to_chord:
        print(yellow("waiting for a node in the chord to request my uploaded file to host..."))
        time.sleep(0.3)

    del common.already_upload_to_chord[hashed_filename]

    return jsonify(message='File successfully uploaded'), 200


def upload_file_thread(filename):
    return insert_file_to_chord({"who_uploads": {"uid": common.my_uid, "ip": common.my_ip, "port": common.my_port},
                                 "filename": filename})


@app.route(endpoints.user_get_file, methods=['GET'])
def get_file():
    """
    Get a file from the node.
    """
    if 'filename' not in request.args:
        return 'Please provide a filename', 400

    print(red(f"user get file {request.args.get('filename', '')}"))

    filename = request.args.get('filename', '')
    filename = secure_filename(filename)

    # check file exist in my host folder
    filepath = common.node_host_file_dir + filename + '.pdf'

    # if there is a optional param type
    if 'type' in request.args:
        print(red(f"user get file, with the type is {request.args.get('type', '')}"))
        if request.args.get('type', '') == 'replica':
            # check file exist in my host folder
            filepath = common.node_replicate_file_dir + filename + '.pdf'

    if not os.path.exists(filepath):
        return 'File not found', 404

    response = send_file(filepath, as_attachment=True)
    timestamp = time.time()
    response.headers['X-Timestamp'] = timestamp

    print(red(f"file {filename} is sent to the user with timestamp {timestamp}"))

    return response


def server_start():
    """
    Entry point of the flask server.
    :return:
    """
    common.server_starting = True

    args = parse_args()

    # Validate and use the values as needed
    if args.port is None:
        wrong_input_format()
        return

    common.my_port = args.port

    common.my_ip = get_my_ip()
    common.my_uid = hash(common.my_ip + ":" + common.my_port)
    common.node_file_dir = config.FILE_DIR + common.my_uid + "/"
    common.node_host_file_dir = common.node_file_dir + "host_files/"
    common.node_replicate_file_dir = common.node_file_dir + "replicate_files/"
    common.node_upload_file_dir = common.node_file_dir + "upload_files/"

    if args.bootstrap:
        if config.BDEBUG:
            print(blue("reading the env file first"))

        if not read_env_file():
            print(red(".env file is not exist or not valid"))
            print(red("{FATAL} exiting the program"))
            return

        print("I am the Bootstrap Node with ip: " + yellow(
            common.my_ip) + " about to run a Flask server on port " + yellow(common.my_port))
        print("and my unique id is: " + green(common.my_uid))
        print("and my file directory is: " + green(common.node_file_dir))
        common.is_bootstrap = True
        common.k = int(args.input_k)
        print("and the system's replication factor is: " + green(common.k))
        init_server()

    else:
        common.is_bootstrap = False
        print("I am a normal Node with ip: " + yellow(common.my_ip) + " about to run a Flask server on port " + yellow(
            common.my_port))
        print("and my unique id is: " + green(common.my_uid))
        print("and my file directory is: " + green(common.node_file_dir))
        # create the directory for the node
        create_node_dir()
        print(red("I have created the file directory for me"))

        print(red("I am about to join the chord, first i need to know who is the server"))
        server_set = get_server_from_cloud()
        if not server_set:
            print(red(f"[FATAL] no server is set in the cloud, exiting the program"))
            exit(1)
        x = threading.Thread(target=node_initial_join, args=())
        x.start()
        init_node()

    app.run(host='0.0.0.0', port=int(common.my_port), debug=True, use_reloader=False)


def create_node_dir():
    """
    Create the directory for the node
    :return:
    """
    if not os.path.exists(common.node_file_dir):
        os.makedirs(common.node_file_dir)
        if config.NDEBUG:
            print(yellow(f"[create_node_dir] Directory {common.node_file_dir} created"))
    if not os.path.exists(common.node_host_file_dir):
        os.makedirs(common.node_host_file_dir)
        if config.NDEBUG:
            print(yellow(f"[create_node_dir] Directory {common.node_host_file_dir} created"))
    if not os.path.exists(common.node_replicate_file_dir):
        os.makedirs(common.node_replicate_file_dir)
        if config.NDEBUG:
            print(yellow(f"[create_node_dir] Directory {common.node_replicate_file_dir} created"))
    if not os.path.exists(common.node_upload_file_dir):
        os.makedirs(common.node_upload_file_dir)
        if config.NDEBUG:
            print(yellow(f"[create_node_dir] Directory {common.node_upload_file_dir} created"))


def wrong_input_format():
    print(red("Argument passing error!"))
    print(underline("Usage:"))
    print(cyan(
        "-p port_to_open (required\n -b [ture, false] for setting server \n -k replication_factor (provide for server only)"))
    exit(0)


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ['pdf']


def get_my_ip():
    # if config.LOCAL_SERVER:
    #     return '127.0.0.1'

    # response = requests.get('https://api.ipify.org?format=json')
    #
    # if response.status_code != 200:
    #     print(red(f"[get_my_ip] response.status_code = {response.status_code}"))
    #     return '127.0.0.1'
    #
    # if config.NDEBUG:
    #     print(yellow(f"[get_my_ip] response.json()['ip'] = {response.json()['ip']}"))
    #
    # return response.json()['ip']

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(0)
    try:
        s.connect(('8.8.8.8', 1))
        ip = s.getsockname()[0]
    except Exception:
        ip = '127.0.0.1'
    finally:
        s.close()

    print(yellow(f"[get_my_ip] ip = {ip}"))
    return ip


def is_valid_course_id(course_id):
    """
    Check if the course id is valid
    :param course_id: 4letters+digits(CSEN317)
    :return:
    """
    return re.match(r'^[A-Za-z]{4}\d+$', course_id)


def read_env_file():
    load_dotenv()

    aws_access_key = os.getenv('AWS_ACCESS_KEY')
    aws_secret_key = os.getenv('AWS_SECRET_KEY')
    aws_region = os.getenv('REGION_NAME')

    if config.BDEBUG:
        print(blue(
            f"[read_env_file] aws_access_key = {aws_access_key}, aws_secret_key = {aws_secret_key}, aws_region = {aws_region}"))

    # if any of the above is None, then we are not using S3
    if aws_access_key is None or aws_secret_key is None or aws_region is None:
        return False

    config.aws_access_key = os.getenv('AWS_ACCESS_KEY')
    config.aws_secret_key = os.getenv('AWS_SECRET_KEY')
    config.aws_region = os.getenv('REGION_NAME')

    supernode.s3_client = boto3.client('s3', aws_access_key_id=config.aws_access_key, aws_secret_access_key=config.aws_secret_key,
                         region_name=config.aws_region)

    return True


def parse_args():
    parser = argparse.ArgumentParser(description="Script description")
    parser.add_argument('-b', '--bootstrap', help='bootstrap node')
    parser.add_argument('-k', '--input_k', help='replication node count')
    parser.add_argument('-p', '--port', '-P', required=True, help='Port number')
    return parser.parse_args()


if __name__ == '__main__':
    server_start()

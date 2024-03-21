#!/usr/bin/env python  
# -*- coding:utf-8 _*-

""" 

@Author: Haomin Cheng
@File Name: common.py
@Time: 2023/11/24
@Contact: haomin.cheng@outlook.com
@Description: This file is used to store the global variables that are used in the whole project.

"""

# --------------------------------------------------------
# The system global variable

global k  # number of replicas
k = 0

global node_k # the k value should be used in the node
node_k = 0

# --------------------------------------------------------
# The node's global variable
global is_bootstrap  # true if node is bootstrap
global is_leader  # true if the bootstrap node is leader
is_leader = False
global my_uid  # my unique identifier, hash of my_ip:my_port
global my_port
global my_ip

# flag that becomes (and stays) false when a node departs (used to prevent unwanted operations from a departed node)
global still_on_chord
still_on_chord = True

# dict of file query result, key is file name, value is node info{uid, ip, port}, if not found, value is '404 not found'
global query_file_result
query_file_result = {}

# --------------------------------------------------------
# The DHT global variable
mids = []  # list of dicts, descending uids
global nids
nids = []  # list of dicts, first element is the previous node and second element is the next node

global my_finger_table
my_finger_table = []  # list of dicts, each dict is a finger table

global my_finger_table_timestamp
my_finger_table_timestamp = 0

# Supernode variables
global finger_tables
finger_tables = {}  # dict of dicts, key is node uid, each dict is a finger table

global current_leader

# --------------------------------------------------------
# The File global variable
global replica_file_list
replica_file_list = {}
global host_file_list
host_file_list = []

global node_file_dir
global node_upload_file_dir
global node_host_file_dir
global node_replicate_file_dir

# --------------------------------------------------------
# variables for async function
global server_starting
server_starting = False

global server_node_joining
server_node_joining = False

global server_updating_finger_table
server_updating_finger_table = False

global node_updating_finger_table
node_updating_finger_table = False

global node_updating_neighbor
node_updating_neighbor = False

global is_data_uploading
is_data_uploading = False

global is_data_replicating
is_data_replicating = False

global is_sending_file
is_sending_file = False

global already_upload_to_chord  # true if one node request my uploaded file to host
already_upload_to_chord = {}

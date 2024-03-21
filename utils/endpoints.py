#!/usr/bin/env python  
# -*- coding:utf-8 _*-

""" 

@Author: Haomin Cheng
@File Name: endpoints.py
@Time: 2023/11/24
@Contact: haomin.cheng@outlook.com

"""

global node_info # GET: returns node info
node_info = '/node/info'

global boot_join  # POST: adds node to the Chord {node uid, ip, port}
boot_join = '/boot/join'

global boot_leave  # POST: removes node from the Chord {node uid}
boot_leave = '/boot/leave'

global b_list  # GET: returns list of nodes in the Chord
b_list = '/boot/list'

global ping_server # GET: check if the node alive, returns "pong"
ping_server = '/ping'

# ----------------------------------------------
# node endpoints

global node_join_procedure # POST: adds node to the Chord {node uid, ip, port}
node_join_procedure = '/node/procedure'

global node_update_replicate # POST: updates the replicate nodes of the node {node uid, ip, port}
node_update_replicate = '/node/update_replicate'

global node_update_neighbours
node_update_neighbours = '/node/update_neighbours'

global replic_nodes_list # POST: returns list of replicate nodes of the node
replic_nodes_list = '/node/replic_nodes_list'

global node_update_finger_table # POST: updates the finger table of the node {node uid, ip, port}
node_update_finger_table = '/node/update_finger_table'

global request_upload_file_to_host # POST: request to upload a file to the node {file name, file content}
request_upload_file_to_host = '/node/request_upload_file'

global file_from_upload_node # POST: adds a new file to the node {file name, file content}
file_from_upload_node = '/node/file_from_upload'

global find_file_host_node # POST: find the host node of the file {file name}
find_file_host_node = '/node/find_file_host_node'

global file_from_redistribute # POST: adds a new file to the node {file name, file content}
file_from_redistribute = '/node/file_from_redistribute'

global node_chain_query_file # POST: query a file in the chord {file name, request node info}
node_chain_query_file = '/node/query_file_in_the_chord'

global node_query_result # POST: the result of querying file in the chord {file name, request node info}
node_query_result = '/node/query_result'

global node_legacy_transfer # POST: a node leaves, it transfers its files to its successor {filename name, file content}
node_legacy_transfer = '/node/legacy_transfer'

global node_update_k # POST: when the nodes number exceeds the replication factor, node start replicate
node_update_k = '/node/update_k'

global node_please_replica
node_please_replica = '/node/please_replica'

global node_check_file_exist # GET: check if the file exist in the node {file name}
node_check_file_exist = '/node/check_file_exist'

global node_chain_query_replica # GET: query a file in the chord p:{filename, remaining_k}
node_chain_query_replica = '/node/query_replica_in_the_chord'

global node_get_replica_file # GET: query a replica file in the chord p:{filename}
node_get_replica_file = '/node/get_replica_file'

# ----------------------------------------------
# user endpoints

global user_add_new_file # POST: adds a new file to the node {file name, file content}
user_add_new_file = '/user/new_file'

global user_get_file # GET: returns the file content {file name}
user_get_file = '/user/get_file'

global user_query_file # GET: query a file in the chord {file name}
user_query_file = '/user/query_file'
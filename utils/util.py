#!/usr/bin/env python  
# -*- coding:utf-8 _*-

""" 

@Author: Haomin Cheng
@File Name: util.py 
@Time: 2023/11/24
@Contact: haomin.cheng@outlook.com

"""

import hashlib

import requests

import config


def hash_str(s):
    return hashlib.sha256(s.encode('utf-8')).hexdigest()


def get_identifier(uid, ip, port):
    return uid + '_' + ip + '_' + str(port)


def get_info_from_identifier(file):
    """
    This function returns the node_id, ip and port from the alive file name.
    :param file:
    :return:  A dictionary with the node_id, ip and port
    """
    return {
        'uid': file.split('_')[0],
        'ip': file.split('_')[1],
        'port': file.split('_')[2]
    }


def ping_server(server_ip=config.BOOTSTRAP_IP, server_port=config.BOOTSTRAP_PORT):
    """
    This function pings a server to check if it is alive.
    :param server_ip: The server ip
    :param server_port: The server port
    :return: True if the server is alive, False otherwise
    """
    response = requests.get(f"{config.ADDR}{server_ip}:{server_port}/ping")
    if response.status_code == 200 and response.text == 'pong':
        return True
    else:
        return False

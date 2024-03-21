#!/usr/bin/env python  
# -*- coding:utf-8 _*-

""" 

@Author: Haomin Cheng
@File Name: config.py 
@Time: 2023/11/24
@Contact: haomin.cheng@outlook.com

"""
import os

cwd = os.getcwd()  # Get the current working directory (cwd)

LOCAL_BOOTSTRAP_IP = "127.0.0.1"  #TODO fix this
EC2_BOOTSTRAP_IP = "172.31.240.178"
BOOTSTRAP_IP = EC2_BOOTSTRAP_IP
BASE_DIR = cwd + '/'
BOOTSTRAP_PORT = "10500"
ADDR = 'http://'
BDEBUG = True  # debug information for bootstrap operations
NDEBUG = True  # debug information for node operations
TDEBUG = False  # debug information fot test operations
vBDEBUG = False  # extra verbose debug information for bootstrap operations
vNDEBUG = False  # extra verbose debug information for node operations

aws_access_key = ""
aws_secret_key = ""
aws_region = ""

aws_server_file_url = "https://file-share-coen317.s3.us-east-2.amazonaws.com/leader_config.json"

LOCAL_SERVER = False # if True, the server will be run locally, else it will be run on the AWS

FILE_DIR = BASE_DIR + 'files/'
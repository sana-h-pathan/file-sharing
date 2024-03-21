#!/usr/bin/env python  
# -*- coding:utf-8 _*-

""" 

@Author: Haomin Cheng
@File Name: colorfy.py 
@Time: 2023/11/24
@Contact: haomin.cheng@outlook.com

"""


def red(string):
    return '\033[1;91m {}\033[00m'.format(string)


def RED(string):
    return '\033[1;91m {}\033[00m'.format(string)


def yellow(string):
    return '\033[93m {}\033[00m'.format(string)


def YELLOW(string):
    return '\033[1;93m {}\033[00m'.format(string)


def blue(string):
    return '\033[94m {}\033[00m'.format(string)


def BLUE(string):
    return '\033[1;94m {}\033[00m'.format(string)


def green(string):
    return '\033[92m {}\033[00m'.format(string)


def GREEN(string):
    return '\033[1;92m {}\033[00m'.format(string)


def cyan(string):
    return '\033[96m {}\033[00m'.format(string)


def underline(string):
    return '\033[4m{}\033[00m'.format(string)


def header(string):
    return '\033[95m{}\033[00m'.format(string)

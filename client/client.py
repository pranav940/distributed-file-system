#!/usr/bin/env python3

# author = Pranav Gummaraj Srinivas prgu6170@colorado.edu
# date = 09/19/2018
# name = assignment 5 ques extra credit
# purpose = server-client socket programming
# version = 3.6.5

import socket
import argparse
import logging
import json
import sys
from time import sleep
from Crypto.Cipher import AES
import configparser
import os
import math
import hashlib


def do_encrypt(message):
    obj = AES.new('sajfq874ohsdfp9qsajfq874ohsdfp9q', AES.MODE_CBC, '98qwy4thkjhwgpf9')
    cipher_text = obj.encrypt(message)
    return cipher_text


def do_decrypt(ciphertext):
    obj = AES.new('sajfq874ohsdfp9qsajfq874ohsdfp9q', AES.MODE_CBC, '98qwy4thkjhwgpf9')
    message = obj.decrypt(ciphertext)
    return message


def md5(fname):
    hash_md5 = hashlib.md5()
    with open(fname, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    md5_value = hash_md5.hexdigest()
    req_value = int(md5_value, 16) % 4
    return  req_value


def validate_ip(address):
    valid = True
    arr = address.split(".")
    if len(arr) != 4:
        valid = False
    else:
        for element in arr:
            if element != "":
                if int(element) < 0 or int(element) > 255:
                    valid = False
            else:
                valid = False
    return valid


def split_equal(mfile):
    content = mfile.read()
    return (content[i: i + math.ceil(len(content) / 4)] for i in range(0, len(content), math.ceil(len(content) / 4)))


def decision_list():
    lst = [{} for i in range(4)]
    lst[0][0] = [0, 3]; lst[0][1] = [0, 1]; lst[0][2] = [1, 2]; lst[0][3] = [2, 3]
    lst[0][0] = [0, 1]; lst[0][1] = [1, 2]; lst[0][2] = [3, 2]; lst[0][3] = [0, 3]
    lst[0][0] = [2, 1]; lst[0][1] = [3, 2]; lst[0][2] = [3, 0]; lst[0][3] = [0, 1]
    lst[0][0] = [2, 3]; lst[0][1] = [3, 0]; lst[0][2] = [1, 0]; lst[0][3] = [2, 1]
    return lst

def user_validity(sockets, user, pwd):
    allowed = False
    for client_socket in sockets:
        client_socket.send(user.encode('utf8'))
        sleep(0.05)
        client_socket.send(pwd.encode('utf8'))
        auth = client_socket.recv(128)
        if auth.decode('utf8') == 'valid':
            allowed = True
    return allowed


def create_socket(server_name, server_ports, usr, pswd):
    # Define the socket
    while True:

        client_sockets = [socket.socket(socket.AF_INET, socket.SOCK_STREAM) for server_port in server_ports]
        i = 0
        for server_port in server_ports:
            client_sockets[i].connect((server_name, server_port))
            i += 1
        credentials = []
        for client_socket in client_sockets:
            client_socket.send(usr.encode('utf8'))
            sleep(0.05)
            client_socket.send(pswd.encode('utf8'))
            validity = client_socket.recv(512)
            credentials.append(validity.decode('utf8'))
        if 'valid' in credentials:
            print("You have the following options:")
            print("-get <filename> <username> <password>")
            print("-put <filename> <username> <password>")
            print("-list <username> <password>")
            print("-exit: Smoothly exits and free up all sockets")
            inp = input("Please enter your input (in the exact format show):\n")
            ip = inp.split()
            if len(ip) == 1:
                func = ip[0]
            elif len(ip) == 3:
                func = ip[0]
                username = ip[1]
                password = ip[2]
            elif len(ip) == 4:
                func = ip[0]
                file_name = ip[1]
                username = ip[2]
                password = ip[3]
            else:
                logs.info("Invalid command")
                continue

            if func == "-get" or func == "-put":

                valid = user_validity(client_sockets, username, password)

                if valid:
                    for client_socket in client_sockets:
                        client_socket.send(func.encode('utf8'))
                        sleep(0.05)
                        client_socket.send(file_name.encode('utf8'))

                    if func == '-get':
                        flag = client_socket.recv(2048)
                        if flag.decode('utf8') == "Found":
                            with open(file_name, 'wb') as file:
                                while True:
                                    print('receiving data....')
                                    data = client_socket.recv(32)
                                    data = do_decrypt(data)
                                    if not data:
                                        break
                                    file.write(data)
                            file.close()
                            print("Successfully transferred file")
                        elif flag.decode('utf8') == "notFound":
                            logs.info("Sorry file not found in server!")
                        elif flag.decode('utf8') == "notAuthorised":
                            logs.info("Sorry! You are not authorised to download this file")

                    elif func == '-put':
                        try:
                            with open(file_name, 'rb') as f:
                                part_number = 0
                                for part in split_equal(f):
                                    with open('.'+file_name+'.'+str(part_number), 'wb') as newfile:
                                        newfile.write(part)
                                    part_number += 1

                            file_length = os.path.getsize(file_name)
                            decision_value = md5(file_name)
                            part_length = int(file_length/4)
                            upload_value = decision_list()
                            upload_dict = upload_value[decision_value]
                            line = f.read(32)
                            sent_count = 0
                            while line:
                                #line = do_encrypt(line.ljust(32, b'0'))
                                i = 0
                                j = 9
                                if sent_count >= part_length:
                                    i += 1
                                    if j != i:
                                        j = i
                                        client_sockets[upload_dict[i][0]].send(str(i+1).encode('utf8'))
                                        client_sockets[upload_dict[i][1]].send(str(i+1).encode('utf8'))
                                print("Sending data......")
                                client_sockets[upload_dict[i][0]].send(line)
                                client_sockets[upload_dict[i][1]].send(line)
                                sent_count = sent_count + 32
                                line = f.read(32)
                            f.close()
                            print("Done Sending")
                        except FileNotFoundError:
                            logs.info("File not Found!")
                    else:
                        logs.info("Invalid command")
                else:
                    logs.info("Invalid username or password\nTry again!")
                    continue

            elif func == "-list" or func == "-exit":
                client_socket.send(func.encode('utf8'))
                if func == "-list":
                    data = client_socket.recv(2048)
                    lst = json.loads(data.decode('utf8'))
                    list_of_files = lst.get("list")
                    print('\nListing all files in the directory:')
                    for item in list_of_files:
                        print("---->  "+item)
                else:
                    client_socket.shutdown(socket.SHUT_RDWR)
                    print("Shutting down socket")
                    break
            else:
                logs.info("Invalid command")
        else:
            logs.info("Invalid credentials!")
            break
    client_socket.close()
    print('Connection closed')


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    logs = logging.getLogger(__name__)
    config = configparser.ConfigParser()
    parser = argparse.ArgumentParser()
    #parser.add_argument("serverIp", help="enter server IP address", type=str)
    parser.add_argument('configfile', help="Enter name of the config file", type=str)
    parser.add_argument("serverPort", help="Enter port of the server you wish to connect", type=int)
    arg = parser.parse_args()
    server_name = '127.0.0.1'
    configfile = arg.configfile
    config.read(configfile)
    user = config['credentials']['username']
    password = config['credentials']['password']
    server_port = arg.serverPort
    if not validate_ip(server_name):
        logs.info("Invalid IP address")
        sys.exit()

    create_socket(server_name, server_port, user, password)
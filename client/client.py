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


def do_encrypt(message):
    obj = AES.new('sajfq874ohsdfp9qsajfq874ohsdfp9q', AES.MODE_CBC, '98qwy4thkjhwgpf9')
    cipher_text = obj.encrypt(message)
    return cipher_text


def do_decrypt(ciphertext):
    obj = AES.new('sajfq874ohsdfp9qsajfq874ohsdfp9q', AES.MODE_CBC, '98qwy4thkjhwgpf9')
    message = obj.decrypt(ciphertext)
    return message


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


def create_socket(server_name, server_port):
    # Define the socket
    while True:
        inp = input("Please enter your input (in the exact format show):\n")
        ip = inp.split()
        if len(ip) == 1:
            func = ip[0]
        elif len(ip) == 2:
            func = ip[0]
            file_name = ip[1]
        else:
            logs.info("Invalid command")
            continue

        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        client_socket.connect((server_name, server_port))
        if func == "-get" or func == "-put":
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
                    f = open(file_name, 'rb')
                    line = f.read(32)
                    while line:
                        line = do_encrypt(line.ljust(32, b'0'))
                        print("Sending data......")
                        client_socket.send(line)
                        line = f.read(32)
                    f.close()
                    print("Done Sending")
                except FileNotFoundError:
                    logs.info("File not Found!")
            else:
                logs.info("Invalid command")
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

    client_socket.close()
    print('Connection closed')


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    logs = logging.getLogger(__name__)
    parser = argparse.ArgumentParser()
    parser.add_argument("serverIp", help="enter server IP address", type=str)
    parser.add_argument("serverPort", help="Enter port of the server you wish to connect", type=int)
    arg = parser.parse_args()
    server_name = arg.serverIp
    server_port = arg.serverPort
    if not validate_ip(server_name):
        logs.info("Invalid IP address")
        sys.exit()
    print("You have the following options:")
    print("-get <filename>: Gets the file by transferring from server directory into client directory.")
    print("-put <filename>: Copies file from your directory to server's directory")
    print("-list: Lists all the files in the servers directory")
    print("-exit: Smoothly exits and free up all sockets")
    create_socket(server_name, server_port)
#!/usr/bin/env python3

# author = Pranav Gummaraj Srinivas prgu6170@colorado.edu
# date = 09/19/2018
# name = assignment 5 extra credit
# purpose = server-client socket programming
# version = 3.6.5

import socket
import argparse
import logging
import sys
import os
import json
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
    # Define socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        # Server socket should bind to one IP and port it is listening on. This must match with dest port on client
        server_socket.bind((server_name, server_port))
        print("Server is ready")
        server_socket.listen(5)
        # Always listening
        while True:
            conn, client_address = server_socket.accept()
            print("Got connection from ", client_address)
            func = conn.recv(2048)
            if func.decode('utf8') == "-get" or func.decode('utf8') == "-put":
                file_name = conn.recv(2048)

                if func.decode('utf8') == "-get":
                    if file_name.decode('utf8') != "server.py":
                        try:
                            f = open(file_name.decode('utf8'), 'rb')
                            conn.send(b"Found")
                            line = f.read(32)
                            while line:
                                line = do_encrypt(line.ljust(16, b'0'))
                                print("Sending data......")
                                conn.send(line)
                                line = f.read(32)
                            f.close()
                            print("Done Sending")
                        except FileNotFoundError:
                            logs.info("File not Found!")
                            conn.send(b"notFound")
                    else:
                        conn.send(b"notAuthorised")
                        print("Client tried to access server.py")

                elif func.decode('utf8') == "-put":
                    with open(file_name, 'wb') as file:
                        while True:
                            print('receiving data....')
                            data = conn.recv(32)
                            data = do_decrypt(data)
                            if not data:
                                break
                            file.write(data)
                    file.close()
                    print("Successfully transferred file")
            elif func.decode('utf8') == "-list":
                if func.decode('utf8') == '-list':
                    arr = os.listdir('.')
                    list_of_file = []
                    for item in arr:
                        if os.path.isfile(item) and item != 'server.py':
                            list_of_file.append(item)
                    data = json.dumps({"list": list_of_file})
                    print("Sending list of files in the directory")
                    conn.send(data.encode('utf8'))
                    print("Sent")
            conn.close()

    except OSError:
        logs.info("Port already in use")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    logs = logging.getLogger(__name__)
    parser = argparse.ArgumentParser()
    parser.add_argument("serverIp", help="enter server IP address", type=str)
    parser.add_argument("serverPort", help="Enter port of the server you wish to connect", type=int)
    args = parser.parse_args()
    server_name = args.serverIp
    server_port = args.serverPort
    if not validate_ip(server_name):
        logs.info("Invalid IP address")
        sys.exit()
    create_socket(server_name, server_port)



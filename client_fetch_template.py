import socket
import time

import network

SERVER = {'IP': '192.168.0.71', 'PORT': 4004}


def server_handler(sock):
    print(network.recv_msg(sock))
    network.send_msg(sock, "Client: Windows")


def connect():
    # Create a TCP/IP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Connecting to remote computer
    server_address = (SERVER['IP'], SERVER['PORT'])
    sock.connect(server_address)

    server_handler(sock)
    time.sleep(5)


def connect_loop():
    while True:
        connect()


if __name__ == '__main__':
    connect()

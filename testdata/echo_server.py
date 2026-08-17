#!/usr/bin/env python3
import socket
import threading


def tcp_server() -> None:
    server = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    server.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("::", 18080))
    server.listen()
    while True:
        connection, _ = server.accept()
        threading.Thread(target=serve_tcp, args=(connection,), daemon=True).start()


def serve_tcp(connection: socket.socket) -> None:
    with connection:
        while data := connection.recv(65536):
            connection.sendall(data)


def udp_server() -> None:
    server = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    server.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
    server.bind(("::", 18080))
    while True:
        data, peer = server.recvfrom(65536)
        server.sendto(data, peer)


threading.Thread(target=tcp_server, daemon=True).start()
udp_server()

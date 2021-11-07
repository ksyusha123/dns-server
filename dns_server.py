import socket
import json
import threading

from dns_resolver import DNSResolver


class DnsServerTcp:

    def __init__(self):
        self.port = 53000
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind(("", self.port))
        self.server_socket.listen()

    def run(self):
        while True:
            conn, address = self.server_socket.accept()
            user_request = conn.recv(1024)
            resp = DNSResolver().resolve(user_request.decode())
            conn.send(json.dumps(resp).encode())


class DnsServerUdp:

    def __init__(self):
        self.port = 53001
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.server_socket.bind(("", self.port))

    def run(self):
        while True:
            user_request, address = self.server_socket.recvfrom(1024)
            resp = DNSResolver().resolve(user_request.decode())
            self.server_socket.sendto(json.dumps(resp).encode(), address)


def main():
    # server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # server_socket.bind(('10.112.89.34', port))
    #
    # while True:
    #     user_request, address = server_socket.recvfrom(1024)
    #     resp = DNSResolver().resolve(user_request.decode())
    #     server_socket.sendto(json.dumps(resp).encode(), address)
    tcp_server = DnsServerTcp()
    udp_server = DnsServerUdp()
    tcp = threading.Thread(target=tcp_server.run)
    udp = threading.Thread(target=udp_server.run)
    tcp.start()
    udp.start()


if __name__ == '__main__':
    main()

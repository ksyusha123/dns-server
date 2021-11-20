import socket
import threading

from dns_resolver import DNSResolver


class DnsServerTcp:

    def __init__(self):
        self.port = 53
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind(("", self.port))
        self.server_socket.listen()

    def run(self):
        while True:
            conn, address = self.server_socket.accept()
            user_request = conn.recv(1024)
            resp, ans = DNSResolver().resolve(user_request)
            conn.send(ans)


class DnsServerUdp:

    def __init__(self):
        self.port = 53
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.server_socket.bind(("", self.port))

    def run(self):
        while True:
            user_request, address = self.server_socket.recvfrom(1024)
            resp, ans = DNSResolver().resolve(user_request)
            self.server_socket.sendto(ans, address)


def main():
    tcp_server = DnsServerTcp()
    udp_server = DnsServerUdp()
    tcp = threading.Thread(target=tcp_server.run)
    udp = threading.Thread(target=udp_server.run)
    tcp.start()
    udp.start()


if __name__ == '__main__':
    main()

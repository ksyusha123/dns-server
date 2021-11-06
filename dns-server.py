import socket
import json

from dns_resolver import DNSResolver

port = 53


def main():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.bind(('10.112.89.34', port))

    while True:
        user_request, address = server_socket.recvfrom(1024)
        resp = DNSResolver().resolve(user_request.decode())
        server_socket.sendto(json.dumps(resp).encode(), address)


if __name__ == '__main__':
    main()

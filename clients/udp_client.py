import socket
import json
from pprint import pprint

client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
client_socket.sendto(input().encode(), ('127.0.0.1', 53001))
resp = client_socket.recv(8192)
pprint(json.loads(resp))

import socket
import json
from pprint import pprint

client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect(('127.0.0.1', 53000))
client_socket.sendto(input().encode(), ('127.0.0.1', 53000))
resp = client_socket.recv(8192)
pprint(json.loads(resp))

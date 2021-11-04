import socket


class DNSRequestMaker:

    def __init__(self, connection_type="udp"):
        self.connection_type = connection_type
        self.port = 53

    def make_request(self, request, host):
        address = (host, self.port)
        return self.make_request_udp(request, address)
        # if self.connection_type == 'udp':
        #     return self.make_request_udp(request, address)
        # return self.make_request_tcp(request, address)

    @staticmethod
    def make_request_udp(request, address):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.sendto(request, address)
            answer, address = sock.recvfrom(1024)
        return answer

    def form_dns_request(self, request):
        header = self.form_dns_header()
        body = self.form_dns_body(request)
        request_type = bytes([0, 1])
        request_class = bytes([0, 1])
        return header + body + request_type + request_class

    @staticmethod
    def form_dns_header():
        request_id = bytearray("id", "utf-8")
        flags = bytes([0, 0])
        requests_count = bytes([0, 1])
        answers_count = bytes([0, 0])
        add_count = bytes([0, 0, 0, 0])
        return request_id + flags + requests_count + answers_count + add_count

    @staticmethod
    def form_dns_body(request):
        domain_parts = request.split('.')
        bytes_request = bytes(0)
        for domain_part in domain_parts:
            bytes_request += bytes([len(domain_part)]) + bytearray(domain_part,
                                                                   "utf-8")
        bytes_request += bytes([0])
        return bytes_request

    # @staticmethod
    # def make_request_tcp(request, address):
    #     with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
    #         sock.connect(address)
    #         sock.send(request)
    #         answer = b''
    #         while True:
    #             data = sock.recv(128)
    #             if not data:
    #                 break
    #             answer += data
    #     return answer

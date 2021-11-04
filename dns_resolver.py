import socket

from dns_parser import DNSParser
from dns_request_maker import DNSRequestMaker

root_host = '199.7.83.42'
port = 53


class DNSResolver:
    def __init__(self, connection_type="udp"):
        self.parser = DNSParser()
        self.request_maker = DNSRequestMaker(connection_type)

    def resolve(self, domain_name):
        dns_response = b''
        host = root_host
        for i in range(domain_name.count('.') + 2):
            dns_request = self.request_maker.form_dns_request(domain_name)
            try:
                dns_answer = self.request_maker.make_request(dns_request, host)
                dns_response = self.parser.parse(dns_answer)
            except:
                dns_answer = self.request_maker.make_request(dns_request, host)
                dns_response = self.parser.parse(dns_answer)
            if dns_response["body"]["answers"]:
                break
            auth_server = dns_response["body"]["authoritative"][0]["response"]
            host = self.parser.get_auth_server_ipv4(
                dns_response, auth_server)
            if host is None:
                break

        return dns_response

    # @staticmethod
    # def make_request(dns_request, host, type=socket.SOCK_DGRAM):
    #     server_address = (host, port)
    #     with socket.socket(socket.AF_INET, type) as sock:
    #         sock.sendto(dns_request, server_address)
    #         answer, address = sock.recvfrom(10000000)
    #     return answer

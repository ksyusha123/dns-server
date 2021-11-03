import socket

from dns_parser import DNSParser

root_host = '199.7.83.42'
port = 53


class DNSResolver:
    def __init__(self):
        self.parser = DNSParser()

    def resolve(self, domain_name):
        dns_request = self.parser.form_dns_request(domain_name)
        dns_answer = self.make_request(dns_request, root_host)
        dns_response = self.parser.parse_dns_answer(dns_answer)
        while len(dns_response["body"]["answers"]) == 0:
            authoritative_server = \
                dns_response["body"]["additional"][0]["response"]
            dns_request = self.parser.form_dns_request(domain_name)
            dns_answer = self.make_request(dns_request, authoritative_server)
            dns_response = self.parser.parse_dns_answer(dns_answer)
        return dns_response

    @staticmethod
    def make_request(dns_request, host, type=socket.SOCK_DGRAM):
        server_address = (host, port)
        with socket.socket(socket.AF_INET, type) as sock:
            sock.sendto(dns_request, server_address)
            answer, address = sock.recvfrom(10000000)
        return answer

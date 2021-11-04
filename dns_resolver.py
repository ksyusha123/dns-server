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
        # while len(dns_response["body"]["answers"]) == 0:
        for i in range(domain_name.count('.') + 1):
            auth_server = dns_response["body"]["authoritative"][0]["response"]
            auth_server_ipv4 = self.parser.get_auth_server_ipv4(
                dns_response, auth_server)
            if auth_server_ipv4 is None:
                break
            dns_request = self.parser.form_dns_request(domain_name)
            dns_answer = self.make_request(dns_request, auth_server_ipv4)
            dns_response = self.parser.parse_dns_answer(dns_answer)
        return dns_response

    @staticmethod
    def make_request(dns_request, host, type=socket.SOCK_DGRAM):
        server_address = (host, port)
        with socket.socket(socket.AF_INET, type) as sock:
            sock.sendto(dns_request, server_address)
            answer, address = sock.recvfrom(10000000)
        return answer

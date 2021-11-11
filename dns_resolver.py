from dns_parser import DNSParser
from request_maker import DNSRequestMaker

root_host = '199.7.83.42'
port = 53


class DNSResolver:
    def __init__(self):
        self.parser = DNSParser()
        self.request_maker = DNSRequestMaker()

    def resolve(self, domain_name):
        host = root_host
        dns_request = self.request_maker.form_dns_request(domain_name)
        dns_response = self.try_get_resp(dns_request, host)
        while not dns_response["body"]["answers"]:
            auth_server = dns_response["body"]["authoritative"][0]["response"]
            host = self.parser.get_auth_server_ipv4(
                dns_response, auth_server)
            if host is None:
                host = DNSResolver().resolve(auth_server)["body"][
                    "answers"][0]["response"]
            dns_response = self.try_get_resp(dns_request, host)

        return dns_response

    def try_get_resp(self, dns_request, host):
        try:
            dns_answer = self.request_maker.make_request(dns_request, host)
            dns_response = self.parser.parse(dns_answer)
        except:
            dns_answer = self.request_maker.make_request(dns_request, host)
            dns_response = self.parser.parse(dns_answer)
        return dns_response

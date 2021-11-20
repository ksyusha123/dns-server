from dns_parser import DNSParser
from request_maker import DNSRequestMaker

root_host = '199.7.83.42'
port = 53


class DNSResolver:
    def __init__(self):
        self.parser = DNSParser()
        self.request_maker = DNSRequestMaker()

    def resolve(self, dns_request):
        host = root_host
        dns_response, dns_answer = self.try_get_resp(dns_request, host)
        while not dns_response["body"]["answers"]:
            auth_server = dns_response["body"]["authoritative"][0]["response"]
            host = self.parser.get_auth_server_ipv4(
                dns_response, auth_server)
            if host is None:
                intermediate_request = self.request_maker\
                    .form_dns_request(auth_server)
                host = DNSResolver().resolve(intermediate_request)[0]["body"][
                    "answers"][0]["response"]
            dns_response, dns_answer = self.try_get_resp(dns_request, host)

        return dns_response, dns_answer

    def try_get_resp(self, dns_request, host):
        try:
            dns_answer = self.request_maker.make_request(dns_request, host)
            dns_response = self.parser.parse(dns_answer)
        except:
            dns_answer = self.request_maker.make_request(dns_request, host)
            dns_response = self.parser.parse(dns_answer)
        return dns_response, dns_answer

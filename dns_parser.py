class DNSParser:

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

    @staticmethod
    def parse_ipv4(ipv4_bytes):
        ipv4_parts = []
        for byte in ipv4_bytes:
            ipv4_parts.append(str(byte))
        return '.'.join(ipv4_parts)

    def parse_ipv6(self, ipv6_bytes):
        octets = self.get_octets_from_ipv6_bytes(ipv6_bytes)
        ipv6 = ':'.join(octets)
        while ':::' in ipv6:
            ipv6 = ipv6.replace('::', ':')
        return ipv6

    @staticmethod
    def get_octets_from_ipv6_bytes(ipv6_bytes):
        octets = [''] * 8
        current_octet = ''
        for i in range(16):
            if i % 2 == 0:
                if ipv6_bytes[i] == 0:
                    continue
                current_octet += "{0:x}".format(ipv6_bytes[i])
            else:
                hex_num = "{0:x}".format(ipv6_bytes[i])
                if ipv6_bytes[i] < 32 and ipv6_bytes[i - 1] != 0:
                    hex_num = '0' + hex_num
                current_octet += hex_num
                if current_octet == '0':
                    current_octet = ''
                octets[i // 2] = current_octet
                current_octet = ''
        return octets

    def parse_name(self, byte_nameserver, dns_answer):
        parts = self.get_parts_ns(byte_nameserver, dns_answer)
        decoded_parts = []
        for part in parts:
            decoded_parts.append(part.decode())
        return '.'.join(decoded_parts)

    def get_parts_ns(self, byte_ns, dns_answer):
        parts = []
        current = 0
        while byte_ns[current] != 0:
            if byte_ns[current] == int.from_bytes(b'\xc0', "big"):
                offset = byte_ns[current + 1]
                ans_by_offset = dns_answer[offset:]
                ans_by_offset = ans_by_offset[:ans_by_offset.find(b'\x00') + 1]
                parts += self.get_parts_ns(ans_by_offset, dns_answer)
                break
            part_length = byte_ns[current]
            parts.append(byte_ns[current + 1: current + 1 + part_length])
            current += 1 + part_length
        return parts

    def get_info_for_answer_type(self, answer_part, dns_response,
                                 full_dns_answer,
                                 answer_type, answer_count):
        for _ in range(answer_count):
            response_type = int.from_bytes(answer_part[2:4], "big")
            response_length = int.from_bytes(answer_part[10:12], "big")
            response = answer_part[12: 12 + response_length]
            if response_type == 1:
                response = self.parse_ipv4(response)
            elif response_type == 2:
                response = self.parse_name(response, full_dns_answer)
            else:
                response = self.parse_ipv6(response)
            dns_response["body"][answer_type].append({
                "response_name": answer_part[:2],
                "response_type": response_type,
                "response_class": int.from_bytes(answer_part[4:6], "big"),
                "ttl": int.from_bytes(answer_part[6:10], "big"),
                "response_length": response_length,
                "response": response
            })
            answer_part = answer_part[12 + response_length:]
        return answer_part

    def parse_dns_answer(self, dns_answer):
        dns_response = {
            "header": {"transaction_id": int.from_bytes(dns_answer[:2], "big"),
                       "resp_code": int.from_bytes(dns_answer[2:4], "big"),
                       "question_count": int.from_bytes(dns_answer[4:6],
                                                        "big"),
                       "answers_count": int.from_bytes(dns_answer[6:8], "big"),
                       "auth_count": int.from_bytes(dns_answer[8:10], "big"),
                       "additional_count": int.from_bytes(dns_answer[10:12],
                                                          "big")}}

        tail_dns_answer = dns_answer[12:]
        dns_response["body"] = {"question": [], "answers": [],
                                "authoritative": [], "additional": []}

        for _ in range(dns_response["header"]["question_count"]):
            request_end_byte = tail_dns_answer.find(0) + 1
            dns_response["body"]["question"].append(
                {"request": tail_dns_answer[:request_end_byte],
                 "question_type": int.from_bytes(
                     tail_dns_answer[request_end_byte:request_end_byte + 2],
                     "big"),
                 "question_class": int.from_bytes(
                     tail_dns_answer[request_end_byte + 2:
                                     request_end_byte + 4], "big")})
            tail_dns_answer = tail_dns_answer[request_end_byte + 4:]

        answer_part = tail_dns_answer
        answer_part = self.get_info_for_answer_type(answer_part, dns_response,
                                                    dns_answer,
                                                    "answers",
                                                    dns_response["header"][
                                                        "answers_count"])
        answer_part = self.get_info_for_answer_type(answer_part, dns_response,
                                                    dns_answer,
                                                    "authoritative",
                                                    dns_response["header"][
                                                        "auth_count"])
        answer_part = self.get_info_for_answer_type(answer_part, dns_response,
                                                    dns_answer,
                                                    "additional",
                                                    dns_response["header"][
                                                        "additional_count"])
        return dns_response

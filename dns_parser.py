class DNSParser:

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

    def add_info_to_resp_and_return_ans_tail(self, answer_part, dns_response,
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
                "response_name": self.parse_name(answer_part[:2],
                                                 full_dns_answer),
                "response_type": response_type,
                "response_class": int.from_bytes(answer_part[4:6], "big"),
                "ttl": int.from_bytes(answer_part[6:10], "big"),
                "response_length": response_length,
                "response": response
            })
            answer_part = answer_part[12 + response_length:]
        return answer_part

    def parse(self, dns_answer):
        header = self.parse_header(dns_answer[:12])
        dns_response = {"header": header}

        tail = dns_answer[12:]
        dns_response["body"] = {"question": [], "answers": [],
                                "authoritative": [], "additional": []}

        dns_response["body"]["question"], tail = self.parse_question(
            tail, dns_response["header"]["question_count"], dns_answer)

        self.parse_answers(tail, dns_response, dns_answer)

        return dns_response

    @staticmethod
    def parse_header(bytes_header):
        return {"transaction_id": int.from_bytes(bytes_header[:2], "big"),
                "resp_code": int.from_bytes(bytes_header[2:4], "big"),
                "question_count": int.from_bytes(bytes_header[4:6],
                                                 "big"),
                "answers_count": int.from_bytes(bytes_header[6:8], "big"),
                "auth_count": int.from_bytes(bytes_header[8:10], "big"),
                "additional_count": int.from_bytes(bytes_header[10:12],
                                                   "big")}

    def parse_question(self, tail, q_count, dns_answer):
        questions = []
        for _ in range(q_count):
            request_end_byte = tail.find(0) + 1
            questions.append(
                {"request": self.parse_name(
                    tail[:request_end_byte], dns_answer),
                    "question_type": int.from_bytes(
                        tail[request_end_byte:request_end_byte + 2],
                        "big"),
                    "question_class": int.from_bytes(
                        tail[request_end_byte + 2:
                             request_end_byte + 4], "big")})
            tail = tail[request_end_byte + 4:]
        return questions, tail

    def parse_answers(self, tail, dns_response, dns_answer):
        tail = self.add_info_to_resp_and_return_ans_tail(
            tail, dns_response, dns_answer, "answers",
            dns_response["header"]["answers_count"])
        tail = self.add_info_to_resp_and_return_ans_tail(
            tail, dns_response, dns_answer, "authoritative",
            dns_response["header"]["auth_count"])
        tail = self.add_info_to_resp_and_return_ans_tail(
            tail, dns_response, dns_answer, "additional",
            dns_response["header"]["additional_count"])

    @staticmethod
    def get_auth_server_ipv4(dns_response, auth_server):
        filtered_resp = filter(lambda ans: ans["response_type"] == 1 and
                                           ans["response_name"] ==
                                           auth_server,
                               dns_response["body"]["additional"])
        try:
            return next(filtered_resp)["response"]
        except StopIteration:
            return None

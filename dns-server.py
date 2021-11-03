import socket

root_host_ip = '199.7.83.42'
port = 53


def form_dns_request(request):
    header = form_dns_header()
    body = form_dns_body(request)
    request_type = bytes([0, 1])
    request_class = bytes([0, 1])
    return header + body + request_type + request_class


def form_dns_header():
    request_id = bytearray("id", "utf-8")
    flags = bytes([0, 0])
    requests_count = bytes([0, 1])
    answers_count = bytes([0, 0])
    add_count = bytes([0, 0, 0, 0])
    return request_id + flags + requests_count + answers_count + add_count


def form_dns_body(request):
    domain_parts = request.split('.')
    bytes_request = bytes(0)
    for domain_part in domain_parts:
        bytes_request += bytes([len(domain_part)]) + bytearray(domain_part,
                                                               "utf-8")
    bytes_request += bytes([0])
    return bytes_request


def make_request_udp(dns_request):
    server_address = (root_host_ip, port)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.sendto(dns_request, server_address)
        answer, address = sock.recvfrom(10000000)
    return answer


def parse_dns_answer(dns_answer):
    transaction_id = dns_answer[:2]
    resp_code = dns_answer[2:4]
    question_count = dns_answer[4:6]
    answers_count = dns_answer[6:8]
    auth_rr_count = dns_answer[8:10]
    add_rr_count = dns_answer[10:12]
    current_byte_number = 12
    while dns_answer[current_byte_number] != 0:
        current_byte_number += 1
    current_byte_number += 1
    request = dns_answer[12:current_byte_number]
    question_type = dns_answer[current_byte_number:current_byte_number+2]
    question_class = dns_answer[current_byte_number+2:current_byte_number+4]
    answer_part = dns_answer[current_byte_number+4:]
    while answer_part:
        resp_name = answer_part[:2]
        resp_type = answer_part[2:4]
        resp_class = answer_part[4:6]
        ttl = answer_part[6:10]
        resp_len = answer_part[10:12]
        response = answer_part[12:12+int.from_bytes(resp_len, "big")]
        if int.from_bytes(resp_type, 'big') == 2:
            print(parse_nameserver(response, dns_answer))
        elif int.from_bytes(resp_type, 'big') == 1:
            print(parse_ipv4(response))
        else:
            print(parse_ipv6(response))
        answer_part = answer_part[12+int.from_bytes(resp_len, "big"):]


def parse_ipv4(ipv4_bytes):
    ipv4_parts = []
    for byte in ipv4_bytes:
        ipv4_parts.append(str(byte))
    return '.'.join(ipv4_parts)


def parse_ipv6(ipv6_bytes):
    octets = get_octets_from_ipv6_bytes(ipv6_bytes)
    ipv6 = ':'.join(octets)
    while ':::' in ipv6:
        ipv6 = ipv6.replace('::', ':')
    return ipv6


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


def parse_nameserver(byte_nameserver, dns_answer):
    parts = get_parts_ns(byte_nameserver, dns_answer)
    decoded_parts = []
    for part in parts:
        decoded_parts.append(part.decode())
    return '.'.join(decoded_parts)


def get_parts_ns(byte_ns, dns_answer):
    parts = []
    current = 0
    while byte_ns[current] != 0:
        if byte_ns[current] == int.from_bytes(b'\xc0', "big"):
            offset = byte_ns[current + 1]
            ans_by_offset = dns_answer[offset:]
            ans_by_offset = ans_by_offset[:ans_by_offset.find(b'\x00') + 1]
            parts += get_parts_ns(ans_by_offset, dns_answer)
            break
        part_length = byte_ns[current]
        parts.append(byte_ns[current + 1: current + 1 + part_length])
        current += 1 + part_length
    return parts


def main():
    user_request = 'yandex'
    dns_request = form_dns_request(user_request)
    dns_answer = make_request_udp(dns_request)
    answer = parse_dns_answer(dns_answer)


if __name__ == '__main__':
    main()

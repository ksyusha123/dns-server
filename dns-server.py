import socket

from dns_resolver import DNSResolver


def main():
    user_request = 'yandex.ru'
    print(DNSResolver().resolve(user_request))


if __name__ == '__main__':
    main()

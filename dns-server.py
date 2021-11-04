import click
from pprint import pprint

from dns_resolver import DNSResolver


@click.command()
@click.argument("domain_name", required=True)
def main(domain_name):
    pprint(DNSResolver().resolve(domain_name))


if __name__ == '__main__':
    main()

# TODO: Consider filter list for getting information about specific domains only
# TODO: Implement paging

import configparser
import csv
import datetime
import dateutil.parser
import json
import socket
import urllib3

import click

try:
    import boto3
    from botocore.config import Config as BotoConfig
    BOTO = True
except ModuleNotFoundError:
    BOTO = False
from jinja2 import Environment, BaseLoader
import requests

CONTEXT_SETTINGS = dict(help_option_names=['-h', '--help'])
LOCAL_TIMEZONE = datetime.datetime.now().astimezone().tzinfo
TEMPLATE = """
╒═════════════════════════╤═════════════╤═════════════╤═══════════╤═══════╤═══════════════════╕
│ Name                    │ Registrar   │ Expires     │ Remaining │ Auto  │ Resolves to       │
╞═════════════════════════╪═════════════╪═════════════╪═══════════╪═══════╪═══════════════════╡ 
{% for domain in domains -%}
{% if (not domain.expired) or (domain.expired and show_expired == True) -%}
│ {{ '%-24s'|format(domain.name[:24]) -}}
│ {{ '%-12s'|format(domain.registrar) -}}
│ {{ '%-12s'|format(domain.expires.strftime('%d %b %Y')) -}}
│ {{ '%-10s'|format(domain.remaining) -}}
│ {{ '%-6s' |format(domain.auto_renew) -}}
│ {{ '%-18s'|format(domain.resolves_to) -}}│
{% endif -%}
{% endfor -%}
╘═════════════════════════╧═════════════╧═════════════╧═══════════╧═══════╧═══════════════════╛
"""


class Domain:
    """A generic class for domain information regardless of the provider.
    Different providers return different pieces of information;
    not every domain will have every piece of information."""

    def __init__(self, name, registrar):
        self.auto_renew = None
        self.contact = None
        self.created = None
        self.dns = None
        self.expires = None
        self.id = None
        self.expired = None
        self.locked = None
        self.name = name
        self.nameservers = None
        self.privacy = None
        self.registrar = registrar
        self.remaining = None
        self.resolves_to = None

    def get_expired(self):
        # Can't compare timezone-aware and timezone-naive timestamps
        # So if timestamp returned from API is timezone-naive, assume it's UTC and set it that way
        if self.expires.tzinfo is None or self.expires.tzinfo.utcoffset(self.expires) is None:
            self.expires = self.expires.replace(tzinfo=datetime.timezone.utc)
        now = datetime.datetime.now(LOCAL_TIMEZONE)
        self.expired = True if now > self.expires else False

    def get_remaining(self):
        now = datetime.datetime.now(LOCAL_TIMEZONE)
        if not self.expired:  # Capture the remaining registration time in days
            self.remaining = (self.expires - now).days
        else:
            self.remaining = 0

    def get_resolves_to(self):
        try:
            self.resolves_to = socket.gethostbyname(self.name)
        except socket.gaierror:
            self.resolves_to = None


class AWSClient:
    """Class for retrieving domain information from AWS Route 53.
    Involves two API calls using the boto3 library.
    The first retrieves all domains, the second retrieves information about specific domains
    on a per-domain basis.
    """

    def __init__(self, proxy, access_key_id, secret_access_key):
        self.domains = []
        self.proxy = {'https': 'http://' + proxy} if proxy else None
        self.verify = False if proxy else True
        self.access_key_id = access_key_id
        self.secret_access_key = secret_access_key
        self.client = boto3.client('route53domains',
                                   aws_access_key_id=self.access_key_id,
                                   aws_secret_access_key=self.secret_access_key,
                                   verify=self.verify,
                                   config=BotoConfig(proxies=self.proxy))
        self.get_domains()
        self.get_domain_details()

    def get_domains(self):
        resp = self.client.list_domains()
        for entry in resp['Domains']:
            domain = Domain(entry['DomainName'], 'AWS')
            domain.expires = entry['Expiry']
            domain.get_expired()
            domain.get_remaining()
            domain.auto_renew = entry['AutoRenew']
            domain.locked = entry['TransferLock']
            self.domains.append(domain)

    def get_domain_details(self):
        for domain in self.domains:
            resp = self.client.get_domain_detail(DomainName=domain.name)
            domain.created = resp['CreationDate']
            admin = resp['AdminContact']['Email']
            registrant = resp['RegistrantContact']['Email']
            tech = resp['TechContact']['Email']
            domain.contact = f'Admin: {admin}; Registrant: {registrant}; Tech: {tech}'
            admin_privacy = resp['AdminPrivacy']
            registrant_privacy = resp['RegistrantPrivacy']
            tech_privacy = resp['TechPrivacy']
            domain.privacy = f'Admin: {admin_privacy}; Registrant: {registrant_privacy}; Tech: {tech_privacy}'
            domain.nameservers = ', '.join([list(x.values())[0] for x in resp['Nameservers']])
            domain.get_resolves_to()


class AzureClient:
    """Class for retrieving domain information from Microsoft Azure.
    Involves two API calls using Python requests.
    The first retrieves a bearer token for subsequent API calls,
    the second retrieves information about domains.
    """

    def __init__(self, proxy, app_id, tenant, client_secret, subscription):
        self.domains = []
        self.proxy = {'https': 'http://' + proxy} if proxy else None
        self.verify = False if proxy else True
        self.app_id = app_id
        self.tenant = tenant
        self.client_secret = client_secret
        self.subscription = subscription
        # All queries require "api-version" parameter
        self.api_version = '2015-04-01'  # https://docs.microsoft.com/en-us/rest/api/appservice/domains
        self.auth_endpoint = f'https://login.microsoftonline.com/{self.tenant}/oauth2/token'
        self.app_service_endpoint = f'https://management.azure.com/subscriptions/{self.subscription}' \
                                    f'/providers/Microsoft.DomainRegistration/domains?api-version={self.api_version}'
        self.resource = 'https://management.azure.com/'
        self.bearer_token = None
        self.authenticate()
        self.get_domains()

    def authenticate(self):
        data = f'grant_type=client_credentials&client_id={self.app_id}' \
               f'&client_secret={self.client_secret}' \
               f'&resource={self.resource}'
        resp = requests.get(self.auth_endpoint, data=data, proxies=self.proxy, verify=False)
        try:
            self.bearer_token = resp.json()['access_token']
        except json.JSONDecoder as err:
            click.secho(f'[-] Failed to authenticate to Azure: {err}', fg='red', bold=True)
            pass

    def get_domains(self):
        headers = {'Authorization': f'Bearer {self.bearer_token}'}
        resp = requests.get(self.app_service_endpoint, headers=headers, proxies=self.proxy, verify=False)

        if not resp.status_code == 200:
            click.secho(f'[-] Failed to retrieve Azure domains: {resp.content}', fg='red', bold=True)
            return

        domains = resp.json()['value']
        for entry in domains:
            domain = Domain(name=entry['name'], registrar='Azure')
            domain.id = entry['id']
            domain.created = dateutil.parser.parse(entry['properties']['createdTime'])
            domain.expires = dateutil.parser.parse(entry['properties']['expirationTime'])
            domain.get_expired()
            domain.get_remaining()
            domain.auto_renew = entry['properties']['autoRenew']
            domain.privacy = entry['properties']['privacy']
            domain.dns = entry['properties']['dnsType']
            domain.nameservers = entry['properties']['nameServers']
            domain.get_resolves_to()
            self.domains.append(domain)


class GoDaddyClient:
    """Class for retrieving domain information from GoDaddy.
    Involves one API calls using Python requests, which
    retrieves information about the account's domains.
    """

    def __init__(self, proxy, api_key, secret):
        self.domains = []
        self.proxy = {'https': 'http://' + proxy} if proxy else None
        self.verify = False if proxy else True
        self.api_key = api_key
        self.secret = secret
        self.headers = {'Authorization': f'sso-key {self.api_key}:{self.secret}'}
        self.endpoint = 'https://api.godaddy.com/v1/domains'
        self.get_domains()

    def get_domains(self):
        resp = requests.get(self.endpoint, headers=self.headers, proxies=self.proxy, verify=self.verify)
        domains = resp.json()
        for entry in domains:
            domain = Domain(name=entry['domain'], registrar='GoDaddy')
            domain.id = entry['domainId']
            domain.created = dateutil.parser.parse(entry['createdAt'])
            domain.expires = dateutil.parser.parse(entry['expires'])
            domain.get_expired()
            domain.get_remaining()
            domain.locked = entry['locked']
            domain.auto_renew = entry['renewAuto']
            domain.privacy = entry['privacy']
            domain.nameservers = entry['nameServers']
            domain.get_resolves_to()
            self.domains.append(domain)


class NamecheapClient:
    """Not implemented."""

    def __init__(self, proxy, api_key, username, api_username, client_ip, page_size=10):
        self.domains = []
        self.proxy = {'https': 'http://' + proxy} if proxy else None
        self.verify = False if proxy else True
        self.api_key = api_key
        self.username = username
        self.api_username = api_username
        self.client_ip = client_ip
        self.page_size = page_size


class SlackClient:
    """Class for posting messages to a Slack.
    The only required configuration parameter is webhook_url.
    """

    def __init__(self, proxy, message, webhook_url, username, channel, alert_target, emoji):
        self.proxy = {'https': 'http://' + proxy} if proxy else None
        self.verify = False if proxy else True
        self.webhook_url = webhook_url
        self.message = message
        self.username = username
        self.channel = channel
        self.alert_target = alert_target
        self.emoji = emoji
        self.send_message()

    def send_message(self):
        data = {'text': self.message,
                'username': self.username,
                'icon_emoji': self.emoji,
                'channel': self.channel}
        resp = requests.post(self.webhook_url, json=data, proxies=self.proxy, verify=self.verify)
        if not resp.status_code == 200:
            click.secho(f'[-] Attempt to send Slack message failed - {resp.content}', fg='red', bold=True)


def read_config(config_file):
    """Read a configuration file and return a dict of dicts.
    Outer dict keys represent config section headers.
    Inner dicts are config parameters and values.
    """
    config = configparser.ConfigParser()
    config.read(config_file)
    config_dict = {x: {} for x in config.sections()}
    for section in config.sections():
        for k, v in config[section].items():
            config_dict[section][k] = v
    return config_dict


def serialize(obj):
    """Change datetime.datetime objects to ISO-format strings and return the updated object."""
    for k, v in vars(obj).items():
        if isinstance(v, datetime.datetime):
            setattr(obj, k, v.isoformat())
    return obj


@click.command(context_settings=CONTEXT_SETTINGS)
@click.option('-p', '--providers',
              type=click.Choice(choices=['AWS', 'Azure', 'GoDaddy', 'Namecheap'], case_sensitive=False), multiple=True,
              help='Specific providers to query. Can list multiple providers each prepended with "-p"')
@click.option('-j', '--json-file', help='Save output to JSON.')
@click.option('-c', '--csv-file', metavar='csv', help='Save output to CSV.')
@click.option('-s', '--slack', is_flag=True, help='Send domain information to slack.')
@click.option('-x', '--show-expired', is_flag=True, help='Include expired domains in output.')
@click.option('-a', '--attr', type=click.Choice(['auto_renew', 'contact', 'created', 'dns', 'expired', 'expires', 'id',
                                                 'locked', 'name', 'nameservers', 'privacy', 'registrar', 'remaining',
                                                 'resolves_to'], case_sensitive=False),
              multiple=True, help='Specific domain attributes to print to terminal.')
@click.argument('config', type=click.Path(exists=True))
def main(config, providers, json_file, csv_file, slack, show_expired, attr):
    """Retrieve domains from different providers.

    CONFIG is the path to the configuration file containing API credential material.

    """

    domains = []

    # Plan to check all providers unless operator selects specific provider(s)
    if not providers:
        providers = ('AWS', 'Azure', 'GoDaddy', 'Namecheap')

    config_dict = read_config(config)

    if slack and not config_dict['Slack']['webhook_url']:
        click.secho(f'[-] Slack webhook URL missing from {config}. Information will not be sent to Slack.', fg='red',
                    bold=True)

    # Currently no validation of proxy address
    proxy = config_dict['Proxy']['proxy_ip']
    if proxy:
        click.secho('[-] Certificate verification disabled with proxy', fg='red', bold=True)
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    if all(config_dict['AWS'].values()) and 'AWS' in providers:
        if not BOTO:
            click.secho('[-] boto3 library not found. Retrieving AWS domains requires boto3.', fg='red', bold=True)
            pass
        aws_client = AWSClient(proxy, **config_dict['AWS'])
        domains.extend(aws_client.domains)

    if all(config_dict['Azure'].values()) and 'Azure' in providers:
        azure_client = AzureClient(proxy, **config_dict['Azure'])
        domains.extend(azure_client.domains)

    # Namecheap API client not implemented
    if all(config_dict['Namecheap'].values()):
        namecheap_client = NamecheapClient(proxy, **config_dict['Namecheap'])

    if all(config_dict['GoDaddy'].values()):
        godaddy_client = GoDaddyClient(proxy, **config_dict['GoDaddy'])
        domains.extend(godaddy_client.domains)

    if domains:
        # Sort domains ascending by number of days remaining
        # To sort by name: domains.sort(key=lambda x: x.name)
        domains.sort(key=lambda x: x.remaining)

        template = Environment(loader=BaseLoader).from_string(TEMPLATE)
        message = template.render(domains=domains, show_expired=show_expired)

        # Slack only needs webhook
        if slack and config_dict['Slack']['webhook_url']:  # and domains:
            slack_client = SlackClient(proxy, '```\n' + message + '\n```', **config_dict['Slack'])

        if json_file or csv_file or attr:
            domains = [serialize(domain).__dict__ for domain in domains]

        if attr:
            for domain in domains:
                for a in attr:
                    print(domain[a]) if (attr.index(a) == len(attr) - 1) else print(domain[a], end=',')
        else:
            click.secho(message)

        if json_file:
            with open(json_file, 'w') as f:
                json.dump(domains, f)

        if csv_file:
            with open(csv_file, 'w', newline='') as f:
                fieldnames = ['name', 'auto_renew', 'contact', 'created', 'dns', 'expired', 'expires', 'id', 'locked',
                              'nameservers', 'privacy', 'registrar', 'remaining', 'resolves_to']
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                for domain in domains:
                    writer.writerow(domain)


if __name__ == '__main__':
    main()

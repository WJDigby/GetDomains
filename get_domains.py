# Disassociating domain retrieval from domain checking
# This script retrieves domains from different providers
# and normalizes the information

# TODO: Filter list for domains applicable?
# TODO: Different output options? (CSV, JSON, stdout, plaintext list)

import configparser
import datetime
import dateutil.parser
import json
import socket
import urllib3

import click
from jinja2 import Environment, BaseLoader
import requests

CONTEXT_SETTINGS = dict(help_option_names=['-h', '--help'])
LOCAL_TIMEZONE = datetime.datetime.now().astimezone().tzinfo
SLACK_TEMPLATE = """
```
╒═════════════════════════╤═════════════╤═════════════╤═══════════╤═══════╤═══════════════════╕
│ Name                    │ Registrar   │ Expires     │ Remaining │ Auto  │ Resolves to       │
╞═════════════════════════╪═════════════╪═════════════╪═══════════╪═══════╪═══════════════════╡ 
{% for domain in domains -%}
│ {{ '%-24s'|format(domain.name[:24]) -}}
│ {{ '%-12s'|format(domain.registrar) -}}
│ {{ '%-12s'|format(domain.expires.strftime('%d %b %Y')) -}}
│ {{ '%-10s'|format(domain.remaining) -}}
│ {{ '%-6s' |format(domain.auto_renew) -}}
│ {{ '%-18s'|format(domain.resolves_to) -}}│
{% endfor -%}
╘═════════════════════════╧═════════════╧═════════════╧═══════════╧═══════╧═══════════════════╛
```
"""


class Domain:
    def __init__(self, name, registrar):
        self.auto_renew = None
        self.contact = None
        self.created = None
        self.dns = None
        self.expires = None
        self.id = None
        self.is_expired = None
        self.locked = None
        self.name = name
        self.nameservers = None
        self.privacy = None
        self.registrar = registrar
        self.remaining = None
        self.resolves_to = None


class AWSClient:
    def __init__(self, proxy, access_key_id, secret_access_key):
        self.domains = []
        self.proxy = {'https': 'http://' + proxy} if proxy else None
        self.verify = False if proxy else True
        self.access_key_id = access_key_id
        self.secret_access_key = secret_access_key
        try:
            import boto3
            from botocore.config import Config as BotoConfig
        except ModuleNotFoundError:
            click.secho('[-] boto3 library not found. Retrieving AWS domains requires boto3.', fg='red', bold=True)
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
            now = datetime.datetime.now(LOCAL_TIMEZONE)
            domain.is_expired = True if now > domain.expires else False
            if not domain.is_expired:  # Capture the remaining registration time in days
                domain.remaining = (domain.expires - now).days
            else:
                domain.remaining = 'Expired'
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
            try:
                domain.resolves_to = socket.gethostbyname(domain.name)
            except socket.gaierror:
                domain.resolves_to = None


class AzureClient:
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
            domain.created = datetime.datetime.strptime(entry['properties']['createdTime'], '%Y-%m-%dT%H:%M:%S')
            domain.expires = datetime.datetime.strptime(entry['properties']['expirationTime'], '%Y-%m-%dT%H:%M:%S')
            now = datetime.datetime.now()
            domain.expired = True if now > domain.expires else False
            if not domain.is_expired:  # Capture the remaining registration time in days
                domain.remaining = (domain.expires - now).days
            else:
                domain.remaining = 'Expired'
            domain.auto_renew = entry['properties']['autoRenew']
            domain.privacy = entry['properties']['privacy']
            domain.dns = entry['properties']['dnsType']
            domain.nameservers = entry['properties']['nameServers']
            try:
                domain.resolves_to = socket.gethostbyname(domain.name)
            except socket.gaierror:
                domain.resolves_to = None
            self.domains.append(domain)


class GoDaddyClient:
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
            now = datetime.datetime.now(LOCAL_TIMEZONE)
            domain.is_expired = True if now > domain.expires else False
            if not domain.is_expired:
                domain.remaining = (domain.expires - now).days
            else:
                domain.remaining = 'Expired'
            domain.locked = entry['locked']
            domain.auto_renew = entry['renewAuto']
            domain.privacy = entry['privacy']
            domain.nameservers = entry['nameServers']
            try:
                domain.resolves_to = socket.gethostbyname(domain.name)
            except socket.gaierror:
                domain.resolves_to = None
            self.domains.append(domain)


class NamecheapClient:
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
    config = configparser.ConfigParser()
    config.read(config_file)
    config_dict = {x: {} for x in config.sections()}
    for section in config.sections():
        for k, v in config[section].items():
            config_dict[section][k] = v
    return config_dict


@click.command(context_settings=CONTEXT_SETTINGS)
@click.option('-p', '--providers',
              type=click.Choice(choices=['AWS', 'Azure', 'GoDaddy', 'Namecheap'], case_sensitive=False), multiple=True,
              help='Specific providers to query. Can list multiple providers each prepended with "-p"')
@click.argument('config', type=click.Path(exists=True))
def main(config, providers):
    """Retrieve domains from different providers.

    CONFIG is the path to the configuration file.

    """

    domains = []

    # Plan to check all providers unless operator selects specific provider(s)
    if not providers:
        providers = ('AWS', 'Azure', 'GoDaddy', 'Namecheap')

    config_dict = read_config(config)

    # Currently no validation of proxy address
    proxy = config_dict['Proxy']['proxy_ip']
    if proxy:
        click.secho('[-] Certificate verification disabled with proxy', fg='red', bold=True)
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    if all(config_dict['AWS'].values()) and 'AWS' in providers:
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

    # Sort domains ascending by number of days remaining
    # To sort by name: domains.sort(key=lambda x: x.name
    domains.sort(key=lambda x: x.remaining)

    # Slack only needs webhook
    if config_dict['Slack']['webhook_url']:  # and domains:
        template = Environment(loader=BaseLoader).from_string(SLACK_TEMPLATE)
        message = template.render(domains=domains)
        slack_client = SlackClient(proxy, message, **config_dict['Slack'])


if __name__ == '__main__':
    main()

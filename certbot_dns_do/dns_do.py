"""DNS Authenticator for Domain-Offensive."""
import logging

import requests
import zope.interface

from certbot import errors
from certbot import interfaces
from certbot.plugins import dns_common

logger = logging.getLogger(__name__)

ACCOUNT_URL = 'https://www.do.de/account/letsencrypt/'
API_URL = 'https://www.do.de/api/letsencrypt'


@zope.interface.implementer(interfaces.IAuthenticator)
@zope.interface.provider(interfaces.IPluginFactory)
class Authenticator(dns_common.DNSAuthenticator):
    """DNS Authenticator for Domain-Offensive

    This Authenticator uses the Domain-Offensive API to fulfill a dns-01 challenge.
    """

    description = ('Obtain certificates using a DNS TXT record (if you are using Domain-Offensive for '
                   'DNS).')

    def __init__(self, *args, **kwargs):
        super(Authenticator, self).__init__(*args, **kwargs)
        self.credentials = None

    @classmethod
    def add_parser_arguments(cls, add):  # pylint: disable=arguments-differ
        super(Authenticator, cls).add_parser_arguments(add)
        add('credentials', help='Domain-Offensive credentials INI file.')

    def more_info(self):  # pylint: disable=missing-docstring,no-self-use
        return 'This plugin configures a DNS TXT record to respond to a dns-01 challenge using ' + \
               'the Domain-Offensive API.'

    def _setup_credentials(self):
        self.credentials = self._configure_credentials(
            'credentials',
            'Domain-Offensive credentials INI file',
            {
                'api-token': 'API token for Domain-Offensive account, obtained from {0}'.format(ACCOUNT_URL)
            }
        )

    def _perform(self, domain, validation_name, validation):
        self._get_do_client().add_txt_record(domain, validation_name, validation)

    def _cleanup(self, domain, validation_name, validation):
        self._get_do_client().del_txt_record(domain, validation_name, validation)

    def _get_do_client(self):
        return _DomainOffensiveClient(self.credentials.conf('api-token'))


class _DomainOffensiveClient(object):
    """
    Encapsulates all communication with the Domain-Offensive API.
    """

    def __init__(self, api_token):
        self.api_token = api_token

    def add_txt_record(self, domain, record_name, record_content):
        """
        Add a TXT record using the supplied information.

        :param str domain: The domain to use to look up the managed zone.
        :param str record_name: The record name (typically beginning with '_acme-challenge.').
        :param str record_content: The record content (typically the challenge validation).
        :param int record_ttl: The record TTL (number of seconds that the record may be cached).
        :raises certbot.errors.PluginError: if an error occurs communicating with the API
        """

        params = {'token': self.api_token,
                'domain': record_name,
                'value': record_content}

        try:
            r = requests.get(API_URL, params=params)
            r.raise_for_status()

            result = r.json()
            if 'success' not in result or result['success'] != True:
                logger.error('Encountered error adding TXT record: not successful')
                raise errors.PluginError('Error adding TXT record: not successful')
        except requests.exceptions.RequestException as e:
            logger.error('Encountered error adding TXT record: %s', e, exc_info=True)
            raise errors.PluginError('Error adding TXT record: {0}'.format(e))

    def del_txt_record(self, domain, record_name, record_content):
        """
        Delete a TXT record using the supplied information.

        Note that both the record's name and content are used to ensure that similar records
        created concurrently (e.g., due to concurrent invocations of this plugin) are not deleted.

        Failures are logged, but not raised.

        :param str domain: The domain to use to look up the managed zone.
        :param str record_name: The record name (typically beginning with '_acme-challenge.').
        :param str record_content: The record content (typically the challenge validation).
        """


        params = {'token': self.api_token,
                'domain': record_name,
                'action': 'delete'}

        try:
            r = requests.get(API_URL, params=params)
            r.raise_for_status()

            result = r.json()
            if 'success' not in result or result['success'] != True:
                logger.error('Encountered error deleting TXT record: not successful')
        except requests.exceptions.RequestException as e:
            logger.error('Encountered error deleting TXT record: %s', e, exc_info=True)

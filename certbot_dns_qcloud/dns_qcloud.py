# -*- coding:utf-8 -*-
"""
    DNS Authenticator for Qcloud
"""
import json
import logging

import zope.interface
from certbot import interfaces
from certbot.plugins import dns_common
from QcloudApi.qcloudapi import QcloudApi

LOGGER = logging.getLogger(__name__)

domain_end = [".com.cn", ".net.cn", ".com", ".net", ".cn"]


def get_domain(domain):
    for i in domain_end:
        if domain.endswith(i):
            return "{}{}".format(domain.replace(i, "").split(".")[-1], i)
    raise NoDomain("can not find domain {}".format(domain))


class NoDomain(Exception):
    def __init__(self, ErrorInfo):
        super().__init__(self)
        self.errorinfo = ErrorInfo

    def __str__(self):
        return self.errorinfo


@zope.interface.implementer(interfaces.IAuthenticator)
@zope.interface.provider(interfaces.IPluginFactory)
class Authenticator(dns_common.DNSAuthenticator):
    """
    Implement the Certbot with Qcloud DNS SDK.
    """

    description = ('Obtain certificates using a DNS TXT record (if you are using Qcloud DNS '
                   'for DNS).')

    def __init__(self, *args, **kwargs):
        super(Authenticator, self).__init__(*args, **kwargs)
        self.credentials = None

    @classmethod
    def add_parser_arguments(cls, add):
        super(Authenticator, cls).add_parser_arguments(add, default_propagation_seconds=60)
        add("credentials",
            help=("Path to local stored Qcloud Access Key &Secret for update DNS record in Qcloud"),
            default=None)

    def more_info(self):
        """
        : show more infos
        """
        return "This plugins setup DNS TXT record for dns-01 challenge by using Qcloud API."

    def _setup_credentials(self):
        self._configure_file("credentials",
                             "path to Qcloud DNS access secret JSON file")
        dns_common.validate_file_permissions(self.conf("credentials"))

    def _perform(self, domain_name, record_name, record_value):
        domain_name = get_domain(domain_name)
        self._get_qclouddns_client().add_txt_record(domain_name, record_name, record_value)

    def _cleanup(self, domain_name, record_name, record_value):
        domain_name = get_domain(domain_name)
        self._get_qclouddns_client().delete_txt_record(domain_name, record_name, record_value)

    def _get_qclouddns_client(self):
        return _QcloudDnsClient(self.conf("credentials"))


TTL = 600
PAGE_SIZE = 100


class _QcloudDnsClient():
    """
    Encapsulates base DNS operation with Qcloud DNS SDK: qcloudsdkalidns.
    """

    def __init__(self, secret_key_path=None):
        try:
            with open(secret_key_path, 'r') as file:
                json_content = file.read()
                self._secretId, self._secretKey = json.loads(json_content)["secretId"], json.loads(json_content)[
                    "secretKey"]
                module = 'cns'
                config = {
                    'secretId': self._secretId,
                    'secretKey': self._secretKey,
                    'method': 'GET',
                    'SignatureMethod': 'HmacSHA1',
                }
            self._client = QcloudApi(module, config)
        except IOError:
            LOGGER.error("Qcloud access secret file: %s not found.", secret_key_path)
        except Exception as error:
            LOGGER.error("Qcloud SDK client init failed: %s.", error)

    def add_txt_record(self, domain_name, record_name, record_value):
        """
        : add TXT domain record for authentication;
        """

        record_name = record_name.replace(("." + domain_name), "")
        action_params = {
            "domain": domain_name,
            "subDomain": record_name,
            "recordType": "TXT",
            "recordLine": "默认",
            "value": record_value,
            "ttl": TTL
        }
        action = 'RecordCreate'
        self._client.generateUrl(action, action_params)
        response = self._client.call(action, action_params)
        LOGGER.info("domain_name: %s, record_name: %s, record_value: %s.", \
                    domain_name, record_name, record_value)
        result = json.loads(str(response, encoding="utf-8"))
        LOGGER.info("add result: %s.", result)

    def delete_txt_record(self, domain_name, record_name, record_value):
        """
        : delete TXT domain record for authentication;
        """

        # describe request for dns record id
        record_id = None
        page_num = 1

        action_params = {
            "domain": domain_name,
            "offset": (page_num - 1) * PAGE_SIZE,
            "length": PAGE_SIZE,
        }
        action = 'RecordList'

        # delete request for delete corresponsing dns record
        # del_request = DeleteDomainRecordRequest.DeleteDomainRecordRequest()
        # del_request.set_accept_format("json")

        record_name = record_name.replace(("." + domain_name), "")
        # des_request.set_DomainName(domain_name)
        self._client.generateUrl(action, action_params)
        response = self._client.call(action, action_params)
        record_first_page_result = json.loads(str(response, encoding="utf-8"))
        # 
        total_record_count = record_first_page_result["data"]["info"]["record_total"]
        if total_record_count < PAGE_SIZE:
            result = record_first_page_result["data"]["records"]
            for record in result:
                if record["type"] == "TXT" and \
                        record["name"] == record_name and \
                        record["value"] == record_value:
                    record_id = record["id"]
                    LOGGER.info("Delete record %s %s-%s, record Id: %s.", \
                                record_name, domain_name, record["value"], record_id)
        else:
            page_num = (total_record_count / PAGE_SIZE) if total_record_count % PAGE_SIZE == 0 \
                else (int(total_record_count / PAGE_SIZE) + 1)
            for page in range(2, page_num + 1):
                action_params = {
                    "domain": domain_name,
                    "offset": (page - 1) * PAGE_SIZE,
                    "length": PAGE_SIZE,
                }
                action = 'RecordList'
                self._client.generateUrl(action, action_params)
                response = self._client.call(action, action_params)
                result = json.loads(str(response, encoding="utf-8"))
                for record in result:
                    if record["type"] == "TXT" and \
                            record["name"] == record_name and \
                            record["value"] == record_value:
                        record_id = record["id"]
                        LOGGER.info("Delete record %s %s-%s, record Id: %s.", \
                                    record_name, domain_name, record["value"], record_id)
                        break
        LOGGER.info("record id: {}.".format(record_id))
        # no record Id no delete operation.
        if record_id:
            action_params = {
                "domain": domain_name,
                "recordId": record_id,
            }
            action = 'RecordDelete'
            self._client.generateUrl(action, action_params)
            response = self._client.call(action, action_params)
            del_result = json.loads(str(response, encoding="utf-8"))
            LOGGER.info("delete result: %s.", del_result)
        else:
            raise Exception("{} {}-{} record cannot be found.".format(
                record_name, domain_name, record["value"]))

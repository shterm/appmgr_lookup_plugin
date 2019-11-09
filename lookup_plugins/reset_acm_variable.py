#!/usr/bin/python
# -*- coding: utf-8 -*-
from ansible.plugins.lookup import LookupBase
from .sdk import pwdlib
class LookupModule(LookupBase):
    def retrieve_secrets(self, terms):
        secrets = []
        if terms is None or len(terms) < 3:
            raise Exception('params is not match required')
        appid = terms[0]
        query = terms[1]
        rtninfo = terms[2]
        #rtn_fields = self.analyize_query_params(rtninfo)
        # ueryPassword(objectName, resourceName, appId, requestReason, credentialFile, port):
        query_params = self.analyize_query_params(query)
        account_name = query_params.get("username", None)
        resouce_name = query_params.get("resourceName", None)
        request_reason = query_params.get("reason", None)
        connect_port = query_params.get("connectPort", 0)
        account_info = pwdlib.PasswordExecutor.queryPassword(account_name, resouce_name, appid, request_reason, None, connect_port)
        really_account = account_info['objectName']
        really_password = account_info['objectContent']
        secret = {'password':really_password, 'account':really_account}
        secrets.append(secret)
        return secrets

    def analyize_query_params(self, query_param):
        """
        str splits with;
        each item was splited by =
        :param query_param:     the params
        :return:
        """
        if not query_param:
            raise Exception('query is empty')

        keyValues = query_param.split(';')
        convert_params = dict()
        for item in keyValues:
            keyValue=item.split("=")
            if len(keyValue) != 2:
                continue
            convert_params[keyValue[0]] = keyValue[1]

        return convert_params

    def analyize_rtn_info(self, rtnInfo):
        """
        analysis the info from the query
        :param rtnInfo: Expect the field to be returned
        :return: list type
        """
        return rtnInfo.split(';')

    def run(self, terms, variables=None, **kwargs):
        return self.retrieve_secrets(terms)

#!/usr/bin/env python3

"""
ArduKey authserver
@author Bastian Raschke

Copyright 2014 Bastian Raschke.
All rights reserved.
"""

import time
import hmac
import hashlib
import urllib.parse


class ValidationRequest(object):
    """
    Server response wrapper class

    @attribute string __response
    The validation response.

    """

    __response = {}

    def __init__(self, requestParameters):
        """
        Constructor

        @param string requestParameters The request query dictionary.
        """


        ## Input:
        ## otp, nonce, apiId, hmac
        ## eg.: http://127.0.0.1:8080/ardukeyotp/1.0/verify?otp=xxx&nonce=xxx&apiId=1000&hmac=xxx

        ## Output:
        ## status, otp, nonce, datetime, hmac

        try:
            otp = urllib.parse.quote(requestParameters['otp'])
            nonce = urllib.parse.quote(requestParameters['nonce'])
            apiId = urllib.parse.quote(requestParameters['apiId'])
            hmac = urllib.parse.quote(requestParameters['hmac'])

        except KeyError as e:

            self.__response['otp'] = ''
            self.__response['nonce'] = ''
            self.__response['time'] = time.strftime("%Y-%m-%dT%H:%M:%S")
            self.__response['status'] = 'MISSING_PARAMETER'

    def getResponse(self):
        """
        Returns the complete response dictionary.

        @return dictionary
        """

        ## Unset old hmac
        self.__response['hmac'] = ''

        responseData = ''

        ## Collects data to calculate hmac
        for element in self.__response.values():
            responseData += element

        ## TODO: Get secret from database
        sharedSecret = 'SECRET-HERE'.encode('utf-8')
        responseData = responseData.encode('utf-8')

        ## Calculates HMAC of current response
        self.__response['hmac'] = hmac.new(sharedSecret, msg=responseData, digestmod=hashlib.sha256).hexdigest()

        return self.__response

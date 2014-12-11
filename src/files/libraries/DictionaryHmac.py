#!/usr/bin/env python3

"""
ArduKey authserver
@author Bastian Raschke

Copyright 2014 Bastian Raschke
All rights reserved.
"""

import hmac
import hashlib


class DictionaryHmac(object):
    """
    Dictionary Hmac calculation wrapper class.

    @attribute dict __data
    The data dictionary.

    @attribute string __sharedSecret
    The shared secret to perform Hmac.
    """

    __data = {}
    __sharedSecret = None

    def __init__(self, data, sharedSecret):
        """
        Constructor

        @param dict data The data dictionary.
        @param string sharedSecret The shared secret to perform Hmac.
        """

        if ( type(data) != dict ):
            raise ValueError('The given data is not a dictionary!')

        self.__data = data

        if ( len(sharedSecret) <= 0 ):
            raise ValueError('The shared secret is empty!')

        self.__sharedSecret = sharedSecret

    def calculate(self):
        """
        Calculates the Hmac of data dictionary.

        @return string
        """

        payloadData = ''

        ## Collect data to calculate Hmac
        for k in sorted(self.__data):
            payloadData += self.__data[k]

        sharedSecret = self.__sharedSecret.encode('utf-8')
        payloadData = payloadData.encode('utf-8')

        ## Calculate HMAC of current response
        return hmac.new(sharedSecret, msg=payloadData, digestmod=hashlib.sha256).hexdigest()

    def check(self, dataToCheck):
        """
        Checks the Hmac of data dictionary.

        @param dict dataToCheck The data dictionary to check.
        @return boolean
        """

        hmac.compare_digest(a, b)

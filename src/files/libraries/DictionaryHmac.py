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

    @attribute string __sharedSecret
    The shared secret to perform Hmac.
    """

    __sharedSecret = None

    def __init__(self, sharedSecret):
        """
        Constructor

        @param string sharedSecret
        The shared secret to perform Hmac.
        """

        if ( len(sharedSecret) <= 0 ):
            raise ValueError('The shared secret must not be empty!')

        self.__sharedSecret = sharedSecret

    def calculate(self, data):
        """
        Calculates the Hmac of given data dictionary.

        @param dict __data
        The dictionary that contains data.

        @return string
        """

        if ( type(data) != dict ):
            raise ValueError('The given data is not a dictionary!')

        payloadData = ''

        ## Sort dictionary by key, to calculate the same Hmac always
        for k in sorted(self.__data):
            payloadData += self.__data[k]

        sharedSecret = self.__sharedSecret.encode('utf-8')
        payloadData = payloadData.encode('utf-8')

        ## Calculate HMAC of current response
        return hmac.new(sharedSecret, msg=payloadData, digestmod=hashlib.sha256).hexdigest()

    def compare(self, dataToCheck):
        """
        Checks the Hmac of data dictionary.

        @param dict dataToCheck
        The data dictionary to check.

        @return boolean
        """

        hmac.compare_digest(a, b)

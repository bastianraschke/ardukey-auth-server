#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
ArduKey authserver
@author Bastian Raschke <bastian.raschke@posteo.de>

Copyright 2015 Bastian Raschke
All rights reserved.
"""

import hmac, hashlib


class Hmac(object):
    """
    Calculates Hmac of given data and returns it as a hexadecimal string.

    @attribute string __sharedSecret
    The shared secret of API key.

    @return string
    """

    __sharedSecret = ''

    def __init__(self, sharedSecret = ''):
        """
        Constructor

        @attribute string filePath
        The path to the configuration file.
        """

        ## Checks if shared secret is given
        if ( len(sharedSecret) == 0 ):
            raise ValueError('No shared secret given to perform Hmac calculation!')

        self.__sharedSecret = sharedSecret

    def calculateHmac(self, data):
        """
        Calculates Hmac of given dictionary and returns it as a hexadecimal string.

        @param dict data
        The dictionary that contains data.

        @return string
        """

        ## Only process dictionaries
        if ( type(data) != dict ):
            raise ValueError('The given data is not a dictionary!')

        dataString = ''

        ## Sort dictionary by key, to calculate the same Hmac always
        for k in sorted(data):
            dataString += str(data[k])

        sharedSecret = self.__sharedSecret.encode('utf-8')
        dataString = dataString.encode('utf-8')

        ## Calculate Hmac of payload
        return hmac.new(sharedSecret, msg=dataString, digestmod=hashlib.sha256).hexdigest()

#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
ArduKey authserver
@author Bastian Raschke <bastian.raschke@posteo.de>

Copyright 2015 Bastian Raschke
All rights reserved.
"""

import urllib.parse


class OTPVerificationRequest(object):
    """
    ArduKey OTP verification request abstration.

    @attribute dict __parameters
    The request parameters.
    """

    __parameters = {}
    __hmac = ''

    def __init__(self, queryString):
        """
        Constructor

        @param string queryString
        The query string of the request.
        """

        ## Parse all query arguments to dictionary
        parameters = urllib.parse.parse_qs(queryString, keep_blank_values=True)

        ## Sanitize all given parameters
        for k in parameters:
            self.__parameters[k] = urllib.parse.quote(parameters[k][0])

        ## Unset hmac parameter if available
        self.__hmac = self.__parameters.pop('hmac', '')

    def getParameters(self):
        """
        Returns the request parameters.

        @return dict
        """

        return self.__parameters

    def getHmac(self):
        """
        Returns the request Hmac.

        @return str
        """

        return self.__hmac
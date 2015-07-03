#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
ArduKey auth-server

Copyright 2015 Bastian Raschke <bastian.raschke@posteo.de>
All rights reserved.
"""

import urllib.parse


class OTPVerificationRequest(object):
    """
    ArduKey OTP verification request abstration.

    @attribute dict __parameters
    The request parameters.

    @attribute str __hmac
    The request hmac.
    """

    def __init__(self, queryString):
        """
        Constructor

        @param str queryString
        The query string of the request.
        """

        self.__parameters = {}
        self.__hmac = ''

        ## Parse all query arguments to dictionary
        parameters = urllib.parse.parse_qs(queryString, keep_blank_values=True)

        ## Sanitize all given parameters
        for k in parameters:
            self.__parameters[k] = urllib.parse.quote(parameters[k][0])

        ## Unset hmac parameter if available
        self.__hmac = self.__parameters.pop('hmac', '')

    def getParameters(self):
        """
        Return the request parameters.

        @return dict
        """

        return self.__parameters

    def getHmac(self):
        """
        Return the request Hmac.

        @return str
        """

        return self.__hmac

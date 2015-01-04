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

    @attribute dict __request
    The request dictionary.
    """

    __request = {}

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
            self.__request[k] = urllib.parse.quote(self.request[k][0])

    def getRequest(self):
        """
        Returns the secure (sanitized) request.

        @return dictionary
        """

        return self.__request

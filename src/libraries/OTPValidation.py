#!/usr/bin/env python3

"""
ArduKey authserver
@author Bastian Raschke

Copyright 2014 Bastian Raschke.
All rights reserved.
"""

import re


class OTPValidation(object):
    """
    ArduKey OTP validation.

    @attribute string __publicId
    The public id part of the OTP.

    @attribute string __token
    The token part of the OTP.
    """

    __publicId = ''
    __token = ''

    def __init__(self, otp):
        """
        Constructor

        @param string otp The OTP to validate.
        """

        otpLength = len(otp)

        ## Pre-regex length check
        if ( otpLength < 32 or otpLength > 44 ):
            raise ValueError('The OTP is too short or long!')

        otpRegex = '^([cbdefghijklnrtuv]{0,12})([cbdefghijklnrtuv]{32})$'

        if ( re.search(otpRegex, otp) != None ):
            raise ValueError('The OTP has an invalid format!')

        self.__publicId = re.group(1)
        self.__token = re.group(2)






    def validate(self):
        """
        Validates the OTP.

        @return boolean
        """

        ## rawtoken: b0d4a2d69bc4 2000 04 07004f 9899 d99a



        return False

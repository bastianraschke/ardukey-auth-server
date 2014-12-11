#!/usr/bin/env python3

"""
ArduKey authserver
@author Bastian Raschke

Copyright 2014 Bastian Raschke
All rights reserved.
"""

import time
import urllib.parse
import re

from libraries.AESWrapper import AESWrapper
from libraries.DictionaryHmac import DictionaryHmac
from libraries.SQLiteWrapper import SQLiteWrapper


class Validation(object):
    """
    OTP validation class.

    @attribute string __sharedSecret
    The shared secret of API user.

    @attribute dict __response
    The response dictionary - means the result of validation request.
    """


    __response = {}

    def __init__(self, request):
        """
        Constructor

        @param dict request The request query as dictionary.
        """

        isoDateTime = time.strftime("%Y-%m-%dT%H:%M:%S")

        try:
            ## Try to get request parameters
            otp = urllib.parse.quote(request['otp'][0])
            nonce = urllib.parse.quote(request['nonce'][0])
            apiId = urllib.parse.quote(request['apiId'][0])
            requestHMAC = urllib.parse.quote(request['hmac'][0])

            ## TODO: Check hmac of request

            ## Try to validate OTP
            if ( self.__validateOTP(otp) == True ):
                self.__response['otp'] = otp
                self.__response['nonce'] = nonce
                self.__response['time'] = isoDateTime
                self.__response['status'] = 'OK'

            else:
                self.__response['otp'] = otp
                self.__response['nonce'] = nonce
                self.__response['time'] = isoDateTime
                self.__response['status'] = 'FAILED'

        ## The OTP has an invalid format
        except ValueError as e:
            self.__response['otp'] = otp
            self.__response['nonce'] = nonce
            self.__response['time'] = isoDateTime
            self.__response['status'] = 'INVALID_OTP'

        ## The request signature (HMAC) failed
        ## except SignatureError as e:
        ##     self.__response['otp'] = otp
        ##     self.__response['nonce'] = nonce
        ##     self.__response['time'] = isoDateTime
        ##     self.__response['status'] = 'INVALID_SIGNATURE'

        ## Some parameters are not okay:
        except KeyError as e:
            self.__response['otp'] = ''
            self.__response['nonce'] = ''
            self.__response['time'] = isoDateTime
            self.__response['status'] = 'MISSING_PARAMETER'

        ## General errors
        ## except Exception as e:
        ##     self.__response['otp'] = ''
        ##     self.__response['nonce'] = ''
        ##     self.__response['time'] = isoDateTime
        ##     self.__response['status'] = 'SERVER_ERROR'

    def __validateOTP(self, otp):
        """
        Validates the OTP.

        @param string otp The OTP to validate.
        @return boolean
        """

        otpLength = len(otp)

        ## Pre-regex length check
        if ( otpLength != 44 ):
            raise ValueError('The OTP is too short or long!')

        otpRegex = '^([cbdefghijklnrtuv]{12})([cbdefghijklnrtuv]{32})$'

        ## Regex general format check
        if ( re.search(otpRegex, otp) == None ):
            raise ValueError('The OTP has an invalid format!')

        publicId = re.group(1)
        encryptedToken = re.group(2)

        ## Regex elements format check
        if ( publicId == None or encryptedToken == None ):
            raise ValueError('The OTP has an invalid format!')

        database = SQLiteWrapper.getInstance()

        ## Query public id in database and get AES key and shared secret
        ## raise ValueError('The public id was not found in database!')
        ## raise ValueError('The ArduKey has been revoked!')
        ## TODO

        aesKey = ''
        self.__sharedSecret = ''

        aes = AESWrapper(aesKey)
        rawToken = aes.decrypt(encryptedToken)

        ## TODO: Check if secret id matches to pub id

        ## rawtoken: b0d4a2d69bc4 2000 04 07004f 9899 d99a

        return False




    def getResponse(self):
        """
        Returns the complete response dictionary.

        @return dictionary
        """

        ## Unset old hmac
        ## TODO: remove element from dict?
        self.__response['hmac'] = ''

        ## Only perform operation if shared secret is available
        if ( self.__sharedSecret != None ):

            ## Calculate HMAC of current response
            dictionaryHmac = DictionaryHmac(self.__response, self.__sharedSecret)
            self.__response['hmac'] = dictionaryHmac.calculate()

        return self.__response

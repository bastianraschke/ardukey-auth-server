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
import re

from libraries.AES import AES
from libraries.SQLiteWrapper import SQLiteWrapper


class ValidationRequest(object):
    """
    Server response wrapper class.

    @attribute string __response
    The validation response.

    """

    __sharedSecret = None
    __response = {}

    def __init__(self, requestParameters):
        """
        Constructor

        @param string requestParameters The request query dictionary.
        """

        isoDateTime = time.strftime("%Y-%m-%dT%H:%M:%S")

        try:
            ## Try to get request parameters
            otp = urllib.parse.quote(requestParameters['otp'][0])
            nonce = urllib.parse.quote(requestParameters['nonce'][0])
            apiId = urllib.parse.quote(requestParameters['apiId'][0])
            requestHMAC = urllib.parse.quote(requestParameters['hmac'][0])

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



        ## Query public id in database and get AES key and shared secret
        ## raise ValueError('The public id was not found in database!')
        ## raise ValueError('The ArduKey has been revoked!')
        ## TODO

        aesKey = ''
        self.__sharedSecret = ''

        aes = AES(aesKey)
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
        self.__response['hmac'] = ''

        ## Only perform operation if shared secret is available
        if ( self.__sharedSecret != None ):

            responseData = ''

            ## Collect data to calculate hmac
            for element in self.__response.values():
                responseData += element

            sharedSecret = self.__sharedSecret.encode('utf-8')
            responseData = responseData.encode('utf-8')

            ## Calculate HMAC of current response
            self.__response['hmac'] = hmac.new(sharedSecret, msg=responseData, digestmod=hashlib.sha256).hexdigest()

        return self.__response

database = SQLiteWrapper.getInstance()

#!/usr/bin/env python3

"""
ArduKey authserver
@author Bastian Raschke

Copyright 2014 Bastian Raschke
All rights reserved.
"""

import time
import urllib.parse
import hmac, hashlib
import re

from libraries.AESWrapper import AESWrapper
from libraries.SQLiteWrapper import SQLiteWrapper


class NoAPIKeyAvailableError(Exception):
    """
    Dummy exception class for not available API key for Hmac signature check.

    """

    pass

class BadHmacSignatureError(Exception):
    """
    Dummy exception class for bad Hmac signature check.

    """

    pass

class ArduKeyVerification(object):
    """
    ArduKey OTP verification class.

    @attribute string __sharedSecret
    The shared secret of API user.

    @attribute dict __response
    The response dictionary (the result of validation request).
    """

    __sharedSecret = ''
    __response = {}

    def __init__(self, request):
        """
        Constructor

        @param dict request
        The request query as dictionary.
        """

        self.__validateRequest(request)

    def __calculateHmac(self, data):
        """
        Calculates a hexadecimal Hmac of given data dictionary.

        @param dict data
        The dictionary that contains data.

        @return string
        """

        ## Only process dictionaries
        if ( type(data) != dict ):
            raise ValueError('The given data is not a dictionary!')

        ## Checks if shared secret is given
        if ( len(self.__sharedSecret) == 0 ):
            raise ValueError('No shared secret given!')

        payloadData = ''

        ## Sort dictionary by key, to calculate the same Hmac always
        for k in sorted(data):
            payloadData += data[k]

        sharedSecret = self.__sharedSecret.encode('utf-8')
        payloadData = payloadData.encode('utf-8')

        ## Calculate HMAC of current response
        return hmac.new(sharedSecret, msg=payloadData, digestmod=hashlib.sha256).hexdigest()

    def __convertModHex(self, modhexData):
        """
        Converts a modhex string to hexadecimal string.

        @param string modhexData
        The modhex string to convert.

        @return string
        """

        ## TODO
        return modhexData

    def __validateRequest(self, request):

        try:
            ## Try to get request parameters
            otp = urllib.parse.quote(request['otp'][0])
            nonce = urllib.parse.quote(request['nonce'][0])
            apiId = urllib.parse.quote(request['apiId'][0])
            requestHmac = urllib.parse.quote(request['hmac'][0])







            ## Get shared secret to verify request Hmac
            SQLiteWrapper.getInstance().cursor.execute('SELECT secret FROM API WHERE id=?', [
                apiId,
            ])

            rows = SQLiteWrapper.getInstance().cursor.fetchall()

            if ( len(rows) > 0 ):
                self.__sharedSecret = rows[0][0]
            else:
                raise NoAPIKeyAvailableError('No API key available for Hmac signature check!')

            request = {}
            request['otp'] = otp
            request['nonce'] = nonce
            request['apiId'] = apiId

            calculatedRequestHmac = self.__calculateHmac(request)

            ## TODO
            ## Compare Hmac via special method to prevent potential timing attacks
            ## if ( hmac.compare_digest(requestHmac, calculatedRequestHmac) == False ):

            ## TODO
            print(calculatedRequestHmac)

            if ( requestHmac != calculatedRequestHmac ):
                raise BadHmacSignatureError('The request Hmac signature is invalid!')

            ## Try to validate OTP
            if ( self.__validateOTP(otp) == True ):
                self.__response['otp'] = otp
                self.__response['nonce'] = nonce
                self.__response['status'] = 'OK'

            else:
                self.__response['otp'] = otp
                self.__response['nonce'] = nonce
                self.__response['status'] = 'INVALID'

        ## The OTP has an invalid format
        ## except ValueError:
        ##     self.__response['otp'] = otp
        ##     self.__response['nonce'] = nonce
        ##     self.__response['status'] = 'CURRUPTED'

        ## The API key was not found
        except NoAPIKeyAvailableError:
            self.__response['otp'] = otp
            self.__response['nonce'] = nonce
            self.__response['status'] = 'NO_APIKEY_AVAILABLE'

        ## The request Hmac signature is bad
        except BadHmacSignatureError:
            self.__response['otp'] = otp
            self.__response['nonce'] = nonce
            self.__response['status'] = 'BAD_SIGNATURE'

        ## Some parameters are not okay:
        except KeyError:
            self.__response['otp'] = ''
            self.__response['nonce'] = ''
            self.__response['status'] = 'MISSING_PARAMETER'

        ## General errors
        ## except:
        ##     self.__response['otp'] = ''
        ##     self.__response['nonce'] = ''
        ##     self.__response['status'] = 'UNKNOWN_ERROR'

    def __validateOTP(self, otp):
        """
        Validates the OTP.

        @param string otp
        The OTP to validate.

        @return boolean
        """

        otpLength = len(otp)

        ## Pre-regex length check
        if ( otpLength != 44 ):
            raise ValueError('The OTP has an invalid length!')

        otpRegex = '^([cbdefghijklnrtuv]{12})([cbdefghijklnrtuv]{32})$'
        otpRegexSearch = re.search(otpRegex, otp)

        ## Regex general format check
        if ( otpRegexSearch == None ):
            raise ValueError('The OTP has an invalid format!')

        ## Try to extract public id and token from OTP
        try:
            publicId = otpRegexSearch.group(1)
            encryptedToken = otpRegexSearch.group(2)

        except:
            raise ValueError('The OTP does not contain public id or token!')

        ## Convert public id and token to default hexadecimal string representation
        publicId = self.__convertModHex(publicId)
        encryptedToken = self.__convertModHex(encryptedToken)

        ## Gets database object instance
        database = SQLiteWrapper.getInstance()

        ## Query publicid, secretid, counter, timestamp in database and get AES key and shared secret
        ## raise Exception('The public id was not found in database!')
        ## raise Exception('The ArduKey has been revoked!')
        ## TODO

        """
        SELECT secretid, counter, timestamp, aesKey
        FROM ardukeyotp
        WHERE publicid = ?
        """

        aesKey = '7A1858592FCB76BD5EB2685421AED45E'
        self.__sharedSecret = ''

        aes = AESWrapper(aesKey)
        rawToken = aes.decrypt(encryptedToken)

        ## rawtoken: b0d4a2d69bc4 2000 04 07004f 9899 d99a

        ## TODO: Check if secret id matches to pub id
        ## TODO: Check counter value
        ## TODO: Check timestamp

        return False

    def getResponse(self):
        """
        Returns the complete response.

        @return dictionary
        """

        ## Sets current datetime
        self.__response['time'] = time.strftime("%Y-%m-%dT%H:%M:%S")

        ## Unset old hmac
        ## Important: Do not remove element, cause if no Hmac signature is possible,
        ## the element always must be available in response!
        self.__response['hmac'] = ''

        ## Only perform operation if shared secret is available
        if ( len(self.__sharedSecret) > 0 ):

            ## Calculate HMAC of current response
            self.__response['hmac'] = self.__calculateHmac(self.__response)

        return self.__response

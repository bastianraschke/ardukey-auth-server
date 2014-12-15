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


class NoAPIIdAvailableError(Exception):
    """
    Dummy exception class for not available API id.

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
    __response = {'otp': '', 'nonce': '', 'time': '', 'status': '', 'hmac': ''}

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
            payloadData += str(data[k])

        sharedSecret = self.__sharedSecret.encode('utf-8')
        payloadData = payloadData.encode('utf-8')

        ## Calculate HMAC of current response
        return hmac.new(sharedSecret, msg=payloadData, digestmod=hashlib.sha256).hexdigest()

    def __decodeArduHex(self, data):
        """
        Converts a arduhex input string to hexadecimal string.

        @param string data
        The arduhex string to convert.

        @return string
        """

        ## Convert data to lowercase
        data = data.lower()

        ## Hexadecimal table
        hexTable = '0123456789abcdef'

        ## TODO: Own table
        ## ArduKey transformation table
        arduhexMappingTable = 'cbdefghijklnrtuv'

        result = ''

        for i in range(0, len(data)):

            position = arduhexMappingTable.find(data[i])

            ## Checks if character was found
            if ( position == -1 ):
                raise ValueError('The given input contains a non-valid character!')
            else:
                result += hexTable[position]

        return result

    def __calculateCRC16(self, data):
        """
        Calculates the CRC16 checksum for given data.

        @param string data
        The data used for calculation.

        @return string
        """

        return 'TODO'

    def __validateRequest(self, request):
        """
        Validates a given request.

        @param dict request
        The request to validate.

        @return void
        """

        try:
            ## Try to get request parameters
            otp = urllib.parse.quote(request['otp'][0])
            nonce = urllib.parse.quote(request['nonce'][0])
            apiId = urllib.parse.quote(request['apiId'][0])
            requestHmac = urllib.parse.quote(request['hmac'][0])


            self.__response['otp'] = otp
            self.__response['nonce'] = nonce

            request = {}
            request['otp'] = otp
            request['nonce'] = nonce
            request['apiId'] = apiId


            ## Get shared secret of API Id to verify request
            SQLiteWrapper.getInstance().cursor.execute(
                'SELECT secret FROM API WHERE id = ?', [
                apiId,
            ])

            rows = SQLiteWrapper.getInstance().cursor.fetchall()

            if ( len(rows) > 0 ):
                self.__sharedSecret = rows[0][0]
            else:
                raise NoAPIIdAvailableError('The API id was not found in database!')



            calculatedRequestHmac = self.__calculateHmac(request)
            print('DEBUG: calculatedRequestHmac = ' + calculatedRequestHmac)

            ## Compare hashes
            ## Unfortunatly the hmac.compare_digest() method is only available in Python 3.3+
            if ( requestHmac != calculatedRequestHmac ):
                raise BadHmacSignatureError('The request Hmac signature is invalid!')

            ## Try to validate OTP
            if ( self.__validateOTP(otp) == True ):
                self.__response['status'] = 'OK'

            else:
                self.__response['status'] = 'INVALID_OTP'

        except ValueError:
            ## The OTP has an invalid format
            self.__response['status'] = 'CURRUPTED_OTP'

        except NoAPIIdAvailableError:
            ## The API id was not found
            self.__response['status'] = 'API_ID_NOTFOUND'

        except BadHmacSignatureError:
            ## The request Hmac signature is bad
            self.__response['status'] = 'INVALID_SIGNATURE'

        except KeyError:
            ## Some parameters are not okay
            self.__response['status'] = 'MISSING_PARAMETER'

        ## General errors
        ## except:
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
        publicId = self.__decodeArduHex(publicId)
        encryptedToken = self.__decodeArduHex(encryptedToken)

        ## Get needed information from database
        SQLiteWrapper.getInstance().cursor.execute(
            'SELECT secretid, counter, timestamp, aeskey, status FROM OTP WHERE publicid = ?', [
            publicId,
        ])

        rows = SQLiteWrapper.getInstance().cursor.fetchall()

        if ( len(rows) > 0 ):
            secretId = rows[0][0]
            oldCounter = int(rows[0][1])
            oldTimestamp = int(rows[0][2])
            aesKey = rows[0][3]
            status = int(rows[0][4])
        else:
            print('DEBUG: No OTP found in database')
            ## No OTP found in database
            return False

        ## Check status of ArduKey (maybe it is revoked)
        if ( status == 0 ):
            print('DEBUG: OTP has been revoked!')
            ## The ArduKey has been revoked!
            return False

        ## Decrypt encrypted token
        rawToken = AESWrapper(aesKey).decrypt(encryptedToken)

        print('DEBUG: rawToken = ' + str(rawToken))

        ## TODO: CRC16 check

        ## TODO
        ## Checks if database secretid matches to OTP value
        ## if ()

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

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

    def __init__(self, requestQuery):
        """
        Constructor

        @param dict requestQuery
        The request query as dictionary.
        """

        self.__processRequest(request)

    def __processRequest(self, requestQuery):
        """
        Validates a given request.

        @param dict requestQuery
        The request to process.

        @return void
        """

        try:
            ## Try to get request parameters
            request = {}
            request['otp'] = urllib.parse.quote(requestQuery['otp'][0])
            request['nonce'] = urllib.parse.quote(requestQuery['nonce'][0])
            request['apiId'] = urllib.parse.quote(requestQuery['apiId'][0])

            ## Do not insert request Hmac to request dictionary, to exclude it from Hmac calculation
            requestHmac = urllib.parse.quote(requestQuery['hmac'][0])

            ## Simply send OTP and nonce back to requester
            self.__response['otp'] = request['otp']
            self.__response['nonce'] = request['nonce']

            ## Get shared secret of given API id
            SQLiteWrapper.getInstance().cursor.execute(
                'SELECT secret FROM API WHERE id = ?', [
                request['apiId'],
            ])

            rows = SQLiteWrapper.getInstance().cursor.fetchall()

            if ( len(rows) > 0 ):
                self.__sharedSecret = rows[0][0]
            else:
                raise NoAPIIdAvailableError('The API id was not found in database!')

            ## Calculates Hmac of request to verify authenticity
            calculatedRequestHmac = self.__calculateHmac(request)
            print('DEBUG: calculatedRequestHmac = ' + calculatedRequestHmac)

            ## Compare request Hmac hashes
            ## Note: Unfortunatly the hmac.compare_digest() method is only available in Python 3.3+
            if ( requestHmac != calculatedRequestHmac ):
                raise BadHmacSignatureError('The request Hmac signature is invalid!')

            ## Try to verity OTP
            if ( self.__verifyOTP(request['otp']) == True ):
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

        ## except:
        ##     ## General errors
        ##     self.__response['status'] = 'UNKNOWN_ERROR'

    def __calculateHmac(self, data):
        """
        Calculates Hmac of given dictionary and returns it as a hexadecimal string.

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

        dataString = ''

        ## Sort dictionary by key, to calculate the same Hmac always
        for k in sorted(data):
            dataString += str(data[k])

        sharedSecret = self.__sharedSecret.encode('utf-8')
        dataString = dataString.encode('utf-8')

        ## Calculate Hmac of payload
        return hmac.new(sharedSecret, msg=dataString, digestmod=hashlib.sha256).hexdigest()

    def __decodeArduHex(self, arduhexString):
        """
        Converts a given arduhex string to hexadecimal string.

        @param string arduhexString
        The arduhex string to convert.

        @return string
        """

        ## TODO

        ## Convert input string to lowercase
        arduhexString = arduhexString.lower()

        ## Hexadecimal table
        hexTable = '0123456789abcdef'

        ## TODO: Own table
        ## ArduKey transformation table
        arduhexTable = 'cbdefghijklnrtuv'

        result = ''

        for i in range(0, len(arduhexString)):

            position = arduhexTable.find(arduhexString[i])

            ## Checks if character was found
            if ( position == -1 ):
                raise ValueError('The given input contains a non-valid character!')
            else:
                result += hexTable[position]

        return result

    def __calculateCRC16(self, hexString):
        """
        Calculates the CRC16-CCITT (0xFFFF) checksum of given a hexadecimal string.

        @param string hexString
        The hexadecimal string used by calculation.

        @return string TODO
        """

        crc = 0xFFFF

        for i in range(0, len(hexString)):

            index = i*2
            currentByte = int(hexString[index:index+2], 16)

            x = (crc >> 8) ^ currentByte
            x = x ^ (x >> 4)

            crc = (crc << 8) ^ (x << 12) ^ (x << 5) ^ x;
            crc = crc & 0xFFFF

        return crc

    def __verifyOTP(self, otp):
        """
        Validates the OTP.

        @param string otp
        The OTP to validate.

        @return boolean
        """

        otpLength = len(otp)

        ## Pre-Regex length check
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

        ## Convert public id and encrypted token to default hexadecimal string representation
        publicId = self.__decodeArduHex(publicId)
        encryptedToken = self.__decodeArduHex(encryptedToken)

        ## Get required information from database
        SQLiteWrapper.getInstance().cursor.execute(
            'SELECT secretid, sessioncounter, counter, timestamp, aeskey, status FROM OTP WHERE publicid = ?', [
            publicId,
        ])

        rows = SQLiteWrapper.getInstance().cursor.fetchall()

        if ( len(rows) > 0 ):
            secretId = rows[0][0]
            oldCounter = int(rows[0][1])
            oldSessionCounter = int(rows[0][2])
            oldTimestamp = int(rows[0][3])
            aesKey = rows[0][4]
            status = int(rows[0][5])
        else:
            print('DEBUG: No OTP found in database')
            return False

        ## Check if ArduKey is disabled (revoked, ...)
        if ( status == 0 ):
            print('DEBUG: The ArduKey has been disabled!')
            return False

        ## Decrypt encrypted token
        decryptedToken = AESWrapper(aesKey).decrypt(encryptedToken)
        print('DEBUG: decryptedToken = ' + str(decryptedToken))

        ## Example token: b0d4a2d69bc4 2000 04 07004f 9899 d99a
        ## b0d4a2d69bc420000407004f9899d99a

        ## TODO
        token = {}
        token['secretId'] = decryptedToken[0:12+1]
        token['sessionCounter'] = int(decryptedToken[28:32+1], 16)
        token['counter'] = int(decryptedToken[28:32+1], 16)
        token['timestamp'] = int(decryptedToken[28:32+1], 16)
        token['crc'] = int(decryptedToken[28:32+1], 16)

        ## Calculate CRC16 checksum of token
        calculatedCRC = self.__calculateCRC16(decryptedToken[0:28])

        ## Compare the OTP and calculated checksum
        if ( token['crc'] != calculatedCRC ):
            print('DEBUG: The CRC checksum of OTP is not correct!')
            return False

        ## Checks if database secretid matches to value in OTP
        if ( token['secretId'] != secretId ):
            print('DEBUG: The secret id is not the same as in database!')
            return False

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
        ## the element must be available in response nevertheless!
        self.__response['hmac'] = ''

        ## Only perform operation if shared secret is available
        if ( len(self.__sharedSecret) > 0 ):

            ## Calculate HMAC of current response
            self.__response['hmac'] = self.__calculateHmac(self.__response)

        return self.__response

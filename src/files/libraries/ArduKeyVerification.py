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

        self.__processRequest(requestQuery)

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
                'SELECT secret FROM API WHERE id = ? AND enabled = 1', [
                request['apiId'],
            ])

            rows = SQLiteWrapper.getInstance().cursor.fetchall()

            if ( len(rows) > 0 ):
                self.__sharedSecret = rows[0][0]
            else:
                raise NoAPIIdAvailableError('No valid API id found in database!')

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

        @return integer
        """

        hexStringLength = len(hexString)

        if ( hexStringLength % 2 != 0 ):
            raise ValueError('The given hexadecimal string is not valid!')

        ## The count of bytes in hexadecimal string
        byteCount = int(hexStringLength / 2)

        crc = 0xFFFF

        for i in range(0, byteCount):

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

        ## Try to get required information from database
        try:
            SQLiteWrapper.getInstance().cursor.execute(
                'SELECT secretid, counter, sessioncounter, timestamp, aeskey FROM ARDUKEY WHERE publicid = ? AND enabled = 1', [
                publicId,
            ])

            rows = SQLiteWrapper.getInstance().cursor.fetchall()

        except Exception as e:
            print('DEBUG: Error occured while database operation: ' + str(e))
            return False

        ## TODO: In previous exception block?
        if ( len(rows) > 0 ):
            secretId = rows[0][0].lower()
            oldCounter = int(rows[0][1])
            oldSessionCounter = int(rows[0][2])
            oldTimestamp = int(rows[0][3])
            aesKey = rows[0][4]
        else:
            print('DEBUG: No valid ArduKey found in database!')
            return False

        ## Decrypt encrypted token
        decryptedToken = AESWrapper(aesKey).decrypt(encryptedToken)
        print('DEBUG: decryptedToken = ' + decryptedToken)

        ## TODO: Big/Little endian description
        token = {}
        token['secretId'] = decryptedToken[0:12]
        token['counter'] = int(decryptedToken[14:16] + decryptedToken[12:14], 16)
        token['sessionCounter'] = int(decryptedToken[16:18], 16)

        token['timestamp'] = int(decryptedToken[18:20] + decryptedToken[20:22] + decryptedToken[22:24], 16)
        token['crc'] = int(decryptedToken[30:32] + decryptedToken[28:30], 16)

        print('secretId = ' + token['secretId'])
        print('sessionCounter = ' + hex(token['sessionCounter']))
        print('counter = ' + hex(token['counter']))
        print('timestamp = ' + hex(token['timestamp']))
        print('crc = ' + hex(token['crc']))

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

        ## Checks if counter value of OTP is greater than database value
        if ( token['counter'] <= oldCounter ):
            print('DEBUG: The counter is not greater than database value!')
            return False

        ## TODO: Check timestamp
        ## TODO: Check counter and sessioncounter in combination

        ## Try to update the current values from OTP to database
        try:
            SQLiteWrapper.getInstance().cursor.execute(
                'UPDATE ARDUKEY SET counter = ?, sessioncounter = ?, timestamp = ? WHERE publicid = ? AND enabled = 1', [
                token['counter'],
                token['sessionCounter'],
                token['timestamp'],
                publicId,
            ])
            SQLiteWrapper.getInstance().connection.commit()

        except Exception as e:
            print('DEBUG: Exception occured while database operation: ' + str(e))
            return False

        return True

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

#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
ArduKey authserver
@author Bastian Raschke <bastian.raschke@posteo.de>

Copyright 2015 Bastian Raschke
All rights reserved.
"""

import logging
import time
import hmac, hashlib
import re
import binascii
import Crypto.Cipher.AES as AES

import ardukeyauth.sqlitewrapper


class NoAPIKeyAvailableError(Exception):
    """
    Dummy exception class for not available API key.

    """

    pass

class BadHmacSignatureError(Exception):
    """
    Dummy exception class for bad hmac signature check.

    """

    pass

class CurruptedOTPError(ValueError):
    """
    Dummy exception class for currupted OTP format.

    """

    pass

class OTPVerification(object):
    """
    ArduKey OTP verification class.

    @attribute string __sharedSecret
    The shared secret of API key.

    @attribute dict __response
    The response dictionary (the result of verification request).
    """

    __sharedSecret = ''
    __response = {'otp': '', 'nonce': '', 'time': '', 'status': '', 'hmac': ''}

    def __init__(self, request):
        """
        Constructor

        @param OTPVerificationRequest request
        The abstract request to process.
        """

        try:
            ## Get sanitized parameters from abstract request class
            requestParameters = request.getParameters()

            ## Simply send OTP and nonce back to requester
            self.__response['otp'] = requestParameters['otp']
            self.__response['nonce'] = requestParameters['nonce']

            ## Get shared secret of given API key
            ardukeyauth.sqlitewrapper.SQLiteWrapper.getInstance().cursor.execute(
                '''
                SELECT secret
                FROM API
                WHERE id = ? AND enabled = 1
                ''', [
                requestParameters['apiId'],
            ])

            rows = ardukeyauth.sqlitewrapper.SQLiteWrapper.getInstance().cursor.fetchall()

            if ( len(rows) > 0 ):
                self.__sharedSecret = rows[0][0]
            else:
                message = 'The given API key "' + requestParameters['apiId'] + '" was not found!'
                raise NoAPIKeyAvailableError(message)

            ## Calculates hmac of request to verify authenticity
            requestHmac = self.__calculateHmac(requestParameters)

            ## Compare request hmac hashes
            ## Note: The better hmac.compare_digest() method is only available in Python 3.3+
            if ( request.getHmac() != requestHmac ):
                message = 'The request hmac signature is invalid (expected: ' + requestHmac + ')!'
                raise BadHmacSignatureError(message)

            ## Try to verify the given OTP
            if ( self.__verifyOTP(requestParameters['otp']) == True ):
                self.__response['status'] = 'OK'

            else:
                self.__response['status'] = 'INVALID_OTP'

        except NoAPIKeyAvailableError as e:
            ## The API key was not found
            logging.getLogger().debug(e)
            self.__response['status'] = 'API_KEY_NOTFOUND'

        except BadHmacSignatureError as e:
            ## The request hmac signature is bad
            logging.getLogger().debug(e)
            self.__response['status'] = 'INVALID_SIGNATURE'

        except CurruptedOTPError as e:
            ## The OTP has an invalid format
            logging.getLogger().debug('Currupted OTP: Exception message: ' + str(e))
            self.__response['status'] = 'CURRUPTED_OTP'

        except KeyError as e:
            ## Some request parameters are not okay
            logging.getLogger().debug('Missing the request parameter: ' + str(e))
            self.__response['status'] = 'MISSING_PARAMETER'

        except Exception:
            ## General unexpected errors
            logging.getLogger().error('Unexpected exception occured:', exc_info=1)
            self.__response['status'] = 'SERVER_ERROR'

    def __calculateHmac(self, data):
        """
        Calculates hmac of given dictionary and returns it as a hexadecimal string.

        @param dict data
        The dictionary that contains data.

        @return string
        """

        ## Only process dictionaries
        if ( type(data) != dict ):
            raise ValueError('The given data is not a dictionary!')

        ## Checks if shared secret is given
        if ( len(self.__sharedSecret) == 0 ):
            raise ValueError('No shared secret given to perform hmac calculation!')

        dataString = ''

        ## Sort dictionary by key, to calculate the same hmac always
        for k in sorted(data):
            dataString += str(data[k])

        sharedSecret = self.__sharedSecret.encode('utf-8')
        dataString = dataString.encode('utf-8')

        ## Calculate hmac of payload
        return hmac.new(sharedSecret, msg=dataString, digestmod=hashlib.sha256).hexdigest()

    def __decodeArduHex(self, arduhexString):
        """
        Converts a given arduhex string to hexadecimal string.

        @param string arduhexString
        The arduhex string to convert.

        @return string
        """

        ## Mapping (arduhex -> hexadecimal) table
        table = {
            'c' : '0',
            'b' : '1',
            'd' : '2',
            'e' : '3',
            'f' : '4',
            'g' : '5',
            'h' : '6',
            'i' : '7',
            'j' : '8',
            'k' : '9',
            'l' : 'a',
            'n' : 'b',
            'r' : 'c',
            't' : 'd',
            'u' : 'e',
            'v' : 'f',
        }

        hexString = ''

        try:
            ## Try to replace each character of arduhex string
            for i in range(0, len(arduhexString)):
                currentArduhexChar = arduhexString[i]
                hexString += table[currentArduhexChar]

        except KeyError:
            raise ValueError('The given input contains non-valid character(s)!')

        return hexString

    def __decryptAES(self, aesKey, cipherText):
        """
        Decrypts (AES-ECB) given cipher text and returns plain text as hexadecimal string.

        @param string aesKey
        The used AES key as hexadecimal string.

        @param string cipherText
        The cipher text as hexadecimal string.

        @return string
        """

        if ( len(aesKey) != 32 ):
            raise ValueError('The length of the hexadecimal AES key must be 32!')

        if ( len(cipherText) != 32 ):
            raise ValueError('The length of the hexadecimal cipher text must be 32!')

        aesKeyBytes = binascii.unhexlify(aesKey.encode('utf-8'))
        aes = AES.new(aesKeyBytes, AES.MODE_ECB)

        cipherBytes = binascii.unhexlify(cipherText.encode('utf-8'))
        plainBytes = aes.decrypt(cipherBytes)

        return binascii.hexlify(plainBytes).decode('utf-8')

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
            raise CurruptedOTPError('The OTP has an invalid length!')

        otpRegex = '^([cbdefghijklnrtuv]{12})([cbdefghijklnrtuv]{32})$'
        otpRegexSearch = re.search(otpRegex, otp)

        ## Regex general format check
        if ( otpRegexSearch == None ):
            raise CurruptedOTPError('The OTP has an invalid format!')

        ## Try to extract public id and token from OTP
        try:
            publicId = otpRegexSearch.group(1)
            encryptedToken = otpRegexSearch.group(2)

        except:
            raise CurruptedOTPError('The OTP does not contain public id or token!')

        ## Convert public id and encrypted token to default hexadecimal string representation
        publicId = self.__decodeArduHex(publicId)
        encryptedToken = self.__decodeArduHex(encryptedToken)

        ## Get required information from database
        ardukeyauth.sqlitewrapper.SQLiteWrapper.getInstance().cursor.execute(
            '''
            SELECT secretid, counter, sessioncounter, timestamp, aeskey
            FROM ARDUKEY
            WHERE publicid = ? AND enabled = 1
            ''', [
            publicId,
        ])

        rows = ardukeyauth.sqlitewrapper.SQLiteWrapper.getInstance().cursor.fetchall()

        if ( len(rows) > 0 ):
            secretId = rows[0][0].lower()
            oldCounter = int(rows[0][1])
            oldSessionCounter = int(rows[0][2])
            oldTimestamp = int(rows[0][3])
            aesKey = rows[0][4]
        else:
            logging.getLogger().debug('The public id "' + publicId + '" was not found in database!')
            return False

        ## Decrypt encrypted token
        decryptedToken = self.__decryptAES(aesKey, encryptedToken)

        ## Extract data from decrypted token
        ## Note: The data in token must be interpreted as little endian:
        ## The string 'aabb' would be become 0xbbaa for example.
        token = {}
        token['secretId'] = decryptedToken[0:12]
        token['counter'] = int(decryptedToken[14:16] + decryptedToken[12:14], 16)
        token['sessionCounter'] = int(decryptedToken[16:18], 16)
        token['timestamp'] = int(decryptedToken[22:24] + decryptedToken[20:22] + decryptedToken[18:20], 16)
        token['random'] = int(decryptedToken[26:28] + decryptedToken[24:26], 16)
        token['crc'] = int(decryptedToken[30:32] + decryptedToken[28:30], 16)

        ## Format the extracted data for easy debugging
        explainedToken = 'counter = 0x{0:0>4X}; session = 0x{1:0>2X}; ' + \
            'timestamp = 0x{2:0>6X}; random = 0x{3:0>4X}; ' + \
            'crc = 0x{4:0>4X}'

        explainedToken = explainedToken.format(token['counter'],
            token['sessionCounter'], token['timestamp'], token['random'], token['crc'])

        logging.getLogger().debug('Raw token: ' + decryptedToken + ' (' + explainedToken + ')')

        ## Calculate CRC16 checksum of token
        calculatedCRC = self.__calculateCRC16(decryptedToken[0:28])

        ## Compare the given OTP checksum and calculated checksum
        if ( token['crc'] != calculatedCRC ):
            raise CurruptedOTPError('The checksum of the OTP is not correct!')

        ## Check if database secret id matches to value in OTP
        if ( token['secretId'] != secretId ):
            raise CurruptedOTPError('The secret id is not the same as in database!')

        ## Check if the ArduKey has been re-plugged (counter is greater than old counter)
        if ( token['counter'] <= oldCounter ):

            ## Check if session counter has been incremented
            if ( token['sessionCounter'] <= oldSessionCounter ):
                logging.getLogger().debug('The session counter is not greater than old value!')
                return False

            ## Check if timestamp has been incremented
            if ( token['timestamp'] <= oldTimestamp ):
                logging.getLogger().debug('The timestamp is not greater than old value!')
                return False

        ## TODO: Security revision

        ## Update the current values from OTP to database
        ardukeyauth.sqlitewrapper.SQLiteWrapper.getInstance().cursor.execute(
            '''
            UPDATE ARDUKEY
            SET counter = ?, sessioncounter = ?, timestamp = ?
            WHERE publicid = ? AND enabled = 1
            ''', [
            token['counter'],
            token['sessionCounter'],
            token['timestamp'],
            publicId,
        ])
        ardukeyauth.sqlitewrapper.SQLiteWrapper.getInstance().connection.commit()

        return True

    def getResponse(self):
        """
        Returns the complete response.

        @return dictionary
        """

        ## Sets current datetime
        self.__response['time'] = time.strftime("%Y-%m-%dT%H:%M:%S")

        ## Unset old hmac
        ## Note: Do not remove element, cause if no hmac signature is possible,
        ## the element must be available in response nevertheless!
        self.__response['hmac'] = ''

        ## Only perform hmac operation if shared secret is available
        if ( len(self.__sharedSecret) > 0 ):
            self.__response['hmac'] = self.__calculateHmac(self.__response)

        return self.__response

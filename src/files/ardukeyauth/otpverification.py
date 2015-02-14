#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
ArduKey authserver

Copyright 2015 Bastian Raschke <bastian.raschke@posteo.de>
All rights reserved.
"""

import logging
import time, datetime
import hmac, hashlib
import re
import binascii
import Crypto.Cipher.AES as AES

import ardukeyauth.sqlitewrapper as sqlitewrapper


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

    @attribute str __sharedSecret
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
            sqlitewrapper.getInstance().cursor.execute(
                '''
                SELECT secret, enabled
                FROM API
                WHERE id = ?
                ''', [
                requestParameters['apiId'],
            ])

            rows = sqlitewrapper.getInstance().cursor.fetchall()

            if ( len(rows) > 0 ):
                sharedSecret = rows[0][0]
                enabled = rows[0][1]
            else:
                message = 'The API key "' + requestParameters['apiId'] + '" was not found!'
                raise NoAPIKeyAvailableError(message)

            if ( enabled == 0 ):
                message = 'The API key "' + requestParameters['apiId'] + '" has been revoked!'
                raise NoAPIKeyAvailableError(message)

            ## Important: Just now set shared secret!
            ## Otherwise the response hmac would leak revokation status!
            self.__sharedSecret = sharedSecret

            ## Calculate hmac of request to verify authenticity
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
            logging.getLogger().debug('Currupted OTP: ' + str(e))
            self.__response['status'] = 'CURRUPTED_OTP'

        except KeyError as e:
            ## Some request parameters are not okay
            logging.getLogger().debug('Missing the request parameter: ' + str(e))
            self.__response['status'] = 'MISSING_PARAMETER'

        except:
            ## General unexpected verification errors
            logging.getLogger().error('Unexpected error occured during verification:', exc_info=1)
            self.__response['status'] = 'SERVER_ERROR'

    def __calculateHmac(self, data):
        """
        Calculate hmac of given dictionary and return it as a hexadecimal string.

        @param dict data
        The dictionary that contains data.

        @return str
        """

        ## Only process dictionaries
        if ( type(data) != dict ):
            raise ValueError('The given data is not a dictionary!')

        ## Check if shared secret is given
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
        Convert a given arduhex string to hexadecimal string.

        @param str arduhexString
        The arduhex string to convert.

        @return str
        """

        ## Character mapping table
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
        Decrypt given cipher text (AES-ECB) and return plain text as hexadecimal string.

        @param str aesKey
        The used AES key as hexadecimal string.

        @param str cipherText
        The cipher text as hexadecimal string.

        @return str
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
        Calculate the CRC16 (ISO-13239) checksum of given hexadecimal data.

        @param str hexString
        The hexadecimal data used by calculation.

        @return int
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

            crc ^= currentByte & 0xFF

            for j in range(0, 8):
                x = crc & 1
                crc >>= 1

                if (x):
                    crc ^= 0x8408

        return crc

    def __verifyOTP(self, otp):
        """
        Validate a OTP.

        @param str otp
        The OTP to validate.

        @return bool
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

        ## Convert encrypted token to default hexadecimal string representation
        encryptedToken = self.__decodeArduHex(encryptedToken)

        ## Get required information from database
        sqlitewrapper.getInstance().cursor.execute(
            '''
            SELECT secretid, counter, sessioncounter, timestamp, aeskey,
                   modified, enabled
            FROM ARDUKEY
            WHERE publicid = ?
            ''', [
            publicId,
        ])

        rows = sqlitewrapper.getInstance().cursor.fetchall()

        if ( len(rows) > 0 ):
            secretId = rows[0][0].lower()
            seenCounter = int(rows[0][1])
            seenSessionCounter = int(rows[0][2])
            seenTimestamp = int(rows[0][3])
            aesKey = rows[0][4]
            modified = rows[0][5]
            enabled = rows[0][6]
        else:
            logging.getLogger().info('The ArduKey "' + publicId + '" was not found in database!')
            return False

        if ( enabled == 0 ):
            logging.getLogger().info('The ArduKey "' + publicId + '" has been revoked!')
            return False

        ## Decrypt encrypted token
        decryptedToken = self.__decryptAES(aesKey, encryptedToken)

        ## Extract data from decrypted token
        ## Note: The data in token must be interpreted as little endian:
        ## The string 'aabb' would be become 0xbbaa for example.
        token = {
            'secretId': decryptedToken[0:12],
            'counter': int(decryptedToken[14:16] + decryptedToken[12:14], 16),
            'timestamp': int(decryptedToken[20:22] + decryptedToken[18:20] + decryptedToken[16:18], 16),
            'sessionCounter': int(decryptedToken[22:24], 16),
            'random': int(decryptedToken[26:28] + decryptedToken[24:26], 16),
            'crc': int(decryptedToken[30:32] + decryptedToken[28:30], 16)
        }

        ## Format the extracted token data for debugging
        explainedTokenDebug = 'Raw token: {0} (' + \
            'counter = 0x{1:0>4X}; ' + \
            'timestamp = 0x{2:0>6X}; ' + \
            'session = 0x{3:0>2X}; ' + \
            'random = 0x{4:0>4X}; ' + \
            'crc = 0x{5:0>4X})'

        explainedTokenDebug = explainedTokenDebug.format(
            decryptedToken,
            token['counter'],
            token['timestamp'],
            token['sessionCounter'],
            token['random'],
            token['crc']
        )
        logging.getLogger().debug(explainedTokenDebug)

        ## Check if CRC16 checksum is correct
        if ( self.__calculateCRC16(decryptedToken) != 0xF0B8 ):
            raise CurruptedOTPError('The checksum of the OTP is not correct!')

        ## Check if database secret id matches to value in OTP
        if ( token['secretId'] != secretId ):
            raise CurruptedOTPError('The secret id is not the same as in database!')

        ## TODO: Check if OTP and nonce already seen together?

        ## General counter and session counter check
        if ( token['counter'] <= seenCounter ):

            ## Check if session counter has been incremented
            if ( token['sessionCounter'] <= seenSessionCounter ):
                logging.getLogger().debug('The session counter is not greater than old value!')
                return False

            ## Check if token timestamp has been incremented
            if ( token['timestamp'] <= seenTimestamp ):
                logging.getLogger().debug('The token timestamp is not greater than old value!')
                return False

        ## Update the current values from OTP to database
        sqlitewrapper.getInstance().cursor.execute(
            '''
            UPDATE ARDUKEY
            SET counter = ?, sessioncounter = ?, timestamp = ?
            WHERE publicid = ?
            ''', [
            token['counter'],
            token['sessionCounter'],
            token['timestamp'],
            publicId,
        ])
        sqlitewrapper.getInstance().connection.commit()

        ## Check if the update command succeeded
        if ( sqlitewrapper.getInstance().cursor.rowcount != 1 ):
            raise Exception('The database update of new token values failed!')

        ## Additional OTP phishing test:
        ## Check the token timestamp if the ArduKey has NOT been re-plugged
        if ( token['counter'] == seenCounter and token['sessionCounter'] > seenSessionCounter ):

            ## The difference of current and seen token timestamp
            tokenTimestampDiff = token['timestamp'] - seenTimestamp

            ## Estimate number of seconds that *should* be elapsed
            ## Note: The timestamp of an ArduKey increments 8 times per second.
            estimatedElapsedSeconds = int(tokenTimestampDiff * (1/8))

            ## Get datetime when the last OTP has been processed
            lastProcessingTime = datetime.datetime.strptime(modified, '%Y-%m-%d %H:%M:%S')

            ## Calculate elapsed seconds since last OTP processing
            currentTime = datetime.datetime.now()
            elapsedSecondsSinceLastProcessing = abs((currentTime - lastProcessingTime).seconds)

            ## Compare the estimated and calculated number seconds
            secondsDeviation = abs(elapsedSecondsSinceLastProcessing - estimatedElapsedSeconds)

            ## Format the phishing test results for debugging
            phishingTestResult = 'OTP phishing test results: ' + \
                'estimatedElapsedSeconds = {0}; ' + \
                'elapsedSecondsSinceLastProcessing = {1}; ' + \
                'secondsDeviation = {2}'

            phishingTestResult = phishingTestResult.format(
                estimatedElapsedSeconds,
                elapsedSecondsSinceLastProcessing,
                secondsDeviation
            )
            logging.getLogger().debug(phishingTestResult)

            ## Decide if the difference of seconds is too wide to reject OTP
            if ( secondsDeviation > 20 ):
                logging.getLogger().info('The OTP phishing test failed!')
                return False
            else:
                logging.getLogger().debug('The OTP phishing test passed!')

        return True

    def getResponse(self):
        """
        Return the complete response.

        @return dict
        """

        ## Set current datetime
        self.__response['time'] = time.strftime('%Y-%m-%dT%H:%M:%S')

        ## Unset old hmac
        ## Note: Do not remove element, cause if no hmac signature is possible,
        ## the element must be available in response nevertheless!
        self.__response['hmac'] = ''

        ## Only perform hmac operation if shared secret is available
        if ( len(self.__sharedSecret) > 0 ):
            self.__response['hmac'] = self.__calculateHmac(self.__response)

        return self.__response

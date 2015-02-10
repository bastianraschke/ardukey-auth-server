#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
ArduKey authserver request tester

Copyright 2015 Bastian Raschke <bastian.raschke@posteo.de>
All rights reserved.
"""

import hmac, hashlib
import http.client
import random
import string
import socket


def calculateHmac(data, sharedSecret):
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
    if ( len(sharedSecret) == 0 ):
        raise ValueError('No shared secret given!')

    payloadData = ''

    ## Sort dictionary by key, to calculate the same Hmac always
    for k in sorted(data):
        payloadData += str(data[k])

    sharedSecret = sharedSecret.encode('utf-8')
    payloadData = payloadData.encode('utf-8')

    ## Calculate HMAC of current response
    return hmac.new(sharedSecret, msg=payloadData, digestmod=hashlib.sha256).hexdigest()

if ( __name__ == '__main__' ):

    server = '127.0.0.1:8080'
    apiId = 1
    sharedSecret = 'IPLOQXIR1626RIO31VVYAQZAUH71TOFC462H26U07B92FMNIMUSB1R51771P9XSN'

    requestTimeout = 4
    connection = http.client.HTTPConnection(server, timeout=requestTimeout)

    try:
        while (True):

            typedOTP = input('Please enter OTP: ')

            ## Generate random nonce
            nonce = ''.join(random.SystemRandom().choice(
                string.ascii_uppercase + string.digits) for _ in range(32))

            request = {
                'otp': typedOTP,
                'nonce': nonce,
                'apiId': apiId,
            }

            ## Calculate request hmac
            request['hmac'] = calculateHmac(request, sharedSecret)

            ## Send request to server
            connection.request('GET', '/ardukeyotp/1.0/verify?otp=' + request['otp'] + '&nonce=' + request['nonce'] + '&apiId=' + str(request['apiId']) + '&hmac=' + request['hmac'])

            ## Receive the response from auth server
            httpResponseData = connection.getresponse().read().decode()

            print('Response from server:')
            print(httpResponseData + '\n')

    except socket.timeout:
        print('Server timeout')

    except KeyboardInterrupt:
        print('KeyboardInterrupt received')

    finally:
        connection.close()

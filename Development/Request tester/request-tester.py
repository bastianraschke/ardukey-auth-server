#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
ArduKey authserver request tester

Copyright 2015 Bastian Raschke <bastian.raschke@posteo.de>
All rights reserved.
"""

import hmac, hashlib
import http.client
import socket
import random, string


def calculateHmac(data, sharedSecret):
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
    if ( len(sharedSecret) == 0 ):
        raise ValueError('No shared secret given to perform hmac calculation!')

    dataString = ''

    ## Sort dictionary by key, to calculate the same hmac always
    for k in sorted(data):
        dataString += str(data[k])

    sharedSecret = sharedSecret.encode('utf-8')
    dataString = dataString.encode('utf-8')

    ## Calculate hmac of payload
    return hmac.new(sharedSecret, msg=dataString, digestmod=hashlib.sha256).hexdigest()

if ( __name__ == '__main__' ):

    server = '127.0.0.1:8080'
    apiId = 1
    sharedSecret = 'RC03R18MIOXPM0KEC76PYHAYRG2DYT9QP5RQN7LAQ6AAF6QUSV6CIT8AG9726FAV'

    requestTimeout = 4
    connection = http.client.HTTPConnection(server, timeout=requestTimeout)

    try:
        while (True):

            typedOTP = input('Please enter OTP: ')

            ## Generate random nonce
            nonce = ''.join(random.SystemRandom().choice(
                string.ascii_lowercase + string.digits) for _ in range(32))

            request = {
                'otp': typedOTP,
                'nonce': nonce,
                'apiId': apiId,
            }

            ## Calculate request hmac
            request['hmac'] = calculateHmac(request, sharedSecret)

            ## Send request to server
            connection.request('GET', '/ardukeyotp/1.0/verify?' + \
                'otp=' + request['otp'] + \
                '&nonce=' + request['nonce'] + \
                '&apiId=' + str(request['apiId']) + \
                '&hmac=' + request['hmac']
            )

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

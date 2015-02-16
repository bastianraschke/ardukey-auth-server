#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import http.client
import socket

server = 'localhost:443'

requestTimeout = 4
connection = http.client.HTTPSConnection(server, timeout=requestTimeout)

try:
    ## Send request to server
    connection.request('GET', '/')

    ## Receive the response from auth server
    httpResponseData = connection.getresponse().read().decode()

    print('Response from server:')
    print(httpResponseData + '\n')

except socket.timeout:
    print('Server timeout')

finally:
    connection.close()

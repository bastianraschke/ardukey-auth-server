#!/usr/bin/env python3

"""
ArduKey authserver
@author Bastian Raschke

Copyright 2014 Bastian Raschke.
All rights reserved.
"""

import http.server
import urllib.parse
import json
import time
import hmac
import hashlib

import libraries.AES
import libraries.SQLite3
import libraries.OTPValidation


"""
Configuration section

"""

## The address the server is running on
SERVER_ADDRESS = '127.0.0.1'

## The port the server is listening
SERVER_PORT = 8080

"""
Configuration section end
"""

## Version of authserver
__version__ = '1.0'

class ArduKeyAuthserver(http.server.BaseHTTPRequestHandler):
    """
    Implementation of BaseHTTPRequestHandler.

    @attribute string server_version
    The server version string.

    @attribute string sys_version
    The Python version string.
    """

    server_version = 'ArduKey authserver/' + __version__

    ## Hide the sys_version attribute:
    sys_version = ''

    def log_message(self, format, *args):
        """
        Log an arbitrary message.
        @see BaseHTTPRequestHandler
        """

        ## Do not output anything
        pass

    def send_output(self, message):
        """
        Sends a given message to client.

        @param string message The message to send to client.
        @return void
        """

        self.wfile.write(message.encode('utf-8'))

    def do_GET(self):

        url = urllib.parse.urlparse(self.path, 'http')

        ## Default request path
        if (url.path == '/ardukeyotp/1.0/verify'):

            self.send_response(200)
            self.send_header('Content-type', 'text/plain')
            self.end_headers()




            isoDateTime = time.strftime("%Y-%m-%dT%H:%M:%S")

            response = {}
            response['otp'] = '1'
            response['nonce'] = '2'
            response['time'] = isoDateTime
            response['status'] = 'MISSING_PARAMETER'


            responseData = ''

            for element in response.values():
                responseData += element

            response['hmac'] = hmac.new('secret'.encode('utf-8'), msg=responseData.encode('utf-8'), digestmod=hashlib.sha256).hexdigest()



            """
            requestParameters = urllib.parse.parse_qs(url.query, keep_blank_values=True)

            ## Input:
            ## otp, nonce, apiId, hmac
            ## eg.: http://127.0.0.1:8080/ardukeyotp/1.0/verify?otp=xxx&nonce=xxx&apiId=1000&hmac=xxx

            ## Output:
            ## status, otp, nonce, datetime, hmac

            try:

                ## The OTP parameter
                otp = requestParameters.get('otp', '')
                otp = urllib.parse.quote(otp)

                ## The given nonce
                nonce = requestParameters.get('nonce', '')
                nonce = urllib.parse.quote(nonce)

                ## The given api id
                apiId = requestParameters.get('apiId', 0)
                apiId = urllib.parse.quote(apiId)

                ## The HMAC hash
                hmac = requestParameters.get('hash', '')
                hmac = urllib.parse.quote(hmac)

            except Exception as e:
                pass
            """




            self.send_output(json.dumps(response, indent="  "))

        else:
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()

            self.send_output('<html><head><title>ArduKey authserver</title></head><body>')
            self.send_output('<h1>ArduKey authserver</h1>')
            self.send_output("<p>Please send your GET requests to: <pre>/ardukeyotp/1.0/verify</pre>")
            self.send_output('</body></html>')

try:
    httpServer = http.server.HTTPServer((SERVER_ADDRESS, SERVER_PORT), ArduKeyAuthserver)
    print('Starting ' + ArduKeyAuthserver.server_version + ': Listening on ' + SERVER_ADDRESS + ':' + str(SERVER_PORT))

    httpServer.serve_forever()

except KeyboardInterrupt:
    print('KeyboardInterrupt received, shutting down server...')
    httpServer.socket.close()

## Default exit
exit(0)

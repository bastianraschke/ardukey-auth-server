#!/usr/bin/env python3

"""
ArduKey authserver
@author Bastian Raschke

Copyright 2014 Bastian Raschke.
All rights reserved.
"""

import libraries.AES
##import libraries.SQLite3
##import libraries.OTPValidation

## See https://docs.python.org/3.3/library/http.server.html
import http.server
import urllib.parse


"""
Configuration section

"""

## The address the server is running on
SERVER_ADDRESS = '127.0.0.1'

## The port the server is listening
SERVER_PORT = 8080

## The path to SQLite database file
DATABASE_FILE = './database.sqlite'

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

        self.wfile.write(bytes(message, 'utf-8'))

    def do_GET(self):

        url = urllib.parse.urlparse(self.path, 'http')

        if (url.path == '/ardukeyotp/1.0/verify'):
            self.send_response(200)
            self.send_header('Content-type', 'text/plain')
            self.end_headers()

            self.send_output('Hallo Welt')

            requestParameters = urllib.parse.parse_qs(url.query, keep_blank_values=True)

            ## The OTP parameter
            otp = requestParameters.get('otp', '')

            ## TODO: receive parameters and validates them
            ## TODO: if validation fails: send_response 500

            ## rawtoken: b0d4a2d69bc4 2000 04 07004f 9899 d99a



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
    print('KeyboardInterrupt received, shutting down the server.')
    httpServer.socket.close()

## Default exit
exit(0)

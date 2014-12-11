#!/usr/bin/env python3

"""
ArduKey authserver
@author Bastian Raschke

Copyright 2014 Bastian Raschke
All rights reserved.
"""

import sys
sys.path.append('/usr/lib/ardukey-auth/')

import http.server
import urllib.parse
import json

from libraries.ConfigurationFile import ConfigurationFile
from libraries.Verification import Verification

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
            self.send_header('Content-Type', 'text/plain')
            self.end_headers()

            ## Parses all query arguments to dictionary
            requestParameters = urllib.parse.parse_qs(url.query, keep_blank_values=True)

            ## Deligates request to Validation class
            verification = Verification(requestParameters)
            response = verification.getResponse();

            ## Sends JSON formatted response
            self.send_output(json.dumps(response, indent=None, sort_keys=True))

        else:
            self.send_response(200)
            self.send_header('Content-Type', 'text/html')
            self.end_headers()

            self.send_output('<!DOCTYPE html>')
            self.send_output('<html><head><title>' + self.server_version + '</title></head><body>')
            self.send_output('<h1>' + self.server_version + '</h1>')
            self.send_output("<p>Please send your GET requests to: <pre>/ardukeyotp/1.0/verify</pre>")
            self.send_output('</body></html>')

## TODO: Path to file
configurationFilePath = './ardukey-auth.conf'

## Reads from configuration file
configuration = ConfigurationFile(configurationFilePath, readOnly=True)

try:
    ## The address the server is running on
    serverAddress = configuration.readString('Default', 'server_address')

    ## The port the server is listening
    serverPort = configuration.readInteger('Default', 'server_port')

except:
    print('The configuration file "' + configurationFilePath + '" could not be read correctly!')
    exit(1)

try:
    httpServer = http.server.HTTPServer((serverAddress, serverPort), ArduKeyAuthserver)
    print('Starting ' + ArduKeyAuthserver.server_version + ': Listening on ' + serverAddress + ':' + str(serverPort))

    httpServer.serve_forever()

except KeyboardInterrupt:
    print('KeyboardInterrupt received, shutting down ArduKey authserver...')
    httpServer.socket.close()

## Default exit
exit(0)

#!/usr/bin/env python3
# coding: utf-8

"""
ArduKey authserver
@author Bastian Raschke

Copyright 2014 Bastian Raschke
All rights reserved.
"""

import http.server
import urllib.parse
import json
import logging
import sys

from ardukeyauth.ConfigurationFile import ConfigurationFile
from ardukeyauth.ArduKeyVerification import ArduKeyVerification
from ardukeyauth import __version__

## Path to logging file
loggingFilePath = '/var/log/ardukey-auth.log'

## Path to configuration file
configurationFilePath = '/etc/ardukey-auth.conf'

class ArduKeyAuthserver(http.server.BaseHTTPRequestHandler):
    """
    Implementation of BaseHTTPRequestHandler.

    @attribute string server_version
    The server version string.

    @attribute string sys_version
    The Python version string.
    """

    server_version = 'ArduKey authserver/' + ardukeyauth.__version__

    ## Hide the sys_version attribute
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
        Send a given message to client.

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

            ## Parse all query arguments to dictionary
            requestParameters = urllib.parse.parse_qs(url.query, keep_blank_values=True)

            ## Deligate request to verification class
            verification = ArduKeyVerification(requestParameters)
            verificationResponse = verification.getResponse();

            ## Send JSON formatted response
            self.send_output(json.dumps(verificationResponse, indent='\t', sort_keys=True))

        ## Fallback message
        else:
            self.send_response(200)
            self.send_header('Content-Type', 'text/html')
            self.end_headers()

            self.send_output('<!DOCTYPE html>')
            self.send_output('<html><head><title>' + self.server_version + '</title></head><body>')
            self.send_output('<h1>' + self.server_version + '</h1>')
            self.send_output("<p>Please send your GET requests to: <pre>/ardukeyotp/1.0/verify</pre>")
            self.send_output('</body></html>')

## Try to initialize logger
try:
    logger = logging.getLogger('ARDUKEY')

    ## TODO: Set logging level
    logger.setLevel(logging.DEBUG)

    logFormatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')

    ## Stream output handler
    strmHandler = logging.StreamHandler()
    strmHandler.setLevel(logging.DEBUG)
    strmHandler.setFormatter(logFormatter)
    logger.addHandler(strmHandler)

    ## Log file handler
    fileHandler = logging.FileHandler(loggingFilePath)
    fileHandler.setLevel(logging.INFO)
    fileHandler.setFormatter(logFormatter)
    logger.addHandler(fileHandler)

except:
    ## The system is able to work without logging
    sys.stderr.write('Warning: The logger could not be initialized correctly!\n')

## Try to read parameters from configuration file
try:
    configuration = ConfigurationFile(configurationFilePath, readOnly=True)

    ## The address the server is running on
    serverAddress = configuration.readString('Default', 'server_address')

    ## The port the server is listening
    serverPort = configuration.readInteger('Default', 'server_port')

except:
    ## Without configuration the system is not able to work
    sys.stderr.write('The configuration file "' + configurationFilePath + '" could not be read correctly!\n')
    exit(1)

## Try to start HTTP server
try:
    httpServer = http.server.HTTPServer((serverAddress, serverPort), ArduKeyAuthserver)
    logger.info('Starting ' + ArduKeyAuthserver.server_version + ': Listening on ' + serverAddress + ':' + str(serverPort) + '\n')

    httpServer.serve_forever()

except KeyboardInterrupt:
    print('KeyboardInterrupt received, shutting down ArduKey authserver...')

finally:
    ## Always shutting down HTTP server
    httpServer.socket.close()

## Default exit
exit(0)

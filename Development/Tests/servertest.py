#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
ArduKey authserver
@author Bastian Raschke <bastian.raschke@posteo.de>

Copyright 2015 Bastian Raschke
All rights reserved.
"""

import http.server
import urllib.parse
import json
import logging
import sys
import traceback


VERSION = '1'


class ArduKeyAuthserver(http.server.BaseHTTPRequestHandler):
    """
    Implementation of BaseHTTPRequestHandler.

    @attribute string server_version
    The server version string.

    @attribute string sys_version
    The Python version string.
    """

    server_version = 'ArduKey authserver/' + VERSION

    ## Hide the sys_version attribute
    sys_version = ''

    def log_message(self, format, *args):
        """
        Log an arbitrary message.

        @see BaseHTTPRequestHandler
        """

        ## Do not output anything
        pass

    def log_error(self, format, *args):
        print('jojojo')

    def send_output(self, message):
        """
        Send a given message to client.

        @param string message The message to send to client.
        @return void
        """

        self.wfile.write(message.encode('utf-8'))

    def do_GET(self):

        try:

            self.send_output('<!DOCTYPE html>')
            self.send_output('<html><head><title>' + self.server_version + '</title></head><body>')
            self.send_output('<h1>' + self.server_version + '</h1>')
            self.send_output("<p>Please send your GET requests to: <pre>/ardukeyotp/1.0/verify</pre>")
            self.send_output('</body></html>')

            raise Exception('dd')

        except:
            ## General unexpected server errors
            logging.getLogger().error('Unexpected exception occured:', exc_info=1)




if ( __name__ == '__main__' ):

    ## Try to initialize logger
    try:
        logger = logging.getLogger()

        ## Enable debug logging if "--debug" flag is given
        if ( '--debug' in sys.argv ):
            loggingLevel = logging.DEBUG
        else:
            loggingLevel = logging.INFO

        logger.setLevel(loggingLevel)

        logFormatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')

        ## Stream output handler
        strmHandler = logging.StreamHandler()
        strmHandler.setLevel(loggingLevel)
        strmHandler.setFormatter(logFormatter)
        logger.addHandler(strmHandler)

    except:
        sys.stderr.write('Warning: The logger could not be initialized correctly!\n\n')
        sys.stderr.write(traceback.format_exc())

    ## Try to start HTTP server
    try:
        httpServer = http.server.HTTPServer(
            ('127.0.0.1', 8081),
            ArduKeyAuthserver
        )

        print('Starting ' + ArduKeyAuthserver.server_version + ': ')
        httpServer.serve_forever()

    except KeyboardInterrupt:
        httpServer.socket.close()
        print('KeyboardInterrupt received, shutting down ArduKey authserver...')

    ## Unknown exceptions
    except Exception as e:
        sys.stderr.write('Error: Unknown exception occured:\n\n')
        sys.stderr.write(traceback.format_exc())
        sys.exit(1)


    ## Default exit
    sys.exit(0)

#!/usr/bin/env python3

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

## See https://docs.python.org/3.3/library/http.server.html
import http.server

## Version of authserver
VERSION = '0.0.1'

class ArduKeyAuthserver(http.server.BaseHTTPRequestHandler):

    protocol_version = 'HTTP/1.0'
    server_version = 'ArduKey authserver/' + VERSION
    sys_version = ''

    """
    ## TODO
    def log_message(self, format, *args):
        pass
    """

    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/plain')
        self.end_headers()

        self.wfile.write(bytes("Hallo Welt", 'utf-8'))


try:


    server = http.server.HTTPServer((SERVER_ADDRESS, SERVER_PORT), ArduKeyAuthserver)
    print('Started httpserver ' + SERVER_ADDRESS + ' on port ' + str(SERVER_PORT))

    server.serve_forever()

except KeyboardInterrupt:
    print('KeyboardInterrupt received, shutting down the web server')
    server.socket.close()

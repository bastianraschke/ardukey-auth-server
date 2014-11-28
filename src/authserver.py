#!/usr/bin/env python3

## See https://docs.python.org/3.3/library/http.server.html
import http.server

class ArduKeyAuthserver(http.server.BaseHTTPRequestHandler):

    protocol_version = 'HTTP/1.0'
    server_version = 'AuthServer 0.1'
    sys_version = 'running on Windows'

    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/plain')
        self.end_headers()

        self.wfile.write(bytes("Hallo Welt", "utf-8"))


try:
    SERVER_ADDRESS = '127.0.0.1'
    SERVER_PORT = 8080

    server = http.server.HTTPServer((SERVER_ADDRESS, SERVER_PORT), ArduKeyAuthserver)
    print('Started httpserver ' + SERVER_ADDRESS + ' on port ' + str(SERVER_PORT))

    server.serve_forever()

except KeyboardInterrupt:
    print('KeyboardInterrupt received, shutting down the web server')
    server.socket.close()

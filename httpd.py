#!/usr/bin/env python
import socket
from BaseHTTPServer import HTTPServer
from SimpleHTTPServer import SimpleHTTPRequestHandler

class MyHandler(SimpleHTTPRequestHandler):
  def do_GET(self):
    if self.path == '/ip':
      self.send_response(200)
      self.send_header('Content-type', 'text/html')
      self.end_headers()
      self.wfile.write('Request received from %s:%s\n' % self.client_address)
      return
    else:
      return SimpleHTTPRequestHandler.do_GET(self)

class HTTPServerV6(HTTPServer):
  address_family = socket.AF_INET6

class HTTPServer(HTTPServer):
  address_family = socket.AF_INET

def main():
  # server = HTTPServerV6(('::', 8080), MyHandler)
  server = HTTPServer(('0.0.0.0', 8080), MyHandler)
  server.serve_forever()

if __name__ == '__main__':
  main()

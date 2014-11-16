#!/usr/bin/python
import sys
import socket
import traceback
import urllib
import struct

def build_request(fileName):
    ## Things that you might find useful in constructing your exploit:
    ##   urllib.quote(s)
    ##     returns string s with "special" characters percent-encoded
    ##   struct.pack("<I", x)
    ##     returns the 4-byte binary encoding of the 32-bit integer x
    ##   variables for program addresses (ebp, buffer, retaddr=ebp+4)

    req = "GET /" + \
          fileName + \
          " HTTP/1.1\r\n\r\n"
    return req


def build_post_request(fileName, contents):
    req = "POST /"
    return req


####

def send_req(host, port, req):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print("Connecting to %s:%d..." % (host, port))
    sock.connect((host, port))

    print("Connected, sending request...")
    sock.send(req)

    print("Request sent, waiting for reply...")
    rbuf = sock.recv(1024)
    resp = ""
    while len(rbuf):
	resp = resp + rbuf
	rbuf = sock.recv(1024)

    print("Received reply.")
    sock.close()
    return resp

####

if len(sys.argv) != 4:
    print("Usage: " + sys.argv[0] + " host port fileName")
    exit()

try:
    fileName = sys.argv[3]
    req = build_request(fileName)
    print("HTTP request:")
    print(req)

    resp = send_req(sys.argv[1], int(sys.argv[2]), req)
    print("HTTP response:")
    print(resp)
except:
    print("Exception:")
    print(traceback.format_exc())

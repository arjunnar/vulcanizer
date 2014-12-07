#!/usr/bin/python
import sys
import socket
import traceback
import urllib
import struct
from httplib import *

def send_get_req(host, port, req):
    connection = HTTPConnection(host, port)
    connection.connect()
    connection.set_debuglevel(1)
    request = connection.request("GET", req)
    print "get ready for response..."
    response = connection.getresponse()
    print "request sent"
    connection.close()
    return response.read()


def send_post_request(host, port, path):
    connection = HTTPConnection(host, port)
    connection.connect()
    connection.set_debuglevel(1)
    params = urllib.urlencode({'fileName': path, 'contents': "This is file content."})
    headers = {"Content-type": "application/x-www-form-urlencoded",
               "Accept": "text/plain"}
    request = connection.request("POST", path, params, headers)
    print "get ready for response..."
    response = connection.getresponse()
    print "request sent"
    connection.close()
    # print response.status
    return response.read()
    

if len(sys.argv) != 4:
    print("Usage: " + sys.argv[0] + " host port fileName")
    exit()

try:
    host = sys.argv[1]
    port = sys.argv[2]
    fileName = sys.argv[3]

    resp = send_post_req(sys.argv[1], int(sys.argv[2]), "/" + fileName)
    
    print(resp)
except:
    print("Exception:")
    print(traceback.format_mat_exc())

#!/usr/bin/env python

import sys

# First ssh-server-g3 expects a protocol version number.
# Currently only version 1 is supported.
sys.stdout.write("version:1\n")
sys.stdout.flush()

# Read the version string sent by the server.
version = sys.stdin.readline()
(ver, num) = version.split(':')
if (ver == "version"): 
    if (int(num) != 1):
        sys.exit(1)
else:
    sys.exit(1)

# Version is OK, let's wait for the request.
request = sys.stdin.readline()
(request_str, num) = request.split(':')
if (request_str == "request") :
    request_no = int(num)
else:
    sys.exit(2)

# Request started, let's read the request's data.
while 1:
    end_of_request = sys.stdin.readline()
    if not end_of_request:
        break
    if end_of_request.find("end-of-request:",0,15) == 0 :
        (end_of_request_str, num) = end_of_request.split(':')
        end_of_request_no = int(num)
        if (end_of_request_no == request_no) :
            break
        else:
            sys.exit(3)
    else:
        pass # handle the request data

# Request finished, let's send the response.
sys.stdout.write("%s" % request)
sys.stdout.write("success: Well done!\n")
sys.stdout.flush()

sys.exit(0)

#!/usr/bin/env python3
#
# Author: K. Walsh <kwalsh@cs.holycross.edu>
# Date: 9 February 2017
# Updated: 17 October 2020
#
# Website analyzer and geolocation service top level program. Run it like this:
#   python3 geolocation.py central_host central_port
# where central_host is the IP address (or the DNS host name) of the host that
# will be the central coordinator, and central_port is the port on which the
# central coordinator will serve HTTP requests from users.
#
# This code looks up its own IP address and DNS name to see where it is running.
# If our own IP address or DNS name matches central_host, then this code just
# calls a function from central.py like this:
#    central.run_central_coordinator(central_host, central_port)
# Otherwise, this code calls a function from worker.py like this:
#    worker.run_worker_server(central_host)
#
# In other words, this file isn't really intended to have any of the code
# implementing the central coordinator or worker code in it. That code should be
# put in central.py and worker.py instead.
#
# Feel free to modify this in any way you like, e.g. adding more command-line
# arguments, or modifying how it works.

import sys            # for sys.argv
import cloud          # for info on our cloud location

# Get the central_host name and port number from the command line
if len(sys.argv) != 3:
    print("usage: %s central_host central_port" % (sys.argv[0]))
    exit()
central_host = sys.argv[1]
central_port = int(sys.argv[2])

if cloud.provider is None:
    print("NOTE: This code does not appear to be running in the cloud!")
else:
    print("We appear to be running on %s somewhere near %s." % (cloud.provider, cloud.city))

print("Our IP is:", cloud.ipaddr)
print("Our DNS name is:", cloud.dnsname)
print("Central coordinator host is:", central_host)

if cloud.ipaddr == central_host or cloud.dnsname == central_host:
    print("We are the central coordinator host...")
    # Call some function in central.py that implements the central coordinator.
    print("Starting central coordinator at http://%s:%s/" % (central_host, central_port))
    import central
    central.run_central_coordinator(central_host, central_port)
else:
    print("We are NOT the central coordinator host, we must be a worker host...")
    # Call some function that implements the worker server.
    print("Starting worker, which will connect to central coordinator at %s" % (central_host))
    import worker
    worker.run_worker_server(central_host)

print("Done!")

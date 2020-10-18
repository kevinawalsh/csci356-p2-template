#!/usr/bin/env python3

import os, sys, socket, socketutil
import random

server_host = None
server_port = 9000

if len(sys.argv) < 4:
    print("usage:")
    print("   %s count size server_host [server_port]" % (sys.argv[0]))
    exit()

count = int(sys.argv[1])
size = int(sys.argv[2])
server_host = sys.argv[3]
if len(sys.argv) > 4:
    server_port = int(sys.argv[4])
server_addr = (server_host, server_port)

print("Sending %d messages of %d bytes each to server at %s:%d" % (count, size, server_host, server_port))

c = socketutil.socket(socket.AF_INET, socket.SOCK_STREAM)
c.connect(server_addr)

c.sendall("count:" + str(count) + "\n")
c.sendall("size:" + str(size) + "\n")

buf = bytearray(random.getrandbits(8) for i in range(size))

for i in range(count):
    # send exactly size bytes of random data
    c.sendall(buf)
    # wait for a 1-byte reply
    reply = c.recv_exactly(1)
    if reply != b"a":
        break
# server will send us a total count of all data received
total = int(c.recv_line())
c.close()
print("Done! Server got %d bytes total" % (total))

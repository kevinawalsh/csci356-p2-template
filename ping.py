#!/usr/bin/env python3

import os, sys, socket, socketutil

server_host = None
server_port = 8005

if len(sys.argv) < 3:
    print("usage:")
    print("   %s count server_host [server_port]" % (sys.argv[0]))
    exit()

count = int(sys.argv[1])
server_host = sys.argv[2]
if len(sys.argv) > 3:
    server_port = int(sys.argv[3])
server_addr = (server_host, server_port)


print("Connecting to server at %s:%d" % (server_host, server_port))
c = socketutil.socket(socket.AF_INET, socket.SOCK_STREAM)
c.connect(server_addr)

print("Sending %d messages to server" % (count))
i = count
while i > 0:
    c.sendall(str(i) + "\n")
    resp = c.recv_line()
    print("server says: %s" % (resp))
    i -= 1
c.close()

#!/usr/bin/env python3

import socket

#
# socket.getnameinfo(sockaddr, flags)
#
# (host, port)
#

IP_ADDRESS = "192.168.1.22"
# IP_ADDRESS = "130.113.224.233" # owl
# IP_ADDRESS = "130.113.10.149"  # www.ece.mcmaster.ca
# IP_ADDRESS = "130.113.64.65"   # www.mcmaster.ca
# IP_ADDRESS = "127.0.0.1"
# IP_ADDRESS = "99.236.34.223" # compeng4dn4.mooo.com

PORT = 80

# Get canonical name of the host.
# FLAGS = socket.NI_NUMERICHOST|socket.AI_CANONNAME
FLAGS = socket.AI_CANONNAME
# print("FLAGS = {}".format(FLAGS))

# Socket address is an address/port tuple.
SOCKADDR = (IP_ADDRESS, PORT)

# Returns a name/port tuple.
info_lookup = socket.getnameinfo(SOCKADDR, FLAGS)
print(info_lookup)

name, port = info_lookup
print("Host Name: \"{}\", Port: {}".format(name, port))






#!/usr/bin/env python3

import sys, socket

#
# socket.getaddrinfo(host, port, family=0, type=0, proto=0, flags=0)
#
# Returns 5-tuple: (family, type, (IP) proto, canonname, sockaddr)
#

################################
FLAGS = 0
################################

# localhost: ipv4, ipv6 and unspec options.

# """

HOST = "localhost"
# HOST = "fe80::b24f:13ff:fe0c:cb99"

FAMILY = socket.AF_INET
# FAMILY = socket.AF_INET6
# FAMILY = socket.AF_UNSPEC # Return either v4 or v6.

TYPE  = socket.SOCK_STREAM
PROTO = socket.IPPROTO_TCP

# TYPE  = socket.SOCK_DGRAM
# PROTO = socket.IPPROTO_UDP

PORT = 'echo'

FLAGS = socket.AI_CANONNAME

# """

########################################################################
# Ethernet/wifi interface.

"""

HOST = "www.mcmaster.ca"

FAMILY = socket.AF_INET
# FAMILY = socket.AF_INET6 # will fail
# FAMILY = socket.AF_UNSPEC

TYPE  = socket.SOCK_STREAM
PROTO = socket.IPPROTO_TCP

# TYPE  = socket.SOCK_DGRAM # fail for "http". ok for "echo".
# PROTO = socket.IPPROTO_UDP

PORT = 'http'
# PORT = 'https'
# PORT = 'echo'

FLAGS = socket.AI_CANONNAME

"""

########################################################################
# Show multiple result options.

"""

HOST = "compeng4dn4.mooo.com"

FAMILY = 0
TYPE   = 0
PROTO  = 0
PORT   = 50000

FLAGS = socket.AI_CANONNAME

"""

########################################################################
# Return multiple identical options.

"""

HOST   = "mail.mcmaster.ca"

FAMILY = socket.AF_INET
TYPE   = socket.SOCK_STREAM
PROTO  = socket.IPPROTO_TCP

PORT   = 'mail'

FLAGS = socket.AI_CANONNAME

"""

########################################################################
# NN

"""

HOST = "compeng4dn4.mooo.com"

FAMILY = socket.AF_INET
# FAMILY = socket.AF_INET6
# FAMILY = socket.AF_UNSPEC

TYPE  = socket.SOCK_STREAM
PROTO = socket.IPPROTO_TCP
# TYPE  = socket.SOCK_DGRAM
# PROTO = socket.IPPROTO_UDP

PORT = 50007

FLAGS = socket.AI_CANONNAME

"""

########################################################################
# NN

"""

HOST = "www.ece.mcmaster.ca"

FAMILY = socket.AF_INET
# FAMILY = socket.AF_INET6
# FAMILY = socket.AF_UNSPEC

TYPE  = socket.SOCK_STREAM
PROTO = socket.IPPROTO_TCP

# TYPE  = socket.SOCK_DGRAM
# PROTO = socket.IPPROTO_UDP

PORT = 50007

FLAGS = socket.AI_CANONNAME

"""

########################################################################
# Get info for Listen socket.

"""

# HOST = "0.0.0.0" # OR
HOST = None

FAMILY = socket.AF_INET
# FAMILY = socket.AF_INET6
# FAMILY = socket.AF_UNSPEC # Returns multiple Listen options.

TYPE  = socket.SOCK_STREAM
PROTO = socket.IPPROTO_TCP
# TYPE  = socket.SOCK_DGRAM
# PROTO = socket.IPPROTO_UDP
# TYPE    = 0
# PROTO   = 0

PORT = 50007

FLAGS = socket.AI_PASSIVE

"""

########################################################################

# FLAGS = socket.AI_PASSIVE # means server (vs client) will give all zeros address.

# "If the AI_PASSIVE flag is specified, the returned address
# information shall be suitable for use in binding a socket for
# accepting incoming connections for the specified service. In this
# case, if the nodename argument is null, then the IP address portion
# of the socket address structure shall be set to INADDR_ANY for an
# IPv4 address or IN6ADDR_ANY_INIT for an IPv6 address."

# "If the AI_PASSIVE flag is not specified, the returned address
# information shall be suitable for a call to connect() (for a
# connection-mode protocol) or for a call to connect(), sendto(), or
# sendmsg() (for a connectionless protocol). In this case, if the
# nodename argument is null, then the IP address portion of the socket
# address structure shall be set to the loopback address."

# AI (Address Info), AI_PASSIVE, AI_CANONNAME, AI_NUMERICHOST (Address
# string given, no DNS lookup), AI_NUMERICSERV (Port string given, no
# lookup), AI_V4MAPPED, AI_ALL, and AI_ADDRCONFIG

########################################################################
# Use the above settings and call getaddrinfo
########################################################################

try:
    response = socket.getaddrinfo(
        HOST,
        PORT,
        family = FAMILY,
        type = TYPE,
        proto = PROTO,
        flags = FLAGS
    )
except Exception as msg:
    print(msg)
    exit()

print(response)    

for result in response:
    # Unpacket each result that was returned.
    family, socktype, proto, canonname, sockaddr = result

    print()
    print('Family        :', family)
    print('Type          :', socktype)
    print('Protocol      :', proto)
    print('Canonical name:', canonname)
    print('Socket address:', sockaddr)
    print()



    






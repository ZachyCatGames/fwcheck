#!/usr/bin/python3
import socket
import sys
import struct

# Get arguments.
src = sys.argv[1]
dst = sys.argv[2]
src_port = int(sys.argv[3])
dst_port = int(sys.argv[4])
data = bytes(sys.argv[5], "ascii")

# Resolve dst.
dst_ip = socket.getaddrinfo(dst, 0)[0][4][0]
src_ip = socket.getaddrinfo(src, 0)[0][4][0]

# Setup header elements.
# https://en.wikipedia.org/wiki/Internet_Protocol_version_4#Header
version    = 4 # byte 0 half 0
ihl        = 5 # byte 0 half 1
byte0      = version << 4 | ihl
byte1      = 0 # byte 1
total_size = 0x20 + 0x8 + len(data) # bytes 2 & 3. sizeof(ip_hdr) + sizeof(udp_hdr) + sizeof(data)
ident      = 0 # bytes 4 & 5.
fragment   = 0x1 << 14 # bytes 6 & 7
ttl        = 64 # byte 8
protocol   = socket.IPPROTO_UDP # byte 9
src_addr   = struct.unpack("!I", socket.inet_aton(src_ip))[0] # bytes 12 - 15
dst_addr   = struct.unpack("!I", socket.inet_aton(dst_ip))[0] # bytes 16 - 19

# Calculate checksum.
checksum = ((byte0 << 8) | byte1) + total_size + ident + fragment + ((ttl << 8) | protocol) + (src_addr >> 16) + (src_addr & 0xFFFF) + \
            (dst_addr >> 16) + (dst_addr & 0xFFFF)
while(checksum > 0xFFFF):
    top = checksum >> 16
    checksum = (checksum & 0xFFFF) + top

# Pack ip header.
ip_hdr = struct.pack("!BBHHHBBHII", byte0, byte1, total_size, ident, fragment, ttl, protocol, checksum, src_addr, dst_addr)
assert(len(ip_hdr) == 20)

# Pack udp header.
# https://en.wikipedia.org/wiki/User_Datagram_Protocol#UDP_datagram_structure
# NOTE: We aren't filling the checksum field since it appear netcat can still receive messages fine without it.
udp_size = 0x8 + len(data)
udp_hdr = struct.pack("!HHHH", src_port, dst_port, udp_size, 0)

# Pack whole packet.
packet = ip_hdr + udp_hdr + data

# Open socket.
sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)

# Send packet.
sock.sendto(packet, (dst_ip, dst_port))

# Close socket.
sock.close()

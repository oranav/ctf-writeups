#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# vim:fenc=utf-8
#
# Copyright: Oran Avraham <contact@oranav.me>
import struct
from z3 import BitVec, Extract, Solver, Concat


s = Solver()
flag = [BitVec(f'f{i}', 8) for i in range(16)]

shuffle = bytes.fromhex('02060701050B090E030F04080A0C0D00')
add32 = bytes.fromhex('EFBEADDEADDEE1FE3713371366746367')
xor = bytes.fromhex('7658B4498D1A5F38D423F834EB86F9AA')
expected_prefix = b'CTF{}'[:-1]

for f, v in zip(flag, expected_prefix):
    s.add(f == v)

dest = [flag[b] for b in shuffle]

words = []
for i in range(0, len(dest), 4):
    words.append(Concat(dest[i+3], dest[i+2], dest[i+1], dest[i]))

for i in range(len(words)):
    words[i] += struct.unpack('<I', add32[i*4:][:4])[0]

for i in range(len(words)):
    j = i*4
    dest[j+0] = Extract(7, 0, words[i])
    dest[j+1] = Extract(15, 8, words[i])
    dest[j+2] = Extract(23, 16, words[i])
    dest[j+3] = Extract(31, 24, words[i])

for i in range(len(dest)):
    dest[i] ^= xor[i]


for i in range(len(flag)):
    s.add(dest[i] == flag[i])

s.check()
m = s.model()
b = [m[f].as_long() for f in flag]
print(bytes(b).decode())

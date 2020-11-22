#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# vim:fenc=utf-8
#
# Copyright: Oran Avraham <contact@oranav.me>
import random
from base64 import b64encode, b64decode
from subprocess import check_output

from Crypto.Util.number import long_to_bytes
from Crypto.Cipher import AES
from pwn import remote, log

from util import DiffieHellman


class Solver:
    def __init__(self):
        # self.r = remote("127.0.0.1", 1337)
        self.r = remote("bitflip1.hackable.software", 1337)
        args = self.r.recvline().decode().split(": ")[1].strip().split()
        assert len(args) == 3
        assert args[0] == "hashcash"
        p = log.progress("Calculating proof of work")
        self.r.send(check_output(args))
        p.success()

    def get_iterations(self, mask):
        self.r.recvuntil(b"bit-flip str:\n")
        self.r.sendline(b64encode(long_to_bytes(mask, 32)))
        self.r.recvuntil(b"Generated after ")
        return int(self.r.recvuntil(b" iterations", drop=True))

    def get_data(self, mask):
        self.r.recvuntil(b"bit-flip str:\n")
        self.r.sendline(b64encode(long_to_bytes(mask, 32)))
        self.r.recvline()
        self.r.recvuntil(b"bob number ")
        bob = int(self.r.recvline().strip())
        iv = b64decode(self.r.recvline())
        enc = b64decode(self.r.recvline())
        return bob, iv, enc


def main():
    solver = Solver()

    # Find a mask that has a long chain of iterations until a prime is found
    p = log.progress("Looking for a suitable mask")
    while True:
        mask = random.randrange(1 << 256)
        if (iterations := solver.get_iterations(mask)) >= 256:
            break
    p.success(f"{hex(mask)} --> {iterations} iterations")

    # Assume LSB is 0... We will fail afterwards if it's wrong
    seed = 0

    # Initial bit finding: observe the offset in the iterations
    for bit in range(1, 8):
        shifted = 1 << bit
        offset = shifted // 2  # Because each prime generation takes 2 sha256s
        assert offset < 256
        if solver.get_iterations(mask ^ shifted) == iterations - offset:
            val = 0 ^ ((mask >> bit) & 1)
        else:
            val = 1 ^ ((mask >> bit) & 1)
        assert val in (0, 1)
        seed |= val << bit
        log.info(f"Current seed value: {hex(seed)}")

    # Use a seed of format XXXX...XX111
    # It's either XXXX...X0111 or XXXX...X1111
    # We then toggle a bit flip in the unknown bit and all other bits except the LSB
    # The seed becomes either XXXX...X1001 or XXXX...X0001
    # In the first case, this means an increment of 2 -- which is observable!
    for bit in range(8, 128):
        mask = seed ^ ((1 << bit) - 1)
        while (iterations := solver.get_iterations(mask)) < 4:
            mask ^= random.randrange(1 << 32) << 128
        for i in range(1, bit + 1):
            mask ^= 1 << i
        val = int(solver.get_iterations(mask) != iterations - 1)
        seed |= val << bit
        log.info(f"Current seed value: {hex(seed)}")

    # We've broken Alice's seed, except the LSB.
    bob, iv, enc = solver.get_data(seed)
    for lsb in range(2):
        alice = DiffieHellman(long_to_bytes(lsb, 32))
        alice.set_other(bob)
        cipher = AES.new(long_to_bytes(alice.shared, 16)[:16], AES.MODE_CBC, IV=iv)
        try:
            flag = cipher.decrypt(enc).decode("ascii")
            log.success(f"Flag is {flag}")
        except UnicodeDecodeError:
            pass


if __name__ == "__main__":
    main()

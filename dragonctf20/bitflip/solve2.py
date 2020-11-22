#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# vim:fenc=utf-8
#
# Copyright: Oran Avraham <contact@oranav.me>
import math
import os
import random
from hashlib import sha256
from base64 import b64encode, b64decode
from subprocess import check_output

import requests
import struct
from Crypto.Util.number import long_to_bytes, bytes_to_long
from Crypto.Cipher import AES
from pwn import remote, log
from gmpy2 import is_prime

from util import DiffieHellman, Rng


class Solver:
    def __init__(self):
        # self.r = remote("127.0.0.1", 1337)
        self.r = remote("bitflip2.hackable.software", 1337)
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
        iv = b64decode(self.r.recvline())
        enc = b64decode(self.r.recvline())
        return iv, enc


def tricky_sha_inputs():
    # Hand-crafted to succeed on the first try:
    block = "0000000000000000014a6c756a385603e2b1eccafbdf974e11ee851072d54303"
    while True:
        req = requests.get(f"https://blockchain.info/rawblock/{block}?format=hex")
        header = bytes.fromhex(req.text[: 80 * 2])
        base = sha256(header).digest()
        if sha256(base).digest().endswith(b"\0\0\0\0\0\0\0\0"):
            yield block, base
        else:
            log.warning("Block not sufficient")
        block = header[4:][:32][::-1].hex()


def find_tricky_rng_seed():
    # Find a seed such that we generate a secret == 0
    rng = Rng()
    for block, base in tricky_sha_inputs():
        p = log.progress(f"Trying block {block}")
        seed = long_to_bytes(bytes_to_long(base) - 2, 32)
        rng.set_seed(seed)
        prime = rng.getbits(512)
        assert rng.getbits() == 0

        if not is_prime(prime):
            p.failure()
        else:
            p.success()
            return seed


def main():
    log.info("Finding a tricky RNG seed value")
    tricky = find_tricky_rng_seed()

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

    # Make Alice generate a secret == 0.
    # We've broken Alice's seed, except the LSB.
    for lsb in range(2):
        iv, enc = solver.get_data(seed ^ bytes_to_long(tricky) ^ lsb)
        alice = DiffieHellman(tricky)
        alice.set_other(1337)
        cipher = AES.new(long_to_bytes(alice.shared, 16)[:16], AES.MODE_CBC, IV=iv)
        try:
            flag = cipher.decrypt(enc).decode("ascii")
            log.success(f"Flag is {flag}")
        except UnicodeDecodeError:
            pass


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# vim:fenc=utf-8
#
# Copyright: Oran Avraham <contact@oranav.me>
import math
import os
import random
import struct
from hashlib import sha256
from base64 import b64encode, b64decode
from subprocess import check_output
from io import BytesIO

import plyvel
from Crypto.Util.number import long_to_bytes, bytes_to_long
from Crypto.Cipher import AES
from pwn import remote, log
from gmpy2 import is_prime

from util import DiffieHellmanStrong, Rng


class Solver:
    def __init__(self):
        # self.r = remote("127.0.0.1", 1337)
        self.r = remote("bitflip3.hackable.software", 1337)
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

    def get_invocations(self, mask):
        return self.get_iterations(mask) * 2

    def get_data(self, mask):
        self.r.recvuntil(b"bit-flip str:\n")
        self.r.sendline(b64encode(long_to_bytes(mask, 32)))
        self.r.recvline()
        iv = b64decode(self.r.recvline())
        enc = b64decode(self.r.recvline())
        return iv, enc


class DiskBlockIndex:
    BLOCK_HAVE_DATA = 8
    BLOCK_HAVE_UNDO = 16

    def __init__(self, value):
        self._stream = BytesIO(value)
        self._parse()

    def _parse(self):
        self.nVersion = self.read_varint()
        self.nHeight = self.read_varint()
        self.nStatus = self.read_varint()
        self.nTx = self.read_varint()
        if self.nStatus & (self.BLOCK_HAVE_DATA | self.BLOCK_HAVE_UNDO):
            self.nFile = self.read_varint()
        if self.nStatus & self.BLOCK_HAVE_DATA:
            self.nDataPos = self.read_varint()
        if self.nStatus & self.BLOCK_HAVE_UNDO:
            self.nUndoPos = self.read_varint()

        self.header = self._stream.read(80)

    def read_varint(self):
        n = 0
        while True:
            x = self._stream.read(1)[0]
            n <<= 7
            n |= x & 0x7F
            if (x & 0x80) == 0:
                break
        return n


def tricky_sha_inputs():
    header_size = 80
    db = plyvel.DB(os.path.expanduser("~/.bitcoincash/blocks/index"))
    for key, value in db.iterator(prefix=b"b"):
        if not key.endswith(b"\0" * 8):
            continue

        index = DiskBlockIndex(value)
        base = sha256(index.header).digest()
        block = key[1:]
        assert sha256(base).digest() == block
        yield block[::-1].hex(), base


def find_tricky_rng_seed():
    # Hand-crafted so you don't have to run Bitcoin Cash before:
    return bytes.fromhex(
        "693e14ccadf6c831ea694f6d8651d6c912c4377ecc22b2f498d2ee60b66c53bd"
    )

    # Find a seed such that we generate a secret == 0
    rng = Rng()
    for block, base in tricky_sha_inputs():
        seed = long_to_bytes(bytes_to_long(base) - 2, 32)
        rng.set_seed(seed)

        prime = rng.getbits(512)
        secret = rng.getbits()
        assert secret == 0

        strong_prime = 2 * prime + 1
        if prime % 5 == 4 and is_prime(prime) and is_prime(strong_prime):
            log.success(f"Seed {seed.hex()} is suitable! (from block {block})")
            return seed
    raise Exception("Could not find a suitable seed!")


def main():
    log.info("Finding a tricky RNG seed value")
    tricky = find_tricky_rng_seed()

    solver = Solver()

    # Find a mask that has a long chain of invocations until a prime is found
    p = log.progress("Looking for a suitable mask")
    while True:
        mask = random.randrange(1 << 256)
        if (invocations := solver.get_invocations(mask)) >= 256:
            break
    p.success(f"{hex(mask)} --> {invocations} invocations")

    # Assume LSB is 0... We will fail afterwards if it's wrong
    seed = 0
    known = [False] * 128

    # Find a sane invocations value
    log.info("Lowering invocations")
    while invocations > (1 << 16):
        bit = int(math.log2(invocations))
        while known[bit]:
            bit -= 1
        if bit <= 9:
            break

        log.info(f"Finding bit {bit}, difficulty {invocations} invocations")
        shifted = 1 << bit
        if solver.get_invocations(mask ^ shifted) == invocations - shifted:
            val = 0 ^ ((mask >> bit) & 1)
            # Update parameters -- so we move faster next time :-)
            invocations -= shifted
            mask ^= shifted
        else:
            val = 1 ^ ((mask >> bit) & 1)
        assert val in (0, 1)
        seed |= val << bit
        known[bit] = True
        log.info(f"Current seed value: {hex(seed)}")

    upper_bit = int(math.log2(invocations))

    # Initial bit finding: observe the offset in the invocations
    log.info("Bit finding")
    for bit in range(upper_bit, 0, -1):
        if known[bit]:
            continue

        log.info(f"Finding bit {bit}, difficulty {invocations} invocations")
        shifted = 1 << bit
        assert shifted <= invocations
        if solver.get_invocations(mask ^ shifted) == invocations - shifted:
            val = 0 ^ ((mask >> bit) & 1)
        else:
            val = 1 ^ ((mask >> bit) & 1)
        assert val in (0, 1)
        seed |= val << bit
        known[bit] = True
        log.info(f"Current seed value: {hex(seed)}")

    # Use a seed of format XXXX...XX111
    # It's either XXXX...X0111 or XXXX...X1111
    # We then toggle a bit flip in the unknown bit and all other bits except the LSB
    # The seed becomes either XXXX...X1001 or XXXX...X0001
    # In the first case, this means an increment of 2 -- which is observable!
    log.info("2^n - 1 attack")
    for bit in range(upper_bit + 1, 128):
        mask = seed ^ ((1 << bit) - 1)
        while (invocations := solver.get_invocations(mask)) < 4:
            mask ^= random.randrange(1 << 32) << 128
        for i in range(1, bit + 1):
            mask ^= 1 << i
        val = int(solver.get_invocations(mask) != invocations - 2)
        seed |= val << bit
        log.info(f"Current seed value: {hex(seed)}")

    # Make Alice generate a secret == 0.
    # We've broken Alice's seed, except the LSB.
    for lsb in range(2):
        iv, enc = solver.get_data(seed ^ bytes_to_long(tricky) ^ lsb)
        alice = DiffieHellmanStrong(tricky)
        alice.set_other(1337)
        cipher = AES.new(long_to_bytes(alice.shared, 16)[:16], AES.MODE_CBC, IV=iv)
        try:
            flag = cipher.decrypt(enc).decode("ascii")
            log.success(f"Flag is {flag}")
        except UnicodeDecodeError:
            pass


if __name__ == "__main__":
    main()

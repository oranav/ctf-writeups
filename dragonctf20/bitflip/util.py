#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# vim:fenc=utf-8
#
# Copyright: Oran Avraham <contact@oranav.me>
import hashlib
from gmpy2 import is_prime
from Crypto.Util.number import bytes_to_long, long_to_bytes


class Rng:
    def __init__(self, seed=b""):
        self.set_seed(seed)

    def set_seed(self, seed):
        self.seed = seed
        self.generated = b""
        self.num = 0

    def more_bytes(self):
        self.generated += hashlib.sha256(self.seed).digest()
        self.seed = long_to_bytes(bytes_to_long(self.seed) + 1, 32)
        self.num += 256

    def getbits(self, num=64):
        while self.num < num:
            self.more_bytes()
        x = bytes_to_long(self.generated)
        self.num -= num
        self.generated = b""
        if self.num > 0:
            self.generated = long_to_bytes(x >> num, self.num // 8)
        return x & ((1 << num) - 1)


class DiffieHellman:
    def gen_prime(self):
        prime = self.rng.getbits(512)
        iter = 0
        while not is_prime(prime):
            iter += 1
            prime = self.rng.getbits(512)
        return prime

    def __init__(self, seed, prime=None):
        self.rng = Rng(seed)
        if prime is None:
            prime = self.gen_prime()

        self.prime = prime
        self.my_secret = self.rng.getbits()
        self.my_number = pow(5, self.my_secret, prime)
        self.shared = 1337

    def set_other(self, x):
        self.shared ^= pow(x, self.my_secret, self.prime)


class DiffieHellmanStrong:
    def gen_strong_prime(self):
        prime = self.rng.getbits(512)
        iter = 0
        strong_prime = 2 * prime + 1
        while not (prime % 5 == 4) or not is_prime(prime) or not is_prime(strong_prime):
            iter += 1
            prime = self.rng.getbits(512)
            strong_prime = 2 * prime + 1
        print("Generated after", iter, "iterations")
        return strong_prime

    def __init__(self, seed, prime=None):
        self.rng = Rng(seed)
        if prime is None:
            prime = self.gen_strong_prime()

        self.prime = prime
        self.my_secret = self.rng.getbits()
        self.my_number = pow(5, self.my_secret, prime)
        self.shared = 1337

    def set_other(self, x):
        self.shared ^= pow(x, self.my_secret, self.prime)

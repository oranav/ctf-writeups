#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# vim:fenc=utf-8
#
# Copyright © 2020 Oranav <contact@oranav.me>
#
# Distributed under terms of the GPLv3 license.
# Based on: https://gist.github.com/HoLyVieR/11e464a91b290e33b38e
import struct

DIGEST_SIZE = 16
BLOCK_SIZE = 64

# Constants for compression function.
S11 = 7
S12 = 12
S13 = 17
S14 = 22

PADDING = b"\x80" + 63*b"\0"


def F(x, y, z): return (((x) & (y)) | ((~x) & (z)))


def ROTATE_LEFT(x, n):
    x = x & 0xffffffff   # make shift unsigned
    return (((x) << (n)) | ((x) >> (32-(n)))) & 0xffffffff


def ROTATE_RIGHT(x, n):
    return ROTATE_LEFT(x, 32-n)


def FF(a, b, c, d, x, s, ac):
    a = a + F ((b), (c), (d)) + (x) + (ac)
    a = ROTATE_LEFT ((a), (s))
    a = a + b
    return a # must assign this to a


def InvFF(res, b, c, d, x, s, ac):
    # This is just FF in reverese, given that only a is unknown.
    res = res - b
    res = ROTATE_RIGHT ((res), (s))
    res = res - F ((b), (c), (d)) - (x) - (ac)
    return res & 0xffffffff


def PreimageFF(res, a, b, c, d, s, ac):
    # This is FF for when the result is known but the input block is unknown.
    res = res - b
    res = ROTATE_RIGHT ((res), (s))
    res = res - F ((b), (c), (d)) - (ac)
    return (res - a) & 0xffffffff, a


def padding(msg_bits):
    """padding(msg_bits) - Generates the padding that should be
    appended to the end of a message of the given size to reach
    a multiple of the block size."""

    index = int((msg_bits >> 3) & 0x3f)
    if index < 56:
        padLen = (56 - index)
    else:
        padLen = (120 - index)

    # (the last 8 bytes store the number of bits in the message)
    return PADDING[:padLen] + _encode((msg_bits & 0xffffffff, msg_bits>>32), 8)


def md15_compress(msg):
    state = (0x67452301,
             0xefcdab89,
             0x98badcfe,
             0x10325476,)
    a, b, c, d = state
    block = msg + padding(len(msg) * 8)
    x = _decode(block, BLOCK_SIZE)

    #  Round
    a = FF (a, b, c, d, x[ 0], S11, 0xd76aa478) # 1
    d = FF (d, a, b, c, x[ 1], S12, 0xe8c7b756) # 2
    c = FF (c, d, a, b, x[ 2], S13, 0x242070db) # 3
    b = FF (b, c, d, a, x[ 3], S14, 0xc1bdceee) # 4
    a = FF (a, b, c, d, x[ 4], S11, 0xf57c0faf) # 5
    d = FF (d, a, b, c, x[ 5], S12, 0x4787c62a) # 6
    c = FF (c, d, a, b, x[ 6], S13, 0xa8304613) # 7
    b = FF (b, c, d, a, x[ 7], S14, 0xfd469501) # 8
    a = FF (a, b, c, d, x[ 8], S11, 0x698098d8) # 9
    d = FF (d, a, b, c, x[ 9], S12, 0x8b44f7af) # 10
    c = FF (c, d, a, b, x[10], S13, 0xffff5bb1) # 11
    b = FF (b, c, d, a, x[11], S14, 0x895cd7be) # 12

    state = (0xffffffff & (state[0] + a),
             0xffffffff & (state[1] + b),
             0xffffffff & (state[2] + c),
             0xffffffff & (state[3] + d),)
    return _encode(state, DIGEST_SIZE)


def md15_decompress(state):
    msg = b'A'*16
    block = msg + padding(len(msg) * 8)
    a, b, c, d = _decode(state, DIGEST_SIZE)
    x = _decode(block, BLOCK_SIZE)
    # x[0:4] are unknowns so we must not use them
    x[0:4] = [None] * 4
    initial_state = (0x67452301,
                     0xefcdab89,
                     0x98badcfe,
                     0x10325476,)

    # reverse final state calculation
    a = (a - initial_state[0]) & 0xffffffff
    b = (b - initial_state[1]) & 0xffffffff
    c = (c - initial_state[2]) & 0xffffffff
    d = (d - initial_state[3]) & 0xffffffff

    # reverse rounds 12...5
    b = InvFF (b, c, d, a, x[11], S14, 0x895cd7be) # 12
    c = InvFF (c, d, a, b, x[10], S13, 0xffff5bb1) # 11
    d = InvFF (d, a, b, c, x[ 9], S12, 0x8b44f7af) # 10
    a = InvFF (a, b, c, d, x[ 8], S11, 0x698098d8) # 9
    b = InvFF (b, c, d, a, x[ 7], S14, 0xfd469501) # 8
    c = InvFF (c, d, a, b, x[ 6], S13, 0xa8304613) # 7
    d = InvFF (d, a, b, c, x[ 5], S12, 0x4787c62a) # 6
    a = InvFF (a, b, c, d, x[ 4], S11, 0xf57c0faf) # 5
    # reverse rounds 4...1 and restore block data
    x[3], b = PreimageFF (b, initial_state[1], c, d, a, S14, 0xc1bdceee) # 4
    x[2], c = PreimageFF (c, initial_state[2], d, a, b, S13, 0x242070db) # 3
    x[1], d = PreimageFF (d, initial_state[3], a, b, c, S12, 0xe8c7b756) # 2
    x[0], a = PreimageFF (a, initial_state[0], b, c, d, S11, 0xd76aa478) # 1

    block = _encode(x, BLOCK_SIZE)
    return block[:16]


def _encode(input, len):
    k = len >> 2
    res = struct.pack(*(("%iI" % k,) + tuple(input[:k])))
    return res


def _decode(input, len):
    k = len >> 2
    res = struct.unpack("%iI" % k, input[:len])
    return list(res)


def main():
    with open('md15', 'rb') as f:
        f.seek(0xb007)
        digest = f.read(16)
    data = md15_decompress(digest)
    assert md15_compress(data) == digest
    text = bytes(x ^ ord('h') for x in data)
    print('hxp{%s}' % text.decode('ascii'))


if __name__=="__main__":
    main()

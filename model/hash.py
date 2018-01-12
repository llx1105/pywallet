#!/usr/bin/env python
# -*- coding: utf-8 -*-
# bitcointools hashes and base58 implementation

import hashlib
from lib.dependency import *
from lib.constants import *

def md5_2(a):
    return hashlib.md5(a).digest()


def Hash(data):
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()

def hash_160(public_key):
    md = hashlib.new('ripemd160')
    md.update(hashlib.sha256(public_key).digest())
    return md.digest()


def public_key_to_bc_address(public_key, v=None):
    if v == None:
        v = addrtype
    h160 = hash_160(public_key)
    return hash_160_to_bc_address(h160, v)


def hash_160_to_bc_address(h160, v=None):
    if v == None:
        v = addrtype
    # 前缀 + 数据
    vh160 = chr(v) + h160
    ##对前缀+数据进行hash计算
    h = Hash(vh160)
    ##取结果前四位做为校验码
    addr = vh160 + h[0:4]
    ##Base58编码
    return b58encode(addr)


def bc_address_to_hash_160(addr):
    bytes = b58decode(addr, 25)
    return bytes[1:21]


__b58chars = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
__b58base = len(__b58chars)


def b58encode(v):
    """ encode v, which is a string of bytes, to base58.
	"""

    long_value = 0L
    for (i, c) in enumerate(v[::-1]):
        long_value += (256 ** i) * ord(c)

    result = ''
    while long_value >= __b58base:
        div, mod = divmod(long_value, __b58base)
        result = __b58chars[mod] + result
        long_value = div
    result = __b58chars[long_value] + result

    # Bitcoin does a little leading-zero-compression:
    # leading 0-bytes in the input become leading-1s
    nPad = 0
    for c in v:
        if c == '\0':
            nPad += 1
        else:
            break

    return (__b58chars[0] * nPad) + result


def b58decode(v, length):
    """ decode v into a string of len bytes
	"""
    long_value = 0L
# reverse
    for (i, c) in enumerate(v[::-1]):
        long_value += __b58chars.find(c) * (__b58base ** i)

    result = ''
    while long_value >= 256:
        div, mod = divmod(long_value, 256)
        result = chr(mod) + result
        long_value = div
    result = chr(long_value) + result

    nPad = 0
    for c in v:
        if c == __b58chars[0]:
            nPad += 1
        else:
            break

    result = chr(0) * nPad + result
    if length is not None and len(result) != length:
        return None

    return result


    # end of bitcointools base58 implementation
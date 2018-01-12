#!/usr/bin/env python
# -*- coding: utf-8 -*-
import random
from lib.constants import *
from lib.dependency import *
from lib.ECDSA_constants import *


try:
    import ecdsa
    from ecdsa import der

    curve_secp256k1 = ecdsa.ellipticcurve.CurveFp(_p, _a, _b)
    generator_secp256k1 = g = ecdsa.ellipticcurve.Point(curve_secp256k1, _Gx, _Gy, _r)
    randrange = random.SystemRandom().randrange
    secp256k1 = ecdsa.curves.Curve("secp256k1", curve_secp256k1, generator_secp256k1, (1, 3, 132, 0, 10))
    ecdsa.curves.curves.append(secp256k1)
except:
    missing_dep.append('ecdsa')


class CurveFp(object):
    def __init__(self, p, a, b):
        self.__p = p
        self.__a = a
        self.__b = b

    def p(self):
        return self.__p

    def a(self):
        return self.__a

    def b(self):
        return self.__b

    def contains_point(self, x, y):
        return (y * y - (x * x * x + self.__a * x + self.__b)) % self.__p == 0


class Point(object):
    def __init__(self, curve, x, y, order=None):
        self.__curve = curve
        self.__x = x
        self.__y = y
        self.__order = order
        if self.__curve: assert self.__curve.contains_point(x, y)
        if order: assert self * order == INFINITY

    def __add__(self, other):
        if other == INFINITY: return self
        if self == INFINITY: return other
        assert self.__curve == other.__curve
        if self.__x == other.__x:
            if (self.__y + other.__y) % self.__curve.p() == 0:
                return INFINITY
            else:
                return self.double()

        p = self.__curve.p()
        l = ((other.__y - self.__y) * \
             inverse_mod(other.__x - self.__x, p)) % p
        x3 = (l * l - self.__x - other.__x) % p
        y3 = (l * (self.__x - x3) - self.__y) % p
        return Point(self.__curve, x3, y3)

    def __mul__(self, other):
        def leftmost_bit(x):
            assert x > 0
            result = 1L
            while result <= x: result = 2 * result
            return result / 2

        e = other
        if self.__order: e = e % self.__order
        if e == 0: return INFINITY
        if self == INFINITY: return INFINITY
        assert e > 0
        e3 = 3 * e
        negative_self = Point(self.__curve, self.__x, -self.__y, self.__order)
        i = leftmost_bit(e3) / 2
        result = self
        while i > 1:
            result = result.double()
            if (e3 & i) != 0 and (e & i) == 0: result = result + self
            if (e3 & i) == 0 and (e & i) != 0: result = result + negative_self
            i = i / 2
        return result

    def __rmul__(self, other):
        return self * other

    def __str__(self):
        if self == INFINITY: return "infinity"
        return "(%d,%d)" % (self.__x, self.__y)

    def double(self):
        if self == INFINITY:
            return INFINITY

        p = self.__curve.p()
        a = self.__curve.a()
        l = ((3 * self.__x * self.__x + a) * \
             inverse_mod(2 * self.__y, p)) % p
        x3 = (l * l - 2 * self.__x) % p
        y3 = (l * (self.__x - x3) - self.__y) % p
        return Point(self.__curve, x3, y3)

    def x(self):
        return self.__x

    def y(self):
        return self.__y

    def curve(self):
        return self.__curve

    def order(self):
        return self.__order


INFINITY = Point(None, None, None)


def inverse_mod(a, m):
    if a < 0 or m <= a: a = a % m
    c, d = a, m
    uc, vc, ud, vd = 1, 0, 0, 1
    while c != 0:
        q, c, d = divmod(d, c) + (c,)
        uc, vc, ud, vd = ud - q * uc, vd - q * vc, uc, vc
    assert d == 1
    if ud > 0:
        return ud
    else:
        return ud + m


class Signature(object):
    def __init__(self, r, s):
        self.r = r
        self.s = s


class Public_key(object):
    def __init__(self, generator, point, c=None):
        self.curve = generator.curve()
        self.generator = generator
        self.point = point
        self.compressed = c
        n = generator.order()
        if not n:
            raise RuntimeError, "Generator point must have order."
        if not n * point == INFINITY:
            raise RuntimeError, "Generator point order is bad."
        if point.x() < 0 or n <= point.x() or point.y() < 0 or n <= point.y():
            raise RuntimeError, "Generator point has x or y out of range."

    def verifies(self, hash, signature):
        G = self.generator
        n = G.order()
        r = signature.r
        s = signature.s
        if r < 1 or r > n - 1: return False
        if s < 1 or s > n - 1: return False
        c = inverse_mod(s, n)
        u1 = (hash * c) % n
        u2 = (r * c) % n
        xy = u1 * G + u2 * self.point
        v = xy.x() % n
        return v == r

    def ser(self):
        if self.compressed:
            pk = ('%02x' % (2 + (self.point.y() & 1))) + '%064x' % self.point.x()
        else:
            pk = '04%064x%064x' % (self.point.x(), self.point.y())

        return pk.decode('hex')

    def get_addr(self, v=0):
        return public_key_to_bc_address(self.ser(), v)


class Private_key(object):
    def __init__(self, public_key, secret_multiplier):
        self.public_key = public_key
        self.secret_multiplier = secret_multiplier

    def der(self):
        hex_der_key = '06052b8104000a30740201010420' + \
                      '%064x' % self.secret_multiplier + \
                      'a00706052b8104000aa14403420004' + \
                      '%064x' % self.public_key.point.x() + \
                      '%064x' % self.public_key.point.y()
        return hex_der_key.decode('hex')

    def sign(self, hash, random_k):
        G = self.public_key.generator
        n = G.order()
        k = random_k % n
        p1 = k * G
        r = p1.x()
        if r == 0: raise RuntimeError, "amazingly unlucky random number r"
        s = (inverse_mod(k, n) * \
             (hash + (self.secret_multiplier * r) % n)) % n
        if s == 0: raise RuntimeError, "amazingly unlucky random number s"
        return Signature(r, s)


class EC_KEY(object):
    def __init__(self, secret):
        curve = CurveFp(_p, _a, _b)
        generator = Point(curve, _Gx, _Gy, _r)
        # 椭圆曲线密码学
        self.pubkey = Public_key(generator, generator * secret)
        self.privkey = Private_key(self.pubkey, secret)
        self.secret = secret


        # end of python-ecdsa code

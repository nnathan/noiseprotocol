#!/usr/bin/env python

from collections import namedtuple
import os

DHKeyPair = namedtuple('DHKeyPair', ['private', 'public'])

class DH(object):
    pass

class Curve25519(DH):

    _P = 2 ** 255 - 19
    _A = 486662

    def __init__(self):
        pass

    @property
    def name(self):
        return '25519'

    @staticmethod
    def _expmod(b, e, m):
        if e == 0:
            return 1

	t = Curve25519._expmod(b, e / 2, m) ** 2 % m

        if e & 1: t = (t * b) % m
        return t

    @staticmethod
    def _inv(x):
        return Curve25519._expmod(x, Curve25519._P - 2, Curve25519._P)

    # Addition and doubling formulas taken from Appendix D of "Curve25519:
    # new Diffie-Hellman speed records".

    @staticmethod
    def _add((xn,zn), (xm,zm), (xd,zd)):
        x = 4 * (xm * xn - zm * zn) ** 2 * zd
        z = 4 * (xm * zn - zm * xn) ** 2 * xd
        return (x % Curve25519._P, z % Curve25519._P)

    @staticmethod
    def _double((xn,zn)):
        x = (xn ** 2 - zn ** 2) ** 2
        z = 4 * xn * zn * (xn ** 2 + Curve25519._A * xn * zn + zn ** 2)
        return (x % Curve25519._P, z % Curve25519._P)

    @staticmethod
    def _curve25519(n, base):
        one = (base,1)
        two = Curve25519._double(one)
        # f(m) evaluates to a tuple containing the mth multiple and the
        # (m+1)th multiple of base.
        def f(m):
            if m == 1: return (one, two)
            (pm, pm1) = f(m / 2)
            if (m & 1):
                return (Curve25519._add(pm, pm1, one), Curve25519._double(pm1))
            return (Curve25519._double(pm), Curve25519._add(pm, pm1, one))
        ((x,z), _) = f(n)
        return (x * Curve25519._inv(z)) % Curve25519._P

    @staticmethod
    def _unpack(s):
        if len(s) != 32: raise ValueError('Invalid Curve25519 argument')
        return sum(ord(s[i]) << (8 * i) for i in range(32))

    @staticmethod
    def _pack(n):
        return ''.join([chr((n >> (8 * i)) & 255) for i in range(32)])

    @staticmethod
    def _clamp(n):
        n &= ~7
        n &= ~(128 << 8 * 31)
        n |= 64 << 8 * 31
        return n

    @staticmethod
    def _smult_curve25519(n, p):
        n = Curve25519._clamp(Curve25519._unpack(n))
        p = Curve25519._unpack(p)
        return Curve25519._pack(Curve25519._curve25519(n, p))

    @staticmethod
    def _smult_curve25519_base(n):
        n = Curve25519._clamp(Curve25519._unpack(n))
        return Curve25519._pack(Curve25519._curve25519(n, 9))

    def generate_keypair(self):
        priv = os.urandom(32)
        pub = self._smult_curve25519_base(priv)
        return DHKeyPair(priv, pub)

    def dh(self, keypair, public_key):
        return self._smult_curve25519(keypair.private, public_key)

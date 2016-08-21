#!/usr/bin/env python

from collections import namedtuple
import os

from eccsnacks.curve25519 import scalarmult as c25519_scalarmult
from eccsnacks.curve25519 import scalarmult_base as c25519_scalarmult_base
from eccsnacks.curve448 import scalarmult as c448_scalarmult
from eccsnacks.curve448 import scalarmult_base as c448_scalarmult_base


DHKeyPair = namedtuple('DHKeyPair', ['private', 'public'])


class Curve25519(object):

    name = '25519'
    dhlen = 32

    def __init__(self):
        pass

    def generate_keypair(self):
        priv = os.urandom(32)
        pub = c25519_scalarmult_base(priv)
        return DHKeyPair(priv, pub)

    def dh(self, keypair, public_key):
        return c25519_scalarmult(keypair.private, public_key)


class Curve448(object):

    name = '448'
    dhlen = 56

    def __init__(self):
        pass

    def generate_keypair(self):
        priv = os.urandom(56)
        pub = c448_scalarmult_base(priv)
        return DHKeyPair(priv, pub)

    def dh(self, keypair, public_key):
        return c448_scalarmult(keypair.private, public_key)

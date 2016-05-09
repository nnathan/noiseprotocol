#!/usr/bin/env python

from hashlib import sha256, sha512

from pyblake2 import blake2s, blake2b


class HashFunction(object):

    @property
    def name(self):
        return self.__class__.__name__


class SHA256(HashFunction):

    def hash(self, data):
        return sha256(data).digest()


class SHA512(HashFunction):

    def hash(self, data):
        return sha512(data).digest()


class BLAKE2b(HashFunction):

    def hash(self, data):
        return blake2b(data).digest()


class BLAKE2s(HashFunction):

    def hash(self, data):
        return blake2s(data).digest()

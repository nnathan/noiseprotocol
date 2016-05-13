#!/usr/bin/env python

from binascii import unhexlify, hexlify

import pytest

from noiseprotocol.crypto.dh import DHKeyPair, Curve25519


def test_Curve25519_name():
    assert Curve25519().name == '25519'


# from https://www.ietf.org/rfc/rfc7748.txt
def test_Curve25519_kat():
    alice_keypair = DHKeyPair(
        unhexlify('77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a'),
        unhexlify('8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a')
    )
    bob_public_key = unhexlify('de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f')

    c = Curve25519()
    k = c.dh(alice_keypair, bob_public_key)
    assert hexlify(k) == '4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742'

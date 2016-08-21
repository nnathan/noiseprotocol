#!/usr/bin/env python

from binascii import unhexlify, hexlify

import pytest

from noiseprotocol.crypto.dh import DHKeyPair, Curve25519, Curve448


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


def test_Curve448_name():
    assert Curve448().name == '448'


# from https://www.ietf.org/rfc/rfc7748.txt
def test_Curve448_kat():
    alice_keypair = DHKeyPair(
        unhexlify(
            '9a8f4925d1519f5775cf46b04b5800d4ee9ee8bae8bc5565d498c28d'
            'd9c9baf574a9419744897391006382a6f127ab1d9ac2d8c0a598726b'
        ),
        unhexlify(
            '1c306a7ac2a0e2e0990b294470cba339e6453772b075811d8fad0d1d'
            '6927c120bb5ee8972b0d3e21374c9c921b09d1b0366f10b65173992d'
        )
    )

    bob_public_key = unhexlify(
            '3eb7a829b0cd20f5bcfc0b599b6feccf6da4627107bdb0d4f345b430'
            '27d8b972fc3e34fb4232a13ca706dcb57aec3dae07bdc1c67bf33609'
    )

    c = Curve448()
    k = c.dh(alice_keypair, bob_public_key)
    assert hexlify(k) == (
        '07fff4181ac6cc95ec1c16a94a0f74d12da232ce40a77552281d282b'
        'b60c0b56fd2464c335543936521c24403085d59a449a5037514a879d'
    )

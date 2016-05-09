#!/usr/bin/env python

from binascii import unhexlify

import pytest

from noiseprotocol.crypto.hash import SHA256, SHA512

from hashlib import sha256 as _sha256, sha512 as _sha512

@pytest.mark.parametrize(
    'data,expected_digest',
    [
        ('\x00', _sha256('\x00').digest()),
        ('\x00'*16, _sha256('\x00'*16).digest()),
        ('\x00'*32, _sha256('\x00'*32).digest()),
        ('\x00'*64, _sha256('\x00'*64).digest()),
        ('\x00'*128, _sha256('\x00'*128).digest()),
    ]
)
def test_sha256_kat(data, expected_digest):
    assert SHA256().hash(data) == expected_digest


@pytest.mark.parametrize(
    'data,expected_digest',
    [
        ('\x00', _sha512('\x00').digest()),
        ('\x00'*16, _sha512('\x00'*16).digest()),
        ('\x00'*32, _sha512('\x00'*32).digest()),
        ('\x00'*64, _sha512('\x00'*64).digest()),
        ('\x00'*128, _sha512('\x00'*128).digest()),
    ]
)
def test_sha512_kat(data, expected_digest):
    assert SHA512().hash(data) == expected_digest

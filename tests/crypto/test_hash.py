#!/usr/bin/env python

from binascii import unhexlify

import pytest

from noiseprotocol.crypto.hash import SHA256, SHA512, BLAKE2s, BLAKE2b

from hashlib import sha256 as _sha256, sha512 as _sha512

from pyblake2 import blake2s as _blake2s, blake2b as _blake2b


def test_SHA256_name():
    assert SHA256().name == 'SHA256'


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
def test_SHA256_kat(data, expected_digest):
    assert SHA256().hash(data) == expected_digest


def test_SHA512_name():
    assert SHA512().name == 'SHA512'


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
def test_SHA512_kat(data, expected_digest):
    assert SHA512().hash(data) == expected_digest


def test_BLAKE2b_name():
    assert BLAKE2b().name == 'BLAKE2b'


@pytest.mark.parametrize(
    'data,expected_digest',
    [
        ('\x00', _blake2b('\x00').digest()),
        ('\x00'*16, _blake2b('\x00'*16).digest()),
        ('\x00'*32, _blake2b('\x00'*32).digest()),
        ('\x00'*64, _blake2b('\x00'*64).digest()),
        ('\x00'*128, _blake2b('\x00'*128).digest()),
    ]
)
def test_BLAKE2b_kat(data, expected_digest):
    assert BLAKE2b().hash(data) == expected_digest


def test_BLAKE2s_name():
    assert BLAKE2s().name == 'BLAKE2s'


@pytest.mark.parametrize(
    'data,expected_digest',
    [
        ('\x00', _blake2s('\x00').digest()),
        ('\x00'*16, _blake2s('\x00'*16).digest()),
        ('\x00'*32, _blake2s('\x00'*32).digest()),
        ('\x00'*64, _blake2s('\x00'*64).digest()),
        ('\x00'*128, _blake2s('\x00'*128).digest()),
    ]
)
def test_BLAKE2s_kat(data, expected_digest):
    assert BLAKE2s().hash(data) == expected_digest

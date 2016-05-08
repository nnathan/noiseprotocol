#!/usr/bin/env python

import pytest

from noiseprotocol.crypto.aead import AESGCM


@pytest.mark.parametrize('invalid_length', range(32) + [33])
def test_AESGCM_invalid_key_length(invalid_length):
    with pytest.raises(ValueError):
        AESGCM('\x00' * invalid_length)


def test_AESGCM_valid_key_length():
    AESGCM('\x00'*32)


@pytest.mark.parametrize('invalid_length', range(16))
def test_AESGCM_decrypt_invalid_ciphertext_length(invalid_length):
    with pytest.raises(ValueError):
        AESGCM('\x00' * 32).decrypt('\x00'*12, '0', 'x'*invalid_length)

@pytest.mark.parametrize(
    'input_nonce,expected',
    [
        (0, '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'),
        (1, '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01'),
        (2**32 - 1, '\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\xff\xff'),
        (2**64 - 1, '\x00\x00\x00\x00\xff\xff\xff\xff\xff\xff\xff\xff'),
    ]
)
def test_AESGCM_nonce(input_nonce, expected):
    assert AESGCM.nonce(input_nonce) == expected

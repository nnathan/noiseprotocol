#!/usr/bin/env python

import pytest

from noiseprotocol.crypto.aead import aes_gcm_encrypt, aes_gcm_decrypt

@pytest.mark.parametrize('invalid_length', range(32) + [33])
def test_aes_gcm_encrypt_invalid_key_length(invalid_length):
    with pytest.raises(ValueError):
        aes_gcm_encrypt('\x00' * invalid_length, 'x', 'x', 'x'*32)

@pytest.mark.parametrize('invalid_length', range(32) + [33])
def test_aes_gcm_decrypt_invalid_key_length(invalid_length):
    with pytest.raises(ValueError):
        aes_gcm_decrypt('\x00' * invalid_length, 'x', 'x', 'x'*32)

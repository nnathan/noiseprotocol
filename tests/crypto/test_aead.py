#!/usr/bin/env python

import pytest

from noiseprotocol.crypto.aead import AESGCM

@pytest.mark.parametrize('invalid_length', range(32) + [33])
def test_AESGCM_invalid_key_length(invalid_length):
    with pytest.raises(ValueError):
        AESGCM('\x00' * invalid_length)

def test_AESGCM_valid_key_length():
    AESGCM('\x00'*32)

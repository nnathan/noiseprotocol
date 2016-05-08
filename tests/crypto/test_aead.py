#!/usr/bin/env python

from binascii import unhexlify

import pytest

from noiseprotocol.crypto.aead import AESGCM


def test_AESGCM_name():
    assert AESGCM('\x00'*32).name == 'AESGCM'


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
    'in_nonce,expected',
    [
        (0, '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'),
        (1, '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01'),
        (2**32 - 1, '\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\xff\xff'),
        (2**64 - 1, '\x00\x00\x00\x00\xff\xff\xff\xff\xff\xff\xff\xff'),
    ]
)
def test_AESGCM_nonce(in_nonce, expected):
    assert AESGCM.nonce(in_nonce) == expected


# KATs (or known answer test/test vectors) have been taken from:
# http://csrc.nist.gov/groups/STM/cavp/
@pytest.mark.parametrize(
    'in_key,in_nonce,in_plaintext,in_ad,expected_ciphertext',
    [
        (
            unhexlify('b52c505a37d78eda5dd34f20c22540ea1b58963cf8e5bf8ffa85f9f2492505b4'),
            unhexlify('516c33929df5a3284ff463d7'),
            '',
            '',
            unhexlify('bdc1ac884d332457a1d2664f168c76f0')
        ),
        (
            unhexlify('78dc4e0aaf52d935c3c01eea57428f00ca1fd475f5da86a49c8dd73d68c8e223'),
            unhexlify('d79cf22d504cc793c3fb6c8a'),
            '',
            unhexlify('b96baa8c1c75a671bfb2d08d06be5f36'),
            unhexlify('3e5d486aa2e30b22e040b85723a06e76'),
        ),
        (
            unhexlify('5fe01c4baf01cbe07796d5aaef6ec1f45193a98a223594ae4f0ef4952e82e330'),
            unhexlify('bd587321566c7f1a5dd8652d'),
            unhexlify('881dc6c7a5d4509f3c4bd2daab08f165ddc204489aa8134562a4eac3d0bcad7965847b102733bb63d1e5c598ece0c3e5dadddd'),  # noqa
            unhexlify('9013617817dda947e135ee6dd3653382'),
            unhexlify('16e375b4973b339d3f746c1c5a568bc7526e909ddff1e19c95c94a6ccff210c9a4a40679de5760c396ac0e2ceb1234f9f5fe26') + unhexlify('abd3d26d65a6275f7a4f56b422acab49')  # noqa
        ),
    ]
)
def test_AESGCM_encrypt_KAT(in_key, in_nonce, in_plaintext, in_ad, expected_ciphertext):
    assert AESGCM(in_key).encrypt(in_nonce, in_ad, in_plaintext) == expected_ciphertext


# KATs (or known answer test/test vectors) have been taken from:
# http://csrc.nist.gov/groups/STM/cavp/
@pytest.mark.parametrize(
    'in_key,in_nonce,in_ciphertext,in_ad,expected_plaintext',
    [
        (
            unhexlify('f5a2b27c74355872eb3ef6c5feafaa740e6ae990d9d48c3bd9bb8235e589f010'),
            unhexlify('58d2240f580a31c1d24948e9'),
            unhexlify('15e051a5e4a5f5da6cea92e2ebee5bac'),
            '',
            '',
        ),
        (
            unhexlify('6dfdafd6703c285c01f14fd10a6012862b2af950d4733abb403b2e745b26945d'),
            unhexlify('3749d0b3d5bacb71be06ade6'),
            unhexlify('4aa4cc69f84ee6ac16d9bfb4e05de500'),
            unhexlify('c0d249871992e70302ae008193d1e89f'),
            '',
        ),
        (
            unhexlify('aeb3830cb9ce31cae7b1d47511bb2d3dcc2131714ace202b21b98820e7079792'),
            unhexlify('e7e87c45ec0a94c8e92353f1'),
            unhexlify('b20542b61b8fa6f847198334cb82fdbcb2311be855a6b2b3662bdb06ff0796238bea092a8ea21b585d38ace950378f41224269') + unhexlify('3bdd1d0cc2bbcefffe0ed2121aecbd00'),  # noqa
            unhexlify('07d9bb1fa3aea7ceeefbedae87dcd713'),
            unhexlify('b4d0ecc410c430b61c11a1a42802858a0e9ee12f9a912f2f6b0570c99177f6de4bd79830cf9efb30759055e1f70d21e3f74957')  # noqa
        ),
    ]
)
def test_AESGCM_decrypt_KAT(in_key, in_nonce, in_ciphertext, in_ad, expected_plaintext):
    assert AESGCM(in_key).decrypt(in_nonce, in_ad, in_ciphertext) == expected_plaintext

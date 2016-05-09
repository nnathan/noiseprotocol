#!/usr/bin/env python

from binascii import unhexlify

import pytest

from noiseprotocol.crypto.aead import AESGCM, ChaChaPoly


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


def test_ChaChaPoly_name():
    assert ChaChaPoly('\x00'*32).name == 'ChaChaPoly'


@pytest.mark.parametrize('invalid_length', range(32) + [33])
def test_ChaChaPoly_invalid_key_length(invalid_length):
    with pytest.raises(ValueError):
        ChaChaPoly('\x00' * invalid_length)


def test_ChaChaPoly_valid_key_length():
    ChaChaPoly('\x00'*32)


@pytest.mark.parametrize('invalid_length', range(16))
def test_ChaChaPoly_decrypt_invalid_ciphertext_length(invalid_length):
    with pytest.raises(ValueError):
        ChaChaPoly('\x00' * 32).decrypt('\x00'*12, '0', 'x'*invalid_length)


@pytest.mark.parametrize(
    'in_nonce,expected',
    [
        (0, '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'),
        (1, '\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00'),
        (2**32 - 1, '\x00\x00\x00\x00\xff\xff\xff\xff\x00\x00\x00\x00'),
        (2**64 - 1, '\x00\x00\x00\x00\xff\xff\xff\xff\xff\xff\xff\xff'),
    ]
)
def test_ChaChaPoly_nonce(in_nonce, expected):
    assert ChaChaPoly.nonce(in_nonce) == expected


# KATs (or known answer test/test vectors) have been taken from:
# http://fossies.org/linux/libressl/tests/aeadtests.txt (chacha20-poly1305-ietf vectors)
@pytest.mark.parametrize(
    'in_key,in_nonce,in_plaintext,in_ad,expected_ciphertext',
    [
        (
            unhexlify('808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f'),
            unhexlify('070000004041424344454647'),
            unhexlify('4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e'),  # noqa
            unhexlify('50515253c0c1c2c3c4c5c6c7'),
            unhexlify('d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116') + unhexlify('1ae10b594f09e26a7e902ecbd0600691')  # noqa
        ),
        (
            unhexlify('1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0'),
            unhexlify('000000000102030405060708'),
            unhexlify('496e7465726e65742d4472616674732061726520647261667420646f63756d656e74732076616c696420666f722061206d6178696d756d206f6620736978206d6f6e74687320616e64206d617920626520757064617465642c207265706c616365642c206f72206f62736f6c65746564206279206f7468657220646f63756d656e747320617420616e792074696d652e20497420697320696e617070726f70726961746520746f2075736520496e7465726e65742d447261667473206173207265666572656e6365206d6174657269616c206f7220746f2063697465207468656d206f74686572207468616e206173202fe2809c776f726b20696e2070726f67726573732e2fe2809d'),  # noqa
            unhexlify('f33388860000000000004e91'),
            unhexlify('64a0861575861af460f062c79be643bd5e805cfd345cf389f108670ac76c8cb24c6cfc18755d43eea09ee94e382d26b0bdb7b73c321b0100d4f03b7f355894cf332f830e710b97ce98c8a84abd0b948114ad176e008d33bd60f982b1ff37c8559797a06ef4f0ef61c186324e2b3506383606907b6a7c02b0f9f6157b53c867e4b9166c767b804d46a59b5216cde7a4e99040c5a40433225ee282a1b0a06c523eaf4534d7f83fa1155b0047718cbc546a0d072b04b3564eea1b422273f548271a0bb2316053fa76991955ebd63159434ecebb4e466dae5a1073a6727627097a1049e617d91d361094fa68f0ff77987130305beaba2eda04df997b714d6c6f2c29a6ad5cb4022b02709b') + unhexlify('eead9d67890cbb22392336fea1851f38')  # noqa
        ),
        (
            unhexlify('808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f'),
            unhexlify('a0a1a2a31011121314151617'),
            unhexlify('45000054a6f200004001e778c6336405c000020508005b7a3a080000553bec100007362708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363701020204'),  # noqa
            unhexlify('0102030400000005'),
            unhexlify('24039428b97f417e3c13753a4f05087b67c352e6a7fab1b982d466ef407ae5c614ee8099d52844eb61aa95dfab4c02f72aa71e7c4c4f64c9befe2facc638e8f3cbec163fac469b502773f6fb94e664da9165b82829f641e0') + unhexlify('76aaa8266b7fb0f7b11b369907e1ad43')  # noqa
        ),
        (
            unhexlify('808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f'),
            unhexlify('a0a1a2a31011121314151617'),
            unhexlify('0000000c000040010000000a00'),
            unhexlify('c0c1c2c3c4c5c6c7d0d1d2d3d4d5d6d72e202500000000090000004529000029'),
            unhexlify('610394701f8d017f7c12924889') + unhexlify('6b71bfe25236efd7cdc67066906315b2')  # noqa
        ),
    ]
)
def test_ChaChaPoly_encrypt_KAT(in_key, in_nonce, in_plaintext, in_ad, expected_ciphertext):
    assert ChaChaPoly(in_key).encrypt(in_nonce, in_ad, in_plaintext) == expected_ciphertext

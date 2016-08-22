#!/usr/bin/env python

from collections import namedtuple

import enum

# taken from:
# https://github.com/rweather/noise-java/blob/master/NoiseJava/src/com/southernstorm/noise/protocol/Pattern.java  # noqa

class Token(enum.Enum):

    S = 1
    E = 2
    DHEE = 3
    DHES = 4
    DHSE = 5
    DHSS = 6
    SWAP = 7

HandshakePattern = namedtuple('HandshakePattern', ['name', 'initiator_premessages', 'responder_premessages', 'messages'])  # noqa

Noise_N = HandshakePattern(
    "N",
    (),
    (Token.S,),
    (Token.E, Token.DHES),
)

Noise_K = HandshakePattern(
    "K",
    (Token.S,),
    (Token.S,),
    (Token.E, Token.DHES, Token.DHSS),
)

Noise_X = HandshakePattern(
    "X",
    (),
    (Token.S,),
    (Token.E, Token.DHES, Token.S, Token.DHSS),
)

Noise_NN = HandshakePattern(
    "NN",
    (),
    (),
    (
        Token.E, Token.SWAP,
        Token.E, Token.DHEE,
    )
)

Noise_NK = HandshakePattern(
    "NK",
    (),
    (Token.S,),
    (
        Token.E, Token.DHES, Token.SWAP,
        Token.E, Token.DHEE,
    ),
)

Noise_NX = HandshakePattern(
    "NX",
    (),
    (),
    (
        Token.E, Token.SWAP,
        Token.E, Token.DHEE, Token.S, Token.DHSE,
    ),
)

Noise_XN = HandshakePattern(
    "XN",
    (),
    (),
    (
        Token.E, Token.SWAP,
        Token.E, Token.DHEE, Token.SWAP,
        Token.S, Token.DHSE,
    ),
)

Noise_XK = HandshakePattern(
    "XK",
    (),
    (Token.S,),
    (
        Token.E, Token.DHES, Token.SWAP,
        Token.E, Token.DHEE, Token.SWAP,
        Token.S, Token.DHSE,
    ),
)

Noise_XX = HandshakePattern(
    "XX",
    (),
    (),
    (
        Token.E, Token.SWAP,
        Token.E, Token.DHEE, Token.S, Token.DHSE, Token.SWAP,
        Token.S, Token.DHSE,
    ),
)

Noise_XR = HandshakePattern(
    "XR",
    (),
    (),
    (
        Token.E, Token.SWAP,
        Token.E, Token.DHEE, Token.SWAP,
        Token.S, Token.DHSE, Token.SWAP,
        Token.S, Token.DHSE,
    ),
)

Noise_KN = HandshakePattern(
    "KN",
    (Token.S,),
    (),
    (
        Token.E, Token.SWAP,
        Token.E, Token.DHEE, Token.DHES,
    ),
)

Noise_KK = HandshakePattern(
    "KK",
    (Token.S,),
    (Token.S,),
    (
        Token.E, Token.DHES, Token.DHSS, Token.SWAP,
        Token.E, Token.DHEE, Token.DHES,
    ),
)

Noise_KX = HandshakePattern(
    "KX",
    (Token.S,),
    (),
    (
        Token.E, Token.SWAP,
        Token.E, Token.DHEE, Token.DHES, Token.S, Token.DHSE,
    ),
)

Noise_IN = HandshakePattern(
    "IN",
    (),
    (),
    (
        Token.E, Token.S, Token.SWAP,
        Token.E, Token.DHEE, Token.DHES,
    ),
)

Noise_IK = HandshakePattern(
    "IK",
    (),
    (Token.S,),
    (
        Token.E, Token.DHES, Token.S, Token.DHSS, Token.SWAP,
        Token.E, Token.DHEE, Token.DHES,
    )
)

Noise_IX = HandshakePattern(
    "IX",
    (),
    (),
    (
        Token.E, Token.S, Token.SWAP,
        Token.E, Token.DHEE, Token.DHES, Token.S, Token.DHSE,
    )
)

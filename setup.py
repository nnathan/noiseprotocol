#!/usr/bin/env python

from distutils.core import setup

packages= [
    'noiseprotocol',
    'noiseprotocol.crypto',
]

classifiers = [
    'Development Status :: 3 - Alpha',
    'Environment :: Console',
    'Intended Audience :: Developers',
    'License :: Public Domain',
    'Operating System :: MacOS :: MacOS X',
    'Operating System :: POSIX',
    'Programming Language :: Python :: 2.7',
    'Topic :: Internet',
    'Topic :: Security :: Cryptography',
    'Topic :: Software Development :: Libraries :: Python Modules',
    'Topic :: System :: Networking'
]

setup(
    name='noiseprotocol',
    description='Python implementation of Noise Protocol Specification',
    author='Naveen Nathan',
    author_email='noise@t.lastninja.net',
    license='BSD',
    url='http://github.com/nnathan/noiseprotocol',
    classifiers=classifiers,
    packages=packages,
)

#!/usr/bin/env python3

from distutils.core import setup

setup(
    name            = 'ardukey-auth',
    version         = '1.0',
    description     = 'ArduKey authentication server for 2FA written in Python 3.',
    author          = 'Bastian Raschke',
    author_email    = 'bastian.raschke@posteo.de',
    url             = 'https://sicherheitskritisch.de',
    license         = 'Simplified BSD License',
    package_dir     = {'': 'files'},
    packages        = ['ardukeyauth'],
)

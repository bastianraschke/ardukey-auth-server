#!/usr/bin/env python

from distutils.core import setup

setup(
    name            = 'ardukeyauth',
    version         = '1.0',
    description     = 'ArduKey authentication server for 2FA.',
    author          = 'Bastian Raschke',
    author_email    = 'bastian.raschke@posteo.de',
    url             = 'https://sicherheitskritisch.de',
    license         = 'Simplified BSD License',
    package_dir     = {'': 'files'},
    packages        = ['ardukeyauth'],
)

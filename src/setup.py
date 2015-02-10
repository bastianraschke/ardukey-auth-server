#!/usr/bin/env python
# -*- coding: utf-8 -*-

from distutils.core import setup

setup(
    name            = 'ArduKey authserver',
    version         = '1.1',
    description     = 'ArduKey authentication server written in Python 3.',
    author          = 'Bastian Raschke',
    author_email    = 'bastian.raschke@posteo.de',
    url             = 'https://sicherheitskritisch.de',
    license         = 'Simplified BSD License',
    package_dir     = {'': 'files'},
    packages        = ['ardukeyauth'],
)

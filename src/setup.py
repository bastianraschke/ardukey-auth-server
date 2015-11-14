#!/usr/bin/env python
# -*- coding: utf-8 -*-

from setuptools import setup

setup(
    name            = 'ardukey-auth-server',
    version         = '1.0.2', ## Never forget to change module version as well!
    description     = 'ArduKey authentication server written in Python 3.',
    author          = 'Bastian Raschke',
    author_email    = 'bastian.raschke@posteo.de',
    url             = 'https://sicherheitskritisch.de',
    license         = 'D-FSL',
    packages        = ['ardukeyauth'],
    package_dir     = {'': 'files'},
)

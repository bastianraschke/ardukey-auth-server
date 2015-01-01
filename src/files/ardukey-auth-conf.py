#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
ArduKey authserver configuration tool
@author Bastian Raschke <bastian.raschke@posteo.de>

Copyright 2015 Bastian Raschke
All rights reserved.
"""

import argparse

from ardukeyauth.Configuration import Configuration
from ardukeyauth import __version__ as VERSION

## Path to configuration file
configurationFilePath = '/etc/ardukey-auth.conf'





def addArduKey(publicId, secretId, aesKey):
        """
        Adds a ArduKey.

        @param string publicId
        The public id of ArduKey.

        @param string secretId
        The secret id of ArduKey.

        @param string aesKey
        The AES key as hexadecimal string.

        @return boolean
        """

        return True




"""
## Try to read parameters from configuration file
try:
    configuration = Configuration(configurationFilePath, readOnly=True)

    ## The address the server is running on
    serverAddress = configuration.readString('Default', 'server_address')

    ## The port the server is listening
    serverPort = configuration.readInteger('Default', 'server_port')

except:
    ## Without configuration the system is not able to work
    sys.stderr.write('Fatal error: The configuration file "' + configurationFilePath + '" could not be read correctly!\n')
    exit(1)
"""

if ( __name__ == '__main__' ):

    parser = argparse.ArgumentParser(description='ArduKey authserver configuration tool ' + VERSION)

    parser.add_argument('--add-ardukey', metavar='NAME', help='Adds a new ArduKey.')
    parser.add_argument('--revoke-ardukey', metavar='NAME', help='Revokes a ArduKey.')

    parser.add_argument('--version', '-v', action='version', version='ArduKey authserver configuration tool ' + VERSION, help='Prints version and exits.')

    ## TODO:
    ## list ArduKeys
    ## generate API key
    ## revoke API key
    ## list API keys

    args = vars(parser.parse_args())

    if ( args['add_ardukey'] ):
        addArduKey(args['add_ardukey'])
    elif ( args['revoke_ardukey'] ):
        print('jo')
    else:
        parser.print_help()

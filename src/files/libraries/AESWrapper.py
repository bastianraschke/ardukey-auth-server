#!/usr/bin/env python3

"""
ArduKey authserver
@author Bastian Raschke

Copyright 2014 Bastian Raschke
All rights reserved.
"""

import Crypto.Cipher.AES as AES
import binascii


class AESWrapper(object):
    """
    AES decryption wrapper class.

    @attribute string __aes
    The AES object.
    """

    __aes = None

    def __init__(self, aesKey):
        """
        Constructor

        @param string aesKey The used AES key as hexadecimal string.
        """

        if ( len(aesKey) != 16 ):
            raise ValueError('The length of the AES key must be 16!')

        aesKeyBytes = binascii.unhexlify(aeskey.encode('utf-8'))
        self.__aes = AES.new(aesKeyBytes, AES.MODE_ECB)

    def decrypt(self, cipher):
        """
        Decrypts given cipher text and returns plain text as hexadecimal string.

        @param string cipher The cipher text for decryption as hexadecimal string.
        @return string
        """

        if ( len(cipher) != 16 ):
            raise ValueError('The length of the cipher text must be 16!')

        cipherBytes = binascii.unhexlify(cipher.encode('utf-8'))
        plainBytes = self.__aes.decrypt(cipher)

        return binascii.hexlify(plainBytes)

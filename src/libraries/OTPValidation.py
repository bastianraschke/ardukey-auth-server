#!/usr/bin/env python3

"""
ArduKey authserver
@author Bastian Raschke

Copyright 2014 Bastian Raschke.
All rights reserved.
"""


class OTPValidation(object):
    """
    ArduKey OTP validation.

    @attribute string __otp
    The OTP to validate.
    """

    __otp = ''

    def __init__(self, otp):
        """
        Constructor

        @param string otp The OTP to validate.
        """

        if ( len(otp) != 44 ):
            raise ValueError('The length of the OTP must be 44!')

        self.__otp = otp






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

#!/usr/bin/env python3

import Crypto.Cipher.AES as AES
import binascii

def aes128ecb_decrypt(aeskey, aesdata):

    key = binascii.unhexlify(aeskey.encode('utf-8'))
    cipher = binascii.unhexlify(aesdata.encode('utf-8'))

    aes = AES.new(key, AES.MODE_ECB)
    plain = aes.decrypt(cipher)

    return binascii.hexlify(plain)


key = '7A1858592FCB76BD5EB2685421AED45E'
cipher = '515608E88EA7D90F3D32946784BE54FB'

print(aes128ecb_decrypt(key, cipher))

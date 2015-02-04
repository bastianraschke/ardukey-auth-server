def __calculateCRC16(hexString):
    """
    Calculate the CRC16 (ISO13239) checksum of given hexadecimal data.

    @param string hexString
    The hexadecimal data used by calculation.

    @return integer
    """

    hexStringLength = len(hexString)

    if ( hexStringLength % 2 != 0 ):
        raise ValueError('The given hexadecimal string is not valid!')

    ## The count of bytes in hexadecimal string
    byteCount = int(hexStringLength / 2)

    crc = 0xFFFF

    for i in range(0, byteCount):

        index = i*2
        currentByte = int(hexString[index:index+2], 16)

        crc ^= currentByte & 0xFF

        for j in range(0, 8):
            x = crc & 1
            crc >>= 1

            if (x):
                crc ^= 0x8408

    return crc

print(hex(__calculateCRC16('55aa00ff4a34'))) # 0xf0b8 = OK

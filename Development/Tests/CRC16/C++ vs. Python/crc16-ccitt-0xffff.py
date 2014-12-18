def __calculateCRC16(self, hexString):
    """
    Calculates the CRC16-CCITT (0xFFFF) checksum of given a hexadecimal string.

    @param string hexString
    The hexadecimal string used by calculation.

    @return integer
    """

    hexStringLength = len(hexString)

    if ( hexStringLength % 2 != 0 ):
        raise ValueError('The given hexadecimal string is not valid!')

    ## The count of bytes in hexadecimal string
    byteCount = hexStringLength / 2

    crc = 0xFFFF

    for i in range(0, byteCount):

        index = i*2
        currentByte = int(hexString[index:index+2], 16)

        x = (crc >> 8) ^ currentByte
        x = x ^ (x >> 4)

        crc = (crc << 8) ^ (x << 12) ^ (x << 5) ^ x;
        crc = crc & 0xFFFF

    return crc

print(__calculateCRC16(None, 'b0d4a2d69bc427000000002ba1c3'))

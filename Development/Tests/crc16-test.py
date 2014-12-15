"""
uint16_t ArduKeyUtilities::CRC16(const uint8_t values[], size_t length)
{
    uint16_t crc = 0xFFFF;

    // Sanity check
    if ( !values || length == 0 )
    {
        return crc;
    }

    uint8_t x;

    for (int i = 0; i < length; i++)
    {
        x = (crc >> 8) ^ values[i];
        x = x ^ (x >> 4);

        crc = (crc << 8) ^ ((uint16_t) (x << 12)) ^ ((uint16_t) (x << 5)) ^ ((uint16_t) x);
    }

    return crc;
}
"""


def crc16(data, length):

    crc = 0xFFFF
    x = 0

    for i in range(0, length):

        b = data[i:i+2]

        print(b)

        x = (crc >> 8) ^ int(b, 16)
        x = x ^ (x >> 4)

        crc = (crc << 8) ^ (x << 12) ^ (x << 5) ^ x;

    return crc

test = b'ff'

def GenCCITT_CRC16(Buffer):

   #~~ Generierung der CCITT-CRC16 Checksumme
   bitrange = xrange(8) # 8 Bits
   crcsum   = 0
   polynom  = 0x1021 #CCITT Polynom

   for byte in Buffer:
      crcsum ^= ord(byte) << 8
      for bit in bitrange: # Schleife fuer 8 Bits
         crcsum <<= 1
         if crcsum & 0x7FFF0000:
            #~~ Es gab einen Uebertrag ins Bit-16
            crcsum = (crcsum & 0x0000FFFF) ^ polynom
   return crcsum

#print(crc16(test, 1))
print(hex(GenCCITT_CRC16(test)))

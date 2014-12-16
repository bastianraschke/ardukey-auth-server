def crc16(data):

    stringLength = len(data)

    if ( stringLength % 2 != 0 ):
        raise ValueError('The given data is not valid!')

    dataLength = stringLength / 2

    crc = 0xFFFF

    for i in range(0, dataLength):

        #index = i*2
        #b = data[index:index+2]

        #print(index)
        #print(index+2)
        #print(b)

        b = data[i*2:i*2+2]
        print("-"+b+"-")


        """
        currentByte = int(b, 16)



        x = (crc >> 8) ^ currentByte
        x = x ^ (x >> 4)

        crc = (crc << 8) ^ (x << 12) ^ (x << 5) ^ x;
        crc = crc & 0xFFFF
        """

    return crc

crc16('ffaabb')



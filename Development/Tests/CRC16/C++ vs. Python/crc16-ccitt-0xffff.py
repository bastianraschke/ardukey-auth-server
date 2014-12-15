"""
function crc16($data)
 {
   $crc = 0xFFFF;
   for ($i = 0; $i < strlen($data); $i++)
   {
     $x = (($crc >> 8) ^ ord($data[$i])) & 0xFF;
     $x ^= $x >> 4;
     $crc = (($crc << 8) ^ ($x << 12) ^ ($x << 5) ^ $x) & 0xFFFF;
   }
   return $crc;
 }
 """

def crc16(data, length):

    crc = 0xFFFF

    for i in range(0, length):

        #index = i*2
        #currentByte = int(data[index:index+2], 16)
        currentByte = ord(data[i])

        x = (crc >> 8) ^ currentByte
        x = x ^ (x >> 4)

        crc = (crc << 8) ^ (x << 12) ^ (x << 5) ^ x;
        crc = crc & 0xFFFF

    return crc

#test = b'ff'
#print(crc16(test, len(test) / 2))

test = "Hallo\0"
print(crc16(test, len(test)))

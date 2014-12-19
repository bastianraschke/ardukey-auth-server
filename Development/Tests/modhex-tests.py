
def decodeArduHex(arduhexData):

    ## Hexadecimal table
    hexTable = '0123456789abcdef'

    ## ArduKey transformation table
    arduhexMappingTable = 'cbdefghijklnrtuv'

    result = ''

    for i in range(0, len(arduhexData)):

        position = arduhexMappingTable.find(arduhexData[i])

        ## Checks if character was found
        if ( position == -1 ):
            raise ValueError('The given input contains a non-valid character!')
        else:
            result += hexTable[position]

    return result

print(decodeArduHex("cccccccccccb"))

def __decodeArduHex(self, arduhexString):
    """
    Converts a given arduhex string to hexadecimal string.

    @param string arduhexString
    The arduhex string to convert.

    @return string
    """

    ## Mapping (arduhex -> hexadecimal) table
    table = {
        'c' : '0',
        'b' : '1',
        'd' : '2',
        'e' : '3',
        'f' : '4',
        'g' : '5',
        'h' : '6',
        'i' : '7',
        'j' : '8',
        'k' : '9',
        'l' : 'a',
        'n' : 'b',
        'r' : 'c',
        't' : 'd',
        'u' : 'e',
        'v' : 'f',
    }

    hexString = ''

    try:
        ## Try to replace each character of arduhex string
        for i in range(0, len(arduhexString)):
            currentArduhexChar = arduhexString[i]
            hexString += table[currentArduhexChar]

    except KeyError:
        raise ValueError('The given input contains non-valid character(s)!')

    return hexString


print(__decodeArduHex(None, 'cccccccccccb'))

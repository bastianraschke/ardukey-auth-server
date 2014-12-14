






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

"""
retVal = ''
for i in range (0, len(string)):
    pos = modhex.find(string[i])
    if pos > -1:
        retVal += hex[pos]
    else:
        raise Exception, '"' + string[i] + '": Character is not a valid hex string'
return retVal
"""


print(decodeArduHex("cccccccccccb"))

#include <iostream>

// Include integer type aliases
#include <inttypes.h>

using namespace std;


uint16_t crc16(const uint8_t values[], size_t length)
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

        crc = (crc << 8) ^ (x << 12) ^ (x << 5) ^ x;
        //crc = crc & 0xFFFF;
    }

    return crc;
}

/*
 * Some test cases.
 *
 */
int main(int argc, char** argv)
{
    //uint8_t test = 0xFF;
    //uint8_t* values = &test;
    //cout << crc16(values, 1) << endl;

    uint8_t values[6] = "Hallo";
    cout << crc16(values, sizeof(values)) << endl;
}

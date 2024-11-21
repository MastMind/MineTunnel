#include <stdint.h>

#include "crc.h"




static uint32_t general_crc32(unsigned char *buf, uint32_t len, uint32_t poly) {
    uint32_t crc_table[256];
    uint32_t crc; 
    int i, j;

    for (i = 0; i < 256; i++)
    {
        crc = i;
        for (j = 0; j < 8; j++)
            crc = crc & 1 ? (crc >> 1) ^ poly : crc >> 1;

        crc_table[i] = crc;
    };

    crc = 0xFFFFFFFF;

    while (len--)
        crc = crc_table[(crc ^ *buf++) & 0xFF] ^ (crc >> 8);

    return crc ^ 0xFFFFFFFF;
}

uint32_t crc32_calc(unsigned char *buf, uint32_t len) {
    return general_crc32(buf, len, POLYNOME_1);
}

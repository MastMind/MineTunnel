#ifndef __CRC_H__
#define __CRC_H__




#include <stdint.h>


#define POLYNOME_1 0x82F63B78


/**
 * Calculate CRC32 checksum
 * @param buf Buffer to calculate checksum for
 * @param len Buffer length
 * @return CRC32 checksum value
 */
uint32_t crc32_calc(unsigned char *buf, uint32_t len);


#endif

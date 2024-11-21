#ifndef __CRC_H__
#define __CRC_H__




#include <stdint.h>


#define POLYNOME_1 0x82F63B78


uint32_t crc32_calc(unsigned char *buf, uint32_t len);


#endif

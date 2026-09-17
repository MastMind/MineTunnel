#ifndef HT_HASH_H
#define HT_HASH_H

#include <stddef.h>
#include <stdint.h>

/* Time O(len): FNV-1a 32-bit over every byte. */
uint32_t ht_fnv1a32(const void *data, size_t len);

/* Time O(len): reference XXH32 (16-byte stripes + tail + avalanche). */
uint32_t ht_xxh32(const void *data, size_t len, uint32_t seed);

/* Time O(len): len <= 16 -> FNV-1a + fmix32, len > 16 -> XXH32,
 * result truncated to 16 bits. */
uint16_t ht_hash16(const void *data, size_t len);

#endif

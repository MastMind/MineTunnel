#include "hash.h"

#define XXH_PRIME1 2654435761u
#define XXH_PRIME2 2246822519u
#define XXH_PRIME3 3266489917u
#define XXH_PRIME4 668265263u
#define XXH_PRIME5 374761393u

#define HT_SHORT_LEN 16

static uint32_t rotl32(uint32_t x, int r)
{
    return (x << r) | (x >> (32 - r));
}

static uint32_t rd32le(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

uint32_t ht_fnv1a32(const void *data, size_t len)
{
    const uint8_t *p = (const uint8_t *)data;
    uint32_t h = 2166136261u;
    size_t i;

    for (i = 0; i < len; i++) {
        h ^= p[i];
        h *= 16777619u;
    }
    return h;
}

static uint32_t xxh32_round(uint32_t acc, uint32_t input)
{
    acc += input * XXH_PRIME2;
    acc = rotl32(acc, 13);
    return acc * XXH_PRIME1;
}

uint32_t ht_xxh32(const void *data, size_t len, uint32_t seed)
{
    const uint8_t *p = (const uint8_t *)data;
    const uint8_t *b = p + len;
    uint32_t h32;

    if (len >= 16) {
        const uint8_t *limit = b - 16;
        uint32_t v1 = seed + XXH_PRIME1 + XXH_PRIME2;
        uint32_t v2 = seed + XXH_PRIME2;
        uint32_t v3 = seed;
        uint32_t v4 = seed - XXH_PRIME1;

        do {
            v1 = xxh32_round(v1, rd32le(p));
            v2 = xxh32_round(v2, rd32le(p + 4));
            v3 = xxh32_round(v3, rd32le(p + 8));
            v4 = xxh32_round(v4, rd32le(p + 12));
            p += 16;
        } while (p <= limit);

        h32 = rotl32(v1, 1) + rotl32(v2, 7) + rotl32(v3, 12) + rotl32(v4, 18);
    } else {
        h32 = seed + XXH_PRIME5;
    }

    h32 += (uint32_t)len;

    while (p + 4 <= b) {
        h32 += rd32le(p) * XXH_PRIME3;
        h32 = rotl32(h32, 17) * XXH_PRIME4;
        p += 4;
    }
    while (p < b) {
        h32 += (uint32_t)*p * XXH_PRIME5;
        h32 = rotl32(h32, 11) * XXH_PRIME1;
        p++;
    }

    h32 ^= h32 >> 15;
    h32 *= XXH_PRIME2;
    h32 ^= h32 >> 13;
    h32 *= XXH_PRIME3;
    h32 ^= h32 >> 16;
    return h32;
}

static uint32_t fmix32(uint32_t h)
{
    h ^= h >> 16;
    h *= 2246822507u;
    h ^= h >> 13;
    h *= 3266489909u;
    h ^= h >> 16;
    return h;
}

uint16_t ht_hash16(const void *data, size_t len)
{
    if (len <= HT_SHORT_LEN)
        return (uint16_t)(fmix32(ht_fnv1a32(data, len)) & 0xFFFFu);
    return (uint16_t)(ht_xxh32(data, len, 0) & 0xFFFFu);
}

#ifndef HT_H
#define HT_H

#include <stddef.h>

#define HT_OK     0
#define HT_ENOMEM (-1)
#define HT_EEXIST (-2)
#define HT_ENOENT (-3)

/*
 * Complexity notation:
 *   B - number of buckets (fixed, 2^16 = 65536)
 *   N - number of elements stored in the table
 *   K - key length (key_len)
 *   C - chain length of the target bucket:
 *       average N/B with uniform hash, worst case N
 *
 * Memory: table is O(B); every element costs one heap allocation
 * of O(K) bytes (node header + key copy). No other allocations.
 */

typedef struct ht ht_t;

typedef int ht_foreach_cb(const void *key, size_t key_len, void *value,
                          void *user);
typedef void ht_free_cb(void *value);

/* Time O(B): zeroes the bucket array. Memory O(B). */
ht_t   *ht_create(void);

/* Time O(B + N): walks every bucket, frees N nodes, calls free_cb
 * N times (never if free_cb is NULL). NULL table is a no-op. */
void    ht_free(ht_t *ht, ht_free_cb *free_cb);

/* Time O(K + C): hash O(K), duplicate scan along the chain O(C).
 * Returns HT_EEXIST without modifying the table on a duplicate key.
 * Amortized O(K + N/B) with uniform hash. */
int     ht_add(ht_t *ht, const void *key, size_t key_len, void *value);

/* Time O(K + C): hash O(K), linear chain scan O(C).
 * Returns the value, or NULL if absent. Amortized O(K + N/B). */
void   *ht_get(ht_t *ht, const void *key, size_t key_len);

/* Time O(K + C): hash O(K), chain scan O(C), unlink and node
 * free are O(1). Amortized O(K + N/B).
 * free_cb is called on the removed value (never if it is NULL or the
 * element is not found). */
int     ht_remove(ht_t *ht, const void *key, size_t key_len,
                  ht_free_cb *free_cb);

/* Time O(B + N): walks every bucket and every node, cb called up to
 * N times; a non-zero cb return stops the walk early. */
void    ht_foreach(ht_t *ht, ht_foreach_cb *cb, void *user);

/* Time O(1): the element count is maintained incrementally. */
size_t  ht_count(const ht_t *ht);

#endif

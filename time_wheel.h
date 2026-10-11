#ifndef CACHE_WHEEL_H
#define CACHE_WHEEL_H

#include <stddef.h>
#include <time.h>

#include "ht.h"


#define CACHE_WHEEL_SLOTS 1024




typedef struct time_wheel_node time_wheel_node_t;

typedef struct time_wheel {
    time_wheel_node_t *heads[CACHE_WHEEL_SLOTS];
    size_t total;
    unsigned short key_len;
} time_wheel_t;

/* Invoked for each expired record right before its removal from the
 * hash table (for logging); may be NULL. */
typedef void time_wheel_expire_cb(const void *key, size_t key_len, void *user);

/*
 * Initialize an empty wheel.
 * @param key_len Length of the keys that will be scheduled
 */
void time_wheel_init(time_wheel_t *w, unsigned short key_len);

/*
 * Free every node of the wheel. Records are NOT freed (they belong to
 * the hash table); safe to call at any time, including after the table
 * has been freed.
 */
void time_wheel_reset(time_wheel_t *w);

/*
 * Schedule a record for expiry at now + ttl.
 * @return the node to associate with the record, or NULL on OOM
 */
time_wheel_node_t *time_wheel_insert(time_wheel_t *w, const void *key,
                                       size_t key_len, time_t now, time_t ttl);

/*
 * Extend a record's expiry to now + ttl (sliding TTL refresh).
 * The node's stored key is kept unchanged.
 */
void time_wheel_refresh(time_wheel_t *w, time_wheel_node_t *n,
                         time_t now, time_t ttl);

/*
 * Drain the slot of second `now`: every expired node removes its record
 * from the hash table (ht_remove with free) and is freed; not-yet-expired
 * nodes are re-queued.
 * @return number of records removed
 */
size_t time_wheel_tick(time_wheel_t *w, ht_t *ht, time_t now,
                        time_wheel_expire_cb *on_expire, void *user);

/*
 * Number of scheduled records.
 */
size_t time_wheel_count(const time_wheel_t *w);

#endif

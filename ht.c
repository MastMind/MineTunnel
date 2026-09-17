#include <stdlib.h>
#include <string.h>

#include "hash.h"
#include "ht.h"

#define HT_BUCKETS 65536u

typedef struct ht_node
{
    size_t key_len;
    struct ht_node *next;
    void *value;
} ht_node_t;

typedef struct ht_bucket
{
    ht_node_t *head;
} ht_bucket_t;

struct ht
{
    ht_bucket_t buckets[HT_BUCKETS];
    size_t total;
};

static uint8_t *node_key(const ht_node_t *n)
{
    return (uint8_t *)(n + 1);
}

static int key_eq(const ht_node_t *n, const void *key, size_t key_len)
{
    if (n->key_len != key_len)
        return 0;
    if (key_len == 0)
        return 1;
    return memcmp(node_key(n), key, key_len) == 0;
}

ht_t *ht_create(void)
{
    return calloc(1, sizeof (ht_t));
}

void ht_free(ht_t *ht, ht_free_cb *free_cb)
{
    unsigned b;

    if (!ht)
        return;
    for (b = 0; b < HT_BUCKETS; b++) {
        ht_node_t *n = ht->buckets[b].head;
        while (n) {
            ht_node_t *next = n->next;
            if (free_cb)
                free_cb(n->value);
            free(n);
            n = next;
        }
    }
    free(ht);
}

int ht_add(ht_t *ht, const void *key, size_t key_len, void *value)
{
    ht_bucket_t *bucket;
    ht_node_t *n;

    if (!ht)
        return HT_ENOMEM;
    if (key_len && !key)
        return HT_ENOMEM;

    bucket = &ht->buckets[ht_hash16(key, key_len)];
    for (n = bucket->head; n; n = n->next)
        if (key_eq(n, key, key_len))
            return HT_EEXIST;

    n = malloc(sizeof (ht_node_t) + key_len);
    if (!n)
        return HT_ENOMEM;
    n->key_len = key_len;
    n->value = value;
    if (key_len)
        memcpy(node_key(n), key, key_len);
    n->next = bucket->head;
    bucket->head = n;
    ht->total++;
    return HT_OK;
}

void *ht_get(ht_t *ht, const void *key, size_t key_len)
{
    const ht_node_t *n;

    if (!ht)
        return NULL;
    if (key_len && !key)
        return NULL;
    for (n = ht->buckets[ht_hash16(key, key_len)].head; n; n = n->next)
        if (key_eq(n, key, key_len))
            return n->value;
    return NULL;
}

int ht_remove(ht_t *ht, const void *key, size_t key_len, ht_free_cb *free_cb)
{
    ht_bucket_t *bucket;
    ht_node_t **link;
    ht_node_t *n;

    if (!ht)
        return HT_ENOENT;
    if (key_len && !key)
        return HT_ENOENT;

    bucket = &ht->buckets[ht_hash16(key, key_len)];
    for (link = &bucket->head; (n = *link) != NULL; link = &n->next) {
        if (key_eq(n, key, key_len)) {
            *link = n->next;
            if (free_cb)
                free_cb(n->value);
            free(n);
            ht->total--;
            return HT_OK;
        }
    }
    return HT_ENOENT;
}

void ht_foreach(ht_t *ht, ht_foreach_cb *cb, void *user)
{
    unsigned b;

    if (!ht || !cb)
        return;
    for (b = 0; b < HT_BUCKETS; b++) {
        const ht_node_t *n;
        for (n = ht->buckets[b].head; n; n = n->next) {
            if (cb(node_key(n), n->key_len, n->value, user))
                return;
        }
    }
}

size_t ht_count(const ht_t *ht)
{
    return ht ? ht->total : 0u;
}

#include <stdlib.h>
#include <string.h>

#include "time_wheel.h"

struct time_wheel_node {
    struct time_wheel_node *prev;
    struct time_wheel_node *next;
    time_t expiry;
    unsigned char key[];
};

static unsigned wheel_slot(time_t t) {
    return (unsigned)(t % (time_t)CACHE_WHEEL_SLOTS);
}

static void wheel_link(time_wheel_t *w, time_wheel_node_t *n) {
    unsigned s = wheel_slot(n->expiry);

    n->next = w->heads[s];
    n->prev = NULL;

    if (n->next) {
        n->next->prev = n;
    }

    w->heads[s] = n;
}

static void wheel_unlink(time_wheel_t *w, time_wheel_node_t *n) {
    unsigned s = wheel_slot(n->expiry);

    if (n->prev) {
        n->prev->next = n->next;
    } else {
        w->heads[s] = n->next;
    }

    if (n->next) {
        n->next->prev = n->prev;
    }

    n->prev = NULL;
    n->next = NULL;
}

void time_wheel_init(time_wheel_t *w, unsigned short key_len) {
    if (!w) {
        return;
    }

    memset(w, 0, sizeof(*w));
    w->key_len = key_len;
}

void time_wheel_reset(time_wheel_t *w) {
    unsigned s;

    if (!w) {
        return;
    }

    for (s = 0; s < CACHE_WHEEL_SLOTS; s++) {
        time_wheel_node_t *n = w->heads[s];

        while (n) {
            time_wheel_node_t *next = n->next;
            free(n);
            n = next;
        }

        w->heads[s] = NULL;
    }

    w->total = 0;
}

time_wheel_node_t *time_wheel_insert(time_wheel_t *w, const void *key,
                                       size_t key_len, time_t now, time_t ttl) {
    time_wheel_node_t *n;

    if (!w) {
        return NULL;
    }

    n = (time_wheel_node_t*)malloc(sizeof(*n) + key_len);
    if (!n) {
        return NULL;
    }

    n->expiry = now + ttl;
    if (key_len) {
        memcpy(n->key, key, key_len);
    }

    w->total++;
    wheel_link(w, n);
    return n;
}

void time_wheel_refresh(time_wheel_t *w, time_wheel_node_t *n,
                         time_t now, time_t ttl) {
    if (!w || !n) {
        return;
    }

    wheel_unlink(w, n);
    n->expiry = now + ttl;
    wheel_link(w, n);
}

size_t time_wheel_tick(time_wheel_t *w, ht_t *ht, time_t now,
                        time_wheel_expire_cb *on_expire, void *user) {
    time_wheel_node_t *list;
    time_wheel_node_t *n;
    size_t removed = 0;
    unsigned s;

    if (!w) {
        return 0;
    }

    s = wheel_slot(now);
    list = w->heads[s];
    w->heads[s] = NULL;

    for (n = list; n; ) {
        time_wheel_node_t *next = n->next;
        if (n->expiry <= now) {
            if (on_expire) {
                on_expire(n->key, (size_t)w->key_len, user);
            }

            ht_remove(ht, n->key, (size_t)w->key_len, free);
            free(n);
            w->total--;
            removed++;
        } else {
            wheel_link(w, n);
        }

        n = next;
    }

    return removed;
}

size_t time_wheel_count(const time_wheel_t *w) {
    return w ? w->total : 0u;
}

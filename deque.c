#include <stdlib.h>

#include "deque.h"




void bhdeque_push_front(bh_deque_t** deque, void* element) {
    bh_deque_t* new_l = (bh_deque_t*)malloc(sizeof(bh_deque_t));

    if (!new_l) {
        return;
    }

    new_l->next = *deque;
    new_l->prev = NULL;
    new_l->data = element;

    if (*deque) {
        (*deque)->prev = new_l;
    }

    *deque = new_l;
}

void bhdeque_erase(bh_deque_t** deque, void (*erase_func)(void*)) {
    if (!deque || !(*deque)) {
        return;
    }

    if ((*deque)->next) {
        ((*deque)->next)->prev = (*deque)->prev;
    }

    if ((*deque)->prev) {
        ((*deque)->prev)->next = (*deque)->next;
    }

    if (erase_func && (*deque)->data) {
        erase_func((*deque)->data);
    }

    bh_deque_t* next = (*deque)->next;
    bh_deque_t* prev = (*deque)->prev;
    free(*deque);

    if (next) {
        *deque = next;
    } else {
        *deque = prev;
    }
}

void bhdeque_clear(bh_deque_t* deque, void (*erase_func)(void*)) {
    bh_deque_t* d = deque;
    while (d) {
        bh_deque_t* n = d->next;
        if (erase_func && d->data) {
            erase_func(d->data);
        }

        free(d);

        d = n;
    }
}

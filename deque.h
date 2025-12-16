#ifndef __BH_DEQUEUE_H__
#define __BH_DEQUEUE_H__




struct bh_deque;

typedef struct bh_deque  bh_deque_t;

struct bh_deque {
    bh_deque_t* next;
    bh_deque_t* prev;
    void* data;
};

void bhdeque_push_front(bh_deque_t** deque, void* element);
void bhdeque_erase(bh_deque_t** deque, void (*erase_func)(void*));
void bhdeque_clear(bh_deque_t* deque, void (*erase_func)(void*));


#endif

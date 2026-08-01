#ifndef __BH_DEQUEUE_H__
#define __BH_DEQUEUE_H__




struct bh_deque;

typedef struct bh_deque  bh_deque_t;

struct bh_deque {
    bh_deque_t* next;
    bh_deque_t* prev;
    void* data;
};

/**
 * Add element to front of deque
 * @param deque Deque pointer
 * @param element Element to add
 */
void bhdeque_push_front(bh_deque_t** deque, void* element);

/**
 * Remove element from deque
 * @param deque Deque pointer
 * @param erase_func Function to free the element data
 */
void bhdeque_erase(bh_deque_t** deque, void (*erase_func)(void*));

/**
 * Clear entire deque
 * @param deque Deque pointer
 * @param erase_func Function to free the element data
 */
void bhdeque_clear(bh_deque_t* deque, void (*erase_func)(void*));


#endif

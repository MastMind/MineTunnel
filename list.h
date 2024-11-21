#ifndef __BH_LIST_H__
#define __BH_LIST_H__




struct bh_list;

typedef struct bh_list   bh_list_t;

struct bh_list {
    bh_list_t* next;
    void* data;
};

void bhlist_push_front(bh_list_t** list, void* element);
void bhlist_erase(bh_list_t** head, bh_list_t** list, void (*erase_func)(void*));
void bhlist_clear(bh_list_t* list, void (*erase_func)(void*));
bh_list_t* bhlist_find(bh_list_t* list, void* element, int (*cmp_func)(void*, void*));


#endif

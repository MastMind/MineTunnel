#include <stdlib.h>

#include "list.h"




void bhlist_push_front(bh_list_t** list, void* element) {
    bh_list_t* new_l = (bh_list_t*)malloc(sizeof(bh_list_t));

    if (!new_l) {
        return;
    }

    new_l->next = *list;
    new_l->data = element;

    *list = new_l;
}

void bhlist_erase(bh_list_t** head, bh_list_t** list, void (*erase_func)(void*)) {
    if (!head || !(*head) || !list || !(*list)) {
        return;
    }

    if (*head == *list) {
        bh_list_t* n = (*list)->next;
        if (erase_func && (*head)->data) {
            erase_func((*head)->data);
        }

        free(*head);
        *head = n;
        *list = n;

        return;
    }

    bh_list_t* h = *head;
    while (h->next && h->next != *list) {
        h = h->next;
    }

    h->next = (*list)->next;

    if (erase_func && (*list)->data) {
        erase_func((*list)->data);
    }

    (*list)->data = NULL;

    free(*list);
    *list = h->next;
}

void bhlist_clear(bh_list_t* list, void (*erase_func)(void*)) {
    bh_list_t* l = list;
    while (l) {
        bh_list_t* n = l->next;
        if (erase_func && l->data) {
            erase_func(l->data);
        }

        free(l);

        l = n;
    }
}

bh_list_t* bhlist_find(bh_list_t* list, void* element, int (*cmp_func)(void*, void*)) {
    if (!list) {
        return NULL;
    }

    while (list) {
        if (cmp_func(element, list->data) == 0) { //equal
            return list;
        }

        list = list->next;
    }

    return NULL;
}

#ifndef __BH_LIST_H__
#define __BH_LIST_H__




struct bh_list;

typedef struct bh_list   bh_list_t;

struct bh_list {
    bh_list_t* next;
    void* data;
};

/**
 * Add element to front of list
 * @param list List pointer
 * @param element Element to add
 */
void bhlist_push_front(bh_list_t** list, void* element);

/**
 * Remove element from list
 * @param head Pointer to head of list
 * @param list Pointer to element to remove
 * @param erase_func Function to free the element data
 */
void bhlist_erase(bh_list_t** head, bh_list_t** list, void (*erase_func)(void*));

/**
 * Clear entire list
 * @param list List pointer
 * @param erase_func Function to free the element data
 */
void bhlist_clear(bh_list_t* list, void (*erase_func)(void*));

/**
 * Find element in list
 * @param list List pointer
 * @param element Element to find
 * @param cmp_func Comparison function
 * @return Pointer to found element, or NULL if not found
 */
bh_list_t* bhlist_find(bh_list_t* list, void* element, int (*cmp_func)(void*, void*));


#endif

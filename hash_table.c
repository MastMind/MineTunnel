#include <stdlib.h>

#include "hash_table.h"




void hash_table_add(hash_table_t** hash_table, void* data, uint32_t (*hash_func)(void* data)) {
    (void)hash_table_add_r(hash_table, data, hash_func);
}

hash_table_t* hash_table_add_r(hash_table_t** hash_table, void* data, uint32_t (*hash_func)(void* data)) {
    if (!(*hash_table)) {
        *hash_table = (hash_table_t*)malloc(sizeof(hash_table_t));

        if (!(*hash_table)) {
            //internal error here
            return NULL;
        }

        (*hash_table)->hash = hash_func(data);
        (*hash_table)->data = NULL;
        (*hash_table)->parent = NULL;
        (*hash_table)->left = NULL;
        (*hash_table)->right = NULL;

        bhlist_push_front(&((*hash_table)->data), data);

        return *hash_table;
    }

    uint32_t new_hash = hash_func(data);
    hash_table_t* p_hash_table = *hash_table;

    //loop for adding
    while (p_hash_table) {
        if (new_hash < p_hash_table->hash) {
            //Add to left
            if (p_hash_table->left) {
                p_hash_table = p_hash_table->left;
            } else {
                hash_table_t* new_hash_table = (hash_table_t*)malloc(sizeof(hash_table_t));

                if (!new_hash_table) {
                    //internal error here
                    return NULL;
                }

                new_hash_table->hash = new_hash;
                new_hash_table->data = NULL;
                new_hash_table->parent = p_hash_table;
                new_hash_table->right = NULL;
                new_hash_table->left = NULL;

                bhlist_push_front(&(new_hash_table->data), data);

                p_hash_table->left = new_hash_table;
                
                return new_hash_table;
            }
        } else if (new_hash > p_hash_table->hash) {
            //Add to right
            if (p_hash_table->right) {
                p_hash_table = p_hash_table->right;
            } else {
                hash_table_t* new_hash_table = (hash_table_t*)malloc(sizeof(hash_table_t));

                if (!new_hash_table) {
                    //internal error here
                    return NULL;
                }

                new_hash_table->hash = new_hash;
                new_hash_table->data = NULL;
                new_hash_table->parent = p_hash_table;
                new_hash_table->right = NULL;
                new_hash_table->left = NULL;

                bhlist_push_front(&(new_hash_table->data), data);

                p_hash_table->right = new_hash_table;
                
                return new_hash_table;
            }
        } else {
            //just add to the list of the current hash_table element new value
            bhlist_push_front(&(p_hash_table->data), data);
            break;
        }
    }

    return *hash_table;
}

void* hash_table_find(hash_table_t** hash_table, void* data, uint32_t (*hash_func)(void* data), int (*cmp_func)(void*, void*)) {

    hash_table_t* p_hash_table = *hash_table;
    uint32_t hash = hash_func(data);

    while (p_hash_table) {
        if (hash == p_hash_table->hash) {
            //search element in list
            bh_list_t* p_list = bhlist_find(p_hash_table->data, data, cmp_func);
            if (p_list) {
                return p_list->data;
            } else {
                return NULL;
            }
        }

        if (hash < p_hash_table->hash) {
            p_hash_table = p_hash_table->left;
        } else {
            p_hash_table = p_hash_table->right;
        }
    }

    return NULL;
}

void hash_table_del_element(hash_table_t** hash_table, void* data, uint32_t (*hash_func)(void* data), int (*cmp_func)(void*, void*), 
                                                                void (*free_record)(void*)) {
    hash_table_t* p_hash_table = *hash_table;
    uint32_t hash = hash_func(data);

    while (p_hash_table) {
        if (hash == p_hash_table->hash) {
            //search element in list
            bh_list_t* p_list = bhlist_find(p_hash_table->data, data, cmp_func);
            if (p_list) {
                bhlist_erase(&(p_hash_table->data), &p_list, free_record);

                if (!p_hash_table->data) {
                    //delete this hash_table
                    hash_table_t* t_hash_table = p_hash_table;
                    hash_table_del(&t_hash_table, free_record);

                    if (p_hash_table == *hash_table) {
                        *hash_table = t_hash_table;
                    }
                }
            }

            break;
        }

        if (hash < p_hash_table->hash) {
            p_hash_table = p_hash_table->left;
        } else {
            p_hash_table = p_hash_table->right;
        }
    }
}

void hash_table_del(hash_table_t** hash_table, void (*free_record)(void*)) {
    if (!(*hash_table)) {
        return;
    }

    hash_table_t* del_hash_table = *hash_table;
    hash_table_t* parent = (*hash_table)->parent;
    hash_table_t* left = (*hash_table)->left;
    hash_table_t* right = (*hash_table)->right;

    if (!left && !right) {
        if (parent) {
            if (del_hash_table->hash > parent->hash) {
                parent->right = NULL;
            } else {
                parent->left = NULL;
            }
        }

        *hash_table = parent;

        goto end;
    }

    if (!left && right) {
        right->parent = parent;

        if (parent) {
            if (del_hash_table->hash > parent->hash) {
                parent->right = right;
            } else {
                parent->left = right;
            }
        }

        *hash_table = right;

        goto end;
    }

    if (left && !right) {
        left->parent = parent;

        if (parent) {
            if (del_hash_table->hash > parent->hash) {
                parent->right = left;
            } else {
                parent->left = left;
            }
        }

        *hash_table = left;

        goto end;
    }

    if (left && right) {
        hash_table_t* p_left = left;

        while (p_left->right) {
            p_left = p_left->right;
        }

        p_left->right = right;
        right->parent = p_left;

        left->parent = parent;

        if (parent) {
            if (del_hash_table->hash > parent->hash) {
                parent->right = left;
            } else {
                parent->left = left;
            }
        }

        *hash_table = left;

        goto end;
    }

end:
    if (del_hash_table->data) {
        bhlist_clear(del_hash_table->data, free_record);
        del_hash_table->data = NULL;
    }

    free(del_hash_table);
}

void hash_table_clear(hash_table_t** hash_table, void (*free_record)(void*)) {
    while (*hash_table) {
        hash_table_del(hash_table, free_record);
    }
}

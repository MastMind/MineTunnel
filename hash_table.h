#ifndef __HASHTABLE_H__
#define __HASHTABLE_H__


#include <stdint.h>

#include "list.h"




struct hash_table;
typedef struct hash_table hash_table_t;

struct hash_table {
    uint32_t hash;
    bh_list_t* data;
    hash_table_t* parent;
    hash_table_t* left;
    hash_table_t* right;
};

void hash_table_add(hash_table_t** hash_table, void* data, uint32_t (*hash_func)(void* data));
hash_table_t* hash_table_add_r(hash_table_t** hash_table, void* data, uint32_t (*hash_func)(void* data));
void* hash_table_find(hash_table_t** hash_table, void* data, uint32_t (*hash_func)(void* data), int (*cmp_func)(void*, void*));
void hash_table_del_element(hash_table_t** hash_table, void* data, uint32_t (*hash_func)(void* data), int (*cmp_func)(void*, void*),
                            void (*free_record)(void*));
void hash_table_del(hash_table_t** hash_table, void (*free_record)(void*));
void hash_table_clear(hash_table_t** hash_table, void (*free_record)(void*));


#endif 

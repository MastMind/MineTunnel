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

/**
 * Add data to hash table
 * @param hash_table Hash table pointer
 * @param data Data to add
 * @param hash_func Hash function for the data
 */
void hash_table_add(hash_table_t** hash_table, void* data, uint32_t (*hash_func)(void* data));

/**
 * Add data to hash table (recursive version)
 * @param hash_table Hash table pointer
 * @param data Data to add
 * @param hash_func Hash function for the data
 * @return Pointer to the created hash table node
 */
hash_table_t* hash_table_add_r(hash_table_t** hash_table, void* data, uint32_t (*hash_func)(void* data));

/**
 * Find data in hash table
 * @param hash_table Hash table pointer
 * @param data Data to find
 * @param hash_func Hash function for the data
 * @param cmp_func Comparison function for the data
 * @return Pointer to found data, or NULL if not found
 */
void* hash_table_find(hash_table_t** hash_table, void* data, uint32_t (*hash_func)(void* data), int (*cmp_func)(void*, void*));

/**
 * Delete specific element from hash table
 * @param hash_table Hash table pointer
 * @param data Data to delete
 * @param hash_func Hash function for the data
 * @param cmp_func Comparison function for the data
 * @param free_record Function to free the record data
 */
void hash_table_del_element(hash_table_t** hash_table, void* data, uint32_t (*hash_func)(void* data), int (*cmp_func)(void*, void*),
                            void (*free_record)(void*));

/**
 * Delete hash table
 * @param hash_table Hash table pointer
 * @param free_record Function to free the record data
 */
void hash_table_del(hash_table_t** hash_table, void (*free_record)(void*));

/**
 * Clear hash table (keep structure)
 * @param hash_table Hash table pointer
 * @param free_record Function to free the record data
 */
void hash_table_clear(hash_table_t** hash_table, void (*free_record)(void*));


#endif 

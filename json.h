#ifndef JSON_H
#define JSON_H

#ifdef DEBUG
#include <stdio.h>
#endif


#ifndef DEBUG
#define JSON_NO_PRINT_ERRORS
#endif

struct json_object;
struct json_array;
struct json_record;
struct json_value;

typedef struct json_object* json_object_t;
typedef struct json_array* json_array_t;
typedef struct json_record* json_record_t;
typedef struct json_value* json_value_t;
typedef enum record_type_s {
	EMPTY = 0,
	STRING,
	JSON_ARRAY,
	JSON_OBJECT
} record_type;

struct json_value {
	record_type type;
	void* value;
};

struct json_record {
	char* key;
	json_value_t value;
};

struct json_array {
	json_value_t* element;
	unsigned int size;	
};

struct json_object {
	json_record_t* element;
};


/**
 * Create a new JSON array
 * @return Pointer to created JSON array
 */
json_array_t json_array_create(void);

/**
 * Create a new JSON object
 * @return Pointer to created JSON object
 */
json_object_t json_object_create(void);

/**
 * Add string element to JSON array
 * @param o JSON array
 * @param e String to add
 * @return 0 on success, non-zero on error
 */
int json_array_add_string(json_array_t o, const char* e);

/**
 * Add array element to JSON array
 * @param o JSON array
 * @param e Array to add
 * @return 0 on success, non-zero on error
 */
int json_array_add_array(json_array_t o, json_array_t e);

/**
 * Add object element to JSON array
 * @param o JSON array
 * @param e Object to add
 * @return 0 on success, non-zero on error
 */
int json_array_add_object(json_array_t o, json_object_t e);

/**
 * Get element from JSON array by index
 * @param o JSON array
 * @param index Element index
 * @return Pointer to JSON value
 */
json_value_t json_array_get_element(json_array_t o, unsigned int index);

/**
 * Delete element from JSON array by index
 * @param o JSON array
 * @param index Element index
 * @return 0 on success, non-zero on error
 */
int json_array_del_element(json_array_t o, unsigned int index);

/**
 * Clear JSON array
 * @param o JSON array
 * @return 0 on success, non-zero on error
 */
int json_array_clear(json_array_t o);

/**
 * Add string element to JSON object
 * @param o JSON object
 * @param key Element key
 * @param e String value
 * @return 0 on success, non-zero on error
 */
int json_object_add_string(json_object_t o, const char* key, const char* e);

/**
 * Add array element to JSON object
 * @param o JSON object
 * @param key Element key
 * @param e Array value
 * @return 0 on success, non-zero on error
 */
int json_object_add_array(json_object_t o, const char* key, json_array_t e);

/**
 * Add object element to JSON object
 * @param o JSON object
 * @param key Element key
 * @param e Object value
 * @return 0 on success, non-zero on error
 */
int json_object_add_object(json_object_t o, const char* key, json_object_t e);

/**
 * Get element from JSON object by key
 * @param o JSON object
 * @param key Element key
 * @return Pointer to JSON value
 */
json_value_t json_object_get_element(json_object_t o, const char* key);

/**
 * Delete element from JSON object by key
 * @param o JSON object
 * @param key Element key
 * @return 0 on success, non-zero on error
 */
int json_object_del_element(json_object_t o, const char* key);

/**
 * Clear JSON object
 * @param o JSON object
 * @return 0 on success, non-zero on error
 */
int json_object_clear(json_object_t o);

/**
 * Convert JSON array to string
 * @param array JSON array
 * @param str Buffer to store string
 * @return 0 on success, non-zero on error
 */
int json_array_to_str(json_array_t array, char* str);

/**
 * Convert JSON object to string
 * @param object JSON object
 * @param str Buffer to store string
 * @return 0 on success, non-zero on error
 */
int json_object_to_str(json_object_t object, char* str);

/**
 * Print JSON array to file (DEBUG only)
 * @param f File handle
 * @param array JSON array
 */
#ifdef DEBUG
void json_array_print(FILE* f, json_array_t array);
void json_object_print(FILE* f, json_object_t object);
#endif

/**
 * Parse JSON from file
 * @param filename File path
 * @return Pointer to JSON value
 */
json_value_t json_from_file(const char* filename);

/**
 * Parse JSON from string
 * @param str JSON string
 * @return Pointer to JSON value
 */
json_value_t json_from_string(const char* str);


#endif

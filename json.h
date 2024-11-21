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


json_array_t json_array_create(void);
json_object_t json_object_create(void);
int json_array_add_string(json_array_t o, const char* e);
int json_array_add_array(json_array_t o, json_array_t e);
int json_array_add_object(json_array_t o, json_object_t e);
json_value_t json_array_get_element(json_array_t o, unsigned int index);
int json_array_del_element(json_array_t o, unsigned int index);
int json_array_clear(json_array_t o);

int json_object_add_string(json_object_t o, const char* key, const char* e);
int json_object_add_array(json_object_t o, const char* key, json_array_t e);
int json_object_add_object(json_object_t o, const char* key, json_object_t e);
json_value_t json_object_get_element(json_object_t o, const char* key);
int json_object_del_element(json_object_t o, const char* key);
int json_object_clear(json_object_t o);

int json_array_to_str(json_array_t array, char* str);
int json_object_to_str(json_object_t object, char* str);
#ifdef DEBUG
void json_array_print(FILE* f, json_array_t array);
void json_object_print(FILE* f, json_object_t object);
#endif

json_value_t json_from_file(const char* filename);
json_value_t json_from_string(const char* str);


#endif

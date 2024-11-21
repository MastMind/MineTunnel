#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "json.h"




static char* strip_line(const char* line);
static int parse_line(json_value_t v, const char* buf);

json_array_t json_array_create(void) {
    json_array_t ret = (json_array_t)malloc(sizeof(struct json_array));
    if (!ret) {
#ifndef JSON_NO_PRINT_ERRORS
        fprintf(stderr, "json_array_create : can't allocate memory\n");
#endif
        return NULL;
    }

    ret->element = NULL;
    ret->size = 0;

    return ret;
}

json_object_t json_object_create(void) {
    json_object_t ret = (json_object_t)malloc(sizeof(struct json_object));
    if (!ret) {
#ifndef JSON_NO_PRINT_ERRORS
        fprintf(stderr, "json_object_create : can't allocate memory\n");
#endif
        return NULL;
    }

    ret->element = NULL;

    return ret;
}

int json_array_add_string(json_array_t o, const char* e) {
    if (!o) {
#ifndef JSON_NO_PRINT_ERRORS
        fprintf(stderr, "json_array_add_string : array pointer is NULL\n");
#endif
        return -1;
    }

    o->size++;
    o->element = (json_value_t*)realloc(o->element, sizeof(json_value_t) * o->size);
    if (!(o->element)) {
#ifndef JSON_NO_PRINT_ERRORS
        fprintf(stderr, "json_array_add_string : can't realloc memory for elements\n");
#endif
        return -2;
    }

    *(o->element + o->size - 1) = (json_value_t)malloc(sizeof(struct json_value));
    if (!(*(o->element + o->size - 1))) {
#ifndef JSON_NO_PRINT_ERRORS
        fprintf(stderr, "json_array_add_string : can't allocate memory for element\n");
#endif

        return -2;
    }

    if (!e || strlen(e) == 0) {
        (*(o->element + o->size - 1))->type = EMPTY;
        (*(o->element + o->size - 1))->value = NULL;
    } else {
        (*(o->element + o->size - 1))->type = STRING;
        (*(o->element + o->size - 1))->value = malloc(sizeof(char) * (strlen(e) + 1));
        if (!((*(o->element + o->size - 1))->value)) {
#ifndef JSON_NO_PRINT_ERRORS
            fprintf(stderr, "json_array_add_string : can't allocate memory for string value\n");
#endif
            return -3;
        }

        memcpy((*(o->element + o->size - 1))->value, e, sizeof(char) * (strlen(e) + 1));
    }

    return 0;
}

int json_array_add_array(json_array_t o, json_array_t e) {
    if (!o) {
#ifndef JSON_NO_PRINT_ERRORS
        fprintf(stderr, "json_array_add_array : array pointer is NULL\n");
#endif
        return -1;
    }

    if (!e) {
#ifndef JSON_NO_PRINT_ERRORS
        fprintf(stderr, "json_array_add_array : object pointer is NULL\n");
#endif
        return -1;
    }

    o->size++;
    o->element = (json_value_t*)realloc(o->element, sizeof(json_value_t) * o->size);
    if (!(o->element)) {
#ifndef JSON_NO_PRINT_ERRORS
        fprintf(stderr, "json_array_add_string : can't realloc memory for elements\n");
#endif
        return -2;
    }

    *(o->element + o->size - 1) = (json_value_t)malloc(sizeof(struct json_value));
    if (!(*(o->element + o->size - 1))) {
#ifndef JSON_NO_PRINT_ERRORS
        fprintf(stderr, "json_array_add_string : can't allocate memory for element\n");
#endif

        return -2;
    }

    (*(o->element + o->size - 1))->type = JSON_ARRAY;
    (*(o->element + o->size - 1))->value = e;

    return 0;
}

int json_array_add_object(json_array_t o, json_object_t e) {
    if (!o) {
#ifndef JSON_NO_PRINT_ERRORS
        fprintf(stderr, "json_array_add_object : array pointer is NULL\n");
#endif
        return -1;
    }

    if (!e) {
#ifndef JSON_NO_PRINT_ERRORS
        fprintf(stderr, "json_array_add_object : object pointer is NULL\n");
#endif
        return -1;
    }

    o->size++;
    o->element = (json_value_t*)realloc(o->element, sizeof(json_value_t) * o->size);
    if (!(o->element)) {
#ifndef JSON_NO_PRINT_ERRORS
        fprintf(stderr, "json_array_add_string : can't realloc memory for elements\n");
#endif
        return -2;
    }

    *(o->element + o->size - 1) = (json_value_t)malloc(sizeof(struct json_value));
    if (!(*(o->element + o->size - 1))) {
#ifndef JSON_NO_PRINT_ERRORS
        fprintf(stderr, "json_array_add_string : can't allocate memory for element\n");
#endif

        return -2;
    }

    (*(o->element + o->size - 1))->type = JSON_OBJECT;
    (*(o->element + o->size - 1))->value = e;

    return 0;
}

json_value_t json_array_get_element(json_array_t o, unsigned int index) {
    if (!o) {
        return NULL;
    }

    if (index >= o->size) {
        return NULL;
    }

    return *(o->element + index);
}

int json_array_del_element(json_array_t o, unsigned int index) {
    if (!o) {
        return -1;
    }

    if (index >= o->size) {
        return -1;
    }

    int ret = 0;
    switch ((*(o->element + index))->type) {
        case STRING:
            free((*(o->element + index))->value);
            break;
        case JSON_ARRAY:
            ret = json_array_clear((json_array_t)((*(o->element + index))->value));
            break;
        case JSON_OBJECT:
            ret = json_object_clear((json_object_t)((*(o->element + index))->value));
            break;
        default:
            break;
    }

    if (ret) {
#ifndef JSON_NO_PRINT_ERRORS
        fprintf(stderr, "json_array_del_element : can't delete element\n");
#endif
        return -2;
    }

    if (index < o->size - 1) {
        memmove(o->element + index, o->element + index + 1, sizeof(json_value_t) * (o->size - index - 1));
    }

    o->size--;
    if (o->size) {
        o->element = (json_value_t*)realloc(o->element, sizeof(json_value_t) * o->size);
        if (!(o->element)) {
#ifndef JSON_NO_PRINT_ERRORS
            fprintf(stderr, "json_array_del_element : can't realloc memory for elements\n");
#endif
            return -3;
        }
    } else {
        free(o->element);
        o->element = NULL;
    }

    return 0;
}

int json_array_clear(json_array_t o) {
    if (!o) { 
        return -1;
    }

    int ret = 0;
    for (unsigned int i = 0; i < o->size; i++) {
        switch ((*(o->element + i))->type) {
            case STRING:
                free((*(o->element + i))->value);
                break;
            case JSON_ARRAY:
                ret = json_array_clear((json_array_t)((*(o->element + i))->value));
                break;
            case JSON_OBJECT:
                ret = json_object_clear((json_object_t)((*(o->element + i))->value));
                break;
            default:
                break;
        }

        free(*(o->element + i));
    }

    if (ret) {
        return -2;
    }

    if (o->element) {
        free(o->element);
    }
    free(o);

    return 0;
}

int json_object_add_string(json_object_t o, const char* key, const char* e) {
    if (!o || !key || !strlen(key)) {
#ifndef JSON_NO_PRINT_ERRORS
        fprintf(stderr, "json_object_add_string : object pointer is NULL\n");
#endif
        return -1;
    }

    unsigned int i = 0;
    while (o->element && *(o->element + i)) {
        i++;
    }

    o->element = (json_record_t*)realloc(o->element, sizeof(json_record_t) * (i + 2));
    if (!(o->element)) {
#ifndef JSON_NO_PRINT_ERRORS
        fprintf(stderr, "json_object_add_string : can't allocate memory for elements\n");
#endif
        return -2;
    }

    *(o->element + i) = (json_record_t)malloc(sizeof(struct json_record));
    if (!(*(o->element + i))) {
#ifndef JSON_NO_PRINT_ERRORS
        fprintf(stderr, "json_object_add_string : can't allocate memory for element\n");
#endif
        return -2;
    }

    (*(o->element + i))->key = (char*)malloc(sizeof(char) * (strlen(key) + 1));
    if (!((*(o->element + i))->key)) {
#ifndef JSON_NO_PRINT_ERRORS
        fprintf(stderr, "json_object_add_string : can't allocate memory for key\n");
#endif
        return -3;
    }
    strcpy((*(o->element + i))->key, key);

    (*(o->element + i))->value = (json_value_t)malloc(sizeof(struct json_value));

    if (!((*(o->element + i))->value)) {
#ifndef JSON_NO_PRINT_ERRORS
        fprintf(stderr, "json_object_add_string : can't allocate memory for value\n");
#endif
        return -3;
    }

    if (!e || strlen(e) == 0) {
        (*(o->element + i))->value->type = EMPTY;
        (*(o->element + i))->value->value = NULL;
    } else {
        (*(o->element + i))->value->type = STRING;
        (*(o->element + i))->value->value = malloc(sizeof(char) * (strlen(e) + 1));
        if (!((*(o->element + i))->value->value)) {
#ifndef JSON_NO_PRINT_ERRORS
            fprintf(stderr, "json_object_add_string : can't allocate memory for value\n");
#endif
            return -4;
        }

        strcpy((char*)((*(o->element + i))->value->value), e);
    }
    *(o->element + i + 1) = NULL;

    return 0;
}

int json_object_add_array(json_object_t o, const char* key, json_array_t e) {
    if (!o || !key || !strlen(key)) {
#ifndef JSON_NO_PRINT_ERRORS
        fprintf(stderr, "json_object_add_array : object pointer is NULL\n");
#endif
        return -1;
    }

    if (!e) {
#ifndef JSON_NO_PRINT_ERRORS
        fprintf(stderr, "json_object_add_array : array pointer is NULL\n");
#endif
        return -1;
    }

    unsigned int i = 0;
    while (o->element && *(o->element + i)) {
        i++;
    }

    o->element = (json_record_t*)realloc(o->element, sizeof(json_record_t) * (i + 2));
    if (!(o->element)) {
#ifndef JSON_NO_PRINT_ERRORS
        fprintf(stderr, "json_object_add_array : can't allocate memory for elements\n");
#endif
        return -2;
    }

    *(o->element + i) = (json_record_t)malloc(sizeof(struct json_record));
    if (!(*(o->element + i))) {
#ifndef JSON_NO_PRINT_ERRORS
        fprintf(stderr, "json_object_add_array : can't allocate memory for element\n");
#endif
        return -2;
    }

    (*(o->element + i))->key = (char*)malloc(sizeof(char) * (strlen(key) + 1));
    if (!((*(o->element + i))->key)) {
#ifndef JSON_NO_PRINT_ERRORS
        fprintf(stderr, "json_object_add_array : can't allocate memory for key\n");
#endif
        return -3;
    }
    strcpy((*(o->element + i))->key, key);

    (*(o->element + i))->value = (json_value_t)malloc(sizeof(struct json_value));
    if (!((*(o->element + i))->value)) {
#ifndef JSON_NO_PRINT_ERRORS
        fprintf(stderr, "json_object_add_array : can't allocate memory for value\n");
#endif
        return -3;
    }

    (*(o->element + i))->value->type = JSON_ARRAY;
    (*(o->element + i))->value->value = e;
    *(o->element + i + 1) = NULL;

    return 0;
}

int json_object_add_object(json_object_t o, const char* key, json_object_t e) {
        if (!o || !key || !strlen(key)) {
#ifndef JSON_NO_PRINT_ERRORS
        fprintf(stderr, "json_object_add_object : object pointer is NULL\n");
#endif
        return -1;
    }

    if (!e) {
#ifndef JSON_NO_PRINT_ERRORS
        fprintf(stderr, "json_object_add_object : object pointer is NULL\n");
#endif
        return -1;
    }

    unsigned int i = 0;
    while (o->element && *(o->element + i)) {
        i++;
    }

    o->element = (json_record_t*)realloc(o->element, sizeof(json_record_t) * (i + 2));
    if (!(o->element)) {
#ifndef JSON_NO_PRINT_ERRORS
        fprintf(stderr, "json_object_add_object : can't allocate memory for elements\n");
#endif
        return -2;
    }

    *(o->element + i) = (json_record_t)malloc(sizeof(struct json_record));
    if (!(*(o->element + i))) {
#ifndef JSON_NO_PRINT_ERRORS
        fprintf(stderr, "json_object_add_object : can't allocate memory for element\n");
#endif
        return -2;
    }

    (*(o->element + i))->key = (char*)malloc(sizeof(char) * (strlen(key) + 1));
    if (!((*(o->element + i))->key)) {
#ifndef JSON_NO_PRINT_ERRORS
        fprintf(stderr, "json_object_add_object : can't allocate memory for key\n");
#endif
        return -3;
    }
    strcpy((*(o->element + i))->key, key);

    (*(o->element + i))->value = (json_value_t)malloc(sizeof(struct json_value));
    if (!((*(o->element + i))->value)) {
#ifndef JSON_NO_PRINT_ERRORS
        fprintf(stderr, "json_object_add_object : can't allocate memory for value\n");
#endif
        return -3;
    }

    (*(o->element + i))->value->type = JSON_OBJECT;
    (*(o->element + i))->value->value = e;
    *(o->element + i + 1) = NULL;

    return 0;
}

json_value_t json_object_get_element(json_object_t o, const char* key) {
    if (!o || !key) {
        return NULL;
    }

    unsigned int i = 0;
    while (o->element && *(o->element + i)) {
        if (!strcmp((*(o->element + i))->key, key)) {
            return (*(o->element + i))->value;
        }
        i++;
    }

    return NULL;
}

int json_object_del_element(json_object_t o, const char* key) {
    if (!o || !key) {
        return -1;
    }

    unsigned int i = 0;
    unsigned int index = 0;
    int ret = 0;
    while (o->element && *(o->element + i)) {
        if (!strcmp((*(o->element + i))->key, key)) {
            switch ((*(o->element + i))->value->type) {
                case STRING:
                    free((*(o->element + i))->value->value);
                    break;
                case JSON_ARRAY:
                    ret = json_array_clear((json_array_t)((*(o->element + i))->value->value));
                    break;
                case JSON_OBJECT:
                    ret = json_object_clear((json_object_t)((*(o->element + i))->value->value));
                    break;
                default:
                    break;
            }

            free((*(o->element + i))->key);
            index = i;
        }

        i++;
    }

    if (i == 0) {
        return 0;
    }

    if (ret) {
#ifndef JSON_NO_PRINT_ERRORS
        fprintf(stderr, "json_object_del_element : can't delete element\n");
#endif
        return -2;
    }

    if (index < i - 1) {
        memmove(o->element + index, o->element + index + 1, sizeof(json_record_t) * (i - index - 1));
    }

    i--;
    if (i) {
        o->element = (json_record_t*)realloc(o->element, sizeof(json_record_t) * i);
        if (!(o->element)) {
#ifndef JSON_NO_PRINT_ERRORS
            fprintf(stderr, "json_object_del_element : can't realloc memory for elements\n");
#endif
            return -3;
        }
    } else {
        free(o->element);
        o->element = NULL;
    }

    return 0;
}

int json_object_clear(json_object_t o) {
    if (!o) { 
        return -1;
    }

    int ret = 0;
    unsigned int i = 0;
    while (o->element && *(o->element + i)) {
        free((*(o->element + i))->key);
        switch ((*(o->element + i))->value->type) {
            case STRING:
                free((*(o->element + i))->value->value);
                break;
            case JSON_ARRAY:
                ret = json_array_clear((json_array_t)((*(o->element + i))->value->value));
                break;
            case JSON_OBJECT:
                ret = json_object_clear((json_object_t)((*(o->element + i))->value->value));
                break;
            default:
                break;
        }

        free((*(o->element + i))->value);
        free(*(o->element + i));

        i++;
    }

    if (ret) {
        return -2;
    }

    if (o->element) {
        free(o->element);
    }
    free(o);

    return 0;
}

int json_array_to_str(json_array_t array, char* str) {
    if (!array || !str) {
        return -1;
    }

    char* p = str;

    sprintf(p, "[");
    p++;

    for (unsigned int i = 0; i < array->size; i++) {
        switch ((*(array->element + i))->type) {
            case STRING:
                sprintf(p, "\"%s\"", (char*)((*(array->element + i))->value));
                p += strlen(p);
                break;
            case JSON_ARRAY:
                if (json_array_to_str((json_array_t)((*(array->element + i))->value), p)) {
                    return -1;
                }
                p += strlen(p);
                break;
            case JSON_OBJECT:
                if (json_object_to_str((json_object_t)((*(array->element + i))->value), p)) {
                    return -1;
                }
                p += strlen(p);
                break;
            default:
                break;
        }

        if (i < array->size - 1) {
            sprintf(p, ", ");
            p++;
        }
    }

    sprintf(p, "]");

    return 0;
}

int json_object_to_str(json_object_t object, char* str) {
    if (!object || !str) {
        return -1;
    }

    char* p = str;

    sprintf(p, "{");
    p++;

    unsigned int i = 0;
    while (object->element && *(object->element + i)) {
        sprintf(p, "\"%s\":", (*(object->element + i))->key);
        p += strlen(p);
        switch ((*(object->element + i))->value->type) {
            case STRING:
                sprintf(p, "\"%s\"", (char*)((*(object->element + i))->value->value));
                p += strlen(p);
                break;
            case JSON_ARRAY:
                if (json_array_to_str((json_array_t)((*(object->element + i))->value->value), p)) {
                    return -1;
                }
                p += strlen(p);
                break;
            case JSON_OBJECT:
                if (json_object_to_str((json_object_t)((*(object->element + i))->value->value), p)) {
                    return -1;
                }
                p += strlen(p);
                break;
            default:
                break;
        }

        i++;
        if (*(object->element + i)) {
            sprintf(p, ", ");
            p++;
        }
    }

    sprintf(p, "}");

    return 0;
}

#ifdef DEBUG

void json_array_print(FILE* f, json_array_t array) {
    fprintf(f, "[");

    for (unsigned int i = 0; i < array->size; i++) {
        switch ((*(array->element + i))->type) {
            case STRING:
                fprintf(f, "\"%s\"", (char*)((*(array->element + i))->value));
                break;
            case JSON_ARRAY:
                json_array_print(f, (json_array_t)((*(array->element + i))->value));
                break;
            case JSON_OBJECT:
                json_object_print(f, (json_object_t)((*(array->element + i))->value));
                break;
            default:
                break;
        }
        if (i < array->size - 1) {
            fprintf(f, ", ");
        }
    }

    fprintf(f, "]");
}

void json_object_print(FILE* f, json_object_t object) {
    fprintf(f, "{");

    unsigned int i = 0;
    while (object->element && *(object->element + i)) {
        fprintf(f, "\"%s\":", (*(object->element + i))->key);
        switch ((*(object->element + i))->value->type) {
            case STRING:
                fprintf(f, "\"%s\"", (char*)((*(object->element + i))->value->value));
                break;
            case JSON_ARRAY:
                json_array_print(f, (json_array_t)((*(object->element + i))->value->value));
                break;
            case JSON_OBJECT:
                json_object_print(f, (json_object_t)((*(object->element + i))->value->value));
                break;
            default:
                break;
        }

        i++;
        if (*(object->element + i)) {
            fprintf(f, ", ");
        }
    }

    fprintf(f, "}");
}

#endif

json_value_t json_from_file(const char* filename) {
    if (!filename || !strlen(filename)) {
        return NULL;
    }

    FILE* f = fopen(filename, "rb");
    if (!f) {
#ifndef JSON_NO_PRINT_ERRORS
        fprintf(stderr, "json_from_file : can't open file %s for reading\n", filename);
#endif
        return NULL;
    }

    json_value_t ret = (json_value_t)malloc(sizeof(struct json_value));
    if (!ret) {
#ifndef JSON_NO_PRINT_ERRORS
        fprintf(stderr, "json_from_file : can't allocate memory\n");
#endif
        return NULL;
    }

    fseek(f, 0, SEEK_END);
    unsigned int size = ftell(f);

    char* buf = (char*)malloc(sizeof(char) * (size + 1));
    if (!buf) {
#ifndef JSON_NO_PRINT_ERRORS
        fprintf(stderr, "json_from_file : can't allocate memory for buf\n");
#endif
        fclose(f);
        free(ret);

        return NULL;
    }

    rewind(f);
    fread(buf, 1, size, f);
    *(buf + size) = '\0'; 

    fclose(f);

    int ret_code = parse_line(ret, buf);
    if (ret_code) {
#ifndef JSON_NO_PRINT_ERRORS
        fprintf(stderr, "json_from_file : error in json file %s\n code: %d\n", filename, ret_code);
#endif
        if (ret->type == JSON_ARRAY) {
            json_array_clear((json_array_t)(ret->value));
        }

        if (ret->type == JSON_OBJECT) {
            json_object_clear((json_object_t)(ret->value));
        }

        free(ret);
        ret = NULL;
    }

    free(buf);
    return ret;
}

json_value_t json_from_string(const char* str) {
    if (!str || !strlen(str)) {
        return NULL;
    }

    json_value_t ret = (json_value_t)malloc(sizeof(struct json_value));
    if (!ret) {
#ifndef JSON_NO_PRINT_ERRORS
        fprintf(stderr, "json_from_string : can't allocate memory\n");
#endif
        return NULL;
    }

    int ret_code = parse_line(ret, str);
    if (ret_code) {
#ifndef JSON_NO_PRINT_ERRORS
        fprintf(stderr, "json_from_string : error in json string %s\n code: %d\n", str, ret_code);
#endif
        if (ret->type == JSON_ARRAY) {
            json_array_clear((json_array_t)(ret->value));
        }

        if (ret->type == JSON_OBJECT) {
            json_object_clear((json_object_t)(ret->value));
        }

        free(ret);
        ret = NULL;
    }

    return ret;
}

static char* strip_line(const char* line) {
    if (!line) {
        return NULL;
    }

    char* ret = (char*)strdup(line + strspn(line, " \n\t"));
    if (!ret) {
#ifndef JSON_NO_PRINT_ERRORS
        fprintf(stderr, "strip_line : can't allocate memory\n");
#endif
        return NULL;
    }

    unsigned int str_length = strlen(ret);

    if (!str_length) {
        free(ret);
        return NULL;
    }

    for (unsigned int i = str_length - 1; i >= 0; i--) {
        if (ret[i] != ' ' && ret[i] != '\n' && ret[i] != '\t') {
            ret[i + 1] = '\0';
            break;
        }
    }

    return ret;
}

static int parse_line(json_value_t v, const char* buf) {
    char* l = strip_line(buf);
    char* line = NULL;
    int ret = 0;
    char* fragment = NULL;
    char* key = NULL;
    json_value_t val = NULL;

    int brackets_score = 0;
    int item_flag = 1;
    int end_flag = 0;
    int array_or_object_flag = 0;

    if (!l) {
        return -1;
    }

    if (*l == '{') {
        v->type = JSON_OBJECT;
        v->value = json_object_create();
    } else if (*l == '[') {
        v->type = JSON_ARRAY;
        v->value = json_array_create();
    } else {
        //bad json string
        ret = -1;
        goto end;
    }

    if (!(v->value)) {
        //something wrong
        ret = -2;
        goto end;
    }

    line = l + 1;

    while (*line) {
        switch (v->type) {
            case JSON_ARRAY:
                switch (*line) {
                    case ',':
                        if (!item_flag) {
                            item_flag = 1;
                            if (array_or_object_flag) {
                                line--;
                            }

                            break;
                        }

                        if (array_or_object_flag) {
                            //skip comma and spaces
                            line += strspn(line, " \n\t");
                            array_or_object_flag = 0;
                            break;
                        }

                        ret = json_array_add_string((json_array_t)(v->value), fragment);
                        if (ret) {
                            //something wrongs
                            goto end;
                        }
                        if (fragment) {
                            free(fragment);
                            fragment = NULL;
                        }
                        break;
                    case '[':
                    case '{':
                        val = (json_value_t)malloc(sizeof(struct json_value));
                        if (!val) {
                            //something wrong
                            ret = -2;
                            goto end;
                        }

                        ret = parse_line(val, line);
                        if (ret) {
                            goto end;
                        }

                        //need line shift
                        if (*line == '{') {
                            line++;
                            brackets_score = 1;
                            while (brackets_score > 0 && *line) {
                                if (*line == '{') {
                                    brackets_score++;
                                }

                                if (*line == '}') {
                                    brackets_score--;
                                }

                                line++;
                            }

                            if (brackets_score) {
                                //wrong syntax
                                ret = -3;
                                goto end;
                            }
                        }

                        if (*line == '[') {
                            line++;
                            brackets_score = 1;
                            while (brackets_score > 0 && *line) {
                                if (*line == '[') {
                                    brackets_score++;
                                }

                                if (*line == ']') {
                                    brackets_score--;
                                }

                                line++;
                            }

                            if (brackets_score) {
                                //wrong syntax
                                ret = -3;
                                goto end;
                            }   
                        }

                        if (val->type == JSON_ARRAY) {
                            ret = json_array_add_array((json_array_t)(v->value), (json_array_t)(val->value));
                            array_or_object_flag = 1;
                        } else if (val->type == JSON_OBJECT) {
                            ret = json_array_add_object((json_array_t)(v->value), (json_object_t)(val->value));
                            array_or_object_flag = 1;
                        } else {
                            ret = -5;
                            goto end;
                        }

                        free(val);
                        val = NULL;

                        item_flag = 0;
                        line--;
                        break;
                    case ']':
                        //end of array
                        if (item_flag) {
                            ret = json_array_add_string((json_array_t)(v->value), fragment);
                        }

                        end_flag = 1;
                        goto end;
                    //bad characters
                    case '}':
                        ret = -3;
                        goto end;
                    //other characters
                    case ' ':
                    case '\n':
                    case '\t':
                        line += strspn(line, " \n\t");
                        if (fragment) {
                            if (*line != ',' &&
                                *line != ']') {
                                //wrong syntax
                                ret = -3;
                                goto end;
                            }
                        }
                        //???? probably need comma's checking when rest of line is not empty
                        if (array_or_object_flag) {
                            if (*line && 
                                *line != ',' &&
                                *line != '}' &&
                                *line != ']') {
                                ret = -3;
                                goto end;
                            }
                        }

                        array_or_object_flag = 0;

                        line--;
                        break;
                    case '\"':
                        if (fragment) {
                            //wrong syntax
                            ret = -3;
                            goto end;
                        }

                        line++;
                        fragment = (char*)malloc(sizeof(char) * (strcspn(line, "\"") + 1));
                        if (!fragment) {
                            //something wrong
                            ret = -2;
                            goto end;
                        }

                        strncpy(fragment, line, strcspn(line, "\""));
                        *(fragment + strcspn(line, "\"")) = '\0';
                        line += strcspn(line, "\"");
                        break;
                    case '\\':
                        line++;
                    default:
                        if (!fragment) {
                            fragment = (char*)malloc(sizeof(char) * 2);
                            if (!fragment) {
                                //something wrong
                                ret = -2;
                                goto end;
                            }

                            *fragment = *line;
                            *(fragment + 1) = '\0';
                        } else {
                            fragment = (char*)realloc(fragment, sizeof(char) * (strlen(fragment) + 2));
                            if (!fragment) {
                                //something wrong
                                ret = -2;
                                goto end;
                            }

                            *(fragment + strlen(fragment) + 1) = '\0';
                            *(fragment + strlen(fragment)) = *line;
                        }

                        break;
                }
                break;
            case JSON_OBJECT:
                switch (*line) {
                    case ':':
                        if (key || !fragment) {
                            //wrong syntax
                            ret = -3;
                            goto end;
                        }

                        key = (char*)strdup(fragment);
                        if (!key) {
                            //something wrong
                            ret = -2;
                            goto end;
                        }

                        free(fragment);
                        fragment = NULL;
                        break;
                    case ',':
                        if (!item_flag) {
                            item_flag = 1;

                            if (array_or_object_flag) {
                                line--;
                            }
                            break;
                        }

                        if (!key) {
                            if (array_or_object_flag) {
                                //skip comma and spaces
                                line += strspn(line, " \n\t");
                                array_or_object_flag = 0;
                                break;
                            }
                            //wrong syntax
                            ret = -3;
                            goto end;
                        }

                        ret = json_object_add_string((json_object_t)(v->value), key, fragment);
                        if (ret) {
                            //something worng
                            goto end;
                        }
                        if (fragment) {
                            free(fragment);
                            fragment = NULL;
                        }

                        free(key);
                        key = NULL;
                        break;
                    case '[':
                    case '{':
                        if (!key) {
                            //wrong syntax
                            ret = -3;
                            goto end;
                        }

                        val = (json_value_t)malloc(sizeof(struct json_value));
                        if (!val) {
                            //something wrong
                            ret = -2;
                            goto end;
                        }

                        ret = parse_line(val, line);
                        if (ret) {
                            goto end;
                        }

                        //need line shift
                        if (*line == '{') {
                            line++;
                            brackets_score = 1;
                            while (brackets_score > 0 && *line) {
                                if (*line == '{') {
                                    brackets_score++;
                                }

                                if (*line == '}') {
                                    brackets_score--;
                                }

                                line++;
                            }

                            if (brackets_score) {
                                //wrong syntax
                                ret = -3;
                                goto end;
                            }
                        }

                        if (*line == '[') {
                            line++;
                            brackets_score = 1;
                            while (brackets_score > 0 && *line) {
                                if (*line == '[') {
                                    brackets_score++;
                                }

                                if (*line == ']') {
                                    brackets_score--;
                                }

                                line++;
                            }

                            if (brackets_score) {
                                //wrong syntax
                                ret = -3;
                                goto end;
                            }   
                        }

                        if (val->type == JSON_ARRAY) {
                            ret = json_object_add_array((json_object_t)(v->value), key, (json_array_t)(val->value));
                            array_or_object_flag = 1;
                        } else if (val->type == JSON_OBJECT) {
                            ret = json_object_add_object((json_object_t)(v->value), key, (json_object_t)(val->value));
                            array_or_object_flag = 1;
                        } else {
                            ret = -5;
                            goto end;
                        }

                        free(val);
                        val = NULL;
                        free(key);
                        key = NULL;

                        line--;
                        item_flag = 0;
                        break;
                    case '}':
                        //end of object
                        if (item_flag) {
                            if (!key) {
                                //wrong syntax
                                ret = -3;
                                goto end;
                            }
                            ret = json_object_add_string((json_object_t)(v->value), key, fragment);
                        }

                        end_flag = 1;
                        goto end;
                    //bad characters
                    case ']':
                        ret = -3;
                        goto end;
                    case ' ':
                    case '\n':
                    case '\t':
                        line += strspn(line, " \n\t");
                        if (fragment) {
                            if (*line != ',' &&
                                *line != ':' &&
                                *line != '}') {
                                //wrong syntax
                                ret = -3;
                                goto end;
                            }
                        }
                        //???? probably need comma's checking when rest of line is not empty
                        if (array_or_object_flag) {
                            if (*line && 
                                *line != ',' &&
                                *line != '}' &&
                                *line != ']') {
                                ret = -3;
                                goto end;
                            }
                        }

                        array_or_object_flag = 0;
                        line--;
                        break;
                    case '\"':
                        if (fragment) {
                            //wrong syntax
                            ret = -3;
                            goto end;
                        }

                        line++;
                        fragment = (char*)malloc(sizeof(char) * (strcspn(line, "\"") + 1));
                        if (!fragment) {
                            //something wrong
                            ret = -2;
                            goto end;
                        }

                        strncpy(fragment, line, strcspn(line, "\""));
                        *(fragment + strcspn(line, "\"")) = '\0';
                        line += strcspn(line, "\"");
                        break;
                    case '\\':
                        line++;
                    default:
                        if (!fragment) {
                            fragment = (char*)malloc(sizeof(char) * 2);
                            if (!fragment) {
                                //something wrong
                                ret = -2;
                                goto end;
                            }

                            *fragment = *line;
                            *(fragment + 1) = '\0';
                        } else {
                            fragment = (char*)realloc(fragment, sizeof(char) * (strlen(fragment) + 2));
                            if (!fragment) {
                                //something wrong
                                ret = -2;
                                goto end;
                            }

                            *(fragment + strlen(fragment) + 1) = '\0';
                            *(fragment + strlen(fragment)) = *line; 
                        }

                        break;
                }
                break;
            default:
                break;
        }

        line++;
    }

    if (!end_flag) {
        //record is not ended
        ret = -3;
    }

end:
    if (fragment) {
        free(fragment);
    }
    if (key) {
        free(key);
    }

    free(l);

    return ret;
}

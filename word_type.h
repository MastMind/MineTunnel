#ifndef WORD_TYPE_H
#define WORD_TYPE_H


typedef enum word_type_s {
    IMPL_WORD = 0,
    STRING,
    NUMBER,
    IPADDR,
    IP6ADDR
} word_type;

/**
 * Check if string matches word type
 * @param str String to check
 * @param wt Word type to match
 * @return 1 if match, 0 otherwise
 */
int striswt(const char* str, word_type wt);


#endif

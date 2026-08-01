#ifndef SYNTAX_TREE_H
#define SYNTAX_TREE_H

#include <stdint.h>

#include "word_type.h"
#include "embed_commands.h"
#include "defines.h"


struct syntax_tree_node;
typedef struct syntax_tree_node* syntax_tree_t;

typedef struct syntax_tree_node {
    char word[MAX_STR_LENGTH];
    word_type wtype;
    syntax_tree_t* node;
    syntax_tree_t parent;
    uint32_t nodeSize;
    int (*func)(CMD_ARGS);
} syntax_tree;

/**
 * Create syntax tree from command list
 * @param cmds Array of commands
 * @return Pointer to created syntax tree
 */
syntax_tree_t create_syntax_tree(const command* cmds);

/**
 * Match input line against syntax tree
 * @param tree Syntax tree pointer
 * @param line Input line to match
 * @param auto_complete Buffer for auto-completion
 * @return 0 if no match, 1 if match
 */
int match_syntax_tree(syntax_tree_t* tree, const char* line, char* auto_complete);

/**
 * Free syntax tree memory
 * @param tree Syntax tree to free
 */
void free_syntax_tree(syntax_tree_t tree);



#endif

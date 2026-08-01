#include <string.h>
#include <stdlib.h>

#include "utils.h"
#include "defines.h"
#include "embed_commands.h"
#include "syntax_tree.h"




static syntax_tree_t synt_tree = NULL;


/**
 * Initialize embedded interpreter
 * @return 0 on success, non-zero on error
 */
int embed_interpreter_init(void) {
    synt_tree = create_syntax_tree(shell_commands);
    if (!synt_tree) {
        return -1;
    }

    return 0;
}

/**
 * Execute embedded script command
 * @param line Command line
 * @param tun Tunnel entity for context
 * @return 0 on success, non-zero on error
 */
int embed_interpreter_exec(char* line, tunnel_entity_t* tun) {
    char* lstr = strip_line(line);
    int ret = 0;
    syntax_tree_t tree = synt_tree;

#ifdef DEBUG
    PrintInform("Executing line: %s\n", lstr);
#endif

    if (!lstr) {
        PrintError("Embed interpreter error: bad string \"%s\"\n", line);
        return -1;
    }

    if (!strlen(lstr)) {
        free(lstr);
        return 0;
    }

    int match = match_syntax_tree(&tree, lstr, NULL);
    if (match) { //execute command
        ret = tree->func(lstr, tun);
    } else {
        PrintError("Embed interpreter error: wrong command \"%s\"\n", lstr);
    }

    free(lstr);
    return ret;
}

/**
 * Deinitialize embedded interpreter
 */
void embed_interpreter_deinit(void) {
    free_syntax_tree(synt_tree);
}

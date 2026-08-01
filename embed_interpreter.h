#ifndef SHELL_H
#define SHELL_H


#include <stdint.h>

#include "tunnel.h"




/**
 * Initialize embedded interpreter
 * @return 0 on success, non-zero on error
 */
int embed_interpreter_init(void);

/**
 * Execute embedded script command
 * @param line Command line
 * @param tun Tunnel entity for context
 * @return 0 on success, non-zero on error
 */
int embed_interpreter_exec(char* line, tunnel_entity_t* tun);

/**
 * Deinitialize embedded interpreter
 */
void embed_interpreter_deinit(void);


#endif

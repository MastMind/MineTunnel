#ifndef EMBED_COMMANDS_H
#define EMBED_COMMANDS_H

#include "embed_commands_impl.h"
#include "defines.h"


typedef struct command_s {
    char name[MAX_STR_LENGTH];
    int (*callback_func)(CMD_ARGS);
} command;

extern const command shell_commands[];


#endif

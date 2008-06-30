#ifndef __COMMANDS_H
#define __COMMANDS_H

struct client_command_context;

#include "managesieve-parser.h"

typedef bool command_func_t(struct client_command_context *cmd);

struct command {
	const char *name;
	command_func_t *func;
};

/* Register command. Given name parameter must be permanently stored until
   command is unregistered. */
void command_register(const char *name, command_func_t *func);
void command_unregister(const char *name);

/* Register array of commands. */
void command_register_array(const struct command *cmdarr, unsigned int count);
void command_unregister_array(const struct command *cmdarr, unsigned int count);

struct command *command_find(const char *name);

void commands_init(void);
void commands_deinit(void);

/* MANAGESIEVE commands: */

/* Non-Authenticated State */
bool cmd_logout(struct client_command_context *cmd);

bool cmd_capability(struct client_command_context *cmd);

/* Authenticated State */
bool cmd_putscript(struct client_command_context *cmd);
bool cmd_getscript(struct client_command_context *cmd);
bool cmd_setactive(struct client_command_context *cmd);
bool cmd_deletescript(struct client_command_context *cmd);
bool cmd_listscripts(struct client_command_context *cmd);
bool cmd_havespace(struct client_command_context *cmd);


#endif

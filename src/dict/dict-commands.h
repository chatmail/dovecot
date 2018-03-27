#ifndef DICT_COMMANDS_H
#define DICT_COMMANDS_H

struct dict_connection;

struct dict_command_stats {
	struct stats_dist *lookups;
	struct stats_dist *iterations;
	struct stats_dist *commits;
};

extern struct dict_command_stats cmd_stats;

int dict_command_input(struct dict_connection *conn, const char *line);

void dict_connection_cmds_output_more(struct dict_connection *conn);

void dict_commands_init(void);
void dict_commands_deinit(void);

#endif

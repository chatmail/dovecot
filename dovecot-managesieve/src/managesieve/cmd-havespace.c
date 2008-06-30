#include "common.h"
#include "commands.h"

bool cmd_havespace(struct client_command_context *cmd)
{
  struct client *client = cmd->client;
	struct managesieve_arg *args;
	const char *scriptname;
	uoff_t size;
	int ret;

	/* <scriptname> <size> */
	if (!(ret=client_read_args(cmd, 2, 0, &args)))
	  return FALSE;

	if ( ret > 2 ) {
		client_send_no(client, "Too many arguments");
		return TRUE;
	}

	if ( (scriptname = managesieve_arg_string(&args[0])) == NULL ) {
		client_send_no(client, "Invalid string for scriptname.");
		return TRUE;
	}

	if ( managesieve_arg_number(&args[1], &size) < 0 ) {
		client_send_no(client, "Invalid scriptsize argument.");
		return TRUE;
	}

	if ( size == 0 ) {
		client_send_no(client, "Cannot upload empty script.");
		return TRUE;
	}

	client_send_ok(client, "Putscript would succeed.");
	return TRUE;
}

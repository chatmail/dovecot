#include "common.h"
#include "ostream.h"
#include "commands.h"

bool cmd_logout(struct client_command_context *cmd)
{
	struct client *client = cmd->client;

	client_send_line(client, "OK \"Logout completed.\"");
	client_disconnect(client, "Logged out");
	return TRUE;
}

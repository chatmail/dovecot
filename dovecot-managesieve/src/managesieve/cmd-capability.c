#include "common.h"
#include "commands.h"
#include "str.h"
#include "strfuncs.h"
#include "ostream.h"

#include "sieve.h"

bool cmd_capability(struct client_command_context *cmd)
{
	struct client *client = cmd->client;
	const char *sievecap, *sieveimpl;

	sievecap = sieve_get_capabilities();
	if (sievecap == NULL)
		sievecap = "";

	t_push();		
	sievecap = t_strconcat("\"SIEVE\" \"", sievecap, "\"", NULL);
  	sieveimpl = t_strconcat("\"IMPLEMENTATION\" \"", 
    managesieve_implementation_string, "\"", NULL);

	client_send_line(client, sieveimpl);
	client_send_line(client, sievecap);
	client_send_line(client, "OK \"Capability completed.\"");
	t_pop();

	return TRUE;

}


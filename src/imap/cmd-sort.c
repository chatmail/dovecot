/* Copyright (C) 2002 Timo Sirainen */

#include "common.h"
#include "buffer.h"
#include "commands.h"
#include "imap-search.h"
#include "imap-sort.h"

struct sort_name {
	enum mail_sort_type type;
	const char *name;
};

static struct sort_name sort_names[] = {
	{ MAIL_SORT_ARRIVAL,	"arrival" },
	{ MAIL_SORT_CC,		"cc" },
	{ MAIL_SORT_DATE,	"date" },
	{ MAIL_SORT_FROM,	"from" },
	{ MAIL_SORT_SIZE,	"size" },
	{ MAIL_SORT_SUBJECT,	"subject" },
	{ MAIL_SORT_TO,		"to" },

	{ MAIL_SORT_REVERSE,	"reverse" },
	{ MAIL_SORT_END,	NULL }
};

static enum mail_sort_type *
get_sort_program(struct client_command_context *cmd, struct imap_arg *args)
{
	enum mail_sort_type type;
	buffer_t *buf;
	int i;

	if (args->type == IMAP_ARG_EOL) {
		/* empyty list */
		client_send_command_error(cmd, "Empty sort program.");
		return NULL;
	}

	buf = buffer_create_dynamic(pool_datastack_create(),
				    32 * sizeof(enum mail_sort_type));

	while (args->type == IMAP_ARG_ATOM || args->type == IMAP_ARG_STRING) {
		const char *arg = IMAP_ARG_STR(args);

		for (i = 0; sort_names[i].type != MAIL_SORT_END; i++) {
			if (strcasecmp(arg, sort_names[i].name) == 0)
				break;
		}

		if (sort_names[i].type == MAIL_SORT_END) {
			client_send_command_error(cmd, t_strconcat(
				"Unknown sort argument: ", arg, NULL));
			return NULL;
		}

		buffer_append(buf, &sort_names[i].type,
			      sizeof(enum mail_sort_type));
		args++;
	}

	type = MAIL_SORT_END;
	buffer_append(buf, &type, sizeof(type));

	if (args->type != IMAP_ARG_EOL) {
		client_send_command_error(cmd,
					  "Invalid sort list argument.");
		return NULL;
	}

	return buffer_free_without_data(buf);
}

bool cmd_sort(struct client_command_context *cmd)
{
	struct client *client = cmd->client;
	struct mail_search_arg *sargs;
	enum mail_sort_type *sorting;
	struct imap_arg *args;
	int args_count;
	pool_t pool;
	const char *error, *charset;

	args_count = imap_parser_read_args(client->parser, 0, 0, &args);
	if (args_count == -2)
		return FALSE;

	if (args_count < 3) {
		client_send_command_error(cmd, args_count < 0 ? NULL :
					  "Missing or invalid arguments.");
		return TRUE;
	}

	if (!client_verify_open_mailbox(cmd))
		return TRUE;

	/* sort program */
	if (args->type != IMAP_ARG_LIST) {
		client_send_command_error(cmd, "Invalid sort argument.");
		return TRUE;
	}

	sorting = get_sort_program(cmd, IMAP_ARG_LIST(args)->args);
	if (sorting == NULL)
		return TRUE;
	args++;

	/* charset */
	if (args->type != IMAP_ARG_ATOM && args->type != IMAP_ARG_STRING) {
		client_send_command_error(cmd,
					  "Invalid charset argument.");
		return TRUE;
	}
	charset = IMAP_ARG_STR(args);
	args++;

	pool = pool_alloconly_create("mail_search_args", 2048);

	sargs = imap_search_args_build(pool, client->mailbox, args, &error);
	if (sargs == NULL) {
		/* error in search arguments */
		client_send_tagline(cmd, t_strconcat("NO ", error, NULL));
	} else if (imap_sort(cmd, charset, sargs, sorting) == 0) {
		pool_unref(pool);
		return cmd_sync(cmd, MAILBOX_SYNC_FLAG_FAST |
				(cmd->uid ? 0 : MAILBOX_SYNC_FLAG_NO_EXPUNGES),
				0, "OK Sort completed.");
	} else {
		client_send_storage_error(cmd,
					  mailbox_get_storage(client->mailbox));
	}

	pool_unref(pool);
	return TRUE;
}

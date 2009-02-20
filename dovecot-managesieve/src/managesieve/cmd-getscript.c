#include "common.h"
#include "ostream.h"
#include "commands.h"
#include "istream.h"

#include "sieve-storage-script.h"

struct cmd_getscript_context {
	struct client *client;
	struct client_command_context *cmd;
	struct sieve_storage *storage;	
	uoff_t scriptsize;

	struct sieve_script *script;
	struct istream *scriptstream;
	bool failed;
	bool exists;
};

static bool cmd_getscript_finish(struct cmd_getscript_context *ctx)
{
  struct client *client = ctx->client;

	if (ctx->script != NULL)
		sieve_script_unref(&ctx->script);

	if (ctx->failed) {
		if (client->output->closed) {
			client_disconnect(client, "Disconnected");
			return TRUE;
		}

		if (!ctx->exists) {
			client_send_no(client, "Script does not exist.");
			return TRUE;
		}
		
		client_send_storage_error(client, client->storage);
		return TRUE;
	}

	client_send_line(client, "");
	client_send_ok(client, "Getscript completed.");
	return TRUE;
}

static bool cmd_getscript_continue(struct client_command_context *cmd)
{
	struct client *client = cmd->client;
	struct cmd_getscript_context *ctx = cmd->context;

	if (o_stream_send_istream(client->output, ctx->scriptstream) < 0) {
		sieve_storage_set_critical(ctx->storage,
			"o_stream_send_istream(%s) failed: %m", sieve_script_filename(ctx->script));
		ctx->failed = TRUE;    
	}

	/* FIXME: Check whether there is a bug in the io_stream_sendfile function
	 * as the eof indicator of the input stream is never set. The stream_sendfile
	 * function does not use read functions of the inputstream and therefore
	 * the eof indicator will not be updated. Workaround: check v_offset == size 
	 * as well.
	 */
	if (ctx->scriptstream->eof || ctx->scriptstream->closed ||
		ctx->scriptstream->v_offset == ctx->scriptsize ) {
		if (client->output->closed || ctx->scriptstream->v_offset < ctx->scriptsize) 
			ctx->failed = TRUE;
	} else if (!ctx->failed) 
		/* unfinished */
		return FALSE;

	return cmd_getscript_finish(ctx);
}

bool cmd_getscript(struct client_command_context *cmd)
{
	struct client *client = cmd->client;
	struct cmd_getscript_context *ctx;
	const char *scriptname;
	bool deleted_r;

	/* <scriptname> */
	if (!client_read_string_args(cmd, 1, &scriptname))
		return FALSE;

	ctx = p_new(cmd->pool, struct cmd_getscript_context, 1);
	ctx->cmd = cmd;
	ctx->client = client;
	ctx->storage = client->storage;
	ctx->failed = FALSE;
	
	ctx->exists = TRUE;
	ctx->script = sieve_storage_script_init(client->storage, scriptname, &ctx->exists);

	if (ctx->script == NULL) {
		ctx->failed = TRUE;
		return cmd_getscript_finish(ctx);
	}
			
	ctx->scriptstream = sieve_script_open(ctx->script, &deleted_r);

	if ( ctx->scriptstream == NULL ) {
		ctx->failed = TRUE;
		ctx->exists = !deleted_r;
		return cmd_getscript_finish(ctx);
	}

	ctx->scriptsize = sieve_script_get_size(ctx->script);

	client_send_line(client, t_strdup_printf("{%"PRIuUOFF_T"}", ctx->scriptsize));

	client->command_pending = TRUE;
	cmd->func = cmd_getscript_continue;
	cmd->context = ctx;

	return cmd_getscript_continue(cmd);
}

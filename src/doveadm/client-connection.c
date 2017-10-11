/* Copyright (c) 2010-2017 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "lib-signals.h"
#include "str.h"
#include "base64.h"
#include "ioloop.h"
#include "istream.h"
#include "ostream.h"
#include "strescape.h"
#include "process-title.h"
#include "settings-parser.h"
#include "iostream-ssl.h"
#include "ostream-multiplex.h"
#include "master-service.h"
#include "master-service-ssl.h"
#include "master-service-settings.h"
#include "mail-storage-service.h"
#include "doveadm-util.h"
#include "doveadm-server.h"
#include "doveadm-mail.h"
#include "doveadm-print.h"
#include "doveadm-settings.h"
#include "client-connection-private.h"

#include <unistd.h>

#define MAX_INBUF_SIZE (1024*1024)

static void client_connection_input(struct client_connection *conn);

static failure_callback_t *orig_error_callback, *orig_fatal_callback;
static failure_callback_t *orig_info_callback, *orig_debug_callback = NULL;

static bool log_recursing = FALSE;


static void ATTR_FORMAT(2, 0)
doveadm_server_log_handler(const struct failure_context *ctx,
			   const char *format, va_list args)
{
	if (!log_recursing && doveadm_client != NULL &&
	    doveadm_client->log_out != NULL) T_BEGIN {
		/* prevent re-entering this code if
		   any of the following code causes logging */
		log_recursing = TRUE;
		char c = doveadm_log_type_to_char(ctx->type);
		const char *ptr,*start;
		bool corked = o_stream_is_corked(doveadm_client->log_out);
		va_list va;
		va_copy(va, args);
		string_t *str = t_str_new(128);
		str_vprintfa(str, format, va);
		va_end(va);
		start = str_c(str);
		if (!corked)
			o_stream_cork(doveadm_client->log_out);
		while((ptr = strchr(start, '\n'))!=NULL) {
			o_stream_nsend(doveadm_client->log_out, &c, 1);
			o_stream_nsend(doveadm_client->log_out, start, ptr-start+1);
			str_delete(str, 0, ptr-start+1);
		}
		if (str->used > 0) {
			o_stream_nsend(doveadm_client->log_out, &c, 1);
			o_stream_nsend(doveadm_client->log_out, str->data, str->used);
			o_stream_nsend(doveadm_client->log_out, "\n", 1);
		}
		o_stream_uncork(doveadm_client->log_out);
		if (corked)
			o_stream_cork(doveadm_client->log_out);
		log_recursing = FALSE;
	} T_END;

	switch(ctx->type) {
	case LOG_TYPE_DEBUG:
		orig_debug_callback(ctx, format, args);
		break;
	case LOG_TYPE_INFO:
		orig_info_callback(ctx, format, args);
		break;
	case LOG_TYPE_WARNING:
	case LOG_TYPE_ERROR:
		orig_error_callback(ctx, format, args);
		break;
	default:
		i_unreached();
	}
}

static void doveadm_server_capture_logs(void)
{
	i_assert(orig_debug_callback == NULL);
	i_get_failure_handlers(&orig_fatal_callback, &orig_error_callback,
			       &orig_info_callback, &orig_debug_callback);
	i_set_error_handler(doveadm_server_log_handler);
	i_set_info_handler(doveadm_server_log_handler);
	i_set_debug_handler(doveadm_server_log_handler);
}

static void doveadm_server_restore_logs(void)
{
	i_assert(orig_debug_callback != NULL);
	i_set_error_handler(orig_error_callback);
	i_set_info_handler(orig_info_callback);
	i_set_debug_handler(orig_debug_callback);
	orig_fatal_callback = NULL;
	orig_error_callback = NULL;
	orig_info_callback = NULL;
	orig_debug_callback = NULL;
}

static void
doveadm_cmd_server_post(struct client_connection *conn, const char *cmd_name)
{
	const char *str = NULL;

	if (doveadm_exit_code == 0) {
		o_stream_nsend(conn->output, "\n+\n", 3);
		return;
	}

	str = doveadm_exit_code_to_str(doveadm_exit_code);

	if (str != NULL) {
		o_stream_nsend_str(conn->output,
				   t_strdup_printf("\n-%s\n", str));
	} else {
		o_stream_nsend_str(conn->output, "\n-\n");
		i_error("BUG: Command '%s' returned unknown error code %d",
			cmd_name, doveadm_exit_code);
	}
}

static void
doveadm_cmd_server_run_ver2(struct client_connection *conn,
			    int argc, const char *const argv[],
			    struct doveadm_cmd_context *cctx)
{
	i_getopt_reset();
	if (doveadm_cmd_run_ver2(argc, argv, cctx) < 0)
		doveadm_exit_code = EX_USAGE;
	doveadm_cmd_server_post(conn, cctx->cmd->name);
}

static void
doveadm_cmd_server_run(struct client_connection *conn,
		       int argc, const char *const argv[],
		       const struct doveadm_cmd *cmd)
{
	i_getopt_reset();
	cmd->cmd(argc, (char **)argv);
	doveadm_cmd_server_post(conn, cmd->name);
}

static int
doveadm_mail_cmd_server_parse(const struct doveadm_mail_cmd *cmd,
			      const struct doveadm_settings *set,
			      int argc, const char *const argv[],
			      struct doveadm_cmd_context *cctx,
			      struct doveadm_mail_cmd_context **mctx_r)
{
	struct doveadm_mail_cmd_context *mctx;
	const char *getopt_args;
	bool add_username_header = FALSE;
	int c;

	mctx = doveadm_mail_cmd_init(cmd, set);
	mctx->full_args = argv+1;
	mctx->proxying = TRUE;
	mctx->cur_username = cctx->username;
	mctx->service_flags |=
		MAIL_STORAGE_SERVICE_FLAG_NO_LOG_INIT |
		MAIL_STORAGE_SERVICE_FLAG_USERDB_LOOKUP;
	if (doveadm_debug)
		mctx->service_flags |= MAIL_STORAGE_SERVICE_FLAG_DEBUG;

	i_getopt_reset();
	getopt_args = t_strconcat("AF:S:u:", mctx->getopt_args, NULL);
	while ((c = getopt(argc, (char **)argv, getopt_args)) > 0) {
		switch (c) {
		case 'A':
		case 'F':
			add_username_header = TRUE;
			break;
		case 'S':
			/* ignore */
			break;
		case 'u':
			if (strchr(optarg, '*') != NULL ||
			    strchr(optarg, '?') != NULL)
				add_username_header = TRUE;
			break;
		default:
			if ((mctx->v.parse_arg == NULL ||
			     !mctx->v.parse_arg(mctx, c))) {
				i_error("doveadm %s: "
					"Client sent unknown parameter: %c",
					cmd->name, c);
				mctx->v.deinit(mctx);
				pool_unref(&mctx->pool);
				return -1;
			}
		}
	}

	if (argv[optind] != NULL && cmd->usage_args == NULL) {
		i_error("doveadm %s: Client sent unknown parameter: %s",
			cmd->name, argv[optind]);
		mctx->v.deinit(mctx);
		pool_unref(&mctx->pool);
		return -1;
	}
	mctx->args = argv+optind;

	if (mctx->cur_username != NULL) {
		if (strchr(mctx->cur_username, '*') != NULL ||
		    strchr(mctx->cur_username, '?') != NULL) {
			add_username_header = TRUE;
		}
	}

	if (doveadm_print_is_initialized() && add_username_header) {
		doveadm_print_header("username", "Username",
				     DOVEADM_PRINT_HEADER_FLAG_STICKY |
				     DOVEADM_PRINT_HEADER_FLAG_HIDE_TITLE);
		doveadm_print_sticky("username", cctx->username);
	}
	*mctx_r = mctx;
	return 0;
}

static void
doveadm_mail_cmd_server_run(struct client_connection *conn,
			    struct doveadm_mail_cmd_context *mctx,
			    struct doveadm_cmd_context *cctx)
{
	const char *error;
	int ret;

	mctx->conn = conn;
	o_stream_cork(conn->output);

	if (mctx->v.preinit != NULL)
		mctx->v.preinit(mctx);

	ret = doveadm_mail_single_user(mctx, cctx, &error);
	doveadm_mail_server_flush();
	mctx->v.deinit(mctx);
	doveadm_print_flush();
	mail_storage_service_deinit(&mctx->storage_service);

	if (ret < 0) {
		i_error("%s: %s", mctx->cmd->name, error);
		o_stream_nsend(conn->output, "\n-\n", 3);
	} else if (ret == 0) {
		o_stream_nsend_str(conn->output, "\n-NOUSER\n");
	} else if (mctx->exit_code != 0) {
		/* maybe not an error, but not a full success either */
		o_stream_nsend_str(conn->output,
				   t_strdup_printf("\n-%u\n", mctx->exit_code));
	} else {
		o_stream_nsend(conn->output, "\n+\n", 3);
	}
	o_stream_uncork(conn->output);
	pool_unref(&mctx->pool);
}

bool doveadm_client_is_allowed_command(const struct doveadm_settings *set,
				       const char *cmd_name)
{
	bool ret = FALSE;

	if (*set->doveadm_allowed_commands == '\0')
		return TRUE;

	T_BEGIN {
		const char *const *cmds =
			t_strsplit(set->doveadm_allowed_commands, ",");
		for (; *cmds != NULL; cmds++) {
			if (strcmp(*cmds, cmd_name) == 0) {
				ret = TRUE;
				break;
			}
		}
	} T_END;
	return ret;
}

static int doveadm_cmd_handle(struct client_connection *conn,
			      const char *cmd_name,
			      int argc, const char *const argv[],
			      struct doveadm_cmd_context *cctx)
{
	struct ioloop *ioloop, *prev_ioloop = current_ioloop;
	const struct doveadm_cmd *cmd = NULL;
	const struct doveadm_mail_cmd *mail_cmd;
	struct doveadm_mail_cmd_context *mctx;
	const struct doveadm_cmd_ver2 *cmd_ver2;

	if ((cmd_ver2 = doveadm_cmd_find_with_args_ver2(cmd_name, &argc, &argv)) == NULL) {
		mail_cmd = doveadm_mail_cmd_find(cmd_name);
		if (mail_cmd == NULL) {
			cmd = doveadm_cmd_find_with_args(cmd_name, &argc, &argv);
			if (cmd == NULL) {
				i_error("doveadm: Client sent unknown command: %s", cmd_name);
				return -1;
			}
		} else {
			if (doveadm_mail_cmd_server_parse(mail_cmd, conn->set,
							  argc, argv,
							  cctx, &mctx) < 0)
				return -1;
		}
	} else {
		cctx->cmd = cmd_ver2;
	}

	/* some commands will want to call io_loop_run(), but we're already
	   running one and we can't call the original one recursively, so
	   create a new ioloop. */
	ioloop = io_loop_create();
	lib_signals_reset_ioloop();

	if (cmd_ver2 != NULL)
		doveadm_cmd_server_run_ver2(conn, argc, argv, cctx);
	else if (cmd != NULL)
		doveadm_cmd_server_run(conn, argc, argv, cmd);
	else
		doveadm_mail_cmd_server_run(conn, mctx, cctx);

	io_loop_set_current(prev_ioloop);
	lib_signals_reset_ioloop();
	o_stream_switch_ioloop(conn->output);
	if (conn->log_out != NULL)
		o_stream_switch_ioloop(conn->log_out);
	io_loop_set_current(ioloop);
	io_loop_destroy(&ioloop);

	/* clear all headers */
	doveadm_print_deinit();
	doveadm_print_init(DOVEADM_PRINT_TYPE_SERVER);
	return doveadm_exit_code == 0 ? 0 : -1;
}

static bool client_handle_command(struct client_connection *conn, char **args)
{
	struct doveadm_cmd_context cctx;
	const char *flags, *cmd_name;
	unsigned int argc;

	for (argc = 0; args[argc] != NULL; argc++)
		args[argc] = str_tabunescape(args[argc]);

	if (argc < 3) {
		i_error("doveadm client: No command given");
		return FALSE;
	}
	i_zero(&cctx);
	cctx.cli = FALSE;
	cctx.tcp_server = TRUE;

	cctx.local_ip = conn->local_ip;
	cctx.remote_ip = conn->remote_ip;
	cctx.local_port = conn->local_port;
	cctx.remote_port = conn->remote_port;
	cctx.conn = conn;
	doveadm_exit_code = 0;

	flags = args[0];
	cctx.username = args[1];
	cmd_name = args[2];

	doveadm_debug = FALSE;
	doveadm_verbose = FALSE;

	for (; *flags != '\0'; flags++) {
		switch (*flags) {
		case 'D':
			doveadm_debug = TRUE;
			doveadm_verbose = TRUE;
			break;
		case 'v':
			doveadm_verbose = TRUE;
			break;
		default:
			i_error("doveadm client: Unknown flag: %c", *flags);
			return FALSE;
		}
	}

	if (!doveadm_client_is_allowed_command(conn->set, cmd_name)) {
		i_error("doveadm client isn't allowed to use command: %s",
			cmd_name);
		return FALSE;
	}

	client_connection_set_proctitle(conn, cmd_name);
	o_stream_cork(conn->output);
	if (doveadm_cmd_handle(conn, cmd_name, argc-2, (const char**)(args+2), &cctx) < 0)
		o_stream_nsend(conn->output, "\n-\n", 3);
	o_stream_uncork(conn->output);
	client_connection_set_proctitle(conn, "");

	/* flush the output and possibly run next command */
	net_set_nonblock(conn->fd, FALSE);
	(void)o_stream_flush(conn->output);
	net_set_nonblock(conn->fd, TRUE);
	return TRUE;
}

static int
client_connection_authenticate(struct client_connection *conn)
{
	const char *line, *pass;
	buffer_t *plain;
	const unsigned char *data;
	size_t size;

	if ((line = i_stream_read_next_line(conn->input)) == NULL) {
		if (conn->input->eof)
			return -1;
		return 0;
	}

	if (*conn->set->doveadm_password == '\0') {
		i_error("doveadm_password not set, "
			"remote authentication disabled");
		return -1;
	}

	/* FIXME: some day we should probably let auth process do this and
	   support all kinds of authentication */
	if (strncmp(line, "PLAIN\t", 6) != 0) {
		i_error("doveadm client attempted non-PLAIN authentication: %s", line);
		return -1;
	}

	plain = buffer_create_dynamic(pool_datastack_create(), 128);
	if (base64_decode(line + 6, strlen(line + 6), NULL, plain) < 0) {
		i_error("doveadm client sent invalid base64 auth PLAIN data");
		return -1;
	}
	data = plain->data;
	size = plain->used;

	if (size < 10 || data[0] != '\0' ||
	    memcmp(data+1, "doveadm", 7) != 0 || data[8] != '\0') {
		i_error("doveadm client didn't authenticate as 'doveadm'");
		return -1;
	}
	pass = t_strndup(data + 9, size - 9);
	if (strlen(pass) != strlen(conn->set->doveadm_password) ||
	    !mem_equals_timing_safe(pass, conn->set->doveadm_password,
				    strlen(pass))) {
		i_error("doveadm client authenticated with wrong password");
		return -1;
	}
	return 1;
}

static void client_log_disconnect_error(struct client_connection *conn)
{
	const char *error;

	error = conn->ssl_iostream == NULL ? NULL :
		ssl_iostream_get_last_error(conn->ssl_iostream);
	if (error == NULL) {
		error = conn->input->stream_errno == 0 ? "EOF" :
			strerror(conn->input->stream_errno);
	}
	i_error("doveadm client disconnected before handshake: %s", error);
}

static void client_connection_input(struct client_connection *conn)
{
	const char *line;
	bool ok = TRUE;
	int ret;
	unsigned int minor;

	if (!conn->handshaked) {
		if ((line = i_stream_read_next_line(conn->input)) == NULL) {
			if (conn->input->eof || conn->input->stream_errno != 0) {
				client_log_disconnect_error(conn);
				client_connection_destroy(&conn);
			}
			return;
		}
		if (!version_string_verify_full(line, "doveadm-server",
				DOVEADM_SERVER_PROTOCOL_VERSION_MAJOR, &minor)) {
			i_error("doveadm client not compatible with this server "
				"(mixed old and new binaries?)");
			client_connection_destroy(&conn);
			return;
		}
		if (minor > 0) {
			/* send version reply */
			o_stream_nsend_str(conn->output,
					   DOVEADM_CLIENT_PROTOCOL_VERSION_LINE"\n");
			conn->use_multiplex = TRUE;
		}
		conn->handshaked = TRUE;
	}
	if (!conn->authenticated) {
		if ((ret = client_connection_authenticate(conn)) <= 0) {
			if (ret < 0) {
				o_stream_nsend(conn->output, "-\n", 2);
				client_connection_destroy(&conn);
			}
			return;
		}
		o_stream_nsend(conn->output, "+\n", 2);
		conn->authenticated = TRUE;
	}

	if (!conn->io_setup) {
		conn->io_setup = TRUE;
                if (conn->use_multiplex) {
                        struct ostream *os = conn->output;
                        conn->output = o_stream_create_multiplex(os, (size_t)-1);
                        o_stream_set_name(conn->output, o_stream_get_name(os));
                        o_stream_set_no_error_handling(conn->output, TRUE);
                        o_stream_unref(&os);
                        conn->log_out =
                                o_stream_multiplex_add_channel(conn->output,
                                                               DOVEADM_LOG_CHANNEL_ID);
                        o_stream_set_no_error_handling(conn->log_out, TRUE);
                        o_stream_set_name(conn->log_out, t_strdup_printf("%s (log)",
                                          o_stream_get_name(conn->output)));
                        doveadm_server_capture_logs();
                }
		doveadm_print_ostream = conn->output;
	}

	while (ok && !conn->input->closed &&
	       (line = i_stream_read_next_line(conn->input)) != NULL) {
		T_BEGIN {
			char **args;

			args = p_strsplit(pool_datastack_create(), line, "\t");
			ok = client_handle_command(conn, args);
		} T_END;
	}
	if (conn->input->eof || conn->input->stream_errno != 0 || !ok)
		client_connection_destroy(&conn);
}

static int client_connection_read_settings(struct client_connection *conn)
{
	const struct setting_parser_info *set_roots[] = {
		&doveadm_setting_parser_info,
		NULL
	};
	struct master_service_settings_input input;
	struct master_service_settings_output output;
	const char *error;
	void *set;

	i_zero(&input);
	input.roots = set_roots;
	input.service = "doveadm";
	input.local_ip = conn->local_ip;
	input.remote_ip = conn->remote_ip;

	if (master_service_settings_read(master_service, &input,
					 &output, &error) < 0) {
		i_error("Error reading configuration: %s", error);
		return -1;
	}
	set = master_service_settings_get_others(master_service)[0];
	conn->set = settings_dup(&doveadm_setting_parser_info, set, conn->pool);
	return 0;
}

static int client_connection_init_ssl(struct client_connection *conn)
{
	const char *error;

	if (master_service_ssl_init(master_service,
				    &conn->input, &conn->output,
				    &conn->ssl_iostream, &error) < 0) {
		i_error("SSL init failed: %s", error);
		return -1;
	}
	if (ssl_iostream_handshake(conn->ssl_iostream) < 0) {
		i_error("SSL handshake failed: %s",
			ssl_iostream_get_last_error(conn->ssl_iostream));
		return -1;
	}
	return 0;
}

static void
client_connection_send_auth_handshake(struct client_connection *
				      conn, int listen_fd)
{
	const char *listen_path;
	struct stat st;

	/* we'll have to do this with stat(), because at least in Linux
	   fstat() always returns mode as 0777 */
	if (net_getunixname(listen_fd, &listen_path) == 0 &&
	    stat(listen_path, &st) == 0 && S_ISSOCK(st.st_mode) &&
	    (st.st_mode & 0777) == 0600) {
		/* no need for client to authenticate */
		conn->authenticated = TRUE;
		o_stream_nsend(conn->output, "+\n", 2);
	} else {
		o_stream_nsend(conn->output, "-\n", 2);
	}
}

int client_connection_init(struct client_connection *conn, int fd)
{
	const char *ip;

	conn->fd = fd;

	(void)net_getsockname(fd, &conn->local_ip, &conn->local_port);
	(void)net_getpeername(fd, &conn->remote_ip, &conn->remote_port);

	ip = net_ip2addr(&conn->remote_ip);
	if (ip[0] != '\0')
		i_set_failure_prefix("doveadm(%s): ", ip);

	if (client_connection_read_settings(conn) < 0) {
		client_connection_destroy(&conn);
		return -1;
	}
	return 0;
}

struct client_connection *
client_connection_create(int fd, int listen_fd, bool ssl)
{
	struct client_connection *conn;
	pool_t pool;

	pool = pool_alloconly_create("doveadm client", 1024*16);
	conn = p_new(pool, struct client_connection, 1);
	conn->pool = pool;

	if (client_connection_init(conn, fd) < 0)
		return NULL;
        doveadm_print_init(DOVEADM_PRINT_TYPE_SERVER);

	conn->name = conn->remote_ip.family == 0 ? "<local>" :
		p_strdup(pool, net_ip2addr(&conn->remote_ip));
	conn->io = io_add(fd, IO_READ, client_connection_input, conn);
	conn->input = i_stream_create_fd(fd, MAX_INBUF_SIZE, FALSE);
	conn->output = o_stream_create_fd(fd, (size_t)-1, FALSE);
	i_stream_set_name(conn->input, conn->name);
	o_stream_set_name(conn->output, conn->name);
	o_stream_set_no_error_handling(conn->output, TRUE);

	if (ssl) {
		if (client_connection_init_ssl(conn) < 0) {
			client_connection_destroy(&conn);
			return NULL;
		}
	}
	client_connection_send_auth_handshake(conn, listen_fd);
	client_connection_set_proctitle(conn, "");

	return conn;
}

void client_connection_destroy(struct client_connection **_conn)
{
	struct client_connection *conn = *_conn;

	*_conn = NULL;

	doveadm_print_deinit();

	if (conn->ssl_iostream != NULL)
		ssl_iostream_destroy(&conn->ssl_iostream);

	if (conn->output != NULL)
		o_stream_destroy(&conn->output);

	if (conn->io != NULL) {
		io_remove(&conn->io);
	}

	if (conn->input != NULL) {
		i_stream_destroy(&conn->input);
	}
	if (conn->log_out != NULL) {
		doveadm_server_restore_logs();
		o_stream_unref(&conn->log_out);
	}

	if (conn->fd > 0 && close(conn->fd) < 0)
		i_error("close(client) failed: %m");
	pool_unref(&conn->pool);

	doveadm_print_ostream = NULL;
	doveadm_client = NULL;
	master_service_client_connection_destroyed(master_service);

	if (doveadm_verbose_proctitle)
		process_title_set("[idling]");
}

void client_connection_set_proctitle(struct client_connection *conn,
				     const char *text)
{
	const char *str;

	if (!doveadm_verbose_proctitle)
		return;

	if (text[0] == '\0')
		str = t_strdup_printf("[%s]", conn->name);
	else
		str = t_strdup_printf("[%s %s]", conn->name, text);
	process_title_set(str);
}

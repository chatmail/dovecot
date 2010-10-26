/* Copyright (c) 2002-2010 Dovecot authors, see the included COPYING file */

#include "common.h"
#include "ioloop.h"
#include "file-lock.h"
#include "network.h"
#include "lib-signals.h"
#include "restrict-access.h"
#include "fd-close-on-exec.h"
#include "base64.h"
#include "buffer.h"
#include "istream.h"
#include "process-title.h"
#include "module-dir.h"
#include "var-expand.h"
#include "dict.h"
#include "mail-storage.h"
#include "mail-namespace.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <syslog.h>

#define IS_STANDALONE() \
        (getenv("LOGGED_IN") == NULL)

struct client_workaround_list {
	const char *name;
	enum client_workarounds num;
};

static struct client_workaround_list client_workaround_list[] = {
	{ "outlook-no-nuls", WORKAROUND_OUTLOOK_NO_NULS },
	{ "oe-ns-eoh", WORKAROUND_OE_NS_EOH },
	{ NULL, 0 }
};

struct ioloop *ioloop;

void (*hook_client_created)(struct client **client) = NULL;

static struct module *modules = NULL;
static char log_prefix[128]; /* syslog() needs this to be permanent */
static struct io *log_io = NULL;

enum client_workarounds client_workarounds = 0;
bool enable_last_command = FALSE;
bool no_flag_updates = FALSE;
bool reuse_xuidl = FALSE;
bool save_uidl = FALSE;
bool lock_session = FALSE;
const char *uidl_format, *logout_format;
enum uidl_keys uidl_keymask;

static void sig_die(const siginfo_t *si, void *context ATTR_UNUSED)
{
	/* warn about being killed because of some signal, except SIGINT (^C)
	   which is too common at least while testing :) */
	if (si->si_signo != SIGINT) {
		i_warning("Killed with signal %d (by pid=%s uid=%s code=%s)",
			  si->si_signo, dec2str(si->si_pid),
			  dec2str(si->si_uid),
			  lib_signal_code_to_str(si->si_signo, si->si_code));
	}
	io_loop_stop(ioloop);
}

static void log_error_callback(void *context ATTR_UNUSED)
{
	/* the log fd is closed, don't die when trying to log later */
	i_set_failure_ignore_errors(TRUE);

	io_loop_stop(ioloop);
}

static void parse_workarounds(void)
{
        struct client_workaround_list *list;
	const char *env, *const *str;

	env = getenv("POP3_CLIENT_WORKAROUNDS");
	if (env == NULL)
		return;

	for (str = t_strsplit_spaces(env, " ,"); *str != NULL; str++) {
		list = client_workaround_list;
		for (; list->name != NULL; list++) {
			if (strcasecmp(*str, list->name) == 0) {
				client_workarounds |= list->num;
				break;
			}
		}
		if (list->name == NULL)
			i_fatal("Unknown client workaround: %s", *str);
	}
}

static enum uidl_keys parse_uidl_keymask(const char *format)
{
	enum uidl_keys mask = 0;

	for (; *format != '\0'; format++) {
		if (format[0] == '%' && format[1] != '\0') {
			switch (var_get_key(++format)) {
			case 'v':
				mask |= UIDL_UIDVALIDITY;
				break;
			case 'u':
				mask |= UIDL_UID;
				break;
			case 'm':
				mask |= UIDL_MD5;
				break;
			case 'f':
				mask |= UIDL_FILE_NAME;
				break;
			}
		}
	}
	return mask;
}

static void open_logfile(void)
{
	const char *user;

	if (getenv("LOG_TO_MASTER") != NULL) {
		i_set_failure_internal();
		return;
	}

	if (getenv("LOG_PREFIX") != NULL)
		i_strocpy(log_prefix, getenv("LOG_PREFIX"), sizeof(log_prefix));
	else {
		user = getenv("USER");
		if (user == NULL) user = "??";
		if (strlen(user) >= sizeof(log_prefix)-6) {
			/* quite a long user name, cut it */
			user = t_strndup(user, sizeof(log_prefix)-6-2);
			user = t_strconcat(user, "..", NULL);
		}
		i_snprintf(log_prefix, sizeof(log_prefix), "pop3(%s): ", user);
	}

	if (getenv("USE_SYSLOG") != NULL) {
		const char *env = getenv("SYSLOG_FACILITY");
		i_set_failure_syslog(log_prefix, LOG_NDELAY,
				     env == NULL ? LOG_MAIL : atoi(env));
	} else {
		/* log to file or stderr */
		i_set_failure_file(getenv("LOGFILE"), log_prefix);
	}

	if (getenv("INFOLOGFILE") != NULL)
		i_set_info_file(getenv("INFOLOGFILE"));

	i_set_failure_timestamp_format(getenv("LOGSTAMP"));
}

static void drop_privileges(void)
{
	const char *version;

	version = getenv("DOVECOT_VERSION");
	if (version != NULL && strcmp(version, PACKAGE_VERSION) != 0) {
		i_fatal("Dovecot version mismatch: "
			"Master is v%s, pop3 is v"PACKAGE_VERSION" "
			"(if you don't care, set version_ignore=yes)", version);
	}

	/* Log file or syslog opening probably requires roots */
	open_logfile();

	/* Load the plugins before chrooting. Their init() is called later. */
	if (getenv("MAIL_PLUGINS") != NULL) {
		const char *plugin_dir = getenv("MAIL_PLUGIN_DIR");

		if (plugin_dir == NULL)
			plugin_dir = MODULEDIR"/pop3";
		modules = module_dir_load(plugin_dir, getenv("MAIL_PLUGINS"),
					  TRUE, version);
	}

	restrict_access_by_env(!IS_STANDALONE());
	restrict_access_allow_coredumps(TRUE);
}

static bool main_init(void)
{
	struct mail_user *user;
	struct client *client;
	const char *str;
	bool ret = TRUE;

	lib_signals_init();
        lib_signals_set_handler(SIGINT, TRUE, sig_die, NULL);
        lib_signals_set_handler(SIGTERM, TRUE, sig_die, NULL);
        lib_signals_ignore(SIGPIPE, TRUE);
        lib_signals_ignore(SIGALRM, FALSE);

	if (getenv("USER") == NULL) {
		if (getenv("DOVECOT_MASTER") == NULL)
			i_fatal("USER environment missing");
		else {
			i_fatal("login_executable setting must be pop3-login, "
				"not pop3");
		}
	}

	if (getenv("DEBUG") != NULL) {
		const char *home;

		home = getenv("HOME");
		i_info("Effective uid=%s, gid=%s, home=%s",
		       dec2str(geteuid()), dec2str(getegid()),
		       home != NULL ? home : "(none)");
	}

	if (getenv("STDERR_CLOSE_SHUTDOWN") != NULL) {
		/* If master dies, the log fd gets closed and we'll quit */
		log_io = io_add(STDERR_FILENO, IO_ERROR,
				log_error_callback, NULL);
	}

	dict_drivers_register_builtin();
	mail_users_init(getenv("AUTH_SOCKET_PATH"), getenv("DEBUG") != NULL);
        mail_storage_init();
	mail_storage_register_all();
	mailbox_list_register_all();
	clients_init();

	module_dir_init(modules);

	parse_workarounds();
	enable_last_command = getenv("POP3_ENABLE_LAST") != NULL;
	no_flag_updates = getenv("POP3_NO_FLAG_UPDATES") != NULL;
	reuse_xuidl = getenv("POP3_REUSE_XUIDL") != NULL;
	save_uidl = getenv("POP3_SAVE_UIDL") != NULL;
	lock_session = getenv("POP3_LOCK_SESSION") != NULL;

	uidl_format = getenv("POP3_UIDL_FORMAT");
	if (uidl_format == NULL || *uidl_format == '\0')
		uidl_format = "%08Xu%08Xv";
	logout_format = getenv("POP3_LOGOUT_FORMAT");
	if (logout_format == NULL)
		logout_format = "top=%t/%p, retr=%r/%b, del=%d/%m, size=%s";
	uidl_keymask = parse_uidl_keymask(uidl_format);
	if (uidl_keymask == 0)
		i_fatal("pop3_uidl_format setting doesn't contain any "
			"%% variables.");

	user = mail_user_init(getenv("USER"));
	mail_user_set_home(user, getenv("HOME"));
	if (mail_namespaces_init(user) < 0)
		i_fatal("Namespace initialization failed");

	client = client_create(0, 1, user);
	if (client == NULL)
		return FALSE;

	if (!IS_STANDALONE())
		client_send_line(client, "+OK Logged in.");

	str = getenv("CLIENT_INPUT");
	if (str != NULL) T_BEGIN {
		buffer_t *buf = t_base64_decode_str(str);
		if (buf->used > 0) {
			if (!i_stream_add_data(client->input, buf->data,
					       buf->used))
				i_panic("Couldn't add client input to stream");
			ret = client_handle_input(client);
		}
	} T_END;
	return ret;
}

static void main_deinit(void)
{
	if (log_io != NULL)
		io_remove(&log_io);
	clients_deinit();

	module_dir_unload(&modules);
	mail_storage_deinit();
	mail_users_deinit();
	dict_drivers_unregister_builtin();

	lib_signals_deinit();
	closelog();
}

int main(int argc ATTR_UNUSED, char *argv[], char *envp[])
{
#ifdef DEBUG
	if (getenv("LOGGED_IN") != NULL && getenv("GDB") == NULL)
		fd_debug_verify_leaks(3, 1024);
#endif
	if (IS_STANDALONE() && getuid() == 0 &&
	    net_getpeername(1, NULL, NULL) == 0) {
		printf("-ERR pop3 binary must not be started from "
		       "inetd, use pop3-login instead.\n");
		return 1;
	}

	/* NOTE: we start rooted, so keep the code minimal until
	   restrict_access_by_env() is called */
	lib_init();
	drop_privileges();

        process_title_init(argv, envp);
	ioloop = io_loop_create();

	if (main_init())
		io_loop_run(ioloop);
	main_deinit();

	io_loop_destroy(&ioloop);
	lib_deinit();

	return 0;
}
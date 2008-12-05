/* Copyright (c) 2006-2008 Dovecot Sieve authors, see the included AUTHORS file */

#include "common.h"
#include "ioloop.h"
#include "network.h"
#include "ostream.h"
#include "str.h"
#include "lib-signals.h"
#include "restrict-access.h"
#include "fd-close-on-exec.h"
#include "process-title.h"
#include "randgen.h"
#include "module-dir.h"
#include "dict-client.h"

#include "sieve-storage.h"
#include "sieve.h"

#include "commands.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <syslog.h>

#define IS_STANDALONE() \
        (getenv("LOGGED_IN") == NULL)

#define CRITICAL_MSG \
  "Internal error occured. Refer to server log for more information."
#define CRITICAL_MSG_STAMP CRITICAL_MSG " [%Y-%m-%d %H:%M:%S]"

struct client_workaround_list {
	const char *name;
	enum client_workarounds num;
};

struct client_workaround_list client_workaround_list[] = {
	{ NULL, 0 }
};

struct ioloop *ioloop;
unsigned int managesieve_max_line_length;
const char *managesieve_implementation_string;
enum client_workarounds client_workarounds = 0;
const char *logout_format;

static struct io *log_io = NULL;
static struct module *modules = NULL;
static char log_prefix[128]; /* syslog() needs this to be permanent */

void (*hook_client_created)(struct client **client) = NULL;

static void sig_die(int signo, void *context ATTR_UNUSED)
{
	/* warn about being killed because of some signal, except SIGINT (^C)
	   which is too common at least while testing :) */
	if (signo != SIGINT)
		i_warning("Killed with signal %d", signo);
	io_loop_stop(ioloop);
}

static void log_error_callback(void *context ATTR_UNUSED)
{
	io_loop_stop(ioloop);
}

static void parse_workarounds(void)
{
	struct client_workaround_list *list;
	const char *env, *const *str;

	env = getenv("MANAGESIEVE_CLIENT_WORKAROUNDS");
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

static void open_logfile(void)
{
	const char *user;

	if (getenv("LOG_TO_MASTER") != NULL) {
		i_set_failure_internal();
		return;
	}

 	if (getenv("LOG_PREFIX") != NULL)
		strncpy(log_prefix, getenv("LOG_PREFIX"), sizeof(log_prefix));
	else {
		user = getenv("USER");
		if (user == NULL) {
			if (IS_STANDALONE())
				user = getlogin();
			if (user == NULL)
				user = "??";
		}
		if (strlen(user) >= sizeof(log_prefix)-6) {	
			/* quite a long user name, cut it */
 			user = t_strndup(user, sizeof(log_prefix)-6-2);
			user = t_strconcat(user, "..", NULL);
		}
		i_snprintf(log_prefix, sizeof(log_prefix), "imap(%s): ", user);
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
			"Master is v%s, managesieve is v"PACKAGE_VERSION" "
			"(if you don't care, set version_ignore=yes)", version);
	}

	/* Log file or syslog opening probably requires roots */
	open_logfile();

	/* Most likely needed. Have to open /dev/urandom before possible
	   chrooting. */
	random_init();
	
	/* Load the plugins before chrooting. Their init() is called later. */
	/* FIXME: MAIL_PLUGINS is a rather odd config value for a MANAGESIEVE
	 * server 
	 */
	if (getenv("MAIL_PLUGINS") != NULL) {
		const char *plugin_dir = getenv("MAIL_PLUGIN_DIR");

		if (plugin_dir == NULL)
			plugin_dir = MODULEDIR"/managesieve";
		modules = module_dir_load(plugin_dir, getenv("MAIL_PLUGINS"),
			TRUE, version);
	}	

	restrict_access_by_env(!IS_STANDALONE());
}

static void internal_error()
{
  struct tm *tm;
  char str[256];

  tm = localtime(&ioloop_time);

  printf("BYE \"%s\"\n",
    strftime(str, sizeof(str), CRITICAL_MSG_STAMP, tm) > 0 ?
    i_strdup(str) : i_strdup(CRITICAL_MSG));
}

static void main_init(void)
{
	struct sieve_storage *storage;
	struct client *client;
	const char *user, *str, *sieve_storage, *mail;

	lib_signals_init();
	lib_signals_set_handler(SIGINT, TRUE, sig_die, NULL);
	lib_signals_set_handler(SIGTERM, TRUE, sig_die, NULL);
	lib_signals_ignore(SIGPIPE, TRUE);
	lib_signals_ignore(SIGALRM, FALSE);

	user = getenv("USER");
	if (user == NULL) {
		if (IS_STANDALONE())
			user = getlogin();
		if (user == NULL) {
			internal_error();
			i_fatal("USER environment missing");
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

	sieve_init("");
	dict_driver_register(&dict_driver_client);
	clients_init();
	commands_init();

	module_dir_init(modules);	

	/* Settings */
	str = getenv("MANAGESIEVE_MAX_LINE_LENGTH");
	managesieve_max_line_length = str != NULL ?
		(unsigned int)strtoul(str, NULL, 10) :
		DEFAULT_MANAGESIEVE_MAX_LINE_LENGTH;

	logout_format = getenv("MANAGESIEVE_LOGOUT_FORMAT");
	if (logout_format == NULL)
		logout_format = "bytes=%i/%o";

	str = getenv("MANAGESIEVE_IMPLEMENTATION_STRING");
	managesieve_implementation_string = str != NULL ?
    str : DEFAULT_MANAGESIEVE_IMPLEMENTATION_STRING;

	parse_workarounds();		

	mail = getenv("MAIL"); 
	sieve_storage = getenv("SIEVE_STORAGE");
	if ( (sieve_storage == NULL || *sieve_storage == '\0') && 
		!(mail == NULL || *mail == '\0') ) { 
		storage = sieve_storage_create_from_mail(mail, user);
	} else 
		storage = sieve_storage_create(sieve_storage, user);

	if (storage == NULL) { 
    	internal_error();

		/* failed */
		if (sieve_storage != NULL && *sieve_storage != '\0')   
			i_fatal("Failed to create sieve storage with data: %s", sieve_storage);
		else if (mail != NULL && *mail != '\0')   
			i_fatal("Failed to create sieve storage with mail-data: %s", mail);
		else {
			const char *home;
	    
			home = getenv("HOME");
			if (home == NULL) home = "not set";
	    
			i_fatal("SIEVE_STORAGE and MAIL environment missing and "
				"autodetection failed (home %s)", home);
		}
	}
	
	client = client_create(0, 1, storage);
	
	client_send_ok(client, "Logged in.");
}

static void main_deinit(void)
{
	if (log_io != NULL)
		io_remove(&log_io);
	clients_deinit();

	module_dir_unload(&modules);
	commands_deinit();
	dict_driver_unregister(&dict_driver_client);
	sieve_deinit();
	random_deinit();

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
		printf("NO \"managesieve binary must not be started from "
		       "inetd, use managesieve-login instead.\"\n");
		return 1;
	}

	/* NOTE: we start rooted, so keep the code minimal until
	   restrict_access_by_env() is called */
	lib_init();
	drop_privileges();

	process_title_init(argv, envp);
	ioloop = io_loop_create();

	main_init();
	io_loop_run(ioloop);
	main_deinit();

	io_loop_destroy(&ioloop);
	lib_deinit();

	return 0;
}

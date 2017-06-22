/* Copyright (c) 2002-2017 Dovecot authors, see the included COPYING file
 */

#ifndef PROGRAM_CLIENT_H
#define PROGRAM_CLIENT_H

#include "restrict-access.h"

struct program_client;

struct program_client_settings {
	unsigned int client_connect_timeout_msecs;
	unsigned int input_idle_timeout_msecs;
	/* initialize with
	   restrict_access_init(&set.restrict_set);
	*/
	struct restrict_access_settings restrict_set;
	const char *home;

	bool allow_root:1;
	bool debug:1;
	bool drop_stderr:1;
};

typedef void program_client_fd_callback_t(void *context, struct istream *input);
typedef void program_client_callback_t(int, void *);

struct program_client *program_client_local_create(const char *bin_path,
	const char *const *args,
	const struct program_client_settings *set);
struct program_client *program_client_remote_create(const char *socket_path,
	const char *const *args,
	const struct program_client_settings *set, bool noreply);
int program_client_create(const char *uri, const char *const *args,
			  const struct program_client_settings *set,
			  bool noreply, struct program_client **pc_r,
			  const char **error_r);

void program_client_destroy(struct program_client **_pclient);

void program_client_set_input(struct program_client *pclient,
	struct istream *input);
void program_client_set_output(struct program_client *pclient,
	struct ostream *output);

void program_client_set_output_seekable(struct program_client *pclient,
	const char *temp_prefix);
struct istream *program_client_get_output_seekable(struct program_client *pclient);

void program_client_switch_ioloop(struct program_client *pclient);

/* Program provides side-channel output through an extra fd */
void program_client_set_extra_fd(struct program_client *pclient, int fd,
	 program_client_fd_callback_t * callback, void *context);
#define program_client_set_extra_fd(pclient, fd, callback, context) \
	program_client_set_extra_fd(pclient, fd + \
		CALLBACK_TYPECHECK(callback, \
			void (*)(typeof(context), struct istream *input)), \
		(program_client_fd_callback_t *)callback, context)

void program_client_set_env(struct program_client *pclient,
	const char *name, const char *value);

/* Since script service cannot return system exit code, the exit value shall be
   -1, 0, or 1. -1 is internal error, 0 is failure and 1 is success */
int program_client_run(struct program_client *pclient);
void program_client_run_async(struct program_client *pclient, program_client_callback_t *, void*);
#define program_client_run_async(pclient, callback, context) \
	program_client_run_async(pclient, (program_client_callback_t*)callback, (char*)context + \
		CALLBACK_TYPECHECK(callback, \
			void (*)(int, typeof(context))))

#endif

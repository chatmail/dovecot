/* Copyright (c) 2001-2015 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "env-util.h"
#include "hostpid.h"
#include "ipwd.h"
#include "process-title.h"

#include <stdlib.h>
#include <unistd.h>
#include <sys/time.h>

struct atexit_callback {
	int priority;
	lib_atexit_callback_t *callback;
};

static ARRAY(struct atexit_callback) atexit_callbacks = ARRAY_INIT;

int close_keep_errno(int *fd)
{
	int ret, old_errno = errno;

	i_assert(*fd != -1);

	ret = close(*fd);
	*fd = -1;
	errno = old_errno;
	return ret;
}

void lib_atexit(lib_atexit_callback_t *callback)
{
	lib_atexit_priority(callback, 0);
}

void lib_atexit_priority(lib_atexit_callback_t *callback, int priority)
{
	struct atexit_callback *cb;
	const struct atexit_callback *callbacks;
	unsigned int i, count;

	if (!array_is_created(&atexit_callbacks))
		i_array_init(&atexit_callbacks, 8);
	else {
		/* skip if it's already added */
		callbacks = array_get(&atexit_callbacks, &count);
		for (i = count; i > 0; i--) {
			if (callbacks[i-1].callback == callback) {
				i_assert(callbacks[i-1].priority == priority);
				return;
			}
		}
	}
	cb = array_append_space(&atexit_callbacks);
	cb->priority = priority;
	cb->callback = callback;
}

static int atexit_callback_priority_cmp(const struct atexit_callback *cb1,
					const struct atexit_callback *cb2)
{
	return cb1->priority - cb2->priority;
}

void lib_atexit_run(void)
{
	const struct atexit_callback *cb;

	if (array_is_created(&atexit_callbacks)) {
		array_sort(&atexit_callbacks, atexit_callback_priority_cmp);
		array_foreach(&atexit_callbacks, cb)
			(*cb->callback)();
		array_free(&atexit_callbacks);
	}
}

void lib_init(void)
{
	struct timeval tv;

	/* standard way to get rand() return different values. */
	if (gettimeofday(&tv, NULL) < 0)
		i_fatal("gettimeofday(): %m");
	rand_set_seed((unsigned int) (tv.tv_sec ^ tv.tv_usec ^ getpid()));

	data_stack_init();
	hostpid_init();
}

void lib_deinit(void)
{
	lib_atexit_run();
	ipwd_deinit();
	hostpid_deinit();
	data_stack_deinit();
	env_deinit();
	failures_deinit();
	process_title_deinit();
}

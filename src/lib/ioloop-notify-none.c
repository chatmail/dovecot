/* Copyright (c) 2003-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop-private.h"

#ifdef IOLOOP_NOTIFY_NONE

#undef io_add_notify
enum io_notify_result
io_add_notify(const char *path ATTR_UNUSED,
	      const char *source_filename ATTR_UNUSED,
	      unsigned int source_linenum ATTR_UNUSED,
	      io_callback_t *callback ATTR_UNUSED,
	      void *context ATTR_UNUSED, struct io **io_r)
{
	*io_r = NULL;
	return IO_NOTIFY_NOSUPPORT;
}

void io_loop_notify_remove(struct io *io ATTR_UNUSED)
{
}

void io_loop_notify_handler_deinit(struct ioloop *ioloop ATTR_UNUSED)
{
}

int io_loop_extract_notify_fd(struct ioloop *ioloop ATTR_UNUSED)
{
	return -1;
}

#endif

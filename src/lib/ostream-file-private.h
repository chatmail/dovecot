#ifndef OSTREAM_FILE_PRIVATE_H
#define OSTREAM_FILE_PRIVATE_H

#include "ostream-private.h"

struct file_ostream {
	struct ostream_private ostream;

	ssize_t (*writev)(struct file_ostream *fstream,
		 const struct const_iovec *iov,
		 unsigned int iov_count);

	int fd;
	struct io *io;
	uoff_t buffer_offset;
	uoff_t real_offset;

	unsigned char *buffer; /* ring-buffer */
	size_t buffer_size, optimal_block_size;
	size_t head, tail; /* first unsent/unused byte */

	unsigned int full:1; /* if head == tail, is buffer empty or full? */
	unsigned int file:1;
	unsigned int flush_pending:1;
	unsigned int socket_cork_set:1;
	unsigned int no_socket_cork:1;
	unsigned int no_sendfile:1;
	unsigned int autoclose_fd:1;
};

struct ostream *
o_stream_create_file_common(struct file_ostream *fstream,
	int fd, size_t max_buffer_size, bool autoclose_fd);
ssize_t o_stream_file_writev(struct file_ostream *fstream,
				   const struct const_iovec *iov,
				   unsigned int iov_size);
ssize_t o_stream_file_sendv(struct ostream_private *stream,
				   const struct const_iovec *iov,
				   unsigned int iov_count);
void o_stream_file_close(struct iostream_private *stream,
				bool close_parent);

#endif

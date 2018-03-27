/* Copyright (c) 2013-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "strescape.h"
#include "net.h"
#include "eacces-error.h"
#include "ostream.h"
#include "istream-private.h"
#include "istream-ext-filter.h"

#include <unistd.h>

struct mail_filter_istream {
	struct istream_private istream;

	int fd;
	struct istream *ext_in;
	struct ostream *ext_out;
	size_t prev_ret;
};

static void
i_stream_mail_filter_close(struct iostream_private *stream, bool close_parent)
{
	struct mail_filter_istream *mstream =
		(struct mail_filter_istream *)stream;

	i_stream_destroy(&mstream->ext_in);
	o_stream_destroy(&mstream->ext_out);
	i_close_fd(&mstream->fd);
	if (close_parent)
		i_stream_close(mstream->istream.parent);
}

static ssize_t
i_stream_read_copy_from(struct istream *istream, struct istream *source)
{
	struct istream_private *stream = istream->real_stream;
	size_t pos;
	ssize_t ret;

	stream->pos -= stream->skip;
	stream->skip = 0;

	stream->buffer = i_stream_get_data(source, &pos);
	if (pos > stream->pos)
		ret = 0;
	else do {
		if ((ret = i_stream_read_memarea(source)) == -2)
			return -2;

		stream->istream.stream_errno = source->stream_errno;
		stream->istream.eof = source->eof;
		stream->buffer = i_stream_get_data(source, &pos);
		/* check again, in case the source stream had been seeked
		   backwards and the previous read() didn't get us far
		   enough. */
	} while (pos <= stream->pos && ret > 0);

	ret = pos > stream->pos ? (ssize_t)(pos - stream->pos) :
		(ret == 0 ? 0 : -1);
	stream->pos = pos;
	i_assert(ret != -1 || stream->istream.eof ||
		 stream->istream.stream_errno != 0);
	return ret;
}

static ssize_t
i_stream_mail_filter_read_once(struct mail_filter_istream *mstream)
{
	struct istream_private *stream = &mstream->istream;
	ssize_t ret;

	if (mstream->ext_out != NULL) {
		/* we haven't sent everything yet */
		switch (o_stream_send_istream(mstream->ext_out, stream->parent)) {
		case OSTREAM_SEND_ISTREAM_RESULT_FINISHED:
			o_stream_destroy(&mstream->ext_out);
			/* if we wanted to be a blocking stream,
			   from now on the rest of the reads are */
			if (stream->istream.blocking)
				net_set_nonblock(mstream->fd, FALSE);
			if (shutdown(mstream->fd, SHUT_WR) < 0)
				i_error("ext-filter: shutdown() failed: %m");
			break;
		case OSTREAM_SEND_ISTREAM_RESULT_WAIT_INPUT:
		case OSTREAM_SEND_ISTREAM_RESULT_WAIT_OUTPUT:
		case OSTREAM_SEND_ISTREAM_RESULT_ERROR_INPUT:
			break;
		case OSTREAM_SEND_ISTREAM_RESULT_ERROR_OUTPUT:
			stream->istream.stream_errno =
				mstream->ext_out->stream_errno;
			io_stream_set_error(&stream->iostream,
				"write(%s) failed: %s",
				o_stream_get_name(mstream->ext_out),
				o_stream_get_error(mstream->ext_out));
			return -1;
		}
	}

	i_stream_skip(mstream->ext_in, mstream->prev_ret);
	ret = i_stream_read_copy_from(&stream->istream, mstream->ext_in);
	mstream->prev_ret = ret < 0 ? 0 : ret;
	return ret;
}

static ssize_t i_stream_mail_filter_read(struct istream_private *stream)
{
	struct mail_filter_istream *mstream =
		(struct mail_filter_istream *)stream;
	ssize_t ret;

	if (mstream->ext_in == NULL) {
		stream->istream.stream_errno = EIO;
		return -1;
	}

	while ((ret = i_stream_mail_filter_read_once(mstream)) == 0) {
		if (!stream->istream.blocking)
			break;
	}
	if (ret == -1 && !i_stream_have_bytes_left(&stream->istream) &&
	    stream->istream.v_offset == 0) {
		/* EOF without any input -> assume the script is reporting
		   failure. pretty ugly way, but currently there's no error
		   reporting channel. */
		stream->istream.stream_errno = EIO;
	}
	return ret;
}

static int
i_stream_mail_filter_stat(struct istream_private *stream, bool exact)
{
	const struct stat *st;

	i_assert(!exact);

	if (i_stream_stat(stream->parent, exact, &st) < 0) {
		stream->istream.stream_errno = stream->parent->stream_errno;
		return -1;
	}
	stream->statbuf = *st;
	return 0;
}

static int filter_connect(struct mail_filter_istream *mstream,
			  const char *socket_path, const char *args)
{
	const char **argv;
	string_t *str;
	ssize_t ret;
	int fd;

	argv = t_strsplit(args, " ");

	if ((fd = net_connect_unix_with_retries(socket_path, 1000)) < 0) {
		if (errno == EACCES) {
			i_error("ext-filter: %s",
				eacces_error_get("net_connect_unix",
						 socket_path));
		} else {
			i_error("ext-filter: net_connect_unix(%s) failed: %m",
				socket_path);
		}
		return -1;
	}
	if (mstream->istream.istream.blocking)
		net_set_nonblock(fd, FALSE);

	mstream->fd = fd;
	mstream->ext_in =
		i_stream_create_fd(fd, mstream->istream.max_buffer_size);
	mstream->ext_out = o_stream_create_fd(fd, 0);

	str = t_str_new(256);
	str_append(str, "VERSION\tscript\t4\t0\nnoreply\n");
	for (; *argv != NULL; argv++) {
		str_append_tabescaped(str, *argv);
		str_append_c(str, '\t');
	}
	str_append_c(str, '\n');

	ret = o_stream_send(mstream->ext_out, str_data(str), str_len(str));
	if (ret < 0) {
		i_error("ext-filter: write(%s) failed: %s", socket_path,
			o_stream_get_error(mstream->ext_out));
		i_stream_mail_filter_close(&mstream->istream.iostream, FALSE);
		return -1;
	}
	i_assert((size_t)ret == str_len(str));
	return 0;
}

struct istream *
i_stream_create_ext_filter(struct istream *input, const char *socket_path,
			   const char *args)
{
	struct mail_filter_istream *mstream;

	mstream = i_new(struct mail_filter_istream, 1);
	mstream->istream.iostream.close = i_stream_mail_filter_close;
	mstream->istream.max_buffer_size = input->real_stream->max_buffer_size;
	mstream->istream.read = i_stream_mail_filter_read;
	mstream->istream.stat = i_stream_mail_filter_stat;

	mstream->istream.istream.readable_fd = FALSE;
	mstream->istream.istream.blocking = input->blocking;
	mstream->istream.istream.seekable = FALSE;

	mstream->fd = -1;
	(void)filter_connect(mstream, socket_path, args);

	return i_stream_create(&mstream->istream, input, mstream->fd, 0);
}

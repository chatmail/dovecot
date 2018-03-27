/* Copyright (c) 2007-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "buffer.h"
#include "istream-private.h"
#include "istream-concat.h"

struct concat_istream {
	struct istream_private istream;

	struct istream **input, *cur_input;
	uoff_t *input_size;
	unsigned int input_count;

	unsigned int cur_idx, unknown_size_idx;
	size_t prev_stream_left, prev_stream_skip, prev_skip;
};

static void i_stream_concat_skip(struct concat_istream *cstream);

static void i_stream_concat_close(struct iostream_private *stream,
				  bool close_parent)
{
	struct concat_istream *cstream = (struct concat_istream *)stream;
	i_assert(cstream->cur_input == cstream->input[cstream->cur_idx]);
	unsigned int i;

	if (cstream->istream.istream.stream_errno == 0) {
		/* get the parent streams to the wanted offset */
		(void)i_stream_concat_skip(cstream);
	}

	if (close_parent) {
		for (i = 0; i < cstream->input_count; i++)
			i_stream_close(cstream->input[i]);
	}
}

static void i_stream_concat_destroy(struct iostream_private *stream)
{
	struct concat_istream *cstream = (struct concat_istream *)stream;
	i_assert(cstream->cur_input == cstream->input[cstream->cur_idx]);
	unsigned int i;

	for (i = 0; i < cstream->input_count; i++)
		i_stream_unref(&cstream->input[i]);
	i_free(cstream->input);
	i_free(cstream->input_size);
	i_stream_free_buffer(&cstream->istream);
}

static void
i_stream_concat_set_max_buffer_size(struct iostream_private *stream,
				    size_t max_size)
{
	struct concat_istream *cstream = (struct concat_istream *)stream;
	i_assert(cstream->cur_input == cstream->input[cstream->cur_idx]);
	unsigned int i;

	cstream->istream.max_buffer_size = max_size;
	for (i = 0; i < cstream->input_count; i++)
		i_stream_set_max_buffer_size(cstream->input[i], max_size);
}

static void i_stream_concat_read_next(struct concat_istream *cstream)
{
	struct istream *prev_input = cstream->cur_input;
	const unsigned char *data;
	size_t data_size, size;

	i_assert(cstream->cur_input->eof);

	if (cstream->prev_stream_skip != 0) {
		i_stream_skip(cstream->input[cstream->cur_idx-1], cstream->prev_stream_skip);
		cstream->prev_stream_skip = 0;
	}

	data = i_stream_get_data(cstream->cur_input, &data_size);
	cstream->cur_idx++;
	cstream->cur_input = cstream->input[cstream->cur_idx];
	i_stream_seek(cstream->cur_input, 0);

	if (cstream->prev_stream_left > 0 || cstream->istream.pos == 0) {
		/* all the pending data is already in w_buffer */
		cstream->prev_stream_skip = data_size;
		cstream->prev_stream_left += data_size;
		i_assert(cstream->prev_stream_left ==
			 cstream->istream.pos - cstream->istream.skip);
		return;
	}
	i_assert(cstream->prev_stream_skip == 0);

	/* we already verified that the data size is less than the
	   maximum buffer size */
	cstream->istream.pos = 0;
	if (data_size > 0) {
		if (!i_stream_try_alloc(&cstream->istream, data_size, &size))
			i_unreached();
		i_assert(size >= data_size);
	}

	cstream->prev_stream_left = data_size;
	memcpy(cstream->istream.w_buffer, data, data_size);
	i_stream_skip(prev_input, data_size);
	cstream->istream.skip = 0;
	cstream->istream.pos = data_size;
}

static void i_stream_concat_skip(struct concat_istream *cstream)
{
	struct istream_private *stream = &cstream->istream;
	size_t bytes_skipped;

	i_assert(stream->skip >= cstream->prev_skip);
	bytes_skipped = stream->skip - cstream->prev_skip;

	if (cstream->prev_stream_left == 0) {
		/* no need to worry about buffers, skip everything */
	} else if (bytes_skipped < cstream->prev_stream_left) {
		/* we're still skipping inside buffer */
		cstream->prev_stream_left -= bytes_skipped;
		bytes_skipped = 0;
	} else {
		/* done with the buffer */
		i_stream_skip(cstream->input[cstream->cur_idx-1], cstream->prev_stream_skip);
		cstream->prev_stream_skip = 0;

		bytes_skipped -= cstream->prev_stream_left;
		cstream->prev_stream_left = 0;
	}
	stream->pos -= bytes_skipped;
	stream->skip -= bytes_skipped;
	stream->buffer += bytes_skipped;
	cstream->prev_skip = stream->skip;
	i_stream_skip(cstream->cur_input, bytes_skipped);
}

static ssize_t i_stream_concat_read(struct istream_private *stream)
{
	struct concat_istream *cstream = (struct concat_istream *)stream;
	i_assert(cstream->cur_input == cstream->input[cstream->cur_idx]);
	const unsigned char *data;
	size_t size, data_size, cur_data_pos, new_pos;
	size_t new_bytes_count;
	ssize_t ret;
	bool last_stream;

	i_assert(cstream->cur_input != NULL);
	i_stream_concat_skip(cstream);

	i_assert(stream->pos >= stream->skip + cstream->prev_stream_left);
	cur_data_pos = stream->pos - (stream->skip + cstream->prev_stream_left);

	data = i_stream_get_data(cstream->cur_input, &data_size);
	if (data_size > cur_data_pos)
		ret = 0;
	else {
		/* need to read more - NOTE: Can't use i_stream_read_memarea()
		   here, because our stream->buffer may point to the parent
		   istream. */
		i_assert(cur_data_pos == data_size);
		ret = i_stream_read(cstream->cur_input);
		if (ret == -2 || ret == 0)
			return ret;

		if (ret == -1 && cstream->cur_input->stream_errno != 0) {
			io_stream_set_error(&cstream->istream.iostream,
				"read(%s) failed: %s",
				i_stream_get_name(cstream->cur_input),
				i_stream_get_error(cstream->cur_input));
			stream->istream.stream_errno =
				cstream->cur_input->stream_errno;
			return -1;
		}

		/* we either read something or we're at EOF */
		last_stream = cstream->cur_idx+1 >= cstream->input_count;
		if (ret == -1 && !last_stream) {
			if (stream->pos - stream->skip >= i_stream_get_max_buffer_size(&stream->istream))
				return -2;

			i_stream_concat_read_next(cstream);
			cstream->prev_skip = stream->skip;
			return i_stream_concat_read(stream);
		}

		stream->istream.eof = cstream->cur_input->eof && last_stream;
		i_assert(ret != -1 || stream->istream.eof);
		data = i_stream_get_data(cstream->cur_input, &data_size);
	}

	if (data_size == cur_data_pos) {
		/* nothing new read - preserve the buffer as it was */
		i_assert(ret == 0 || ret == -1);
		return ret;
	}
	if (cstream->prev_stream_left == 0) {
		/* we can point directly to the current stream's buffers */
		stream->buffer = data;
		stream->pos -= stream->skip;
		stream->skip = 0;
		new_pos = data_size;
	} else {
		/* we still have some of the previous stream left. merge the
		   new data with it. */
		i_assert(data_size > cur_data_pos);
		new_bytes_count = data_size - cur_data_pos;
		if (!i_stream_try_alloc(stream, new_bytes_count, &size)) {
			stream->buffer = stream->w_buffer;
			return -2;
		}
		stream->buffer = stream->w_buffer;

		/* we'll copy all the new input to w_buffer. if we skip over
		   prev_stream_left bytes, the next read will switch to
		   pointing to cur_input's data directly. */
		if (new_bytes_count > size)
			new_bytes_count = size;
		memcpy(stream->w_buffer + stream->pos,
		       data + cur_data_pos, new_bytes_count);
		new_pos = stream->pos + new_bytes_count;
	}

	i_assert(new_pos > stream->pos);
	ret = (ssize_t)(new_pos - stream->pos);
	stream->pos = new_pos;
	cstream->prev_skip = stream->skip;
	return ret;
}

static int
find_v_offset(struct concat_istream *cstream, uoff_t *v_offset,
	      unsigned int *idx_r)
{
	const struct stat *st;
	unsigned int i;

	for (i = 0; i < cstream->input_count; i++) {
		if (*v_offset == 0) {
			/* seek to beginning of this stream */
			break;
		}
		if (i == cstream->unknown_size_idx) {
			/* we'll need to figure out this stream's size */
			if (i_stream_stat(cstream->input[i], TRUE, &st) < 0) {
				io_stream_set_error(&cstream->istream.iostream,
					"stat(%s) failed: %s",
					i_stream_get_name(cstream->input[i]),
					i_stream_get_error(cstream->input[i]));
				i_error("istream-concat: stat(%s) failed: %s",
					i_stream_get_name(cstream->input[i]),
					i_stream_get_error(cstream->input[i]));
				cstream->istream.istream.stream_errno =
					cstream->input[i]->stream_errno;
				return -1;
			}

			/* @UNSAFE */
			cstream->input_size[i] = st->st_size;
			cstream->unknown_size_idx = i + 1;
		}
		if (*v_offset < cstream->input_size[i])
			break;
		*v_offset -= cstream->input_size[i];
	}

	*idx_r = i;
	return 0;
}

static void i_stream_concat_seek(struct istream_private *stream,
				 uoff_t v_offset, bool mark ATTR_UNUSED)
{
	struct concat_istream *cstream = (struct concat_istream *)stream;
	i_assert(cstream->cur_input == cstream->input[cstream->cur_idx]);

	stream->istream.v_offset = v_offset;
	stream->skip = stream->pos = 0;
	cstream->prev_stream_left = 0;
	cstream->prev_stream_skip = 0;
	cstream->prev_skip = 0;

	if (find_v_offset(cstream, &v_offset, &cstream->cur_idx) < 0) {
		/* failed */
		stream->istream.stream_errno = EINVAL;
		return;
	}
	if (cstream->cur_idx < cstream->input_count)
		cstream->cur_input = cstream->input[cstream->cur_idx];
	else {
		/* we allow seeking to EOF, but not past it. */
		if (v_offset != 0) {
			io_stream_set_error(&cstream->istream.iostream,
				"Seeking past EOF by %"PRIuUOFF_T" bytes", v_offset);
			cstream->istream.istream.stream_errno = EINVAL;
			return;
		}
		i_assert(cstream->cur_idx > 0);
		/* Position ourselves at the EOF of the last actual stream. */
		cstream->cur_idx--;
		cstream->cur_input = cstream->input[cstream->cur_idx];
		v_offset = cstream->input_size[cstream->cur_idx];
	}
	i_stream_seek(cstream->cur_input, v_offset);
}

static int
i_stream_concat_stat(struct istream_private *stream, bool exact ATTR_UNUSED)
{
	struct concat_istream *cstream = (struct concat_istream *)stream;
	i_assert(cstream->cur_input == cstream->input[cstream->cur_idx]);
	uoff_t v_offset = (uoff_t)-1;
	unsigned int i, cur_idx;

	/* make sure we have all sizes */
	if (find_v_offset(cstream, &v_offset, &cur_idx) < 0)
		return -1;

	stream->statbuf.st_size = 0;
	for (i = 0; i < cstream->unknown_size_idx; i++)
		stream->statbuf.st_size += cstream->input_size[i];
	return 0;
}

struct istream *i_stream_create_concat(struct istream *input[])
{
	struct concat_istream *cstream;
	unsigned int count;
	size_t max_buffer_size = I_STREAM_MIN_SIZE;
	bool blocking = TRUE, seekable = TRUE;

	/* if any of the streams isn't blocking or seekable, set ourself also
	   nonblocking/nonseekable */
	for (count = 0; input[count] != NULL; count++) {
		size_t cur_max = i_stream_get_max_buffer_size(input[count]);

		if (cur_max > max_buffer_size)
			max_buffer_size = cur_max;
		if (!input[count]->blocking)
			blocking = FALSE;
		if (!input[count]->seekable)
			seekable = FALSE;
		i_stream_ref(input[count]);
	}
	i_assert(count != 0);

	cstream = i_new(struct concat_istream, 1);
	cstream->input_count = count;
	cstream->input = p_memdup(default_pool, input, sizeof(*input) * count);
	cstream->input_size = i_new(uoff_t, count);

	cstream->cur_input = cstream->input[0];
	i_stream_seek(cstream->cur_input, 0);

	cstream->istream.iostream.close = i_stream_concat_close;
	cstream->istream.iostream.destroy = i_stream_concat_destroy;
	cstream->istream.iostream.set_max_buffer_size =
		i_stream_concat_set_max_buffer_size;

	cstream->istream.max_buffer_size = max_buffer_size;
	cstream->istream.read = i_stream_concat_read;
	cstream->istream.seek = i_stream_concat_seek;
	cstream->istream.stat = i_stream_concat_stat;

	cstream->istream.istream.readable_fd = FALSE;
	cstream->istream.istream.blocking = blocking;
	cstream->istream.istream.seekable = seekable;
	return i_stream_create(&cstream->istream, NULL, -1,
			       ISTREAM_CREATE_FLAG_NOOP_SNAPSHOT);
}

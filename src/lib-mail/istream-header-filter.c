/* Copyright (c) 2003-2010 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "message-parser.h"
#include "istream-internal.h"
#include "istream-header-filter.h"

#include <stdlib.h>

struct header_filter_istream {
	struct istream_private istream;
	pool_t pool;

	struct message_header_parser_ctx *hdr_ctx;

	const char **headers;
	unsigned int headers_count;

	header_filter_callback *callback;
	void *context;

	buffer_t *hdr_buf;
	struct message_size header_size;
	uoff_t skip_count;

	unsigned int cur_line, parsed_lines;
	ARRAY_DEFINE(match_change_lines, unsigned int);

	unsigned int header_read:1;
	unsigned int seen_eoh:1;
	unsigned int header_parsed:1;
	unsigned int exclude:1;
	unsigned int crlf:1;
	unsigned int hide_body:1;
	unsigned int add_missing_eoh:1;
};

header_filter_callback *null_header_filter_callback = NULL;

static void i_stream_header_filter_destroy(struct iostream_private *stream)
{
	struct header_filter_istream *mstream =
		(struct header_filter_istream *)stream;

	if (mstream->hdr_ctx != NULL)
		message_parse_header_deinit(&mstream->hdr_ctx);
	i_stream_unref(&mstream->istream.parent);
	if (array_is_created(&mstream->match_change_lines))
		array_free(&mstream->match_change_lines);
	pool_unref(&mstream->pool);
}

static void
i_stream_header_filter_set_max_buffer_size(struct iostream_private *stream,
					   size_t max_size)
{
	struct header_filter_istream *mstream =
		(struct header_filter_istream *)stream;

	mstream->istream.max_buffer_size = max_size;
	i_stream_set_max_buffer_size(mstream->istream.parent, max_size);
}

static ssize_t
read_mixed(struct header_filter_istream *mstream, size_t body_highwater_size)
{
	const unsigned char *data;
	size_t pos;
	ssize_t ret;

	if (mstream->hide_body) {
		mstream->istream.istream.eof = TRUE;
		return -1;
	}

	data = i_stream_get_data(mstream->istream.parent, &pos);
	if (pos == body_highwater_size) {
		ret = i_stream_read(mstream->istream.parent);
		mstream->istream.istream.stream_errno =
			mstream->istream.parent->stream_errno;
		mstream->istream.istream.eof = mstream->istream.parent->eof;

		if (ret <= 0)
			return ret;

		data = i_stream_get_data(mstream->istream.parent, &pos);
	}
	i_assert(pos > body_highwater_size);
	buffer_append(mstream->hdr_buf, data + body_highwater_size,
		      pos - body_highwater_size);

	mstream->istream.buffer = buffer_get_data(mstream->hdr_buf, &pos);
	ret = (ssize_t)(pos - mstream->istream.pos - mstream->istream.skip);
	i_assert(ret > 0);
	mstream->istream.pos = pos;
	return ret;
}

static int cmp_uint(const void *p1, const void *p2)
{
	const unsigned int *i1 = p1, *i2 = p2;

	return *i1 < *i2 ? -1 :
		(*i1 > *i2 ? 1 : 0);
}

static bool match_line_changed(struct header_filter_istream *mstream)
{
	const unsigned int *lines;
	unsigned int count;

	if (!array_is_created(&mstream->match_change_lines))
		return FALSE;

	lines = array_get(&mstream->match_change_lines, &count);
	return bsearch(&mstream->cur_line, lines, count, sizeof(*lines),
		       cmp_uint) != NULL;
}

static void add_eol(struct header_filter_istream *mstream)
{
	if (mstream->crlf)
		buffer_append(mstream->hdr_buf, "\r\n", 2);
	else
		buffer_append_c(mstream->hdr_buf, '\n');
}

static ssize_t read_header(struct header_filter_istream *mstream)
{
	struct message_header_line *hdr;
	uoff_t highwater_offset;
	size_t pos;
	ssize_t ret;
	bool matched;
	int hdr_ret;

	if (mstream->hdr_ctx == NULL) {
		mstream->hdr_ctx =
			message_parse_header_init(mstream->istream.parent,
						  NULL, 0);
	}

	/* remove skipped data from hdr_buf */
	buffer_copy(mstream->hdr_buf, 0,
		    mstream->hdr_buf, mstream->istream.skip, (size_t)-1);

        mstream->istream.pos -= mstream->istream.skip;
	mstream->istream.skip = 0;
	buffer_set_used_size(mstream->hdr_buf, mstream->istream.pos);

	if (mstream->header_read) {
		highwater_offset = mstream->istream.istream.v_offset +
			(mstream->istream.pos - mstream->istream.skip);
		if (highwater_offset >= mstream->header_size.virtual_size) {
			/* we want to return mixed headers and body */
			size_t body_highwater_size = highwater_offset -
				mstream->header_size.virtual_size;
			return read_mixed(mstream, body_highwater_size);
		}
	}

	while ((hdr_ret = message_parse_header_next(mstream->hdr_ctx,
						    &hdr)) > 0) {
		mstream->cur_line++;

		if (hdr->eoh) {
			mstream->seen_eoh = TRUE;
			matched = TRUE;
			if (!mstream->header_parsed &&
			    mstream->callback != NULL) {
				mstream->callback(hdr, &matched,
						  mstream->context);
			}

			if (!matched)
				continue;

			add_eol(mstream);
			continue;
		}

		matched = mstream->headers_count == 0 ? FALSE :
			bsearch(hdr->name, mstream->headers,
				mstream->headers_count,
				sizeof(*mstream->headers),
				bsearch_strcasecmp) != NULL;
		if (mstream->callback == NULL) {
			/* nothing gets excluded */
		} else if (mstream->cur_line > mstream->parsed_lines) {
			/* first time in this line */
			bool orig_matched = matched;

			mstream->parsed_lines = mstream->cur_line;
			mstream->callback(hdr, &matched, mstream->context);
			if (matched != orig_matched) {
				i_array_init(&mstream->match_change_lines, 8);
				array_append(&mstream->match_change_lines,
					     &mstream->cur_line, 1);
			}
		} else {
			/* second time in this line. was it excluded by the
			   callback the first time? */
			if (match_line_changed(mstream))
				matched = !matched;
		}

		if (matched == mstream->exclude) {
			/* ignore */
		} else {
			if (!hdr->continued) {
				buffer_append(mstream->hdr_buf,
					      hdr->name, hdr->name_len);
				buffer_append(mstream->hdr_buf,
					      hdr->middle, hdr->middle_len);
			}
			buffer_append(mstream->hdr_buf,
				      hdr->value, hdr->value_len);
			if (!hdr->no_newline)
				add_eol(mstream);

			if (mstream->skip_count >= mstream->hdr_buf->used) {
				/* we need more */
				mstream->skip_count -= mstream->hdr_buf->used;
				buffer_set_used_size(mstream->hdr_buf, 0);
			} else {
				if (mstream->skip_count > 0) {
					mstream->istream.skip =
						mstream->skip_count;
					mstream->skip_count = 0;
				}
				break;
			}
		}
	}

	if (hdr_ret < 0) {
		if (mstream->istream.parent->stream_errno != 0) {
			mstream->istream.istream.stream_errno =
				mstream->istream.parent->stream_errno;
			mstream->istream.istream.eof =
				mstream->istream.parent->eof;
			return -1;
		}
		if (!mstream->seen_eoh && mstream->add_missing_eoh) {
			mstream->seen_eoh = TRUE;
			add_eol(mstream);
		}
	}

	/* don't copy eof here because we're only returning headers here.
	   the body will be returned in separate read() call. */
	mstream->istream.buffer = buffer_get_data(mstream->hdr_buf, &pos);
	ret = (ssize_t)(pos - mstream->istream.pos - mstream->istream.skip);
	i_assert(ret >= 0);
	mstream->istream.pos = pos;

	if (hdr_ret == 0) {
		/* need more data to finish parsing headers. we may have some
		   data already available though. */
		return ret;
	}

	if (hdr == NULL) {
		/* finished */
		message_parse_header_deinit(&mstream->hdr_ctx);
		mstream->hdr_ctx = NULL;

		if (!mstream->header_parsed && mstream->callback != NULL)
			mstream->callback(NULL, &matched, mstream->context);
		mstream->header_parsed = TRUE;
		mstream->header_read = TRUE;

		mstream->header_size.physical_size =
			mstream->istream.parent->v_offset;
		mstream->header_size.virtual_size =
			mstream->istream.istream.v_offset + pos;
	}

	if (ret == 0) {
		/* we're at the end of headers. */
		i_assert(hdr == NULL);
		i_assert(mstream->istream.istream.v_offset +
			 mstream->istream.pos ==
			 mstream->header_size.virtual_size);

		return read_header(mstream);
	}

	return ret;
}

static ssize_t i_stream_header_filter_read(struct istream_private *stream)
{
	struct header_filter_istream *mstream =
		(struct header_filter_istream *)stream;
	ssize_t ret;

	if (!mstream->header_read ||
	    stream->istream.v_offset < mstream->header_size.virtual_size) {
		ret = read_header(mstream);
		if (ret != -2 || stream->pos != stream->skip)
			return ret;
	}

	if (mstream->hide_body) {
		stream->istream.eof = TRUE;
		return -1;
	}

	i_stream_seek(stream->parent, mstream->istream.parent_start_offset +
		      stream->istream.v_offset -
		      mstream->header_size.virtual_size +
		      mstream->header_size.physical_size);
	return i_stream_read_copy_from_parent(&stream->istream);
}

static void parse_header(struct header_filter_istream *mstream)
{
	size_t pos;

	while (!mstream->header_read) {
		if (i_stream_header_filter_read(&mstream->istream) == -1)
			break;

		(void)i_stream_get_data(&mstream->istream.istream, &pos);
		i_stream_skip(&mstream->istream.istream, pos);
	}
}

static void i_stream_header_filter_seek(struct istream_private *stream,
					uoff_t v_offset, bool mark ATTR_UNUSED)
{
	struct header_filter_istream *mstream =
		(struct header_filter_istream *)stream;

	parse_header(mstream);
	stream->istream.v_offset = v_offset;
	stream->skip = stream->pos = 0;
	stream->buffer = NULL;
	buffer_set_used_size(mstream->hdr_buf, 0);

	if (mstream->hdr_ctx != NULL) {
		message_parse_header_deinit(&mstream->hdr_ctx);
		mstream->hdr_ctx = NULL;
	}

	if (v_offset < mstream->header_size.virtual_size) {
		/* seek into headers. we'll have to re-parse them, use
		   skip_count to set the wanted position */
		i_stream_seek(stream->parent, stream->parent_start_offset);
		mstream->skip_count = v_offset;
		mstream->cur_line = 0;
		mstream->header_read = FALSE;
		mstream->seen_eoh = FALSE;
	} else {
		/* body */
		v_offset += mstream->header_size.physical_size -
			mstream->header_size.virtual_size;
		i_stream_seek(stream->parent,
			      stream->parent_start_offset + v_offset);
	}
}

static void ATTR_NORETURN
i_stream_header_filter_sync(struct istream_private *stream ATTR_UNUSED)
{
	i_panic("istream-header-filter sync() not implemented");
}

static const struct stat *
i_stream_header_filter_stat(struct istream_private *stream, bool exact)
{
	struct header_filter_istream *mstream =
		(struct header_filter_istream *)stream;
	const struct stat *st;

	st = i_stream_stat(stream->parent, exact);
	if (st == NULL || st->st_size == -1 || !exact)
		return st;

	parse_header(mstream);

	stream->statbuf = *st;
	stream->statbuf.st_size -=
		(off_t)mstream->header_size.physical_size -
		(off_t)mstream->header_size.virtual_size;
	return &stream->statbuf;
}

#undef i_stream_create_header_filter
struct istream *
i_stream_create_header_filter(struct istream *input,
                              enum header_filter_flags flags,
			      const char *const *headers,
			      unsigned int headers_count,
			      header_filter_callback *callback, void *context)
{
	struct header_filter_istream *mstream;
	unsigned int i;

	i_assert((flags & (HEADER_FILTER_INCLUDE|HEADER_FILTER_EXCLUDE)) != 0);

	mstream = i_new(struct header_filter_istream, 1);
	mstream->pool = pool_alloconly_create(MEMPOOL_GROWING
					      "header filter stream", 4096);
	mstream->istream.max_buffer_size = input->real_stream->max_buffer_size;

	mstream->headers = headers_count == 0 ? NULL :
		p_new(mstream->pool, const char *, headers_count);
	for (i = 0; i < headers_count; i++) 
		mstream->headers[i] = p_strdup(mstream->pool, headers[i]);
	mstream->headers_count = headers_count;
	mstream->hdr_buf = buffer_create_dynamic(mstream->pool, 1024);

	mstream->callback = callback;
	mstream->context = context;
	mstream->exclude = (flags & HEADER_FILTER_EXCLUDE) != 0;
	mstream->crlf = (flags & HEADER_FILTER_NO_CR) == 0;
	mstream->hide_body = (flags & HEADER_FILTER_HIDE_BODY) != 0;
	mstream->add_missing_eoh = (flags & HEADER_FILTER_ADD_MISSING_EOH) != 0;

	mstream->istream.iostream.destroy = i_stream_header_filter_destroy;
	mstream->istream.iostream.set_max_buffer_size =
		i_stream_header_filter_set_max_buffer_size;

	mstream->istream.read = i_stream_header_filter_read;
	mstream->istream.seek = i_stream_header_filter_seek;
	mstream->istream.sync = i_stream_header_filter_sync;
	mstream->istream.stat = i_stream_header_filter_stat;

	mstream->istream.istream.readable_fd = FALSE;
	mstream->istream.istream.blocking = input->blocking;
	mstream->istream.istream.seekable = input->seekable;

	i_stream_ref(input);
	return i_stream_create(&mstream->istream, input, -1);
}
/* Copyright (c) 2017-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "array.h"
#include "ostream-private.h"
#include "ostream-multiplex.h"

/* all multiplex packets are [1 byte cid][4 byte length][data] */

struct multiplex_ostream;

struct multiplex_ochannel {
	struct ostream_private ostream;
	struct multiplex_ostream *mstream;
	uint8_t cid;
	buffer_t *buf;
	uint64_t last_sent_counter;
	bool closed:1;
	bool corked:1;
};

struct multiplex_ostream {
	struct ostream *parent;

	stream_flush_callback_t *old_flush_callback;
	void *old_flush_context;

	/* channel 0 is main channel */
	uint8_t cur_channel;
	unsigned int remain;
	size_t bufsize;
	uint64_t send_counter;
	ARRAY(struct multiplex_ochannel *) channels;

	bool destroyed:1;
};

static struct multiplex_ochannel *
get_channel(struct multiplex_ostream *mstream, uint8_t cid)
{
	struct multiplex_ochannel **channelp;
	i_assert(mstream != NULL);
	array_foreach_modifiable(&mstream->channels, channelp) {
		if (*channelp != NULL && (*channelp)->cid == cid)
			return *channelp;
	}
	return NULL;
}

static void propagate_error(struct multiplex_ostream *mstream, int stream_errno)
{
	struct multiplex_ochannel **channelp;
	array_foreach_modifiable(&mstream->channels, channelp)
		if (*channelp != NULL)
			(*channelp)->ostream.ostream.stream_errno = stream_errno;
}

static struct multiplex_ochannel *get_next_channel(struct multiplex_ostream *mstream)
{
	struct multiplex_ochannel *channel = NULL;
	struct multiplex_ochannel **channelp;
	uint64_t last_counter = mstream->send_counter;

	array_foreach_modifiable(&mstream->channels, channelp) {
		if (*channelp != NULL &&
		   (*channelp)->last_sent_counter <= last_counter &&
		    (*channelp)->buf->used > 0) {
			last_counter = (*channelp)->last_sent_counter;
			channel = *channelp;
		}
	}
	return channel;
}

static bool
o_stream_multiplex_sendv(struct multiplex_ostream *mstream)
{
	struct multiplex_ochannel *channel;
	ssize_t ret = 0;
	bool all_sent = TRUE;

	while((channel = get_next_channel(mstream)) != NULL) {
		if (channel->buf->used == 0)
			continue;
		if (o_stream_get_buffer_avail_size(mstream->parent) < 6) {
			all_sent = FALSE;
			break;
		}
		/* check parent stream capacity */
		size_t tmp = o_stream_get_buffer_avail_size(mstream->parent) - 5;
		/* ensure it fits into 32 bit int */
		size_t amt = I_MIN(UINT_MAX, I_MIN(tmp, channel->buf->used));
		/* ensure amt fits */
		if (tmp == 0)
			break;
		/* delay corking here now that we are going to send something */
		if (!o_stream_is_corked(mstream->parent))
			o_stream_cork(mstream->parent);
		uint32_t len = cpu32_to_be(amt);
		const struct const_iovec vec[] = {
			{ &channel->cid, 1 },
			{ &len, 4 },
			{ channel->buf->data, amt }
		};
		if ((ret = o_stream_sendv(mstream->parent, vec, N_ELEMENTS(vec))) < 0) {
			propagate_error(mstream, mstream->parent->stream_errno);
			break;
		}
		i_assert((size_t)ret == 1 + 4 + amt);
		buffer_delete(channel->buf, 0, amt);
		channel->last_sent_counter = ++mstream->send_counter;
	}
	if (o_stream_is_corked(mstream->parent))
		o_stream_uncork(mstream->parent);
	return all_sent;
}

static int o_stream_multiplex_flush(struct multiplex_ostream *mstream)
{
	int ret = o_stream_flush(mstream->parent);
	if (ret >= 0) {
		if (!o_stream_multiplex_sendv(mstream))
			ret = 0;
	}
	if (ret <= 0)
		return ret;

	/* Everything is flushed. See if one of the callbacks' flush callbacks
	   wants to write more data. */
	struct multiplex_ochannel **channelp;
	bool unfinished = FALSE;
	array_foreach_modifiable(&mstream->channels, channelp) {
		if (*channelp != NULL && (*channelp)->ostream.callback != NULL) {
			ret = (*channelp)->ostream.callback((*channelp)->ostream.context);
			if (ret < 0)
				return -1;
			if (ret == 0)
				unfinished = TRUE;
		}
	}
	return unfinished ? 0 : 1;
}

static int o_stream_multiplex_ochannel_flush(struct ostream_private *stream)
{
	ssize_t ret;
	struct multiplex_ochannel *channel =
		container_of(stream, struct multiplex_ochannel, ostream);
	struct multiplex_ostream *mstream = channel->mstream;

	/* flush parent stream always, so there is room for more. */
	if ((ret = o_stream_flush(mstream->parent)) <= 0) {
		if (ret == -1)
			propagate_error(mstream, mstream->parent->stream_errno);
		return ret;
	}

	/* send all channels */
	o_stream_multiplex_sendv(mstream);

	if (channel->buf->used > 0)
		return 0;
	return 1;
}

static void o_stream_multiplex_ochannel_cork(struct ostream_private *stream, bool set)
{
	struct multiplex_ochannel *channel =
		container_of(stream, struct multiplex_ochannel, ostream);
	if (channel->corked != set && !set) {
		/* flush */
		(void)o_stream_multiplex_ochannel_flush(stream);
	}
	channel->corked = set;
}

static ssize_t
o_stream_multiplex_ochannel_sendv(struct ostream_private *stream,
				 const struct const_iovec *iov, unsigned int iov_count)
{
	struct multiplex_ochannel *channel =
		container_of(stream, struct multiplex_ochannel, ostream);
	size_t total = 0, avail = o_stream_get_buffer_avail_size(&stream->ostream);
	size_t optimal_size = I_MIN(IO_BLOCK_SIZE, avail);

	for (unsigned int i = 0; i < iov_count; i++)
		total += iov[i].iov_len;

	if (avail < total) {
		o_stream_multiplex_sendv(channel->mstream);
		avail = o_stream_get_buffer_avail_size(&stream->ostream);
		if (avail == 0)
			return 0;
	}

	total = 0;

	for (unsigned int i = 0; i < iov_count; i++) {
		/* copy data to buffer */
		size_t tmp = avail - total;
		if (tmp == 0)
			break;
		buffer_append(channel->buf, iov[i].iov_base,
			      I_MIN(tmp, iov[i].iov_len));
		total += I_MIN(tmp, iov[i].iov_len);
	}

	stream->ostream.offset += total;

	/* will send later */
	if (channel->corked && channel->buf->used < optimal_size)
		return total;

	o_stream_multiplex_sendv(channel->mstream);
	return total;
}

static void
o_stream_multiplex_ochannel_set_flush_callback(struct ostream_private *stream,
					       stream_flush_callback_t *callback,
					       void *context)
{
	/* We have overwritten our parent's flush-callback. Don't change it. */
	stream->callback = callback;
	stream->context = context;
}

static size_t
o_stream_multiplex_ochannel_get_buffer_used_size(const struct ostream_private *stream)
{
	const struct multiplex_ochannel *channel =
		container_of(stream, const struct multiplex_ochannel, ostream);

	return channel->buf->used +
		o_stream_get_buffer_used_size(channel->mstream->parent);
}

static size_t
o_stream_multiplex_ochannel_get_buffer_avail_size(const struct ostream_private *stream)
{
	const struct multiplex_ochannel *channel =
		container_of(stream, const struct multiplex_ochannel, ostream);
	size_t max_avail = I_MIN(channel->mstream->bufsize,
				 o_stream_get_buffer_avail_size(stream->parent));

	/* There is 5-byte overhead per message, so take that into account */
	return max_avail <= (channel->buf->used + 5) ? 0 :
		max_avail - (channel->buf->used + 5);
}

static void
o_stream_multiplex_ochannel_close(struct iostream_private *stream, bool close_parent)
{
	struct multiplex_ochannel *const *channelp;
	struct multiplex_ochannel *channel =
		container_of(stream, struct multiplex_ochannel, ostream.iostream);

	channel->closed = TRUE;
	if (close_parent) {
		array_foreach(&channel->mstream->channels, channelp)
			if (*channelp !=NULL && !(*channelp)->closed)
				return;
		o_stream_close(channel->mstream->parent);
	}
}

static void o_stream_multiplex_try_destroy(struct multiplex_ostream *mstream)
{
	struct multiplex_ochannel **channelp;
	/* can't do anything until they are all closed */
	array_foreach_modifiable(&mstream->channels, channelp)
		if (*channelp != NULL)
			return;

	i_assert(mstream->parent->real_stream->callback ==
		 (stream_flush_callback_t *)o_stream_multiplex_flush);
	o_stream_set_flush_callback(mstream->parent,
				    *mstream->old_flush_callback,
				    mstream->old_flush_context);
	o_stream_unref(&mstream->parent);
	array_free(&mstream->channels);
	i_free(mstream);
}

static void o_stream_multiplex_ochannel_destroy(struct iostream_private *stream)
{
	struct multiplex_ochannel **channelp;
	struct multiplex_ochannel *channel =
		container_of(stream, struct multiplex_ochannel, ostream.iostream);
	o_stream_unref(&channel->ostream.parent);
	if (channel->buf != NULL)
		buffer_free(&channel->buf);
	/* delete the channel */
	array_foreach_modifiable(&channel->mstream->channels, channelp) {
		if (*channelp != NULL && (*channelp)->cid == channel->cid) {
			*channelp = NULL;
			break;
		}
	}
	o_stream_multiplex_try_destroy(channel->mstream);
}

static struct ostream *
o_stream_add_channel_real(struct multiplex_ostream *mstream, uint8_t cid)
{
	struct multiplex_ochannel *channel = i_new(struct multiplex_ochannel, 1);
	channel->cid = cid;
	channel->buf = buffer_create_dynamic(default_pool, 256);
	channel->mstream = mstream;
	channel->ostream.cork = o_stream_multiplex_ochannel_cork;
	channel->ostream.flush = o_stream_multiplex_ochannel_flush;
	channel->ostream.sendv = o_stream_multiplex_ochannel_sendv;
	channel->ostream.set_flush_callback =
		o_stream_multiplex_ochannel_set_flush_callback;
	channel->ostream.get_buffer_used_size =
		o_stream_multiplex_ochannel_get_buffer_used_size;
	channel->ostream.get_buffer_avail_size =
		o_stream_multiplex_ochannel_get_buffer_avail_size;
	channel->ostream.iostream.close = o_stream_multiplex_ochannel_close;
	channel->ostream.iostream.destroy = o_stream_multiplex_ochannel_destroy;
	channel->ostream.fd = o_stream_get_fd(mstream->parent);
	array_push_back(&channel->mstream->channels, &channel);

	(void)o_stream_create(&channel->ostream, mstream->parent, -1);
	/* o_stream_create() defaults the flush_callback to parent's callback.
	   Here it points to o_stream_multiplex_flush(), which just causes
	   infinite looping. */
	channel->ostream.callback = NULL;
	channel->ostream.context = NULL;
	return &channel->ostream.ostream;
}

struct ostream *o_stream_multiplex_add_channel(struct ostream *stream, uint8_t cid)
{
	struct multiplex_ochannel *chan =
		container_of(stream->real_stream, struct multiplex_ochannel,
			     ostream);
	i_assert(get_channel(chan->mstream, cid) == NULL);

	return o_stream_add_channel_real(chan->mstream, cid);
}

struct ostream *o_stream_create_multiplex(struct ostream *parent, size_t bufsize)
{
	struct multiplex_ostream *mstream;

	mstream = i_new(struct multiplex_ostream, 1);
	mstream->parent = parent;
	mstream->bufsize = bufsize;
	mstream->old_flush_callback = parent->real_stream->callback;
	mstream->old_flush_context = parent->real_stream->context;
	o_stream_set_flush_callback(parent, o_stream_multiplex_flush, mstream);
	i_array_init(&mstream->channels, 8);
	o_stream_ref(parent);

	return o_stream_add_channel_real(mstream, 0);
}

uint8_t o_stream_multiplex_get_channel_id(struct ostream *stream)
{
	struct multiplex_ochannel *channel =
		container_of(stream->real_stream, struct multiplex_ochannel,
			     ostream);
	return channel->cid;
}

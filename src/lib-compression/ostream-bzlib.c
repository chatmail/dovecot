/* Copyright (c) 2010-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"

#ifdef HAVE_BZLIB

#include "ostream-private.h"
#include "ostream-zlib.h"
#include <bzlib.h>

#define CHUNK_SIZE (1024*64)

struct bzlib_ostream {
	struct ostream_private ostream;
	bz_stream zs;

	char outbuf[CHUNK_SIZE];
	unsigned int outbuf_offset, outbuf_used;

	bool flushed:1;
};

/* in bzlib, level is actually block size. From bzlib manual:

   The block size affects both the compression ratio achieved,
   and the amount of memory needed for compression and decompression.

   BlockSize 1 through BlockSize 9 specify the block size to be 100,000 bytes
   through 900,000 bytes respectively. The default is to use the maximum block
   size.

   Larger block sizes give rapidly diminishing marginal returns.
   Most of the compression comes from the first two or three hundred k of
   block size, a fact worth bearing in mind when using bzip2 on small machines.
   It is also important to appreciate that the decompression memory
   requirement is set at compression time by the choice of block size.

   * In general, try and use the largest block size memory constraints
     allow, since that maximises the compression achieved.
   * Compression and decompression speed are virtually unaffected by block
     size.

   Another significant point applies to files which fit in a single block -
   that means most files you'd encounter using a large block size. The
   amount of real memory touched is proportional to the size of the file,
   since the file is smaller than a block. For example, compressing a file
   20,000 bytes long with the flag BlockSize 9 will cause the compressor to
   allocate around 7600k of memory, but only touch 400k + 20000 * 8 = 560 kbytes
   of it. Similarly, the decompressor will allocate 3700k but only
   touch 100k + 20000 * 4 = 180 kbytes.
*/

int compression_get_min_level_bz2(void)
{
	return 1;
}

int compression_get_default_level_bz2(void)
{
	/* default is maximum level */
	return 9;
}

int compression_get_max_level_bz2(void)
{
	return 9;
}

static void o_stream_bzlib_close(struct iostream_private *stream,
				 bool close_parent)
{
	struct bzlib_ostream *zstream = (struct bzlib_ostream *)stream;

	(void)BZ2_bzCompressEnd(&zstream->zs);
	if (close_parent)
		o_stream_close(zstream->ostream.parent);
}

static int o_stream_zlib_send_outbuf(struct bzlib_ostream *zstream)
{
	ssize_t ret;
	size_t size;

	if (zstream->outbuf_used == 0)
		return 1;

	size = zstream->outbuf_used - zstream->outbuf_offset;
	i_assert(size > 0);
	ret = o_stream_send(zstream->ostream.parent,
			    zstream->outbuf + zstream->outbuf_offset, size);
	if (ret < 0) {
		o_stream_copy_error_from_parent(&zstream->ostream);
		return -1;
	}
	if ((size_t)ret != size) {
		zstream->outbuf_offset += ret;
		return 0;
	}
	zstream->outbuf_offset = 0;
	zstream->outbuf_used = 0;
	return 1;
}

static ssize_t
o_stream_bzlib_send_chunk(struct bzlib_ostream *zstream,
			  const void *data, size_t size)
{
	bz_stream *zs = &zstream->zs;
	int ret;

	i_assert(zstream->outbuf_used == 0);

	zs->next_in = (void *)data;
	zs->avail_in = size;
	while (zs->avail_in > 0) {
		if (zs->avail_out == 0) {
			/* previous block was compressed. send it and start
			   compression for a new block. */
			zs->next_out = zstream->outbuf;
			zs->avail_out = sizeof(zstream->outbuf);

			zstream->outbuf_used = sizeof(zstream->outbuf);
			if ((ret = o_stream_zlib_send_outbuf(zstream)) < 0)
				return -1;
			if (ret == 0) {
				/* parent stream's buffer full */
				break;
			}
		}

		switch ((ret = BZ2_bzCompress(zs, BZ_RUN))) {
		case BZ_RUN_OK:
			break;
		case BZ_MEM_ERROR:
			i_fatal_status(FATAL_OUTOFMEM, "bzip2.write(%s): Out of memory",
				       o_stream_get_name(&zstream->ostream.ostream));
		default:
			i_fatal("BZ2_bzCompress() failed with %d", ret);
		}
	}
	size -= zs->avail_in;

	zstream->flushed = FALSE;
	return size;
}

static int o_stream_bzlib_send_flush(struct bzlib_ostream *zstream, bool final)
{
	bz_stream *zs = &zstream->zs;
	size_t len;
	bool done = FALSE;
	int ret;

	i_assert(zs->avail_in == 0);

	if (zstream->flushed) {
		i_assert(zstream->outbuf_used == 0);
		return 1;
	}

	if ((ret = o_stream_flush_parent_if_needed(&zstream->ostream)) <= 0)
		return ret;
	if ((ret = o_stream_zlib_send_outbuf(zstream)) <= 0)
		return ret;

	/* do not attempt to finish the stream early */
	if (!final)
		return 1;

	i_assert(zstream->outbuf_used == 0);
	do {
		len = sizeof(zstream->outbuf) - zs->avail_out;
		if (len != 0) {
			zs->next_out = zstream->outbuf;
			zs->avail_out = sizeof(zstream->outbuf);

			zstream->outbuf_used = len;
			if ((ret = o_stream_zlib_send_outbuf(zstream)) <= 0)
				return ret;
			if (done)
				break;
		}

		ret = BZ2_bzCompress(zs, BZ_FINISH);
		switch (ret) {
		case BZ_RUN_OK:
		case BZ_FLUSH_OK:
		case BZ_STREAM_END:
			done = TRUE;
			break;
		case BZ_FINISH_OK:
			break;
                case BZ_MEM_ERROR:
                        i_fatal_status(FATAL_OUTOFMEM, "bzip2.write(%s): Out of memory",
                                       o_stream_get_name(&zstream->ostream.ostream));
                default:
                        i_fatal("BZ2_bzCompress() failed with %d", ret);
		}
	} while (zs->avail_out != sizeof(zstream->outbuf));

	if (final)
		zstream->flushed = TRUE;
	i_assert(zstream->outbuf_used == 0);
	return 1;
}

static int o_stream_bzlib_flush(struct ostream_private *stream)
{
	struct bzlib_ostream *zstream = (struct bzlib_ostream *)stream;
	int ret;
	if ((ret = o_stream_bzlib_send_flush(zstream, stream->finished)) < 0)
		return -1;
	else if (ret > 0)
		return o_stream_flush_parent(stream);
	return ret;
}

static size_t
o_stream_bzlib_get_buffer_used_size(const struct ostream_private *stream)
{
	const struct bzlib_ostream *zstream =
		(const struct bzlib_ostream *)stream;

	/* outbuf has already compressed data that we're trying to send to the
	   parent stream. We're not including bzlib's internal compression
	   buffer size. */
	return (zstream->outbuf_used - zstream->outbuf_offset) +
		o_stream_get_buffer_used_size(stream->parent);
}

static size_t
o_stream_bzlib_get_buffer_avail_size(const struct ostream_private *stream)
{
	/* FIXME: not correct - this is counting compressed size, which may be
	   too larger than uncompressed size in some situations. Fixing would
	   require some kind of additional buffering. */
	return o_stream_get_buffer_avail_size(stream->parent);
}

static ssize_t
o_stream_bzlib_sendv(struct ostream_private *stream,
		    const struct const_iovec *iov, unsigned int iov_count)
{
	struct bzlib_ostream *zstream = (struct bzlib_ostream *)stream;
	ssize_t ret, bytes = 0;
	unsigned int i;

	if ((ret = o_stream_zlib_send_outbuf(zstream)) <= 0) {
		/* error / we still couldn't flush existing data to
		   parent stream. */
		return ret;
	}

	for (i = 0; i < iov_count; i++) {
		ret = o_stream_bzlib_send_chunk(zstream, iov[i].iov_base,
						iov[i].iov_len);
		if (ret < 0)
			return -1;
		bytes += ret;
		if ((size_t)ret != iov[i].iov_len)
			break;
	}
	stream->ostream.offset += bytes;

	/* avail_in!=0 check is used to detect errors. if it's non-zero here
	   it simply means we didn't send all the data */
	zstream->zs.avail_in = 0;
	return bytes;
}

struct ostream *o_stream_create_bz2(struct ostream *output, int level)
{
	struct bzlib_ostream *zstream;
	int ret;

	i_assert(level >= 1 && level <= 9);

	zstream = i_new(struct bzlib_ostream, 1);
	zstream->ostream.sendv = o_stream_bzlib_sendv;
	zstream->ostream.flush = o_stream_bzlib_flush;
	zstream->ostream.get_buffer_used_size =
		o_stream_bzlib_get_buffer_used_size;
	zstream->ostream.get_buffer_avail_size =
		o_stream_bzlib_get_buffer_avail_size;
	zstream->ostream.iostream.close = o_stream_bzlib_close;

	ret = BZ2_bzCompressInit(&zstream->zs, level, 0, 0);
	switch (ret) {
	case BZ_OK:
		break;
	case BZ_MEM_ERROR:
		i_fatal_status(FATAL_OUTOFMEM,
			       "bzlib: Out of memory");
	case BZ_CONFIG_ERROR:
		i_fatal("Wrong bzlib library version (broken compilation)");
	case BZ_PARAM_ERROR:
		i_fatal("bzlib: Invalid parameters");
	default:
		i_fatal("BZ2_bzCompressInit() failed with %d", ret);
	}

	zstream->zs.next_out = zstream->outbuf;
	zstream->zs.avail_out = sizeof(zstream->outbuf);
	return o_stream_create(&zstream->ostream, output,
			       o_stream_get_fd(output));
}
#endif

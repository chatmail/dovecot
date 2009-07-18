/* Copyright (c) 2002-2009 Dovecot Sieve authors, see the included COPYING file
 */

#include "lib.h"
#include "mempool.h"
#include "buffer.h"
#include "array.h"
#include "str.h"
#include "istream.h"
#include "rfc822-parser.h"
#include "message-date.h"
#include "message-parser.h"
#include "message-decoder.h"

#include "sieve-common.h"
#include "sieve-message.h"
#include "sieve-interpreter.h"

#include "ext-body-common.h"

/* This implementation is largely borrowed from the original sieve-cmu.c of the 
 * cmusieve plugin.
 */
 
struct ext_body_part_cached {
	const char *content_type;

	const char *raw_body;
	const char *decoded_body;
	size_t raw_body_size;
	size_t decoded_body_size;
	
	bool have_body; /* there's the empty end-of-headers line */
};

struct ext_body_message_context {
	pool_t pool;
	ARRAY_DEFINE(cached_body_parts, struct ext_body_part_cached);
	ARRAY_DEFINE(return_body_parts, struct ext_body_part);
	buffer_t *tmp_buffer;
};

static bool _is_wanted_content_type
(const char * const *wanted_types, const char *content_type)
{
	const char *subtype = strchr(content_type, '/');
	size_t type_len;

	type_len = ( subtype == NULL ? strlen(content_type) :
		(size_t)(subtype - content_type) );

	i_assert( wanted_types != NULL );

	for (; *wanted_types != NULL; wanted_types++) {
		const char *wanted_subtype = strchr(*wanted_types, '/');

		if (**wanted_types == '\0') {
			/* empty string matches everything */
			return TRUE;
		}
		if (wanted_subtype == NULL) {
			/* match only main type */
			if (strlen(*wanted_types) == type_len &&
			    strncasecmp(*wanted_types, content_type,
					type_len) == 0)
				return TRUE;
		} else {
			/* match whole type/subtype */
			if (strcasecmp(*wanted_types, content_type) == 0)
				return TRUE;
		}
	}
	return FALSE;
}

static bool ext_body_get_return_parts
(struct ext_body_message_context *ctx, const char * const *wanted_types,
	bool decode_to_plain)
{
	const struct ext_body_part_cached *body_parts;
	unsigned int i, count;
	struct ext_body_part *return_part;

	/* Check whether any body parts are cached already */
	body_parts = array_get(&ctx->cached_body_parts, &count);
	if ( count == 0 )
		return FALSE;

	/* Clear result array */
	array_clear(&ctx->return_body_parts);
	
	/* Fill result array with requested content_types */
	for (i = 0; i < count; i++) {
		if (!body_parts[i].have_body) {
			/* Part has no body; according to RFC this MUST not match to anything and 
			 * therefore it is not included in the result.
			 */
			continue;
		}

		/* Skip content types that are not requested */
		if (!_is_wanted_content_type(wanted_types, body_parts[i].content_type))
			continue;

		/* Add new item to the result */
		return_part = array_append_space(&ctx->return_body_parts);
		
		/* Depending on whether a decoded body part is requested, the appropriate
		 * cache item is read. If it is missing, this function fails and the cache 
		 * needs to be completed by ext_body_parts_add_missing().
		 */
		if (decode_to_plain) {
			if (body_parts[i].decoded_body == NULL)
				return FALSE;
			return_part->content = body_parts[i].decoded_body;
			return_part->size = body_parts[i].decoded_body_size;
		} else {
			if (body_parts[i].raw_body == NULL)
				return FALSE;
			return_part->content = body_parts[i].raw_body;
			return_part->size = body_parts[i].raw_body_size;
		}
	}

	return TRUE;
}

static void ext_body_part_save
(struct ext_body_message_context *ctx, struct message_part *part,
	struct ext_body_part_cached *body_part, bool decoded)
{
	buffer_t *buf = ctx->tmp_buffer;
	char *part_data;
	size_t part_size;

	/* Add terminating NUL to the body part buffer */
	buffer_append_c(buf, '\0');

	part_data = p_malloc(ctx->pool, buf->used);
	memcpy(part_data, buf->data, buf->used);
	part_size = buf->used - 1;
	
	/* Depending on whether the part is decoded or not store message body in the
	 * appropriate cache location.
	 */
	if ( !decoded ) {
		body_part->raw_body = part_data;
		body_part->raw_body_size = part_size;
		i_assert(buf->used - 1 == part->body_size.physical_size);
	} else {
		body_part->decoded_body = part_data;
		body_part->decoded_body_size = part_size;
	}
	
	/* Clear buffer */
	buffer_set_used_size(buf, 0);
}

static const char *_parse_content_type(const struct message_header_line *hdr)
{
	struct rfc822_parser_context parser;
	string_t *content_type;

	rfc822_parser_init(&parser, hdr->full_value, hdr->full_value_len, NULL);
	(void)rfc822_skip_lwsp(&parser);

	content_type = t_str_new(64);
	if (rfc822_parse_content_type(&parser, content_type) < 0)
		return "";
	return str_c(content_type);
}

/* ext_body_parts_add_missing():
 *   Add requested message body parts to the cache that are missing. 
 */
static bool ext_body_parts_add_missing
(const struct sieve_message_data *msgdata, struct ext_body_message_context *ctx, 
	const char * const *content_types, bool decode_to_plain)
{
	struct ext_body_part_cached *body_part = NULL;
	struct message_parser_ctx *parser;
	struct message_decoder_context *decoder;
	struct message_block block, decoded;
	struct message_part *parts, *prev_part = NULL;
	struct istream *input;
	unsigned int idx = 0;
	bool save_body = FALSE, have_all;
	int ret;

	/* First check whether any are missing */
	if (ext_body_get_return_parts(ctx, content_types, decode_to_plain)) {
		/* Cache hit; all are present */
		return TRUE;
	}

	/* Get the message stream */
	if ( mail_get_stream(msgdata->mail, NULL, NULL, &input) < 0 )
		return FALSE;
		
	buffer_set_used_size(ctx->tmp_buffer, 0);
	
	/* Initialize body decoder */
	decoder = decode_to_plain ? message_decoder_init(FALSE) : NULL;
	
	parser = message_parser_init
		(ctx->pool, input, 0, MESSAGE_PARSER_FLAG_SKIP_BODY_BLOCK);
	while ( (ret = message_parser_parse_next_block(parser, &block)) > 0 ) {
		if ( block.part != prev_part ) {
			/* Save previous body part */
			if ( body_part != NULL && save_body ) {
				ext_body_part_save(ctx, prev_part, body_part, decoder != NULL);
			}
			
			/* Start processing next */
			prev_part = block.part;
			body_part = array_idx_modifiable(&ctx->cached_body_parts, idx);
			idx++;
			body_part->content_type = "text/plain";
		}
		
		if ( block.hdr != NULL || block.size == 0 ) {
			/* reading headers */
			if ( decoder != NULL ) {
				(void)message_decoder_decode_next_block(decoder,
					&block, &decoded);
			}

			if ( block.hdr == NULL ) {
				/* save bodies only if we have a wanted
				   content-type */
				save_body = _is_wanted_content_type
					(content_types, body_part->content_type);
				continue;
			}
			
			/* Encountered the empty line that indicates the end of the headers and 
			 * the start of the body
			 */
			if ( block.hdr->eoh )
				body_part->have_body = TRUE;
				
			/* We're interested of only Content-Type: header */
			if ( strcasecmp(block.hdr->name, "Content-Type" ) != 0)
				continue;

			/* Header can have folding whitespace. Acquire the full value before 
			 * continuing
			 */
			if ( block.hdr->continues ) {
				block.hdr->use_full_value = TRUE;
				continue;
			}
		
			/* Parse the content type from the Content-type header */
			T_BEGIN {
				body_part->content_type =
					p_strdup(ctx->pool, _parse_content_type(block.hdr));
			} T_END;
			
			continue;
		}

		/* reading body */
		if (save_body) {
			if (decoder != NULL) {
				(void)message_decoder_decode_next_block(decoder,
							&block, &decoded);
				buffer_append(ctx->tmp_buffer,
					      decoded.data, decoded.size);
			} else {
				buffer_append(ctx->tmp_buffer,
					      block.data, block.size);
			}
		}
	}

	/* Save last body part if necessary */
	if (body_part != NULL && save_body)
		ext_body_part_save(ctx, prev_part, body_part, decoder != NULL);

	/* Try to fill the return_body_parts array once more */
	have_all = ext_body_get_return_parts(ctx, content_types, decode_to_plain);
	
	/* This time, failure is a bug */
	i_assert(have_all);

	/* Cleanup */
	(void)message_parser_deinit(&parser, &parts);
	if (decoder != NULL)
		message_decoder_deinit(&decoder);
	
	/* Return status */
	return ( input->stream_errno == 0 );
}

static struct ext_body_message_context *ext_body_get_context
(struct sieve_message_context *msgctx)
{
	pool_t pool = sieve_message_context_pool(msgctx);
	struct ext_body_message_context *ctx;
	
	/* Get message context (contains cached message body information) */
	ctx = (struct ext_body_message_context *)
		sieve_message_context_extension_get(msgctx, &body_extension);
	
	/* Create it if it does not exist already */
	if ( ctx == NULL ) {
		ctx = p_new(pool, struct ext_body_message_context, 1);	
		ctx->pool = pool;
		p_array_init(&ctx->cached_body_parts, pool, 8);
		p_array_init(&ctx->return_body_parts, pool, 8);
		ctx->tmp_buffer = buffer_create_dynamic(pool, 1024*64);
		
		/* Register context */
		sieve_message_context_extension_set(msgctx, &body_extension, (void *) ctx);
	}
	
	return ctx;
}

bool ext_body_get_content
(const struct sieve_runtime_env *renv, const char * const *content_types,
	int decode_to_plain, struct ext_body_part **parts_r)
{
	bool result = TRUE;
	struct ext_body_message_context *ctx = ext_body_get_context(renv->msgctx);

	T_BEGIN {
		/* Fill the return_body_parts array */
		if ( !ext_body_parts_add_missing
			(renv->msgdata, ctx, content_types, decode_to_plain != 0) )
			result = FALSE;
	} T_END;
	
	/* Check status */
	if ( !result ) return FALSE;

	/* Return the array of body items */
	(void) array_append_space(&ctx->return_body_parts); /* NULL-terminate */
	*parts_r = array_idx_modifiable(&ctx->return_body_parts, 0);

	return result;
}
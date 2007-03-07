/* Copyright (C) 2002-2003 Timo Sirainen */

#include "lib.h"
#include "array.h"
#include "buffer.h"
#include "istream.h"
#include "hex-binary.h"
#include "str.h"
#include "message-date.h"
#include "message-part-serialize.h"
#include "message-parser.h"
#include "imap-bodystructure.h"
#include "imap-envelope.h"
#include "mail-cache.h"
#include "index-storage.h"
#include "index-mail.h"

struct mail_cache_field global_cache_fields[MAIL_INDEX_CACHE_FIELD_COUNT] = {
	{ "flags", 0, MAIL_CACHE_FIELD_BITMASK, sizeof(uint32_t), 0 },
	{ "date.sent", 0, MAIL_CACHE_FIELD_FIXED_SIZE,
	  sizeof(struct mail_sent_date), 0 },
	{ "date.received", 0, MAIL_CACHE_FIELD_FIXED_SIZE,
	  sizeof(uint32_t), 0 },
	{ "size.virtual", 0, MAIL_CACHE_FIELD_FIXED_SIZE,
	  sizeof(uoff_t), 0 },
	{ "size.physical", 0, MAIL_CACHE_FIELD_FIXED_SIZE,
	  sizeof(uoff_t), 0 },
	{ "imap.body", 0, MAIL_CACHE_FIELD_STRING, 0, 0 },
	{ "imap.bodystructure", 0, MAIL_CACHE_FIELD_STRING, 0, 0 },
	{ "imap.envelope", 0, MAIL_CACHE_FIELD_STRING, 0, 0 },
	{ "mime.parts", 0, MAIL_CACHE_FIELD_VARIABLE_SIZE, 0, 0 }
};

static void index_mail_parse_body(struct index_mail *mail, bool need_parts);

static bool get_cached_parts(struct index_mail *mail)
{
	struct mail_cache_field *cache_fields = mail->ibox->cache_fields;
	struct message_part *part;
	buffer_t *part_buf;
	const char *error;

	t_push();
	part_buf = buffer_create_dynamic(pool_datastack_create(), 128);
	if (mail_cache_lookup_field(mail->trans->cache_view, part_buf,
			mail->data.seq,
			cache_fields[MAIL_CACHE_MESSAGEPART].idx) <= 0) {
		t_pop();
		return FALSE;
	}

	part = message_part_deserialize(mail->data_pool,
					part_buf->data, part_buf->used, &error);
	t_pop();

	if (part == NULL) {
		mail_cache_set_corrupted(mail->ibox->cache,
			"Corrupted cached message_part data (%s)", error);
		return FALSE;
	}

	/* we know the NULs now, update them */
	if ((part->flags & MESSAGE_PART_FLAG_HAS_NULS) != 0) {
		mail->mail.mail.has_nuls = TRUE;
		mail->mail.mail.has_no_nuls = FALSE;
	} else {
		mail->mail.mail.has_nuls = FALSE;
		mail->mail.mail.has_no_nuls = TRUE;
	}

	mail->data.parts = part;
	return TRUE;
}

const char *index_mail_get_cached_string(struct index_mail *mail,
					 enum index_cache_field field)
{
	string_t *str;

	str = str_new(mail->data_pool, 32);
	if (mail_cache_lookup_field(mail->trans->cache_view, str,
				    mail->data.seq,
				    mail->ibox->cache_fields[field].idx) <= 0) {
		str_free(&str);
		return NULL;
	}

	return str_c(str);
}

static bool index_mail_get_fixed_field(struct index_mail *mail,
				       enum index_cache_field field,
				       void *data, size_t data_size)
{
	buffer_t *buf;
	int ret;

	t_push();
	buf = buffer_create_data(pool_datastack_create(), data, data_size);
	if (mail_cache_lookup_field(mail->trans->cache_view, buf,
				    mail->data.seq,
				    mail->ibox->cache_fields[field].idx) <= 0) {
		ret = FALSE;
	} else {
		i_assert(buffer_get_used_size(buf) == data_size);
		ret = TRUE;
	}
	t_pop();

	return ret;
}

uoff_t index_mail_get_cached_uoff_t(struct index_mail *mail,
				    enum index_cache_field field)
{
	uoff_t uoff;

	if (!index_mail_get_fixed_field(mail,
					mail->ibox->cache_fields[field].idx,
					&uoff, sizeof(uoff)))
		uoff = (uoff_t)-1;

	return uoff;
}

uoff_t index_mail_get_cached_virtual_size(struct index_mail *mail)
{
	return index_mail_get_cached_uoff_t(mail, MAIL_CACHE_VIRTUAL_FULL_SIZE);
}

static uoff_t index_mail_get_cached_physical_size(struct index_mail *mail)
{
	return index_mail_get_cached_uoff_t(mail,
					    MAIL_CACHE_PHYSICAL_FULL_SIZE);
}

time_t index_mail_get_cached_received_date(struct index_mail *mail)
{
	uint32_t t;

	if (!index_mail_get_fixed_field(mail, MAIL_CACHE_RECEIVED_DATE,
					&t, sizeof(t)))
		return (time_t)-1;
	return t;
}

enum mail_flags index_mail_get_flags(struct mail *_mail)
{
	struct index_mail *mail = (struct index_mail *) _mail;
	struct index_mail_data *data = &mail->data;

	data->flags = data->rec->flags & MAIL_FLAGS_MASK;
	if (index_mailbox_is_recent(mail->ibox, data->seq))
		data->flags |= MAIL_RECENT;

	return data->flags;
}

const char *const *index_mail_get_keywords(struct mail *_mail)
{
	struct index_mail *mail = (struct index_mail *) _mail;
	struct index_mail_data *data = &mail->data;
	array_t ARRAY_DEFINE(keyword_indexes_arr, unsigned int);
	const char *const *names;
	const unsigned int *keyword_indexes;
	unsigned int i, count, names_count;

	if (array_is_created(&data->keywords))
		return array_get(&data->keywords, NULL);

	t_push();
	ARRAY_CREATE(&keyword_indexes_arr, pool_datastack_create(),
		     unsigned int, 128);
	if (mail_index_lookup_keywords(mail->ibox->view, mail->data.seq,
				       &keyword_indexes_arr) < 0) {
		mail_storage_set_index_error(mail->ibox);
		t_pop();
		return NULL;
	}

	keyword_indexes = array_get(&keyword_indexes_arr, &count);
	names = array_get(mail->ibox->keyword_names, &names_count);

	ARRAY_CREATE(&data->keywords, mail->data_pool, const char *, count);
	for (i = 0; i < count; i++) {
		const char *name;
		i_assert(keyword_indexes[i] < names_count);

		name = names[keyword_indexes[i]];
		array_append(&data->keywords, &name, 1);
	}

	/* end with NULL */
	(void)array_append_space(&data->keywords);

	t_pop();
	return array_get(&data->keywords, NULL);
}

const struct message_part *index_mail_get_parts(struct mail *_mail)
{
	struct index_mail *mail = (struct index_mail *) _mail;
	struct index_mail_data *data = &mail->data;

	if (data->parts != NULL)
		return data->parts;

	if (get_cached_parts(mail))
		return data->parts;

	if (data->parser_ctx == NULL) {
		if (index_mail_parse_headers(mail, NULL) < 0)
			return NULL;
	}
	index_mail_parse_body(mail, TRUE);

	return data->parts;
}

time_t index_mail_get_received_date(struct mail *_mail)
{
	struct index_mail *mail = (struct index_mail *) _mail;
	struct index_mail_data *data = &mail->data;

	if (data->received_date == (time_t)-1) {
		data->received_date = index_mail_get_cached_received_date(mail);
		if (data->received_date != (time_t)-1)
			return data->received_date;
	}

	return data->received_date;
}

time_t index_mail_get_date(struct mail *_mail, int *timezone)
{
	struct index_mail *mail = (struct index_mail *) _mail;
	struct index_mail_data *data = &mail->data;
	const char *str;

	if (data->sent_date.time != (uint32_t)-1) {
		if (timezone != NULL)
			*timezone = data->sent_date.timezone;
		return data->sent_date.time;
	}

	(void)index_mail_get_fixed_field(mail, MAIL_CACHE_SENT_DATE,
					 &data->sent_date,
					 sizeof(data->sent_date));

	if (data->sent_date.time == (uint32_t)-1) {
		time_t t;
		int tz;

		str = mail_get_first_header(_mail, "Date");
		if (str == NULL ||
		    !message_date_parse((const unsigned char *)str,
					strlen(str), &t, &tz)) {
			/* 0 = not found / invalid */
			t = 0;
			tz = 0;
		}
		data->sent_date.time = t;
		data->sent_date.timezone = tz;
		index_mail_cache_add(mail, MAIL_CACHE_SENT_DATE,
				     &data->sent_date, sizeof(data->sent_date));
	}

	if (timezone != NULL)
		*timezone = data->sent_date.timezone;
	return data->sent_date.time;
}

static bool get_cached_msgpart_sizes(struct index_mail *mail)
{
	struct index_mail_data *data = &mail->data;

	if (data->parts == NULL)
		get_cached_parts(mail);

	if (data->parts != NULL) {
		data->hdr_size_set = TRUE;
		data->hdr_size = data->parts->header_size;
		data->body_size = data->parts->body_size;
		data->body_size_set = TRUE;
		data->virtual_size = data->parts->header_size.virtual_size +
			data->body_size.virtual_size;
		data->physical_size = data->parts->header_size.physical_size +
			data->body_size.physical_size;
	}

	return data->parts != NULL;
}

uoff_t index_mail_get_virtual_size(struct mail *_mail)
{
	struct index_mail *mail = (struct index_mail *) _mail;
	struct index_mail_data *data = &mail->data;
	struct message_size hdr_size, body_size;
	uoff_t old_offset;

	if (data->virtual_size != (uoff_t)-1)
		return data->virtual_size;

	data->virtual_size = index_mail_get_cached_virtual_size(mail);
	if (data->virtual_size != (uoff_t)-1)
		return data->virtual_size;

	if (!get_cached_msgpart_sizes(mail)) {
		old_offset = data->stream == NULL ? 0 : data->stream->v_offset;

		if (mail_get_stream(_mail, &hdr_size, &body_size) == NULL)
			return (uoff_t)-1;
		i_stream_seek(data->stream, old_offset);
	}

	i_assert(data->virtual_size != (uoff_t)-1);
	index_mail_cache_add(mail, MAIL_CACHE_VIRTUAL_FULL_SIZE,
			     &data->virtual_size, sizeof(data->virtual_size));
	return data->virtual_size;
}

uoff_t index_mail_get_physical_size(struct mail *_mail)
{
	struct index_mail *mail = (struct index_mail *) _mail;
	struct index_mail_data *data = &mail->data;

	if (data->physical_size != (uoff_t)-1)
		return data->physical_size;

	data->physical_size = index_mail_get_cached_physical_size(mail);
	if (data->physical_size != (uoff_t)-1)
		return data->physical_size;

	if (get_cached_msgpart_sizes(mail))
		return data->physical_size;

	return (uoff_t)-1;
}

void index_mail_cache_add(struct index_mail *mail, enum index_cache_field field,
			  const void *data, size_t data_size)
{
	index_mail_cache_add_idx(mail, mail->ibox->cache_fields[field].idx,
				 data, data_size);
}

void index_mail_cache_add_idx(struct index_mail *mail, unsigned int field_idx,
			      const void *data, size_t data_size)
{
	const struct mail_index_header *hdr;

	if (mail->ibox->mail_cache_min_mail_count > 0) {
		/* First check if we've configured caching not to be used with
		   low enough message count. */
		hdr = mail_index_get_header(mail->ibox->view);
		if (hdr->messages_count < mail->ibox->mail_cache_min_mail_count)
			return;
	}

	mail_cache_add(mail->trans->cache_trans, mail->data.seq,
		       field_idx, data, data_size);
}

static void parse_bodystructure_part_header(struct message_part *part,
					    struct message_header_line *hdr,
					    void *context)
{
	pool_t pool = context;

	imap_bodystructure_parse_header(pool, part, hdr);
}

static void index_mail_parse_body(struct index_mail *mail, bool need_parts)
{
	struct index_mail_data *data = &mail->data;
	struct mail_cache_field *cache_fields = mail->ibox->cache_fields;
	enum mail_cache_decision_type decision;
	buffer_t *buffer;
	const void *buf_data;
	size_t buf_size;
	uoff_t old_offset;
	uint32_t cache_flags = data->cache_flags;

	i_assert(data->parts == NULL);
	i_assert(data->parser_ctx != NULL);

	old_offset = data->stream->v_offset;
	i_stream_seek(data->stream, data->hdr_size.physical_size);

	if (data->save_bodystructure_body) {
		/* bodystructure header is parsed, we want the body's mime
		   headers too */
		i_assert(!data->save_bodystructure_header);
		message_parser_parse_body(data->parser_ctx,
					  parse_bodystructure_part_header,
					  NULL, mail->data_pool);
		data->save_bodystructure_body = FALSE;
		data->parsed_bodystructure = TRUE;
	} else {
		message_parser_parse_body(data->parser_ctx, NULL, NULL, NULL);
	}
	data->parts = message_parser_deinit(&data->parser_ctx);
	i_stream_seek(data->stream, old_offset);

	if (data->parsed_bodystructure &&
	    imap_bodystructure_is_plain_7bit(data->parts)) {
		cache_flags |= MAIL_CACHE_FLAG_TEXT_PLAIN_7BIT_ASCII;
		/* we need message_parts cached to be able to
		   actually use it in BODY/BODYSTRUCTURE reply */
		need_parts = TRUE;
	}

	data->body_size = data->parts->body_size;
	data->body_size_set = TRUE;

	cache_flags &= ~(MAIL_CACHE_FLAG_BINARY_HEADER |
			 MAIL_CACHE_FLAG_BINARY_BODY |
			 MAIL_CACHE_FLAG_HAS_NULS |
			 MAIL_CACHE_FLAG_HAS_NO_NULS);
	if (!mail->mail.mail.has_nuls && !mail->mail.mail.has_no_nuls) {
		/* we know the NULs now, update them */
		if ((data->parts->flags & MESSAGE_PART_FLAG_HAS_NULS) != 0) {
			mail->mail.mail.has_nuls = TRUE;
			mail->mail.mail.has_no_nuls = FALSE;
		} else {
			mail->mail.mail.has_nuls = FALSE;
			mail->mail.mail.has_no_nuls = TRUE;
		}

		if (mail->mail.mail.has_nuls)
			cache_flags |= MAIL_CACHE_FLAG_HAS_NULS;
		else
			cache_flags |= MAIL_CACHE_FLAG_HAS_NO_NULS;
	}

	if (data->hdr_size.virtual_size == data->hdr_size.physical_size)
		cache_flags |= MAIL_CACHE_FLAG_BINARY_HEADER;
	if (data->body_size.virtual_size == data->body_size.physical_size)
		cache_flags |= MAIL_CACHE_FLAG_BINARY_BODY;

	if (cache_flags != data->cache_flags) {
		data->cache_flags = cache_flags;
		index_mail_cache_add(mail, MAIL_CACHE_FLAGS,
				     &cache_flags, sizeof(cache_flags));
	}

	/* see if we want to cache the message part */
	if (mail_cache_field_exists(mail->trans->cache_view, mail->data.seq,
			cache_fields[MAIL_CACHE_MESSAGEPART].idx) != 0)
		return;

	decision = mail_cache_field_get_decision(mail->ibox->cache,
				cache_fields[MAIL_CACHE_MESSAGEPART].idx);
	if (decision != (MAIL_CACHE_DECISION_NO | MAIL_CACHE_DECISION_FORCED) &&
	    (decision != MAIL_CACHE_DECISION_NO || need_parts ||
	     (mail->wanted_fields & MAIL_FETCH_MESSAGE_PARTS) != 0)) {
		t_push();
		buffer = buffer_create_dynamic(pool_datastack_create(), 1024);
		message_part_serialize(mail->data.parts, buffer);

		buf_data = buffer_get_data(buffer, &buf_size);
                index_mail_cache_add(mail, MAIL_CACHE_MESSAGEPART,
				     buf_data, buf_size);
		t_pop();
		data->messageparts_saved_to_cache = TRUE;
	}
}

struct istream *index_mail_init_stream(struct index_mail *_mail,
				       struct message_size *hdr_size,
				       struct message_size *body_size)
{
	struct index_mail *mail = (struct index_mail *) _mail;
	struct index_mail_data *data = &mail->data;

	if (hdr_size != NULL || body_size != NULL)
		(void)get_cached_msgpart_sizes(mail);

	if (hdr_size != NULL || body_size != NULL) {
		i_stream_seek(data->stream, 0);
		if (!data->hdr_size_set) {
			if ((data->access_part & PARSE_HDR) != 0) {
				if (index_mail_parse_headers(mail, NULL) < 0)
					return NULL;
			} else {
				message_get_header_size(data->stream,
							&data->hdr_size, NULL);
				data->hdr_size_set = TRUE;
			}
		}

		if (hdr_size != NULL)
			*hdr_size = data->hdr_size;
	}

	if (body_size != NULL) {
		i_stream_seek(data->stream, data->hdr_size.physical_size);
		if (!data->body_size_set) {
			if ((data->access_part & PARSE_BODY) != 0)
				index_mail_parse_body(mail, FALSE);
			else {
				message_get_body_size(data->stream,
						      &data->body_size, NULL);
				data->body_size_set = TRUE;
			}
		}

		*body_size = data->body_size;
	}

	if (data->hdr_size_set && data->body_size_set) {
		data->virtual_size = data->hdr_size.virtual_size +
			data->body_size.virtual_size;
		data->physical_size = data->hdr_size.physical_size +
			data->body_size.physical_size;
	}

	i_stream_seek(data->stream, 0);
	return data->stream;
}

static void index_mail_parse_bodystructure(struct index_mail *mail,
					   enum index_cache_field field)
{
	struct index_mail_data *data = &mail->data;
	struct mail_cache_field *cache_fields = mail->ibox->cache_fields;
	enum mail_cache_decision_type dec;
	string_t *str;
	uoff_t old_offset;
	bool bodystructure_cached = FALSE;
	bool plain_bodystructure = FALSE;

	if (!data->parsed_bodystructure) {
		if (data->save_bodystructure_header ||
		    !data->save_bodystructure_body) {
			/* we haven't parsed the header yet */
			data->save_bodystructure_header = TRUE;
			data->save_bodystructure_body = TRUE;
			if (index_mail_parse_headers(mail, NULL) < 0)
				return;
		}

		if (data->parts != NULL) {
			i_assert(data->parts->next == NULL);

			old_offset = data->stream->v_offset;
			i_stream_seek(data->stream,
				      data->hdr_size.physical_size);
			message_parse_from_parts(data->parts->children,
						data->stream,
						parse_bodystructure_part_header,
						mail->data_pool);
			data->parsed_bodystructure = TRUE;
			i_stream_seek(data->stream, old_offset);
		} else {
			index_mail_parse_body(mail, FALSE);
		}
	}

	if ((data->cache_flags & MAIL_CACHE_FLAG_TEXT_PLAIN_7BIT_ASCII) != 0) {
		if (data->messageparts_saved_to_cache ||
		    mail_cache_field_exists(mail->trans->cache_view, data->seq,
				cache_fields[MAIL_CACHE_MESSAGEPART].idx) > 0) {
			/* cached it as flag + message_parts */
			plain_bodystructure = TRUE;
		}
	}

	dec = mail_cache_field_get_decision(mail->ibox->cache,
			cache_fields[MAIL_CACHE_IMAP_BODYSTRUCTURE].idx);
	if (field == MAIL_CACHE_IMAP_BODYSTRUCTURE ||
	    ((dec & ~MAIL_CACHE_DECISION_FORCED) != MAIL_CACHE_DECISION_NO &&
	     mail_cache_field_exists(mail->trans->cache_view, data->seq,
	     	       cache_fields[MAIL_CACHE_IMAP_BODYSTRUCTURE].idx) == 0)) {
		str = str_new(mail->data_pool, 128);
		imap_bodystructure_write(data->parts, str, TRUE);
		data->bodystructure = str_c(str);

		if (!plain_bodystructure &&
		    dec != (MAIL_CACHE_DECISION_NO |
			    MAIL_CACHE_DECISION_FORCED)) {
			index_mail_cache_add(mail,
				MAIL_CACHE_IMAP_BODYSTRUCTURE,
				str_c(str), str_len(str)+1);
			bodystructure_cached = TRUE;
		}
	}

	dec = mail_cache_field_get_decision(mail->ibox->cache,
				cache_fields[MAIL_CACHE_IMAP_BODY].idx);
	if (field == MAIL_CACHE_IMAP_BODY ||
	    ((dec & ~MAIL_CACHE_DECISION_FORCED) != MAIL_CACHE_DECISION_NO &&
	     mail_cache_field_exists(mail->trans->cache_view, data->seq,
	     			cache_fields[MAIL_CACHE_IMAP_BODY].idx) == 0)) {
		str = str_new(mail->data_pool, 128);
		imap_bodystructure_write(data->parts, str, FALSE);
		data->body = str_c(str);

		if (!bodystructure_cached && !plain_bodystructure &&
		    dec != (MAIL_CACHE_DECISION_NO |
			    MAIL_CACHE_DECISION_FORCED)) {
			index_mail_cache_add(mail, MAIL_CACHE_IMAP_BODY,
					     str_c(str), str_len(str)+1);
		}
	}
}

static void
index_mail_get_plain_bodystructure(struct index_mail *mail, string_t *str,
				   bool extended)
{
	str_printfa(str, IMAP_BODY_PLAIN_7BIT_ASCII" %"PRIuUOFF_T" %u",
		    mail->data.parts->body_size.virtual_size,
		    mail->data.parts->body_size.lines);
	if (extended)
		str_append(str, " NIL NIL NIL");
}

const char *index_mail_get_special(struct mail *_mail,
				   enum mail_fetch_field field)
{
	struct index_mail *mail = (struct index_mail *) _mail;
	struct index_mail_data *data = &mail->data;
	struct mail_cache_field *cache_fields = mail->ibox->cache_fields;
	string_t *str;
	const void *ext_data;

	switch (field) {
	case MAIL_FETCH_IMAP_BODY: {
		unsigned int body_cache_field =
                        cache_fields[MAIL_CACHE_IMAP_BODY].idx;
		unsigned int bodystructure_cache_field =
                        cache_fields[MAIL_CACHE_IMAP_BODYSTRUCTURE].idx;
		if (data->body != NULL)
			return data->body;

		/* 1) use plain-7bit-ascii flag if it exists
		   2) get BODY if it exists
		   3) get it using BODYSTRUCTURE if it exists
		   4) parse body structure, and save BODY/BODYSTRUCTURE
		      depending on what we want cached */

		str = str_new(mail->data_pool, 128);
		if ((mail->data.cache_flags &
		     MAIL_CACHE_FLAG_TEXT_PLAIN_7BIT_ASCII) != 0 &&
		    get_cached_parts(mail)) {
			index_mail_get_plain_bodystructure(mail, str, FALSE);
			return str_c(str);
		}

		if (mail_cache_lookup_field(mail->trans->cache_view, str,
				mail->data.seq, body_cache_field) > 0) {
			data->body = str_c(str);
			return data->body;
		}
		if (mail_cache_lookup_field(mail->trans->cache_view, str,
					    mail->data.seq,
					    bodystructure_cache_field) > 0) {
			data->bodystructure =
				p_strdup(mail->data_pool, str_c(str));
			str_truncate(str, 0);

			if (imap_body_parse_from_bodystructure(
						data->bodystructure, str)) {
				data->body = str_c(str);
				return data->body;
			}

			/* broken, continue.. */
			mail_cache_set_corrupted(mail->ibox->cache,
				"Corrupted BODYSTRUCTURE for mail %u",
				mail->mail.mail.uid);
			data->bodystructure = NULL;
		}
		str_free(&str);

		index_mail_parse_bodystructure(mail, MAIL_CACHE_IMAP_BODY);
		return data->body;
	}
	case MAIL_FETCH_IMAP_BODYSTRUCTURE: {
		unsigned int bodystructure_cache_field =
                        cache_fields[MAIL_CACHE_IMAP_BODYSTRUCTURE].idx;

		if (data->bodystructure != NULL)
			return data->bodystructure;

		str = str_new(mail->data_pool, 128);
		if ((mail->data.cache_flags &
		     MAIL_CACHE_FLAG_TEXT_PLAIN_7BIT_ASCII) != 0 &&
		    get_cached_parts(mail)) {
			index_mail_get_plain_bodystructure(mail, str, TRUE);
			return str_c(str);
		}

		if (mail_cache_lookup_field(mail->trans->cache_view, str,
					    mail->data.seq,
					    bodystructure_cache_field) > 0) {
			data->bodystructure = str_c(str);
			return data->bodystructure;
		}
		str_free(&str);

		index_mail_parse_bodystructure(mail,
					       MAIL_CACHE_IMAP_BODYSTRUCTURE);
		return data->bodystructure;
	}
	case MAIL_FETCH_IMAP_ENVELOPE:
		if (data->envelope == NULL)
			index_mail_headers_get_envelope(mail);
		return data->envelope;
	case MAIL_FETCH_FROM_ENVELOPE:
	case MAIL_FETCH_UIDL_FILE_NAME:
		return NULL;
	case MAIL_FETCH_HEADER_MD5:
		if (mail_index_lookup_ext(mail->trans->trans_view, data->seq,
					  mail->ibox->md5hdr_ext_idx,
					  &ext_data) < 0) {
			mail_storage_set_index_error(mail->ibox);
			return NULL;
		}
		if (ext_data == NULL)
			return NULL;
		return binary_to_hex(ext_data, 16);
	default:
		i_unreached();
		return NULL;
	}
}

struct mail *
index_mail_alloc(struct mailbox_transaction_context *_t,
		 enum mail_fetch_field wanted_fields,
		 struct mailbox_header_lookup_ctx *_wanted_headers)
{
	struct index_transaction_context *t =
		(struct index_transaction_context *)_t;
	struct index_header_lookup_ctx *wanted_headers =
		(struct index_header_lookup_ctx *)_wanted_headers;
	struct index_mail *mail;
	const struct mail_index_header *hdr;
	pool_t pool;

	pool = pool_alloconly_create("mail", 1024);
	mail = p_new(pool, struct index_mail, 1);
	mail->mail.pool = pool;
	array_create(&mail->mail.module_contexts, pool, sizeof(void *), 5);

	mail->mail.v = *t->ibox->mail_vfuncs;
	mail->mail.mail.box = &t->ibox->box;
	mail->mail.mail.transaction = &t->mailbox_ctx;

	hdr = mail_index_get_header(t->ibox->view);
	mail->uid_validity = hdr->uid_validity;

	mail->data_pool = pool_alloconly_create("index_mail", 16384);
	mail->ibox = t->ibox;
	mail->trans = t;
	mail->wanted_fields = wanted_fields;
	mail->wanted_headers = wanted_headers;

	return &mail->mail.mail;
}

static void index_mail_close(struct index_mail *mail)
{
	if (mail->data.parser_ctx != NULL)
		(void)message_parser_deinit(&mail->data.parser_ctx);
	if (mail->data.stream != NULL)
		i_stream_destroy(&mail->data.stream);
	if (mail->data.filter_stream != NULL)
		i_stream_destroy(&mail->data.filter_stream);
}

int index_mail_set_seq(struct mail *_mail, uint32_t seq)
{
	struct index_mail *mail = (struct index_mail *)_mail;
	struct index_mail_data *data = &mail->data;
	struct mail_cache_field *cache_fields = mail->ibox->cache_fields;
        struct mail_cache_view *cache_view = mail->trans->cache_view;
	const struct mail_index_header *hdr;
	const struct mail_index_record *rec;

	if (mail_index_lookup(mail->trans->trans_view, seq, &rec) < 0) {
		mail_storage_set_index_error(mail->ibox);
		return -1;
	}

	/* FIXME: We get the header only to make sure the UID is valid.
	   Remove this code once the below panic never occurs. */
	hdr = mail_index_get_header(mail->trans->trans_view);
	if (rec->uid >= hdr->next_uid)
		i_panic("uid %u >= next_uid %u", rec->uid, hdr->next_uid);

	index_mail_close(mail);

	memset(data, 0, sizeof(*data));
	p_clear(mail->data_pool);

	data->rec = rec;
	data->seq = seq;
	data->virtual_size = (uoff_t)-1;
	data->physical_size = (uoff_t)-1;
	data->received_date = (time_t)-1;
	data->sent_date.time = (uint32_t)-1;

	if (!index_mail_get_fixed_field(mail, MAIL_CACHE_FLAGS,
					&data->cache_flags,
					sizeof(data->cache_flags)))
		data->cache_flags = 0;

	/* set public fields */
	mail->mail.mail.seq = seq;
	mail->mail.mail.uid = rec->uid;
	mail->mail.mail.has_nuls =
		(data->cache_flags & MAIL_CACHE_FLAG_HAS_NULS) != 0;
	mail->mail.mail.has_no_nuls =
		(data->cache_flags & MAIL_CACHE_FLAG_HAS_NO_NULS) != 0;

	/* see if wanted_fields can tell us if we need to read/parse
	   header/body */
	if ((mail->wanted_fields & MAIL_FETCH_MESSAGE_PARTS) != 0) {
		unsigned int cache_field =
			cache_fields[MAIL_CACHE_MESSAGEPART].idx;

		if (mail_cache_field_exists(cache_view, seq, cache_field) <= 0)
			data->access_part |= PARSE_HDR | PARSE_BODY;
	}

	if ((mail->wanted_fields & MAIL_FETCH_VIRTUAL_SIZE) != 0) {
		unsigned int cache_field =
			cache_fields[MAIL_CACHE_VIRTUAL_FULL_SIZE].idx;

		if (mail_cache_field_exists(cache_view, seq, cache_field) <= 0)
			data->access_part |= READ_HDR | READ_BODY;
	}

	if ((mail->wanted_fields & MAIL_FETCH_IMAP_ENVELOPE) != 0 &&
	    (data->access_part & PARSE_HDR) == 0) {
		/* don't waste time doing full checks for all required
		   headers. assume that if we have "hdr.message-id" or
		   "imap.envelope" cached, we don't need to parse header. */
		unsigned int cache_field1 =
			mail_cache_register_lookup(mail->ibox->cache,
						   "hdr.message-id");
		unsigned int cache_field2 =
			cache_fields[MAIL_CACHE_IMAP_ENVELOPE].idx;

		if ((cache_field1 == (unsigned int)-1 ||
		     mail_cache_field_exists(cache_view, seq,
					     cache_field1) <= 0) &&
		    mail_cache_field_exists(cache_view, seq,
					    cache_field2) <= 0)
			data->access_part |= PARSE_HDR;
	}

	if ((mail->wanted_fields & MAIL_FETCH_IMAP_BODY) != 0 &&
	    (data->cache_flags & MAIL_CACHE_FLAG_TEXT_PLAIN_7BIT_ASCII) == 0) {
		/* we need either imap.body or imap.bodystructure */
		unsigned int cache_field1 =
			cache_fields[MAIL_CACHE_IMAP_BODY].idx;
		unsigned int cache_field2 =
			cache_fields[MAIL_CACHE_IMAP_BODYSTRUCTURE].idx;

		if (mail_cache_field_exists(cache_view,
					    seq, cache_field1) <= 0 &&
		    mail_cache_field_exists(cache_view,
                                            seq, cache_field2) <= 0) {
			data->access_part |= PARSE_HDR | PARSE_BODY;
			data->save_bodystructure_header = TRUE;
			data->save_bodystructure_body = TRUE;
		}
	}

	if ((mail->wanted_fields & MAIL_FETCH_IMAP_BODYSTRUCTURE) != 0 &&
	    (data->cache_flags & MAIL_CACHE_FLAG_TEXT_PLAIN_7BIT_ASCII) == 0) {
		unsigned int cache_field =
			cache_fields[MAIL_CACHE_IMAP_BODYSTRUCTURE].idx;

                if (mail_cache_field_exists(cache_view, seq,
                                            cache_field) <= 0) {
			data->access_part |= PARSE_HDR | PARSE_BODY;
			data->save_bodystructure_header = TRUE;
			data->save_bodystructure_body = TRUE;
		}
	}

	if ((mail->wanted_fields & MAIL_FETCH_DATE) != 0) {
		unsigned int cache_field =
			cache_fields[MAIL_CACHE_SENT_DATE].idx;

		if (mail_cache_field_exists(cache_view, seq,
					    cache_field) <= 0) {
			data->access_part |= PARSE_HDR;
			data->save_sent_date = TRUE;
		}
	}

	if ((mail->wanted_fields & MAIL_FETCH_IMAP_ENVELOPE) != 0)
		data->save_envelope = TRUE;

	if ((mail->wanted_fields & (MAIL_FETCH_STREAM_HEADER |
				    MAIL_FETCH_STREAM_BODY)) != 0) {
		/* open stream immediately to set expunged flag if
		   it's already lost */
		if ((mail->wanted_fields & MAIL_FETCH_STREAM_HEADER) != 0)
			data->access_part |= READ_HDR;
		if ((mail->wanted_fields & MAIL_FETCH_STREAM_BODY) != 0)
			data->access_part |= READ_BODY;

		(void)mail_get_stream(_mail, NULL, NULL);
	}

	return 0;
}

void index_mail_free(struct mail *_mail)
{
	struct index_mail *mail = (struct index_mail *)_mail;

	index_mail_close(mail);

	if (mail->header_data != NULL)
		buffer_free(mail->header_data);
	if (array_is_created(&mail->header_lines))
		array_free(&mail->header_lines);
	if (array_is_created(&mail->header_match))
		array_free(&mail->header_match);
	if (array_is_created(&mail->header_match_lines))
		array_free(&mail->header_match_lines);

	pool_unref(mail->data_pool);
	pool_unref(mail->mail.pool);
}

int index_mail_update_flags(struct mail *mail, enum modify_type modify_type,
			    enum mail_flags flags)
{
	struct index_mail *imail = (struct index_mail *)mail;

	mail_index_update_flags(imail->trans->trans, mail->seq, modify_type,
				flags & MAIL_FLAGS_MASK);
	return 0;
}

int index_mail_update_keywords(struct mail *mail, enum modify_type modify_type,
			       struct mail_keywords *keywords)
{
	struct index_mail *imail = (struct index_mail *)mail;

	mail_index_update_keywords(imail->trans->trans, mail->seq, modify_type,
				   keywords);
	return 0;
}

int index_mail_expunge(struct mail *mail)
{
	struct index_mail *imail = (struct index_mail *)mail;

	mail_index_expunge(imail->trans->trans, mail->seq);
	return 0;
}

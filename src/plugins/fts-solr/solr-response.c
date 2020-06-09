/* Copyright (c) 2006-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "hash.h"
#include "str.h"
#include "istream.h"
#include "solr-response.h"

#include <expat.h>

#define MAX_VALUE_LEN 2048

enum solr_xml_response_state {
	SOLR_XML_RESPONSE_STATE_ROOT,
	SOLR_XML_RESPONSE_STATE_RESPONSE,
	SOLR_XML_RESPONSE_STATE_RESULT,
	SOLR_XML_RESPONSE_STATE_DOC,
	SOLR_XML_RESPONSE_STATE_CONTENT
};

enum solr_xml_content_state {
	SOLR_XML_CONTENT_STATE_NONE = 0,
	SOLR_XML_CONTENT_STATE_UID,
	SOLR_XML_CONTENT_STATE_SCORE,
	SOLR_XML_CONTENT_STATE_MAILBOX,
	SOLR_XML_CONTENT_STATE_NAMESPACE,
	SOLR_XML_CONTENT_STATE_UIDVALIDITY,
	SOLR_XML_CONTENT_STATE_ERROR
};

struct solr_response_parser {
	XML_Parser xml_parser;
	struct istream *input;

	enum solr_xml_response_state state;
	enum solr_xml_content_state content_state;
	int depth;
	string_t *buffer;

	uint32_t uid, uidvalidity;
	float score;
	char *mailbox, *ns;

	pool_t result_pool;
	/* box_id -> solr_result */
	HASH_TABLE(char *, struct solr_result *) mailboxes;
	ARRAY(struct solr_result *) results;

	bool xml_failed:1;
};

static int
solr_xml_parse(struct solr_response_parser *parser,
	       const void *data, size_t size, bool done)
{
	enum XML_Error err;
	int line, col;

	if (parser->xml_failed)
		return -1;

	if (XML_Parse(parser->xml_parser, data, size, done ? 1 : 0) != 0)
		return 0;

	err = XML_GetErrorCode(parser->xml_parser);
	if (err != XML_ERROR_FINISHED) {
		line = XML_GetCurrentLineNumber(parser->xml_parser);
		col = XML_GetCurrentColumnNumber(parser->xml_parser);
		i_error("fts_solr: Invalid XML input at %d:%d: %s "
			"(near: %.*s)", line, col, XML_ErrorString(err),
			(int)I_MIN(size, 128), (const char *)data);
		parser->xml_failed = TRUE;
		return -1;
	}
	return 0;
}

static const char *attrs_get_name(const char **attrs)
{
	for (; *attrs != NULL; attrs += 2) {
		if (strcmp(attrs[0], "name") == 0)
			return attrs[1];
	}
	return "";
}

static void
solr_lookup_xml_start(void *context, const char *name, const char **attrs)
{
	struct solr_response_parser *parser = context;
	const char *name_attr;

	i_assert(parser->depth >= (int)parser->state);

	parser->depth++;
	if (parser->depth - 1 > (int)parser->state) {
		/* skipping over unwanted elements */
		return;
	}

	str_truncate(parser->buffer, 0);

	/* response -> result -> doc */
	switch (parser->state) {
	case SOLR_XML_RESPONSE_STATE_ROOT:
		if (strcmp(name, "response") == 0)
			parser->state++;
		break;
	case SOLR_XML_RESPONSE_STATE_RESPONSE:
		if (strcmp(name, "result") == 0)
			parser->state++;
		break;
	case SOLR_XML_RESPONSE_STATE_RESULT:
		if (strcmp(name, "doc") == 0) {
			parser->state++;
			parser->uid = 0;
			parser->score = 0;
			i_free_and_null(parser->mailbox);
			i_free_and_null(parser->ns);
			parser->uidvalidity = 0;
		}
		break;
	case SOLR_XML_RESPONSE_STATE_DOC:
		name_attr = attrs_get_name(attrs);
		if (strcmp(name_attr, "uid") == 0)
			parser->content_state = SOLR_XML_CONTENT_STATE_UID;
		else if (strcmp(name_attr, "score") == 0)
			parser->content_state = SOLR_XML_CONTENT_STATE_SCORE;
		else if (strcmp(name_attr, "box") == 0)
			parser->content_state = SOLR_XML_CONTENT_STATE_MAILBOX;
		else if (strcmp(name_attr, "ns") == 0)
			parser->content_state = SOLR_XML_CONTENT_STATE_NAMESPACE;
		else if (strcmp(name_attr, "uidv") == 0)
			parser->content_state = SOLR_XML_CONTENT_STATE_UIDVALIDITY;
		else
			break;
		parser->state++;
		break;
	case SOLR_XML_RESPONSE_STATE_CONTENT:
		break;
	}
}

static struct solr_result *
solr_result_get(struct solr_response_parser *parser, const char *box_id)
{
	struct solr_result *result;
	char *box_id_dup;

	result = hash_table_lookup(parser->mailboxes, box_id);
	if (result != NULL)
		return result;

	box_id_dup = p_strdup(parser->result_pool, box_id);
	result = p_new(parser->result_pool, struct solr_result, 1);
	result->box_id = box_id_dup;
	p_array_init(&result->uids, parser->result_pool, 32);
	p_array_init(&result->scores, parser->result_pool, 32);
	hash_table_insert(parser->mailboxes, box_id_dup, result);
	array_push_back(&parser->results, &result);
	return result;
}

static int solr_lookup_add_doc(struct solr_response_parser *parser)
{
	struct fts_score_map *score;
	struct solr_result *result;
	const char *box_id;

	if (parser->uid == 0) {
		i_error("fts_solr: uid missing from inside doc");
		return -1;
	}

	if (parser->mailbox == NULL) {
		/* looking up from a single mailbox only */
		box_id = "";
	} else if (parser->uidvalidity != 0) {
		/* old style lookup */
		string_t *str = t_str_new(64);
		str_printfa(str, "%u\001", parser->uidvalidity);
		str_append(str, parser->mailbox);
		if (parser->ns != NULL)
			str_printfa(str, "\001%s", parser->ns);
		box_id = str_c(str);
	} else {
		/* new style lookup */
		box_id = parser->mailbox;
	}
	result = solr_result_get(parser, box_id);

	if (seq_range_array_add(&result->uids, parser->uid)) {
		/* duplicate result */
	} else if (parser->score != 0) {
		score = array_append_space(&result->scores);
		score->uid = parser->uid;
		score->score = parser->score;
	}
	return 0;
}

static void solr_lookup_xml_end(void *context, const char *name ATTR_UNUSED)
{
	struct solr_response_parser *parser = context;
	string_t *buf = parser->buffer;
	int ret;

	switch (parser->content_state) {
	case SOLR_XML_CONTENT_STATE_NONE:
		break;
	case SOLR_XML_CONTENT_STATE_UID:
		if (str_to_uint32(str_c(buf), &parser->uid) < 0 ||
		    parser->uid == 0) {
			i_error("fts_solr: received invalid uid '%s'",
				str_c(buf));
			parser->content_state = SOLR_XML_CONTENT_STATE_ERROR;
		}
		break;
	case SOLR_XML_CONTENT_STATE_SCORE:
		parser->score = strtod(str_c(buf), NULL);
		break;
	case SOLR_XML_CONTENT_STATE_MAILBOX:
		parser->mailbox = i_strdup(str_c(buf));
		break;
	case SOLR_XML_CONTENT_STATE_NAMESPACE:
		parser->ns = i_strdup(str_c(buf));
		break;
	case SOLR_XML_CONTENT_STATE_UIDVALIDITY:
		if (str_to_uint32(str_c(buf), &parser->uidvalidity) < 0)
			i_error("fts_solr: received invalid uidvalidity");
		break;
	case SOLR_XML_CONTENT_STATE_ERROR:
		return;
	}

	i_assert(parser->depth >= (int)parser->state);

	if (parser->state == SOLR_XML_RESPONSE_STATE_CONTENT &&
	    parser->content_state == SOLR_XML_CONTENT_STATE_MAILBOX &&
	    parser->mailbox == NULL) {
		/* mailbox is namespace prefix */
		parser->mailbox = i_strdup("");
	}

	if (parser->depth == (int)parser->state) {
		ret = 0;
		if (parser->state == SOLR_XML_RESPONSE_STATE_DOC) {
			T_BEGIN {
				ret = solr_lookup_add_doc(parser);
			} T_END;
		}
		parser->state--;
		if (ret < 0)
			parser->content_state = SOLR_XML_CONTENT_STATE_ERROR;
		else
			parser->content_state = SOLR_XML_CONTENT_STATE_NONE;
	}
	parser->depth--;
}

static void solr_lookup_xml_data(void *context, const char *str, int len)
{
	struct solr_response_parser *parser = context;

	switch (parser->content_state) {
	case SOLR_XML_CONTENT_STATE_NONE:
	case SOLR_XML_CONTENT_STATE_ERROR:
		/* ignore element data */
		return;
	case SOLR_XML_CONTENT_STATE_UID:
	case SOLR_XML_CONTENT_STATE_SCORE:
	case SOLR_XML_CONTENT_STATE_MAILBOX:
	case SOLR_XML_CONTENT_STATE_NAMESPACE:
	case SOLR_XML_CONTENT_STATE_UIDVALIDITY:
		break;
	}

	if (str_len(parser->buffer) + len > MAX_VALUE_LEN) {
		i_error("fts_solr: XML element data length out of range");
		parser->content_state = SOLR_XML_CONTENT_STATE_ERROR;
		return;
	}

	str_append_data(parser->buffer, str, len);
}

struct solr_response_parser *
solr_response_parser_init(pool_t result_pool, struct istream *input)
{
	struct solr_response_parser *parser;

	parser = i_new(struct solr_response_parser, 1);

	parser->xml_parser = XML_ParserCreate("UTF-8");
	if (parser->xml_parser == NULL) {
		i_fatal_status(FATAL_OUTOFMEM,
			       "fts_solr: Failed to allocate XML parser");
	}

	parser->buffer = str_new(default_pool, 256);
	hash_table_create(&parser->mailboxes, default_pool, 0,
			  str_hash, strcmp);

	parser->result_pool = result_pool;
	pool_ref(result_pool);
	p_array_init(&parser->results, result_pool, 32);

	parser->input = input;
	i_stream_ref(input);

	parser->xml_failed = FALSE;
	XML_SetElementHandler(parser->xml_parser,
			      solr_lookup_xml_start, solr_lookup_xml_end);
	XML_SetCharacterDataHandler(parser->xml_parser, solr_lookup_xml_data);
	XML_SetUserData(parser->xml_parser, parser);

	return parser;
}

void solr_response_parser_deinit(struct solr_response_parser **_parser)
{
	struct solr_response_parser *parser = *_parser;

	*_parser = NULL;

	if (parser == NULL)
		return;

	str_free(&parser->buffer);
	hash_table_destroy(&parser->mailboxes);
	XML_ParserFree(parser->xml_parser);
	i_stream_unref(&parser->input);
	pool_unref(&parser->result_pool);
	i_free(parser);
}

int solr_response_parse(struct solr_response_parser *parser,
			struct solr_result ***box_results_r)
{
	const unsigned char *data;
	size_t size;
	int stream_errno, ret;

	i_assert(parser->input != NULL);
	i_zero(box_results_r);

	/* read payload */
	while ((ret = i_stream_read_more(parser->input, &data, &size)) > 0) {
		(void)solr_xml_parse(parser, data, size, FALSE);
		i_stream_skip(parser->input, size);
	}

	if (ret == 0) {
		/* we will be called again for more data */
		return 0;
	}

	stream_errno = parser->input->stream_errno;
	i_stream_unref(&parser->input);

	if (parser->content_state == SOLR_XML_CONTENT_STATE_ERROR)
		return -1;
	if (stream_errno != 0)
		return -1;

	ret = solr_xml_parse(parser, "", 0, TRUE);

	array_append_zero(&parser->results);
	*box_results_r = array_front_modifiable(&parser->results);
	return (ret == 0 ? 1 : -1);
}

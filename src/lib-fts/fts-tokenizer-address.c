/* Copyright (c) 2015 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "buffer.h"
#include "rfc822-parser.h"
#include "fts-tokenizer-private.h"

#define IS_DTEXT(c) \
	(rfc822_atext_chars[(int)(unsigned char)(c)] == 2)

enum email_address_parser_state {
	EMAIL_ADDRESS_PARSER_STATE_NONE = 0,
	EMAIL_ADDRESS_PARSER_STATE_LOCALPART,
	EMAIL_ADDRESS_PARSER_STATE_DOMAIN,
	EMAIL_ADDRESS_PARSER_STATE_COMPLETE
};

struct email_address_fts_tokenizer {
	struct fts_tokenizer tokenizer;
	enum email_address_parser_state state;
	string_t *last_word;
	string_t *parent_data; /* Copy of input data between tokens. */
	bool search;
};

static int
fts_tokenizer_email_address_create(const char *const *settings,
				   struct fts_tokenizer **tokenizer_r,
				   const char **error_r)
{
	struct email_address_fts_tokenizer *tok;
	bool search = FALSE;
	unsigned int i;

	for (i = 0; settings[i] != NULL; i += 2) {
		const char *key = settings[i];

		if (strcmp(key, "search") == 0) {
			search = TRUE;
		} else {
			*error_r = t_strdup_printf("Unknown setting: %s", key);
			return -1;
		}
	}

	tok = i_new(struct email_address_fts_tokenizer, 1);
	tok->tokenizer = *fts_tokenizer_email_address;
	tok->last_word = str_new(default_pool, 128);
	tok->parent_data = str_new(default_pool, 128);
	tok->search = search;
	*tokenizer_r = &tok->tokenizer;
	return 0;
}

static void fts_tokenizer_email_address_destroy(struct fts_tokenizer *_tok)
{
	struct email_address_fts_tokenizer *tok =
		(struct email_address_fts_tokenizer *)_tok;

	str_free(&tok->last_word);
	str_free(&tok->parent_data);
	i_free(tok);
}

static void
fts_tokenizer_address_current_token(struct email_address_fts_tokenizer *tok,
                                    const char **token_r)
{
	tok->tokenizer.skip_parents = TRUE;
	tok->state = EMAIL_ADDRESS_PARSER_STATE_NONE;
	*token_r = t_strdup(str_c(tok->last_word));
}

static bool
fts_tokenizer_address_parent_data(struct email_address_fts_tokenizer *tok,
                                  const char **token_r)
{
	if (tok->tokenizer.parent == NULL || str_len(tok->parent_data) == 0)
		return FALSE;

	if (tok->search && tok->state >= EMAIL_ADDRESS_PARSER_STATE_DOMAIN) {
		/* we're searching and we want to find only the full
		   user@domain (not "user" and "domain"). we'll do this by
		   not feeding the last user@domain to parent tokenizer. */
		unsigned int parent_prefix_len =
			str_len(tok->parent_data) - str_len(tok->last_word);
		i_assert(str_len(tok->parent_data) >= str_len(tok->last_word) &&
			 strcmp(str_c(tok->parent_data) + parent_prefix_len,
				str_c(tok->last_word)) == 0);
		str_truncate(tok->parent_data, parent_prefix_len);
		if (str_len(tok->parent_data) == 0)
			return FALSE;
	}

	*token_r = t_strdup(str_c(tok->parent_data));
	str_truncate(tok->parent_data, 0);
	return TRUE;
}

/* Used to rewind past characters that can not be the start of a new localpart.
 Returns size that can be skipped. */
static size_t skip_nonlocal_part(const unsigned char *data, size_t size)
{
	size_t skip = 0;

	/* Yes, a dot can start an address. De facto before de jure. */
	while (skip < size && (!IS_ATEXT(data[skip]) && data[skip] != '.'))
		skip++;
	return skip;
}

static enum email_address_parser_state
fts_tokenizer_email_address_parse_local(struct email_address_fts_tokenizer *tok,
                                        const unsigned char *data, size_t size,
                                        size_t *skip_r)
{
	size_t pos = 0;
	bool seen_at = FALSE;

	while (pos < size && (IS_ATEXT(data[pos]) ||
			      data[pos] == '@' || data[pos] == '.')) {
		if (data[pos] == '@')
			seen_at = TRUE;
		pos++;
		if (seen_at)
			break;
	}
	 /* localpart and @ */
	if (seen_at && (pos > 1 || str_len(tok->last_word) > 0)) {
		str_append_n(tok->last_word, data, pos);
		*skip_r = pos;
		return EMAIL_ADDRESS_PARSER_STATE_DOMAIN;
	}

	/* localpart, @ not included yet */
	if (pos > 0 && (IS_ATEXT(data[pos-1]) || data[pos-1] == '.')) {
		str_append_n(tok->last_word, data, pos);
		*skip_r = pos;
		return  EMAIL_ADDRESS_PARSER_STATE_LOCALPART;
	}
	/* not a localpart. skip past rest of no-good chars. */
	pos += skip_nonlocal_part(data+pos, size - pos);
	*skip_r = pos;
	return EMAIL_ADDRESS_PARSER_STATE_NONE;
}

static bool domain_is_empty(struct email_address_fts_tokenizer *tok)
{
	const char *p, *str = str_c(tok->last_word);

	if ((p = strchr(str, '@')) == NULL)
		return TRUE;
	return p[1] == '\0';
}

static enum email_address_parser_state
fts_tokenizer_email_address_parse_domain(struct email_address_fts_tokenizer *tok,
                                         const unsigned char *data, size_t size,
                                         size_t *skip_r)
{
	size_t pos = 0;

	while (pos < size && (IS_DTEXT(data[pos]) || data[pos] == '.'))
		pos++;
	 /* A complete domain name */
	if ((pos > 1 && pos < size) || /* non-atext after atext in this data*/
	    (pos < size && !domain_is_empty(tok))) { /* non-atext after previous atext */
		str_append_n(tok->last_word, data, pos);
		*skip_r = pos;
		return EMAIL_ADDRESS_PARSER_STATE_COMPLETE;
	}
	if (pos == size) { /* All good, but possibly not complete. */
		str_append_n(tok->last_word, data, pos);
		*skip_r = pos;
		return EMAIL_ADDRESS_PARSER_STATE_DOMAIN;
	}
	/* not a domain. skip past no-good chars. */
	pos += skip_nonlocal_part(data + pos, size - pos);
	*skip_r = pos;
	return EMAIL_ADDRESS_PARSER_STATE_NONE;
}

/* Buffer raw data for parent. */
static void
fts_tokenizer_address_update_parent(struct email_address_fts_tokenizer *tok,
                                    const unsigned char *data, size_t size)
{
	if (tok->tokenizer.parent != NULL)
		str_append_n(tok->parent_data, data, size);
}

static void fts_tokenizer_email_address_reset(struct fts_tokenizer *_tok)
{
	struct email_address_fts_tokenizer *tok =
		(struct email_address_fts_tokenizer *)_tok;

	tok->state = EMAIL_ADDRESS_PARSER_STATE_NONE;
	str_truncate(tok->last_word, 0);
	str_truncate(tok->parent_data, 0);
}

static int
fts_tokenizer_email_address_next(struct fts_tokenizer *_tok,
                                 const unsigned char *data, size_t size,
				 size_t *skip_r, const char **token_r,
				 const char **error_r ATTR_UNUSED)
{
	struct email_address_fts_tokenizer *tok =
		(struct email_address_fts_tokenizer *)_tok;
	size_t pos = 0, local_skip;

	if (tok->tokenizer.skip_parents == TRUE)
		tok->tokenizer.skip_parents = FALSE;

	if (tok->state == EMAIL_ADDRESS_PARSER_STATE_COMPLETE) {
		*skip_r = pos;
		fts_tokenizer_address_current_token(tok, token_r);
		return 1;
	}

	/* end of data, output lingering tokens. first the parents data, then
	   possibly our token, if complete enough */
	if (size == 0) {
		if (tok->state == EMAIL_ADDRESS_PARSER_STATE_DOMAIN &&
		    domain_is_empty(tok)) {
			/* user@ without domain - reset state */
			str_truncate(tok->last_word, 0);
			tok->state = EMAIL_ADDRESS_PARSER_STATE_NONE;
		}

		if (fts_tokenizer_address_parent_data(tok, token_r))
			return 1;

		if (tok->state == EMAIL_ADDRESS_PARSER_STATE_DOMAIN) {
			fts_tokenizer_address_current_token(tok, token_r);
			return 1;
		}
		tok->state = EMAIL_ADDRESS_PARSER_STATE_NONE;
	}

	/* 1) regular input data OR
	   2) circle around to return completed address */
	while(pos < size || tok->state == EMAIL_ADDRESS_PARSER_STATE_COMPLETE) {

		switch (tok->state) {
		case EMAIL_ADDRESS_PARSER_STATE_NONE:
			/* no part of address found yet. remove possible
			   earlier data */
			str_truncate(tok->last_word, 0);

			/* fall through */
		case EMAIL_ADDRESS_PARSER_STATE_LOCALPART:
			/* last_word is empty or has the beginnings of a valid
			   local-part, but no '@' found yet. continue parsing
			   the beginning of data to see if it contains a full
			   local-part@ */
			tok->state =
				fts_tokenizer_email_address_parse_local(tok,
				                                        data + pos,
				                                        size - pos,
				                                        &local_skip);
			fts_tokenizer_address_update_parent(tok, data+pos,
			                                    local_skip);
			pos += local_skip;

			break;
		case EMAIL_ADDRESS_PARSER_STATE_DOMAIN:
			/* last_word has a local-part@ and maybe the beginning
			   of a domain. continue parsing the beginning of data
			   to see if it contains a valid domain. */

			tok->state =
				fts_tokenizer_email_address_parse_domain(tok,
				                                        data + pos,
				                                        size - pos,
				                                        &local_skip);
			fts_tokenizer_address_update_parent(tok, data+pos,
			                                    local_skip);
			pos += local_skip;

			break;
		case EMAIL_ADDRESS_PARSER_STATE_COMPLETE:
			*skip_r = pos;
			if (!fts_tokenizer_address_parent_data(tok, token_r))
				fts_tokenizer_address_current_token(tok, token_r);
			return 1;
		default:
			i_unreached();
		}

	}
	*skip_r = pos;
	return 0;
}

static const struct fts_tokenizer_vfuncs email_address_tokenizer_vfuncs = {
	fts_tokenizer_email_address_create,
	fts_tokenizer_email_address_destroy,
	fts_tokenizer_email_address_reset,
	fts_tokenizer_email_address_next
};

static const struct fts_tokenizer fts_tokenizer_email_address_real = {
	.name = "email-address",
	.v = &email_address_tokenizer_vfuncs
};
const struct fts_tokenizer *fts_tokenizer_email_address =
	&fts_tokenizer_email_address_real;

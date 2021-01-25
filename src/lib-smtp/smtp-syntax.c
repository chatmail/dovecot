/* Copyright (c) 2013-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "array.h"
#include "smtp-parser.h"

#include "smtp-syntax.h"

#include <ctype.h>

/*
 * String
 */

int smtp_string_parse(const char *string, const char **value_r,
		      const char **error_r)
{
	struct smtp_parser parser;

	*value_r = NULL;
	*error_r = NULL;

	if (string == NULL || *string == '\0') {
		*value_r = "";
		return 0;
	}

	smtp_parser_init(&parser, pool_datastack_create(), string);

	if (smtp_parser_parse_string(&parser, value_r) < 0) {
		*error_r = parser.error;
		return -1;
	}
	if (parser.cur < parser.end) {
		*error_r = "Invalid character in string";
		return -1;
	}
	return 1;
}

void smtp_string_write(string_t *out, const char *value)
{
	bool quoted = FALSE;
	const unsigned char *p, *pend, *pblock;
	size_t begin = str_len(out);

	if (value == NULL)
		return;
	p = (const unsigned char *)value;
	pend = p + strlen(value);
	while (p < pend) {
		pblock = p;
		while (p < pend && smtp_char_is_atext(*p))
			p++;

		if (!quoted && p < pend) {
			quoted = TRUE;
			str_insert(out, begin, "\"");
		}

		str_append_data(out, pblock, p-pblock);
		if (p >= pend)
			break;

		i_assert(quoted);
		i_assert(smtp_char_is_qpair(*p));

		if (!smtp_char_is_qtext(*p))
			str_append_c(out, '\\');
		str_append_c(out, *p);

		p++;
	}

	if (quoted)
		str_append_c(out, '\"');
}

/*
 * Xtext encoding
 */

int smtp_xtext_decode(string_t *out, const char *xtext, bool allow_nul,
		      const char **error_r)
{
	struct smtp_parser parser;

	if (xtext == NULL || *xtext == '\0')
		return 1;

	smtp_parser_init(&parser, pool_datastack_create(), xtext);

	if (smtp_parser_parse_xtext(&parser, out) < 0) {
		*error_r = parser.error;
		return -1;
	}
	if (parser.cur < parser.end) {
		*error_r = "Invalid character in xtext";
		return -1;
	}
	if (!allow_nul && strlen(str_c(out)) != str_len(out)) {
		*error_r = "Encountered NUL character in xtext";
		return -1;
	}
	return 1;
}

int smtp_xtext_parse(const char *xtext, const char **value_r,
		     const char **error_r)
{
	string_t *value;
	int ret;

	*value_r = NULL;
	*error_r = NULL;

	if (xtext == NULL || *xtext == '\0') {
		*value_r = "";
		return 1;
	}

	value = t_str_new(256);
	ret = smtp_xtext_decode(value, xtext, FALSE, error_r);
	if (ret <= 0)
		return ret;

	*value_r = str_c(value);
	return 1;
}

void smtp_xtext_encode(string_t *out, const unsigned char *data, size_t size)
{
	const unsigned char *p, *pbegin, *pend;

	p = data;
	pend = p + size;
	while (p < pend) {
		pbegin = p;
		while (p < pend && smtp_char_is_xtext(*p))
			p++;

		str_append_data(out, pbegin, p-pbegin);
		if (p >= pend)
			break;

		str_printfa(out, "+%02X", (unsigned int)*p);
		p++;
	}
}

/*
 * HELO domain
 */

int smtp_helo_domain_parse(const char *helo, bool allow_literal,
			   const char **domain_r)
{
	struct smtp_parser parser;
	int ret;

	smtp_parser_init(&parser, pool_datastack_create(), helo);

	ret = smtp_parser_parse_domain(&parser, domain_r);
	if (ret == 0) {
		if (allow_literal) {
			ret = smtp_parser_parse_address_literal(
				&parser, domain_r, NULL);
		}
	}

	if (ret <= 0 || (parser.cur < parser.end && *parser.cur != ' '))
		return -1;
	return 0;
}

/*
 * EHLO reply
 */

bool smtp_ehlo_keyword_is_valid(const char *keyword)
{
	const char *p;

	for (p = keyword; *p != '\0'; p++) {
		if (!i_isalnum(*p))
			return FALSE;
	}
	return TRUE;
}

bool smtp_ehlo_param_is_valid(const char *param)
{
	const char *p;

	for (p = param; *p != '\0'; p++) {
		if (!smtp_char_is_ehlo_param(*p))
			return FALSE;
	}
	return TRUE;
}

bool smtp_ehlo_params_are_valid(const char *const *params)
{
	if (params == NULL)
		return TRUE;

	while (*params != NULL) {
		if (!smtp_ehlo_param_is_valid(*params))
			return FALSE;
		params++;
	}

	return TRUE;
}

bool smtp_ehlo_params_str_is_valid(const char *params)
{
	const char *p;
	bool space = FALSE;

	for (p = params; *p != '\0'; p++) {
		if (*p == ' ') {
			if (space)
				return FALSE;
			space = TRUE;
			continue;
		}
		space = FALSE;

		if (!smtp_char_is_ehlo_param(*p))
			return FALSE;
	}
	return TRUE;
}

static int
smtp_parse_ehlo_line(struct smtp_parser *parser, const char **key_r,
		     const char *const **params_r)
{
	const unsigned char *pbegin = parser->cur;
	ARRAY_TYPE(const_string) params = ARRAY_INIT;
	const char *param;

	/* ehlo-line      = ehlo-keyword *( SP ehlo-param )
	   ehlo-keyword   = (ALPHA / DIGIT) *(ALPHA / DIGIT / "-")
	                    ; additional syntax of ehlo-params depends on
	                    ; ehlo-keyword
	   ehlo-param     = 1*(%d33-126)
	                    ; any CHAR excluding <SP> and all
	                    ; control characters (US-ASCII 0-31 and 127
	                    ; inclusive)
	 */

	if (parser->cur >= parser->end || !i_isalnum(*parser->cur)) {
		parser->error = "Unexpected character in EHLO keyword";
		return -1;
	}
	parser->cur++;

	while (parser->cur < parser->end &&
	       (i_isalnum(*parser->cur) || *parser->cur == '-'))
		parser->cur++;

	*key_r = p_strdup_until(parser->pool, pbegin, parser->cur);

	if (parser->cur >= parser->end) {
		*params_r = p_new(parser->pool, const char *, 1);
		return 1;
	}
	if (*parser->cur != ' ') {
		parser->error = "Unexpected character in EHLO keyword";
		return -1;
	}
	parser->cur++;

	pbegin = parser->cur;
	p_array_init(&params, parser->pool, 32);
	while (parser->cur < parser->end) {
		if (*parser->cur == ' ') {
			if (parser->cur+1 >= parser->end ||
			    *(parser->cur+1) == ' ') {
				parser->error =
					"Missing EHLO parameter after ' '";
				return -1;
			}
			param = p_strdup_until(parser->pool, pbegin,
					       parser->cur);
			array_push_back(&params, &param);
			pbegin = parser->cur + 1;
		} else if (!smtp_char_is_ehlo_param(*parser->cur)) {
			parser->error =
				"Unexpected character in EHLO parameter";
			return -1;
		}
		parser->cur++;
	}

	param = p_strdup_until(parser->pool, pbegin, parser->cur);
	array_push_back(&params, &param);
	array_append_zero(&params);
	*params_r = array_front(&params);
	return 1;
}

int smtp_ehlo_line_parse(const char *ehlo_line, const char **key_r,
			 const char *const **params_r, const char **error_r)
{
	struct smtp_parser parser;

	*key_r = NULL;
	*params_r = NULL;
	*error_r = NULL;

	if (ehlo_line == NULL || *ehlo_line == '\0') {
		*error_r = "Parameter is empty";
		return -1;
	}

	smtp_parser_init(&parser, pool_datastack_create(), ehlo_line);

	if (smtp_parse_ehlo_line(&parser, key_r, params_r) <= 0) {
		*error_r = parser.error;
		return -1;
	}
	return 1;
}

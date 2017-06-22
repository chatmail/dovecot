/* Copyright (c) 2015-2017 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "rfc822-parser.h"
#include "test-common.h"

static void test_rfc822_parse_quoted_string(void)
{
	const struct {
		const char *input, *output;
		int ret;
	} tests[] = {
		{ "\"", "", -1 },
		{ "\"\"", "", 0 },
		{ "\"foo\"", "foo", 0 },
		{ "\"\"foo", "", 1 },
		{ "\"\"\"", "", 1 },
		{ "\"\\\"\"", "\"", 0 },
		{ "\"\\\\\"", "\\", 0 },
		{ "\"\\\\foo\\\\foo\\\\\"", "\\foo\\foo\\", 0 }
	};
	struct rfc822_parser_context parser;
	string_t *str = t_str_new(64);
	unsigned int i = 0;

	test_begin("rfc822 parse quoted string");
	for (i = 0; i < N_ELEMENTS(tests); i++) {
		rfc822_parser_init(&parser, (const void *)tests[i].input,
				   strlen(tests[i].input), NULL);
		test_assert_idx(rfc822_parse_quoted_string(&parser, str) == tests[i].ret, i);
		test_assert_idx(tests[i].ret < 0 ||
				strcmp(tests[i].output, str_c(str)) == 0, i);
		str_truncate(str, 0);
	}
	test_end();
}

static void test_rfc822_parse_content_param(void)
{
	const char *input =
		"; key1=value1#$!%&'*+-.^_`{|}~"
		"; key2=\" \\\"(),/:;<=>?@[\\\\]\"";
	const struct {
		const char *key, *value;
	} output[] = {
		{ "key1", "value1#$!%&'*+-.^_`{|}~" },
		{ "key2", " \"(),/:;<=>?@[\\]" }
	};
	struct rfc822_parser_context parser;
	const char *key, *value;
	unsigned int i = 0;
	int ret;

	test_begin("rfc822 parse content param");
	rfc822_parser_init(&parser, (const void *)input, strlen(input), NULL);
	while ((ret = rfc822_parse_content_param(&parser, &key, &value)) > 0 &&
	       i < N_ELEMENTS(output)) {
		test_assert_idx(strcmp(output[i].key, key) == 0, i);
		test_assert_idx(strcmp(output[i].value, value) == 0, i);
		i++;
	}
	test_assert(ret == 0);
	test_assert(i == N_ELEMENTS(output));
	test_end();
}

int main(void)
{
	static void (*test_functions[])(void) = {
		test_rfc822_parse_quoted_string,
		test_rfc822_parse_content_param,
		NULL
	};
	return test_run(test_functions);
}

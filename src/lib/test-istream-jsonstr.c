/* Copyright (c) 2016-2018 Dovecot authors, see the included COPYING file */

#include "test-lib.h"
#include "str.h"
#include "istream-private.h"
#include "istream-jsonstr.h"

static const struct {
	const char *input;
	const char *output;
	int stream_errno;
} tests[] = {
	{ "foo\\\\\\\"\\b\\f\\n\\r\\t\\u0001\\uffff\"",
	  "foo\\\"\b\f\n\r\t\001\xEF\xBF\xBF", 0 },
	{ "\\ud801\\udc37\"", "\xf0\x90\x90\xb7", 0 }, /* valid codepoint */
	{ "\"", "", 0 },
	{ "foo\\?\"", "foo", EINVAL },
	{ "foo\\?\"", "foo", EINVAL },
	{ "", "", EPIPE },
	{ "\\\"", "\"", EPIPE },
	{ "foo", "foo", EPIPE },
	{ "\\ud801", "", EPIPE }, /* high surrogate alone */
	{ "\\udced\\udc37\"", "", EINVAL }, /* low surrogate before high */
	{ "\\ud8011\\udc37\"", "", EINVAL }, /* has extra 1 in middle */
	{ "hello \\udc37\"", "hello ", EINVAL }, /* low surrogate before high with valid prefix*/
	{ "hello \\ud801", "hello ", EPIPE }, /* high surrogate alone with valid prefix */
	{ "\\uabcg", "", EINVAL }, /* invalid hex value */
};

static void
run_test_buffer(const char *json_input, const char *output, int stream_errno,
		unsigned int skip_count)
{
	size_t json_input_len = strlen(json_input);
	struct istream *input_data, *input;
	const unsigned char *data;
	size_t i, size;
	ssize_t ret = 0;

	input_data = test_istream_create_data(json_input, json_input_len);
	test_istream_set_allow_eof(input_data, FALSE);
	input = i_stream_create_jsonstr(input_data);

	for (i = 1; i < json_input_len;) {
		test_istream_set_size(input_data, i);
		while ((ret = i_stream_read(input)) > 0) ;
		if (ret == -1 && stream_errno != 0)
			break;
		test_assert_idx(ret == 0, i);
		if (i + skip_count < json_input_len)
			i += skip_count;
		else
			i++;
	}
	test_istream_set_allow_eof(input_data, TRUE);
	test_istream_set_size(input_data, json_input_len);
	ret = i_stream_read(input);
	while (ret > 0 && stream_errno != 0)
		ret = i_stream_read(input);
	test_assert(ret == -1);
	test_assert(input->stream_errno == stream_errno);

	if (stream_errno == 0) {
		data = i_stream_get_data(input, &size);
		test_assert(size == strlen(output));
		if (size > 0)
			test_assert(memcmp(data, output, size) == 0);
	}
	i_stream_unref(&input);
	i_stream_unref(&input_data);
}

static void
run_test(const char *json_input, const char *output, int stream_errno)
{
	for (unsigned int i = 1; i <= 5; i++)
		run_test_buffer(json_input, output, stream_errno, i);
}

static void test_istream_jsonstr_autoretry(void)
{
	const char *json_input = "\\u0001\"";
	const size_t json_input_len = strlen(json_input);
	struct istream *input_data, *input;

	test_begin("istream-jsonstr autoretry");
	input_data = test_istream_create_data(json_input, json_input_len);
	input = i_stream_create_jsonstr(input_data);

	test_istream_set_size(input_data, 2);
	test_assert(i_stream_read(input_data) == 2);
	test_istream_set_size(input_data, json_input_len);
	test_assert(i_stream_read(input) == 1);
	test_assert(i_stream_read(input) == -1);

	i_stream_unref(&input);
	i_stream_unref(&input_data);
	test_end();
}

static void test_istream_jsonstr_partial(void)
{
	size_t len = 0;
	const char *json_input = "hello\\u0060x\"";
	const char *output = "hello`x";
	const size_t json_input_len = strlen(json_input);
	struct istream *input_data, *input;

	test_begin("istream-jsonstr partial");

	input_data = test_istream_create_data(json_input, json_input_len);
	input = i_stream_create_jsonstr(input_data);
	test_istream_set_size(input_data, 9);
	test_assert(i_stream_read(input) == 5);
	test_istream_set_size(input_data, json_input_len);
	test_assert(i_stream_read(input) == 2);
	test_assert(i_stream_read(input) == -1);

	test_assert(memcmp(i_stream_get_data(input, &len), output, I_MIN(len, strlen(output))) == 0 &&
		    len == strlen(output));

	i_stream_unref(&input);
	i_stream_unref(&input_data);

	test_end();
}

void test_istream_jsonstr(void)
{
	unsigned int i;

	for (i = 0; i < N_ELEMENTS(tests); i++) {
		test_begin(t_strdup_printf("istream-jsonstr %u", i+1));
		run_test(tests[i].input, tests[i].output, tests[i].stream_errno);
		test_end();
	}
	test_istream_jsonstr_autoretry();
	test_istream_jsonstr_partial();
}

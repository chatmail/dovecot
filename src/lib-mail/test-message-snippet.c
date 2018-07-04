/* Copyright (c) 2015-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "istream.h"
#include "message-snippet.h"
#include "test-common.h"

static const struct {
	const char *input;
	unsigned int max_snippet_chars;
	const char *output;
} tests[] = {
	{ "Content-Type: text/plain\n"
	  "\n"
	  "1234567890 234567890",
	  12,
	  "1234567890 2" },
	{ "Content-Type: text/plain\n"
	  "\n"
	  "line1\n>quote2\nline2\n",
	  100,
	  "line1 line2" },
	{ "Content-Type: text/plain\n"
	  "\n"
	  "line1\n>quote2\n> quote3\n > line4\n\n  \t\t  \nline5\n  \t ",
	  100,
	  "line1 > line4 line5" },
	{ "Content-Type: text/plain; charset=utf-8\n"
	  "\n"
	  "hyv\xC3\xA4\xC3\xA4 p\xC3\xA4iv\xC3\xA4\xC3\xA4",
	  11,
	  "hyv\xC3\xA4\xC3\xA4 p\xC3\xA4iv\xC3\xA4" },
	{ "Content-Type: text/plain; charset=utf-8\n"
	  "Content-Transfer-Encoding: quoted-printable\n"
	  "\n"
	  "hyv=C3=A4=C3=A4 p=C3=A4iv=C3=A4=C3=A4",
	  11,
	  "hyv\xC3\xA4\xC3\xA4 p\xC3\xA4iv\xC3\xA4" },

	{ "Content-Transfer-Encoding: quoted-printable\n"
	  "Content-Type: text/html;\n"
	  "      charset=utf-8\n"
	  "\n"
	  "<html><head><meta http-equiv=3D\"Content-Type\" content=3D\"text/html =\n"
	  "charset=3Dutf-8\"></head><body style=3D\"word-wrap: break-word; =\n"
	  "-webkit-nbsp-mode: space; -webkit-line-break: after-white-space;\" =\n"
	  "class=3D\"\">Hi,<div class=3D\"\"><br class=3D\"\"></div><div class=3D\"\">How =\n"
	  "is it going? <blockquote>quoted text is ignored</blockquote>\n"
	  "&gt; -foo\n"
	  "</div><br =class=3D\"\"></body></html>=\n",
	  100,
	  "Hi, How is it going? > -foo" },

	{ "Content-Transfer-Encoding: quoted-printable\n"
	  "Content-Type: application/xhtml+xml;\n"
	  "      charset=utf-8\n"
	  "\n"
	  "<html><head><meta http-equiv=3D\"Content-Type\" content=3D\"text/html =\n"
	  "charset=3Dutf-8\"></head><body style=3D\"word-wrap: break-word; =\n"
	  "-webkit-nbsp-mode: space; -webkit-line-break: after-white-space;\" =\n"
	  "class=3D\"\">Hi,<div class=3D\"\"><br class=3D\"\"></div><div class=3D\"\">How =\n"
	  "is it going? <blockquote>quoted text is ignored</blockquote>\n"
	  "&gt; -foo\n"
	  "</div><br =class=3D\"\"></body></html>=\n",
	  100,
	  "Hi, How is it going? > -foo" },
};

static void test_message_snippet(void)
{
	string_t *str = t_str_new(128);
	struct istream *input;
	unsigned int i;

	test_begin("message snippet");
	for (i = 0; i < N_ELEMENTS(tests); i++) {
		str_truncate(str, 0);
		input = i_stream_create_from_data(tests[i].input, strlen(tests[i].input));
		test_assert_idx(message_snippet_generate(input, tests[i].max_snippet_chars, str) == 0, i);
		test_assert_idx(strcmp(tests[i].output, str_c(str)) == 0, i);
		i_stream_destroy(&input);
	}
	test_end();
}

int main(void)
{
	static void (*const test_functions[])(void) = {
		test_message_snippet,
		NULL
	};
	return test_run(test_functions);
}

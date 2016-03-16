/* Copyright (c) 2007-2016 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "istream.h"
#include "message-parser.h"
#include "test-common.h"

static const char test_msg[] =
"Return-Path: <test@example.org>\n"
"Subject: Hello world\n"
"From: Test User <test@example.org>\n"
"To: Another User <test2@example.org>\n"
"Message-Id: <1.2.3.4@example>\n"
"Mime-Version: 1.0\n"
"Date: Sun, 23 May 2007 04:58:08 +0300\n"
"Content-Type: multipart/signed; micalg=pgp-sha1;\n"
"	protocol=\"application/pgp-signature\";\n"
"	boundary=\"=-GNQXLhuj24Pl1aCkk4/d\"\n"
"\n"
"--=-GNQXLhuj24Pl1aCkk4/d\n"
"Content-Type: text/plain\n"
"Content-Transfer-Encoding: quoted-printable\n"
"\n"
"There was a day=20\n"
"a happy=20day\n"
"\n"
"--=-GNQXLhuj24Pl1aCkk4/d\n"
"Content-Type: application/pgp-signature; name=signature.asc\n"
"\n"
"-----BEGIN PGP SIGNATURE-----\n"
"Version: GnuPG v1.2.4 (GNU/Linux)\n"
"\n"
"invalid\n"
"-----END PGP SIGNATURE-----\n"
"\n"
"--=-GNQXLhuj24Pl1aCkk4/d--\n"
"\n"
"\n";
#define TEST_MSG_LEN (sizeof(test_msg)-1)

static bool msg_parts_cmp(struct message_part *p1, struct message_part *p2)
{
	while (p1 != NULL || p2 != NULL) {
		if ((p1 != NULL) != (p2 != NULL))
			return FALSE;
		if ((p1->children != NULL) != (p2->children != NULL))
			return FALSE;

		if (p1->children) {
			if (!msg_parts_cmp(p1->children, p2->children))
				return FALSE;
		}

		if (p1->physical_pos != p2->physical_pos ||
		    p1->header_size.physical_size != p2->header_size.physical_size ||
		    p1->header_size.virtual_size != p2->header_size.virtual_size ||
		    p1->header_size.lines != p2->header_size.lines ||
		    p1->body_size.physical_size != p2->body_size.physical_size ||
		    p1->body_size.virtual_size != p2->body_size.virtual_size ||
		    p1->body_size.lines != p2->body_size.lines ||
		    p1->flags != p2->flags)
			return FALSE;

		p1 = p1->next;
		p2 = p2->next;
	}
	return TRUE;
}

static void test_message_parser_small_blocks(void)
{
	struct message_parser_ctx *parser;
	struct istream *input;
	struct message_part *parts, *parts2;
	struct message_block block;
	unsigned int i, end_of_headers_idx;
	string_t *output;
	pool_t pool;
	int ret;

	test_begin("message parser in small blocks");
	pool = pool_alloconly_create("message parser", 10240);
	input = test_istream_create(test_msg);
	output = t_str_new(128);

	/* full parsing */
	parser = message_parser_init(pool, input, 0,
		MESSAGE_PARSER_FLAG_INCLUDE_MULTIPART_BLOCKS |
		MESSAGE_PARSER_FLAG_INCLUDE_BOUNDARIES);
	while ((ret = message_parser_parse_next_block(parser, &block)) > 0) {
		if (block.hdr != NULL)
			message_header_line_write(output, block.hdr);
		else
			str_append_n(output, block.data, block.size);
	}

	test_assert(ret < 0);
	test_assert(message_parser_deinit(&parser, &parts) == 0);
	test_assert(strcmp(test_msg, str_c(output)) == 0);

	/* parsing in small blocks */
	i_stream_seek(input, 0);
	test_istream_set_allow_eof(input, FALSE);

	parser = message_parser_init(pool, input, 0, 0);
	for (i = 1; i <= TEST_MSG_LEN*2+1; i++) {
		test_istream_set_size(input, i/2);
		if (i > TEST_MSG_LEN*2)
			test_istream_set_allow_eof(input, TRUE);
		while ((ret = message_parser_parse_next_block(parser,
							      &block)) > 0) ;
		test_assert((ret == 0 && i <= TEST_MSG_LEN*2) ||
			    (ret < 0 && i > TEST_MSG_LEN*2));
	}
	test_assert(message_parser_deinit(&parser, &parts2) == 0);
	test_assert(msg_parts_cmp(parts, parts2));

	/* parsing in small blocks from preparsed parts */
	i_stream_seek(input, 0);
	test_istream_set_allow_eof(input, FALSE);

	end_of_headers_idx = (strstr(test_msg, "\n-----") - test_msg);
	parser = message_parser_init_from_parts(parts, input, 0,
					MESSAGE_PARSER_FLAG_SKIP_BODY_BLOCK);
	for (i = 1; i <= TEST_MSG_LEN*2+1; i++) {
		test_istream_set_size(input, i/2);
		if (i > TEST_MSG_LEN*2)
			test_istream_set_allow_eof(input, TRUE);
		while ((ret = message_parser_parse_next_block(parser,
							      &block)) > 0) ;
		test_assert((ret == 0 && i/2 <= end_of_headers_idx) ||
			    (ret < 0 && i/2 > end_of_headers_idx));
	}
	test_assert(message_parser_deinit(&parser, &parts2) == 0);
	test_assert(msg_parts_cmp(parts, parts2));

	i_stream_unref(&input);
	pool_unref(&pool);
	test_end();
}

static void test_message_parser_truncated_mime_headers(void)
{
static const char input_msg[] =
"Content-Type: multipart/mixed; boundary=\":foo\"\n"
"\n"
"--:foo\n"
"--:foo\n"
"Content-Type: text/plain\n"
"--:foo\n"
"Content-Type: text/plain\r\n"
"--:foo\n"
"Content-Type: text/html\n"
"--:foo--\n";
	struct message_parser_ctx *parser;
	struct istream *input;
	struct message_part *parts, *part;
	struct message_block block;
	pool_t pool;
	int ret;

	test_begin("message parser truncated mime headers");
	pool = pool_alloconly_create("message parser", 10240);
	input = test_istream_create(input_msg);

	parser = message_parser_init(pool, input, 0, 0);
	while ((ret = message_parser_parse_next_block(parser, &block)) > 0) ;
	test_assert(ret < 0);
	test_assert(message_parser_deinit(&parser, &parts) == 0);

	test_assert((parts->flags & MESSAGE_PART_FLAG_MULTIPART) != 0);
	test_assert(parts->body_size.lines == 8);
	test_assert(parts->body_size.physical_size == 112);
	test_assert(parts->body_size.virtual_size == 112+7);
	test_assert(parts->children->header_size.physical_size == 0);
	test_assert(parts->children->body_size.physical_size == 0);
	test_assert(parts->children->body_size.lines == 0);
	test_assert(parts->children->next->header_size.physical_size == 24);
	test_assert(parts->children->next->header_size.virtual_size == 24);
	test_assert(parts->children->next->header_size.lines == 0);
	test_assert(parts->children->next->next->header_size.physical_size == 24);
	test_assert(parts->children->next->next->header_size.virtual_size == 24);
	test_assert(parts->children->next->next->header_size.lines == 0);
	test_assert(parts->children->next->next->next->header_size.physical_size == 23);
	test_assert(parts->children->next->next->next->header_size.virtual_size == 23);
	test_assert(parts->children->next->next->next->header_size.lines == 0);
	for (part = parts->children; part != NULL; part = part->next) {
		test_assert(part->body_size.physical_size == 0);
		test_assert(part->body_size.virtual_size == 0);
	}
	test_assert(parts->children->next->next->next->next == NULL);

	i_stream_unref(&input);
	pool_unref(&pool);
	test_end();
}

static void test_message_parser_no_eoh(void)
{
	static const char input_msg[] = "a:b\n";
	struct message_parser_ctx *parser;
	struct istream *input;
	struct message_part *parts;
	struct message_block block;
	pool_t pool;

	test_begin("message parser no EOH");
	pool = pool_alloconly_create("message parser", 10240);
	input = test_istream_create(input_msg);

	parser = message_parser_init(pool, input, 0, 0);
	test_assert(message_parser_parse_next_block(parser, &block) > 0 &&
		    block.hdr != NULL && strcmp(block.hdr->name, "a") == 0 &&
		    block.hdr->value_len == 1 && block.hdr->value[0] == 'b');
	test_assert(message_parser_parse_next_block(parser, &block) > 0 &&
		    block.hdr == NULL && block.size == 0);
	test_assert(message_parser_parse_next_block(parser, &block) < 0);
	test_assert(message_parser_deinit(&parser, &parts) == 0);

	i_stream_unref(&input);
	pool_unref(&pool);
	test_end();
}

int main(void)
{
	static void (*test_functions[])(void) = {
		test_message_parser_small_blocks,
		test_message_parser_truncated_mime_headers,
		test_message_parser_no_eoh,
		NULL
	};
	return test_run(test_functions);
}

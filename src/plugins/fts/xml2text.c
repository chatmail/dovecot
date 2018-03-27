/* Copyright (c) 2011-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "message-parser.h"
#include "fts-parser.h"

#include <unistd.h>

int main(void)
{
	struct fts_parser *parser;
	unsigned char buf[IO_BLOCK_SIZE];
	struct message_block block;
	ssize_t ret;
	struct fts_parser_context parser_context = {.content_type = "text/html"};

	lib_init();

	parser = fts_parser_html.try_init(&parser_context);
	i_assert(parser != NULL);

	i_zero(&block);
	while ((ret = read(STDIN_FILENO, buf, sizeof(buf))) > 0) {
		block.data = buf;
		block.size = ret;
		parser->v.more(parser, &block);
		if (write(STDOUT_FILENO, block.data, block.size) < 0)
			i_fatal("write(stdout) failed: %m");
	}
	if (ret < 0)
		i_fatal("read(stdin) failed: %m");

	for (;;) {
		block.size = 0;
		parser->v.more(parser, &block);
		if (block.size == 0)
			break;
		if (write(STDOUT_FILENO, block.data, block.size) < 0)
			i_fatal("write(stdout) failed: %m");
	}

	lib_deinit();
	return 0;
}

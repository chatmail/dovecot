/* Copyright (c) 2002-2010 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "str.h"
#include "strescape.h"
#include "mail-types.h"
#include "imap-parser.h"
#include "imap-util.h"

void imap_write_flags(string_t *dest, enum mail_flags flags,
		      const char *const *keywords)
{
	size_t size;

	size = str_len(dest);
	if ((flags & MAIL_ANSWERED) != 0)
		str_append(dest, "\\Answered ");
	if ((flags & MAIL_FLAGGED) != 0)
		str_append(dest, "\\Flagged ");
	if ((flags & MAIL_DELETED) != 0)
		str_append(dest, "\\Deleted ");
	if ((flags & MAIL_SEEN) != 0)
		str_append(dest, "\\Seen ");
	if ((flags & MAIL_DRAFT) != 0)
		str_append(dest, "\\Draft ");
	if ((flags & MAIL_RECENT) != 0)
		str_append(dest, "\\Recent ");

	if (keywords != NULL) {
		/* we have keywords too */
		while (*keywords != NULL) {
			str_append(dest, *keywords);
			str_append_c(dest, ' ');
			keywords++;
		}
	}

	if (str_len(dest) != size)
		str_truncate(dest, str_len(dest)-1);
}

void imap_write_seq_range(string_t *dest, const ARRAY_TYPE(seq_range) *array)
{
	const struct seq_range *range;
	unsigned int i, count;

	range = array_get(array, &count);
	for (i = 0; i < count; i++) {
		if (i > 0)
			str_append_c(dest, ',');
		str_printfa(dest, "%u", range[i].seq1);
		if (range[i].seq1 != range[i].seq2)
			str_printfa(dest, ":%u", range[i].seq2);
	}
}

void imap_write_args(string_t *dest, const struct imap_arg *args)
{
	const ARRAY_TYPE(imap_arg_list) *list;
	bool first = TRUE;

	for (; args->type != IMAP_ARG_EOL; args++) {
		if (first)
			first = FALSE;
		else
			str_append_c(dest, ' ');

		switch (args->type) {
		case IMAP_ARG_NIL:
			str_append(dest, "NIL");
			break;
		case IMAP_ARG_ATOM:
			str_append(dest, IMAP_ARG_STR(args));
			break;
		case IMAP_ARG_STRING:
			str_append_c(dest, '"');
			str_append(dest, str_escape(IMAP_ARG_STR(args)));
			str_append_c(dest, '"');
			break;
		case IMAP_ARG_LITERAL: {
			const char *strarg = IMAP_ARG_STR(args);
			str_printfa(dest, "{%"PRIuSIZE_T"}\r\n",
				    strlen(strarg));
			str_append(dest, strarg);
			break;
		}
		case IMAP_ARG_LIST:
			str_append_c(dest, '(');
			list = IMAP_ARG_LIST(args);
			imap_write_args(dest, array_idx(list, 0));
			str_append_c(dest, ')');
			break;
		case IMAP_ARG_LITERAL_SIZE:
		case IMAP_ARG_LITERAL_SIZE_NONSYNC:
			str_printfa(dest, "{%"PRIuUOFF_T"}\r\n",
				    IMAP_ARG_LITERAL_SIZE(args));
			str_append(dest, "<too large>");
			break;
		case IMAP_ARG_EOL:
			i_unreached();
		}
	}
}

const char *imap_args_to_str(const struct imap_arg *args)
{
	string_t *str;

	str = t_str_new(128);
	imap_write_args(str, args);
	return str_c(str);
}
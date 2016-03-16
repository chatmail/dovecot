#include "lib.h"
#include "unichar.h"
#include "fts-tokenizer-common.h"
void
fts_tokenizer_delete_trailing_partial_char(const unsigned char *data,
					   size_t *len)
{
	size_t pos;
	unsigned int char_bytes;

	/* the token is truncated - make sure the last character
	   exists entirely in the token */
	for (pos = *len-1; pos > 0; pos--) {
		if (UTF8_IS_START_SEQ(data[pos]))
			break;
	}
	char_bytes = uni_utf8_char_bytes(data[pos]);
	if (char_bytes != *len-pos) {
		i_assert(char_bytes > *len-pos);
		*len = pos;
	}
}

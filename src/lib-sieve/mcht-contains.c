/* Copyright (c) 2002-2009 Dovecot Sieve authors, see the included COPYING file 
 */

/* Match-type ':contains' 
 */

#include "lib.h"

#include "sieve-match-types.h"
#include "sieve-comparators.h"
#include "sieve-match.h"

#include <string.h>
#include <stdio.h>

/*
 * Forward declarations
 */ 

static int mcht_contains_match
	(struct sieve_match_context *mctx, const char *val, size_t val_size, 
		const char *key, size_t key_size, int key_index);

/*
 * Match-type object
 */

const struct sieve_match_type contains_match_type = {
	SIEVE_OBJECT("contains", &match_type_operand,	SIEVE_MATCH_TYPE_CONTAINS),
	TRUE, TRUE,
	NULL,
	sieve_match_substring_validate_context,
	NULL,
	mcht_contains_match,
	NULL
};

/*
 * Match-type implementation
 */

/* FIXME: Naive substring match implementation. Should switch to more 
 * efficient algorithm if large values need to be searched (e.g. message body).
 */
static int mcht_contains_match
(struct sieve_match_context *mctx, const char *val, size_t val_size, 
	const char *key, size_t key_size, int key_index ATTR_UNUSED)
{
	const struct sieve_comparator *cmp = mctx->comparator;
	const char *vend = (const char *) val + val_size;
	const char *kend = (const char *) key + key_size;
	const char *vp = val;
	const char *kp = key;

	if ( val == NULL || val_size == 0 ) 
		return ( key_size == 0 );

	if ( mctx->comparator->char_match == NULL ) 
		return FALSE;

	while ( (vp < vend) && (kp < kend) ) {
		if ( !cmp->char_match(cmp, &vp, vend, &kp, kend) )
			vp++;
	}
    
	return (kp == kend);
}


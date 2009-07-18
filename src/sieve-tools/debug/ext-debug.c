/* Copyright (c) 2002-2009 Dovecot Sieve authors, see the included COPYING file
 */

/* Extension debug 
 * ------------------
 *
 * Authors: Stephan Bosch
 * Specification: vendor-defined
 * Implementation: full
 * Status: experimental
 *
 */
 
#include "lib.h"
#include "array.h"

#include "sieve-extensions.h"
#include "sieve-commands.h"
#include "sieve-comparators.h"
#include "sieve-match-types.h"
#include "sieve-address-parts.h"

#include "sieve-validator.h"
#include "sieve-generator.h"
#include "sieve-binary.h"
#include "sieve-interpreter.h"
#include "sieve-dump.h"

#include "ext-debug-common.h"

/* 
 * Extension 
 */

static bool ext_debug_validator_load(struct sieve_validator *validator);

int ext_debug_my_id = -1;

const struct sieve_extension debug_extension = { 
	"vnd.dovecot.debug", 
	&ext_debug_my_id,
	NULL, NULL,
	ext_debug_validator_load, 
	NULL, NULL, NULL, NULL, NULL,
	SIEVE_EXT_DEFINE_OPERATION(debug_print_operation), 
	SIEVE_EXT_DEFINE_NO_OPERANDS
};

static bool ext_debug_validator_load(struct sieve_validator *validator)
{
	/* Register new test */
	sieve_validator_register_command(validator, &debug_print_command);

	return TRUE;
}


/* Copyright (c) 2002-2009 Dovecot Sieve authors, see the included COPYING file
 */

#include "sieve-common.h"
#include "sieve-commands.h"
#include "sieve-validator.h"
#include "sieve-generator.h"
#include "sieve-interpreter.h"
#include "sieve-code.h"
#include "sieve-binary.h"
#include "sieve-dump.h"

#include "testsuite-common.h"

/* 
 * Test_fail command
 *
 * Syntax:   
 *   test_fail <reason: string>
 */

static bool cmd_test_fail_validate
	(struct sieve_validator *validator, struct sieve_command_context *cmd);
static bool cmd_test_fail_generate
	(const struct sieve_codegen_env *cgenv, struct sieve_command_context *ctx);

const struct sieve_command cmd_test_fail = { 
	"test_fail", 
	SCT_COMMAND, 
	1, 0, FALSE, FALSE,
	NULL, NULL,
	cmd_test_fail_validate, 
	cmd_test_fail_generate, 
	NULL 
};

/* 
 * Test operation 
 */

static bool cmd_test_fail_operation_dump
	(const struct sieve_operation *op,
		const struct sieve_dumptime_env *denv, sieve_size_t *address);
static int cmd_test_fail_operation_execute
	(const struct sieve_operation *op, 
		const struct sieve_runtime_env *renv, sieve_size_t *address);

const struct sieve_operation test_fail_operation = { 
	"TEST_FAIL",
	&testsuite_extension, 
	TESTSUITE_OPERATION_TEST_FAIL,
	cmd_test_fail_operation_dump, 
	cmd_test_fail_operation_execute 
};

/* 
 * Validation 
 */

static bool cmd_test_fail_validate
(struct sieve_validator *valdtr ATTR_UNUSED, struct sieve_command_context *cmd) 
{
	struct sieve_ast_argument *arg = cmd->first_positional;
	
	if ( !sieve_validate_positional_argument
		(valdtr, cmd, arg, "reason", 1, SAAT_STRING) ) {
		return FALSE;
	}
	
	return sieve_validator_argument_activate(valdtr, cmd, arg, FALSE);
}

/* 
 * Code generation 
 */

static inline struct testsuite_generator_context *
	_get_generator_context(struct sieve_generator *gentr)
{
	return (struct testsuite_generator_context *) 
		sieve_generator_extension_get_context(gentr, &testsuite_extension);
}

static bool cmd_test_fail_generate
(const struct sieve_codegen_env *cgenv, struct sieve_command_context *ctx)
{
	struct testsuite_generator_context *genctx = 
		_get_generator_context(cgenv->gentr);
	
	sieve_operation_emit_code(cgenv->sbin, &test_fail_operation);

	/* Generate arguments */
	if ( !sieve_generate_arguments(cgenv, ctx, NULL) )
		return FALSE;
		
	sieve_jumplist_add(genctx->exit_jumps, 
		sieve_binary_emit_offset(cgenv->sbin, 0));			
	
	return TRUE;
}

/* 
 * Code dump
 */
 
static bool cmd_test_fail_operation_dump
(const struct sieve_operation *op ATTR_UNUSED,
	const struct sieve_dumptime_env *denv, sieve_size_t *address)
{
	unsigned int pc;
	int offset;
    
	sieve_code_dumpf(denv, "TEST_FAIL:");
	sieve_code_descend(denv);

	if ( !sieve_opr_string_dump(denv, address, "reason") ) 
		return FALSE;

	sieve_code_mark(denv);
	pc = *address;
	if ( sieve_binary_read_offset(denv->sbin, address, &offset) )
		sieve_code_dumpf(denv, "offset: %d [%08x]", offset, pc + offset);
	else
		return FALSE;

	return TRUE;
}

/*
 * Intepretation
 */

static int cmd_test_fail_operation_execute
(const struct sieve_operation *op ATTR_UNUSED,
	const struct sieve_runtime_env *renv, sieve_size_t *address)
{
	string_t *reason;

	if ( !sieve_opr_string_read(renv, address, &reason) ) {
		sieve_runtime_trace_error(renv, "invalid reason operand");
		return SIEVE_EXEC_BIN_CORRUPT;
	}

	sieve_runtime_trace(renv, "TEST FAIL");
	testsuite_test_fail(reason);
	
	return sieve_interpreter_program_jump(renv->interp, TRUE);
}




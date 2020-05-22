/* Copyright (c) 2002-2018 Pigeonhole authors, see the included COPYING file
 */

#include "lib.h"
#include "str.h"
#include "str-sanitize.h"

#include "rfc2822.h"

#include "sieve-common.h"
#include "sieve-ast.h"
#include "sieve-validator.h"
#include "sieve-generator.h"
#include "sieve-binary.h"
#include "sieve-commands.h"
#include "sieve-code.h"
#include "sieve-interpreter.h"

/*
 * Literal arguments
 */

/* Forward declarations */

static bool arg_number_generate
	(const struct sieve_codegen_env *cgenv, struct sieve_ast_argument *arg,
		struct sieve_command *context);
static bool arg_string_generate
	(const struct sieve_codegen_env *cgenv, struct sieve_ast_argument *arg,
		struct sieve_command *context);
static bool arg_string_list_validate
	(struct sieve_validator *valdtr, struct sieve_ast_argument **arg,
		struct sieve_command *context);
static bool arg_string_list_generate
	(const struct sieve_codegen_env *cgenv, struct sieve_ast_argument *arg,
		struct sieve_command *context);

/* Argument objects */

const struct sieve_argument_def number_argument = {
	.identifier = "@number",
	.generate = arg_number_generate
};

const struct sieve_argument_def string_argument = {
	.identifier = "@string",
	.generate = arg_string_generate
};

const struct sieve_argument_def string_list_argument = {
	.identifier = "@string-list",
	.validate = arg_string_list_validate,
	.generate = arg_string_list_generate
};

/* Argument implementations */

static bool arg_number_generate
(const struct sieve_codegen_env *cgenv, struct sieve_ast_argument *arg,
	struct sieve_command *cmd ATTR_UNUSED)
{
	sieve_opr_number_emit(cgenv->sblock, sieve_ast_argument_number(arg));

	return TRUE;
}

static bool arg_string_generate
(const struct sieve_codegen_env *cgenv, struct sieve_ast_argument *arg,
	struct sieve_command *cmd ATTR_UNUSED)
{
	sieve_opr_string_emit(cgenv->sblock, sieve_ast_argument_str(arg));

	return TRUE;
}

static bool arg_string_list_validate
(struct sieve_validator *valdtr, struct sieve_ast_argument **arg,
	struct sieve_command *cmd)
{
	struct sieve_ast_argument *stritem;

	stritem = sieve_ast_strlist_first(*arg);
	while ( stritem != NULL ) {
		if ( !sieve_validator_argument_activate(valdtr, cmd, stritem, FALSE) )
			return FALSE;

		stritem = sieve_ast_strlist_next(stritem);
	}

	return TRUE;
}

static bool emit_string_list_operand
(const struct sieve_codegen_env *cgenv, const struct sieve_ast_argument *strlist,
	struct sieve_command *cmd)
{
	void *list_context;
	struct sieve_ast_argument *stritem;

	sieve_opr_stringlist_emit_start
		(cgenv->sblock, sieve_ast_strlist_count(strlist), &list_context);

	stritem = sieve_ast_strlist_first(strlist);
	while ( stritem != NULL ) {
		if ( !sieve_generate_argument(cgenv, stritem, cmd) )
			return FALSE;

		stritem = sieve_ast_strlist_next(stritem);
	}

	sieve_opr_stringlist_emit_end(cgenv->sblock, list_context);

	return TRUE;
}

static bool arg_string_list_generate
(const struct sieve_codegen_env *cgenv, struct sieve_ast_argument *arg,
	struct sieve_command *cmd)
{
	if ( sieve_ast_argument_type(arg) == SAAT_STRING ) {
		return ( sieve_generate_argument(cgenv, arg, cmd) );

	} else if ( sieve_ast_argument_type(arg) == SAAT_STRING_LIST ) {
		bool result = TRUE;

		if ( sieve_ast_strlist_count(arg) == 1 )
			return ( sieve_generate_argument
				(cgenv, sieve_ast_strlist_first(arg), cmd) );
		else {
			T_BEGIN {
				result=emit_string_list_operand(cgenv, arg, cmd);
			} T_END;
		}

		return result;
	}

	return FALSE;
}

/*
 * Abstract arguments
 *
 *   (Generated by processing and not by parsing the grammar)
 */

/* Catenated string */

struct sieve_arg_catenated_string {
	struct sieve_ast_arg_list *str_parts;
};

struct sieve_arg_catenated_string *sieve_arg_catenated_string_create
(struct sieve_ast_argument *orig_arg)
{
	pool_t pool = sieve_ast_pool(orig_arg->ast);
	struct sieve_ast_arg_list *arglist;
	struct sieve_arg_catenated_string *catstr;

	arglist = sieve_ast_arg_list_create(pool);

	catstr = p_new(pool, struct sieve_arg_catenated_string, 1);
	catstr->str_parts = arglist;
	(orig_arg)->argument->data = (void *) catstr;

	return catstr;
}

void sieve_arg_catenated_string_add_element
(struct sieve_arg_catenated_string *catstr,
	struct sieve_ast_argument *element)
{
	sieve_ast_arg_list_add(catstr->str_parts, element);
}

#define _cat_string_first(catstr) __AST_LIST_FIRST((catstr)->str_parts)
#define _cat_string_count(catstr) __AST_LIST_COUNT((catstr)->str_parts)
#define _cat_string_next(item) __AST_LIST_NEXT(item)

bool sieve_arg_catenated_string_generate
(const struct sieve_codegen_env *cgenv, struct sieve_ast_argument *arg,
	struct sieve_command *cmd)
{
	struct sieve_arg_catenated_string *catstr =
		(struct sieve_arg_catenated_string *) arg->argument->data;
	struct sieve_ast_argument *strpart;

	if ( _cat_string_count(catstr) == 1 )
		sieve_generate_argument(cgenv, _cat_string_first(catstr), cmd);
	else {
		sieve_opr_catenated_string_emit(cgenv->sblock, _cat_string_count(catstr));

		strpart = _cat_string_first(catstr);
		while ( strpart != NULL ) {
			if ( !sieve_generate_argument(cgenv, strpart, cmd) )
				return FALSE;

			strpart = _cat_string_next(strpart);
		}
	}

	return TRUE;
}

/*
 * Argument creation
 */

struct sieve_argument *sieve_argument_create
(struct sieve_ast *ast, const struct sieve_argument_def *def,
	const struct sieve_extension *ext, int id_code)
{
	struct sieve_argument *arg;
	pool_t pool;

	pool = sieve_ast_pool(ast);
	arg = p_new(pool, struct sieve_argument, 1);
	arg->def = def;
	arg->ext = ext;
	arg->id_code = id_code;

	return arg;
}

/*
 * Core tests and commands
 */

const struct sieve_command_def *sieve_core_tests[] = {
	&tst_false, &tst_true,
	&tst_not, &tst_anyof, &tst_allof,
	&tst_address, &tst_header, &tst_exists, &tst_size
};

const unsigned int sieve_core_tests_count = N_ELEMENTS(sieve_core_tests);

const struct sieve_command_def *sieve_core_commands[] = {
	&cmd_require,
	&cmd_stop, &cmd_if, &cmd_elsif, &cmd_else,
	&cmd_keep, &cmd_discard, &cmd_redirect
};

const unsigned int sieve_core_commands_count = N_ELEMENTS(sieve_core_commands);

/*
 * Command context
 */

struct sieve_command *sieve_command_prev
(struct sieve_command *cmd)
{
	struct sieve_ast_node *node = sieve_ast_node_prev(cmd->ast_node);

	if ( node != NULL ) {
		return node->command;
	}

	return NULL;
}

struct sieve_command *sieve_command_parent
(struct sieve_command *cmd)
{
	struct sieve_ast_node *node = sieve_ast_node_parent(cmd->ast_node);

	return ( node != NULL ? node->command : NULL );
}

struct sieve_command *sieve_command_create
(struct sieve_ast_node *cmd_node, const struct sieve_extension *ext,
	const struct sieve_command_def *cmd_def,
	struct sieve_command_registration *cmd_reg)
{
	struct sieve_command *cmd;

	cmd = p_new(sieve_ast_node_pool(cmd_node), struct sieve_command, 1);

	cmd->ast_node = cmd_node;
	cmd->def = cmd_def;
	cmd->ext = ext;
	cmd->reg = cmd_reg;

	cmd->block_exit_command = NULL;

	return cmd;
}

const char *sieve_command_def_type_name
(const struct sieve_command_def *cmd_def)
{
	switch ( cmd_def->type ) {
	case SCT_NONE: return "command of unspecified type (bug)";
	case SCT_TEST: return "test";
	case SCT_COMMAND: return "command";
	case SCT_HYBRID: return "command or test";
	default:
		break;
	}
	return "??COMMAND-TYPE??";
}

const char *sieve_command_type_name
	(const struct sieve_command *cmd)
{
	switch ( cmd->def->type ) {
	case SCT_NONE: return "command of unspecified type (bug)";
	case SCT_TEST: return "test";
	case SCT_COMMAND: return "command";
	case SCT_HYBRID:
		if ( cmd->ast_node->type == SAT_TEST )
			return "test";
		return "command";
	default:
		break;
	}
	return "??COMMAND-TYPE??";
}

struct sieve_ast_argument *sieve_command_add_dynamic_tag
(struct sieve_command *cmd, const struct sieve_extension *ext,
	const struct sieve_argument_def *tag, int id_code)
{
	struct sieve_ast_argument *arg;

	if ( cmd->first_positional != NULL )
		arg = sieve_ast_argument_tag_insert
			(cmd->first_positional, tag->identifier, cmd->ast_node->source_line);
	else
		arg = sieve_ast_argument_tag_create
			(cmd->ast_node, tag->identifier, cmd->ast_node->source_line);

	arg->argument = sieve_argument_create(cmd->ast_node->ast, tag, ext, id_code);

	return arg;
}

struct sieve_ast_argument *sieve_command_find_argument
(struct sieve_command *cmd, const struct sieve_argument_def *arg_def)
{
	struct sieve_ast_argument *arg = sieve_ast_argument_first(cmd->ast_node);

	/* Visit tagged and optional arguments */
	while ( arg != NULL ) {
		if ( arg->argument != NULL && arg->argument->def == arg_def )
			return arg;

		arg = sieve_ast_argument_next(arg);
	}

	return arg;
}

/* Use this function with caution. The command commits to exiting the block.
 * When it for some reason does not, the interpretation will break later on,
 * because exiting jumps are not generated when they would otherwise be
 * necessary.
 */
void sieve_command_exit_block_unconditionally
	(struct sieve_command *cmd)
{
	struct sieve_command *parent = sieve_command_parent(cmd);

	/* Only the first unconditional exit is of importance */
	if ( parent != NULL && parent->block_exit_command == NULL )
		parent->block_exit_command = cmd;
}

bool sieve_command_block_exits_unconditionally
	(struct sieve_command *cmd)
{
	return ( cmd->block_exit_command != NULL );
}

/*
 * Command utility functions
 */

/* NOTE: this may be moved */

static int _verify_header_name_item
(void *context, struct sieve_ast_argument *header)
{
	struct sieve_validator *valdtr = (struct sieve_validator *) context;
	string_t *name = sieve_ast_argument_str(header);

	if ( sieve_argument_is_string_literal(header) &&
		!rfc2822_header_field_name_verify(str_c(name), str_len(name)) ) {
		sieve_argument_validate_warning
			(valdtr, header, "specified header field name '%s' is invalid",
				str_sanitize(str_c(name), 80));

		return 0;
	}

	return 1;
}

bool sieve_command_verify_headers_argument
(struct sieve_validator *valdtr, struct sieve_ast_argument *headers)
{
	return ( sieve_ast_stringlist_map
		(&headers, (void *) valdtr, _verify_header_name_item) >= 0 );
}

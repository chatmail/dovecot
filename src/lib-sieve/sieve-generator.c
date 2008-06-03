#include <stdio.h>

#include "lib.h"
#include "mempool.h"

#include "sieve-common.h"
#include "sieve-extensions.h"
#include "sieve-commands-private.h"
#include "sieve-code.h"
#include "sieve-binary.h"

#include "sieve-generator.h"

/* Jump list */
struct sieve_jumplist *sieve_jumplist_create
	(pool_t pool, struct sieve_binary *sbin)
{
	struct sieve_jumplist *jlist;
	
	jlist = p_new(pool, struct sieve_jumplist, 1);
	jlist->binary = sbin;
	p_array_init(&jlist->jumps, pool, 4);
	
	return jlist;
}

void sieve_jumplist_init_temp
	(struct sieve_jumplist *jlist, struct sieve_binary *sbin)
{
	jlist->binary = sbin;
	t_array_init(&jlist->jumps, 4);
}

void sieve_jumplist_reset
	(struct sieve_jumplist *jlist)
{
	array_clear(&jlist->jumps);
}

void sieve_jumplist_add(struct sieve_jumplist *jlist, sieve_size_t jump) 
{
	array_append(&jlist->jumps, &jump, 1);
}

void sieve_jumplist_resolve(struct sieve_jumplist *jlist) 
{
	unsigned int i;
	
	for ( i = 0; i < array_count(&jlist->jumps); i++ ) {
		const sieve_size_t *jump = array_idx(&jlist->jumps, i);
	
		sieve_binary_resolve_offset(jlist->binary, *jump);
	}
	
	array_free(&jlist->jumps);
}

/* Generator */

struct sieve_generator {
	pool_t pool;
	
	struct sieve_error_handler *ehandler;
	
	struct sieve_ast *ast;
	struct sieve_script *script;
	
	struct sieve_binary *binary;
	
	ARRAY_DEFINE(ext_contexts, void *);
};

struct sieve_generator *sieve_generator_create
	(struct sieve_ast *ast, struct sieve_error_handler *ehandler) 
{
	pool_t pool;
	struct sieve_generator *gentr;
	
	pool = pool_alloconly_create("sieve_generator", 4096);	
	gentr = p_new(pool, struct sieve_generator, 1);
	gentr->pool = pool;

	gentr->ehandler = ehandler;
	sieve_error_handler_ref(ehandler);
	
	gentr->ast = ast;	
	gentr->script = sieve_ast_script(ast);
	sieve_ast_ref(ast);

	/* Setup storage for extension contexts */		
	array_create(&gentr->ext_contexts, pool, sizeof(void *), 
		sieve_extensions_get_count());
	
	/* Pre-load core language features implemented as 'extensions' (none) */
	/*for ( i = 0; i < sieve_preloaded_extensions_count; i++ ) {
		const struct sieve_extension *ext = sieve_preloaded_extensions[i];
		
		if ( ext->generator_load != NULL )
			(void)ext->generator_load(gentr);		
	}*/
	
	return gentr;
}

void sieve_generator_free(struct sieve_generator **generator) 
{
	sieve_ast_unref(&(*generator)->ast);
	
	if ( (*generator)->binary != NULL )
		sieve_binary_unref(&(*generator)->binary);
	
	sieve_error_handler_unref(&(*generator)->ehandler);

	pool_unref(&((*generator)->pool));
	
	*generator = NULL;
}

struct sieve_script *sieve_generator_get_script
	(struct sieve_generator *gentr)
{
	return gentr->script;
}

/* Error handling */

void sieve_generator_warning
(struct sieve_generator *gentr, struct sieve_ast_node *node, 
	const char *fmt, ...) 
{ 
	va_list args;
	
	va_start(args, fmt);
	sieve_ast_error(gentr->ehandler, sieve_vwarning, node, fmt, args);
	va_end(args);
}
 
void sieve_generator_error
(struct sieve_generator *gentr, struct sieve_ast_node *node, 
	const char *fmt, ...) 
{
	va_list args;
	
	va_start(args, fmt);
	sieve_ast_error(gentr->ehandler, sieve_verror, node, fmt, args);
	va_end(args);
}

void sieve_generator_critical
(struct sieve_generator *gentr, struct sieve_ast_node *node, 
	const char *fmt, ...) 
{
	va_list args;
	
	va_start(args, fmt);
	sieve_ast_error(gentr->ehandler, sieve_vcritical, node, fmt, args);
	va_end(args);
}

/* Extension support */

bool sieve_generator_link_extension
	(struct sieve_generator *gentr, int ext_id) 
{
	const struct sieve_extension *ext = sieve_extension_get_by_id(ext_id);
	
	(void)sieve_binary_extension_link(gentr->binary, ext_id);
	
	if ( ext == NULL ) 
		return FALSE;
	
	if ( ext->generator_load != NULL )
		return ext->generator_load(gentr);
	
	return TRUE;
}

void sieve_generator_extension_set_context
	(struct sieve_generator *gentr, int ext_id, void *context)
{
	array_idx_set(&gentr->ext_contexts, (unsigned int) ext_id, &context);	
}

const void *sieve_generator_extension_get_context
	(struct sieve_generator *gentr, int ext_id) 
{
	void * const *ctx;

	if  ( ext_id < 0 || ext_id >= (int) array_count(&gentr->ext_contexts) )
		return NULL;
	
	ctx = array_idx(&gentr->ext_contexts, (unsigned int) ext_id);		

	return *ctx;
}

/* Binary access */

struct sieve_binary *sieve_generator_get_binary
	(struct sieve_generator *gentr)
{
	return gentr->binary;
}

sieve_size_t sieve_generator_emit_operation
	(struct sieve_generator *gentr, const struct sieve_operation *op)
{
	return sieve_operation_emit_code(gentr->binary, op, -1);
}

sieve_size_t sieve_generator_emit_operation_ext
	(struct sieve_generator *gentr, const struct sieve_operation *op, int ext_id)
{	
	return sieve_operation_emit_code(gentr->binary, op, ext_id);
}

/* Generator functions */

bool sieve_generate_argument
(struct sieve_generator *generator, struct sieve_ast_argument *arg, 
	struct sieve_command_context *cmd)
{
	const struct sieve_argument *argument = arg->argument;
	
	if ( argument == NULL ) return FALSE;
	
	return ( argument->generate == NULL || 	
		argument->generate(generator, arg, cmd) );
}

bool sieve_generate_arguments(struct sieve_generator *generator, 
	struct sieve_command_context *cmd, struct sieve_ast_argument **last_arg)
{
	enum { ARG_START, ARG_OPTIONAL, ARG_POSITIONAL } state = ARG_START;
	struct sieve_ast_argument *arg = sieve_ast_argument_first(cmd->ast_node);
	
	/* Generate all arguments with assigned generator function */
	
	while ( arg != NULL && arg->argument != NULL) {
		const struct sieve_argument *argument = arg->argument;
		
		switch ( state ) {
		case ARG_START: 
			if ( arg->arg_id_code == 0 )
				state = ARG_POSITIONAL;
			else {
				/* Mark start of optional operands with 0 operand identifier */
				sieve_binary_emit_byte(generator->binary, SIEVE_OPERAND_OPTIONAL);
				
				/* Emit argument id for optional operand */
				sieve_binary_emit_byte(generator->binary, (unsigned char) arg->arg_id_code);

				state = ARG_OPTIONAL;
			}
			break;
		case ARG_OPTIONAL: 
			if ( arg->arg_id_code == 0 )
				state = ARG_POSITIONAL;
			
			/* Emit argument id for optional operand (0 marks the end of the optionals) */
			sieve_binary_emit_byte(generator->binary, (unsigned char) arg->arg_id_code);

			break;
		case ARG_POSITIONAL:
			if ( arg->arg_id_code != 0 )
				return FALSE;
			break;
		}
		
		/* Call the generation function for the argument */ 
		if ( argument->generate != NULL ) { 
			if ( !argument->generate(generator, arg, cmd) ) 
				return FALSE;
		} else if ( state == ARG_POSITIONAL ) break;

		arg = sieve_ast_argument_next(arg);
	}
	
	if ( last_arg != NULL )
		*last_arg = arg;
	
	return TRUE;
}

bool sieve_generate_argument_parameters(struct sieve_generator *gentr, 
	struct sieve_command_context *cmd, struct sieve_ast_argument *arg)
{
	struct sieve_ast_argument *param = arg->parameters;
	
	/* Generate all parameters with assigned generator function */
	
	while ( param != NULL && param->argument != NULL) {
		const struct sieve_argument *parameter = param->argument;
				
		/* Call the generation function for the parameter */ 
		if ( parameter->generate != NULL ) { 
			if ( !parameter->generate(gentr, param, cmd) ) 
				return FALSE;
		}

		param = sieve_ast_argument_next(param);
	}
		
	return TRUE;
}


bool sieve_generate_test
	(struct sieve_generator *generator, struct sieve_ast_node *tst_node,
		struct sieve_jumplist *jlist, bool jump_true) 
{
	i_assert( tst_node->context != NULL && tst_node->context->command != NULL );

	if ( tst_node->context->command->control_generate != NULL ) {
		if ( tst_node->context->command->control_generate
			(generator, tst_node->context, jlist, jump_true) ) 
			return TRUE;
		
		return FALSE;
	}
	
	if ( tst_node->context->command->generate != NULL ) {

		if ( tst_node->context->command->generate(generator, tst_node->context) ) {
			
			if ( jump_true ) 
				sieve_operation_emit_code(generator->binary, &sieve_jmptrue_operation, -1);
			else
				sieve_operation_emit_code(generator->binary, &sieve_jmpfalse_operation, -1);
			sieve_jumplist_add(jlist, sieve_binary_emit_offset(generator->binary, 0));
						
			return TRUE;
		}	
		
		return FALSE;
	}
	
	return TRUE;
}

static bool sieve_generate_command
	(struct sieve_generator *generator, struct sieve_ast_node *cmd_node) 
{
	i_assert( cmd_node->context != NULL && cmd_node->context->command != NULL );

	if ( cmd_node->context->command->generate != NULL ) {
		return cmd_node->context->command->generate(generator, cmd_node->context);
	}
	
	return TRUE;		
}

bool sieve_generate_block
	(struct sieve_generator *generator, struct sieve_ast_node *block) 
{
	bool result = TRUE;
	struct sieve_ast_node *command;

	T_BEGIN {	
		command = sieve_ast_command_first(block);
		while ( result && command != NULL ) {	
			result = sieve_generate_command(generator, command);	
			command = sieve_ast_command_next(command);
		}		
	} T_END;
	
	return result;
}

bool sieve_generator_run
	(struct sieve_generator *generator, struct sieve_binary **sbin) 
{
	bool topmost = ( *sbin == NULL );
	bool result = TRUE;
	
	if ( topmost )
		*sbin = sieve_binary_create_new(sieve_ast_script(generator->ast));
	
	sieve_binary_ref(*sbin);
		
	generator->binary = *sbin;
	
	if ( !sieve_generate_block(generator, sieve_ast_root(generator->ast)) ) 
		result = FALSE;
	else if ( topmost ) 
		sieve_binary_activate(*sbin);
	
	generator->binary = NULL;
	sieve_binary_unref(sbin);

	if ( topmost && !result ) {
		sieve_binary_unref(sbin);
		*sbin = NULL;
	}
	
	return result;
}

/* Accessors */

struct sieve_error_handler *sieve_generator_error_handler
	(struct sieve_generator *gentr)
{
	return gentr->ehandler;
}

pool_t sieve_generator_pool(struct sieve_generator *gentr)
{
	return gentr->pool;
}

struct sieve_script *sieve_generator_script
	(struct sieve_generator *gentr)
{
	return gentr->script;
}




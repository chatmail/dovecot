#include <stdio.h>

#include "lib.h"
#include "str.h"
#include "mempool.h"
#include "array.h"

#include "sieve-script.h"
#include "sieve-extensions.h"

#include "sieve-ast.h"

/* Forward declarations */

static struct sieve_ast_node *sieve_ast_node_create
	(struct sieve_ast *ast, struct sieve_ast_node *parent, 
		enum sieve_ast_type type, unsigned int source_line);

/* Links to other objects (notified if AST is destroyed) */

struct sieve_ast_node_link {
	struct sieve_ast_node *node;
	const struct sieve_ast_node_object *object;
};

/* The AST object */

struct sieve_ast {
	pool_t pool;
	int refcount;
		
	struct sieve_script *script;
		
	struct sieve_ast_node *root;
	
	ARRAY_DEFINE(ext_contexts, void *);

	ARRAY_DEFINE(node_links, struct sieve_ast_node_link);
};

struct sieve_ast *sieve_ast_create(struct sieve_script *script) 
{
	pool_t pool;
	struct sieve_ast *ast;
	
	pool = pool_alloconly_create("sieve_ast", 4096);	
	ast = p_new(pool, struct sieve_ast, 1);
	ast->pool = pool;
	ast->refcount = 1;
	
	ast->script = script;
	sieve_script_ref(script);
		
	ast->root = sieve_ast_node_create(ast, NULL, SAT_ROOT, 0);
	ast->root->identifier = "ROOT";
	
	p_array_init(&ast->node_links, pool, 4);
	p_array_init(&ast->ext_contexts, pool, sieve_extensions_get_count());
	
	return ast;
}

void sieve_ast_link_object
(struct sieve_ast_node *node, const struct sieve_ast_node_object *obj)
{
	struct sieve_ast_node_link link;
	
	link.node = node;
	link.object = obj;
	array_append(&node->ast->node_links, &link, 1);
}

void sieve_ast_ref(struct sieve_ast *ast) 
{
	ast->refcount++;
}

void sieve_ast_unref(struct sieve_ast **ast) 
{
	unsigned int i, lcount;
	const struct sieve_ast_node_link *node_links;
	
	i_assert((*ast)->refcount > 0);

	if (--(*ast)->refcount != 0)
		return;
	
	/* Release script reference */
	sieve_script_unref(&(*ast)->script);
	
	/* Signal linked objects that the AST is being destroyed */
	node_links = array_get(&(*ast)->node_links, &lcount);
	for ( i = 0; i < lcount; i++ ) {
		node_links[i].object->ast_destroy(*ast, node_links[i].node);
	}
	
	/* Destroy AST */
	pool_unref(&(*ast)->pool);
	
	*ast = NULL;
}

struct sieve_ast_node *sieve_ast_root(struct sieve_ast *ast)
{
	return ast->root;
}

pool_t sieve_ast_pool(struct sieve_ast *ast)
{
	return ast->pool;
}

struct sieve_script *sieve_ast_script(struct sieve_ast *ast)
{
	return ast->script;
}

const char *sieve_ast_type_name(enum sieve_ast_type ast_type) {
	switch ( ast_type ) {
	
	case SAT_NONE: return "none";
	case SAT_ROOT: return "ast root node";
	case SAT_COMMAND: return "command";
	case SAT_TEST: return "test";
	
	default: return "??AST NODE??";
	}
}

/* Extension support */

void sieve_ast_extension_set_context
	(struct sieve_ast *ast, int ext_id, void *context)
{
	array_idx_set(&ast->ext_contexts, (unsigned int) ext_id, &context);	
}

const void *sieve_ast_extension_get_context
	(struct sieve_ast *ast, int ext_id) 
{
	void * const *ctx;

	if  ( ext_id < 0 || ext_id >= (int) array_count(&ast->ext_contexts) )
		return NULL;
	
	ctx = array_idx(&ast->ext_contexts, (unsigned int) ext_id);		

	return *ctx;
}

/* AST-based error reporting */

void sieve_ast_error
(struct sieve_error_handler *ehandler, sieve_error_vfunc_t vfunc, 
	struct sieve_ast_node *node, const char *fmt, va_list args) 
{ 
	struct sieve_script *script = node->ast->script;
	
	T_BEGIN {
		vfunc(ehandler, 
			t_strdup_printf("%s:%d", sieve_script_name(script),
				sieve_ast_node_line(node)), fmt, args);
	} T_END; 
}
 

/* Very simplistic linked list implementation
 */
#define __LIST_CREATE(pool, type) { \
		type *list = p_new(pool, type, 1); \
		list->head = NULL; \
		list->tail = NULL; \
		list->len = 0;		\
		return list; \
	}

#define __LIST_ADD(list, node) { \
		node->next = NULL; \
		if ( list->head == NULL ) { \
			node->prev = NULL; \
			list->head = node; \
			list->tail = node; \
		} else { \
			list->tail->next = node; \
			node->prev = list->tail; \
			list->tail = node; \
		} \
		list->len++; \
		node->list = list; \
	}	 
	
/* List of AST nodes */
static struct sieve_ast_list *sieve_ast_list_create( pool_t pool ) 
	__LIST_CREATE(pool, struct sieve_ast_list)

static void sieve_ast_list_add( struct sieve_ast_list *list, struct sieve_ast_node *node ) 
	__LIST_ADD(list, node)

/* List of argument AST nodes */
struct sieve_ast_arg_list *sieve_ast_arg_list_create( pool_t pool ) 
	__LIST_CREATE(pool, struct sieve_ast_arg_list)
	
void sieve_ast_arg_list_add
	( struct sieve_ast_arg_list *list, struct sieve_ast_argument *argument )
	__LIST_ADD(list, argument)

void sieve_ast_arg_list_substitute
(struct sieve_ast_arg_list *list, struct sieve_ast_argument *argument, 
	struct sieve_ast_argument *replacement)
{
	if ( list->head == argument )
		list->head = replacement;
	if ( list->tail == argument )
		list->tail = replacement;
		
	if ( argument->prev != NULL )
		argument->prev->next = replacement;
	if ( argument->next != NULL )
		argument->next->prev = replacement;
	
	replacement->prev = argument->prev;
	replacement->next = argument->next;
	replacement->list = argument->list;
	
	argument->next = NULL;
	argument->prev = NULL;
}

static struct sieve_ast_argument *sieve_ast_arg_list_detach
	(struct sieve_ast_argument *first, const unsigned int count)
{
	struct sieve_ast_argument *last, *result;
	unsigned int left;
	
	i_assert(first->list != NULL);
	
	/* Find the last of the deleted arguments */
	left = count - 1;
	last = first;
	while ( left > 0 && last->next != NULL ) {
		left--;
		last = last->next;
	}

	/* Perform substitution */
		
	if ( first->list->head == first ) 
		first->list->head = last->next;

	if ( first->list->tail == last )
		first->list->tail = first->prev;
		
	if ( first->prev != NULL )
		first->prev->next = last->next;
		
	if ( last->next != NULL )
		last->next->prev = first->prev;
		
	first->list->len -= count - left;
	
	result = last->next;
	first->prev = NULL;
	last->next = NULL;
	
	/* Detached objects will eventually freed along with AST pool */
	
	return result;
}

/* AST Node */

static struct sieve_ast_node *sieve_ast_node_create
	(struct sieve_ast *ast, struct sieve_ast_node *parent, enum sieve_ast_type type, 
	unsigned int source_line) 
{
	struct sieve_ast_node *node = p_new(ast->pool, struct sieve_ast_node, 1);
	
	node->ast = ast;
	node->parent = parent;
	node->type = type;
	
	node->prev = NULL;
	node->next = NULL;
	
	node->arguments = NULL;
	node->tests = NULL;
	node->commands = NULL;		
	
	node->test_list = FALSE;
	node->block = FALSE;
	
	node->source_line = source_line;
	
	return node;
}

static void sieve_ast_node_add_command
	(struct sieve_ast_node *node, struct sieve_ast_node *command) 
{
	i_assert( command->type == SAT_COMMAND && (node->type == SAT_ROOT || node->type == SAT_COMMAND) );
	
	if (node->commands == NULL) node->commands = sieve_ast_list_create(node->ast->pool);
	
	sieve_ast_list_add(node->commands, command);
}

static void sieve_ast_node_add_test
	(struct sieve_ast_node *node, struct sieve_ast_node *test) 
{
	i_assert( test->type == SAT_TEST && (node->type == SAT_TEST || node->type == SAT_COMMAND) );
	
	if (node->tests == NULL) node->tests = sieve_ast_list_create(node->ast->pool);
	
	sieve_ast_list_add(node->tests, test);
}

static void sieve_ast_node_add_argument
	(struct sieve_ast_node *node, struct sieve_ast_argument *argument) 
{
	i_assert( node->type == SAT_TEST || node->type == SAT_COMMAND );
	
	if (node->arguments == NULL) node->arguments = sieve_ast_arg_list_create(node->ast->pool);
	
	sieve_ast_arg_list_add(node->arguments, argument);
}

static void sieve_ast_argument_substitute
	(struct sieve_ast_argument *argument, struct sieve_ast_argument *replacement) 
{
	sieve_ast_arg_list_substitute(argument->list, argument, replacement);
}

/* Argument AST node */
struct sieve_ast_argument *sieve_ast_argument_create
	(struct sieve_ast *ast, unsigned int source_line) 
{	
	struct sieve_ast_argument *arg = 
		p_new(ast->pool, struct sieve_ast_argument, 1);
	
	arg->ast = ast;
	
	arg->prev = NULL;
	arg->next = NULL;
	
	arg->source_line = source_line;
	arg->context = NULL;
	
	arg->argument = NULL;
	arg->arg_id_code = 0;
			
	return arg;
}

struct sieve_ast_argument *sieve_ast_argument_string_create
	(struct sieve_ast_node *node, const string_t *str, unsigned int source_line) 
{	
	struct sieve_ast_argument *argument = sieve_ast_argument_create
		(node->ast, source_line);
		
	argument->type = SAAT_STRING;
	
	/* Clone string */
	argument->_value.str = str_new(node->ast->pool, str_len(str));
	str_append_str(argument->_value.str, str);

	sieve_ast_node_add_argument(node, argument);

	return argument;
}

struct sieve_ast_argument *sieve_ast_argument_stringlist_create
	(struct sieve_ast_node *node, unsigned int source_line) 
{
	struct sieve_ast_argument *argument = 
		sieve_ast_argument_create(node->ast, source_line);
	
	argument->type = SAAT_STRING_LIST;
	argument->_value.strlist = NULL;
	
	sieve_ast_node_add_argument(node, argument);

	return argument;
}

struct sieve_ast_argument *sieve_ast_argument_stringlist_substitute
	(struct sieve_ast_node *node, struct sieve_ast_argument *arg) 
{
	struct sieve_ast_argument *argument = 
		sieve_ast_argument_create(node->ast, arg->source_line);
	
	argument->type = SAAT_STRING_LIST;
	argument->_value.strlist = NULL;
	
	sieve_ast_argument_substitute(arg, argument);

	return argument;
}

static void _sieve_ast_stringlist_add
	(struct sieve_ast_argument *list, string_t *str, unsigned int source_line) 
{
	struct sieve_ast_argument *stritem;
	
	i_assert( list->type == SAAT_STRING_LIST );
	
	if ( list->_value.strlist == NULL ) 
		list->_value.strlist = sieve_ast_arg_list_create(list->ast->pool);
	
	stritem = sieve_ast_argument_create(list->ast, source_line);
		
	stritem->type = SAAT_STRING;
	
	/* Clone string */
	stritem->_value.str = str;

	sieve_ast_arg_list_add(list->_value.strlist, stritem);
}

void sieve_ast_stringlist_add
	(struct sieve_ast_argument *list, const string_t *str, unsigned int source_line) 
{
	string_t *copied_str = str_new(list->ast->pool, str_len(str));
	str_append_str(copied_str, str);

	_sieve_ast_stringlist_add(list, copied_str, source_line);
}

void sieve_ast_stringlist_add_strc
	(struct sieve_ast_argument *list, const char *str, unsigned int source_line) 
{
	string_t *copied_str = str_new(list->ast->pool, strlen(str));
	str_append(copied_str, str);
	
	_sieve_ast_stringlist_add(list, copied_str, source_line);
}

struct sieve_ast_argument *sieve_ast_argument_tag_create
	(struct sieve_ast_node *node, const char *tag, unsigned int source_line) 
{	
	struct sieve_ast_argument *argument = 
		sieve_ast_argument_create(node->ast, source_line);
	
	argument->type = SAAT_TAG;
	argument->_value.tag = p_strdup(node->ast->pool, tag);

	sieve_ast_node_add_argument(node, argument);

	return argument;
}

struct sieve_ast_argument *sieve_ast_argument_number_create
	(struct sieve_ast_node *node, int number, unsigned int source_line) 
{
	
	struct sieve_ast_argument *argument = 
		sieve_ast_argument_create(node->ast, source_line);
		
	argument->type = SAAT_NUMBER;
	argument->_value.number = number;
	
	sieve_ast_node_add_argument(node, argument);
	
	return argument;
}

struct sieve_ast_argument *sieve_ast_arguments_detach
	(struct sieve_ast_argument *first, unsigned int count) 
{	
	return sieve_ast_arg_list_detach(first, count);
}

const char *sieve_ast_argument_type_name(enum sieve_ast_argument_type arg_type) {
	switch ( arg_type ) {
	
	case SAAT_NONE: return "none";
	case SAAT_STRING_LIST: return "a string list";
	case SAAT_STRING: return "a string";
	case SAAT_NUMBER: return "a number";
	case SAAT_TAG: return "a tag";
	
	default: return "??ARGUMENT??";
	}
}

/* Test AST node */

struct sieve_ast_node *sieve_ast_test_create
	(struct sieve_ast_node *parent, const char *identifier, unsigned int source_line) {
	
	struct sieve_ast_node *test = sieve_ast_node_create
		(parent->ast, parent, SAT_TEST, source_line);
		
	test->identifier = p_strdup(parent->ast->pool, identifier);
	
	sieve_ast_node_add_test(parent, test);
	
	return test;
}

/* Command AST node */

struct sieve_ast_node *sieve_ast_command_create
	(struct sieve_ast_node *parent, const char *identifier, unsigned int source_line) {

	struct sieve_ast_node *command = sieve_ast_node_create
		(parent->ast, parent, SAT_COMMAND, source_line);
	
	command->identifier = p_strdup(parent->ast->pool, identifier);
	
	sieve_ast_node_add_command(parent, command);
	
	return command;
}


/* Debug */

/* Unparsing, currently implemented using plain printf()s */

static void sieve_ast_unparse_string(const string_t *strval) {
	char *str = t_strdup_noconst(str_c((string_t *) strval));

	if ( strchr(str, '\n') != NULL && str[strlen(str)-1] == '\n' ) {
		/* Print it as a multi-line string and do required dotstuffing */
		char *spos = str;
		char *epos = strchr(str, '\n');
		printf("text:\n");
		
		while ( epos != NULL ) {
			*epos = '\0';
			if ( *spos == '.' ) 
				printf(".");
			
			printf("%s\n", spos);
			
			spos = epos+1;
			epos = strchr(spos, '\n');
		}
		if ( *spos == '.' ) 
				printf(".");
		
		printf("%s\n.\n", spos);	
	} else {
		/* Print it as a quoted string and escape " */
		char *spos = str;
		char *epos = strchr(str, '"');
		printf("\"");
		
		while ( epos != NULL ) {
			*epos = '\0';
			printf("%s\\\"", spos);
			
			spos = epos+1;
			epos = strchr(spos, '"');
		}
		
		printf("%s\"", spos);
	}
}

static void sieve_ast_unparse_argument(struct sieve_ast_argument *argument, int level);

static void sieve_ast_unparse_stringlist(struct sieve_ast_argument *strlist, int level) {
	struct sieve_ast_argument *stritem;
	
	if ( sieve_ast_strlist_count(strlist) > 1 ) { 
		int i;
		
		printf("[\n");
	
		/* Create indent */
		for ( i = 0; i < level+2; i++ ) 
			printf("  ");	

		stritem = sieve_ast_strlist_first(strlist);
		sieve_ast_unparse_string(sieve_ast_strlist_str(stritem));
		
		stritem = sieve_ast_strlist_next(stritem);
		while ( stritem != NULL ) {
			printf(",\n");
			for ( i = 0; i < level+2; i++ ) 
				printf("  ");
			sieve_ast_unparse_string(sieve_ast_strlist_str(stritem));
		  stritem = sieve_ast_strlist_next(stritem);
	  }
 
		printf(" ]");
	} else {
		stritem = sieve_ast_strlist_first(strlist);
		if ( stritem != NULL ) 
			sieve_ast_unparse_string(sieve_ast_strlist_str(stritem));
	}
}

static void sieve_ast_unparse_argument(struct sieve_ast_argument *argument, int level) {
	switch ( argument->type ) {
	case SAAT_STRING:
		sieve_ast_unparse_string(sieve_ast_argument_str(argument));
		break;
	case SAAT_STRING_LIST:
		sieve_ast_unparse_stringlist(argument, level+1);
		break;
	case SAAT_NUMBER:
		printf("%d", sieve_ast_argument_number(argument));
		break;
	case SAAT_TAG:
		printf(":%s", sieve_ast_argument_tag(argument));
		break;
	default:
		printf("??ARGUMENT??");
		break;
	}
}

static void sieve_ast_unparse_test(struct sieve_ast_node *node, int level);

static void sieve_ast_unparse_tests(struct sieve_ast_node *node, int level) {
	struct sieve_ast_node *test;
	
	if ( sieve_ast_test_count(node) > 1 ) { 
		int i;
		
		printf(" (\n");
	
		/* Create indent */
		for ( i = 0; i < level+2; i++ ) 
			printf("  ");	

		test = sieve_ast_test_first(node);
		sieve_ast_unparse_test(test, level+1);
		
		test = sieve_ast_test_next(test);
		while ( test != NULL ) {
			printf(", \n");
			for ( i = 0; i < level+2; i++ ) 
				printf("  ");
			sieve_ast_unparse_test(test, level+1);
		  test = sieve_ast_test_next(test);
	  }
 
		printf(" )");
	} else {
		test = sieve_ast_test_first(node);
		if ( test != NULL ) 
			sieve_ast_unparse_test(test, level);
	}
}

static void sieve_ast_unparse_test(struct sieve_ast_node *node, int level) {
	struct sieve_ast_argument *argument;
		
	printf(" %s", node->identifier);
	
	argument = sieve_ast_argument_first(node);
	while ( argument != NULL ) {
		printf(" ");
		sieve_ast_unparse_argument(argument, level);
		argument = sieve_ast_argument_next(argument);
	}
	
	sieve_ast_unparse_tests(node, level);
}

static void sieve_ast_unparse_command(struct sieve_ast_node *node, int level) {
	struct sieve_ast_node *command;
	struct sieve_ast_argument *argument;
	
	int i;
	
	/* Create indent */
	for ( i = 0; i < level; i++ ) 
		printf("  ");
		
	printf("%s", node->identifier);
	
	argument = sieve_ast_argument_first(node);
	while ( argument != NULL ) {
		printf(" ");
		sieve_ast_unparse_argument(argument, level);
		argument = sieve_ast_argument_next(argument);
	}
	
	sieve_ast_unparse_tests(node, level);
	
	command = sieve_ast_command_first(node);
	if ( command != NULL ) {
		printf(" {\n");
		
		while ( command != NULL) {	
			sieve_ast_unparse_command(command, level+1);
			command = sieve_ast_command_next(command);
		}
		
		for ( i = 0; i < level; i++ ) 
			printf("  ");
		printf("}\n");
	} else 
		printf(";\n");
}

void sieve_ast_unparse(struct sieve_ast *ast) {
	struct sieve_ast_node *command;

	printf("Unparsing Abstract Syntax Tree:\n");

	T_BEGIN {	
		command = sieve_ast_command_first(sieve_ast_root(ast));
		while ( command != NULL ) {	
			sieve_ast_unparse_command(command, 0);
			command = sieve_ast_command_next(command);
		}		
	} T_END;
}



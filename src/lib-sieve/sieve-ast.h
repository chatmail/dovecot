#ifndef __SIEVE_AST_H__
#define __SIEVE_AST_H__

#include "lib.h"
#include "str.h"

#include "sieve-common.h"
#include "sieve-commands.h"

/*
	Abstract Syntax Tree (AST) structure:
	
	sieve_ast (root)
	[*command]
	 |
	 +-- command:
	 |   ....
	 +-- command:
	 |	 [identifier *argument                      *test *command]
	 |                +-- argument:                 |     \--> as from root
	 |                |   ....                      |
 	 |                +-- argument:                 V (continued below)
	 |                |   [number | tag | *string]
	 |                .
	 .
	
	 *test
	 +-- test:
	 |   ....
	 +-- test:
	 |   [identifier *argument                     *test]
	 |               +-- argument:                 \-->  as from the top 
	 .               |   ....                              of this tree
	                 +-- argument:
	                 |   [number | tag | *string]
	                 .
	                 
	 Tests and commands are defined using the same structure: sieve_ast_node. However, arguments and 
	 string-lists are described using sieve_ast_argument.  
*/

/* IMPORTANT NOTICE: Do not decorate the AST with objects other than those allocated on 
 * the ast's pool or static const objects. Otherwise it is possible that pointers in the tree 
 * become dangling which is highly undesirable.
 */

struct sieve_ast_list;
struct sieve_ast_value;

enum sieve_ast_argument_type {
	SAAT_NONE,
	SAAT_STRING,
	SAAT_STRING_LIST,
	SAAT_TAG,
	SAAT_NUMBER
};

struct sieve_ast_argument {
	enum sieve_ast_argument_type type;

	/* Back reference to the AST object */
	struct sieve_ast *ast;

	struct sieve_ast_argument *next;
	struct sieve_ast_argument *prev;
  
	union {	
		string_t *str;
		struct sieve_ast_arg_list *strlist;
		const char *tag;
		int number;
  } _value;
  
  unsigned int source_line;
};

struct sieve_ast_list {
	struct sieve_ast_node *head;		
	struct sieve_ast_node *tail;
	unsigned int len; 	
};

struct sieve_ast_arg_list {
	struct sieve_ast_argument *head;		
	struct sieve_ast_argument *tail;
	unsigned int len; 	
};

enum sieve_ast_type {
	SAT_NONE,
	SAT_ROOT,
	SAT_COMMAND,
	SAT_TEST,
};

struct sieve_ast_node {
	enum sieve_ast_type type;

	/* Back reference to the AST object */
	struct sieve_ast *ast;
	
	/* Back reference to this node's parent */
	struct sieve_ast_node *parent;
	
	/* Linked list references to tree siblings */
	struct sieve_ast_node *next;
	struct sieve_ast_node *prev;
	
	/* Commands (NULL if not allocated) */
	bool block;
	struct sieve_ast_list *commands;
	
	/* Tests (NULL if not allocated)*/
	bool test_list;
	struct sieve_ast_list *tests;

	/* Arguments (NULL if not allocated) */
	struct sieve_ast_arg_list *arguments;	
		
	/* Context (associated during validation) */
	struct sieve_command_context *context;	
	
	const char *identifier;		
	
	unsigned int source_line;
};

struct sieve_ast {
	pool_t pool;
	
	struct sieve_ast_node *root;
};
	
/* sieve_ast_argument */
struct sieve_ast_argument *sieve_ast_argument_string_create
	(struct sieve_ast_node *node, const string_t *str, unsigned int source_line);
struct sieve_ast_argument *sieve_ast_argument_stringlist_create
	(struct sieve_ast_node *node, unsigned int source_line);
struct sieve_ast_argument *sieve_ast_argument_tag_create
	(struct sieve_ast_node *node, const char *tag, unsigned int source_line);
struct sieve_ast_argument *sieve_ast_argument_number_create
	(struct sieve_ast_node *node, int number, unsigned int source_line);

const char *sieve_ast_argument_name(struct sieve_ast_argument *argument);

void sieve_ast_stringlist_add
	(struct sieve_ast_argument *list, const string_t *str, unsigned int source_line);

/* sieve_ast_test */
struct sieve_ast_node *sieve_ast_test_create
	(struct sieve_ast_node *parent, const char *identifier, unsigned int source_line);
	
/* sieve_ast_command */
struct sieve_ast_node *sieve_ast_command_create
	(struct sieve_ast_node *parent, const char *identifier, unsigned int source_line);
	
/* sieve_ast */
struct sieve_ast *sieve_ast_create( void );
void sieve_ast_ref(struct sieve_ast *ast);
void sieve_ast_unref(struct sieve_ast **ast);

/* Debug */
void sieve_ast_unparse(struct sieve_ast *ast);

/* AST access macros */

/* Generic list access macros */
#define __LIST_FIRST(node, list) ((node)->list == NULL ? NULL : (node)->list->head)
#define __LIST_NEXT(item) ((item)->next)
#define __LIST_PREV(item) ((item)->prev)
#define __LIST_COUNT(node, list) ((node)->list == NULL || (node)->list->head == NULL ? 0 : (node)->list->len)

/* AST macros */
#define sieve_ast_root(ast) (ast->root)
#define sieve_ast_pool(ast) (ast->pool)

/* AST node macros */
#define sieve_ast_node_pool(node) ((node)->ast->pool)
#define sieve_ast_node_parent(node) ((node)->parent)
#define sieve_ast_node_prev(node) __LIST_PREV(node)
#define sieve_ast_node_next(node) __LIST_NEXT(node)
#define sieve_ast_node_type(node) ((node) == NULL ? SAT_NONE : (node)->type)
#define sieve_ast_node_line(node) ((node) == NULL ? 0 : (node)->source_line)

/* AST command node macros */
#define sieve_ast_command_first(node) __LIST_FIRST(node, commands)
#define sieve_ast_command_prev(command) __LIST_PREV(command)
#define sieve_ast_command_next(command) __LIST_NEXT(command)
#define sieve_ast_command_count(node) __LIST_COUNT(node, commands)

/* Compare the identifier of the previous command */
#define sieve_ast_prev_cmd_is(cmd, id) \
	( (cmd)->prev == NULL ? FALSE : strncasecmp((cmd)->prev->identifier, id, sizeof(id)-1) == 0 )
	
/* AST test macros */
#define sieve_ast_test_first(node) __LIST_FIRST(node, tests)
#define sieve_ast_test_next(test) __LIST_NEXT(test)
#define sieve_ast_test_count(node) __LIST_COUNT(node, tests)

/* AST argument macros */
#define sieve_ast_argument_first(node) __LIST_FIRST(node, arguments)
#define sieve_ast_argument_next(argument) __LIST_NEXT(argument)
#define sieve_ast_argument_count(node) __LIST_COUNT(node, arguments)
#define sieve_ast_argument_type(argument) ((argument) == NULL ? SAAT_NONE : (argument)->type)
#define sieve_ast_argument_line(argument) ((argument) == NULL ? 0 : (argument)->source_line)

#define sieve_ast_argument_str(argument) ((argument)->_value.str)
#define sieve_ast_argument_strc(argument) (str_c((argument)->_value.str))
#define sieve_ast_argument_tag(argument) ((argument)->_value.tag)
#define sieve_ast_argument_number(argument) ((argument)->_value.number)

/* AST string list macros */
// @UNSAFE: should check whether we are actually accessing a string list
#define sieve_ast_strlist_first(list) __LIST_FIRST(list, _value.strlist)
#define sieve_ast_strlist_next(str) __LIST_NEXT(str)
#define sieve_ast_strlist_str(str) sieve_ast_argument_str(str)
#define sieve_ast_strlist_strc(str) sieve_ast_argument_strc(str)
#define sieve_ast_strlist_count(list) __LIST_COUNT(list, _value.strlist)

#endif /* __SIEVE_AST_H__ */

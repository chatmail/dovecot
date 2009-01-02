/* Copyright (c) 2002-2008 Dovecot Sieve authors, see the included COPYING file
 */

#ifndef __SIEVE_RESULT_H
#define __SIEVE_RESULT_H

#include "sieve-common.h"

/*
 * Types
 */
 
struct sieve_side_effects_list;

/*
 * Result object
 */

struct sieve_result;

struct sieve_result *sieve_result_create
	(struct sieve_error_handler *ehandler);

void sieve_result_ref(struct sieve_result *result); 

void sieve_result_unref(struct sieve_result **result); 

pool_t sieve_result_pool(struct sieve_result *result);

struct sieve_error_handler *sieve_result_get_error_handler
	(struct sieve_result *result);

/*
 * Extension support
 */

void sieve_result_extension_set_context
	(struct sieve_result *result, const struct sieve_extension *ext,
		void *context);
const void *sieve_result_extension_get_context
	(struct sieve_result *result, const struct sieve_extension *ext); 

/* 
 * Result printing 
 */

struct sieve_result_print_env {
	struct sieve_result *result;
	const struct sieve_script_env *scriptenv;
	struct ostream *stream;
};

void sieve_result_printf
	(const struct sieve_result_print_env *penv, const char *fmt, ...);
void sieve_result_action_printf
	(const struct sieve_result_print_env *penv, const char *fmt, ...);
void sieve_result_seffect_printf
	(const struct sieve_result_print_env *penv, const char *fmt, ...);

bool sieve_result_print
	(struct sieve_result *result, const struct sieve_script_env *senv, 
		struct ostream *stream);

/* 
 * Error handling 
 */

void sieve_result_log
	(const struct sieve_action_exec_env *aenv, const char *fmt, ...)
		ATTR_FORMAT(2, 3);
void sieve_result_warning
	(const struct sieve_action_exec_env *aenv, const char *fmt, ...)
		ATTR_FORMAT(2, 3);
void sieve_result_error
	(const struct sieve_action_exec_env *aenv, const char *fmt, ...)
		ATTR_FORMAT(2, 3);

/*
 * Result composition
 */
 
void sieve_result_add_implicit_side_effect
(struct sieve_result *result, const struct sieve_action *to_action, 
	const struct sieve_side_effect *seffect, void *context);
	
int sieve_result_add_action
	(const struct sieve_runtime_env *renv, const struct sieve_action *action, 
		struct sieve_side_effects_list *seffects, unsigned int source_line, 
		void *context, unsigned int instance_limit);
int sieve_result_add_keep
	(const struct sieve_runtime_env *renv, 
		struct sieve_side_effects_list *seffects, unsigned int source_line);

/*
 * Result execution
 */
 
bool sieve_result_implicit_keep
	(struct sieve_result *result, const struct sieve_message_data *msgdata,
		const struct sieve_script_env *senv, struct sieve_exec_status *estatus);

int sieve_result_execute
	(struct sieve_result *result, const struct sieve_message_data *msgdata,
		const struct sieve_script_env *senv, struct sieve_exec_status *estatus);

/*
 * Result evaluation
 */

struct sieve_result_iterate_context;

struct sieve_result_iterate_context *sieve_result_iterate_init
	(struct sieve_result *result);
const struct sieve_action *sieve_result_iterate_next
	(struct sieve_result_iterate_context *rictx, bool *keep, void **context);
	
/*
 * Side effects list
 */
 
struct sieve_side_effects_list *sieve_side_effects_list_create
	(struct sieve_result *result);
void sieve_side_effects_list_add
(struct sieve_side_effects_list *list, const struct sieve_side_effect *seffect, 
	void *context);

#endif

/* Copyright (c) 2002-2009 Dovecot Sieve authors, see the included COPYING file 
 */

#ifndef __SIEVE_ACTIONS_H
#define __SIEVE_ACTIONS_H

#include "lib.h"
#include "mail-storage.h"

#include "sieve-common.h"
#include "sieve-objects.h"
#include "sieve-extensions.h"

/*
 * Action execution environment
 */

struct sieve_action_exec_env { 
	struct sieve_result *result;
	const struct sieve_message_data *msgdata;
	const struct sieve_script_env *scriptenv;
	struct sieve_exec_status *exec_status;
};

const char *sieve_action_get_location(const struct sieve_action_exec_env *aenv);

/*
 * Action flags
 */

enum sieve_action_flags {
	SIEVE_ACTFLAG_TRIES_DELIVER = (1 << 0),
	SIEVE_ACTFLAG_SENDS_RESPONSE = (1 << 1)
};

/*
 *
 */
 
struct sieve_action_data {
	const struct sieve_action *action;
	const char *location;
	void *context;
	bool executed;
};

/* 
 * Action object
 */

struct sieve_action {
	const char *name;
	unsigned int flags;
	
	bool (*equals)
		(const struct sieve_script_env *senv, const void *ctx1, const void *ctx2);

	/* Result verification */
	
	int (*check_duplicate)	
		(const struct sieve_runtime_env *renv,
			const struct sieve_action_data *act, 
			const struct sieve_action_data *act_other);	
	int (*check_conflict)
		(const struct sieve_runtime_env *renv, 
			const struct sieve_action_data *act, 
			const struct sieve_action_data *act_other);	

	/* Result printing */
	
	void (*print)
		(const struct sieve_action *action, 
			const struct sieve_result_print_env *penv, void *context, bool *keep);	
		
	/* Result execution */	
		
	bool (*start)
		(const struct sieve_action *action, 
			const struct sieve_action_exec_env *aenv, void *context, 
			void **tr_context);		
	bool (*execute)
		(const struct sieve_action *action, 
			const struct sieve_action_exec_env *aenv, void *tr_context);
	bool (*commit)
		(const struct sieve_action *action, 
			const struct sieve_action_exec_env *aenv, void *tr_context, bool *keep);
	void (*rollback)
		(const struct sieve_action *action, 
			const struct sieve_action_exec_env *aenv, void *tr_context, bool success);
};

/* 
 * Action side effects 
 */

/* Side effect object */

struct sieve_side_effect {
	struct sieve_object object;
	
	/* The action it is supposed to link to */
	
	const struct sieve_action *to_action;
		
	/* Context coding */
	
	bool (*dump_context)
		(const struct sieve_side_effect *seffect, 
			const struct sieve_dumptime_env *renv, sieve_size_t *address);
	bool (*read_context)
		(const struct sieve_side_effect *seffect, 
			const struct sieve_runtime_env *renv, sieve_size_t *address,
			void **se_context);
		
	/* Result verification */
	
	int (*merge)
		(const struct sieve_runtime_env *renv, const struct sieve_action *action, 
			const struct sieve_side_effect *seffect, 
			void **old_context, void *new_context);

	/* Result printing */	
			
	void (*print)
		(const struct sieve_side_effect *seffect, const struct sieve_action *action, 
			const struct sieve_result_print_env *penv, void *se_context, bool *keep);

	/* Result execution */

	bool (*pre_execute)
		(const struct sieve_side_effect *seffect, const struct sieve_action *action, 
			const struct sieve_action_exec_env *aenv, void **se_context, 
			void *tr_context);
	bool (*post_execute)
		(const struct sieve_side_effect *seffect, const struct sieve_action *action, 
			const struct sieve_action_exec_env *aenv, void *se_context, 
			void *tr_context);
	void (*post_commit)
		(const struct sieve_side_effect *seffect, const struct sieve_action *action, 
			const struct sieve_action_exec_env *aenv, void *se_context,
			void *tr_context, bool *keep);
	void (*rollback)
		(const struct sieve_side_effect *seffect, const struct sieve_action *action, 
			const struct sieve_action_exec_env *aenv, void *se_context,
			void *tr_context, bool success);
};

/*
 * Side effect operand
 */
 
#define SIEVE_EXT_DEFINE_SIDE_EFFECT(SEF) SIEVE_EXT_DEFINE_OBJECT(SEF)
#define SIEVE_EXT_DEFINE_SIDE_EFFECTS(SEFS) SIEVE_EXT_DEFINE_OBJECTS(SEFS)

#define SIEVE_OPT_SIDE_EFFECT -1

extern const struct sieve_operand_class sieve_side_effect_operand_class;

static inline void sieve_opr_side_effect_emit
(struct sieve_binary *sbin, const struct sieve_side_effect *seff)
{ 
	sieve_opr_object_emit(sbin, &seff->object);
}

static inline const struct sieve_side_effect *sieve_opr_side_effect_read
(const struct sieve_runtime_env *renv, sieve_size_t *address)
{
	return (const struct sieve_side_effect *) sieve_opr_object_read
		(renv, &sieve_side_effect_operand_class, address);
}

bool sieve_opr_side_effect_dump
	(const struct sieve_dumptime_env *denv, sieve_size_t *address);

/* 
 * Core actions 
 */

extern const struct sieve_action act_redirect;
extern const struct sieve_action act_store;
extern const struct sieve_action act_discard;

/* 
 * Store action
 */

struct act_store_context {
	/* Folder name represented in modified utf-7 */
	const char *folder; 
};

struct act_store_transaction {
	struct act_store_context *context;
	struct mail_namespace *namespace;
	struct mailbox *box;
	struct mailbox_transaction_context *mail_trans;
	struct mail *dest_mail;
	const char *error;
	
	enum mail_flags flags;
	ARRAY_DEFINE(keywords, const char *);
};

int sieve_act_store_add_to_result
	(const struct sieve_runtime_env *renv, 
		struct sieve_side_effects_list *seffects, const char *folder,
		unsigned int source_line);

/*		
 * Action utility functions
 */

bool sieve_action_duplicate_check_available
	(const struct sieve_script_env *senv);
int sieve_action_duplicate_check
	(const struct sieve_script_env *senv, const void *id, size_t id_size);
void sieve_action_duplicate_mark
	(const struct sieve_script_env *senv, const void *id, size_t id_size,
		time_t time);

#endif /* __SIEVE_ACTIONS_H */
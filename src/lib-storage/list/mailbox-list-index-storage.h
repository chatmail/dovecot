#ifndef MAILBOX_LIST_INDEX_STORAGE_H
#define MAILBOX_LIST_INDEX_STORAGE_H

#include "mail-storage-private.h"

#define INDEX_LIST_STORAGE_CONTEXT(obj) \
	MODULE_CONTEXT_REQUIRE(obj, index_list_storage_module)

struct index_list_mailbox {
	union mailbox_module_context module_ctx;

	uint32_t pre_sync_log_file_seq;
	uoff_t pre_sync_log_file_head_offset;

	bool have_backend:1;
};

extern MODULE_CONTEXT_DEFINE(index_list_storage_module,
			     &mail_storage_module_register);

#endif

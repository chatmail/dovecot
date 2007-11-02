/* Copyright (C) 2005 Timo Sirainen */

#include "lib.h"
#include "array.h"
#include "istream-zlib.h"
#include "home-expand.h"
#include "istream.h"
#include "maildir/maildir-storage.h"
#include "maildir/maildir-uidlist.h"
#include "index-mail.h"
#include "zlib-plugin.h"

#include <fcntl.h>

struct zlib_mail_storage {
	struct mail_storage_vfuncs super;
};

struct zlib_mailbox {
	struct mailbox_vfuncs super;
};

struct zlib_mail {
	struct mail_vfuncs super;
};

#define ZLIB_CONTEXT(obj) \
	*((void **)array_idx_modifyable(&(obj)->module_contexts, \
					zlib_storage_module_id))

/* defined by imap, pop3, lda */
extern void (*hook_mail_storage_created)(struct mail_storage *storage);

const char *zlib_plugin_version = PACKAGE_VERSION;

static void (*zlib_next_hook_mail_storage_created)
	(struct mail_storage *storage);

static unsigned int zlib_storage_module_id = 0;
static bool zlib_storage_module_id_set = FALSE;

static struct istream *
zlib_maildir_get_stream(struct mail *_mail, struct message_size *hdr_size,
			struct message_size *body_size)
{
	struct maildir_mailbox *mbox = (struct maildir_mailbox *)_mail->box;
	struct mail_private *mail = (struct mail_private *)_mail;
	struct index_mail *imail = (struct index_mail *)mail;
	struct zlib_mail *zmail = ZLIB_CONTEXT(mail);
	struct istream *input;
	const char *fname, *p;
        enum maildir_uidlist_rec_flag flags;
	int fd;

	if (imail->data.stream != NULL)
		return zmail->super.get_stream(_mail, hdr_size, body_size);

	input = zmail->super.get_stream(_mail, NULL, NULL);
	if (input == NULL)
		return NULL;
	i_assert(input == imail->data.stream);

	fname = maildir_uidlist_lookup(mbox->uidlist, _mail->uid, &flags);
	i_assert(fname != NULL);
	p = strstr(fname, ":2,");
	if (p != NULL && strchr(p + 3, 'Z') != NULL) {
		/* has a Z flag - it's compressed */
		fd = dup(i_stream_get_fd(imail->data.stream));
		if (fd == -1)
			i_error("zlib plugin: dup() failed: %m");
		i_stream_unref(&imail->data.stream);

		if (fd == -1)
			return NULL;
		imail->data.stream = i_stream_create_zlib(fd, default_pool);
	}
	return index_mail_init_stream(imail, hdr_size, body_size);
}

static struct mail *
zlib_maildir_mail_alloc(struct mailbox_transaction_context *t,
			enum mail_fetch_field wanted_fields,
			struct mailbox_header_lookup_ctx *wanted_headers)
{
	struct zlib_mailbox *zbox = ZLIB_CONTEXT(t->box);
	struct zlib_mail *zmail;
	struct mail *_mail;
	struct mail_private *mail;

	_mail = zbox->super.mail_alloc(t, wanted_fields, wanted_headers);
	mail = (struct mail_private *)_mail;

	zmail = p_new(mail->pool, struct zlib_mail, 1);
	zmail->super = mail->v;

	mail->v.get_stream = zlib_maildir_get_stream;
	array_idx_set(&mail->module_contexts, zlib_storage_module_id, &zmail);
	return _mail;
}

static void zlib_maildir_open_init(struct mailbox *box)
{
	struct zlib_mailbox *zbox;

	zbox = p_new(box->pool, struct zlib_mailbox, 1);
	zbox->super = box->v;
	box->v.mail_alloc = zlib_maildir_mail_alloc;

	array_idx_set(&box->module_contexts, zlib_storage_module_id, &zbox);
}

static struct mailbox *
zlib_mailbox_open(struct mail_storage *storage, const char *name,
		  struct istream *input, enum mailbox_open_flags flags)
{
	struct zlib_mail_storage *qstorage = ZLIB_CONTEXT(storage);
	struct mailbox *box;
	struct istream *zlib_input = NULL;
	size_t len = strlen(name);

	if (input == NULL && len > 3 && strcmp(name + len - 3, ".gz") == 0 &&
	    strcmp(storage->name, "mbox") == 0) {
		/* Looks like a .gz mbox file */
		const char *path;
		bool is_file;

		path = mail_storage_get_mailbox_path(storage, name, &is_file);
		if (is_file && path != NULL) {
			/* it's a single file mailbox. we can handle this. */
			int fd;

			fd = open(path, O_RDONLY);
			if (fd != -1) {
				input = zlib_input =
					i_stream_create_zlib(fd, default_pool);
			}
		}
	}

	box = qstorage->super.mailbox_open(storage, name, input, flags);

	if (zlib_input != NULL)
		i_stream_unref(&zlib_input);

	if (strcmp(storage->name, "maildir") == 0) 
		zlib_maildir_open_init(box);
	return box;
}

static void zlib_mail_storage_created(struct mail_storage *storage)
{
	struct zlib_mail_storage *qstorage;

	if (zlib_next_hook_mail_storage_created != NULL)
		zlib_next_hook_mail_storage_created(storage);

	qstorage = p_new(storage->pool, struct zlib_mail_storage, 1);
	qstorage->super = storage->v;
	storage->v.mailbox_open = zlib_mailbox_open;

	if (!zlib_storage_module_id_set) {
		zlib_storage_module_id = mail_storage_module_id++;
		zlib_storage_module_id_set = TRUE;
	}

	array_idx_set(&storage->module_contexts,
		      zlib_storage_module_id, &qstorage);
}

void zlib_plugin_init(void)
{
	zlib_next_hook_mail_storage_created =
		hook_mail_storage_created;
	hook_mail_storage_created = zlib_mail_storage_created;
}

void zlib_plugin_deinit(void)
{
	hook_mail_storage_created =
		zlib_next_hook_mail_storage_created;
}

#ifndef DSYNC_BRAIN_H
#define DSYNC_BRAIN_H

#include "guid.h"
#include "mail-error.h"

struct mail_namespace;
struct mail_user;
struct dsync_ibc;

enum dsync_brain_flags {
	DSYNC_BRAIN_FLAG_SEND_MAIL_REQUESTS	= 0x01,
	DSYNC_BRAIN_FLAG_BACKUP_SEND		= 0x02,
	DSYNC_BRAIN_FLAG_BACKUP_RECV		= 0x04,
	DSYNC_BRAIN_FLAG_DEBUG			= 0x08,
	DSYNC_BRAIN_FLAG_SYNC_VISIBLE_NAMESPACES= 0x10,
	/* Sync everything but the actual mails (e.g. mailbox creates,
	   deletes) */
	DSYNC_BRAIN_FLAG_NO_MAIL_SYNC		= 0x20,
	/* Used with BACKUP_SEND/RECV: Don't force the
	   Use the two-way syncing algorithm, but don't actually modify
	   anything locally. (Useful during migration.) */
	DSYNC_BRAIN_FLAG_NO_BACKUP_OVERWRITE	= 0x40,
	/* Run storage purge on the remote after syncing.
	   Useful with e.g. a nightly doveadm backup. */
	DSYNC_BRAIN_FLAG_PURGE_REMOTE		= 0x80,
	/* Don't prefetch mail bodies until they're actually needed. This works
	   only with pipe ibc. It's useful if most of the mails can be copied
	   directly within filesystem without having to read them. */
	DSYNC_BRAIN_FLAG_NO_MAIL_PREFETCH	= 0x100,
	/* Disable mailbox renaming logic. This is just a kludge that should
	   be removed once the renaming logic has no more bugs.. */
	DSYNC_BRAIN_FLAG_NO_MAILBOX_RENAMES	= 0x200,
	/* Add MAILBOX_TRANSACTION_FLAG_NO_NOTIFY to transactions. */
	DSYNC_BRAIN_FLAG_NO_NOTIFY		= 0x400,
	/* Workaround missing Date/Message-ID headers */
	DSYNC_BRAIN_FLAG_EMPTY_HDR_WORKAROUND	= 0x800,
};

enum dsync_brain_sync_type {
	DSYNC_BRAIN_SYNC_TYPE_UNKNOWN,
	/* Go through all mailboxes to make sure everything is synced */
	DSYNC_BRAIN_SYNC_TYPE_FULL,
	/* Go through all mailboxes that have changed (based on UIDVALIDITY,
	   UIDNEXT, HIGHESTMODSEQ). If both sides have had equal amount of
	   changes in some mailbox, it may get incorrectly skipped. */
	DSYNC_BRAIN_SYNC_TYPE_CHANGED,
	/* Use saved state to find out what has changed. */
	DSYNC_BRAIN_SYNC_TYPE_STATE
};

struct dsync_brain_settings {
	const char *process_title_prefix;
	/* Sync only these namespaces */
	ARRAY(struct mail_namespace *) sync_namespaces;
	/* Sync only this mailbox name */
	const char *sync_box;
	/* Use this virtual \All mailbox to be able to copy mails with the same
	   GUID instead of saving them twice. With most storages this results
	   in less disk space usage. */
	const char *virtual_all_box;
	/* Sync only this mailbox GUID */
	guid_128_t sync_box_guid;
	/* Exclude these mailboxes from the sync. They can contain '*'
	   wildcards and be \special-use flags. */
	const char *const *exclude_mailboxes;
	/* Alternative character to use in mailbox names where the original
	   character cannot be used. */
	char mailbox_alt_char;
	/* Sync only mails with received timestamp at least this high. */
	time_t sync_since_timestamp;
	/* Sync only mails with received timestamp less or equal than this */
	time_t sync_until_timestamp;
	/* Don't sync mails larger than this. */
	uoff_t sync_max_size;
	/* Sync only mails which contains / doesn't contain this flag.
	   '-' at the beginning means this flag must not exist. */
	const char *sync_flag;
	/* Headers to hash (defaults to Date, Message-ID) */
	const char *const *hashed_headers;

	/* If non-zero, use dsync lock file for this user */
	unsigned int lock_timeout_secs;
	/* If non-zero, importing will attempt to commit transaction after
	   saving this many messages. */
	unsigned int import_commit_msgs_interval;
	/* Input state for DSYNC_BRAIN_SYNC_TYPE_STATE */
	const char *state;
};

struct dsync_brain *
dsync_brain_master_init(struct mail_user *user, struct dsync_ibc *ibc,
			enum dsync_brain_sync_type sync_type,
			enum dsync_brain_flags flags,
			const struct dsync_brain_settings *set);
struct dsync_brain *
dsync_brain_slave_init(struct mail_user *user, struct dsync_ibc *ibc,
		       bool local, const char *process_title_prefix);
/* Returns 0 if everything was successful, -1 if syncing failed in some way */
int dsync_brain_deinit(struct dsync_brain **brain, enum mail_error *error_r);

/* Returns TRUE if brain needs to run more, FALSE if it's finished.
   changed_r is TRUE if anything happened during this run. */
bool dsync_brain_run(struct dsync_brain *brain, bool *changed_r);
/* Returns TRUE if brain has failed, and there's no point in continuing. */
bool dsync_brain_has_failed(struct dsync_brain *brain);
/* Returns the current sync state string, which can be given as parameter to
   dsync_brain_master_init() to quickly sync only the new changes. */
void dsync_brain_get_state(struct dsync_brain *brain, string_t *output);
/* Returns the sync type that was used. Mainly useful with slave brain. */
enum dsync_brain_sync_type dsync_brain_get_sync_type(struct dsync_brain *brain);
/* If there were any unexpected changes during the sync, return the reason
   for them. Otherwise return NULL. If remote_only_r=TRUE, this brain itself
   didn't see any changes, but the remote brain did. */
const char *dsync_brain_get_unexpected_changes_reason(struct dsync_brain *brain,
						      bool *remote_only_r);
/* Returns TRUE if we want to sync this namespace. */
bool dsync_brain_want_namespace(struct dsync_brain *brain,
				struct mail_namespace *ns);

#endif

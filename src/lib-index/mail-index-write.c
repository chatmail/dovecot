/* Copyright (c) 2003-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "nfs-workarounds.h"
#include "read-full.h"
#include "write-full.h"
#include "ostream.h"
#include "mail-index-private.h"
#include "mail-transaction-log-private.h"

#include <stdio.h>

#define MAIL_INDEX_MIN_UPDATE_SIZE 1024
/* if we're updating >= count-n messages, recreate the index */
#define MAIL_INDEX_MAX_OVERWRITE_NEG_SEQ_COUNT 10

static int mail_index_create_backup(struct mail_index *index)
{
	const char *backup_path, *tmp_backup_path;
	int ret;

	if (index->fd != -1) {
		/* we very much want to avoid creating a backup file that
		   hasn't been written to disk yet */
		if (fdatasync(index->fd) < 0) {
			mail_index_set_error(index, "fdatasync(%s) failed: %m",
					     index->filepath);
			return -1;
		}
	}

	backup_path = t_strconcat(index->filepath, ".backup", NULL);
	tmp_backup_path = t_strconcat(backup_path, ".tmp", NULL);
	ret = link(index->filepath, tmp_backup_path);
	if (ret < 0 && errno == EEXIST) {
		if (unlink(tmp_backup_path) < 0 && errno != ENOENT) {
			mail_index_set_error(index, "unlink(%s) failed: %m",
					     tmp_backup_path);
			return -1;
		}
		ret = link(index->filepath, tmp_backup_path);
	}
	if (ret < 0) {
		if (errno == ENOENT) {
			/* no dovecot.index file, ignore */
			return 0;
		}
		mail_index_set_error(index, "link(%s, %s) failed: %m",
				     index->filepath, tmp_backup_path);
		return -1;
	}

	if (rename(tmp_backup_path, backup_path) < 0) {
		mail_index_set_error(index, "rename(%s, %s) failed: %m",
				     tmp_backup_path, backup_path);
		return -1;
	}
	return 0;
}

static int mail_index_recreate(struct mail_index *index)
{
	struct mail_index_map *map = index->map;
	struct ostream *output;
	unsigned int base_size;
	const char *path;
	int ret = 0, fd;

	i_assert(!MAIL_INDEX_IS_IN_MEMORY(index));
	i_assert(map->hdr.indexid == index->indexid);
	i_assert((map->hdr.flags & MAIL_INDEX_HDR_FLAG_CORRUPTED) == 0);
	i_assert(index->indexid != 0);

	fd = mail_index_create_tmp_file(index, index->filepath, &path);
	if (fd == -1)
		return -1;

	output = o_stream_create_fd_file(fd, 0, FALSE);
	o_stream_cork(output);

	base_size = I_MIN(map->hdr.base_header_size, sizeof(map->hdr));
	o_stream_nsend(output, &map->hdr, base_size);
	o_stream_nsend(output, MAIL_INDEX_MAP_HDR_OFFSET(map, base_size),
		       map->hdr.header_size - base_size);
	o_stream_nsend(output, map->rec_map->records,
		       map->rec_map->records_count * map->hdr.record_size);
	if (o_stream_finish(output) < 0) {
		mail_index_file_set_syscall_error(index, path, "write()");
		ret = -1;
	}
	o_stream_destroy(&output);

	if (ret == 0 && index->set.fsync_mode != FSYNC_MODE_NEVER) {
		if (fdatasync(fd) < 0) {
			mail_index_file_set_syscall_error(index, path,
							  "fdatasync()");
			ret = -1;
		}
	}

	if (close(fd) < 0) {
		mail_index_file_set_syscall_error(index, path, "close()");
		ret = -1;
	}

	if ((index->flags & MAIL_INDEX_OPEN_FLAG_KEEP_BACKUPS) != 0)
		(void)mail_index_create_backup(index);

	if (ret == 0 && rename(path, index->filepath) < 0) {
		mail_index_set_error(index, "rename(%s, %s) failed: %m",
				     path, index->filepath);
		ret = -1;
	}

	if (ret < 0)
		i_unlink(path);
	return ret;
}

static bool mail_index_should_recreate(struct mail_index *index)
{
	struct stat st1, st2;

	if (nfs_safe_stat(index->filepath, &st1) < 0) {
		if (errno != ENOENT) {
			mail_index_set_syscall_error(index, "stat()");
			return FALSE;
		} else if (index->fd == -1) {
			/* main index hasn't been created yet */
			return TRUE;
		} else {
			/* mailbox was just deleted? don't log an error */
			return FALSE;
		}
	}
	if (index->fd == -1) {
		/* main index was just created by another process */
		return FALSE;
	}
	if (fstat(index->fd, &st2) < 0) {
		if (!ESTALE_FSTAT(errno))
			mail_index_set_syscall_error(index, "fstat()");
		return FALSE;
	}
	if (st1.st_ino != st2.st_ino ||
	    !CMP_DEV_T(st1.st_dev, st2.st_dev)) {
		/* Index has already been recreated since we last read it.
		   We can't trust our decisions about whether to recreate it. */
		return FALSE;
	}
	return TRUE;
}

void mail_index_write(struct mail_index *index, bool want_rotate,
		      const char *reason)
{
	struct mail_index_header *hdr = &index->map->hdr;
	bool rotated = FALSE;

	i_assert(index->log_sync_locked);

	if (index->readonly)
		return;

	/* rotate the .log before writing index, so the index will point to
	   the latest log. Note that it's the caller's responsibility to make
	   sure that the .log can be safely rotated (i.e. everything has been
	   synced). */
	if (want_rotate) {
		if (mail_transaction_log_rotate(index->log, FALSE) == 0) {
			struct mail_transaction_log_file *file =
				index->log->head;
			/* Log rotation refreshes the index, which may cause the
			   map to change. Because we're locked, it's not
			   supposed to happen and will likely lead to an
			   assert-crash below, but we still need to make sure
			   we're using the latest map to do the checks. */
			hdr = &index->map->hdr;
			i_assert(file->hdr.prev_file_seq == hdr->log_file_seq);
			i_assert(file->hdr.prev_file_offset == hdr->log_file_head_offset);
			hdr->log_file_seq = file->hdr.file_seq;
			hdr->log_file_head_offset =
				hdr->log_file_tail_offset = file->hdr.hdr_size;
			/* Assume .log.2 was created successfully. If it
			   wasn't, it just causes an extra stat() and gets
			   fixed later on. */
			hdr->log2_rotate_time = ioloop_time;
			rotated = TRUE;
		}
	}

	if (MAIL_INDEX_IS_IN_MEMORY(index))
		;
	else if (!rotated && !mail_index_should_recreate(index)) {
		/* make sure we don't keep getting back in here */
		index->reopen_main_index = TRUE;
	} else {
		if (mail_index_recreate(index) < 0) {
			(void)mail_index_move_to_memory(index);
			return;
		}
		event_set_name(index->event, "mail_index_recreated");
		e_debug(index->event, "Recreated %s (file_seq=%u) because: %s",
			index->filepath, hdr->log_file_seq, reason);
	}

	index->main_index_hdr_log_file_seq = hdr->log_file_seq;
	index->main_index_hdr_log_file_tail_offset = hdr->log_file_tail_offset;
}

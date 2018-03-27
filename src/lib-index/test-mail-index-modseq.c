/* Copyright (c) 2016-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "unlink-directory.h"
#include "test-common.h"
#include "mail-index-private.h"
#include "mail-index-modseq.h"
#include "mail-transaction-log-private.h"

#define TESTDIR_NAME ".dovecot.test"

static void test_mail_index_modseq_get_next_log_offset(void)
{
	static const struct {
		uint32_t log_seq;
		uoff_t log_offset;
	} tests[] = {
		{ 0, 0 },
		{ 2, 40 },
		{ 2, 148 },
		{ 2, 164 },
		{ 3, 40 },
		{ 3, 56 },
		{ 3, 72 },
		{ 3, 88 },
	};
	struct mail_index *index;
	struct mail_index_view *view, *view2;
	struct mail_index_transaction *trans;
	uint32_t seq, uid;
	const char *error;

	(void)unlink_directory(TESTDIR_NAME, UNLINK_DIRECTORY_FLAG_RMDIR, &error);
	if (mkdir(TESTDIR_NAME, 0700) < 0)
		i_error("mkdir(%s) failed: %m", TESTDIR_NAME);

	ioloop_time = 1;

	test_begin("mail_transaction_log_file_get_modseq_next_offset()");
	index = mail_index_alloc(NULL, TESTDIR_NAME, "test.dovecot.index");
	test_assert(mail_index_open_or_create(index, MAIL_INDEX_OPEN_FLAG_CREATE) == 0);
	view = mail_index_view_open(index);
	mail_index_modseq_enable(index);

	trans = mail_index_transaction_begin(view, 0);
	uid = 1234;
	mail_index_update_header(trans,
		offsetof(struct mail_index_header, uid_validity),
		&uid, sizeof(uid), TRUE);
	test_assert(mail_index_transaction_commit(&trans) == 0);

	for (uid = 1; uid <= 3; uid++) {
		trans = mail_index_transaction_begin(view, 0);
		mail_index_append(trans, uid, &seq);
		test_assert(mail_index_transaction_commit(&trans) == 0);
	}
	test_assert(mail_transaction_log_file_lock(index->log->head) == 0);
	test_assert(mail_transaction_log_rotate(index->log, FALSE) == 0);
	mail_transaction_log_file_unlock(index->log->head, "rotating");
	for (uid = 4; uid <= 6; uid++) {
		trans = mail_index_transaction_begin(view, 0);
		mail_index_append(trans, uid, &seq);
		test_assert(mail_index_transaction_commit(&trans) == 0);
	}

	view2 = mail_index_view_open(index);
	for (uint64_t modseq = 1; modseq <= 7; modseq++) {
		uint32_t log_seq;
		uoff_t log_offset;

		test_assert_idx(mail_index_modseq_get_next_log_offset(view2, modseq, &log_seq, &log_offset) == (tests[modseq].log_seq != 0), modseq);
		test_assert_idx(tests[modseq].log_seq == log_seq && tests[modseq].log_offset == log_offset, modseq);
	}

	mail_index_view_close(&view);
	mail_index_view_close(&view2);
	mail_index_close(index);
	mail_index_free(&index);

	(void)unlink_directory(TESTDIR_NAME, UNLINK_DIRECTORY_FLAG_RMDIR, &error);
	test_end();
}

int main(void)
{
	static void (*const test_functions[])(void) = {
		test_mail_index_modseq_get_next_log_offset,
		NULL
	};
	return test_run(test_functions);
}

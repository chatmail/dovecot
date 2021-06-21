/* Copyright (c) 2011-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "istream.h"
#include "write-full.h"
#include "strescape.h"
#include "process-title.h"
#include "master-service.h"
#include "master-service-settings.h"
#include "mail-namespace.h"
#include "mail-storage-private.h"
#include "mail-storage-service.h"
#include "mail-search-build.h"
#include "master-connection.h"

#include <unistd.h>

#define INDEXER_PROTOCOL_MAJOR_VERSION 1
#define INDEXER_PROTOCOL_MINOR_VERSION 0

#define INDEXER_WORKER_HANDSHAKE "VERSION\tindexer-worker-master\t1\t0\n%u\n"
#define INDEXER_MASTER_NAME "indexer-master-worker"

struct master_connection *master_conn;

struct master_connection {
	struct mail_storage_service_ctx *storage_service;

	int fd;
	struct io *io;
	struct istream *input;
	struct ostream *output;

	bool version_received:1;
};

static void ATTR_NULL(1, 2)
indexer_worker_refresh_proctitle(const char *username, const char *mailbox,
				 uint32_t seq1, uint32_t seq2)
{
	if (!master_service_settings_get(master_service)->verbose_proctitle)
		return;

	if (username == NULL)
		process_title_set("[idling]");
	else if (seq1 == 0)
		process_title_set(t_strdup_printf("[%s %s]", username, mailbox));
	else {
		process_title_set(t_strdup_printf("[%s %s - %u/%u]",
						  username, mailbox, seq1, seq2));
	}
}

static const char *
get_attempt_error(unsigned int counter, uint32_t first_uid, uint32_t last_uid)
{
	if (counter == 0)
		return " (no mails indexed)";
	return t_strdup_printf(
		" (attempted to index %u messages between UIDs %u..%u)",
		counter, first_uid, last_uid);
}

static int
index_mailbox_precache(struct master_connection *conn, struct mailbox *box)
{
	struct mail_storage *storage = mailbox_get_storage(box);
	const char *username = mail_storage_get_user(storage)->username;
	const char *box_vname = mailbox_get_vname(box);
	const char *errstr;
	enum mail_error error;
	struct mailbox_status status;
	struct mailbox_transaction_context *trans;
	struct mail_search_args *search_args;
	struct mail_search_context *ctx;
	struct mail *mail;
	struct mailbox_metadata metadata;
	uint32_t seq, first_uid = 0, last_uid = 0;
	char percentage_str[2+1+1];
	unsigned int counter = 0, max, percentage, percentage_sent = 0;
	int ret = 0;

	if (mailbox_get_metadata(box, MAILBOX_METADATA_PRECACHE_FIELDS,
				 &metadata) < 0) {
		i_error("Mailbox %s: Precache-fields lookup failed: %s",
			mailbox_get_vname(box),
			mailbox_get_last_internal_error(box, NULL));
		return -1;
	}
	if (mailbox_get_status(box, STATUS_MESSAGES | STATUS_LAST_CACHED_SEQ,
			       &status) < 0) {
		i_error("Mailbox %s: Status lookup failed: %s",
			mailbox_get_vname(box),
			mailbox_get_last_internal_error(box, NULL));
		return -1;
	}
	seq = status.last_cached_seq + 1;

	trans = mailbox_transaction_begin(box, MAILBOX_TRANSACTION_FLAG_NO_CACHE_DEC,
					  "indexing");
	search_args = mail_search_build_init();
	mail_search_build_add_seqset(search_args, seq, status.messages);

	struct event *index_event = event_create(box->event);
	event_set_name(index_event, "indexer_worker_indexing_finished");
	event_enable_user_cpu_usecs(index_event);

	ctx = mailbox_search_init(trans, search_args, NULL,
				  metadata.precache_fields, NULL);
	mail_search_args_unref(&search_args);

	max = status.messages + 1 - seq;
	while (mailbox_search_next(ctx, &mail)) {
		if (first_uid == 0)
			first_uid = mail->uid;
		last_uid = mail->uid;

		if (mail_precache(mail) < 0) {
			i_error("Mailbox %s: Precache for UID=%u failed: %s%s",
				mailbox_get_vname(box), mail->uid,
				mailbox_get_last_internal_error(box, NULL),
				get_attempt_error(counter, first_uid, last_uid));
			ret = -1;
			break;
		}
		if (++counter % 100 == 0) {
			percentage = counter*100 / max;
			if (percentage != percentage_sent && percentage < 100) {
				percentage_sent = percentage;
				if (i_snprintf(percentage_str,
					       sizeof(percentage_str), "%u\n",
					       percentage) < 0)
					i_unreached();
				(void)write_full(conn->fd, percentage_str,
						 strlen(percentage_str));
			}
			indexer_worker_refresh_proctitle(username, box_vname,
							 counter, max);
		}
	}
	if (mailbox_search_deinit(&ctx) < 0) {
		i_error("Mailbox %s: Mail search failed: %s%s",
			mailbox_get_vname(box),
			mailbox_get_last_internal_error(box, NULL),
			get_attempt_error(counter, first_uid, last_uid));
		ret = -1;
	}
	const char *uids = first_uid == 0 ? "" :
		t_strdup_printf(" (UIDs %u..%u)", first_uid, last_uid);
	event_add_int(index_event, "message_count", counter);
	event_add_int(index_event, "first_uid", first_uid);
	event_add_int(index_event, "last_uid", last_uid);

	if (mailbox_transaction_commit(&trans) < 0) {
		errstr = t_strdup_printf("Transaction commit failed: %s",
					 mailbox_get_last_internal_error(box, &error));
		event_add_str(index_event, "error", errstr);
		const char *log_error = t_strdup_printf("%s (attempted to index %u messages%s)",
							errstr, counter, uids);
		if (error != MAIL_ERROR_NOTFOUND)
			e_error(index_event, "%s", log_error);
		else
			e_debug(index_event, "%s", log_error);
		ret = -1;
	} else {
		e_debug(index_event, "Indexed %u messages%s", counter, uids);
	}
	event_unref(&index_event);
	return ret;
}

static int
index_mailbox(struct master_connection *conn, struct mail_user *user,
	      const char *mailbox, unsigned int max_recent_msgs,
	      const char *what)
{
	struct mail_namespace *ns;
	struct mailbox *box;
	struct mailbox_status status;
	const char *path, *errstr;
	enum mail_error error;
	enum mailbox_sync_flags sync_flags = MAILBOX_SYNC_FLAG_FULL_READ;
	int ret;

	ns = mail_namespace_find(user->namespaces, mailbox);
	box = mailbox_alloc(ns->list, mailbox, 0);
	mailbox_set_reason(box, "indexing");
	ret = mailbox_get_path_to(box, MAILBOX_LIST_PATH_TYPE_INDEX, &path);
	if (ret < 0) {
		errstr = mailbox_get_last_internal_error(box, &error);
		if (error != MAIL_ERROR_NOTFOUND)
			i_error("Getting path to mailbox %s failed: %s",
				mailbox, errstr);
		mailbox_free(&box);
		return -1;
	}
	if (ret == 0) {
		i_info("Indexes disabled for mailbox %s, skipping", mailbox);
		mailbox_free(&box);
		return 0;
	}
	ret = 0;

	if (max_recent_msgs != 0) {
		/* index only if there aren't too many recent messages.
		   don't bother syncing the mailbox, that alone can take a
		   while with large maildirs. */
		if (mailbox_open(box) < 0) {
			errstr = mailbox_get_last_internal_error(box, &error);
			if (error != MAIL_ERROR_NOTFOUND)
				i_error("Opening mailbox %s failed: %s",
					mailbox, errstr);
			ret = -1;
		} else {
			mailbox_get_open_status(box, STATUS_RECENT, &status);
		}
		if (ret < 0 || status.recent > max_recent_msgs) {
			mailbox_free(&box);
			return ret;
		}
	}

	if (strchr(what, 'o') != NULL)
		sync_flags |= MAILBOX_SYNC_FLAG_OPTIMIZE;

	if (mailbox_sync(box, sync_flags) < 0) {
		errstr = mailbox_get_last_internal_error(box, &error);
		if (error != MAIL_ERROR_NOTFOUND) {
			i_error("Syncing mailbox %s failed: %s",
				mailbox, errstr);
		} else {
			e_debug(user->event, "Syncing mailbox %s failed: %s",
				mailbox, errstr);
		}
		ret = -1;
	} else if (strchr(what, 'i') != NULL) {
		if (index_mailbox_precache(conn, box) < 0)
			ret = -1;
	}
	mailbox_free(&box);
	return ret;
}

static int
master_connection_input_line(struct master_connection *conn, const char *line)
{
	const char *const *args = t_strsplit_tabescaped(line);
	struct mail_storage_service_input input;
	struct mail_storage_service_user *service_user;
	struct mail_user *user;
	const char *str, *error;
	unsigned int max_recent_msgs;
	int ret;

	/* <username> <mailbox> <session ID> <max_recent_msgs> [i][o] */
	if (str_array_length(args) != 5 ||
	    str_to_uint(args[3], &max_recent_msgs) < 0 || args[4][0] == '\0') {
		i_error("Invalid input from master: %s", line);
		return -1;
	}

	i_zero(&input);
	input.module = "mail";
	input.service = "indexer-worker";
	input.username = args[0];
	/* if session-id is given, use it as a prefix to a unique session ID.
	   we can't use the session-id directly or stats process will complain
	   about duplicates. (especially LMTP would use the same session-id for
	   multiple users' indexing at the same time.) */
	if (args[2][0] != '\0')
		input.session_id_prefix = args[2];

	if (mail_storage_service_lookup_next(conn->storage_service, &input,
					     &service_user, &user, &error) <= 0) {
		i_error("User %s lookup failed: %s", args[0], error);
		ret = -1;
	} else {
		indexer_worker_refresh_proctitle(user->username, args[1], 0, 0);
		ret = index_mailbox(conn, user, args[1],
				    max_recent_msgs, args[4]);
		/* refresh proctitle before a potentially long-running
		   user unref */
		indexer_worker_refresh_proctitle(user->username, "(deinit)", 0, 0);
		mail_user_deinit(&user);
		mail_storage_service_user_unref(&service_user);
		indexer_worker_refresh_proctitle(NULL, NULL, 0, 0);
	}

	str = ret < 0 ? "-1\n" : "100\n";
	return write_full(conn->fd, str, strlen(str));
}

static void master_connection_input(struct master_connection *conn)
{
	const char *line;
	int ret;

	if (i_stream_read(conn->input) < 0) {
		master_connection_destroy();
		return;
	}

	if (!conn->version_received) {
		if ((line = i_stream_next_line(conn->input)) == NULL)
			return;

		if (!version_string_verify(line, INDEXER_MASTER_NAME,
				INDEXER_PROTOCOL_MAJOR_VERSION)) {
			i_error("Indexer master not compatible with this master "
				"(mixed old and new binaries?)");
			master_connection_destroy();
			return;
		}
		conn->version_received = TRUE;
	}

	while ((line = i_stream_next_line(conn->input)) != NULL) {
		T_BEGIN {
			ret = master_connection_input_line(conn, line);
		} T_END;
		if (ret < 0) {
			master_connection_destroy();
			break;
		}
	}
}

struct master_connection *
master_connection_create(int fd, struct mail_storage_service_ctx *storage_service)
{
	struct master_connection *conn;
	const char *handshake;

	conn = i_new(struct master_connection, 1);
	conn->storage_service = storage_service;
	conn->fd = fd;
	conn->io = io_add(conn->fd, IO_READ, master_connection_input, conn);
	conn->input = i_stream_create_fd(conn->fd, SIZE_MAX);

	handshake = t_strdup_printf(INDEXER_WORKER_HANDSHAKE,
		master_service_get_process_limit(master_service));
	(void)write_full(conn->fd, handshake, strlen(handshake));
	return conn;
}

void master_connection_destroy(void)
{
	struct master_connection *conn = master_conn;

	master_conn = NULL;

	io_remove(&conn->io);
	i_stream_destroy(&conn->input);

	if (close(conn->fd) < 0)
		i_error("close(master conn) failed: %m");
	i_free(conn);

	master_service_client_connection_destroyed(master_service);
}

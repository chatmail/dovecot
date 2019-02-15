#ifndef IMAP_SETTINGS_H
#define IMAP_SETTINGS_H

#include "net.h"

struct mail_user_settings;

/* <settings checks> */
enum imap_client_workarounds {
	WORKAROUND_DELAY_NEWMAIL		= 0x01,
	WORKAROUND_TB_EXTRA_MAILBOX_SEP		= 0x08,
	WORKAROUND_TB_LSUB_FLAGS		= 0x10
};

enum imap_client_fetch_failure {
	IMAP_CLIENT_FETCH_FAILURE_DISCONNECT_IMMEDIATELY,
	IMAP_CLIENT_FETCH_FAILURE_DISCONNECT_AFTER,
	IMAP_CLIENT_FETCH_FAILURE_NO_AFTER,
};
/* </settings checks> */

struct imap_settings {
	bool verbose_proctitle;
	const char *rawlog_dir;

	/* imap: */
	uoff_t imap_max_line_length;
	unsigned int imap_idle_notify_interval;
	const char *imap_capability;
	const char *imap_client_workarounds;
	const char *imap_logout_format;
	const char *imap_id_send;
	const char *imap_id_log;
	const char *imap_fetch_failure;
	bool imap_metadata;
	bool imap_literal_minus;
	unsigned int imap_hibernate_timeout;

	/* imap urlauth: */
	const char *imap_urlauth_host;
	in_port_t imap_urlauth_port;

	enum imap_client_workarounds parsed_workarounds;
	enum imap_client_fetch_failure parsed_fetch_failure;
};

extern const struct setting_parser_info imap_setting_parser_info;

#endif

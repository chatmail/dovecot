/* Copyright (c) 2005-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "buffer.h"
#include "hostpid.h"
#include "settings-parser.h"
#include "service-settings.h"
#include "mail-storage-settings.h"
#include "smtp-submit-settings.h"
#include "imap-settings.h"

#include <stddef.h>
#include <unistd.h>

static bool imap_settings_verify(void *_set, pool_t pool,
				 const char **error_r);

/* <settings checks> */
static struct file_listener_settings imap_unix_listeners_array[] = {
	{ "login/imap", 0666, "", "" },
	{ "imap-master", 0600, "", "" }
};
static struct file_listener_settings *imap_unix_listeners[] = {
	&imap_unix_listeners_array[0],
	&imap_unix_listeners_array[1]
};
static buffer_t imap_unix_listeners_buf = {
	{ { imap_unix_listeners, sizeof(imap_unix_listeners) } }
};
/* </settings checks> */

struct service_settings imap_service_settings = {
	.name = "imap",
	.protocol = "imap",
	.type = "",
	.executable = "imap",
	.user = "",
	.group = "",
	.privileged_group = "",
	.extra_groups = "$default_internal_group",
	.chroot = "",

	.drop_priv_before_exec = FALSE,

	.process_min_avail = 0,
	.process_limit = 1024,
	.client_limit = 1,
	.service_count = 1,
	.idle_kill = 0,
	.vsz_limit = UOFF_T_MAX,

	.unix_listeners = { { &imap_unix_listeners_buf,
			      sizeof(imap_unix_listeners[0]) } },
	.fifo_listeners = ARRAY_INIT,
	.inet_listeners = ARRAY_INIT
};

#undef DEF
#undef DEFLIST
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type(#name, name, struct imap_settings)
#define DEFLIST(field, name, defines) \
	{ .type = SET_DEFLIST, .key = name, \
	  .offset = offsetof(struct imap_settings, field), \
	  .list_info = defines }

static const struct setting_define imap_setting_defines[] = {
	DEF(BOOL, verbose_proctitle),
	DEF(STR_VARS, rawlog_dir),

	DEF(SIZE, imap_max_line_length),
	DEF(TIME, imap_idle_notify_interval),
	DEF(STR, imap_capability),
	DEF(STR, imap_client_workarounds),
	DEF(STR, imap_logout_format),
	DEF(STR, imap_id_send),
	DEF(STR, imap_id_log),
	DEF(ENUM, imap_fetch_failure),
	DEF(BOOL, imap_metadata),
	DEF(BOOL, imap_literal_minus),
	DEF(TIME, imap_hibernate_timeout),

	DEF(STR, imap_urlauth_host),
	DEF(IN_PORT, imap_urlauth_port),

	SETTING_DEFINE_LIST_END
};

static const struct imap_settings imap_default_settings = {
	.verbose_proctitle = FALSE,
	.rawlog_dir = "",

	/* RFC-2683 recommends at least 8000 bytes. Some clients however don't
	   break large message sets to multiple commands, so we're pretty
	   liberal by default. */
	.imap_max_line_length = 64*1024,
	.imap_idle_notify_interval = 2*60,
	.imap_capability = "",
	.imap_client_workarounds = "",
	.imap_logout_format = "in=%i out=%o deleted=%{deleted} "
		"expunged=%{expunged} trashed=%{trashed} "
		"hdr_count=%{fetch_hdr_count} hdr_bytes=%{fetch_hdr_bytes} "
		"body_count=%{fetch_body_count} body_bytes=%{fetch_body_bytes}",
	.imap_id_send = "name *",
	.imap_id_log = "",
	.imap_fetch_failure = "disconnect-immediately:disconnect-after:no-after",
	.imap_metadata = FALSE,
	.imap_literal_minus = FALSE,
	.imap_hibernate_timeout = 0,

	.imap_urlauth_host = "",
	.imap_urlauth_port = 143
};

static const struct setting_parser_info *imap_setting_dependencies[] = {
	&mail_user_setting_parser_info,
	&smtp_submit_setting_parser_info,
	NULL
};

const struct setting_parser_info imap_setting_parser_info = {
	.module_name = "imap",
	.defines = imap_setting_defines,
	.defaults = &imap_default_settings,

	.type_offset = SIZE_MAX,
	.struct_size = sizeof(struct imap_settings),

	.parent_offset = SIZE_MAX,

	.check_func = imap_settings_verify,
	.dependencies = imap_setting_dependencies
};

/* <settings checks> */
struct imap_client_workaround_list {
	const char *name;
	enum imap_client_workarounds num;
};

static const struct imap_client_workaround_list imap_client_workaround_list[] = {
	{ "delay-newmail", WORKAROUND_DELAY_NEWMAIL },
	{ "tb-extra-mailbox-sep", WORKAROUND_TB_EXTRA_MAILBOX_SEP },
	{ "tb-lsub-flags", WORKAROUND_TB_LSUB_FLAGS },
	{ NULL, 0 }
};

static int
imap_settings_parse_workarounds(struct imap_settings *set,
				const char **error_r)
{
        enum imap_client_workarounds client_workarounds = 0;
        const struct imap_client_workaround_list *list;
	const char *const *str;

        str = t_strsplit_spaces(set->imap_client_workarounds, " ,");
	for (; *str != NULL; str++) {
		list = imap_client_workaround_list;
		for (; list->name != NULL; list++) {
			if (strcasecmp(*str, list->name) == 0) {
				client_workarounds |= list->num;
				break;
			}
		}
		if (list->name == NULL) {
			*error_r = t_strdup_printf("imap_client_workarounds: "
				"Unknown workaround: %s", *str);
			return -1;
		}
	}
	set->parsed_workarounds = client_workarounds;
	return 0;
}


static bool
imap_settings_verify(void *_set, pool_t pool ATTR_UNUSED, const char **error_r)
{
	struct imap_settings *set = _set;

	if (imap_settings_parse_workarounds(set, error_r) < 0)
		return FALSE;

	if (strcmp(set->imap_fetch_failure, "disconnect-immediately") == 0)
		set->parsed_fetch_failure = IMAP_CLIENT_FETCH_FAILURE_DISCONNECT_IMMEDIATELY;
	else if (strcmp(set->imap_fetch_failure, "disconnect-after") == 0)
		set->parsed_fetch_failure = IMAP_CLIENT_FETCH_FAILURE_DISCONNECT_AFTER;
	else if (strcmp(set->imap_fetch_failure, "no-after") == 0)
		set->parsed_fetch_failure = IMAP_CLIENT_FETCH_FAILURE_NO_AFTER;
	else {
		*error_r = t_strdup_printf("Unknown imap_fetch_failure: %s",
					   set->imap_fetch_failure);
		return FALSE;
	}
	return TRUE;
}
/* </settings checks> */

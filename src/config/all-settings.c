/* WARNING: THIS FILE IS GENERATED - DO NOT PATCH!
   It's not enough alone in any case, because the defaults may be
   coming from the individual *-settings.c in some situations. If you
   wish to modify defaults, change the other *-settings.c files and
   just delete this file. This file will be automatically regenerated
   by make. (This file is distributed in the tarball only because some
   systems might not have Perl installed.) */
#include "lib.h"
#include "array.h"
#include "str.h"
#include "ipwd.h"
#include "var-expand.h"
#include "file-lock.h"
#include "fsync-mode.h"
#include "hash-format.h"
#include "net.h"
#include "unichar.h"
#include "hash-method.h"
#include "settings-parser.h"
#include "message-header-parser.h"
#include "all-settings.h"
#include <stddef.h>
#include <unistd.h>
#define CONFIG_BINARY
extern buffer_t config_all_services_buf;/* ../../src/lib-storage/mail-storage-settings.h */
extern const struct setting_parser_info mail_user_setting_parser_info;
extern const struct setting_parser_info mail_namespace_setting_parser_info;
extern const struct setting_parser_info mail_storage_setting_parser_info;
/* <settings checks> */
#define MAILBOX_SET_AUTO_NO "no"
#define MAILBOX_SET_AUTO_CREATE "create"
#define MAILBOX_SET_AUTO_SUBSCRIBE "subscribe"
/* </settings checks> */
struct mail_storage_settings {
	const char *mail_location;
	const char *mail_attachment_fs;
	const char *mail_attachment_dir;
	const char *mail_attachment_hash;
	uoff_t mail_attachment_min_size;
	const char *mail_attribute_dict;
	unsigned int mail_prefetch_count;
	const char *mail_cache_fields;
	const char *mail_always_cache_fields;
	const char *mail_never_cache_fields;
	const char *mail_server_comment;
	const char *mail_server_admin;
	unsigned int mail_cache_min_mail_count;
	unsigned int mail_cache_unaccessed_field_drop;
	uoff_t mail_cache_record_max_size;
	uoff_t mail_cache_max_size;
	uoff_t mail_cache_purge_min_size;
	unsigned int mail_cache_purge_delete_percentage;
	unsigned int mail_cache_purge_continued_percentage;
	unsigned int mail_cache_purge_header_continue_count;
	uoff_t mail_index_rewrite_min_log_bytes;
	uoff_t mail_index_rewrite_max_log_bytes;
	uoff_t mail_index_log_rotate_min_size;
	uoff_t mail_index_log_rotate_max_size;
	unsigned int mail_index_log_rotate_min_age;
	unsigned int mail_index_log2_max_age;
	unsigned int mailbox_idle_check_interval;
	unsigned int mail_max_keyword_length;
	unsigned int mail_max_lock_timeout;
	unsigned int mail_temp_scan_interval;
	unsigned int mail_vsize_bg_after_count;
	unsigned int mail_sort_max_read_count;
	bool mail_save_crlf;
	const char *mail_fsync;
	bool mmap_disable;
	bool dotlock_use_excl;
	bool mail_nfs_storage;
	bool mail_nfs_index;
	bool mailbox_list_index;
	bool mailbox_list_index_very_dirty_syncs;
	bool mailbox_list_index_include_inbox;
	bool mail_debug;
	bool mail_full_filesystem_access;
	bool maildir_stat_dirs;
	bool mail_shared_explicit_inbox;
	const char *lock_method;
	const char *pop3_uidl_format;

	const char *hostname;
	const char *recipient_delimiter;

	const char *mail_attachment_detection_options;

	enum file_lock_method parsed_lock_method;
	enum fsync_mode parsed_fsync_mode;

	const char *const *parsed_mail_attachment_content_type_filter;
	bool parsed_mail_attachment_exclude_inlined;
	bool parsed_mail_attachment_detection_add_flags;
	bool parsed_mail_attachment_detection_no_flags_on_fetch;
};
struct mail_namespace_settings {
	const char *name;
	const char *type;
	const char *separator;
	const char *prefix;
	const char *location;
	const char *alias_for;

	bool inbox;
	bool hidden;
	const char *list;
	bool subscriptions;
	bool ignore_on_failure;
	bool disabled;
	unsigned int order;

	ARRAY(struct mailbox_settings *) mailboxes;
	struct mail_user_settings *user_set;
};
struct mailbox_settings {
	const char *name;
	const char *autocreate;
	const char *special_use;
	const char *driver;
	const char *comment;
	unsigned int autoexpunge;
	unsigned int autoexpunge_max_mails;
};
struct mail_user_settings {
	const char *base_dir;
	const char *auth_socket_path;
	const char *mail_temp_dir;

	const char *mail_uid;
	const char *mail_gid;
	const char *mail_home;
	const char *mail_chroot;
	const char *mail_access_groups;
	const char *mail_privileged_group;
	const char *valid_chroot_dirs;

	unsigned int first_valid_uid, last_valid_uid;
	unsigned int first_valid_gid, last_valid_gid;

	const char *mail_plugins;
	const char *mail_plugin_dir;

	const char *mail_log_prefix;

	const char *hostname;
	const char *postmaster_address;

	ARRAY(struct mail_namespace_settings *) namespaces;
	ARRAY(const char *) plugin_envs;

	/* May be NULL - use mail_storage_get_postmaster_address() instead of
	   directly accessing this. */
	const struct message_address *_parsed_postmaster_address;
	const struct smtp_address *_parsed_postmaster_address_smtp;
};
/* ../../src/lib-storage/index/pop3c/pop3c-settings.h */
/* <settings checks> */
enum pop3c_features {
        POP3C_FEATURE_NO_PIPELINING = 0x1,
};
/* </settings checks> */
struct pop3c_settings {
	const char *pop3c_host;
	in_port_t pop3c_port;

	const char *pop3c_user;
	const char *pop3c_master_user;
	const char *pop3c_password;

	const char *pop3c_ssl;
	bool pop3c_ssl_verify;

	const char *pop3c_rawlog_dir;
	bool pop3c_quick_received_date;

	const char *pop3c_features;
	enum pop3c_features parsed_features;
};
/* ../../src/lib-storage/index/mbox/mbox-settings.h */
struct mbox_settings {
	const char *mbox_read_locks;
	const char *mbox_write_locks;
	unsigned int mbox_lock_timeout;
	unsigned int mbox_dotlock_change_timeout;
	uoff_t mbox_min_index_size;
	bool mbox_dirty_syncs;
	bool mbox_very_dirty_syncs;
	bool mbox_lazy_writes;
	const char *mbox_md5;
};
/* ../../src/lib-storage/index/maildir/maildir-settings.h */
struct maildir_settings {
	bool maildir_copy_with_hardlinks;
	bool maildir_very_dirty_syncs;
	bool maildir_broken_filename_sizes;
	bool maildir_empty_new;
};
/* ../../src/lib-storage/index/imapc/imapc-settings.h */
/* <settings checks> */
enum imapc_features {
	IMAPC_FEATURE_RFC822_SIZE		= 0x01,
	IMAPC_FEATURE_GUID_FORCED		= 0x02,
	IMAPC_FEATURE_FETCH_HEADERS		= 0x04,
	IMAPC_FEATURE_GMAIL_MIGRATION		= 0x08,
	IMAPC_FEATURE_SEARCH			= 0x10,
	IMAPC_FEATURE_ZIMBRA_WORKAROUNDS	= 0x20,
	IMAPC_FEATURE_NO_EXAMINE		= 0x40,
	IMAPC_FEATURE_PROXYAUTH			= 0x80,
	IMAPC_FEATURE_FETCH_MSN_WORKAROUNDS	= 0x100,
	IMAPC_FEATURE_FETCH_FIX_BROKEN_MAILS	= 0x200,
	IMAPC_FEATURE_MODSEQ			= 0x400,
	IMAPC_FEATURE_DELAY_LOGIN		= 0x800,
	IMAPC_FEATURE_FETCH_BODYSTRUCTURE	= 0x1000,
	IMAPC_FEATURE_SEND_ID			= 0x2000,
	IMAPC_FEATURE_FETCH_EMPTY_IS_EXPUNGED	= 0x4000,
	IMAPC_FEATURE_NO_MSN_UPDATES		= 0x8000,
	IMAPC_FEATURE_ACL 			= 0x10000,
};
/* </settings checks> */
struct imapc_settings {
	const char *imapc_host;
	in_port_t imapc_port;

	const char *imapc_user;
	const char *imapc_master_user;
	const char *imapc_password;
	const char *imapc_sasl_mechanisms;

	const char *imapc_ssl;
	bool imapc_ssl_verify;

	const char *imapc_features;
	const char *imapc_rawlog_dir;
	const char *imapc_list_prefix;
	unsigned int imapc_cmd_timeout;
	unsigned int imapc_max_idle_time;
	unsigned int imapc_connection_retry_count;
	unsigned int imapc_connection_retry_interval;
	uoff_t imapc_max_line_length;

	const char *pop3_deleted_flag;

	enum imapc_features parsed_features;
	unsigned int throttle_init_msecs;
	unsigned int throttle_max_msecs;
	unsigned int throttle_shrink_min_msecs;
};
/* ../../src/lib-storage/index/dbox-multi/mdbox-settings.h */
struct mdbox_settings {
	bool mdbox_preallocate_space;
	uoff_t mdbox_rotate_size;
	unsigned int mdbox_rotate_interval;
};
/* ../../src/lib-smtp/smtp-submit-settings.h */
extern const struct setting_parser_info smtp_submit_setting_parser_info;
struct smtp_submit_settings {
	const char *hostname;
	bool mail_debug;

	const char *submission_host;
	const char *sendmail_path;
	unsigned int submission_timeout;

	const char *submission_ssl;
};
/* ../../src/lib-settings/settings.h */
#define DEF_STRUCT_STR(name, struct_name) \
	{ SET_STR + COMPILE_ERROR_IF_TYPES_NOT_COMPATIBLE( \
		((struct struct_name *)0)->name, const char *), \
	  #name, offsetof(struct struct_name, name) }
#define DEF_STRUCT_INT(name, struct_name) \
	{ SET_INT + COMPILE_ERROR_IF_TYPES_NOT_COMPATIBLE( \
		((struct struct_name *)0)->name, unsigned int), \
	  #name, offsetof(struct struct_name, name) }
#define DEF_STRUCT_BOOL(name, struct_name) \
	{ SET_BOOL + COMPILE_ERROR_IF_TYPES_NOT_COMPATIBLE( \
		((struct struct_name *)0)->name, bool), \
	  #name, offsetof(struct struct_name, name) }
/* ../../src/lib-master/service-settings.h */
/* <settings checks> */
enum service_user_default {
	SERVICE_USER_DEFAULT_NONE = 0,
	SERVICE_USER_DEFAULT_INTERNAL,
	SERVICE_USER_DEFAULT_LOGIN
};

enum service_type {
	SERVICE_TYPE_UNKNOWN,
	SERVICE_TYPE_LOG,
	SERVICE_TYPE_ANVIL,
	SERVICE_TYPE_CONFIG,
	SERVICE_TYPE_LOGIN,
	SERVICE_TYPE_STARTUP,
	/* Worker processes are intentionally limited to their process_limit,
	   and they can regularly reach it. There shouldn't be unnecessary
	   warnings about temporarily reaching the limit. */
	SERVICE_TYPE_WORKER,
};
/* </settings checks> */
struct file_listener_settings {
	const char *path;
	unsigned int mode;
	const char *user;
	const char *group;
};
ARRAY_DEFINE_TYPE(file_listener_settings, struct file_listener_settings *);
struct inet_listener_settings {
	const char *name;
	const char *address;
	in_port_t port;
	bool ssl;
	bool reuse_port;
	bool haproxy;
};
ARRAY_DEFINE_TYPE(inet_listener_settings, struct inet_listener_settings *);
struct service_settings {
	const char *name;
	const char *protocol;
	const char *type;
	const char *executable;
	const char *user;
	const char *group;
	const char *privileged_group;
	const char *extra_groups;
	const char *chroot;

	bool drop_priv_before_exec;

	unsigned int process_min_avail;
	unsigned int process_limit;
	unsigned int client_limit;
	unsigned int service_count;
	unsigned int idle_kill;
	uoff_t vsz_limit;

	ARRAY_TYPE(file_listener_settings) unix_listeners;
	ARRAY_TYPE(file_listener_settings) fifo_listeners;
	ARRAY_TYPE(inet_listener_settings) inet_listeners;

	/* internal to master: */
	struct master_settings *master_set;
	enum service_type parsed_type;
	enum service_user_default user_default;
	bool login_dump_core:1;

	/* -- flags that can be set internally -- */

	/* process_limit must not be higher than 1 */
	bool process_limit_1:1;
};
ARRAY_DEFINE_TYPE(service_settings, struct service_settings *);
/* ../../src/lib-master/master-service-ssl-settings.h */
extern const struct setting_parser_info master_service_ssl_setting_parser_info;
extern const struct setting_parser_info master_service_ssl_server_setting_parser_info;
struct master_service_ssl_settings {
	const char *ssl;
	const char *ssl_ca;
	const char *ssl_client_ca_file;
	const char *ssl_client_ca_dir;
	const char *ssl_client_cert;
	const char *ssl_client_key;
	const char *ssl_cipher_list;
	const char *ssl_cipher_suites;
	const char *ssl_curve_list;
	const char *ssl_min_protocol;
	const char *ssl_cert_username_field;
	const char *ssl_crypto_device;
	const char *ssl_options;

	bool ssl_verify_client_cert;
	bool ssl_client_require_valid_cert;
	bool ssl_require_crl;
	bool verbose_ssl;
	bool ssl_prefer_server_ciphers;

	/* These are derived from ssl_options, not set directly */
	struct {
		bool compression;
		bool tickets;
	} parsed_opts;
};
struct master_service_ssl_server_settings {
	const char *ssl_cert;
	const char *ssl_alt_cert;
	const char *ssl_key;
	const char *ssl_alt_key;
	const char *ssl_key_password;
	const char *ssl_dh;
};
/* ../../src/lib-master/master-service-settings.h */
extern const struct setting_parser_info master_service_setting_parser_info;
struct master_service_settings {
	/* NOTE: log process won't see any new settings unless they're
	   explicitly sent via environment variables by master process. */
	const char *base_dir;
	const char *state_dir;
	const char *instance_name;
	const char *log_path;
	const char *info_log_path;
	const char *debug_log_path;
	const char *log_timestamp;
	const char *log_debug;
	const char *log_core_filter;
	const char *process_shutdown_filter;
	const char *syslog_facility;
	const char *import_environment;
	const char *stats_writer_socket_path;
	uoff_t config_cache_size;
	bool version_ignore;
	bool shutdown_clients;
	bool verbose_proctitle;

	const char *haproxy_trusted_networks;
	unsigned int haproxy_timeout;
};
/* ../../src/lib-lda/lda-settings.h */
extern const struct setting_parser_info lda_setting_parser_info;
struct lda_settings {
	const char *hostname;
	const char *rejection_subject;
	const char *rejection_reason;
	const char *deliver_log_format;
	const char *recipient_delimiter;
	const char *lda_original_recipient_header;

	bool quota_full_tempfail;
	bool lda_mailbox_autocreate;
	bool lda_mailbox_autosubscribe;
};
/* ../../src/lib-dict-backend/dict-sql-settings.h */
struct dict_sql_settings {
	const char *connect;

	unsigned int max_pattern_fields_count;
	ARRAY(struct dict_sql_map) maps;
};
/* ../../src/lib-dict-backend/dict-ldap-settings.h */
struct dict_ldap_settings {
	const char *uri;
	const char *bind_dn;
	const char *password;
	unsigned int timeout;
	unsigned int max_idle_time;
	unsigned int debug;
	unsigned int max_attribute_count;
	bool require_ssl;
	bool start_tls;
	ARRAY(struct dict_ldap_map) maps;
};
/* ../../src/lib-storage/mail-storage-settings.c */
extern const struct setting_parser_info mailbox_setting_parser_info;
extern const struct setting_parser_info mail_namespace_setting_parser_info;
/* <settings checks> */
static bool mail_cache_fields_parse(const char *key, const char *value,
				    const char **error_r)
{
	const char *const *arr;

	for (arr = t_strsplit_spaces(value, " ,"); *arr != NULL; arr++) {
		const char *name = *arr;

		if (strncasecmp(name, "hdr.", 4) == 0 &&
		    !message_header_name_is_valid(name+4)) {
			*error_r = t_strdup_printf(
				"Invalid %s: %s is not a valid header name",
				key, name);
			return FALSE;
		}
	}
	return TRUE;
}

static bool mail_storage_settings_check(void *_set, pool_t pool,
					const char **error_r)
{
	struct mail_storage_settings *set = _set;
	struct hash_format *format;
	const char *p, *error;
	bool uidl_format_ok;
	char c;

	if (set->mailbox_idle_check_interval == 0) {
		*error_r = "mailbox_idle_check_interval must not be 0";
		return FALSE;
	}

	if (strcmp(set->mail_fsync, "optimized") == 0)
		set->parsed_fsync_mode = FSYNC_MODE_OPTIMIZED;
	else if (strcmp(set->mail_fsync, "never") == 0)
		set->parsed_fsync_mode = FSYNC_MODE_NEVER;
	else if (strcmp(set->mail_fsync, "always") == 0)
		set->parsed_fsync_mode = FSYNC_MODE_ALWAYS;
	else {
		*error_r = t_strdup_printf("Unknown mail_fsync: %s",
					   set->mail_fsync);
		return FALSE;
	}

	if (set->mail_nfs_index && !set->mmap_disable) {
		*error_r = "mail_nfs_index=yes requires mmap_disable=yes";
		return FALSE;
	}
	if (set->mail_nfs_index &&
	    set->parsed_fsync_mode != FSYNC_MODE_ALWAYS) {
		*error_r = "mail_nfs_index=yes requires mail_fsync=always";
		return FALSE;
	}

	if (!file_lock_method_parse(set->lock_method,
				    &set->parsed_lock_method)) {
		*error_r = t_strdup_printf("Unknown lock_method: %s",
					   set->lock_method);
		return FALSE;
	}

	if (set->mail_cache_max_size > 1024 * 1024 * 1024) {
		*error_r = "mail_cache_max_size can't be over 1 GB";
		return FALSE;
	}
	if (set->mail_cache_purge_delete_percentage > 100) {
		*error_r = "mail_cache_purge_delete_percentage can't be over 100";
		return FALSE;
	}

	uidl_format_ok = FALSE;
	for (p = set->pop3_uidl_format; *p != '\0'; p++) {
		if (p[0] != '%' || p[1] == '\0')
			continue;

		c = var_get_key(++p);
		switch (c) {
		case 'v':
		case 'u':
		case 'm':
		case 'f':
		case 'g':
			uidl_format_ok = TRUE;
			break;
		case '%':
			break;
		default:
			*error_r = t_strdup_printf(
				"Unknown pop3_uidl_format variable: %%%c", c);
			return FALSE;
		}
	}
	if (!uidl_format_ok) {
		*error_r = "pop3_uidl_format setting doesn't contain any "
			"%% variables.";
		return FALSE;
	}

	if (strchr(set->mail_attachment_hash, '/') != NULL) {
		*error_r = "mail_attachment_hash setting "
			"must not contain '/' characters";
		return FALSE;
	}
	if (hash_format_init(set->mail_attachment_hash, &format, &error) < 0) {
		*error_r = t_strconcat("Invalid mail_attachment_hash setting: ",
				       error, NULL);
		return FALSE;
	}
	if (strchr(set->mail_attachment_hash, '-') != NULL) {
		*error_r = "mail_attachment_hash setting "
			"must not contain '-' characters";
		return FALSE;
	}
	hash_format_deinit_free(&format);

	// FIXME: check set->mail_server_admin syntax (RFC 5464, Section 6.2.2)

#ifndef CONFIG_BINARY
	if (*set->hostname == '\0')
		set->hostname = p_strdup(pool, my_hostdomain());
#endif

	/* parse mail_attachment_indicator_options */
	if (*set->mail_attachment_detection_options != '\0') {
		ARRAY_TYPE(const_string) content_types;
		p_array_init(&content_types, pool, 2);

		const char *const *options =
			t_strsplit_spaces(set->mail_attachment_detection_options, " ");

		while(*options != NULL) {
			const char *opt = *options;

			if (strcmp(opt, "add-flags") == 0 ||
			    strcmp(opt, "add-flags-on-save") == 0) {
				set->parsed_mail_attachment_detection_add_flags = TRUE;
			} else if (strcmp(opt, "no-flags-on-fetch") == 0) {
				set->parsed_mail_attachment_detection_no_flags_on_fetch = TRUE;
			} else if (strcmp(opt, "exclude-inlined") == 0) {
				set->parsed_mail_attachment_exclude_inlined = TRUE;
			} else if (str_begins(opt, "content-type=")) {
				const char *value = p_strdup(pool, opt+13);
				array_push_back(&content_types, &value);
			} else {
				*error_r = t_strdup_printf("mail_attachment_detection_options: "
					"Unknown option: %s", opt);
				return FALSE;
			}
			options++;
		}

		array_append_zero(&content_types);
		set->parsed_mail_attachment_content_type_filter = array_front(&content_types);
	}

	if (!mail_cache_fields_parse("mail_cache_fields",
				     set->mail_cache_fields, error_r))
		return FALSE;
	if (!mail_cache_fields_parse("mail_always_cache_fields",
				     set->mail_always_cache_fields, error_r))
		return FALSE;
	if (!mail_cache_fields_parse("mail_never_cache_fields",
				     set->mail_never_cache_fields, error_r))
		return FALSE;
	return TRUE;
}

static bool namespace_settings_check(void *_set, pool_t pool ATTR_UNUSED,
				     const char **error_r)
{
	struct mail_namespace_settings *ns = _set;
	struct mail_namespace_settings *const *namespaces;
	const char *name;
	unsigned int i, count;

	name = ns->prefix != NULL ? ns->prefix : "";

	if (ns->separator[0] != '\0' && ns->separator[1] != '\0') {
		*error_r = t_strdup_printf("Namespace '%s': "
			"Hierarchy separator must be only one character long",
			name);
		return FALSE;
	}
	if (!uni_utf8_str_is_valid(name)) {
		*error_r = t_strdup_printf("Namespace prefix not valid UTF8: %s",
					   name);
		return FALSE;
	}

	if (ns->alias_for != NULL && !ns->disabled) {
		if (array_is_created(&ns->user_set->namespaces)) {
			namespaces = array_get(&ns->user_set->namespaces,
					       &count);
		} else {
			namespaces = NULL;
			count = 0;
		}
		for (i = 0; i < count; i++) {
			if (strcmp(namespaces[i]->prefix, ns->alias_for) == 0)
				break;
		}
		if (i == count) {
			*error_r = t_strdup_printf(
				"Namespace '%s': alias_for points to "
				"unknown namespace: %s", name, ns->alias_for);
			return FALSE;
		}
		if (namespaces[i]->alias_for != NULL) {
			*error_r = t_strdup_printf(
				"Namespace '%s': alias_for chaining isn't "
				"allowed: %s -> %s", name, ns->alias_for,
				namespaces[i]->alias_for);
			return FALSE;
		}
	}
	return TRUE;
}

static bool mailbox_special_use_exists(const char *name)
{
	if (name[0] != '\\')
		return FALSE;
	name++;

	if (strcasecmp(name, "All") == 0)
		return TRUE;
	if (strcasecmp(name, "Archive") == 0)
		return TRUE;
	if (strcasecmp(name, "Drafts") == 0)
		return TRUE;
	if (strcasecmp(name, "Flagged") == 0)
		return TRUE;
	if (strcasecmp(name, "Important") == 0)
		return TRUE;
	if (strcasecmp(name, "Junk") == 0)
		return TRUE;
	if (strcasecmp(name, "Sent") == 0)
		return TRUE;
	if (strcasecmp(name, "Trash") == 0)
		return TRUE;
	return FALSE;
}

static bool
mailbox_special_use_check(struct mailbox_settings *set, pool_t pool,
			  const char **error_r)
{
	const char *const *uses, *str;
	unsigned int i;

	uses = t_strsplit_spaces(set->special_use, " ");
	for (i = 0; uses[i] != NULL; i++) {
		if (!mailbox_special_use_exists(uses[i])) {
			*error_r = t_strdup_printf(
				"mailbox %s: unknown special_use: %s",
				set->name, uses[i]);
			return FALSE;
		}
	}
	/* make sure there are no extra spaces */
	str = t_strarray_join(uses, " ");
	if (strcmp(str, set->special_use) != 0)
		set->special_use = p_strdup(pool, str);
	return TRUE;
}

static bool mailbox_settings_check(void *_set, pool_t pool,
				   const char **error_r)
{
	struct mailbox_settings *set = _set;

	if (!uni_utf8_str_is_valid(set->name)) {
		*error_r = t_strdup_printf("mailbox %s: name isn't valid UTF-8",
					   set->name);
		return FALSE;
	}
	if (*set->special_use != '\0') {
		if (!mailbox_special_use_check(set, pool, error_r))
			return FALSE;
	}
	return TRUE;
}

static bool mail_user_settings_check(void *_set, pool_t pool ATTR_UNUSED,
				     const char **error_r ATTR_UNUSED)
{
	struct mail_user_settings *set = _set;

#ifndef CONFIG_BINARY
	fix_base_path(set, pool, &set->auth_socket_path);

	if (*set->hostname == '\0')
		set->hostname = p_strdup(pool, my_hostdomain());
	if (set->postmaster_address[0] == SETTING_STRVAR_UNEXPANDED[0] &&
	    set->postmaster_address[1] == '\0') {
		/* check for valid looking fqdn in hostname */
		if (strchr(set->hostname, '.') == NULL) {
			*error_r = "postmaster_address setting not given";
			return FALSE;
		}
		set->postmaster_address =
			p_strconcat(pool, SETTING_STRVAR_UNEXPANDED,
				    "postmaster@", set->hostname, NULL);
	}
#else
	if (*set->mail_plugins != '\0' &&
	    access(set->mail_plugin_dir, R_OK | X_OK) < 0) {
		*error_r = t_strdup_printf(
			"mail_plugin_dir: access(%s) failed: %m",
			set->mail_plugin_dir);
		return FALSE;
	}
#endif
	return TRUE;
}

#ifndef CONFIG_BINARY
static bool parse_postmaster_address(const char *address, pool_t pool,
				     struct mail_user_settings *set,
				     const char **error_r) ATTR_NULL(3)
{
	struct message_address *addr;
	struct smtp_address *smtp_addr;

	addr = message_address_parse(pool,
		(const unsigned char *)address,
		strlen(address), 2, 0);
	if (addr == NULL || addr->domain == NULL || addr->invalid_syntax ||
	    smtp_address_create_from_msg(pool, addr, &smtp_addr) < 0) {
		*error_r = t_strdup_printf(
			"invalid address `%s' specified for the "
			"postmaster_address setting", address);
		return FALSE;
	}
	if (addr->next != NULL) {
		*error_r = "more than one address specified for the "
			"postmaster_address setting";
		return FALSE;
	}
	if (addr->name == NULL || *addr->name == '\0')
		addr->name = "Postmaster";
	if (set != NULL) {
		set->_parsed_postmaster_address = addr;
		set->_parsed_postmaster_address_smtp = smtp_addr;
	}
	return TRUE;
}

static bool
mail_user_settings_expand_check(void *_set, pool_t pool,
				const char **error_r ATTR_UNUSED)
{
	struct mail_user_settings *set = _set;
	const char *error;

	/* Parse if possible. Perform error handling later. */
	(void)parse_postmaster_address(set->postmaster_address, pool,
				       set, &error);
	return TRUE;
}
#endif

/* </settings checks> */
#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type(#name, name, struct mail_storage_settings)
static const struct setting_define mail_storage_setting_defines[] = {
	DEF(STR_VARS, mail_location),
	{ .type = SET_ALIAS, .key = "mail" },
	DEF(STR_VARS, mail_attachment_fs),
	DEF(STR_VARS, mail_attachment_dir),
	DEF(STR, mail_attachment_hash),
	DEF(SIZE, mail_attachment_min_size),
	DEF(STR, mail_attachment_detection_options),
	DEF(STR_VARS, mail_attribute_dict),
	DEF(UINT, mail_prefetch_count),
	DEF(STR, mail_cache_fields),
	DEF(STR, mail_always_cache_fields),
	DEF(STR, mail_never_cache_fields),
	DEF(STR, mail_server_comment),
	DEF(STR, mail_server_admin),
	DEF(TIME_HIDDEN, mail_cache_unaccessed_field_drop),
	DEF(SIZE_HIDDEN, mail_cache_record_max_size),
	DEF(SIZE_HIDDEN, mail_cache_max_size),
	DEF(UINT_HIDDEN, mail_cache_min_mail_count),
	DEF(SIZE_HIDDEN, mail_cache_purge_min_size),
	DEF(UINT_HIDDEN, mail_cache_purge_delete_percentage),
	DEF(UINT_HIDDEN, mail_cache_purge_continued_percentage),
	DEF(UINT_HIDDEN, mail_cache_purge_header_continue_count),
	DEF(SIZE_HIDDEN, mail_index_rewrite_min_log_bytes),
	DEF(SIZE_HIDDEN, mail_index_rewrite_max_log_bytes),
	DEF(SIZE_HIDDEN, mail_index_log_rotate_min_size),
	DEF(SIZE_HIDDEN, mail_index_log_rotate_max_size),
	DEF(TIME_HIDDEN, mail_index_log_rotate_min_age),
	DEF(TIME_HIDDEN, mail_index_log2_max_age),
	DEF(TIME, mailbox_idle_check_interval),
	DEF(UINT, mail_max_keyword_length),
	DEF(TIME, mail_max_lock_timeout),
	DEF(TIME, mail_temp_scan_interval),
	DEF(UINT, mail_vsize_bg_after_count),
	DEF(UINT, mail_sort_max_read_count),
	DEF(BOOL, mail_save_crlf),
	DEF(ENUM, mail_fsync),
	DEF(BOOL, mmap_disable),
	DEF(BOOL, dotlock_use_excl),
	DEF(BOOL, mail_nfs_storage),
	DEF(BOOL, mail_nfs_index),
	DEF(BOOL, mailbox_list_index),
	DEF(BOOL, mailbox_list_index_very_dirty_syncs),
	DEF(BOOL, mailbox_list_index_include_inbox),
	DEF(BOOL, mail_debug),
	DEF(BOOL, mail_full_filesystem_access),
	DEF(BOOL, maildir_stat_dirs),
	DEF(BOOL, mail_shared_explicit_inbox),
	DEF(ENUM, lock_method),
	DEF(STR, pop3_uidl_format),

	DEF(STR, hostname),
	DEF(STR, recipient_delimiter),

	SETTING_DEFINE_LIST_END
};
const struct mail_storage_settings mail_storage_default_settings = {
	.mail_location = "",
	.mail_attachment_fs = "sis posix",
	.mail_attachment_dir = "",
	.mail_attachment_hash = "%{sha1}",
	.mail_attachment_min_size = 1024*128,
	.mail_attachment_detection_options = "",
	.mail_attribute_dict = "",
	.mail_prefetch_count = 0,
	.mail_cache_fields = "flags",
	.mail_always_cache_fields = "",
	.mail_never_cache_fields = "imap.envelope",
	.mail_server_comment = "",
	.mail_server_admin = "",
	.mail_cache_min_mail_count = 0,
	.mail_cache_unaccessed_field_drop = 60*60*24*30,
	.mail_cache_record_max_size = 64 * 1024,
	.mail_cache_max_size = 1024 * 1024 * 1024,
	.mail_cache_purge_min_size = 32 * 1024,
	.mail_cache_purge_delete_percentage = 20,
	.mail_cache_purge_continued_percentage = 200,
	.mail_cache_purge_header_continue_count = 4,
	.mail_index_rewrite_min_log_bytes = 8 * 1024,
	.mail_index_rewrite_max_log_bytes = 128 * 1024,
	.mail_index_log_rotate_min_size = 32 * 1024,
	.mail_index_log_rotate_max_size = 1024 * 1024,
	.mail_index_log_rotate_min_age = 5 * 60,
	.mail_index_log2_max_age = 3600 * 24 * 2,
	.mailbox_idle_check_interval = 30,
	.mail_max_keyword_length = 50,
	.mail_max_lock_timeout = 0,
	.mail_temp_scan_interval = 7*24*60*60,
	.mail_vsize_bg_after_count = 0,
	.mail_sort_max_read_count = 0,
	.mail_save_crlf = FALSE,
	.mail_fsync = "optimized:never:always",
	.mmap_disable = FALSE,
	.dotlock_use_excl = TRUE,
	.mail_nfs_storage = FALSE,
	.mail_nfs_index = FALSE,
	.mailbox_list_index = TRUE,
	.mailbox_list_index_very_dirty_syncs = FALSE,
	.mailbox_list_index_include_inbox = FALSE,
	.mail_debug = FALSE,
	.mail_full_filesystem_access = FALSE,
	.maildir_stat_dirs = FALSE,
	.mail_shared_explicit_inbox = FALSE,
	.lock_method = "fcntl:flock:dotlock",
	.pop3_uidl_format = "%08Xu%08Xv",

	.hostname = "",
	.recipient_delimiter = "+",
};
const struct setting_parser_info mail_storage_setting_parser_info = {
	.module_name = "mail",
	.defines = mail_storage_setting_defines,
	.defaults = &mail_storage_default_settings,

	.type_offset = SIZE_MAX,
	.struct_size = sizeof(struct mail_storage_settings),

	.parent_offset = SIZE_MAX,
	.parent = &mail_user_setting_parser_info,

	.check_func = mail_storage_settings_check,
};
#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type(#name, name, struct mailbox_settings)
static const struct setting_define mailbox_setting_defines[] = {
	DEF(STR, name),
	{ .type = SET_ENUM, .key = "auto",
	  .offset = offsetof(struct mailbox_settings, autocreate) } ,
	DEF(STR, special_use),
	DEF(STR, driver),
	DEF(STR, comment),
	DEF(TIME, autoexpunge),
	DEF(UINT, autoexpunge_max_mails),

	SETTING_DEFINE_LIST_END
};
const struct mailbox_settings mailbox_default_settings = {
	.name = "",
	.autocreate = MAILBOX_SET_AUTO_NO":"
		MAILBOX_SET_AUTO_CREATE":"
		MAILBOX_SET_AUTO_SUBSCRIBE,
	.special_use = "",
	.driver = "",
	.comment = "",
	.autoexpunge = 0,
	.autoexpunge_max_mails = 0
};
const struct setting_parser_info mailbox_setting_parser_info = {
	.defines = mailbox_setting_defines,
	.defaults = &mailbox_default_settings,

	.type_offset = offsetof(struct mailbox_settings, name),
	.struct_size = sizeof(struct mailbox_settings),

	.parent_offset = SIZE_MAX,
	.parent = &mail_user_setting_parser_info,

	.check_func = mailbox_settings_check
};
#undef DEF
#undef DEFLIST_UNIQUE
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type(#name, name, struct mail_namespace_settings)
#define DEFLIST_UNIQUE(field, name, defines) \
	{ .type = SET_DEFLIST_UNIQUE, .key = name, \
	  .offset = offsetof(struct mail_namespace_settings, field), \
	  .list_info = defines }
static const struct setting_define mail_namespace_setting_defines[] = {
	DEF(STR, name),
	DEF(ENUM, type),
	DEF(STR, separator),
	DEF(STR_VARS, prefix),
	DEF(STR_VARS, location),
	{ .type = SET_ALIAS, .key = "mail" },
	{ .type = SET_ALIAS, .key = "mail_location" },
	DEF(STR_VARS, alias_for),

	DEF(BOOL, inbox),
	DEF(BOOL, hidden),
	DEF(ENUM, list),
	DEF(BOOL, subscriptions),
	DEF(BOOL, ignore_on_failure),
	DEF(BOOL, disabled),
	DEF(UINT, order),

	DEFLIST_UNIQUE(mailboxes, "mailbox", &mailbox_setting_parser_info),

	SETTING_DEFINE_LIST_END
};
const struct mail_namespace_settings mail_namespace_default_settings = {
	.name = "",
	.type = "private:shared:public",
	.separator = "",
	.prefix = "",
	.location = "",
	.alias_for = NULL,

	.inbox = FALSE,
	.hidden = FALSE,
	.list = "yes:no:children",
	.subscriptions = TRUE,
	.ignore_on_failure = FALSE,
	.disabled = FALSE,
	.order = 0,

	.mailboxes = ARRAY_INIT
};
const struct setting_parser_info mail_namespace_setting_parser_info = {
	.defines = mail_namespace_setting_defines,
	.defaults = &mail_namespace_default_settings,

	.type_offset = offsetof(struct mail_namespace_settings, name),
	.struct_size = sizeof(struct mail_namespace_settings),

	.parent_offset = offsetof(struct mail_namespace_settings, user_set),
	.parent = &mail_user_setting_parser_info,

	.check_func = namespace_settings_check
};
#undef DEF
#undef DEFLIST_UNIQUE
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type(#name, name, struct mail_user_settings)
#define DEFLIST_UNIQUE(field, name, defines) \
	{ .type = SET_DEFLIST_UNIQUE, .key = name, \
	  .offset = offsetof(struct mail_user_settings, field), \
	  .list_info = defines }
static const struct setting_define mail_user_setting_defines[] = {
	DEF(STR, base_dir),
	DEF(STR, auth_socket_path),
	DEF(STR_VARS, mail_temp_dir),

	DEF(STR, mail_uid),
	DEF(STR, mail_gid),
	DEF(STR_VARS, mail_home),
	DEF(STR_VARS, mail_chroot),
	DEF(STR, mail_access_groups),
	DEF(STR, mail_privileged_group),
	DEF(STR, valid_chroot_dirs),

	DEF(UINT, first_valid_uid),
	DEF(UINT, last_valid_uid),
	DEF(UINT, first_valid_gid),
	DEF(UINT, last_valid_gid),

	DEF(STR, mail_plugins),
	DEF(STR, mail_plugin_dir),

	DEF(STR, mail_log_prefix),

	DEF(STR, hostname),
	DEF(STR_VARS, postmaster_address),

	DEFLIST_UNIQUE(namespaces, "namespace", &mail_namespace_setting_parser_info),
	{ .type = SET_STRLIST, .key = "plugin",
	  .offset = offsetof(struct mail_user_settings, plugin_envs) },

	SETTING_DEFINE_LIST_END
};
static const struct mail_user_settings mail_user_default_settings = {
	.base_dir = PKG_RUNDIR,
	.auth_socket_path = "auth-userdb",
	.mail_temp_dir = "/tmp",

	.mail_uid = "",
	.mail_gid = "",
	.mail_home = "",
	.mail_chroot = "",
	.mail_access_groups = "",
	.mail_privileged_group = "",
	.valid_chroot_dirs = "",

	.first_valid_uid = 500,
	.last_valid_uid = 0,
	.first_valid_gid = 1,
	.last_valid_gid = 0,

	.mail_plugins = "",
	.mail_plugin_dir = MODULEDIR,

	.mail_log_prefix = "%s(%u)<%{pid}><%{session}>: ",

	.hostname = "",
	.postmaster_address = "postmaster@%{if;%d;ne;;%d;%{hostname}}",

	.namespaces = ARRAY_INIT,
	.plugin_envs = ARRAY_INIT
};
const struct setting_parser_info mail_user_setting_parser_info = {
	.module_name = "mail",
	.defines = mail_user_setting_defines,
	.defaults = &mail_user_default_settings,

	.type_offset = SIZE_MAX,
	.struct_size = sizeof(struct mail_user_settings),

	.parent_offset = SIZE_MAX,

	.check_func = mail_user_settings_check,
#ifndef CONFIG_BINARY
	.expand_check_func = mail_user_settings_expand_check,
#endif
};
/* ../../src/lib-storage/index/pop3c/pop3c-settings.c */
/* <settings checks> */
struct pop3c_feature_list {
	const char *name;
	enum pop3c_features num;
};

static const struct pop3c_feature_list pop3c_feature_list[] = {
	{ "no-pipelining", POP3C_FEATURE_NO_PIPELINING },
	{ NULL, 0 }
};

static int
pop3c_settings_parse_features(struct pop3c_settings *set,
			      const char **error_r)
{
	enum pop3c_features features = 0;
	const struct pop3c_feature_list *list;
	const char *const *str;

	str = t_strsplit_spaces(set->pop3c_features, " ,");
	for (; *str != NULL; str++) {
		list = pop3c_feature_list;
		for (; list->name != NULL; list++) {
			if (strcasecmp(*str, list->name) == 0) {
				features |= list->num;
				break;
			}
		}
		if (list->name == NULL) {
			*error_r = t_strdup_printf("pop3c_features: "
				"Unknown feature: %s", *str);
			return -1;
		}
	}
	set->parsed_features = features;
	return 0;
}

static bool pop3c_settings_check(void *_set, pool_t pool ATTR_UNUSED,
				 const char **error_r)
{
	struct pop3c_settings *set = _set;

	if (pop3c_settings_parse_features(set, error_r) < 0)
		return FALSE;
	return TRUE;
}
/* </settings checks> */
#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type(#name, name, struct pop3c_settings)
static const struct setting_define pop3c_setting_defines[] = {
	DEF(STR, pop3c_host),
	DEF(IN_PORT, pop3c_port),

	DEF(STR_VARS, pop3c_user),
	DEF(STR_VARS, pop3c_master_user),
	DEF(STR, pop3c_password),

	DEF(ENUM, pop3c_ssl),
	DEF(BOOL, pop3c_ssl_verify),

	DEF(STR, pop3c_rawlog_dir),
	DEF(BOOL, pop3c_quick_received_date),

	DEF(STR, pop3c_features),

	SETTING_DEFINE_LIST_END
};
static const struct pop3c_settings pop3c_default_settings = {
	.pop3c_host = "",
	.pop3c_port = 110,

	.pop3c_user = "%u",
	.pop3c_master_user = "",
	.pop3c_password = "",

	.pop3c_ssl = "no:pop3s:starttls",
	.pop3c_ssl_verify = TRUE,

	.pop3c_rawlog_dir = "",
	.pop3c_quick_received_date = FALSE,

	.pop3c_features = ""
};
static const struct setting_parser_info pop3c_setting_parser_info = {
	.module_name = "pop3c",
	.defines = pop3c_setting_defines,
	.defaults = &pop3c_default_settings,

	.type_offset = SIZE_MAX,
	.struct_size = sizeof(struct pop3c_settings),

	.parent_offset = SIZE_MAX,
	.parent = &mail_user_setting_parser_info,

        .check_func = pop3c_settings_check
};
/* ../../src/lib-storage/index/mbox/mbox-settings.c */
#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type(#name, name, struct mbox_settings)
static const struct setting_define mbox_setting_defines[] = {
	DEF(STR, mbox_read_locks),
	DEF(STR, mbox_write_locks),
	DEF(TIME, mbox_lock_timeout),
	DEF(TIME, mbox_dotlock_change_timeout),
	DEF(SIZE, mbox_min_index_size),
	DEF(BOOL, mbox_dirty_syncs),
	DEF(BOOL, mbox_very_dirty_syncs),
	DEF(BOOL, mbox_lazy_writes),
	DEF(ENUM, mbox_md5),

	SETTING_DEFINE_LIST_END
};
static const struct mbox_settings mbox_default_settings = {
	.mbox_read_locks = "fcntl",
	.mbox_write_locks = "dotlock fcntl",
	.mbox_lock_timeout = 5*60,
	.mbox_dotlock_change_timeout = 2*60,
	.mbox_min_index_size = 0,
	.mbox_dirty_syncs = TRUE,
	.mbox_very_dirty_syncs = FALSE,
	.mbox_lazy_writes = TRUE,
	.mbox_md5 = "apop3d:all"
};
static const struct setting_parser_info mbox_setting_parser_info = {
	.module_name = "mbox",
	.defines = mbox_setting_defines,
	.defaults = &mbox_default_settings,

	.type_offset = SIZE_MAX,
	.struct_size = sizeof(struct mbox_settings),

	.parent_offset = SIZE_MAX,
	.parent = &mail_user_setting_parser_info
};
/* ../../src/lib-storage/index/maildir/maildir-settings.c */
#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type(#name, name, struct maildir_settings)
static const struct setting_define maildir_setting_defines[] = {
	DEF(BOOL, maildir_copy_with_hardlinks),
	DEF(BOOL, maildir_very_dirty_syncs),
	DEF(BOOL, maildir_broken_filename_sizes),
	DEF(BOOL, maildir_empty_new),

	SETTING_DEFINE_LIST_END
};
static const struct maildir_settings maildir_default_settings = {
	.maildir_copy_with_hardlinks = TRUE,
	.maildir_very_dirty_syncs = FALSE,
	.maildir_broken_filename_sizes = FALSE,
	.maildir_empty_new = FALSE
};
static const struct setting_parser_info maildir_setting_parser_info = {
	.module_name = "maildir",
	.defines = maildir_setting_defines,
	.defaults = &maildir_default_settings,

	.type_offset = SIZE_MAX,
	.struct_size = sizeof(struct maildir_settings),

	.parent_offset = SIZE_MAX,
	.parent = &mail_user_setting_parser_info
};
/* ../../src/lib-storage/index/imapc/imapc-settings.c */
/* <settings checks> */
struct imapc_feature_list {
	const char *name;
	enum imapc_features num;
};

static const struct imapc_feature_list imapc_feature_list[] = {
	{ "rfc822.size", IMAPC_FEATURE_RFC822_SIZE },
	{ "guid-forced", IMAPC_FEATURE_GUID_FORCED },
	{ "fetch-headers", IMAPC_FEATURE_FETCH_HEADERS },
	{ "gmail-migration", IMAPC_FEATURE_GMAIL_MIGRATION },
	{ "search", IMAPC_FEATURE_SEARCH },
	{ "zimbra-workarounds", IMAPC_FEATURE_ZIMBRA_WORKAROUNDS },
	{ "no-examine", IMAPC_FEATURE_NO_EXAMINE },
	{ "proxyauth", IMAPC_FEATURE_PROXYAUTH },
	{ "fetch-msn-workarounds", IMAPC_FEATURE_FETCH_MSN_WORKAROUNDS },
	{ "fetch-fix-broken-mails", IMAPC_FEATURE_FETCH_FIX_BROKEN_MAILS },
	{ "modseq", IMAPC_FEATURE_MODSEQ },
	{ "delay-login", IMAPC_FEATURE_DELAY_LOGIN },
	{ "fetch-bodystructure", IMAPC_FEATURE_FETCH_BODYSTRUCTURE },
	{ "send-id", IMAPC_FEATURE_SEND_ID },
	{ "fetch-empty-is-expunged", IMAPC_FEATURE_FETCH_EMPTY_IS_EXPUNGED },
	{ "no-msn-updates", IMAPC_FEATURE_NO_MSN_UPDATES },
	{ "acl", IMAPC_FEATURE_ACL },
	{ NULL, 0 }
};

static int
imapc_settings_parse_throttle(struct imapc_settings *set,
			      const char *throttle_str, const char **error_r)
{
	const char *const *tmp;

	tmp = t_strsplit(throttle_str, ":");
	if (str_array_length(tmp) != 3 ||
	    str_to_uint(tmp[0], &set->throttle_init_msecs) < 0 ||
	    str_to_uint(tmp[1], &set->throttle_max_msecs) < 0 ||
	    str_to_uint(tmp[2], &set->throttle_shrink_min_msecs) < 0) {
		*error_r = "imapc_features: Invalid throttle settings";
		return -1;
	}
	return 0;
}

static int
imapc_settings_parse_features(struct imapc_settings *set,
			      const char **error_r)
{
        enum imapc_features features = 0;
        const struct imapc_feature_list *list;
	const char *const *str;

        str = t_strsplit_spaces(set->imapc_features, " ,");
	for (; *str != NULL; str++) {
		list = imapc_feature_list;
		for (; list->name != NULL; list++) {
			if (strcasecmp(*str, list->name) == 0) {
				features |= list->num;
				break;
			}
		}
		if (strncasecmp(*str, "throttle:", 9) == 0) {
			if (imapc_settings_parse_throttle(set, *str + 9, error_r) < 0)
				return -1;
			continue;
		}
		if (list->name == NULL) {
			*error_r = t_strdup_printf("imapc_features: "
				"Unknown feature: %s", *str);
			return -1;
		}
	}
	set->parsed_features = features;
	return 0;
}

static bool imapc_settings_check(void *_set, pool_t pool ATTR_UNUSED,
				 const char **error_r)
{
	struct imapc_settings *set = _set;

	if (set->imapc_max_idle_time == 0) {
		*error_r = "imapc_max_idle_time must not be 0";
		return FALSE;
	}
	if (imapc_settings_parse_features(set, error_r) < 0)
		return FALSE;
	return TRUE;
}
#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type(#name, name, struct imapc_settings)
static const struct setting_define imapc_setting_defines[] = {
	DEF(STR, imapc_host),
	DEF(IN_PORT, imapc_port),

	DEF(STR_VARS, imapc_user),
	DEF(STR_VARS, imapc_master_user),
	DEF(STR, imapc_password),
	DEF(STR, imapc_sasl_mechanisms),

	DEF(ENUM, imapc_ssl),
	DEF(BOOL, imapc_ssl_verify),

	DEF(STR, imapc_features),
	DEF(STR, imapc_rawlog_dir),
	DEF(STR, imapc_list_prefix),
	DEF(TIME, imapc_cmd_timeout),
	DEF(TIME, imapc_max_idle_time),
	DEF(UINT, imapc_connection_retry_count),
	DEF(TIME_MSECS, imapc_connection_retry_interval),
	DEF(SIZE, imapc_max_line_length),

	DEF(STR, pop3_deleted_flag),

	SETTING_DEFINE_LIST_END
};
static const struct imapc_settings imapc_default_settings = {
	.imapc_host = "",
	.imapc_port = 143,

	.imapc_user = "",
	.imapc_master_user = "",
	.imapc_password = "",
	.imapc_sasl_mechanisms = "",

	.imapc_ssl = "no:imaps:starttls",
	.imapc_ssl_verify = TRUE,

	.imapc_features = "",
	.imapc_rawlog_dir = "",
	.imapc_list_prefix = "",
	.imapc_cmd_timeout = 5*60,
	.imapc_max_idle_time = 60*29,
	.imapc_connection_retry_count = 1,
	.imapc_connection_retry_interval = 1000,
	.imapc_max_line_length = 0,

	.pop3_deleted_flag = ""
};
static const struct setting_parser_info imapc_setting_parser_info = {
	.module_name = "imapc",
	.defines = imapc_setting_defines,
	.defaults = &imapc_default_settings,

	.type_offset = SIZE_MAX,
	.struct_size = sizeof(struct imapc_settings),

	.parent_offset = SIZE_MAX,
	.parent = &mail_user_setting_parser_info,

	.check_func = imapc_settings_check
};
/* ../../src/lib-storage/index/dbox-multi/mdbox-settings.c */
#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type(#name, name, struct mdbox_settings)
static const struct setting_define mdbox_setting_defines[] = {
	DEF(BOOL, mdbox_preallocate_space),
	DEF(SIZE, mdbox_rotate_size),
	DEF(TIME, mdbox_rotate_interval),

	SETTING_DEFINE_LIST_END
};
static const struct mdbox_settings mdbox_default_settings = {
	.mdbox_preallocate_space = FALSE,
	.mdbox_rotate_size = 10*1024*1024,
	.mdbox_rotate_interval = 0
};
static const struct setting_parser_info mdbox_setting_parser_info = {
	.module_name = "mdbox",
	.defines = mdbox_setting_defines,
	.defaults = &mdbox_default_settings,

	.type_offset = SIZE_MAX,
	.struct_size = sizeof(struct mdbox_settings),

	.parent_offset = SIZE_MAX,
	.parent = &mail_user_setting_parser_info
};
/* ../../src/lib-lda/lda-settings.c */
#undef DEF
#undef DEFLIST
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type(#name, name, struct lda_settings)
#define DEFLIST(field, name, defines) \
	{ .type = SET_DEFLIST, .key = name, \
	  .offset = offsetof(struct lda_settings, field), \
	  .list_info = defines }
static const struct setting_define lda_setting_defines[] = {
	DEF(STR, hostname),
	DEF(STR, rejection_subject),
	DEF(STR, rejection_reason),
	DEF(STR, deliver_log_format),
	DEF(STR, recipient_delimiter),
	DEF(STR, lda_original_recipient_header),
	DEF(BOOL, quota_full_tempfail),
	DEF(BOOL, lda_mailbox_autocreate),
	DEF(BOOL, lda_mailbox_autosubscribe),

	SETTING_DEFINE_LIST_END
};
static const struct lda_settings lda_default_settings = {
	.hostname = "",
	.rejection_subject = "Rejected: %s",
	.rejection_reason =
		"Your message to <%t> was automatically rejected:%n%r",
	.deliver_log_format = "msgid=%m: %$",
	.recipient_delimiter = "+",
	.lda_original_recipient_header = "",
	.quota_full_tempfail = FALSE,
	.lda_mailbox_autocreate = FALSE,
	.lda_mailbox_autosubscribe = FALSE
};
static const struct setting_parser_info *lda_setting_dependencies[] = {
	&mail_user_setting_parser_info,
	&smtp_submit_setting_parser_info,
	NULL
};
const struct setting_parser_info lda_setting_parser_info = {
	.module_name = "lda",
	.defines = lda_setting_defines,
	.defaults = &lda_default_settings,

	.type_offset = SIZE_MAX,
	.struct_size = sizeof(struct lda_settings),

	.parent_offset = SIZE_MAX,

#ifndef CONFIG_BINARY
	.check_func = lda_settings_check,
#endif
	.dependencies = lda_setting_dependencies
};
/* ../../src/lib-dict-backend/dict-sql-settings.c */
#define DEF_STR(name) DEF_STRUCT_STR(name, dict_sql_map)
#define DEF_BOOL(name) DEF_STRUCT_BOOL(name, dict_sql_map)
/* ../../src/lib-dict-backend/dict-ldap-settings.c */
#undef DEF_STR
#undef DEF_BOOL
#undef DEF_UINT
#define DEF_STR(name) DEF_STRUCT_STR(name, dict_ldap_map)
#define DEF_BOOL(name) DEF_STRUCT_BOOL(name, dict_ldap_map)
#define DEF_UINT(name) DEF_STRUCT_UINT(name ,dict_ldap_map)
/* ../../src/submission/submission-settings.h */
extern const struct setting_parser_info submission_setting_parser_info;
/* <settings checks> */
enum submission_client_workarounds {
	SUBMISSION_WORKAROUND_WHITESPACE_BEFORE_PATH	= BIT(0),
	SUBMISSION_WORKAROUND_MAILBOX_FOR_PATH		= BIT(1),
};
/* </settings checks> */
struct submission_settings {
	bool verbose_proctitle;
	const char *rawlog_dir;

	const char *hostname;

	const char *login_greeting;
	const char *login_trusted_networks;

	const char *recipient_delimiter;

	/* submission: */
	uoff_t submission_max_mail_size;
	unsigned int submission_max_recipients;
	const char *submission_client_workarounds;
	const char *submission_logout_format;

	/* submission backend: */
	const char *submission_backend_capabilities;

	/* submission relay: */
	const char *submission_relay_host;
	in_port_t submission_relay_port;
	bool submission_relay_trusted;

	const char *submission_relay_user;
	const char *submission_relay_master_user;
	const char *submission_relay_password;

	const char *submission_relay_ssl;
	bool submission_relay_ssl_verify;

	const char *submission_relay_rawlog_dir;
	unsigned int submission_relay_max_idle_time;

	unsigned int submission_relay_connect_timeout;
	unsigned int submission_relay_command_timeout;

	/* imap urlauth: */
	const char *imap_urlauth_host;
	in_port_t imap_urlauth_port;

	enum submission_client_workarounds parsed_workarounds;
};
/* ../../src/submission-login/submission-login-settings.h */
extern const struct setting_parser_info *submission_login_setting_roots[];
/* <settings checks> */
enum submission_login_client_workarounds {
	SUBMISSION_LOGIN_WORKAROUND_IMPLICIT_AUTH_EXTERNAL	= BIT(0),
	SUBMISSION_LOGIN_WORKAROUND_EXOTIC_BACKEND		= BIT(1),
};
/* </settings checks> */
struct submission_login_settings {
	const char *hostname;

	/* submission: */
	uoff_t submission_max_mail_size;
	const char *submission_client_workarounds;
	const char *submission_backend_capabilities;

	enum submission_login_client_workarounds parsed_workarounds;
};
/* ../../src/stats/stats-settings.h */
extern const struct setting_parser_info stats_setting_parser_info;
extern const struct setting_parser_info stats_metric_setting_parser_info;
/* <settings checks> */
/*
 * We allow a selection of a timestamp format.
 *
 * The 'time-unix' format generates a number with the number of seconds
 * since 1970-01-01 00:00 UTC.
 *
 * The 'time-rfc3339' format uses the YYYY-MM-DDTHH:MM:SS.uuuuuuZ format as
 * defined by RFC 3339.
 *
 * The special native format (not explicitly selectable in the config, but
 * default if no time-* token is used) uses the format's native timestamp
 * format.  Note that not all formats have a timestamp data format.
 *
 * The native format and the rules below try to address the question: can a
 * parser that doesn't have any knowledge of fields' values' types losslessly
 * reconstruct the fields?
 *
 * For example, JSON only has strings and numbers, so it cannot represent a
 * timestamp in a "context-free lossless" way.  Therefore, when making a
 * JSON blob, we need to decide which way to serialize timestamps.  No
 * matter how we do it, we incur some loss.  If a decoder sees 1557232304 in
 * a field, it cannot be certain if the field is an integer that just
 * happens to be a reasonable timestamp, or if it actually is a timestamp.
 * Same goes with RFC3339 - it could just be that the user supplied a string
 * that looks like a timestamp, and that string made it into an event field.
 *
 * Other common serialization formats, such as CBOR, have a lossless way of
 * encoding timestamps.
 *
 * Note that there are two concepts at play: native and default.
 *
 * The rules for how the format's timestamp formats are used:
 *
 * 1. The default time format is the native format.
 * 2. The native time format may or may not exist for a given format (e.g.,
 *    in JSON)
 * 3. If the native format doesn't exist and no time format was specified in
 *    the config, it is a config error.
 *
 * We went with these rules because:
 *
 * 1. It prevents type information loss by default.
 * 2. It completely isolates the policy from the algorithm.
 * 3. It defers the decision whether each format without a native timestamp
 *    type should have a default acting as native until after we've had some
 *    operational experience.
 * 4. A future decision to add a default (via 3. point) will be 100% compatible.
 */
enum event_exporter_time_fmt {
	EVENT_EXPORTER_TIME_FMT_NATIVE = 0,
	EVENT_EXPORTER_TIME_FMT_UNIX,
	EVENT_EXPORTER_TIME_FMT_RFC3339,
};
/* </settings checks> */
/* <settings checks> */
enum stats_metric_group_by_func {
	STATS_METRIC_GROUPBY_DISCRETE = 0,
	STATS_METRIC_GROUPBY_QUANTIZED,
};

/*
 * A range covering a stats bucket.  The the interval is half closed - the
 * minimum is excluded and the maximum is included.  In other words: (min, max].
 * Because we don't have a +Inf and -Inf, we use INTMAX_MIN and INTMAX_MAX
 * respectively.
 */
struct stats_metric_settings_bucket_range {
	intmax_t min;
	intmax_t max;
};

struct stats_metric_settings_group_by {
	const char *field;
	enum stats_metric_group_by_func func;
	unsigned int num_ranges;
	struct stats_metric_settings_bucket_range *ranges;
};
/* </settings checks> */
#define STATS_METRIC_SETTINGS_DEFAULT_EXPORTER_INCLUDE \
	"name hostname timestamps categories fields"
struct stats_exporter_settings {
	const char *name;
	const char *transport;
	const char *transport_args;
	unsigned int transport_timeout;
	const char *format;
	const char *format_args;

	/* parsed values */
	enum event_exporter_time_fmt parsed_time_format;
};
struct stats_metric_settings {
	const char *metric_name;
	const char *description;
	const char *fields;
	const char *group_by;
	const char *filter;

	ARRAY(struct stats_metric_settings_group_by) parsed_group_by;
	struct event_filter *parsed_filter;

	/* exporter related fields */
	const char *exporter;
	const char *exporter_include;
};
struct stats_settings {
	const char *stats_http_rawlog_dir;

	ARRAY(struct stats_exporter_settings *) exporters;
	ARRAY(struct stats_metric_settings *) metrics;
};
/* ../../src/replication/replicator/replicator-settings.h */
extern const struct setting_parser_info replicator_setting_parser_info;
struct replicator_settings {
	const char *auth_socket_path;
	const char *doveadm_socket_path;
	const char *replication_dsync_parameters;

	unsigned int replication_full_sync_interval;
	unsigned int replication_max_conns;
};
/* ../../src/replication/aggregator/aggregator-settings.h */
extern const struct setting_parser_info aggregator_setting_parser_info;
struct aggregator_settings {
	const char *replicator_host;
	in_port_t replicator_port;
};
/* ../../src/pop3/pop3-settings.h */
extern const struct setting_parser_info pop3_setting_parser_info;
/* <settings checks> */
enum pop3_client_workarounds {
	WORKAROUND_OUTLOOK_NO_NULS		= 0x01,
	WORKAROUND_OE_NS_EOH			= 0x02
};
enum pop3_delete_type {
	POP3_DELETE_TYPE_EXPUNGE = 0,
	POP3_DELETE_TYPE_FLAG,
};
/* </settings checks> */
struct pop3_settings {
	bool verbose_proctitle;
	const char *rawlog_dir;

	/* pop3: */
	bool pop3_no_flag_updates;
	bool pop3_enable_last;
	bool pop3_reuse_xuidl;
	bool pop3_save_uidl;
	bool pop3_lock_session;
	bool pop3_fast_size_lookups;
	const char *pop3_client_workarounds;
	const char *pop3_logout_format;
	const char *pop3_uidl_duplicates;
	const char *pop3_deleted_flag;
	const char *pop3_delete_type;

	enum pop3_client_workarounds parsed_workarounds;
	enum pop3_delete_type parsed_delete_type;
};
/* ../../src/pop3-login/pop3-login-settings.h */
extern const struct setting_parser_info *pop3_login_setting_roots[];
/* ../../src/plugins/quota/quota-status-settings.h */
extern const struct setting_parser_info quota_status_setting_parser_info;
struct quota_status_settings {
	const char *recipient_delimiter;
};
/* ../../src/plugins/mail-crypt/fs-crypt-settings.h */
extern const struct setting_parser_info fs_crypt_setting_parser_info;
struct fs_crypt_settings {
	ARRAY(const char *) plugin_envs;
};
/* ../../src/old-stats/stats-settings.h */
extern const struct setting_parser_info old_stats_setting_parser_info;
struct old_stats_settings {
	uoff_t memory_limit;

	unsigned int command_min_time;
	unsigned int session_min_time;
	unsigned int user_min_time;
	unsigned int domain_min_time;
	unsigned int ip_min_time;

	unsigned int carbon_interval;
	const char *carbon_server;
	const char *carbon_name;
};
/* ../../src/master/master-settings.h */
extern const struct setting_parser_info master_setting_parser_info;
struct master_settings {
	const char *base_dir;
	const char *state_dir;
	const char *libexec_dir;
	const char *instance_name;
	const char *protocols;
	const char *listen;
	const char *ssl;
	const char *default_internal_user;
	const char *default_internal_group;
	const char *default_login_user;
	unsigned int default_process_limit;
	unsigned int default_client_limit;
	unsigned int default_idle_kill;
	uoff_t default_vsz_limit;

	bool version_ignore;

	unsigned int first_valid_uid, last_valid_uid;
	unsigned int first_valid_gid, last_valid_gid;

	ARRAY_TYPE(service_settings) services;
	char **protocols_split;
};
/* ../../src/login-common/login-settings.h */
extern const struct setting_parser_info **login_set_roots;
extern const struct setting_parser_info login_setting_parser_info;
struct login_settings {
	const char *login_trusted_networks;
	const char *login_source_ips;
	const char *login_greeting;
	const char *login_log_format_elements, *login_log_format;
	const char *login_access_sockets;
	const char *login_proxy_notify_path;
	const char *login_plugin_dir;
	const char *login_plugins;
	unsigned int login_proxy_timeout;
	unsigned int login_proxy_max_reconnects;
	unsigned int login_proxy_max_disconnect_delay;
	const char *login_proxy_rawlog_dir;
	const char *director_username_hash;

	bool auth_ssl_require_client_cert;
	bool auth_ssl_username_from_cert;

	bool disable_plaintext_auth;
	bool auth_verbose;
	bool auth_debug;
	bool auth_debug_passwords;
	bool verbose_proctitle;

	unsigned int mail_max_userip_connections;

	/* generated: */
	char *const *log_format_elements_split;
};
/* ../../src/lmtp/lmtp-settings.h */
extern const struct setting_parser_info lmtp_setting_parser_info;
/* <settings checks> */
enum lmtp_hdr_delivery_address {
	LMTP_HDR_DELIVERY_ADDRESS_NONE,
	LMTP_HDR_DELIVERY_ADDRESS_FINAL,
	LMTP_HDR_DELIVERY_ADDRESS_ORIGINAL
};

enum lmtp_client_workarounds {
	LMTP_WORKAROUND_WHITESPACE_BEFORE_PATH	= BIT(0),
	LMTP_WORKAROUND_MAILBOX_FOR_PATH	= BIT(1),
};
/* </settings checks> */
struct lmtp_settings {
	bool lmtp_proxy;
	bool lmtp_save_to_detail_mailbox;
	bool lmtp_rcpt_check_quota;
	bool lmtp_add_received_header;
	bool lmtp_verbose_replies;
	unsigned int lmtp_user_concurrency_limit;
	const char *lmtp_hdr_delivery_address;
	const char *lmtp_rawlog_dir;
	const char *lmtp_proxy_rawlog_dir;

	const char *lmtp_client_workarounds;

	const char *login_greeting;
	const char *login_trusted_networks;

	const char *mail_plugins;
	const char *mail_plugin_dir;

	enum lmtp_hdr_delivery_address parsed_lmtp_hdr_delivery_address;

	enum lmtp_client_workarounds parsed_workarounds;
};
/* ../../src/imap/imap-settings.h */
extern const struct setting_parser_info imap_setting_parser_info;
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
/* ../../src/imap-urlauth/imap-urlauth-worker-settings.h */
extern const struct setting_parser_info imap_urlauth_worker_setting_parser_info;
struct imap_urlauth_worker_settings {
	bool verbose_proctitle;

	/* imap_urlauth: */
	const char *imap_urlauth_host;
	in_port_t imap_urlauth_port;
};
/* ../../src/imap-urlauth/imap-urlauth-settings.h */
extern const struct setting_parser_info imap_urlauth_setting_parser_info;
struct imap_urlauth_settings {
	const char *base_dir;

	bool mail_debug;

	bool verbose_proctitle;

	/* imap_urlauth: */
	const char *imap_urlauth_logout_format;

	const char *imap_urlauth_submit_user;
	const char *imap_urlauth_stream_user;
};
/* ../../src/imap-urlauth/imap-urlauth-login-settings.h */
extern const struct setting_parser_info *imap_urlauth_login_setting_roots[];
/* ../../src/imap-login/imap-login-settings.h */
extern const struct setting_parser_info *imap_login_setting_roots[];
struct imap_login_settings {
	const char *imap_capability;
	const char *imap_id_send;
	const char *imap_id_log;
	bool imap_literal_minus;
	bool imap_id_retain;
};
/* ../../src/doveadm/doveadm-settings.h */
extern const struct setting_parser_info doveadm_setting_parser_info;
/* <settings checks> */
enum dsync_features {
	DSYNC_FEATURE_EMPTY_HDR_WORKAROUND = 0x1,
	DSYNC_FEATURE_NO_HEADER_HASHES = 0x2,
};
/* </settings checks> */
struct doveadm_settings {
	const char *base_dir;
	const char *libexec_dir;
	const char *mail_plugins;
	const char *mail_plugin_dir;
	const char *mail_temp_dir;
	bool auth_debug;
	const char *auth_socket_path;
	const char *doveadm_socket_path;
	unsigned int doveadm_worker_count;
	in_port_t doveadm_port;
	const char *doveadm_ssl;
	const char *doveadm_username;
	const char *doveadm_password;
	const char *doveadm_allowed_commands;
	const char *dsync_alt_char;
	const char *dsync_remote_cmd;
	const char *director_username_hash;
	const char *doveadm_api_key;
	const char *dsync_features;
	const char *dsync_hashed_headers;
	unsigned int dsync_commit_msgs_interval;
	const char *doveadm_http_rawlog_dir;
	enum dsync_features parsed_features;
	ARRAY(const char *) plugin_envs;
};
/* ../../src/director/director-settings.h */
extern const struct setting_parser_info director_setting_parser_info;
struct director_settings {
	const char *auth_master_user_separator;

	const char *director_servers;
	const char *director_mail_servers;
	const char *director_username_hash;
	const char *director_flush_socket;

	unsigned int director_ping_idle_timeout;
	unsigned int director_ping_max_timeout;
	unsigned int director_user_expire;
	unsigned int director_user_kick_delay;
	unsigned int director_max_parallel_moves;
	unsigned int director_max_parallel_kicks;
	uoff_t director_output_buffer_size;
};
/* ../../src/dict/dict-settings.h */
extern const struct setting_parser_info dict_setting_parser_info;
struct dict_server_settings {
	const char *base_dir;
	bool verbose_proctitle;

	const char *dict_db_config;
	ARRAY(const char *) dicts;
};
/* ../../src/auth/auth-settings.h */
extern const struct setting_parser_info auth_setting_parser_info;
struct auth_passdb_settings {
	const char *name;
	const char *driver;
	const char *args;
	const char *default_fields;
	const char *override_fields;
	const char *mechanisms;
	const char *username_filter;

	const char *skip;
	const char *result_success;
	const char *result_failure;
	const char *result_internalfail;
	bool deny;
	bool pass; /* deprecated, use result_success=continue instead */
	bool master;
	const char *auth_verbose;
};
struct auth_userdb_settings {
	const char *name;
	const char *driver;
	const char *args;
	const char *default_fields;
	const char *override_fields;

	const char *skip;
	const char *result_success;
	const char *result_failure;
	const char *result_internalfail;
	const char *auth_verbose;
};
struct auth_settings {
	const char *mechanisms;
	const char *realms;
	const char *default_realm;
	uoff_t cache_size;
	unsigned int cache_ttl;
	unsigned int cache_negative_ttl;
	bool cache_verify_password_with_worker;
	const char *username_chars;
	const char *username_translation;
	const char *username_format;
	const char *master_user_separator;
	const char *anonymous_username;
	const char *krb5_keytab;
	const char *gssapi_hostname;
	const char *winbind_helper_path;
	const char *proxy_self;
	unsigned int failure_delay;

	const char *policy_server_url;
	const char *policy_server_api_header;
	unsigned int policy_server_timeout_msecs;
	const char *policy_hash_mech;
	const char *policy_hash_nonce;
	const char *policy_request_attributes;
	bool policy_reject_on_fail;
	bool policy_check_before_auth;
	bool policy_check_after_auth;
	bool policy_report_after_auth;
	bool policy_log_only;
	unsigned int policy_hash_truncate;

	bool stats;
	bool verbose, debug, debug_passwords;
	const char *verbose_passwords;
	bool ssl_require_client_cert;
	bool ssl_username_from_cert;
	bool use_winbind;

	unsigned int worker_max_count;

	/* settings that don't have auth_ prefix: */
	ARRAY(struct auth_passdb_settings *) passdbs;
	ARRAY(struct auth_userdb_settings *) userdbs;

	const char *base_dir;
	const char *ssl_client_ca_dir;
	const char *ssl_client_ca_file;

	bool verbose_proctitle;
	unsigned int first_valid_uid;
	unsigned int last_valid_uid;
	unsigned int first_valid_gid;
	unsigned int last_valid_gid;

	/* generated: */
	char username_chars_map[256];
	char username_translation_map[256];
	const char *const *realms_arr;
	const struct ip_addr *proxy_self_ips;
};
/* ../../src/util/tcpwrap-settings.c */
#ifdef HAVE_LIBWRAP
struct service_settings tcpwrap_service_settings = {
	.name = "tcpwrap",
	.protocol = "",
	.type = "",
	.executable = "tcpwrap",
	.user = "$default_internal_user",
	.group = "",
	.privileged_group = "",
	.extra_groups = "",
	.chroot = "",

	.drop_priv_before_exec = FALSE,

	.process_min_avail = 0,
	.process_limit = 0,
	.client_limit = 1,
	.service_count = 0,
	.idle_kill = 0,
	.vsz_limit = UOFF_T_MAX,

	.unix_listeners = ARRAY_INIT,
	.fifo_listeners = ARRAY_INIT,
	.inet_listeners = ARRAY_INIT
};
#endif
/* ../../src/util/health-check-settings.c */
struct service_settings health_check_service_settings = {
	.name = "health-check",
	.protocol = "",
	.type = "",
	.executable = "script -p health-check.sh",
	.user = "$default_internal_user",
	.group = "",
	.privileged_group = "",
	.extra_groups = "",
	.chroot = "",

	.drop_priv_before_exec = TRUE,

	.process_min_avail = 0,
	.process_limit = 0,
	.client_limit = 1,
	.service_count = 0,
	.idle_kill = 0,
	.vsz_limit = UOFF_T_MAX,

	.unix_listeners = ARRAY_INIT,
	.fifo_listeners = ARRAY_INIT,
	.inet_listeners = ARRAY_INIT
};
/* ../../src/submission/submission-settings.c */
/* <settings checks> */
static struct file_listener_settings submission_unix_listeners_array[] = {
	{ "login/submission", 0666, "", "" }
};
static struct file_listener_settings *submission_unix_listeners[] = {
	&submission_unix_listeners_array[0]
};
static buffer_t submission_unix_listeners_buf = {
	{ { submission_unix_listeners, sizeof(submission_unix_listeners) } }
};
/* </settings checks> */
/* <settings checks> */
struct submission_client_workaround_list {
	const char *name;
	enum submission_client_workarounds num;
};

/* These definitions need to be kept in sync with equivalent definitions present
   in src/submission-login/submission-login-settings.c. Workarounds that are not
   relevant to the submission service are defined as 0 here to prevent "Unknown
   workaround" errors below. */
static const struct submission_client_workaround_list
submission_client_workaround_list[] = {
	{ "whitespace-before-path",
	  SUBMISSION_WORKAROUND_WHITESPACE_BEFORE_PATH },
	{ "mailbox-for-path",
	  SUBMISSION_WORKAROUND_MAILBOX_FOR_PATH },
	{ "implicit-auth-external", 0 },
	{ "exotic-backend", 0 },
	{ NULL, 0 }
};

static int
submission_settings_parse_workarounds(struct submission_settings *set,
				const char **error_r)
{
	enum submission_client_workarounds client_workarounds = 0;
        const struct submission_client_workaround_list *list;
	const char *const *str;

        str = t_strsplit_spaces(set->submission_client_workarounds, " ,");
	for (; *str != NULL; str++) {
		list = submission_client_workaround_list;
		for (; list->name != NULL; list++) {
			if (strcasecmp(*str, list->name) == 0) {
				client_workarounds |= list->num;
				break;
			}
		}
		if (list->name == NULL) {
			*error_r = t_strdup_printf(
				"submission_client_workarounds: "
				"Unknown workaround: %s", *str);
			return -1;
		}
	}
	set->parsed_workarounds = client_workarounds;
	return 0;
}

static bool
submission_settings_verify(void *_set, pool_t pool ATTR_UNUSED, const char **error_r)
{
	struct submission_settings *set = _set;

	if (submission_settings_parse_workarounds(set, error_r) < 0)
		return FALSE;

#ifndef CONFIG_BINARY
	if (set->submission_relay_max_idle_time == 0) {
		*error_r = "submission_relay_max_idle_time must not be 0";
		return FALSE;
	}
	if (*set->hostname == '\0')
		set->hostname = p_strdup(pool, my_hostdomain());
#endif
	return TRUE;
}
/* </settings checks> */
struct service_settings submission_service_settings = {
	.name = "submission",
	.protocol = "submission",
	.type = "",
	.executable = "submission",
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

	.unix_listeners = { { &submission_unix_listeners_buf,
			      sizeof(submission_unix_listeners[0]) } },
	.fifo_listeners = ARRAY_INIT,
	.inet_listeners = ARRAY_INIT
};
#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type(#name, name, struct submission_settings)
static const struct setting_define submission_setting_defines[] = {
	DEF(BOOL, verbose_proctitle),
	DEF(STR_VARS, rawlog_dir),

	DEF(STR, hostname),

	DEF(STR, login_greeting),
	DEF(STR, login_trusted_networks),

	DEF(STR, recipient_delimiter),

	DEF(SIZE, submission_max_mail_size),
	DEF(UINT, submission_max_recipients),
	DEF(STR, submission_client_workarounds),
	DEF(STR, submission_logout_format),

	DEF(STR, submission_backend_capabilities),

	DEF(STR, submission_relay_host),
	DEF(IN_PORT, submission_relay_port),
	DEF(BOOL, submission_relay_trusted),

	DEF(STR, submission_relay_user),
	DEF(STR, submission_relay_master_user),
	DEF(STR, submission_relay_password),

	DEF(ENUM, submission_relay_ssl),
	DEF(BOOL, submission_relay_ssl_verify),

	DEF(STR_VARS, submission_relay_rawlog_dir),
	DEF(TIME, submission_relay_max_idle_time),

	DEF(TIME_MSECS, submission_relay_connect_timeout),
	DEF(TIME_MSECS, submission_relay_command_timeout),

	DEF(STR, imap_urlauth_host),
	DEF(IN_PORT, imap_urlauth_port),

	SETTING_DEFINE_LIST_END
};
static const struct submission_settings submission_default_settings = {
	.verbose_proctitle = FALSE,
	.rawlog_dir = "",

	.hostname = "",

	.login_greeting = PACKAGE_NAME" ready.",
	.login_trusted_networks = "",

	.recipient_delimiter = "+",

	.submission_max_mail_size = 40*1024*1024,
	.submission_max_recipients = 0,
	.submission_client_workarounds = "",
	.submission_logout_format = "in=%i out=%o",

	.submission_backend_capabilities = NULL,

	.submission_relay_host = "",
	.submission_relay_port = 25,
	.submission_relay_trusted = FALSE,

	.submission_relay_user = "",
	.submission_relay_master_user = "",
	.submission_relay_password = "",

	.submission_relay_ssl = "no:smtps:starttls",
	.submission_relay_ssl_verify = TRUE,

	.submission_relay_rawlog_dir = "",
	.submission_relay_max_idle_time = 60*29,

	.submission_relay_connect_timeout = 30*1000,
	.submission_relay_command_timeout = 60*5*1000,

	.imap_urlauth_host = "",
	.imap_urlauth_port = 143,
};
static const struct setting_parser_info *submission_setting_dependencies[] = {
	&mail_user_setting_parser_info,
	NULL
};
const struct setting_parser_info submission_setting_parser_info = {
	.module_name = "submission",
	.defines = submission_setting_defines,
	.defaults = &submission_default_settings,

	.type_offset = SIZE_MAX,
	.struct_size = sizeof(struct submission_settings),

	.parent_offset = SIZE_MAX,

	.check_func = submission_settings_verify,
	.dependencies = submission_setting_dependencies
};
/* ../../src/submission-login/submission-login-settings.c */
/* <settings checks> */
static struct inet_listener_settings submission_login_inet_listeners_array[] = {
	{ .name = "submission", .address = "", .port = 587  },
	{ .name = "submissions", .address = "", .port = 465, .ssl = TRUE }
};
static struct inet_listener_settings *submission_login_inet_listeners[] = {
	&submission_login_inet_listeners_array[0]
};
static buffer_t submission_login_inet_listeners_buf = {
	{ { submission_login_inet_listeners,
	    sizeof(submission_login_inet_listeners) } }
};

/* </settings checks> */
/* <settings checks> */
struct submission_login_client_workaround_list {
	const char *name;
	enum submission_login_client_workarounds num;
};

/* These definitions need to be kept in sync with equivalent definitions present
   in src/submission/submission-settings.c. Workarounds that are not relevant
   to the submission-login service are defined as 0 here to prevent "Unknown
   workaround" errors below. */
static const struct submission_login_client_workaround_list
submission_login_client_workaround_list[] = {
	{ "whitespace-before-path", 0},
	{ "mailbox-for-path", 0 },
	{ "implicit-auth-external",
	  SUBMISSION_LOGIN_WORKAROUND_IMPLICIT_AUTH_EXTERNAL },
	{ "exotic-backend",
	  SUBMISSION_LOGIN_WORKAROUND_EXOTIC_BACKEND },
	{ NULL, 0 }
};

static int
submission_login_settings_parse_workarounds(
	struct submission_login_settings *set, const char **error_r)
{
	enum submission_login_client_workarounds client_workarounds = 0;
        const struct submission_login_client_workaround_list *list;
	const char *const *str;

        str = t_strsplit_spaces(set->submission_client_workarounds, " ,");
	for (; *str != NULL; str++) {
		list = submission_login_client_workaround_list;
		for (; list->name != NULL; list++) {
			if (strcasecmp(*str, list->name) == 0) {
				client_workarounds |= list->num;
				break;
			}
		}
		if (list->name == NULL) {
			*error_r = t_strdup_printf(
				"submission_client_workarounds: "
				"Unknown workaround: %s", *str);
			return -1;
		}
	}
	set->parsed_workarounds = client_workarounds;
	return 0;
}

static bool
submission_login_settings_check(void *_set, pool_t pool ATTR_UNUSED,
				const char **error_r)
{
	struct submission_login_settings *set = _set;

	if (submission_login_settings_parse_workarounds(set, error_r) < 0)
		return FALSE;

#ifndef CONFIG_BINARY
	if (*set->hostname == '\0')
		set->hostname = p_strdup(pool, my_hostdomain());
#endif
	return TRUE;
}
/* </settings checks> */
struct service_settings submission_login_service_settings = {
	.name = "submission-login",
	.protocol = "submission",
	.type = "login",
	.executable = "submission-login",
	.user = "$default_login_user",
	.group = "",
	.privileged_group = "",
	.extra_groups = "",
	.chroot = "login",

	.drop_priv_before_exec = FALSE,

	.process_min_avail = 0,
	.process_limit = 0,
	.client_limit = 0,
	.service_count = 1,
	.idle_kill = 0,
	.vsz_limit = UOFF_T_MAX,

	.unix_listeners = ARRAY_INIT,
	.fifo_listeners = ARRAY_INIT,
	.inet_listeners = { { &submission_login_inet_listeners_buf,
			      sizeof(submission_login_inet_listeners[0]) } }
};
#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type(#name, name, struct submission_login_settings)
static const struct setting_define submission_login_setting_defines[] = {
	DEF(STR, hostname),

	DEF(SIZE, submission_max_mail_size),
	DEF(STR, submission_client_workarounds),
	DEF(STR, submission_backend_capabilities),

	SETTING_DEFINE_LIST_END
};
static const struct submission_login_settings submission_login_default_settings = {
	.hostname = "",

	.submission_max_mail_size = 0,
	.submission_client_workarounds = "",
	.submission_backend_capabilities = NULL
};
static const struct setting_parser_info *submission_login_setting_dependencies[] = {
	&login_setting_parser_info,
	NULL
};
const struct setting_parser_info submission_login_setting_parser_info = {
	.module_name = "submission-login",
	.defines = submission_login_setting_defines,
	.defaults = &submission_login_default_settings,

	.type_offset = SIZE_MAX,
	.struct_size = sizeof(struct submission_login_settings),
	.parent_offset = SIZE_MAX,

	.check_func = submission_login_settings_check,
	.dependencies = submission_login_setting_dependencies
};
const struct setting_parser_info *submission_login_setting_roots[] = {
	&login_setting_parser_info,
	&submission_login_setting_parser_info,
	NULL
};
/* ../../src/stats/stats-settings.c */
extern const struct setting_parser_info stats_metric_setting_parser_info;
extern const struct setting_parser_info stats_exporter_setting_parser_info;
/* <settings checks> */
#include "event-filter.h"
#include <math.h>
/* </settings checks> */
/* <settings checks> */
static struct file_listener_settings stats_unix_listeners_array[] = {
	{ "stats-reader", 0600, "", "" },
	{ "stats-writer", 0660, "", "$default_internal_group" },
	{ "login/stats-writer", 0600, "$default_login_user", "" },
};
static struct file_listener_settings *stats_unix_listeners[] = {
	&stats_unix_listeners_array[0],
	&stats_unix_listeners_array[1],
	&stats_unix_listeners_array[2],
};
static buffer_t stats_unix_listeners_buf = {
	{ { stats_unix_listeners, sizeof(stats_unix_listeners) } }
};
/* </settings checks> */
/* <settings checks> */
static bool parse_format_args_set_time(struct stats_exporter_settings *set,
				       enum event_exporter_time_fmt fmt,
				       const char **error_r)
{
	if ((set->parsed_time_format != EVENT_EXPORTER_TIME_FMT_NATIVE) &&
	    (set->parsed_time_format != fmt)) {
		*error_r = t_strdup_printf("Exporter '%s' specifies multiple "
					   "time format args", set->name);
		return FALSE;
	}

	set->parsed_time_format = fmt;

	return TRUE;
}

static bool parse_format_args(struct stats_exporter_settings *set,
			      const char **error_r)
{
	const char *const *tmp;

	/* Defaults */
	set->parsed_time_format = EVENT_EXPORTER_TIME_FMT_NATIVE;

	tmp = t_strsplit_spaces(set->format_args, " ");

	/*
	 * If the config contains multiple types of the same type (e.g.,
	 * both time-rfc3339 and time-unix) we fail the config check.
	 *
	 * Note: At the moment, we have only time-* tokens.  In the future
	 * when we have other tokens, they should be parsed here.
	 */
	for (; *tmp != NULL; tmp++) {
		enum event_exporter_time_fmt fmt;

		if (strcmp(*tmp, "time-rfc3339") == 0) {
			fmt = EVENT_EXPORTER_TIME_FMT_RFC3339;
		} else if (strcmp(*tmp, "time-unix") == 0) {
			fmt = EVENT_EXPORTER_TIME_FMT_UNIX;
		} else {
			*error_r = t_strdup_printf("Unknown exporter format "
						   "arg: %s", *tmp);
			return FALSE;
		}

		if (!parse_format_args_set_time(set, fmt, error_r))
			return FALSE;
	}

	return TRUE;
}

static bool stats_exporter_settings_check(void *_set, pool_t pool ATTR_UNUSED,
					  const char **error_r)
{
	struct stats_exporter_settings *set = _set;
	bool time_fmt_required;

	if (set->name[0] == '\0') {
		*error_r = "Exporter name can't be empty";
		return FALSE;
	}

	/* TODO: The following should be plugable.
	 *
	 * Note: Make sure to mirror any changes to the below code in
	 * stats_exporters_add_set().
	 */
	if (set->format[0] == '\0') {
		*error_r = "Exporter format name can't be empty";
		return FALSE;
	} else if (strcmp(set->format, "none") == 0) {
		time_fmt_required = FALSE;
	} else if (strcmp(set->format, "json") == 0) {
		time_fmt_required = TRUE;
	} else if (strcmp(set->format, "tab-text") == 0) {
		time_fmt_required = TRUE;
	} else {
		*error_r = t_strdup_printf("Unknown exporter format '%s'",
					   set->format);
		return FALSE;
	}

	/* TODO: The following should be plugable.
	 *
	 * Note: Make sure to mirror any changes to the below code in
	 * stats_exporters_add_set().
	 */
	if (set->transport[0] == '\0') {
		*error_r = "Exporter transport name can't be empty";
		return FALSE;
	} else if (strcmp(set->transport, "drop") == 0 ||
		   strcmp(set->transport, "http-post") == 0 ||
		   strcmp(set->transport, "log") == 0) {
		/* no-op */
	} else {
		*error_r = t_strdup_printf("Unknown transport type '%s'",
					   set->transport);
		return FALSE;
	}

	if (!parse_format_args(set, error_r))
		return FALSE;

	/* Some formats don't have a native way of serializing time stamps */
	if (time_fmt_required &&
	    set->parsed_time_format == EVENT_EXPORTER_TIME_FMT_NATIVE) {
		*error_r = t_strdup_printf("%s exporter format requires a "
					   "time-* argument", set->format);
		return FALSE;
	}

	return TRUE;
}

static bool parse_metric_group_by_common(const char *func,
					 const char *const *params,
					 intmax_t *min_r,
					 intmax_t *max_r,
					 intmax_t *other_r,
					 const char **error_r)
{
	intmax_t min, max, other;

	if ((str_array_length(params) != 3) ||
	    (str_to_intmax(params[0], &min) < 0) ||
	    (str_to_intmax(params[1], &max) < 0) ||
	    (str_to_intmax(params[2], &other) < 0)) {
		*error_r = t_strdup_printf("group_by '%s' aggregate function takes "
					   "3 int args", func);
		return FALSE;
	}

	if ((min < 0) || (max < 0) || (other < 0)) {
		*error_r = t_strdup_printf("group_by '%s' aggregate function "
					   "arguments must be >= 0", func);
		return FALSE;
	}

	if (min >= max) {
		*error_r = t_strdup_printf("group_by '%s' aggregate function "
					   "min must be < max (%ju must be < %ju)",
					   func, min, max);
		return FALSE;
	}

	*min_r = min;
	*max_r = max;
	*other_r = other;

	return TRUE;
}

static bool parse_metric_group_by_exp(pool_t pool, struct stats_metric_settings_group_by *group_by,
				      const char *const *params, const char **error_r)
{
	intmax_t min, max, base;

	if (!parse_metric_group_by_common("exponential", params, &min, &max, &base, error_r))
		return FALSE;

	if ((base != 2) && (base != 10)) {
		*error_r = t_strdup_printf("group_by 'exponential' aggregate function "
					   "base must be one of: 2, 10 (base=%ju)",
					   base);
		return FALSE;
	}

	group_by->func = STATS_METRIC_GROUPBY_QUANTIZED;

	/*
	 * Allocate the bucket range array and fill it in
	 *
	 * The first bucket is special - it contains everything less than or
	 * equal to 'base^min'.  The last bucket is also special - it
	 * contains everything greater than 'base^max'.
	 *
	 * The second bucket begins at 'base^min + 1', the third bucket
	 * begins at 'base^(min + 1) + 1', and so on.
	 */
	group_by->num_ranges = max - min + 2;
	group_by->ranges = p_new(pool, struct stats_metric_settings_bucket_range,
				 group_by->num_ranges);

	/* set up min & max buckets */
	group_by->ranges[0].min = INTMAX_MIN;
	group_by->ranges[0].max = pow(base, min);
	group_by->ranges[group_by->num_ranges - 1].min = pow(base, max);
	group_by->ranges[group_by->num_ranges - 1].max = INTMAX_MAX;

	/* remaining buckets */
	for (unsigned int i = 1; i < group_by->num_ranges - 1; i++) {
		group_by->ranges[i].min = pow(base, min + (i - 1));
		group_by->ranges[i].max = pow(base, min + i);
	}

	return TRUE;
}

static bool parse_metric_group_by_lin(pool_t pool, struct stats_metric_settings_group_by *group_by,
				      const char *const *params, const char **error_r)
{
	intmax_t min, max, step;

	if (!parse_metric_group_by_common("linear", params, &min, &max, &step, error_r))
		return FALSE;

	if ((min + step) > max) {
		*error_r = t_strdup_printf("group_by 'linear' aggregate function "
					   "min+step must be <= max (%ju must be <= %ju)",
					   min + step, max);
		return FALSE;
	}

	group_by->func = STATS_METRIC_GROUPBY_QUANTIZED;

	/*
	 * Allocate the bucket range array and fill it in
	 *
	 * The first bucket is special - it contains everything less than or
	 * equal to 'min'.  The last bucket is also special - it contains
	 * everything greater than 'max'.
	 *
	 * The second bucket begins at 'min + 1', the third bucket begins at
	 * 'min + 1 * step + 1', the fourth at 'min + 2 * step + 1', and so on.
	 */
	group_by->num_ranges = (max - min) / step + 2;
	group_by->ranges = p_new(pool, struct stats_metric_settings_bucket_range,
				 group_by->num_ranges);

	/* set up min & max buckets */
	group_by->ranges[0].min = INTMAX_MIN;
	group_by->ranges[0].max = min;
	group_by->ranges[group_by->num_ranges - 1].min = max;
	group_by->ranges[group_by->num_ranges - 1].max = INTMAX_MAX;

	/* remaining buckets */
	for (unsigned int i = 1; i < group_by->num_ranges - 1; i++) {
		group_by->ranges[i].min = min + (i - 1) * step;
		group_by->ranges[i].max = min + i * step;
	}

	return TRUE;
}

static bool parse_metric_group_by(struct stats_metric_settings *set,
				  pool_t pool, const char **error_r)
{
	const char *const *tmp = t_strsplit_spaces(set->group_by, " ");

	if (tmp[0] == NULL)
		return TRUE;

	p_array_init(&set->parsed_group_by, pool, str_array_length(tmp));

	/* For each group_by field */
	for (; *tmp != NULL; tmp++) {
		struct stats_metric_settings_group_by group_by;
		const char *const *params;

		i_zero(&group_by);

		/* <field name>:<aggregation func>... */
		params = t_strsplit(*tmp, ":");

		if (params[1] == NULL) {
			/* <field name> - alias for <field>:discrete */
			group_by.func = STATS_METRIC_GROUPBY_DISCRETE;
		} else if (strcmp(params[1], "discrete") == 0) {
			/* <field>:discrete */
			group_by.func = STATS_METRIC_GROUPBY_DISCRETE;
			if (params[2] != NULL) {
				*error_r = "group_by 'discrete' aggregate function "
					   "does not take any args";
				return FALSE;
			}
		} else if (strcmp(params[1], "exponential") == 0) {
			/* <field>:exponential:<min mag>:<max mag>:<base> */
			if (!parse_metric_group_by_exp(pool, &group_by, &params[2], error_r))
				return FALSE;
		} else if (strcmp(params[1], "linear") == 0) {
			/* <field>:linear:<min val>:<max val>:<step> */
			if (!parse_metric_group_by_lin(pool, &group_by, &params[2], error_r))
				return FALSE;
		} else {
			*error_r = t_strdup_printf("unknown aggregation function "
						   "'%s' on field '%s'", params[1], params[0]);
			return FALSE;
		}

		group_by.field = p_strdup(pool, params[0]);

		array_push_back(&set->parsed_group_by, &group_by);
	}

	return TRUE;
}

static bool stats_metric_settings_check(void *_set, pool_t pool, const char **error_r)
{
	struct stats_metric_settings *set = _set;

	if (set->metric_name[0] == '\0') {
		*error_r = "Metric name can't be empty";
		return FALSE;
	}

	if (set->filter[0] == '\0') {
		*error_r = t_strdup_printf("metric %s { filter } is empty - "
					   "will not match anything", set->metric_name);
		return FALSE;
	}

	set->parsed_filter = event_filter_create_fragment(pool);
	if (event_filter_parse(set->filter, set->parsed_filter, error_r) < 0)
		return FALSE;

	if (!parse_metric_group_by(set, pool, error_r))
		return FALSE;

	return TRUE;
}

static bool stats_settings_check(void *_set, pool_t pool ATTR_UNUSED,
				 const char **error_r)
{
	struct stats_settings *set = _set;
	struct stats_exporter_settings *exporter;
	struct stats_metric_settings *metric;

	if (!array_is_created(&set->metrics) || !array_is_created(&set->exporters))
		return TRUE;

	/* check that all metrics refer to exporters that exist */
	array_foreach_elem(&set->metrics, metric) {
		bool found = FALSE;

		if (metric->exporter[0] == '\0')
			continue; /* metric not exported */

		array_foreach_elem(&set->exporters, exporter) {
			if (strcmp(metric->exporter, exporter->name) == 0) {
				found = TRUE;
				break;
			}
		}

		if (!found) {
			*error_r = t_strdup_printf("metric %s refers to "
						   "non-existent exporter '%s'",
						   metric->metric_name,
						   metric->exporter);
			return FALSE;
		}
	}

	return TRUE;
}
/* </settings checks> */
struct service_settings stats_service_settings = {
	.name = "stats",
	.protocol = "",
	.type = "",
	.executable = "stats",
	.user = "$default_internal_user",
	.group = "",
	.privileged_group = "",
	.extra_groups = "",
	.chroot = "",

	.drop_priv_before_exec = FALSE,

	.process_min_avail = 0,
	.process_limit = 1,
	.client_limit = 0,
	.service_count = 0,
	.idle_kill = UINT_MAX,
	.vsz_limit = UOFF_T_MAX,

	.unix_listeners = { { &stats_unix_listeners_buf,
			      sizeof(stats_unix_listeners[0]) } },
	.inet_listeners = ARRAY_INIT,
};
#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type(#name, name, struct stats_exporter_settings)
static const struct setting_define stats_exporter_setting_defines[] = {
	DEF(STR, name),
	DEF(STR, transport),
	DEF(STR, transport_args),
	DEF(TIME_MSECS, transport_timeout),
	DEF(STR, format),
	DEF(STR, format_args),
	SETTING_DEFINE_LIST_END
};
static const struct stats_exporter_settings stats_exporter_default_settings = {
	.name = "",
	.transport = "",
	.transport_args = "",
	.transport_timeout = 250, /* ms */
	.format = "",
	.format_args = "",
};
const struct setting_parser_info stats_exporter_setting_parser_info = {
	.defines = stats_exporter_setting_defines,
	.defaults = &stats_exporter_default_settings,

	.type_offset = offsetof(struct stats_exporter_settings, name),
	.struct_size = sizeof(struct stats_exporter_settings),

	.parent_offset = SIZE_MAX,
	.check_func = stats_exporter_settings_check,
};
#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type(#name, name, struct stats_metric_settings)
static const struct setting_define stats_metric_setting_defines[] = {
	DEF(STR, metric_name),
	DEF(STR, fields),
	DEF(STR, group_by),
	DEF(STR, filter),
	DEF(STR, exporter),
	DEF(STR, exporter_include),
	DEF(STR, description),
	SETTING_DEFINE_LIST_END
};
static const struct stats_metric_settings stats_metric_default_settings = {
	.metric_name = "",
	.fields = "",
	.filter = "",
	.exporter = "",
	.group_by = "",
	.exporter_include = STATS_METRIC_SETTINGS_DEFAULT_EXPORTER_INCLUDE,
	.description = "",
};
const struct setting_parser_info stats_metric_setting_parser_info = {
	.defines = stats_metric_setting_defines,
	.defaults = &stats_metric_default_settings,

	.type_offset = offsetof(struct stats_metric_settings, metric_name),
	.struct_size = sizeof(struct stats_metric_settings),

	.parent_offset = SIZE_MAX,
	.check_func = stats_metric_settings_check,
};
#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type(#name, name, struct stats_settings)
#undef DEFLIST_UNIQUE
#define DEFLIST_UNIQUE(field, name, defines) \
	{ .type = SET_DEFLIST_UNIQUE, .key = name, \
	  .offset = offsetof(struct stats_settings, field), \
	  .list_info = defines }
static const struct setting_define stats_setting_defines[] = {
	DEF(STR, stats_http_rawlog_dir),

	DEFLIST_UNIQUE(metrics, "metric", &stats_metric_setting_parser_info),
	DEFLIST_UNIQUE(exporters, "event_exporter", &stats_exporter_setting_parser_info),
	SETTING_DEFINE_LIST_END
};
const struct stats_settings stats_default_settings = {
	.stats_http_rawlog_dir = "",

	.metrics = ARRAY_INIT,
	.exporters = ARRAY_INIT,
};
const struct setting_parser_info stats_setting_parser_info = {
	.module_name = "stats",
	.defines = stats_setting_defines,
	.defaults = &stats_default_settings,

	.type_offset = SIZE_MAX,
	.struct_size = sizeof(struct stats_settings),

	.parent_offset = SIZE_MAX,
	.check_func = stats_settings_check,
};
/* ../../src/replication/replicator/replicator-settings.c */
/* <settings checks> */
static struct file_listener_settings replicator_unix_listeners_array[] = {
	{ "replicator", 0600, "$default_internal_user", "" },
	{ "replicator-doveadm", 0, "$default_internal_user", "" }
};
static struct file_listener_settings *replicator_unix_listeners[] = {
	&replicator_unix_listeners_array[0],
	&replicator_unix_listeners_array[1]
};
static buffer_t replicator_unix_listeners_buf = {
	{ { replicator_unix_listeners, sizeof(replicator_unix_listeners) } }
};
/* </settings checks> */
struct service_settings replicator_service_settings = {
	.name = "replicator",
	.protocol = "",
	.type = "",
	.executable = "replicator",
	.user = "",
	.group = "",
	.privileged_group = "",
	.extra_groups = "",
	.chroot = "",

	.drop_priv_before_exec = FALSE,

	.process_min_avail = 0,
	.process_limit = 1,
	.client_limit = 0,
	.service_count = 0,
	.idle_kill = UINT_MAX,
	.vsz_limit = UOFF_T_MAX,

	.unix_listeners = { { &replicator_unix_listeners_buf,
			      sizeof(replicator_unix_listeners[0]) } },
	.fifo_listeners = ARRAY_INIT,
	.inet_listeners = ARRAY_INIT,

	.process_limit_1 = TRUE
};
#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type(#name, name, struct replicator_settings)
static const struct setting_define replicator_setting_defines[] = {
	DEF(STR, auth_socket_path),
	DEF(STR, doveadm_socket_path),
	DEF(STR, replication_dsync_parameters),

	DEF(TIME, replication_full_sync_interval),
	DEF(UINT, replication_max_conns),

	SETTING_DEFINE_LIST_END
};
const struct replicator_settings replicator_default_settings = {
	.auth_socket_path = "auth-userdb",
	.doveadm_socket_path = "doveadm-server",
	.replication_dsync_parameters = "-d -N -l 30 -U",

	.replication_full_sync_interval = 60*60*24,
	.replication_max_conns = 10
};
const struct setting_parser_info replicator_setting_parser_info = {
	.module_name = "replicator",
	.defines = replicator_setting_defines,
	.defaults = &replicator_default_settings,

	.type_offset = SIZE_MAX,
	.struct_size = sizeof(struct replicator_settings),

	.parent_offset = SIZE_MAX
};
/* ../../src/replication/aggregator/aggregator-settings.c */
/* <settings checks> */
static struct file_listener_settings aggregator_unix_listeners_array[] = {
	{ "replication-notify", 0600, "", "" }
};
static struct file_listener_settings *aggregator_unix_listeners[] = {
	&aggregator_unix_listeners_array[0]
};
static buffer_t aggregator_unix_listeners_buf = {
	{ { aggregator_unix_listeners, sizeof(aggregator_unix_listeners) } }
};

static struct file_listener_settings aggregator_fifo_listeners_array[] = {
	{ "replication-notify-fifo", 0600, "", "" }
};
static struct file_listener_settings *aggregator_fifo_listeners[] = {
	&aggregator_fifo_listeners_array[0]
};
static buffer_t aggregator_fifo_listeners_buf = {
	{ { aggregator_fifo_listeners, sizeof(aggregator_fifo_listeners) } }
};
/* </settings checks> */
struct service_settings aggregator_service_settings = {
	.name = "aggregator",
	.protocol = "",
	.type = "",
	.executable = "aggregator",
	.user = "$default_internal_user",
	.group = "",
	.privileged_group = "",
	.extra_groups = "",
	.chroot = ".",

	.drop_priv_before_exec = FALSE,

	.process_min_avail = 0,
	.process_limit = 0,
	.client_limit = 0,
	.service_count = 0,
	.idle_kill = 0,
	.vsz_limit = UOFF_T_MAX,

	.unix_listeners = { { &aggregator_unix_listeners_buf,
			      sizeof(aggregator_unix_listeners[0]) } },
	.fifo_listeners = { { &aggregator_fifo_listeners_buf,
			      sizeof(aggregator_fifo_listeners[0]) } },
	.inet_listeners = ARRAY_INIT
};
#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type(#name, name, struct aggregator_settings)
static const struct setting_define aggregator_setting_defines[] = {
	DEF(STR, replicator_host),
	DEF(IN_PORT, replicator_port),

	SETTING_DEFINE_LIST_END
};
const struct aggregator_settings aggregator_default_settings = {
	.replicator_host = "replicator",
	.replicator_port = 0
};
const struct setting_parser_info aggregator_setting_parser_info = {
	.module_name = "aggregator",
	.defines = aggregator_setting_defines,
	.defaults = &aggregator_default_settings,

	.type_offset = SIZE_MAX,
	.struct_size = sizeof(struct aggregator_settings),

	.parent_offset = SIZE_MAX
};
/* ../../src/pop3/pop3-settings.c */
/* <settings checks> */
static struct file_listener_settings pop3_unix_listeners_array[] = {
	{ "login/pop3", 0666, "", "" }
};
static struct file_listener_settings *pop3_unix_listeners[] = {
	&pop3_unix_listeners_array[0]
};
static buffer_t pop3_unix_listeners_buf = {
	{ { pop3_unix_listeners, sizeof(pop3_unix_listeners) } }
};
/* </settings checks> */
/* <settings checks> */
struct pop3_client_workaround_list {
	const char *name;
	enum pop3_client_workarounds num;
};

static const struct pop3_client_workaround_list pop3_client_workaround_list[] = {
	{ "outlook-no-nuls", WORKAROUND_OUTLOOK_NO_NULS },
	{ "oe-ns-eoh", WORKAROUND_OE_NS_EOH },
	{ NULL, 0 }
};

static int
pop3_settings_parse_workarounds(struct pop3_settings *set,
				const char **error_r)
{
        enum pop3_client_workarounds client_workarounds = 0;
	const struct pop3_client_workaround_list *list;
	const char *const *str;

        str = t_strsplit_spaces(set->pop3_client_workarounds, " ,");
	for (; *str != NULL; str++) {
		list = pop3_client_workaround_list;
		for (; list->name != NULL; list++) {
			if (strcasecmp(*str, list->name) == 0) {
				client_workarounds |= list->num;
				break;
			}
		}
		if (list->name == NULL) {
			*error_r = t_strdup_printf("pop3_client_workarounds: "
				"Unknown workaround: %s", *str);
			return -1;
		}
	}
	set->parsed_workarounds = client_workarounds;
	return 0;
}

static bool
pop3_settings_verify(void *_set, pool_t pool ATTR_UNUSED, const char **error_r)
{
	struct pop3_settings *set = _set;

	if (pop3_settings_parse_workarounds(set, error_r) < 0)
		return FALSE;
	if (strcmp(set->pop3_delete_type, "default") == 0) {
		if (set->pop3_deleted_flag[0] == '\0')
			set->parsed_delete_type = POP3_DELETE_TYPE_EXPUNGE;
		else
			set->parsed_delete_type = POP3_DELETE_TYPE_FLAG;
	} else if (strcmp(set->pop3_delete_type, "expunge") == 0) {
		set->parsed_delete_type = POP3_DELETE_TYPE_EXPUNGE;
	} else if (strcmp(set->pop3_delete_type, "flag") == 0) {
		if (set->pop3_deleted_flag[0] == '\0') {
			*error_r = "pop3_delete_type=flag, but pop3_deleted_flag not set";
			return FALSE;
		}
		set->parsed_delete_type = POP3_DELETE_TYPE_FLAG;
	} else {
		*error_r = t_strdup_printf("pop3_delete_type: Unknown value '%s'",
					   set->pop3_delete_type);
		return FALSE;
	}
	return TRUE;
}
/* </settings checks> */
struct service_settings pop3_service_settings = {
	.name = "pop3",
	.protocol = "pop3",
	.type = "",
	.executable = "pop3",
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

	.unix_listeners = { { &pop3_unix_listeners_buf,
			      sizeof(pop3_unix_listeners[0]) } },
	.fifo_listeners = ARRAY_INIT,
	.inet_listeners = ARRAY_INIT
};
#undef DEF
#undef DEFLIST
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type(#name, name, struct pop3_settings)
#define DEFLIST(field, name, defines) \
	{ .type = SET_DEFLIST, .key = name, \
	  .offset = offsetof(struct pop3_settings, field), \
	  .list_info = defines }
static const struct setting_define pop3_setting_defines[] = {
	DEF(BOOL, verbose_proctitle),
	DEF(STR_VARS, rawlog_dir),

	DEF(BOOL, pop3_no_flag_updates),
	DEF(BOOL, pop3_enable_last),
	DEF(BOOL, pop3_reuse_xuidl),
	DEF(BOOL, pop3_save_uidl),
	DEF(BOOL, pop3_lock_session),
	DEF(BOOL, pop3_fast_size_lookups),
	DEF(STR, pop3_client_workarounds),
	DEF(STR, pop3_logout_format),
	DEF(ENUM, pop3_uidl_duplicates),
	DEF(STR, pop3_deleted_flag),
	DEF(ENUM, pop3_delete_type),

	SETTING_DEFINE_LIST_END
};
static const struct pop3_settings pop3_default_settings = {
	.verbose_proctitle = FALSE,
	.rawlog_dir = "",

	.pop3_no_flag_updates = FALSE,
	.pop3_enable_last = FALSE,
	.pop3_reuse_xuidl = FALSE,
	.pop3_save_uidl = FALSE,
	.pop3_lock_session = FALSE,
	.pop3_fast_size_lookups = FALSE,
	.pop3_client_workarounds = "",
	.pop3_logout_format = "top=%t/%p, retr=%r/%b, del=%d/%m, size=%s",
	.pop3_uidl_duplicates = "allow:rename",
	.pop3_deleted_flag = "",
	.pop3_delete_type = "default:expunge:flag"
};
static const struct setting_parser_info *pop3_setting_dependencies[] = {
	&mail_user_setting_parser_info,
	NULL
};
const struct setting_parser_info pop3_setting_parser_info = {
	.module_name = "pop3",
	.defines = pop3_setting_defines,
	.defaults = &pop3_default_settings,

	.type_offset = SIZE_MAX,
	.struct_size = sizeof(struct pop3_settings),

	.parent_offset = SIZE_MAX,

	.check_func = pop3_settings_verify,
	.dependencies = pop3_setting_dependencies
};
/* ../../src/pop3-login/pop3-login-settings.c */
/* <settings checks> */
static struct inet_listener_settings pop3_login_inet_listeners_array[] = {
	{ .name = "pop3", .address = "", .port = 110 },
	{ .name = "pop3s", .address = "", .port = 995, .ssl = TRUE }
};
static struct inet_listener_settings *pop3_login_inet_listeners[] = {
	&pop3_login_inet_listeners_array[0],
	&pop3_login_inet_listeners_array[1]
};
static buffer_t pop3_login_inet_listeners_buf = {
	{ { pop3_login_inet_listeners, sizeof(pop3_login_inet_listeners) } }
};

/* </settings checks> */
struct service_settings pop3_login_service_settings = {
	.name = "pop3-login",
	.protocol = "pop3",
	.type = "login",
	.executable = "pop3-login",
	.user = "$default_login_user",
	.group = "",
	.privileged_group = "",
	.extra_groups = "",
	.chroot = "login",

	.drop_priv_before_exec = FALSE,

	.process_min_avail = 0,
	.process_limit = 0,
	.client_limit = 0,
	.service_count = 1,
	.idle_kill = 0,
	.vsz_limit = UOFF_T_MAX,

	.unix_listeners = ARRAY_INIT,
	.fifo_listeners = ARRAY_INIT,
	.inet_listeners = { { &pop3_login_inet_listeners_buf,
			      sizeof(pop3_login_inet_listeners[0]) } }
};
static const struct setting_define pop3_login_setting_defines[] = {
	SETTING_DEFINE_LIST_END
};
static const struct setting_parser_info *pop3_login_setting_dependencies[] = {
	&login_setting_parser_info,
	NULL
};
const struct setting_parser_info pop3_login_setting_parser_info = {
	.module_name = "pop3-login",
	.defines = pop3_login_setting_defines,

	.type_offset = SIZE_MAX,
	.parent_offset = SIZE_MAX,

	.dependencies = pop3_login_setting_dependencies
};
const struct setting_parser_info *pop3_login_setting_roots[] = {
	&login_setting_parser_info,
	&pop3_login_setting_parser_info,
	NULL
};
/* ../../src/plugins/quota/quota-status-settings.c */
#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type(#name, name, struct quota_status_settings)
static const struct setting_define quota_status_setting_defines[] = {
	DEF(STR, recipient_delimiter),

	SETTING_DEFINE_LIST_END
};
static const struct quota_status_settings quota_status_default_settings = {
	.recipient_delimiter = "+",
};
static const struct setting_parser_info *quota_status_setting_dependencies[] = {
	NULL
};
const struct setting_parser_info quota_status_setting_parser_info = {
	.module_name = "mail",
	.defines = quota_status_setting_defines,
	.defaults = &quota_status_default_settings,

	.type_offset = SIZE_MAX,
	.struct_size = sizeof(struct quota_status_settings),

	.parent_offset = SIZE_MAX,
	.dependencies = quota_status_setting_dependencies
};
/* ../../src/plugins/mail-crypt/fs-crypt-settings.c */
static const struct setting_define fs_crypt_setting_defines[] = {
	{ .type = SET_STRLIST, .key = "plugin",
	  .offset = offsetof(struct fs_crypt_settings, plugin_envs) },

	SETTING_DEFINE_LIST_END
};
const struct fs_crypt_settings fs_crypt_default_settings = {
	.plugin_envs = ARRAY_INIT
};
static const struct setting_parser_info *fs_crypt_setting_dependencies[] = {
	NULL
};
const struct setting_parser_info fs_crypt_setting_parser_info = {
	.module_name = "fs-crypt",
	.defines = fs_crypt_setting_defines,
	.defaults = &fs_crypt_default_settings,

	.type_offset = SIZE_MAX,
	.struct_size = sizeof(struct fs_crypt_settings),

	.parent_offset = SIZE_MAX,
	.dependencies = fs_crypt_setting_dependencies
};
/* ../../src/old-stats/stats-settings.c */
/* <settings checks> */
static struct file_listener_settings old_stats_unix_listeners_array[] = {
	{ "old-stats", 0600, "", "" }
};
static struct file_listener_settings *old_stats_unix_listeners[] = {
	&old_stats_unix_listeners_array[0]
};
static buffer_t old_stats_unix_listeners_buf = {
	{ { old_stats_unix_listeners, sizeof(old_stats_unix_listeners) } }
};
static struct file_listener_settings old_stats_fifo_listeners_array[] = {
	{ "old-stats-mail", 0600, "", "" },
	{ "old-stats-user", 0600, "", "" }
};
static struct file_listener_settings *old_stats_fifo_listeners[] = {
	&old_stats_fifo_listeners_array[0],
	&old_stats_fifo_listeners_array[1]
};
static buffer_t old_stats_fifo_listeners_buf = {
	{ { old_stats_fifo_listeners, sizeof(old_stats_fifo_listeners) } }
};
/* </settings checks> */
struct service_settings old_stats_service_settings = {
	.name = "old-stats",
	.protocol = "",
	.type = "",
	.executable = "old-stats",
	.user = "$default_internal_user",
	.group = "",
	.privileged_group = "",
	.extra_groups = "",
	.chroot = "empty",

	.drop_priv_before_exec = FALSE,

	.process_min_avail = 0,
	.process_limit = 1,
	.client_limit = 0,
	.service_count = 0,
	.idle_kill = UINT_MAX,
	.vsz_limit = UOFF_T_MAX,

	.unix_listeners = { { &old_stats_unix_listeners_buf,
			      sizeof(old_stats_unix_listeners[0]) } },
	.fifo_listeners = { { &old_stats_fifo_listeners_buf,
			      sizeof(old_stats_fifo_listeners[0]) } },
	.inet_listeners = ARRAY_INIT,

	.process_limit_1 = TRUE
};
#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type("old_stats_"#name, name, struct old_stats_settings)
static const struct setting_define old_stats_setting_defines[] = {
	DEF(SIZE, memory_limit),
	DEF(TIME, command_min_time),
	DEF(TIME, session_min_time),
	DEF(TIME, user_min_time),
	DEF(TIME, domain_min_time),
	DEF(TIME, ip_min_time),
	DEF(STR, carbon_server),
	DEF(TIME, carbon_interval),
	DEF(STR, carbon_name),
	SETTING_DEFINE_LIST_END
};
const struct old_stats_settings old_stats_default_settings = {
	.memory_limit = 1024*1024*16,

	.command_min_time = 60,
	.session_min_time = 60*15,
	.user_min_time = 60*60,
	.domain_min_time = 60*60*12,
	.ip_min_time = 60*60*12,

	.carbon_interval = 30,
	.carbon_server = "",
	.carbon_name = ""
};
const struct setting_parser_info old_stats_setting_parser_info = {
	.module_name = "stats",
	.defines = old_stats_setting_defines,
	.defaults = &old_stats_default_settings,

	.type_offset = SIZE_MAX,
	.struct_size = sizeof(struct old_stats_settings),

	.parent_offset = SIZE_MAX
};
/* ../../src/master/master-settings.c */
extern const struct setting_parser_info service_setting_parser_info;
extern const struct setting_parser_info service_setting_parser_info;
/* <settings checks> */
static void
expand_user(const char **user, enum service_user_default *default_r,
	    const struct master_settings *set)
{
	/* $variable expansion is typically done by doveconf, but these
	   variables can come from built-in settings, so we need to expand
	   them here */
	if (strcmp(*user, "$default_internal_user") == 0) {
		*user = set->default_internal_user;
		*default_r = SERVICE_USER_DEFAULT_INTERNAL;
	} else if (strcmp(*user, "$default_login_user") == 0) {
		*user = set->default_login_user;
		*default_r = SERVICE_USER_DEFAULT_LOGIN;
	} else {
		*default_r = SERVICE_USER_DEFAULT_NONE;
	}
}

static void
expand_group(const char **group, const struct master_settings *set)
{
	/* $variable expansion is typically done by doveconf, but these
	   variables can come from built-in settings, so we need to expand
	   them here */
	if (strcmp(*group, "$default_internal_group") == 0)
		*group = set->default_internal_group;
}

static bool
fix_file_listener_paths(ARRAY_TYPE(file_listener_settings) *l,
			pool_t pool, const struct master_settings *master_set,
			ARRAY_TYPE(const_string) *all_listeners,
			const char **error_r)
{
	struct file_listener_settings *set;
	size_t base_dir_len = strlen(master_set->base_dir);
	enum service_user_default user_default;

	if (!array_is_created(l))
		return TRUE;

	array_foreach_elem(l, set) {
		if (set->path[0] == '\0') {
			*error_r = "path must not be empty";
			return FALSE;
		}

		expand_user(&set->user, &user_default, master_set);
		expand_group(&set->group, master_set);
		if (*set->path != '/') {
			set->path = p_strconcat(pool, master_set->base_dir, "/",
						set->path, NULL);
		} else if (strncmp(set->path, master_set->base_dir,
				   base_dir_len) == 0 &&
			   set->path[base_dir_len] == '/') {
			i_warning("You should remove base_dir prefix from "
				  "unix_listener: %s", set->path);
		}
		if (set->mode != 0)
			array_push_back(all_listeners, &set->path);
	}
	return TRUE;
}

static void add_inet_listeners(ARRAY_TYPE(inet_listener_settings) *l,
			       ARRAY_TYPE(const_string) *all_listeners)
{
	struct inet_listener_settings *set;
	const char *str;

	if (!array_is_created(l))
		return;

	array_foreach_elem(l, set) {
		if (set->port != 0) {
			str = t_strdup_printf("%u:%s", set->port, set->address);
			array_push_back(all_listeners, &str);
		}
	}
}

static bool master_settings_parse_type(struct service_settings *set,
				       const char **error_r)
{
	if (*set->type == '\0')
		set->parsed_type = SERVICE_TYPE_UNKNOWN;
	else if (strcmp(set->type, "log") == 0)
		set->parsed_type = SERVICE_TYPE_LOG;
	else if (strcmp(set->type, "config") == 0)
		set->parsed_type = SERVICE_TYPE_CONFIG;
	else if (strcmp(set->type, "anvil") == 0)
		set->parsed_type = SERVICE_TYPE_ANVIL;
	else if (strcmp(set->type, "login") == 0)
		set->parsed_type = SERVICE_TYPE_LOGIN;
	else if (strcmp(set->type, "startup") == 0)
		set->parsed_type = SERVICE_TYPE_STARTUP;
	else if (strcmp(set->type, "worker") == 0)
		set->parsed_type = SERVICE_TYPE_WORKER;
	else {
		*error_r = t_strconcat("Unknown service type: ",
				       set->type, NULL);
		return FALSE;
	}
	return TRUE;
}

static void service_set_login_dump_core(struct service_settings *set)
{
	const char *p;

	if (set->parsed_type != SERVICE_TYPE_LOGIN)
		return;

	p = strstr(set->executable, " -D");
	if (p != NULL && (p[3] == '\0' || p[3] == ' '))
		set->login_dump_core = TRUE;
}

static bool
services_have_protocol(struct master_settings *set, const char *name)
{
	struct service_settings *service;

	array_foreach_elem(&set->services, service) {
		if (strcmp(service->protocol, name) == 0)
			return TRUE;
	}
	return FALSE;
}

#ifdef CONFIG_BINARY
static const struct service_settings *
master_default_settings_get_service(const char *name)
{
	extern struct master_settings master_default_settings;
	struct service_settings *set;

	array_foreach_elem(&master_default_settings.services, set) {
		if (strcmp(set->name, name) == 0)
			return set;
	}
	return NULL;
}
#endif

static unsigned int
service_get_client_limit(struct master_settings *set, const char *name)
{
	struct service_settings *service;

	array_foreach_elem(&set->services, service) {
		if (strcmp(service->name, name) == 0) {
			if (service->client_limit != 0)
				return service->client_limit;
			else
				return set->default_client_limit;
		}
	}
	return set->default_client_limit;
}

static bool
master_settings_verify(void *_set, pool_t pool, const char **error_r)
{
	static bool warned_auth = FALSE, warned_anvil = FALSE;
	struct master_settings *set = _set;
	struct service_settings *const *services;
	const char *const *strings;
	ARRAY_TYPE(const_string) all_listeners;
	struct passwd pw;
	unsigned int i, j, count, client_limit, process_limit;
	unsigned int max_auth_client_processes, max_anvil_client_processes;
	string_t *max_auth_client_processes_reason = t_str_new(64);
	string_t *max_anvil_client_processes_reason = t_str_new(64);
	size_t len;
#ifdef CONFIG_BINARY
	const struct service_settings *default_service;
#else
	rlim_t fd_limit;
	const char *max_client_limit_source = "default_client_limit";
	unsigned int max_client_limit = set->default_client_limit;
#endif

	if (*set->listen == '\0') {
		*error_r = "listen can't be set empty";
		return FALSE;
	}

	len = strlen(set->base_dir);
	if (len > 0 && set->base_dir[len-1] == '/') {
		/* drop trailing '/' */
		set->base_dir = p_strndup(pool, set->base_dir, len - 1);
	}

	if (set->last_valid_uid != 0 &&
	    set->first_valid_uid > set->last_valid_uid) {
		*error_r = "first_valid_uid can't be larger than last_valid_uid";
		return FALSE;
	}
	if (set->last_valid_gid != 0 &&
	    set->first_valid_gid > set->last_valid_gid) {
		*error_r = "first_valid_gid can't be larger than last_valid_gid";
		return FALSE;
	}

	if (i_getpwnam(set->default_login_user, &pw) == 0) {
		*error_r = t_strdup_printf("default_login_user doesn't exist: %s",
					   set->default_login_user);
		return FALSE;
	}
	if (i_getpwnam(set->default_internal_user, &pw) == 0) {
		*error_r = t_strdup_printf("default_internal_user doesn't exist: %s",
					   set->default_internal_user);
		return FALSE;
	}

	/* check that we have at least one service. the actual service
	   structure validity is checked later while creating them. */
	if (!array_is_created(&set->services) ||
	    array_count(&set->services) == 0) {
		*error_r = "No services defined";
		return FALSE;
	}
	services = array_get(&set->services, &count);
	for (i = 0; i < count; i++) {
		struct service_settings *service = services[i];

		if (*service->name == '\0') {
			*error_r = t_strdup_printf(
				"Service #%d is missing name", i);
			return FALSE;
		}
		if (!master_settings_parse_type(service, error_r))
			return FALSE;
		for (j = 0; j < i; j++) {
			if (strcmp(service->name, services[j]->name) == 0) {
				*error_r = t_strdup_printf(
					"Duplicate service name: %s",
					service->name);
				return FALSE;
			}
		}
		expand_user(&service->user, &service->user_default, set);
		expand_group(&service->extra_groups, set);
		service_set_login_dump_core(service);
	}
	set->protocols_split = p_strsplit_spaces(pool, set->protocols, " ");
	if (set->protocols_split[0] != NULL &&
	    strcmp(set->protocols_split[0], "none") == 0 &&
	    set->protocols_split[1] == NULL)
		set->protocols_split[0] = NULL;

	for (i = 0; set->protocols_split[i] != NULL; i++) {
		if (!services_have_protocol(set, set->protocols_split[i])) {
			*error_r = t_strdup_printf("protocols: "
						   "Unknown protocol: %s",
						   set->protocols_split[i]);
			return FALSE;
		}
	}
	t_array_init(&all_listeners, 64);
	max_auth_client_processes = 0;
	max_anvil_client_processes = 2; /* blocking, nonblocking pipes */
	for (i = 0; i < count; i++) {
		struct service_settings *service = services[i];

		if (*service->protocol != '\0' &&
		    !str_array_find((const char **)set->protocols_split,
				    service->protocol)) {
			/* protocol not enabled, ignore its settings */
			continue;
		}

		if (*service->executable != '/' &&
		    *service->executable != '\0') {
			service->executable =
				p_strconcat(pool, set->libexec_dir, "/",
					    service->executable, NULL);
		}
		if (*service->chroot != '/' && *service->chroot != '\0') {
			service->chroot =
				p_strconcat(pool, set->base_dir, "/",
					    service->chroot, NULL);
		}
		if (service->drop_priv_before_exec &&
		    *service->chroot != '\0') {
			*error_r = t_strdup_printf("service(%s): "
				"drop_priv_before_exec=yes can't be "
				"used with chroot", service->name);
			return FALSE;
		}
		process_limit = service->process_limit;
		if (process_limit == 0)
			process_limit = set->default_process_limit;
		if (service->process_min_avail > process_limit) {
			*error_r = t_strdup_printf("service(%s): "
				"process_min_avail is higher than process_limit",
				service->name);
			return FALSE;
		}
		if (service->vsz_limit < 1024*1024 && service->vsz_limit != 0) {
			*error_r = t_strdup_printf("service(%s): "
				"vsz_limit is too low", service->name);
			return FALSE;
		}

#ifdef CONFIG_BINARY
		default_service =
			master_default_settings_get_service(service->name);
		if (default_service != NULL &&
		    default_service->process_limit_1 && process_limit > 1) {
			*error_r = t_strdup_printf("service(%s): "
				"process_limit must be 1", service->name);
			return FALSE;
		}
#else
		if (max_client_limit < service->client_limit) {
			max_client_limit = service->client_limit;
			max_client_limit_source = t_strdup_printf(
				"service %s { client_limit }", service->name);
		}
#endif

		if (*service->protocol != '\0') {
			/* each imap/pop3/lmtp process can use up a connection,
			   although if service_count=1 it's only temporary.
			   imap-hibernate doesn't do any auth lookups. */
			if ((service->service_count != 1 ||
			     strcmp(service->type, "login") == 0) &&
			    strcmp(service->name, "imap-hibernate") != 0) {
				str_printfa(max_auth_client_processes_reason,
					    " + service %s { process_limit=%u }",
					    service->name, process_limit);
				max_auth_client_processes += process_limit;
			}
		}
		if (strcmp(service->type, "login") == 0 ||
		    strcmp(service->name, "auth") == 0) {
			max_anvil_client_processes += process_limit;
			str_printfa(max_anvil_client_processes_reason,
				    " + service %s { process_limit=%u }",
				    service->name, process_limit);
		}

		if (!fix_file_listener_paths(&service->unix_listeners, pool,
					     set, &all_listeners, error_r)) {
			*error_r = t_strdup_printf("service(%s): unix_listener: %s",
						   service->name, *error_r);
			return FALSE;
		}
		if (!fix_file_listener_paths(&service->fifo_listeners, pool,
					     set, &all_listeners, error_r)) {
			*error_r = t_strdup_printf("service(%s): fifo_listener: %s",
						   service->name, *error_r);
			return FALSE;
		}
		add_inet_listeners(&service->inet_listeners, &all_listeners);
	}

	client_limit = service_get_client_limit(set, "auth");
	if (client_limit < max_auth_client_processes && !warned_auth) {
		warned_auth = TRUE;
		str_delete(max_auth_client_processes_reason, 0, 3);
		i_warning("service auth { client_limit=%u } is lower than "
			  "required under max. load (%u). "
			  "Counted for protocol services with service_count != 1: %s",
			  client_limit, max_auth_client_processes,
			  str_c(max_auth_client_processes_reason));
	}

	client_limit = service_get_client_limit(set, "anvil");
	if (client_limit < max_anvil_client_processes && !warned_anvil) {
		warned_anvil = TRUE;
		str_delete(max_anvil_client_processes_reason, 0, 3);
		i_warning("service anvil { client_limit=%u } is lower than "
			  "required under max. load (%u). Counted with: %s",
			  client_limit, max_anvil_client_processes,
			  str_c(max_anvil_client_processes_reason));
	}
#ifndef CONFIG_BINARY
	if (restrict_get_fd_limit(&fd_limit) == 0 &&
	    fd_limit < (rlim_t)max_client_limit) {
		i_warning("fd limit (ulimit -n) is lower than required "
			  "under max. load (%u < %u), because of %s",
			  (unsigned int)fd_limit, max_client_limit,
			  max_client_limit_source);
	}
#endif

	/* check for duplicate listeners */
	array_sort(&all_listeners, i_strcmp_p);
	strings = array_get(&all_listeners, &count);
	for (i = 1; i < count; i++) {
		if (strcmp(strings[i-1], strings[i]) == 0) {
			*error_r = t_strdup_printf("duplicate listener: %s",
						   strings[i]);
			return FALSE;
		}
	}
	return TRUE;
}
/* </settings checks> */
#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type(#name, name, struct file_listener_settings)
static const struct setting_define file_listener_setting_defines[] = {
	DEF(STR, path),
	DEF(UINT_OCT, mode),
	DEF(STR, user),
	DEF(STR, group),

	SETTING_DEFINE_LIST_END
};
static const struct file_listener_settings file_listener_default_settings = {
	.path = "",
	.mode = 0600,
	.user = "",
	.group = "",
};
static const struct setting_parser_info file_listener_setting_parser_info = {
	.defines = file_listener_setting_defines,
	.defaults = &file_listener_default_settings,

	.type_offset = offsetof(struct file_listener_settings, path),
	.struct_size = sizeof(struct file_listener_settings),

	.parent_offset = SIZE_MAX,
	.parent = &service_setting_parser_info
};
#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type(#name, name, struct inet_listener_settings)
static const struct setting_define inet_listener_setting_defines[] = {
	DEF(STR, name),
	DEF(STR, address),
	DEF(IN_PORT, port),
	DEF(BOOL, ssl),
	DEF(BOOL, reuse_port),
	DEF(BOOL, haproxy),

	SETTING_DEFINE_LIST_END
};
static const struct inet_listener_settings inet_listener_default_settings = {
	.name = "",
	.address = "",
	.port = 0,
	.ssl = FALSE,
	.reuse_port = FALSE,
	.haproxy = FALSE
};
static const struct setting_parser_info inet_listener_setting_parser_info = {
	.defines = inet_listener_setting_defines,
	.defaults = &inet_listener_default_settings,

	.type_offset = offsetof(struct inet_listener_settings, name),
	.struct_size = sizeof(struct inet_listener_settings),

	.parent_offset = SIZE_MAX,
	.parent = &service_setting_parser_info
};
#undef DEF
#undef DEFLIST_UNIQUE
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type(#name, name, struct service_settings)
#define DEFLIST_UNIQUE(field, name, defines) \
	{ .type = SET_DEFLIST_UNIQUE, .key = name, \
	  .offset = offsetof(struct service_settings, field), \
	  .list_info = defines }
static const struct setting_define service_setting_defines[] = {
	DEF(STR, name),
	DEF(STR, protocol),
	DEF(STR, type),
	DEF(STR, executable),
	DEF(STR, user),
	DEF(STR, group),
	DEF(STR, privileged_group),
	DEF(STR, extra_groups),
	DEF(STR, chroot),

	DEF(BOOL, drop_priv_before_exec),

	DEF(UINT, process_min_avail),
	DEF(UINT, process_limit),
	DEF(UINT, client_limit),
	DEF(UINT, service_count),
	DEF(TIME, idle_kill),
	DEF(SIZE, vsz_limit),

	DEFLIST_UNIQUE(unix_listeners, "unix_listener",
		       &file_listener_setting_parser_info),
	DEFLIST_UNIQUE(fifo_listeners, "fifo_listener",
		       &file_listener_setting_parser_info),
	DEFLIST_UNIQUE(inet_listeners, "inet_listener",
		       &inet_listener_setting_parser_info),

	SETTING_DEFINE_LIST_END
};
static const struct service_settings service_default_settings = {
	.name = "",
	.protocol = "",
	.type = "",
	.executable = "",
	.user = "",
	.group = "",
	.privileged_group = "",
	.extra_groups = "",
	.chroot = "",

	.drop_priv_before_exec = FALSE,

	.process_min_avail = 0,
	.process_limit = 0,
	.client_limit = 0,
	.service_count = 0,
	.idle_kill = 0,
	.vsz_limit = UOFF_T_MAX,

	.unix_listeners = ARRAY_INIT,
	.fifo_listeners = ARRAY_INIT,
	.inet_listeners = ARRAY_INIT
};
const struct setting_parser_info service_setting_parser_info = {
	.defines = service_setting_defines,
	.defaults = &service_default_settings,

	.type_offset = offsetof(struct service_settings, name),
	.struct_size = sizeof(struct service_settings),

	.parent_offset = offsetof(struct service_settings, master_set),
	.parent = &master_setting_parser_info
};
#undef DEF
#undef DEFLIST_UNIQUE
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type(#name, name, struct master_settings)
#define DEFLIST_UNIQUE(field, name, defines) \
	{ .type = SET_DEFLIST_UNIQUE, .key = name, \
	  .offset = offsetof(struct master_settings, field), \
	  .list_info = defines }
static const struct setting_define master_setting_defines[] = {
	DEF(STR, base_dir),
	DEF(STR, state_dir),
	DEF(STR, libexec_dir),
	DEF(STR, instance_name),
	DEF(STR, protocols),
	DEF(STR, listen),
	DEF(ENUM, ssl),
	DEF(STR, default_internal_user),
	DEF(STR, default_internal_group),
	DEF(STR, default_login_user),
	DEF(UINT, default_process_limit),
	DEF(UINT, default_client_limit),
	DEF(TIME, default_idle_kill),
	DEF(SIZE, default_vsz_limit),

	DEF(BOOL, version_ignore),

	DEF(UINT, first_valid_uid),
	DEF(UINT, last_valid_uid),
	DEF(UINT, first_valid_gid),
	DEF(UINT, last_valid_gid),

	DEFLIST_UNIQUE(services, "service", &service_setting_parser_info),

	SETTING_DEFINE_LIST_END
};
struct master_settings master_default_settings = {
	.base_dir = PKG_RUNDIR,
	.state_dir = PKG_STATEDIR,
	.libexec_dir = PKG_LIBEXECDIR,
	.instance_name = PACKAGE,
	.protocols = "imap pop3 lmtp",
	.listen = "*, ::",
	.ssl = "yes:no:required",
	.default_internal_user = "dovecot",
	.default_internal_group = "dovecot",
	.default_login_user = "dovenull",
	.default_process_limit = 100,
	.default_client_limit = 1000,
	.default_idle_kill = 60,
	.default_vsz_limit = 256*1024*1024,

	.version_ignore = FALSE,

	.first_valid_uid = 500,
	.last_valid_uid = 0,
	.first_valid_gid = 1,
	.last_valid_gid = 0,

#ifndef CONFIG_BINARY
	.services = ARRAY_INIT
#else
	.services = { { &config_all_services_buf,
			     sizeof(struct service_settings *) } },
#endif
};
const struct setting_parser_info master_setting_parser_info = {
	.module_name = "master",
	.defines = master_setting_defines,
	.defaults = &master_default_settings,

	.type_offset = SIZE_MAX,
	.struct_size = sizeof(struct master_settings),

	.parent_offset = SIZE_MAX,

	.check_func = master_settings_verify
};
/* ../../src/login-common/login-settings.c */
/* <settings checks> */
static bool login_settings_check(void *_set, pool_t pool,
				 const char **error_r ATTR_UNUSED)
{
	struct login_settings *set = _set;

	set->log_format_elements_split =
		p_strsplit(pool, set->login_log_format_elements, " ");

	if (set->auth_debug_passwords)
		set->auth_debug = TRUE;
	if (set->auth_debug)
		set->auth_verbose = TRUE;
	return TRUE;
}
/* </settings checks> */
#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type(#name, name, struct login_settings)
static const struct setting_define login_setting_defines[] = {
	DEF(STR, login_trusted_networks),
	DEF(STR, login_source_ips),
	DEF(STR_VARS, login_greeting),
	DEF(STR, login_log_format_elements),
	DEF(STR, login_log_format),
	DEF(STR, login_access_sockets),
	DEF(STR_VARS, login_proxy_notify_path),
	DEF(STR, login_plugin_dir),
	DEF(STR, login_plugins),
	DEF(TIME_MSECS, login_proxy_timeout),
	DEF(UINT, login_proxy_max_reconnects),
	DEF(TIME, login_proxy_max_disconnect_delay),
	DEF(STR, login_proxy_rawlog_dir),
	DEF(STR, director_username_hash),

	DEF(BOOL, auth_ssl_require_client_cert),
	DEF(BOOL, auth_ssl_username_from_cert),

	DEF(BOOL, disable_plaintext_auth),
	DEF(BOOL, auth_verbose),
	DEF(BOOL, auth_debug),
	DEF(BOOL, verbose_proctitle),

	DEF(UINT, mail_max_userip_connections),

	SETTING_DEFINE_LIST_END
};
static const struct login_settings login_default_settings = {
	.login_trusted_networks = "",
	.login_source_ips = "",
	.login_greeting = PACKAGE_NAME" ready.",
	.login_log_format_elements = "user=<%u> method=%m rip=%r lip=%l mpid=%e %c session=<%{session}>",
	.login_log_format = "%$: %s",
	.login_access_sockets = "",
	.login_proxy_notify_path = "proxy-notify",
	.login_plugin_dir = MODULEDIR"/login",
	.login_plugins = "",
	.login_proxy_timeout = 30*1000,
	.login_proxy_max_reconnects = 3,
	.login_proxy_max_disconnect_delay = 0,
	.login_proxy_rawlog_dir = "",
	.director_username_hash = "%Lu",

	.auth_ssl_require_client_cert = FALSE,
	.auth_ssl_username_from_cert = FALSE,

	.disable_plaintext_auth = TRUE,
	.auth_verbose = FALSE,
	.auth_debug = FALSE,
	.verbose_proctitle = FALSE,

	.mail_max_userip_connections = 10
};
const struct setting_parser_info login_setting_parser_info = {
	.module_name = "login",
	.defines = login_setting_defines,
	.defaults = &login_default_settings,

	.type_offset = SIZE_MAX,
	.struct_size = sizeof(struct login_settings),

	.parent_offset = SIZE_MAX,

	.check_func = login_settings_check
};
/* ../../src/log/log-settings.c */
/* <settings checks> */
static struct file_listener_settings log_unix_listeners_array[] = {
	{ "log-errors", 0600, "", "" }
};
static struct file_listener_settings *log_unix_listeners[] = {
	&log_unix_listeners_array[0]
};
static buffer_t log_unix_listeners_buf = {
	{ { log_unix_listeners, sizeof(log_unix_listeners) } }
};
/* </settings checks> */
struct service_settings log_service_settings = {
	.name = "log",
	.protocol = "",
	.type = "log",
	.executable = "log",
	.user = "",
	.group = "",
	.privileged_group = "",
	.extra_groups = "",
	.chroot = "",

	.drop_priv_before_exec = FALSE,

	.process_min_avail = 0,
	.process_limit = 1,
	.client_limit = 0,
	.service_count = 0,
	.idle_kill = UINT_MAX,
	.vsz_limit = UOFF_T_MAX,

	.unix_listeners = { { &log_unix_listeners_buf,
			      sizeof(log_unix_listeners[0]) } },
	.fifo_listeners = ARRAY_INIT,
	.inet_listeners = ARRAY_INIT,

	.process_limit_1 = TRUE
};
/* ../../src/lmtp/lmtp-settings.c */
/* <settings checks> */
static struct file_listener_settings lmtp_unix_listeners_array[] = {
	{ "lmtp", 0666, "", "" }
};
static struct file_listener_settings *lmtp_unix_listeners[] = {
	&lmtp_unix_listeners_array[0]
};
static buffer_t lmtp_unix_listeners_buf = {
	{ { lmtp_unix_listeners, sizeof(lmtp_unix_listeners) } }
};
/* </settings checks> */
/* <settings checks> */
struct lmtp_client_workaround_list {
	const char *name;
	enum lmtp_client_workarounds num;
};

static const struct lmtp_client_workaround_list
lmtp_client_workaround_list[] = {
	{ "whitespace-before-path", LMTP_WORKAROUND_WHITESPACE_BEFORE_PATH },
	{ "mailbox-for-path", LMTP_WORKAROUND_MAILBOX_FOR_PATH },
	{ NULL, 0 }
};

static int
lmtp_settings_parse_workarounds(struct lmtp_settings *set,
				const char **error_r)
{
	enum lmtp_client_workarounds client_workarounds = 0;
        const struct lmtp_client_workaround_list *list;
	const char *const *str;

        str = t_strsplit_spaces(set->lmtp_client_workarounds, " ,");
	for (; *str != NULL; str++) {
		list = lmtp_client_workaround_list;
		for (; list->name != NULL; list++) {
			if (strcasecmp(*str, list->name) == 0) {
				client_workarounds |= list->num;
				break;
			}
		}
		if (list->name == NULL) {
			*error_r = t_strdup_printf(
				"lmtp_client_workarounds: "
				"Unknown workaround: %s", *str);
			return -1;
		}
	}
	set->parsed_workarounds = client_workarounds;
	return 0;
}

static bool lmtp_settings_check(void *_set, pool_t pool ATTR_UNUSED,
				const char **error_r)
{
	struct lmtp_settings *set = _set;

	if (lmtp_settings_parse_workarounds(set, error_r) < 0)
		return FALSE;

	if (strcmp(set->lmtp_hdr_delivery_address, "none") == 0) {
		set->parsed_lmtp_hdr_delivery_address =
			LMTP_HDR_DELIVERY_ADDRESS_NONE;
	} else if (strcmp(set->lmtp_hdr_delivery_address, "final") == 0) {
		set->parsed_lmtp_hdr_delivery_address =
			LMTP_HDR_DELIVERY_ADDRESS_FINAL;
	} else if (strcmp(set->lmtp_hdr_delivery_address, "original") == 0) {
		set->parsed_lmtp_hdr_delivery_address =
			LMTP_HDR_DELIVERY_ADDRESS_ORIGINAL;
	} else {
		*error_r = t_strdup_printf("Unknown lmtp_hdr_delivery_address: %s",
					   set->lmtp_hdr_delivery_address);
		return FALSE;
	}
	return TRUE;
}
/* </settings checks> */
struct service_settings lmtp_service_settings = {
	.name = "lmtp",
	.protocol = "lmtp",
	.type = "",
	.executable = "lmtp",
	.user = "",
	.group = "",
	.privileged_group = "",
	.extra_groups = "$default_internal_group",
	.chroot = "",

	.drop_priv_before_exec = FALSE,

	.process_min_avail = 0,
	.process_limit = 0,
	.client_limit = 1,
	.service_count = 0,
	.idle_kill = 0,
	.vsz_limit = UOFF_T_MAX,

	.unix_listeners = { { &lmtp_unix_listeners_buf,
			      sizeof(lmtp_unix_listeners[0]) } },
	.fifo_listeners = ARRAY_INIT,
	.inet_listeners = ARRAY_INIT
};
#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type(#name, name, struct lmtp_settings)
static const struct setting_define lmtp_setting_defines[] = {
	DEF(BOOL, lmtp_proxy),
	DEF(BOOL, lmtp_save_to_detail_mailbox),
	DEF(BOOL, lmtp_rcpt_check_quota),
	DEF(BOOL, lmtp_add_received_header),
	DEF(BOOL, lmtp_verbose_replies),
	DEF(UINT, lmtp_user_concurrency_limit),
	DEF(ENUM, lmtp_hdr_delivery_address),
	DEF(STR_VARS, lmtp_rawlog_dir),
	DEF(STR_VARS, lmtp_proxy_rawlog_dir),

	DEF(STR, lmtp_client_workarounds),

	DEF(STR_VARS, login_greeting),
	DEF(STR, login_trusted_networks),

	DEF(STR, mail_plugins),
	DEF(STR, mail_plugin_dir),

	SETTING_DEFINE_LIST_END
};
static const struct lmtp_settings lmtp_default_settings = {
	.lmtp_proxy = FALSE,
	.lmtp_save_to_detail_mailbox = FALSE,
	.lmtp_rcpt_check_quota = FALSE,
	.lmtp_add_received_header = TRUE,
	.lmtp_verbose_replies = FALSE,
	.lmtp_user_concurrency_limit = 0,
	.lmtp_hdr_delivery_address = "final:none:original",
	.lmtp_rawlog_dir = "",
	.lmtp_proxy_rawlog_dir = "",

	.lmtp_client_workarounds = "",

	.login_greeting = PACKAGE_NAME" ready.",
	.login_trusted_networks = "",

	.mail_plugins = "",
	.mail_plugin_dir = MODULEDIR,
};
static const struct setting_parser_info *lmtp_setting_dependencies[] = {
	&lda_setting_parser_info,
	NULL
};
const struct setting_parser_info lmtp_setting_parser_info = {
	.module_name = "lmtp",
	.defines = lmtp_setting_defines,
	.defaults = &lmtp_default_settings,

	.type_offset = SIZE_MAX,
	.struct_size = sizeof(struct lmtp_settings),

	.parent_offset = SIZE_MAX,

	.check_func = lmtp_settings_check,
	.dependencies = lmtp_setting_dependencies
};
/* ../../src/ipc/ipc-settings.c */
/* <settings checks> */
static struct file_listener_settings ipc_unix_listeners_array[] = {
	{ "ipc", 0600, "$default_internal_user", "" },
	{ "login/ipc-proxy", 0600, "$default_login_user", "" }
};
static struct file_listener_settings *ipc_unix_listeners[] = {
	&ipc_unix_listeners_array[0],
	&ipc_unix_listeners_array[1]
};
static buffer_t ipc_unix_listeners_buf = {
	{ { ipc_unix_listeners, sizeof(ipc_unix_listeners) } }
};
/* </settings checks> */
struct service_settings ipc_service_settings = {
	.name = "ipc",
	.protocol = "",
	.type = "",
	.executable = "ipc",
	.user = "$default_internal_user",
	.group = "",
	.privileged_group = "",
	.extra_groups = "",
	.chroot = "empty",

	.drop_priv_before_exec = FALSE,

	.process_min_avail = 0,
	.process_limit = 1,
	.client_limit = 0,
	.service_count = 0,
	.idle_kill = 0,
	.vsz_limit = UOFF_T_MAX,

	.unix_listeners = { { &ipc_unix_listeners_buf,
			      sizeof(ipc_unix_listeners[0]) } },
	.fifo_listeners = ARRAY_INIT,
	.inet_listeners = ARRAY_INIT,

	.process_limit_1 = TRUE
};
/* ../../src/indexer/indexer-worker-settings.c */
/* <settings checks> */
static struct file_listener_settings indexer_worker_unix_listeners_array[] = {
	{ "indexer-worker", 0600, "$default_internal_user", "" }
};
static struct file_listener_settings *indexer_worker_unix_listeners[] = {
	&indexer_worker_unix_listeners_array[0]
};
static buffer_t indexer_worker_unix_listeners_buf = {
	{ { indexer_worker_unix_listeners, sizeof(indexer_worker_unix_listeners) } }
};
/* </settings checks> */
struct service_settings indexer_worker_service_settings = {
	.name = "indexer-worker",
	.protocol = "",
	.type = "worker",
	.executable = "indexer-worker",
	.user = "",
	.group = "",
	.privileged_group = "",
	.extra_groups = "$default_internal_group",
	.chroot = "",

	.drop_priv_before_exec = FALSE,

	.process_min_avail = 0,
	.process_limit = 10,
	.client_limit = 1,
	.service_count = 0,
	.idle_kill = 0,
	.vsz_limit = UOFF_T_MAX,

	.unix_listeners = { { &indexer_worker_unix_listeners_buf,
			      sizeof(indexer_worker_unix_listeners[0]) } },
	.fifo_listeners = ARRAY_INIT,
	.inet_listeners = ARRAY_INIT
};
/* ../../src/indexer/indexer-settings.c */
extern const struct setting_parser_info service_setting_parser_info;
/* <settings checks> */
static struct file_listener_settings indexer_unix_listeners_array[] = {
	{ "indexer", 0666, "", "" }
};
static struct file_listener_settings *indexer_unix_listeners[] = {
	&indexer_unix_listeners_array[0]
};
static buffer_t indexer_unix_listeners_buf = {
	{ { indexer_unix_listeners, sizeof(indexer_unix_listeners) } }
};
/* </settings checks> */
struct service_settings indexer_service_settings = {
	.name = "indexer",
	.protocol = "",
	.type = "",
	.executable = "indexer",
	.user = "$default_internal_user",
	.group = "",
	.privileged_group = "",
	.extra_groups = "",
	.chroot = "",

	.drop_priv_before_exec = FALSE,

	.process_min_avail = 0,
	.process_limit = 1,
	.client_limit = 0,
	.service_count = 0,
	.idle_kill = 0,
	.vsz_limit = UOFF_T_MAX,

	.unix_listeners = { { &indexer_unix_listeners_buf,
			      sizeof(indexer_unix_listeners[0]) } },
	.fifo_listeners = ARRAY_INIT,
	.inet_listeners = ARRAY_INIT,

	.process_limit_1 = TRUE
};
/* ../../src/imap/imap-settings.c */
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
/* ../../src/imap-urlauth/imap-urlauth-worker-settings.c */
/* <settings checks> */
static struct file_listener_settings imap_urlauth_worker_unix_listeners_array[] = {
	{ "imap-urlauth-worker", 0600, "$default_internal_user", "" }
};
static struct file_listener_settings *imap_urlauth_worker_unix_listeners[] = {
	&imap_urlauth_worker_unix_listeners_array[0]
};
static buffer_t imap_urlauth_worker_unix_listeners_buf = {
	{ { imap_urlauth_worker_unix_listeners,
	    sizeof(imap_urlauth_worker_unix_listeners) } }
};
/* </settings checks> */
struct service_settings imap_urlauth_worker_service_settings = {
	.name = "imap-urlauth-worker",
	.protocol = "imap",
	.type = "",
	.executable = "imap-urlauth-worker",
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

	.unix_listeners = { { &imap_urlauth_worker_unix_listeners_buf,
			      sizeof(imap_urlauth_worker_unix_listeners[0]) } },
	.fifo_listeners = ARRAY_INIT,
	.inet_listeners = ARRAY_INIT
};
#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type(#name, name, struct imap_urlauth_worker_settings)
static const struct setting_define imap_urlauth_worker_setting_defines[] = {
	DEF(BOOL, verbose_proctitle),

	DEF(STR, imap_urlauth_host),
	DEF(IN_PORT, imap_urlauth_port),

	SETTING_DEFINE_LIST_END
};
const struct imap_urlauth_worker_settings imap_urlauth_worker_default_settings = {
	.verbose_proctitle = FALSE,

	.imap_urlauth_host = "",
	.imap_urlauth_port = 143
};
static const struct setting_parser_info *imap_urlauth_worker_setting_dependencies[] = {
	&mail_user_setting_parser_info,
	NULL
};
const struct setting_parser_info imap_urlauth_worker_setting_parser_info = {
	.module_name = "imap-urlauth-worker",
	.defines = imap_urlauth_worker_setting_defines,
	.defaults = &imap_urlauth_worker_default_settings,

	.type_offset = SIZE_MAX,
	.struct_size = sizeof(struct imap_urlauth_worker_settings),

	.parent_offset = SIZE_MAX,

	.dependencies = imap_urlauth_worker_setting_dependencies
};
/* ../../src/imap-urlauth/imap-urlauth-settings.c */
/* <settings checks> */
static struct file_listener_settings imap_urlauth_unix_listeners_array[] = {
	{ "token-login/imap-urlauth", 0666, "", "" }
};
static struct file_listener_settings *imap_urlauth_unix_listeners[] = {
	&imap_urlauth_unix_listeners_array[0]
};
static buffer_t imap_urlauth_unix_listeners_buf = {
	{ { imap_urlauth_unix_listeners, sizeof(imap_urlauth_unix_listeners) } }
};
/* </settings checks> */
struct service_settings imap_urlauth_service_settings = {
	.name = "imap-urlauth",
	.protocol = "imap",
	.type = "",
	.executable = "imap-urlauth",
	.user = "$default_internal_user",
	.group = "",
	.privileged_group = "",
	.extra_groups = "",
	.chroot = "",

	.drop_priv_before_exec = FALSE,

	.process_min_avail = 0,
	.process_limit = 1024,
	.client_limit = 1,
	.service_count = 1,
	.idle_kill = 0,
	.vsz_limit = UOFF_T_MAX,

	.unix_listeners = { { &imap_urlauth_unix_listeners_buf,
			      sizeof(imap_urlauth_unix_listeners[0]) } },
	.fifo_listeners = ARRAY_INIT,
	.inet_listeners = ARRAY_INIT
};
#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type(#name, name, struct imap_urlauth_settings)
static const struct setting_define imap_urlauth_setting_defines[] = {
	DEF(STR, base_dir),

	DEF(BOOL, mail_debug),

	DEF(BOOL, verbose_proctitle),

	DEF(STR, imap_urlauth_logout_format),
	DEF(STR, imap_urlauth_submit_user),
	DEF(STR, imap_urlauth_stream_user),

	SETTING_DEFINE_LIST_END
};
const struct imap_urlauth_settings imap_urlauth_default_settings = {
	.base_dir = PKG_RUNDIR,
  .mail_debug = FALSE,

	.verbose_proctitle = FALSE,

	.imap_urlauth_logout_format = "in=%i out=%o",
	.imap_urlauth_submit_user = NULL,
	.imap_urlauth_stream_user = NULL
};
static const struct setting_parser_info *imap_urlauth_setting_dependencies[] = {
	NULL
};
const struct setting_parser_info imap_urlauth_setting_parser_info = {
	.module_name = "imap-urlauth",
	.defines = imap_urlauth_setting_defines,
	.defaults = &imap_urlauth_default_settings,

	.type_offset = SIZE_MAX,
	.struct_size = sizeof(struct imap_urlauth_settings),

	.parent_offset = SIZE_MAX,

	.dependencies = imap_urlauth_setting_dependencies
};
/* ../../src/imap-urlauth/imap-urlauth-login-settings.c */
/* <settings checks> */
static struct file_listener_settings
imap_urlauth_login_unix_listeners_array[] = {
	{ "imap-urlauth", 0666, "", "" }
};
static struct file_listener_settings *imap_urlauth_login_unix_listeners[] = {
	&imap_urlauth_login_unix_listeners_array[0]
};
static buffer_t imap_urlauth_login_unix_listeners_buf = {
	{ { imap_urlauth_login_unix_listeners,
	    sizeof(imap_urlauth_login_unix_listeners) } }
};
/* </settings checks> */
struct service_settings imap_urlauth_login_service_settings = {
	.name = "imap-urlauth-login",
	.protocol = "imap",
	.type = "login",
	.executable = "imap-urlauth-login",
	.user = "$default_login_user",
	.group = "",
	.privileged_group = "",
	.extra_groups = "",
	.chroot = "token-login",

	.drop_priv_before_exec = FALSE,

	.process_min_avail = 0,
	.process_limit = 0,
	.client_limit = 0,
	.service_count = 1,
	.idle_kill = 0,
	.vsz_limit = UOFF_T_MAX,

	.unix_listeners = { { &imap_urlauth_login_unix_listeners_buf,
			      sizeof(imap_urlauth_login_unix_listeners[0]) } },
	.fifo_listeners = ARRAY_INIT,
	.inet_listeners = ARRAY_INIT
};
static const struct setting_define imap_urlauth_login_setting_defines[] = {
	SETTING_DEFINE_LIST_END
};
static const struct setting_parser_info *imap_urlauth_login_setting_dependencies[] = {
	&login_setting_parser_info,
	NULL
};
const struct setting_parser_info imap_urlauth_login_setting_parser_info = {
	.module_name = "imap-urlauth-login",
	.defines = imap_urlauth_login_setting_defines,

	.type_offset = SIZE_MAX,
	.parent_offset = SIZE_MAX,

	.dependencies = imap_urlauth_login_setting_dependencies
};
const struct setting_parser_info *imap_urlauth_login_setting_roots[] = {
	&login_setting_parser_info,
	&imap_urlauth_login_setting_parser_info,
	NULL
};
/* ../../src/imap-login/imap-login-settings.c */
/* <settings checks> */
static struct inet_listener_settings imap_login_inet_listeners_array[] = {
	{ .name = "imap", .address = "", .port = 143 },
	{ .name = "imaps", .address = "", .port = 993, .ssl = TRUE }
};
static struct inet_listener_settings *imap_login_inet_listeners[] = {
	&imap_login_inet_listeners_array[0],
	&imap_login_inet_listeners_array[1]
};
static buffer_t imap_login_inet_listeners_buf = {
	{ { imap_login_inet_listeners, sizeof(imap_login_inet_listeners) } }
};
/* </settings checks> */
struct service_settings imap_login_service_settings = {
	.name = "imap-login",
	.protocol = "imap",
	.type = "login",
	.executable = "imap-login",
	.user = "$default_login_user",
	.group = "",
	.privileged_group = "",
	.extra_groups = "",
	.chroot = "login",

	.drop_priv_before_exec = FALSE,

	.process_min_avail = 0,
	.process_limit = 0,
	.client_limit = 0,
	.service_count = 1,
	.idle_kill = 0,
	.vsz_limit = UOFF_T_MAX,

	.unix_listeners = ARRAY_INIT,
	.fifo_listeners = ARRAY_INIT,
	.inet_listeners = { { &imap_login_inet_listeners_buf,
			      sizeof(imap_login_inet_listeners[0]) } }
};
#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type(#name, name, struct imap_login_settings)
static const struct setting_define imap_login_setting_defines[] = {
	DEF(STR, imap_capability),
	DEF(STR, imap_id_send),
	DEF(STR, imap_id_log),
	DEF(BOOL, imap_literal_minus),
	DEF(BOOL, imap_id_retain),

	SETTING_DEFINE_LIST_END
};
static const struct imap_login_settings imap_login_default_settings = {
	.imap_capability = "",
	.imap_id_send = "name *",
	.imap_id_log = "",
	.imap_literal_minus = FALSE,
	.imap_id_retain = FALSE,
};
static const struct setting_parser_info *imap_login_setting_dependencies[] = {
	&login_setting_parser_info,
	NULL
};
static const struct setting_parser_info imap_login_setting_parser_info = {
	.module_name = "imap-login",
	.defines = imap_login_setting_defines,
	.defaults = &imap_login_default_settings,

	.type_offset = SIZE_MAX,
	.struct_size = sizeof(struct imap_login_settings),

	.parent_offset = SIZE_MAX,
	.dependencies = imap_login_setting_dependencies
};
const struct setting_parser_info *imap_login_setting_roots[] = {
	&login_setting_parser_info,
	&imap_login_setting_parser_info,
	NULL
};
/* ../../src/imap-hibernate/imap-hibernate-settings.c */
/* <settings checks> */
static struct file_listener_settings imap_hibernate_unix_listeners_array[] = {
	{ "imap-hibernate", 0660, "", "$default_internal_group" }
};
static struct file_listener_settings *imap_hibernate_unix_listeners[] = {
	&imap_hibernate_unix_listeners_array[0]
};
static buffer_t imap_hibernate_unix_listeners_buf = {
	{ { imap_hibernate_unix_listeners, sizeof(imap_hibernate_unix_listeners) } }
};
/* </settings checks> */
struct service_settings imap_hibernate_service_settings = {
	.name = "imap-hibernate",
	.protocol = "imap",
	.type = "",
	.executable = "imap-hibernate",
	.user = "$default_internal_user",
	.group = "",
	.privileged_group = "",
	.extra_groups = "",
	.chroot = "",

	.drop_priv_before_exec = FALSE,

	.process_min_avail = 0,
	.process_limit = 0,
	.client_limit = 0,
	.service_count = 0,
	.idle_kill = 0,
	.vsz_limit = UOFF_T_MAX,

	.unix_listeners = { { &imap_hibernate_unix_listeners_buf,
			      sizeof(imap_hibernate_unix_listeners[0]) } },
	.fifo_listeners = ARRAY_INIT,
	.inet_listeners = ARRAY_INIT
};
/* ../../src/doveadm/doveadm-settings.c */
/* <settings checks> */
static struct file_listener_settings doveadm_unix_listeners_array[] = {
	{ "doveadm-server", 0600, "", "" }
};
static struct file_listener_settings *doveadm_unix_listeners[] = {
	&doveadm_unix_listeners_array[0]
};
static buffer_t doveadm_unix_listeners_buf = {
	{ { doveadm_unix_listeners, sizeof(doveadm_unix_listeners) } }
};
/* </settings checks> */
/* <settings checks> */
struct dsync_feature_list {
	const char *name;
	enum dsync_features num;
};

static const struct dsync_feature_list dsync_feature_list[] = {
	{ "empty-header-workaround", DSYNC_FEATURE_EMPTY_HDR_WORKAROUND },
	{ "no-header-hashes", DSYNC_FEATURE_NO_HEADER_HASHES },
	{ NULL, 0 }
};

static int
dsync_settings_parse_features(struct doveadm_settings *set,
			      const char **error_r)
{
	enum dsync_features features = 0;
	const struct dsync_feature_list *list;
	const char *const *str;

	str = t_strsplit_spaces(set->dsync_features, " ,");
	for (; *str != NULL; str++) {
		list = dsync_feature_list;
		for (; list->name != NULL; list++) {
			if (strcasecmp(*str, list->name) == 0) {
				features |= list->num;
				break;
			}
		}
		if (list->name == NULL) {
			*error_r = t_strdup_printf("dsync_features: "
				"Unknown feature: %s", *str);
			return -1;
		}
	}
	set->parsed_features = features;
	return 0;
}

static bool doveadm_settings_check(void *_set, pool_t pool ATTR_UNUSED,
				   const char **error_r)
{
	struct doveadm_settings *set = _set;

#ifndef CONFIG_BINARY
	fix_base_path(set, pool, &set->auth_socket_path);
	fix_base_path(set, pool, &set->doveadm_socket_path);
#endif
	if (*set->dsync_hashed_headers == '\0') {
		*error_r = "dsync_hashed_headers must not be empty";
		return FALSE;
	}
	if (*set->dsync_alt_char == '\0') {
		*error_r = "dsync_alt_char must not be empty";
		return FALSE;
	}
	if (dsync_settings_parse_features(set, error_r) != 0)
		return FALSE;
	return TRUE;
}
/* </settings checks> */
struct service_settings doveadm_service_settings = {
	.name = "doveadm",
	.protocol = "",
	.type = "",
	.executable = "doveadm-server",
	.user = "",
	.group = "",
	.privileged_group = "",
	.extra_groups = "$default_internal_group",
	.chroot = "",

	.drop_priv_before_exec = FALSE,

	.process_min_avail = 0,
	.process_limit = 0,
	.client_limit = 1,
	.service_count = 1,
	.idle_kill = 0,
	.vsz_limit = UOFF_T_MAX,

	.unix_listeners = { { &doveadm_unix_listeners_buf,
			      sizeof(doveadm_unix_listeners[0]) } },
	.fifo_listeners = ARRAY_INIT,
	.inet_listeners = ARRAY_INIT
};
#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type(#name, name, struct doveadm_settings)
static const struct setting_define doveadm_setting_defines[] = {
	DEF(STR, base_dir),
	DEF(STR, libexec_dir),
	DEF(STR, mail_plugins),
	DEF(STR, mail_plugin_dir),
	DEF(STR_VARS, mail_temp_dir),
	DEF(BOOL, auth_debug),
	DEF(STR, auth_socket_path),
	DEF(STR, doveadm_socket_path),
	DEF(UINT, doveadm_worker_count),
	DEF(IN_PORT, doveadm_port),
	{ .type = SET_ALIAS, .key = "doveadm_proxy_port" },
	DEF(ENUM, doveadm_ssl),
	DEF(STR, doveadm_username),
	DEF(STR, doveadm_password),
	DEF(STR, doveadm_allowed_commands),
	DEF(STR, dsync_alt_char),
	DEF(STR, dsync_remote_cmd),
	DEF(STR, director_username_hash),
	DEF(STR, doveadm_api_key),
	DEF(STR, dsync_features),
	DEF(UINT, dsync_commit_msgs_interval),
	DEF(STR, doveadm_http_rawlog_dir),
	DEF(STR, dsync_hashed_headers),

	{ .type = SET_STRLIST, .key = "plugin",
	  .offset = offsetof(struct doveadm_settings, plugin_envs) },

	SETTING_DEFINE_LIST_END
};
const struct doveadm_settings doveadm_default_settings = {
	.base_dir = PKG_RUNDIR,
	.libexec_dir = PKG_LIBEXECDIR,
	.mail_plugins = "",
	.mail_plugin_dir = MODULEDIR,
	.mail_temp_dir = "/tmp",
	.auth_debug = FALSE,
	.auth_socket_path = "auth-userdb",
	.doveadm_socket_path = "doveadm-server",
	.doveadm_worker_count = 0,
	.doveadm_port = 0,
	.doveadm_ssl = "no:ssl:starttls",
	.doveadm_username = "doveadm",
	.doveadm_password = "",
	.doveadm_allowed_commands = "",
	.dsync_alt_char = "_",
	.dsync_remote_cmd = "ssh -l%{login} %{host} doveadm dsync-server -u%u -U",
	.dsync_features = "",
	.dsync_hashed_headers = "Date Message-ID",
	.dsync_commit_msgs_interval = 100,
	.director_username_hash = "%Lu",
	.doveadm_api_key = "",
	.doveadm_http_rawlog_dir = "",

	.plugin_envs = ARRAY_INIT
};
static const struct setting_parser_info *doveadm_setting_dependencies[] = {
	&mail_user_setting_parser_info,
	NULL
};
const struct setting_parser_info doveadm_setting_parser_info = {
	.module_name = "doveadm",
	.defines = doveadm_setting_defines,
	.defaults = &doveadm_default_settings,

	.type_offset = SIZE_MAX,
	.struct_size = sizeof(struct doveadm_settings),

	.parent_offset = SIZE_MAX,
	.check_func = doveadm_settings_check,
	.dependencies = doveadm_setting_dependencies
};
/* ../../src/dns/dns-client-settings.c */
/* <settings checks> */
static struct file_listener_settings dns_client_unix_listeners_array[] = {
	{ "dns-client", 0666, "", "" },
	{ "login/dns-client", 0666, "", "" },
};
static struct file_listener_settings *dns_client_unix_listeners[] = {
	&dns_client_unix_listeners_array[0],
        &dns_client_unix_listeners_array[1],
};
static buffer_t dns_client_unix_listeners_buf = {
	{ { dns_client_unix_listeners, sizeof(dns_client_unix_listeners) } }
};
/* </settings checks> */
struct service_settings dns_client_service_settings = {
	.name = "dns-client",
	.protocol = "",
	.type = "",
	.executable = "dns-client",
	.user = "$default_internal_user",
	.group = "",
	.privileged_group = "",
	.extra_groups = "",
	.chroot = "",

	.drop_priv_before_exec = FALSE,

	.process_min_avail = 0,
	.process_limit = 0,
	.client_limit = 1,
	.service_count = 0,
	.idle_kill = 0,
	.vsz_limit = UOFF_T_MAX,

	.unix_listeners = { { &dns_client_unix_listeners_buf,
			      sizeof(dns_client_unix_listeners[0]) } },
	.fifo_listeners = ARRAY_INIT,
	.inet_listeners = ARRAY_INIT
};
/* ../../src/director/director-settings.c */
/* <settings checks> */
static bool director_settings_verify(void *_set, pool_t pool, const char **error_r);

static struct file_listener_settings director_unix_listeners_array[] = {
	{ "login/director", 0, "", "" },
	{ "director-admin", 0600, "", "" }
};
static struct file_listener_settings *director_unix_listeners[] = {
	&director_unix_listeners_array[0],
	&director_unix_listeners_array[1]
};
static buffer_t director_unix_listeners_buf = {
	{ { director_unix_listeners, sizeof(director_unix_listeners) } }
};
static struct file_listener_settings director_fifo_listeners_array[] = {
	{ "login/proxy-notify", 0, "", "" }
};
static struct file_listener_settings *director_fifo_listeners[] = {
	&director_fifo_listeners_array[0]
};
static buffer_t director_fifo_listeners_buf = {
	{ { director_fifo_listeners, sizeof(director_fifo_listeners) } }
};
/* </settings checks> */
/* <settings checks> */
static bool
director_settings_verify(void *_set, pool_t pool ATTR_UNUSED, const char **error_r)
{
	struct director_settings *set = _set;

	if (set->director_user_expire < 10) {
		*error_r = "director_user_expire is too low";
		return FALSE;
	}
	return TRUE;
}
/* </settings checks> */
struct service_settings director_service_settings = {
	.name = "director",
	.protocol = "",
	.type = "",
	.executable = "director",
	.user = "$default_internal_user",
	.group = "",
	.privileged_group = "",
	.extra_groups = "",
	.chroot = ".",

	.drop_priv_before_exec = FALSE,

	.process_min_avail = 0,
	.process_limit = 1,
	.client_limit = 0,
	.service_count = 0,
	.idle_kill = UINT_MAX,
	.vsz_limit = UOFF_T_MAX,

	.unix_listeners = { { &director_unix_listeners_buf,
			      sizeof(director_unix_listeners[0]) } },
	.fifo_listeners = { { &director_fifo_listeners_buf,
			      sizeof(director_fifo_listeners[0]) } },
	.inet_listeners = ARRAY_INIT,

	.process_limit_1 = TRUE
};
#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type(#name, name, struct director_settings)
static const struct setting_define director_setting_defines[] = {
	DEF(STR, auth_master_user_separator),

	DEF(STR, director_servers),
	DEF(STR, director_mail_servers),
	DEF(STR, director_username_hash),
	DEF(STR, director_flush_socket),
	DEF(TIME, director_ping_idle_timeout),
	DEF(TIME, director_ping_max_timeout),
	DEF(TIME, director_user_expire),
	DEF(TIME, director_user_kick_delay),
	DEF(UINT, director_max_parallel_moves),
	DEF(UINT, director_max_parallel_kicks),
	DEF(SIZE, director_output_buffer_size),

	SETTING_DEFINE_LIST_END
};
const struct director_settings director_default_settings = {
	.auth_master_user_separator = "",

	.director_servers = "",
	.director_mail_servers = "",
	.director_username_hash = "%Lu",
	.director_flush_socket = "",
	.director_ping_idle_timeout = 30,
	.director_ping_max_timeout = 60,
	.director_user_expire = 60*15,
	.director_user_kick_delay = 2,
	.director_max_parallel_moves = 100,
	.director_max_parallel_kicks = 100,
	.director_output_buffer_size = 10 * 1024 * 1024,
};
const struct setting_parser_info director_setting_parser_info = {
	.module_name = "director",
	.defines = director_setting_defines,
	.defaults = &director_default_settings,

	.type_offset = SIZE_MAX,
	.struct_size = sizeof(struct director_settings),

	.parent_offset = SIZE_MAX,

	.check_func = director_settings_verify
};
/* ../../src/dict/dict-settings.c */
/* <settings checks> */
static struct file_listener_settings dict_unix_listeners_array[] = {
	{ "dict", 0660, "", "$default_internal_group" }
};
static struct file_listener_settings *dict_unix_listeners[] = {
	&dict_unix_listeners_array[0]
};
static buffer_t dict_unix_listeners_buf = {
	{ { dict_unix_listeners, sizeof(dict_unix_listeners) } }
};

static struct file_listener_settings dict_async_unix_listeners_array[] = {
	{ "dict-async", 0660, "", "$default_internal_group" }
};
static struct file_listener_settings *dict_async_unix_listeners[] = {
	&dict_async_unix_listeners_array[0]
};
static buffer_t dict_async_unix_listeners_buf = {
	{ { dict_async_unix_listeners, sizeof(dict_async_unix_listeners) } }
};
/* </settings checks> */
struct service_settings dict_service_settings = {
	.name = "dict",
	.protocol = "",
	.type = "",
	.executable = "dict",
	.user = "$default_internal_user",
	.group = "",
	.privileged_group = "",
	.extra_groups = "",
	.chroot = "",

	.drop_priv_before_exec = FALSE,

	.process_min_avail = 0,
	.process_limit = 0,
	.client_limit = 1,
	.service_count = 0,
	.idle_kill = 0,
	.vsz_limit = UOFF_T_MAX,

	.unix_listeners = { { &dict_unix_listeners_buf,
			      sizeof(dict_unix_listeners[0]) } },
	.fifo_listeners = ARRAY_INIT,
	.inet_listeners = ARRAY_INIT
};
struct service_settings dict_async_service_settings = {
	.name = "dict-async",
	.protocol = "",
	.type = "",
	.executable = "dict",
	.user = "$default_internal_user",
	.group = "",
	.privileged_group = "",
	.extra_groups = "",
	.chroot = "",

	.drop_priv_before_exec = FALSE,

	.process_min_avail = 0,
	.process_limit = 0,
	.client_limit = 0,
	.service_count = 0,
	.idle_kill = 0,
	.vsz_limit = UOFF_T_MAX,

	.unix_listeners = { { &dict_async_unix_listeners_buf,
			      sizeof(dict_async_unix_listeners[0]) } },
	.fifo_listeners = ARRAY_INIT,
	.inet_listeners = ARRAY_INIT
};
#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type(#name, name, struct dict_server_settings)
static const struct setting_define dict_setting_defines[] = {
	DEF(STR, base_dir),
	DEF(BOOL, verbose_proctitle),

	DEF(STR, dict_db_config),
	{ .type = SET_STRLIST, .key = "dict",
	  .offset = offsetof(struct dict_server_settings, dicts) },

	SETTING_DEFINE_LIST_END
};
const struct dict_server_settings dict_default_settings = {
	.base_dir = PKG_RUNDIR,
	.verbose_proctitle = FALSE,

	.dict_db_config = "",
	.dicts = ARRAY_INIT
};
const struct setting_parser_info dict_setting_parser_info = {
	.module_name = "dict",
	.defines = dict_setting_defines,
	.defaults = &dict_default_settings,

	.type_offset = SIZE_MAX,
	.struct_size = sizeof(struct dict_server_settings),

	.parent_offset = SIZE_MAX
};
/* ../../src/config/config-settings.c */
/* <settings checks> */
static struct file_listener_settings config_unix_listeners_array[] = {
	{ "config", 0600, "", "" }
};
static struct file_listener_settings *config_unix_listeners[] = {
	&config_unix_listeners_array[0]
};
static buffer_t config_unix_listeners_buf = {
	{ { config_unix_listeners, sizeof(config_unix_listeners) } }
};
/* </settings checks> */
struct service_settings config_service_settings = {
	.name = "config",
	.protocol = "",
	.type = "config",
	.executable = "config",
	.user = "",
	.group = "",
	.privileged_group = "",
	.extra_groups = "",
	.chroot = "",

	.drop_priv_before_exec = FALSE,

	.process_min_avail = 0,
	.process_limit = 0,
	.client_limit = 0,
	.service_count = 0,
	.idle_kill = UINT_MAX,
	.vsz_limit = UOFF_T_MAX,

	.unix_listeners = { { &config_unix_listeners_buf,
			      sizeof(config_unix_listeners[0]) } },
	.fifo_listeners = ARRAY_INIT,
	.inet_listeners = ARRAY_INIT
};
/* ../../src/auth/auth-settings.c */
extern const struct setting_parser_info auth_passdb_setting_parser_info;
extern const struct setting_parser_info auth_userdb_setting_parser_info;
/* <settings checks> */
static struct file_listener_settings auth_unix_listeners_array[] = {
	{ "login/login", 0666, "", "" },
	{ "token-login/tokenlogin", 0666, "", "" },
	{ "auth-login", 0600, "$default_internal_user", "" },
	{ "auth-client", 0600, "$default_internal_user", "" },
	{ "auth-userdb", 0666, "$default_internal_user", "" },
	{ "auth-master", 0600, "", "" }
};
static struct file_listener_settings *auth_unix_listeners[] = {
	&auth_unix_listeners_array[0],
	&auth_unix_listeners_array[1],
	&auth_unix_listeners_array[2],
	&auth_unix_listeners_array[3],
	&auth_unix_listeners_array[4],
	&auth_unix_listeners_array[5]
};
static buffer_t auth_unix_listeners_buf = {
	{ { auth_unix_listeners, sizeof(auth_unix_listeners) } }
};
/* </settings checks> */
/* <settings checks> */
static struct file_listener_settings auth_worker_unix_listeners_array[] = {
	{ "auth-worker", 0600, "$default_internal_user", "" }
};
static struct file_listener_settings *auth_worker_unix_listeners[] = {
	&auth_worker_unix_listeners_array[0]
};
static buffer_t auth_worker_unix_listeners_buf = {
	{ { auth_worker_unix_listeners, sizeof(auth_worker_unix_listeners) } }
};
/* </settings checks> */
/* <settings checks> */
static bool
auth_settings_set_self_ips(struct auth_settings *set, pool_t pool,
			   const char **error_r)
{
	const char *const *tmp;
	ARRAY(struct ip_addr) ips_array;
	struct ip_addr *ips;
	unsigned int ips_count;
	int ret;

	if (*set->proxy_self == '\0') {
		set->proxy_self_ips = p_new(pool, struct ip_addr, 1);
		return TRUE;
	}

	p_array_init(&ips_array, pool, 4);
	tmp = t_strsplit_spaces(set->proxy_self, " ");
	for (; *tmp != NULL; tmp++) {
		ret = net_gethostbyname(*tmp, &ips, &ips_count);
		if (ret != 0) {
			*error_r = t_strdup_printf("auth_proxy_self_ips: "
				"gethostbyname(%s) failed: %s",
				*tmp, net_gethosterror(ret));
		}
		array_append(&ips_array, ips, ips_count);
	}
	array_append_zero(&ips_array);
	set->proxy_self_ips = array_front(&ips_array);
	return TRUE;
}

static bool
auth_verify_verbose_password(struct auth_settings *set,
			     const char **error_r)
{
	const char *p, *value = set->verbose_passwords;
	unsigned int num;

	p = strchr(value, ':');
	if (p != NULL) {
		if (str_to_uint(p+1, &num) < 0 || num == 0) {
			*error_r = t_strdup_printf("auth_verbose_passwords: "
				"Invalid truncation number: '%s'", p+1);
			return FALSE;
		}
		value = t_strdup_until(value, p);
	}
	if (strcmp(value, "no") == 0)
		return TRUE;
	else if (strcmp(value, "plain") == 0)
		return TRUE;
	else if (strcmp(value, "sha1") == 0)
		return TRUE;
	else if (strcmp(value, "yes") == 0) {
		/* just use it as alias for "plain" */
		set->verbose_passwords = "plain";
		return TRUE;
	} else {
		*error_r = "auth_verbose_passwords: Invalid value";
		return FALSE;
	}
}

static bool auth_settings_check(void *_set, pool_t pool,
				const char **error_r)
{
	struct auth_settings *set = _set;
	const char *p;

	if (set->debug_passwords)
		set->debug = TRUE;
	if (set->debug)
		set->verbose = TRUE;

	if (set->worker_max_count == 0) {
		*error_r = "auth_worker_max_count must be above zero";
		return FALSE;
	}

	if (set->cache_size > 0 && set->cache_size < 1024) {
		/* probably a configuration error.
		   older versions used megabyte numbers */
		*error_r = t_strdup_printf("auth_cache_size value is too small "
					   "(%"PRIuUOFF_T" bytes)",
					   set->cache_size);
		return FALSE;
	}

	if (!auth_verify_verbose_password(set, error_r))
		return FALSE;

	if (*set->username_chars == '\0') {
		/* all chars are allowed */
		memset(set->username_chars_map, 1,
		       sizeof(set->username_chars_map));
	} else {
		for (p = set->username_chars; *p != '\0'; p++)
			set->username_chars_map[(int)(uint8_t)*p] = 1;
	}

	if (*set->username_translation != '\0') {
		p = set->username_translation;
		for (; *p != '\0' && p[1] != '\0'; p += 2)
			set->username_translation_map[(int)(uint8_t)*p] = p[1];
	}
	set->realms_arr =
		(const char *const *)p_strsplit_spaces(pool, set->realms, " ");

	if (*set->policy_server_url != '\0') {
		if (*set->policy_hash_nonce == '\0') {

			*error_r = "auth_policy_hash_nonce must be set when policy server is used";
			return FALSE;
		}
		const struct hash_method *digest = hash_method_lookup(set->policy_hash_mech);
		if (digest == NULL) {
			*error_r = "invalid auth_policy_hash_mech given";
			return FALSE;
		}
		if (set->policy_hash_truncate > 0 && set->policy_hash_truncate >= digest->digest_size*8) {
			*error_r = t_strdup_printf("policy_hash_truncate is not smaller than digest size (%u >= %u)",
				set->policy_hash_truncate,
				digest->digest_size*8);
			return FALSE;
		}
	}

	if (!auth_settings_set_self_ips(set, pool, error_r))
		return FALSE;
	return TRUE;
}

static bool
auth_passdb_settings_check(void *_set, pool_t pool ATTR_UNUSED,
			   const char **error_r)
{
	struct auth_passdb_settings *set = _set;

	if (set->driver == NULL || *set->driver == '\0') {
		*error_r = "passdb is missing driver";
		return FALSE;
	}
	if (set->pass && strcmp(set->result_success, "return-ok") != 0) {
		*error_r = "Obsolete pass=yes setting mixed with non-default result_success";
		return FALSE;
	}
	return TRUE;
}

static bool
auth_userdb_settings_check(void *_set, pool_t pool ATTR_UNUSED,
			   const char **error_r)
{
	struct auth_userdb_settings *set = _set;

	if (set->driver == NULL || *set->driver == '\0') {
		*error_r = "userdb is missing driver";
		return FALSE;
	}
	return TRUE;
}
/* </settings checks> */
struct service_settings auth_service_settings = {
	.name = "auth",
	.protocol = "",
	.type = "",
	.executable = "auth",
	.user = "$default_internal_user",
	.group = "",
	.privileged_group = "",
	.extra_groups = "",
	.chroot = "",

	.drop_priv_before_exec = FALSE,

	.process_min_avail = 0,
	.process_limit = 1,
	.client_limit = 0,
	.service_count = 0,
	.idle_kill = 0,
	.vsz_limit = UOFF_T_MAX,

	.unix_listeners = { { &auth_unix_listeners_buf,
			      sizeof(auth_unix_listeners[0]) } },
	.fifo_listeners = ARRAY_INIT,
	.inet_listeners = ARRAY_INIT,

	.process_limit_1 = TRUE
};
struct service_settings auth_worker_service_settings = {
	.name = "auth-worker",
	.protocol = "",
	.type = "worker",
	.executable = "auth -w",
	.user = "",
	.group = "",
	.privileged_group = "",
	.extra_groups = "",
	.chroot = "",

	.drop_priv_before_exec = FALSE,

	.process_min_avail = 0,
	.process_limit = 0,
	.client_limit = 1,
	.service_count = 0,
	.idle_kill = 0,
	.vsz_limit = UOFF_T_MAX,

	.unix_listeners = { { &auth_worker_unix_listeners_buf,
			      sizeof(auth_worker_unix_listeners[0]) } },
	.fifo_listeners = ARRAY_INIT,
	.inet_listeners = ARRAY_INIT
};
#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type(#name, name, struct auth_passdb_settings)
static const struct setting_define auth_passdb_setting_defines[] = {
	DEF(STR, name),
	DEF(STR, driver),
	DEF(STR, args),
	DEF(STR, default_fields),
	DEF(STR, override_fields),
	DEF(STR, mechanisms),
	DEF(STR, username_filter),

	DEF(ENUM, skip),
	DEF(ENUM, result_success),
	DEF(ENUM, result_failure),
	DEF(ENUM, result_internalfail),

	DEF(BOOL, deny),
	DEF(BOOL, pass),
	DEF(BOOL, master),
	DEF(ENUM, auth_verbose),

	SETTING_DEFINE_LIST_END
};
static const struct auth_passdb_settings auth_passdb_default_settings = {
	.name = "",
	.driver = "",
	.args = "",
	.default_fields = "",
	.override_fields = "",
	.mechanisms = "",
	.username_filter = "",

	.skip = "never:authenticated:unauthenticated",
	.result_success = "return-ok:return:return-fail:continue:continue-ok:continue-fail",
	.result_failure = "continue:return:return-ok:return-fail:continue-ok:continue-fail",
	.result_internalfail = "continue:return:return-ok:return-fail:continue-ok:continue-fail",

	.deny = FALSE,
	.pass = FALSE,
	.master = FALSE,
	.auth_verbose = "default:yes:no"
};
const struct setting_parser_info auth_passdb_setting_parser_info = {
	.defines = auth_passdb_setting_defines,
	.defaults = &auth_passdb_default_settings,

	.type_offset = offsetof(struct auth_passdb_settings, name),
	.struct_size = sizeof(struct auth_passdb_settings),

	.parent_offset = SIZE_MAX,
	.parent = &auth_setting_parser_info,

	.check_func = auth_passdb_settings_check
};
#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type(#name, name, struct auth_userdb_settings)
static const struct setting_define auth_userdb_setting_defines[] = {
	DEF(STR, name),
	DEF(STR, driver),
	DEF(STR, args),
	DEF(STR, default_fields),
	DEF(STR, override_fields),

	DEF(ENUM, skip),
	DEF(ENUM, result_success),
	DEF(ENUM, result_failure),
	DEF(ENUM, result_internalfail),

	DEF(ENUM, auth_verbose),

	SETTING_DEFINE_LIST_END
};
static const struct auth_userdb_settings auth_userdb_default_settings = {
	/* NOTE: when adding fields, update also auth.c:userdb_dummy_set */
	.name = "",
	.driver = "",
	.args = "",
	.default_fields = "",
	.override_fields = "",

	.skip = "never:found:notfound",
	.result_success = "return-ok:return:return-fail:continue:continue-ok:continue-fail",
	.result_failure = "continue:return:return-ok:return-fail:continue-ok:continue-fail",
	.result_internalfail = "continue:return:return-ok:return-fail:continue-ok:continue-fail",

	.auth_verbose = "default:yes:no"
};
const struct setting_parser_info auth_userdb_setting_parser_info = {
	.defines = auth_userdb_setting_defines,
	.defaults = &auth_userdb_default_settings,

	.type_offset = offsetof(struct auth_userdb_settings, name),
	.struct_size = sizeof(struct auth_userdb_settings),

	.parent_offset = SIZE_MAX,
	.parent = &auth_setting_parser_info,

	.check_func = auth_userdb_settings_check
};
#undef DEF
#undef DEF_NOPREFIX
#undef DEFLIST
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type("auth_"#name, name, struct auth_settings)
#define DEF_NOPREFIX(type, name) \
	SETTING_DEFINE_STRUCT_##type(#name, name, struct auth_settings)
#define DEFLIST(field, name, defines) \
	{ .type = SET_DEFLIST, .key = name, \
	  .offset = offsetof(struct auth_settings, field), \
	  .list_info = defines }
static const struct setting_define auth_setting_defines[] = {
	DEF(STR, mechanisms),
	DEF(STR, realms),
	DEF(STR, default_realm),
	DEF(SIZE, cache_size),
	DEF(TIME, cache_ttl),
	DEF(TIME, cache_negative_ttl),
	DEF(BOOL, cache_verify_password_with_worker),
	DEF(STR, username_chars),
	DEF(STR, username_translation),
	DEF(STR, username_format),
	DEF(STR, master_user_separator),
	DEF(STR, anonymous_username),
	DEF(STR, krb5_keytab),
	DEF(STR, gssapi_hostname),
	DEF(STR, winbind_helper_path),
	DEF(STR, proxy_self),
	DEF(TIME, failure_delay),

	DEF(STR, policy_server_url),
	DEF(STR, policy_server_api_header),
	DEF(UINT, policy_server_timeout_msecs),
	DEF(STR, policy_hash_mech),
	DEF(STR, policy_hash_nonce),
	DEF(STR, policy_request_attributes),
	DEF(BOOL, policy_reject_on_fail),
	DEF(BOOL, policy_check_before_auth),
	DEF(BOOL, policy_check_after_auth),
	DEF(BOOL, policy_report_after_auth),
	DEF(BOOL, policy_log_only),
	DEF(UINT, policy_hash_truncate),

	DEF(BOOL, stats),
	DEF(BOOL, verbose),
	DEF(BOOL, debug),
	DEF(BOOL, debug_passwords),
	DEF(STR, verbose_passwords),
	DEF(BOOL, ssl_require_client_cert),
	DEF(BOOL, ssl_username_from_cert),
	DEF(BOOL, use_winbind),

	DEF(UINT, worker_max_count),

	DEFLIST(passdbs, "passdb", &auth_passdb_setting_parser_info),
	DEFLIST(userdbs, "userdb", &auth_userdb_setting_parser_info),

	DEF_NOPREFIX(STR, base_dir),
	DEF_NOPREFIX(BOOL, verbose_proctitle),
	DEF_NOPREFIX(UINT, first_valid_uid),
	DEF_NOPREFIX(UINT, last_valid_uid),
	DEF_NOPREFIX(UINT, first_valid_gid),
	DEF_NOPREFIX(UINT, last_valid_gid),

	DEF_NOPREFIX(STR, ssl_client_ca_dir),
	DEF_NOPREFIX(STR, ssl_client_ca_file),

	SETTING_DEFINE_LIST_END
};
static const struct auth_settings auth_default_settings = {
	.mechanisms = "plain",
	.realms = "",
	.default_realm = "",
	.cache_size = 0,
	.cache_ttl = 60*60,
	.cache_negative_ttl = 60*60,
	.cache_verify_password_with_worker = FALSE,
	.username_chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ01234567890.-_@",
	.username_translation = "",
	.username_format = "%Lu",
	.master_user_separator = "",
	.anonymous_username = "anonymous",
	.krb5_keytab = "",
	.gssapi_hostname = "",
	.winbind_helper_path = "/usr/bin/ntlm_auth",
	.proxy_self = "",
	.failure_delay = 2,

	.policy_server_url = "",
	.policy_server_api_header = "",
	.policy_server_timeout_msecs = 2000,
	.policy_hash_mech = "sha256",
	.policy_hash_nonce = "",
	.policy_request_attributes = "login=%{requested_username} pwhash=%{hashed_password} remote=%{rip} device_id=%{client_id} protocol=%s session_id=%{session}",
	.policy_reject_on_fail = FALSE,
	.policy_check_before_auth = TRUE,
	.policy_check_after_auth = TRUE,
	.policy_report_after_auth = TRUE,
	.policy_log_only = FALSE,
	.policy_hash_truncate = 12,

	.stats = FALSE,
	.verbose = FALSE,
	.debug = FALSE,
	.debug_passwords = FALSE,
	.verbose_passwords = "no",
	.ssl_require_client_cert = FALSE,
	.ssl_username_from_cert = FALSE,
	.ssl_client_ca_dir = "",
	.ssl_client_ca_file = "",

	.use_winbind = FALSE,

	.worker_max_count = 30,

	.passdbs = ARRAY_INIT,
	.userdbs = ARRAY_INIT,

	.base_dir = PKG_RUNDIR,
	.verbose_proctitle = FALSE,
	.first_valid_uid = 500,
	.last_valid_uid = 0,
	.first_valid_gid = 1,
	.last_valid_gid = 0,
};
const struct setting_parser_info auth_setting_parser_info = {
	.module_name = "auth",
	.defines = auth_setting_defines,
	.defaults = &auth_default_settings,

	.type_offset = SIZE_MAX,
	.struct_size = sizeof(struct auth_settings),

	.parent_offset = SIZE_MAX,

	.check_func = auth_settings_check
};
/* ../../src/anvil/anvil-settings.c */
/* <settings checks> */
static struct file_listener_settings anvil_unix_listeners_array[] = {
	{ "anvil", 0600, "", "" },
	{ "anvil-auth-penalty", 0600, "", "" }
};
static struct file_listener_settings *anvil_unix_listeners[] = {
	&anvil_unix_listeners_array[0],
	&anvil_unix_listeners_array[1]
};
static buffer_t anvil_unix_listeners_buf = {
	{ { anvil_unix_listeners, sizeof(anvil_unix_listeners) } }
};
/* </settings checks> */
struct service_settings anvil_service_settings = {
	.name = "anvil",
	.protocol = "",
	.type = "anvil",
	.executable = "anvil",
	.user = "$default_internal_user",
	.group = "",
	.privileged_group = "",
	.extra_groups = "",
	.chroot = "empty",

	.drop_priv_before_exec = FALSE,

	.process_min_avail = 1,
	.process_limit = 1,
	.client_limit = 0,
	.service_count = 0,
	.idle_kill = UINT_MAX,
	.vsz_limit = UOFF_T_MAX,

	.unix_listeners = { { &anvil_unix_listeners_buf,
			      sizeof(anvil_unix_listeners[0]) } },
	.fifo_listeners = ARRAY_INIT,
	.inet_listeners = ARRAY_INIT,

	.process_limit_1 = TRUE
};
static struct service_settings *config_all_services[] = {
#ifdef HAVE_LIBWRAP
	&tcpwrap_service_settings,
#endif
	&health_check_service_settings,
	&submission_service_settings,
	&submission_login_service_settings,
	&stats_service_settings,
	&replicator_service_settings,
	&aggregator_service_settings,
	&pop3_service_settings,
	&pop3_login_service_settings,
	&old_stats_service_settings,
	&log_service_settings,
	&lmtp_service_settings,
	&ipc_service_settings,
	&indexer_worker_service_settings,
	&indexer_service_settings,
	&imap_service_settings,
	&imap_urlauth_worker_service_settings,
	&imap_urlauth_service_settings,
	&imap_urlauth_login_service_settings,
	&imap_login_service_settings,
	&imap_hibernate_service_settings,
	&doveadm_service_settings,
	&dns_client_service_settings,
	&director_service_settings,
	&dict_service_settings,
	&dict_async_service_settings,
	&config_service_settings,
	&auth_service_settings,
	&auth_worker_service_settings,
	&anvil_service_settings,
};
buffer_t config_all_services_buf = {
	{ { config_all_services, sizeof(config_all_services) } }
};
const struct setting_parser_info *all_default_roots[] = {
	&master_service_setting_parser_info,
	&master_service_ssl_setting_parser_info,
	&master_service_ssl_server_setting_parser_info,
	&smtp_submit_setting_parser_info,
	&aggregator_setting_parser_info, 
	&auth_setting_parser_info, 
	&dict_setting_parser_info, 
	&director_setting_parser_info, 
	&doveadm_setting_parser_info, 
	&fs_crypt_setting_parser_info, 
	&imap_login_setting_parser_info, 
	&imap_setting_parser_info, 
	&imap_urlauth_login_setting_parser_info, 
	&imap_urlauth_setting_parser_info, 
	&imap_urlauth_worker_setting_parser_info, 
	&imapc_setting_parser_info, 
	&lda_setting_parser_info, 
	&lmtp_setting_parser_info, 
	&login_setting_parser_info, 
	&mail_storage_setting_parser_info, 
	&mail_user_setting_parser_info, 
	&maildir_setting_parser_info, 
	&master_setting_parser_info, 
	&mbox_setting_parser_info, 
	&mdbox_setting_parser_info, 
	&old_stats_setting_parser_info, 
	&pop3_login_setting_parser_info, 
	&pop3_setting_parser_info, 
	&pop3c_setting_parser_info, 
	&quota_status_setting_parser_info, 
	&replicator_setting_parser_info, 
	&stats_setting_parser_info, 
	&submission_login_setting_parser_info, 
	&submission_setting_parser_info, 
	NULL
};
const struct setting_parser_info *const *all_roots = all_default_roots;
ARRAY_TYPE(service_settings) *default_services = &master_default_settings.services;

/* Copyright (c) 2009-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "buffer.h"
#include "settings-parser.h"
#include "service-settings.h"
#include "stats-settings.h"

static bool stats_metric_settings_check(void *_set, pool_t pool, const char **error_r);

/* <settings checks> */
static struct file_listener_settings stats_unix_listeners_array[] = {
	{ "stats-reader", 0600, "", "" },
	{ "stats-writer", 0660, "", "$default_internal_group" },
};
static struct file_listener_settings *stats_unix_listeners[] = {
	&stats_unix_listeners_array[0],
	&stats_unix_listeners_array[1],
};
static buffer_t stats_unix_listeners_buf = {
	stats_unix_listeners, sizeof(stats_unix_listeners), { NULL, }
};
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
	.chroot = "empty",

	.drop_priv_before_exec = FALSE,

	.process_min_avail = 0,
	.process_limit = 1,
	.client_limit = 0,
	.service_count = 0,
	.idle_kill = UINT_MAX,
	.vsz_limit = (uoff_t)-1,

	.unix_listeners = { { &stats_unix_listeners_buf,
			      sizeof(stats_unix_listeners[0]) } },
	.inet_listeners = ARRAY_INIT,
};

#undef DEF
#define DEF(type, name) \
	{ type, #name, offsetof(struct stats_metric_settings, name), NULL }

static const struct setting_define stats_metric_setting_defines[] = {
	DEF(SET_STR, name),
	DEF(SET_STR, event_name),
	DEF(SET_STR, source_location),
	DEF(SET_STR, categories),
	DEF(SET_STR, fields),
	{ SET_STRLIST, "filter", offsetof(struct stats_metric_settings, filter), NULL },
	SETTING_DEFINE_LIST_END
};

const struct stats_metric_settings stats_metric_default_settings = {
	.name = "",
	.event_name = "",
	.source_location = "",
	.categories = "",
	.fields = "",
};

const struct setting_parser_info stats_metric_setting_parser_info = {
	.defines = stats_metric_setting_defines,
	.defaults = &stats_metric_default_settings,

	.type_offset = offsetof(struct stats_metric_settings, name),
	.struct_size = sizeof(struct stats_metric_settings),

	.parent_offset = (size_t)-1,
	.check_func = stats_metric_settings_check,
};

#undef DEFLIST_UNIQUE
#define DEFLIST_UNIQUE(field, name, defines) \
	{ SET_DEFLIST_UNIQUE, name, \
	  offsetof(struct stats_settings, field), defines }

static const struct setting_define stats_setting_defines[] = {
	DEFLIST_UNIQUE(metrics, "metric", &stats_metric_setting_parser_info),
	SETTING_DEFINE_LIST_END
};

const struct stats_settings stats_default_settings = {
	.metrics = ARRAY_INIT
};

const struct setting_parser_info stats_setting_parser_info = {
	.module_name = "stats",
	.defines = stats_setting_defines,
	.defaults = &stats_default_settings,

	.type_offset = (size_t)-1,
	.struct_size = sizeof(struct stats_settings),

	.parent_offset = (size_t)-1
};

/* <settings checks> */
static bool stats_metric_settings_check(void *_set, pool_t pool ATTR_UNUSED,
					const char **error_r)
{
	struct stats_metric_settings *set = _set;
	const char *p;

	if (set->name[0] == '\0') {
		*error_r = "Metric name can't be empty";
		return FALSE;
	}
	if (set->source_location[0] != '\0') {
		if ((p = strchr(set->source_location, ':')) == NULL) {
			*error_r = "source_location is missing ':'";
			return FALSE;
		}
		if (str_to_uint(p+1, &set->parsed_source_linenum) < 0 ||
		    set->parsed_source_linenum == 0) {
			*error_r = "source_location has invalid line number after ':'";
			return FALSE;
		}
	}
	return TRUE;
}
/* </settings checks> */

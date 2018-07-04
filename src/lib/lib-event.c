/* Copyright (c) 2017-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "lib-event-private.h"
#include "event-filter.h"
#include "array.h"
#include "llist.h"
#include "str.h"
#include "strescape.h"
#include "ioloop.h"

enum event_code {
	EVENT_CODE_ALWAYS_LOG_SOURCE	= 'a',
	EVENT_CODE_CATEGORY		= 'c',
	EVENT_CODE_TV_LAST_SENT		= 'l',
	EVENT_CODE_SENDING_NAME		= 'n',
	EVENT_CODE_SOURCE		= 's',

	EVENT_CODE_FIELD_INTMAX		= 'I',
	EVENT_CODE_FIELD_STR		= 'S',
	EVENT_CODE_FIELD_TIMEVAL	= 'T',
};

extern const struct event_passthrough event_passthrough_vfuncs;

static struct event *events = NULL;
static struct event *current_global_event = NULL;
static struct event_passthrough *event_last_passthrough = NULL;
static ARRAY(event_callback_t *) event_handlers;
static ARRAY(event_category_callback_t *) event_category_callbacks;
static ARRAY(struct event_category *) event_registered_categories;
static ARRAY(struct event *) global_event_stack;
static uint64_t event_id_counter = 0;

static struct event *last_passthrough_event(void)
{
	return container_of(event_last_passthrough,
			    struct event, event_passthrough);
}

static void event_copy_parent_defaults(struct event *event,
				       const struct event *parent)
{
	event->always_log_source = parent->always_log_source;
	event->passthrough = parent->passthrough;
	event->forced_debug = parent->forced_debug;
}

#undef event_create
struct event *event_create(struct event *parent, const char *source_filename,
			   unsigned int source_linenum)
{
	struct event *event;
	pool_t pool = pool_alloconly_create(MEMPOOL_GROWING"event", 64);

	event = p_new(pool, struct event, 1);
	event->event_passthrough = event_passthrough_vfuncs;
	event->refcount = 1;
	event->id = ++event_id_counter;
	event->pool = pool;
	event->tv_created = ioloop_timeval;
	event->source_filename = source_filename;
	event->source_linenum = source_linenum;
	if (parent != NULL) {
		event->parent = parent;
		event_ref(event->parent);
		event_copy_parent_defaults(event, parent);
	}
	DLLIST_PREPEND(&events, event);
	return event;
}

#undef event_create_passthrough
struct event_passthrough *
event_create_passthrough(struct event *parent, const char *source_filename,
			 unsigned int source_linenum)
{
	if (!parent->passthrough) {
		if (event_last_passthrough != NULL) {
			/* API is being used in a wrong or dangerous way */
			i_panic("Can't create multiple passthrough events - finish the earlier with ->event()");
		}
		struct event *event =
			event_create(parent, source_filename, source_linenum);
		event->passthrough = TRUE;
		/* This event only intends to extend the parent event.
		   Use the parent's creation timestamp. */
		event->tv_created = parent->tv_created;
		event_last_passthrough = &event->event_passthrough;
	} else {
		event_last_passthrough = &parent->event_passthrough;
	}
	return event_last_passthrough;
}

static bool
event_send_callbacks(struct event *event, enum event_callback_type type,
		     struct failure_context *ctx, const char *fmt, va_list args)
{
	event_callback_t *const *callbackp;

	array_foreach(&event_handlers, callbackp) {
		bool ret;

		T_BEGIN {
			ret = (*callbackp)(event, type, ctx, fmt, args);
		} T_END;
		if (!ret) {
			/* event sending was stopped */
			return FALSE;
		}
	}
	return TRUE;
}

struct event *event_ref(struct event *event)
{
	i_assert(event->refcount > 0);

	event->refcount++;
	return event;
}

static void event_send_free(struct event *event, ...)
{
	va_list args;

	/* the args are empty and not used for anything, but there doesn't seem
	   to be any nice and standard way of passing an initialized va_list
	   as a parameter without va_start(). */
	va_start(args, event);
	(void)event_send_callbacks(event, EVENT_CALLBACK_TYPE_FREE,
				   NULL, NULL, args);
	va_end(args);
}

void event_unref(struct event **_event)
{
	struct event *event = *_event;

	if (event == NULL)
		return;
	*_event = NULL;

	i_assert(event->refcount > 0);
	if (--event->refcount > 0)
		return;
	i_assert(event != current_global_event);

	if (event->call_free)
		event_send_free(event);

	if (last_passthrough_event() == event)
		event_last_passthrough = NULL;
	if (event->log_prefix_from_system_pool)
		i_free(event->log_prefix);
	i_free(event->sending_name);
	event_unref(&event->parent);

	DLLIST_REMOVE(&events, event);
	pool_unref(&event->pool);
}

struct event *events_get_head(void)
{
	return events;
}

struct event *event_push_global(struct event *event)
{
	if (current_global_event != NULL) {
		if (!array_is_created(&global_event_stack))
			i_array_init(&global_event_stack, 4);
		array_append(&global_event_stack, &current_global_event, 1);
	}
	current_global_event = event;
	return event;
}

struct event *event_pop_global(struct event *event)
{
	i_assert(event != NULL);
	i_assert(event == current_global_event);

	if (!array_is_created(&global_event_stack) ||
	    array_count(&global_event_stack) == 0)
		current_global_event = NULL;
	else {
		unsigned int event_count;
		struct event *const *events =
			array_get(&global_event_stack, &event_count);

		i_assert(event_count > 0);
		current_global_event = events[event_count-1];
		array_delete(&global_event_stack, event_count-1, 1);
	}
	return current_global_event;
}

struct event *event_get_global(void)
{
	return current_global_event;
}

static struct event *
event_set_log_prefix(struct event *event, const char *prefix, bool append)
{
	if (event->log_prefix == NULL) {
		/* allocate the first log prefix from the pool */
		event->log_prefix = p_strdup(event->pool, prefix);
	} else {
		/* log prefix is being updated multiple times -
		   switch to system pool so we don't keep leaking memory */
		if (event->log_prefix_from_system_pool)
			i_free(event->log_prefix);
		else
			event->log_prefix_from_system_pool = TRUE;
		event->log_prefix = i_strdup(prefix);
	}
	event->log_prefix_replace = !append;
	return event;
}

struct event *
event_set_append_log_prefix(struct event *event, const char *prefix)
{
	return event_set_log_prefix(event, prefix, TRUE);
}

struct event *event_replace_log_prefix(struct event *event, const char *prefix)
{
	return event_set_log_prefix(event, prefix, FALSE);
}

struct event *
event_set_name(struct event *event, const char *name)
{
	i_free(event->sending_name);
	event->sending_name = i_strdup(name);
	return event;
}

struct event *
event_set_source(struct event *event, const char *filename,
		 unsigned int linenum, bool literal_fname)
{
	event->source_filename = literal_fname ? filename :
		p_strdup(event->pool, filename);
	event->source_linenum = linenum;
	return event;
}

struct event *event_set_always_log_source(struct event *event)
{
	event->always_log_source = TRUE;
	return event;
}

struct event_category *event_category_find_registered(const char *name)
{
	struct event_category *const *catp;

	array_foreach(&event_registered_categories, catp) {
		if (strcmp((*catp)->name, name) == 0)
			return *catp;
	}
	return NULL;
}

struct event_category *const *
event_get_registered_categories(unsigned int *count_r)
{
	return array_get(&event_registered_categories, count_r);
}

static void event_category_register(struct event_category *category)
{
	event_category_callback_t *const *callbackp;

	if (category->registered)
		return;

	/* register parent categories first */
	if (category->parent != NULL)
		event_category_register(category->parent);

	category->registered = TRUE;
	array_append(&event_registered_categories, &category, 1);

	array_foreach(&event_category_callbacks, callbackp) T_BEGIN {
		(*callbackp)(category);
	} T_END;
}

static bool
event_find_category(struct event *event, const struct event_category *category)
{
	struct event_category *const *categoryp;

	array_foreach(&event->categories, categoryp) {
		if (*categoryp == category)
			return TRUE;
	}
	return FALSE;
}

struct event *
event_add_categories(struct event *event,
		     struct event_category *const *categories)
{
	if (!array_is_created(&event->categories))
		p_array_init(&event->categories, event->pool, 4);

	for (unsigned int i = 0; categories[i] != NULL; i++) {
		event_category_register(categories[i]);
		if (!event_find_category(event, categories[i]))
			array_append(&event->categories, &categories[i], 1);
	}
	return event;
}

struct event *
event_add_category(struct event *event, struct event_category *category)
{
	struct event_category *const categories[] = { category, NULL };
	return event_add_categories(event, categories);
}

static struct event_field *
event_find_field_int(struct event *event, const char *key)
{
	struct event_field *field;

	if (!array_is_created(&event->fields))
		return NULL;

	array_foreach_modifiable(&event->fields, field) {
		if (strcmp(field->key, key) == 0)
			return field;
	}
	return NULL;
}

const struct event_field *
event_find_field(struct event *event, const char *key)
{
	const struct event_field *field = event_find_field_int(event, key);
	if (field != NULL || event->parent == NULL)
		return field;
	return event_find_field(event->parent, key);
}

const char *
event_find_field_str(struct event *event, const char *key)
{
	const struct event_field *field;

	field = event_find_field(event, key);
	if (field == NULL)
		return NULL;

	switch (field->value_type) {
	case EVENT_FIELD_VALUE_TYPE_STR:
		return field->value.str;
	case EVENT_FIELD_VALUE_TYPE_INTMAX:
		return dec2str(field->value.intmax);
	case EVENT_FIELD_VALUE_TYPE_TIMEVAL:
		return t_strdup_printf("%"PRIdTIME_T".%u",
				       field->value.timeval.tv_sec,
				       (unsigned int)field->value.timeval.tv_usec);
	}
	i_unreached();
}

static struct event_field *
event_get_field(struct event *event, const char *key)
{
	struct event_field *field;

	field = event_find_field_int(event, key);
	if (field == NULL) {
		if (!array_is_created(&event->fields))
			p_array_init(&event->fields, event->pool, 8);
		field = array_append_space(&event->fields);
		field->key = p_strdup(event->pool, key);
	}
	return field;
}

struct event *
event_add_str(struct event *event, const char *key, const char *value)
{
	struct event_field *field;

	field = event_get_field(event, key);
	field->value_type = EVENT_FIELD_VALUE_TYPE_STR;
	i_zero(&field->value);
	field->value.str = p_strdup(event->pool, value);
	return event;
}

struct event *
event_add_int(struct event *event, const char *key, intmax_t num)
{
	struct event_field *field;

	field = event_get_field(event, key);
	field->value_type = EVENT_FIELD_VALUE_TYPE_INTMAX;
	i_zero(&field->value);
	field->value.intmax = num;
	return event;
}

struct event *
event_add_timeval(struct event *event, const char *key,
		  const struct timeval *tv)
{
	struct event_field *field;

	field = event_get_field(event, key);
	field->value_type = EVENT_FIELD_VALUE_TYPE_TIMEVAL;
	i_zero(&field->value);
	field->value.timeval = *tv;
	return event;
}

struct event *
event_add_fields(struct event *event,
		 const struct event_add_field *fields)
{
	for (unsigned int i = 0; fields[i].key != NULL; i++) {
		if (fields[i].value != NULL)
			event_add_str(event, fields[i].key, fields[i].value);
		else if (fields[i].value_timeval.tv_sec != 0)
			event_add_timeval(event, fields[i].key, &fields[i].value_timeval);
		else
			event_add_int(event, fields[i].key, fields[i].value_intmax);
	}
	return event;
}

struct event *event_get_parent(struct event *event)
{
	return event->parent;
}

void event_get_create_time(struct event *event, struct timeval *tv_r)
{
	*tv_r = event->tv_created;
}

bool event_get_last_send_time(struct event *event, struct timeval *tv_r)
{
	*tv_r = event->tv_last_sent;
	return tv_r->tv_sec != 0;
}

const struct event_field *
event_get_fields(struct event *event, unsigned int *count_r)
{
	if (!array_is_created(&event->fields)) {
		*count_r = 0;
		return NULL;
	}
	return array_get(&event->fields, count_r);
}

struct event_category *const *
event_get_categories(struct event *event, unsigned int *count_r)
{
	if (!array_is_created(&event->categories)) {
		*count_r = 0;
		return NULL;
	}
	return array_get(&event->categories, count_r);
}

void event_send(struct event *event, struct failure_context *ctx,
		const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	event_vsend(event, ctx, fmt, args);
	va_end(args);
}

void event_vsend(struct event *event, struct failure_context *ctx,
		 const char *fmt, va_list args)
{
	event->tv_last_sent = ioloop_timeval;
	if (event_send_callbacks(event, EVENT_CALLBACK_TYPE_EVENT,
				 ctx, fmt, args)) {
		if (ctx->type != LOG_TYPE_DEBUG ||
		    event->sending_debug_log)
			i_log_typev(ctx, fmt, args);
	}
	event_send_abort(event);
}

void event_send_abort(struct event *event)
{
	/* if the event is sent again, it needs a new name */
	i_free(event->sending_name);
	if (event->passthrough)
		event_unref(&event);
}

static void
event_export_field_value(string_t *dest, const struct event_field *field)
{
	switch (field->value_type) {
	case EVENT_FIELD_VALUE_TYPE_STR:
		str_append_c(dest, EVENT_CODE_FIELD_STR);
		str_append_tabescaped(dest, field->key);
		str_append_c(dest, '\t');
		str_append_tabescaped(dest, field->value.str);
		break;
	case EVENT_FIELD_VALUE_TYPE_INTMAX:
		str_append_c(dest, EVENT_CODE_FIELD_INTMAX);
		str_append_tabescaped(dest, field->key);
		str_printfa(dest, "\t%jd", field->value.intmax);
		break;
	case EVENT_FIELD_VALUE_TYPE_TIMEVAL:
		str_append_c(dest, EVENT_CODE_FIELD_TIMEVAL);
		str_append_tabescaped(dest, field->key);
		str_printfa(dest, "\t%"PRIdTIME_T"\t%u",
			    field->value.timeval.tv_sec,
			    (unsigned int)field->value.timeval.tv_usec);
		break;
	}
}

void event_export(const struct event *event, string_t *dest)
{
	/* required fields: */
	str_printfa(dest, "%"PRIdTIME_T"\t%u",
		    event->tv_created.tv_sec,
		    (unsigned int)event->tv_created.tv_usec);

	/* optional fields: */
	if (event->source_filename != NULL) {
		str_append_c(dest, '\t');
		str_append_c(dest, EVENT_CODE_SOURCE);
		str_append_tabescaped(dest, event->source_filename);
		str_printfa(dest, "\t%u", event->source_linenum);
	}
	if (event->always_log_source) {
		str_append_c(dest, '\t');
		str_append_c(dest, EVENT_CODE_ALWAYS_LOG_SOURCE);
	}
	if (event->tv_last_sent.tv_sec != 0) {
		str_printfa(dest, "\t%c%"PRIdTIME_T"\t%u",
			    EVENT_CODE_TV_LAST_SENT,
			    event->tv_last_sent.tv_sec,
			    (unsigned int)event->tv_last_sent.tv_usec);
	}
	if (event->sending_name != NULL) {
		str_append_c(dest, '\t');
		str_append_c(dest, EVENT_CODE_SENDING_NAME);
		str_append_tabescaped(dest, event->sending_name);
	}

	if (array_is_created(&event->categories)) {
		struct event_category *const *catp;
		array_foreach(&event->categories, catp) {
			str_append_c(dest, '\t');
			str_append_c(dest, EVENT_CODE_CATEGORY);
			str_append_tabescaped(dest, (*catp)->name);
		}
	}

	if (array_is_created(&event->fields)) {
		const struct event_field *field;
		array_foreach(&event->fields, field) {
			str_append_c(dest, '\t');
			event_export_field_value(dest, field);
		}
	}
}

bool event_import(struct event *event, const char *str, const char **error_r)
{
	return event_import_unescaped(event, t_strsplit_tabescaped(str), error_r);
}

static bool event_import_tv(const char *arg_secs, const char *arg_usecs,
			    struct timeval *tv_r, const char **error_r)
{
	unsigned int usecs;

	if (str_to_time(arg_secs, &tv_r->tv_sec) < 0) {
		*error_r = "Invalid timeval seconds parameter";
		return FALSE;
	}

	if (arg_usecs == NULL) {
		*error_r = "Timeval missing microseconds parameter";
		return FALSE;
	}
	if (str_to_uint(arg_usecs, &usecs) < 0 || usecs >= 1000000) {
		*error_r = "Invalid timeval microseconds parameter";
		return FALSE;
	}
	tv_r->tv_usec = usecs;
	return TRUE;
}

bool event_import_unescaped(struct event *event, const char *const *args,
			    const char **error_r)
{
	const char *error;

	/* required fields: */
	if (args[0] == NULL) {
		*error_r = "Missing required fields";
		return FALSE;
	}
	if (!event_import_tv(args[0], args[1], &event->tv_created, &error)) {
		*error_r = t_strdup_printf("Invalid tv_created: %s", error);
		return FALSE;
	}
	args += 2;

	/* optional fields: */
	while (*args != NULL) {
		const char *arg = *args;
		enum event_code code = arg[0];

		arg++;
		switch (code) {
		case EVENT_CODE_ALWAYS_LOG_SOURCE:
			event->always_log_source = TRUE;
			break;
		case EVENT_CODE_CATEGORY: {
			struct event_category *category =
				event_category_find_registered(arg);
			if (category == NULL) {
				*error_r = t_strdup_printf("Unregistered category: '%s'", arg);
				return FALSE;
			}
			if (!array_is_created(&event->categories))
				p_array_init(&event->categories, event->pool, 4);
			array_append(&event->categories, &category, 1);
			break;
		}
		case EVENT_CODE_TV_LAST_SENT:
			if (!event_import_tv(arg, args[1], &event->tv_last_sent, &error)) {
				*error_r = t_strdup_printf("Invalid tv_last_sent: %s", error);
				return FALSE;
			}
			args++;
			break;
		case EVENT_CODE_SENDING_NAME:
			i_free(event->sending_name);
			event->sending_name = i_strdup(arg);
			break;
		case EVENT_CODE_SOURCE:
			event->source_filename = p_strdup(event->pool, arg);
			if (args[1] == NULL) {
				*error_r = "Source line number missing";
				return FALSE;
			}
			if (str_to_uint(args[1], &event->source_linenum) < 0) {
				*error_r = "Invalid Source line number";
				return FALSE;
			}
			args++;
			break;

		case EVENT_CODE_FIELD_INTMAX:
		case EVENT_CODE_FIELD_STR:
		case EVENT_CODE_FIELD_TIMEVAL: {
			struct event_field *field =
				event_get_field(event, arg);
			if (args[1] == NULL) {
				*error_r = "Field value is missing";
				return FALSE;
			}
			args++;
			i_zero(&field->value);
			switch (code) {
			case EVENT_CODE_FIELD_INTMAX:
				field->value_type = EVENT_FIELD_VALUE_TYPE_INTMAX;
				if (str_to_intmax(*args, &field->value.intmax) < 0) {
					*error_r = t_strdup_printf(
						"Invalid field value '%s' number for '%s'",
						*args, field->key);
					return FALSE;
				}
				break;
			case EVENT_CODE_FIELD_STR:
				field->value_type = EVENT_FIELD_VALUE_TYPE_STR;
				field->value.str = p_strdup(event->pool, *args);
				break;
			case EVENT_CODE_FIELD_TIMEVAL:
				field->value_type = EVENT_FIELD_VALUE_TYPE_TIMEVAL;
				if (!event_import_tv(args[0], args[1],
						     &field->value.timeval, &error)) {
					*error_r = t_strdup_printf(
						"Field '%s' value '%s': %s",
						field->key, args[1], error);
					return FALSE;
				}
				args++;
				break;
			default:
				i_unreached();
			}
			break;
		}
		}
		args++;
	}
	return TRUE;
}

void event_register_callback(event_callback_t *callback)
{
	array_append(&event_handlers, &callback, 1);
}

void event_unregister_callback(event_callback_t *callback)
{
	event_callback_t *const *callbackp;

	array_foreach(&event_handlers, callbackp) {
		if (*callbackp == callback) {
			array_delete(&event_handlers,
				     array_foreach_idx(&event_handlers, callbackp), 1);
			return;
		}
	}
	i_unreached();
}

void event_category_register_callback(event_category_callback_t *callback)
{
	array_append(&event_category_callbacks, &callback, 1);
}

void event_category_unregister_callback(event_category_callback_t *callback)
{
	event_category_callback_t *const *callbackp;

	array_foreach(&event_category_callbacks, callbackp) {
		if (*callbackp == callback) {
			array_delete(&event_category_callbacks,
				     array_foreach_idx(&event_category_callbacks, callbackp), 1);
			return;
		}
	}
	i_unreached();
}

static void event_category_remove_from_array(struct event_category *category)
{
	struct event_category *const *catp;

	array_foreach(&event_registered_categories, catp) {
		if (*catp == category) {
			array_delete(&event_registered_categories,
				array_foreach_idx(&event_registered_categories, catp), 1);
			return;
		}
	}
	i_unreached();
}

void event_category_unregister(struct event_category *category)
{
	event_category_callback_t *const *callbackp;

	if (!category->registered) {
		/* it was never registered in the first place - ignore */
		return;
	}

	category->registered = FALSE;
	event_category_remove_from_array(category);

	array_foreach(&event_category_callbacks, callbackp) T_BEGIN {
		(*callbackp)(category);
	} T_END;
}

static struct event_passthrough *
event_passthrough_set_append_log_prefix(const char *prefix)
{
	event_set_append_log_prefix(last_passthrough_event(), prefix);
	return event_last_passthrough;
}

static struct event_passthrough *
event_passthrough_replace_log_prefix(const char *prefix)
{
	event_replace_log_prefix(last_passthrough_event(), prefix);
	return event_last_passthrough;
}

static struct event_passthrough *
event_passthrough_set_name(const char *name)
{
	event_set_name(last_passthrough_event(), name);
	return event_last_passthrough;
}

static struct event_passthrough *
event_passthrough_set_source(const char *filename,
			     unsigned int linenum, bool literal_fname)
{
	event_set_source(last_passthrough_event(), filename,
			 linenum, literal_fname);
	return event_last_passthrough;
}

static struct event_passthrough *
event_passthrough_set_always_log_source(void)
{
	event_set_always_log_source(last_passthrough_event());
	return event_last_passthrough;
}

static struct event_passthrough *
event_passthrough_add_categories(struct event_category *const *categories)
{
	event_add_categories(last_passthrough_event(), categories);
	return event_last_passthrough;
}

static struct event_passthrough *
event_passthrough_add_category(struct event_category *category)
{
	event_add_category(last_passthrough_event(), category);
	return event_last_passthrough;
}

static struct event_passthrough *
event_passthrough_add_fields(const struct event_add_field *fields)
{
	event_add_fields(last_passthrough_event(), fields);
	return event_last_passthrough;
}

static struct event_passthrough *
event_passthrough_add_str(const char *key, const char *value)
{
	event_add_str(last_passthrough_event(), key, value);
	return event_last_passthrough;
}

static struct event_passthrough *
event_passthrough_add_int(const char *key, intmax_t num)
{
	event_add_int(last_passthrough_event(), key, num);
	return event_last_passthrough;
}

static struct event_passthrough *
event_passthrough_add_timeval(const char *key, const struct timeval *tv)
{
	event_add_timeval(last_passthrough_event(), key, tv);
	return event_last_passthrough;
}

static struct event *event_passthrough_event(void)
{
	struct event *event = last_passthrough_event();
	event_last_passthrough = NULL;
	return event;
}

const struct event_passthrough event_passthrough_vfuncs = {
	event_passthrough_set_append_log_prefix,
	event_passthrough_replace_log_prefix,
	event_passthrough_set_name,
	event_passthrough_set_source,
	event_passthrough_set_always_log_source,
	event_passthrough_add_categories,
	event_passthrough_add_category,
	event_passthrough_add_fields,
	event_passthrough_add_str,
	event_passthrough_add_int,
	event_passthrough_add_timeval,
	event_passthrough_event,
};

void lib_event_init(void)
{
	i_array_init(&event_handlers, 4);
	i_array_init(&event_category_callbacks, 4);
	i_array_init(&event_registered_categories, 16);
}

void lib_event_deinit(void)
{
	event_unset_global_debug_log_filter();
	event_unset_global_debug_send_filter();
	for (struct event *event = events; event != NULL; event = event->next) {
		i_warning("Event %p leaked (parent=%p): %s:%u",
			  event, event->parent,
			  event->source_filename, event->source_linenum);
	}
	array_free(&event_handlers);
	array_free(&event_category_callbacks);
	array_free(&event_registered_categories);
}

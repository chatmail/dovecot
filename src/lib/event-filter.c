/* Copyright (c) 2017-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "llist.h"
#include "str.h"
#include "strescape.h"
#include "wildcard-match.h"
#include "lib-event-private.h"
#include "event-filter.h"
#include "event-filter-private.h"

/* Note: this has to match the regexp behavior in the event filter lexer file */
#define event_filter_append_escaped(dst, str) \
	str_append_escaped((dst), (str), strlen(str))

enum event_filter_code {
	EVENT_FILTER_CODE_NAME		= 'n',
	EVENT_FILTER_CODE_SOURCE	= 's',
	EVENT_FILTER_CODE_CATEGORY	= 'c',
	EVENT_FILTER_CODE_FIELD		= 'f',
};

/* map <log type> to <event filter log type & name> */
static const struct log_type_map {
	enum event_filter_log_type log_type;
	const char *name;
} event_filter_log_type_map[] = {
	[LOG_TYPE_DEBUG]   = { EVENT_FILTER_LOG_TYPE_DEBUG, "debug" },
	[LOG_TYPE_INFO]    = { EVENT_FILTER_LOG_TYPE_INFO, "info" },
	[LOG_TYPE_WARNING] = { EVENT_FILTER_LOG_TYPE_WARNING, "warning" },
	[LOG_TYPE_ERROR]   = { EVENT_FILTER_LOG_TYPE_ERROR, "error" },
	[LOG_TYPE_FATAL]   = { EVENT_FILTER_LOG_TYPE_FATAL, "fatal" },
	[LOG_TYPE_PANIC]   = { EVENT_FILTER_LOG_TYPE_PANIC, "panic" },
};

struct event_filter_query_internal {
	struct event_filter_node *expr;
	void *context;
};

struct event_filter {
	struct event_filter *prev, *next;

	pool_t pool;
	int refcount;
	ARRAY(struct event_filter_query_internal) queries;

	bool fragment;
	bool named_queries_only;
};

static struct event_filter *event_filters = NULL;

static struct event_filter *event_filter_create_real(pool_t pool, bool fragment)
{
	struct event_filter *filter;

	filter = p_new(pool, struct event_filter, 1);
	filter->pool = pool;
	filter->refcount = 1;
	filter->named_queries_only = TRUE;
	filter->fragment = fragment;
	p_array_init(&filter->queries, pool, 4);
	if (!fragment)
		DLLIST_PREPEND(&event_filters, filter);
	return filter;
}

struct event_filter *event_filter_create(void)
{
	return event_filter_create_real(pool_alloconly_create("event filter", 2048), FALSE);
}

struct event_filter *event_filter_create_fragment(pool_t pool)
{
	return event_filter_create_real(pool, TRUE);
}

void event_filter_ref(struct event_filter *filter)
{
	i_assert(filter->refcount > 0);
	filter->refcount++;
}

void event_filter_unref(struct event_filter **_filter)
{
	struct event_filter *filter = *_filter;

	if (filter == NULL)
		return;
	i_assert(filter->refcount > 0);

	*_filter = NULL;
	if (--filter->refcount > 0)
		return;

	if (!filter->fragment) {
		DLLIST_REMOVE(&event_filters, filter);

		/* fragments' pools are freed by the consumer */
		pool_unref(&filter->pool);
	}
}

int event_filter_parse(const char *str, struct event_filter *filter,
		       const char **error_r)
{
	struct event_filter_query_internal *int_query;
	struct event_filter_parser_state state;
	int ret;

	i_zero(&state);
	state.input = str;
	state.len = strlen(str);
	state.pos = 0;
	state.pool = filter->pool;

	event_filter_parser_lex_init(&state.scanner);
	event_filter_parser_set_extra(&state, state.scanner);

	ret = event_filter_parser_parse(&state);

	event_filter_parser_lex_destroy(state.scanner);

	if ((ret == 0) && (state.output != NULL)) {
		/* success - non-NULL expression */
		i_assert(state.error == NULL);

		int_query = array_append_space(&filter->queries);
		int_query->context = NULL;
		int_query->expr = state.output;

		filter->named_queries_only = filter->named_queries_only && state.has_event_name;
	} else if (ret != 0) {
		/* error */
		i_assert(state.error != NULL);

		*error_r = state.error;
	}

	/*
	 * Note that success with a NULL expression output is possible, but
	 * turns into a no-op.
	 */

	return (ret != 0) ? -1 : 0;
}

bool event_filter_category_to_log_type(const char *name,
				       enum event_filter_log_type *log_type_r)
{
	unsigned int i;

	for (i = 0; i < N_ELEMENTS(event_filter_log_type_map); i++) {
		if (strcmp(name, event_filter_log_type_map[i].name) == 0) {
			*log_type_r = event_filter_log_type_map[i].log_type;
			return TRUE;
		}
	}
	return FALSE;
}

const char *
event_filter_category_from_log_type(enum event_filter_log_type log_type)
{
	unsigned int i;

	for (i = 0; i < N_ELEMENTS(event_filter_log_type_map); i++) {
		if (event_filter_log_type_map[i].log_type == log_type)
			return event_filter_log_type_map[i].name;
	}
	i_unreached();
}

static void add_node(pool_t pool, struct event_filter_node **root,
		     struct event_filter_node *new)
{
	struct event_filter_node *parent;

	if (*root == NULL) {
		*root = new;
		return;
	}

	parent = p_new(pool, struct event_filter_node, 1);
	parent->type = EVENT_FILTER_NODE_TYPE_LOGIC;
	parent->op = EVENT_FILTER_OP_AND;
	parent->children[0] = *root;
	parent->children[1] = new;

	*root = parent;
}

static void
event_filter_add_categories(pool_t pool,
			    struct event_filter_query_internal *int_query,
			    const char *const *categories)
{
	unsigned int categories_count = str_array_length(categories);
	unsigned int i;

	if (categories_count == 0)
		return;

	for (i = 0; i < categories_count; i++) {
		struct event_filter_node *node;

		node = p_new(pool, struct event_filter_node, 1);
		node->type = EVENT_FILTER_NODE_TYPE_EVENT_CATEGORY;
		node->op = EVENT_FILTER_OP_CMP_EQ;
		if (!event_filter_category_to_log_type(categories[i], &node->category.log_type)) {
			node->category.name = p_strdup(pool, categories[i]);
			node->category.ptr = event_category_find_registered(categories[i]);
		}

		add_node(pool, &int_query->expr, node);
	}
}

static void
event_filter_add_fields(pool_t pool,
			struct event_filter_query_internal *int_query,
			const struct event_filter_field *fields)
{
	unsigned int i;

	if (fields == NULL)
		return;

	for (i = 0; fields[i].key != NULL; i++) {
		struct event_filter_node *node;

		node = p_new(pool, struct event_filter_node, 1);
		node->type = EVENT_FILTER_NODE_TYPE_EVENT_FIELD;
		node->op = EVENT_FILTER_OP_CMP_EQ;
		node->field.key = p_strdup(pool, fields[i].key);
		node->field.value.str = p_strdup(pool, fields[i].value);

		/* Filter currently supports only comparing strings
		   and numbers. */
		if (str_to_intmax(fields[i].value, &node->field.value.intmax) < 0) {
			/* not a number - no problem
			   Either we have a string, or a number with wildcards */
			node->field.value.intmax = INT_MIN;
		}

		add_node(pool, &int_query->expr, node);
	}
}

void event_filter_add(struct event_filter *filter,
		      const struct event_filter_query *query)
{
	struct event_filter_query_internal *int_query;

	int_query = array_append_space(&filter->queries);
	int_query->context = query->context;
	int_query->expr = NULL;

	if (query->name != NULL) {
		struct event_filter_node *node;

		node = p_new(filter->pool, struct event_filter_node, 1);
		node->type = EVENT_FILTER_NODE_TYPE_EVENT_NAME;
		node->op = EVENT_FILTER_OP_CMP_EQ;
		node->str = p_strdup(filter->pool, query->name);

		add_node(filter->pool, &int_query->expr, node);
	} else {
		filter->named_queries_only = FALSE;
	}

	if ((query->source_filename != NULL) && (query->source_filename[0] != '\0')) {
		struct event_filter_node *node;

		node = p_new(filter->pool, struct event_filter_node, 1);
		node->type = EVENT_FILTER_NODE_TYPE_EVENT_SOURCE_LOCATION;
		node->op = EVENT_FILTER_OP_CMP_EQ;
		node->str = p_strdup(filter->pool, query->source_filename);
		node->intmax = query->source_linenum;

		add_node(filter->pool, &int_query->expr, node);
	}

	event_filter_add_categories(filter->pool, int_query, query->categories);
	event_filter_add_fields(filter->pool, int_query, query->fields);
}

static struct event_filter_node *
clone_expr(pool_t pool, struct event_filter_node *old)
{
	struct event_filter_node *new;

	if (old == NULL)
		return NULL;

	new = p_new(pool, struct event_filter_node, 1);
	new->type = old->type;
	new->op = old->op;
	new->children[0] = clone_expr(pool, old->children[0]);
	new->children[1] = clone_expr(pool, old->children[1]);
	new->str = p_strdup(pool, old->str);
	new->intmax = old->intmax;
	new->category.log_type = old->category.log_type;
	new->category.name = p_strdup(pool, old->category.name);
	new->category.ptr = old->category.ptr;
	new->field.key = p_strdup(pool, old->field.key);
	new->field.value_type = old->field.value_type;
	new->field.value.str = p_strdup(pool, old->field.value.str);
	new->field.value.intmax = old->field.value.intmax;
	new->field.value.timeval = old->field.value.timeval;

	return new;
}

static void
event_filter_merge_with_context_internal(struct event_filter *dest,
					 const struct event_filter *src,
					 void *new_context, bool with_context)
{
	const struct event_filter_query_internal *int_query;

	array_foreach(&src->queries, int_query) T_BEGIN {
		struct event_filter_query_internal *new;

		new = array_append_space(&dest->queries);
		new->expr = clone_expr(dest->pool, int_query->expr);
		new->context = with_context ? new_context : int_query->context;
	} T_END;
}

void event_filter_merge(struct event_filter *dest,
			const struct event_filter *src)
{
	event_filter_merge_with_context_internal(dest, src, NULL, FALSE);
}

void event_filter_merge_with_context(struct event_filter *dest,
				     const struct event_filter *src,
				     void *new_context)
{
	event_filter_merge_with_context_internal(dest, src, new_context, TRUE);
}

static const char *
event_filter_export_query_expr_op(enum event_filter_node_op op)
{
	switch (op) {
	case EVENT_FILTER_OP_AND:
	case EVENT_FILTER_OP_OR:
	case EVENT_FILTER_OP_NOT:
		i_unreached();
	case EVENT_FILTER_OP_CMP_EQ:
		return "=";
	case EVENT_FILTER_OP_CMP_GT:
		return ">";
	case EVENT_FILTER_OP_CMP_LT:
		return "<";
	case EVENT_FILTER_OP_CMP_GE:
		return ">=";
	case EVENT_FILTER_OP_CMP_LE:
		return "<=";
	}

	i_unreached();
}

static void
event_filter_export_query_expr(const struct event_filter_query_internal *query,
			       struct event_filter_node *node,
			       string_t *dest)
{
	switch (node->type) {
	case EVENT_FILTER_NODE_TYPE_LOGIC:
		str_append_c(dest, '(');
		switch (node->op) {
		case EVENT_FILTER_OP_AND:
			event_filter_export_query_expr(query, node->children[0], dest);
			str_append(dest, " AND ");
			event_filter_export_query_expr(query, node->children[1], dest);
			break;
		case EVENT_FILTER_OP_OR:
			event_filter_export_query_expr(query, node->children[0], dest);
			str_append(dest, " OR ");
			event_filter_export_query_expr(query, node->children[1], dest);
			break;
		case EVENT_FILTER_OP_NOT:
			str_append(dest, "NOT ");
			event_filter_export_query_expr(query, node->children[0], dest);
			break;
		case EVENT_FILTER_OP_CMP_EQ:
		case EVENT_FILTER_OP_CMP_GT:
		case EVENT_FILTER_OP_CMP_LT:
		case EVENT_FILTER_OP_CMP_GE:
		case EVENT_FILTER_OP_CMP_LE:
			i_unreached();
		}
		str_append_c(dest, ')');
		break;
	case EVENT_FILTER_NODE_TYPE_EVENT_NAME:
		str_append(dest, "event");
		str_append(dest, event_filter_export_query_expr_op(node->op));
		str_append_c(dest, '"');
		event_filter_append_escaped(dest, node->str);
		str_append_c(dest, '"');
		break;
	case EVENT_FILTER_NODE_TYPE_EVENT_SOURCE_LOCATION:
		str_append(dest, "source_location");
		str_append(dest, event_filter_export_query_expr_op(node->op));
		str_append_c(dest, '"');
		event_filter_append_escaped(dest, node->str);
		if (node->intmax != 0)
			str_printfa(dest, ":%ju", node->intmax);
		str_append_c(dest, '"');
		break;
	case EVENT_FILTER_NODE_TYPE_EVENT_CATEGORY:
		str_append(dest, "category");
		str_append(dest, event_filter_export_query_expr_op(node->op));
		if (node->category.name != NULL) {
			str_append_c(dest, '"');
			event_filter_append_escaped(dest, node->category.name);
			str_append_c(dest, '"');
		} else
			str_append(dest, event_filter_category_from_log_type(node->category.log_type));
		break;
	case EVENT_FILTER_NODE_TYPE_EVENT_FIELD:
		str_append_c(dest, '"');
		event_filter_append_escaped(dest, node->field.key);
		str_append_c(dest, '"');
		str_append(dest, event_filter_export_query_expr_op(node->op));
		str_append_c(dest, '"');
		event_filter_append_escaped(dest, node->field.value.str);
		str_append_c(dest, '"');
		break;
	}
}

static void
event_filter_export_query(const struct event_filter_query_internal *query,
			  string_t *dest)
{
	str_append_c(dest, '(');
	event_filter_export_query_expr(query, query->expr, dest);
	str_append_c(dest, ')');
}

void event_filter_export(struct event_filter *filter, string_t *dest)
{
	const struct event_filter_query_internal *query;
	bool first = TRUE;

	array_foreach(&filter->queries, query) {
		if (!first)
			str_append(dest, " OR ");
		first = FALSE;
		event_filter_export_query(query, dest);
	}
}

struct event_filter_node *
event_filter_get_expr_for_testing(struct event_filter *filter,
				  unsigned int *count_r)
{
	const struct event_filter_query_internal *queries;

	queries = array_get(&filter->queries, count_r);

	return (*count_r == 0) ? NULL : queries[0].expr;
}

static bool
event_category_match(const struct event_category *category,
		     const struct event_category *wanted_category)
{
	for (; category != NULL; category = category->parent) {
		if (category->internal == wanted_category->internal)
			return TRUE;
	}
	return FALSE;
}

static bool
event_has_category(struct event *event, struct event_filter_node *node,
		   enum event_filter_log_type log_type)
{
	struct event_category *wanted_category = node->category.ptr;
	struct event_category *const *catp;

	/* category is a log type */
	if (node->category.name == NULL)
		return (node->category.log_type & log_type) != 0;

	/* category not registered, therefore the event cannot have it */
	if (wanted_category == NULL)
		return FALSE;

	while (event != NULL) {
		if (array_is_created(&event->categories)) {
			array_foreach(&event->categories, catp) {
				if (event_category_match(*catp, wanted_category))
					return TRUE;
			}
		}
		/* try also the parent events */
		event = event_get_parent(event);
	}
	return FALSE;
}

static bool
event_match_field(struct event *event, const struct event_field *wanted_field,
		  enum event_filter_node_op op)
{
	const struct event_field *field;

	/* wanted_field has the value in all available formats */
	while ((field = event_find_field(event, wanted_field->key)) == NULL) {
		event = event_get_parent(event);
		if (event == NULL) {
			/* field="" matches nonexistent field */
			return wanted_field->value.str[0] == '\0';
		}
	}
	switch (field->value_type) {
	case EVENT_FIELD_VALUE_TYPE_STR:
		if (op != EVENT_FILTER_OP_CMP_EQ) {
			/* we only support string equality comparisons */
			return FALSE;
		}
		if (field->value.str[0] == '\0') {
			/* field was removed, but it matches field="" filter */
			return wanted_field->value.str[0] == '\0';
		}
		return wildcard_match_icase(field->value.str, wanted_field->value.str);
	case EVENT_FIELD_VALUE_TYPE_INTMAX:
		if (wanted_field->value.intmax > INT_MIN) {
			/* compare against an integer */
			switch (op) {
			case EVENT_FILTER_OP_CMP_EQ:
				return field->value.intmax == wanted_field->value.intmax;
			case EVENT_FILTER_OP_CMP_GT:
				return field->value.intmax > wanted_field->value.intmax;
			case EVENT_FILTER_OP_CMP_LT:
				return field->value.intmax < wanted_field->value.intmax;
			case EVENT_FILTER_OP_CMP_GE:
				return field->value.intmax >= wanted_field->value.intmax;
			case EVENT_FILTER_OP_CMP_LE:
				return field->value.intmax <= wanted_field->value.intmax;
			case EVENT_FILTER_OP_AND:
			case EVENT_FILTER_OP_OR:
			case EVENT_FILTER_OP_NOT:
				i_unreached();
			}
			i_unreached();
		} else {
			/* compare against an "integer" with wildcards */
			if (op != EVENT_FILTER_OP_CMP_EQ) {
				/* we only support string equality comparisons */
				return FALSE;
			}
			char tmp[MAX_INT_STRLEN];
			i_snprintf(tmp, sizeof(tmp), "%jd", field->value.intmax);
			return wildcard_match_icase(tmp, wanted_field->value.str);
		}
	case EVENT_FIELD_VALUE_TYPE_TIMEVAL:
		/* there's no point to support matching exact timestamps */
		return FALSE;
	}
	i_unreached();
}

static bool
event_filter_query_match_cmp(struct event_filter_node *node,
			     struct event *event, const char *source_filename,
			     unsigned int source_linenum,
			     enum event_filter_log_type log_type)
{
	i_assert((node->op == EVENT_FILTER_OP_CMP_EQ) ||
		 (node->op == EVENT_FILTER_OP_CMP_GT) ||
		 (node->op == EVENT_FILTER_OP_CMP_LT) ||
		 (node->op == EVENT_FILTER_OP_CMP_GE) ||
		 (node->op == EVENT_FILTER_OP_CMP_LE));

	switch (node->type) {
		case EVENT_FILTER_NODE_TYPE_LOGIC:
			i_unreached();
		case EVENT_FILTER_NODE_TYPE_EVENT_NAME:
			return (event->sending_name != NULL) &&
			       wildcard_match(event->sending_name, node->str);
		case EVENT_FILTER_NODE_TYPE_EVENT_SOURCE_LOCATION:
			return !((source_linenum != node->intmax &&
				  node->intmax != 0) ||
				 source_filename == NULL ||
				 strcmp(event->source_filename, node->str) != 0);
		case EVENT_FILTER_NODE_TYPE_EVENT_CATEGORY:
			return event_has_category(event, node, log_type);
		case EVENT_FILTER_NODE_TYPE_EVENT_FIELD:
			return event_match_field(event, &node->field, node->op);
	}

	i_unreached();
}

bool
event_filter_query_match_eval(struct event_filter_node *node,
			      struct event *event, const char *source_filename,
			      unsigned int source_linenum,
			      enum event_filter_log_type log_type)
{
	switch (node->op) {
	case EVENT_FILTER_OP_CMP_EQ:
	case EVENT_FILTER_OP_CMP_GT:
	case EVENT_FILTER_OP_CMP_LT:
	case EVENT_FILTER_OP_CMP_GE:
	case EVENT_FILTER_OP_CMP_LE:
		return event_filter_query_match_cmp(node, event, source_filename,
						    source_linenum, log_type);
	case EVENT_FILTER_OP_AND:
		return event_filter_query_match_eval(node->children[0], event,
						     source_filename, source_linenum,
						     log_type) &&
		       event_filter_query_match_eval(node->children[1], event,
						     source_filename, source_linenum,
						     log_type);
	case EVENT_FILTER_OP_OR:
		return event_filter_query_match_eval(node->children[0], event,
						     source_filename, source_linenum,
						     log_type) ||
		       event_filter_query_match_eval(node->children[1], event,
						     source_filename, source_linenum,
						     log_type);
	case EVENT_FILTER_OP_NOT:
		return !event_filter_query_match_eval(node->children[0], event,
						      source_filename, source_linenum,
						      log_type);
	}

	i_unreached();
}

static bool
event_filter_query_match(const struct event_filter_query_internal *query,
			 struct event *event, const char *source_filename,
			 unsigned int source_linenum,
			 const struct failure_context *ctx)
{
	enum event_filter_log_type log_type;

	i_assert(ctx->type < N_ELEMENTS(event_filter_log_type_map));
	log_type = event_filter_log_type_map[ctx->type].log_type;

	return event_filter_query_match_eval(query->expr, event, source_filename,
					     source_linenum, log_type);
}

static bool
event_filter_match_fastpath(struct event_filter *filter, struct event *event)
{
	if (filter->named_queries_only && event->sending_name == NULL) {
		/* No debug logging is enabled. Only named events may be wanted
		   for stats. This event doesn't have a name, so we don't need
		   to check any further. */
		return FALSE;
	}
	return TRUE;
}

bool event_filter_match(struct event_filter *filter, struct event *event,
			const struct failure_context *ctx)
{
	return event_filter_match_source(filter, event, event->source_filename,
					 event->source_linenum, ctx);
}

bool event_filter_match_source(struct event_filter *filter, struct event *event,
			       const char *source_filename,
			       unsigned int source_linenum,
			       const struct failure_context *ctx)
{
	const struct event_filter_query_internal *query;

	i_assert(!filter->fragment);

	if (!event_filter_match_fastpath(filter, event))
		return FALSE;

	array_foreach(&filter->queries, query) {
		if (event_filter_query_match(query, event, source_filename,
					     source_linenum, ctx))
			return TRUE;
	}
	return FALSE;
}

struct event_filter_match_iter {
	struct event_filter *filter;
	struct event *event;
	const struct failure_context *failure_ctx;
	unsigned int idx;
};

struct event_filter_match_iter *
event_filter_match_iter_init(struct event_filter *filter, struct event *event,
			     const struct failure_context *ctx)
{
	struct event_filter_match_iter *iter;

	i_assert(!filter->fragment);

	iter = i_new(struct event_filter_match_iter, 1);
	iter->filter = filter;
	iter->event = event;
	iter->failure_ctx = ctx;
	if (!event_filter_match_fastpath(filter, event))
		iter->idx = UINT_MAX;
	return iter;
}

void *event_filter_match_iter_next(struct event_filter_match_iter *iter)
{
	const struct event_filter_query_internal *queries;
	unsigned int count;

	queries = array_get(&iter->filter->queries, &count);
	while (iter->idx < count) {
		const struct event_filter_query_internal *query =
			&queries[iter->idx];

		iter->idx++;
		if (query->context != NULL &&
		    event_filter_query_match(query, iter->event,
					     iter->event->source_filename,
					     iter->event->source_linenum,
					     iter->failure_ctx))
			return query->context;
	}
	return NULL;
}

void event_filter_match_iter_deinit(struct event_filter_match_iter **_iter)
{
	struct event_filter_match_iter *iter = *_iter;

	*_iter = NULL;
	i_free(iter);
}

static void
event_filter_query_update_category(struct event_filter_query_internal *query,
				   struct event_filter_node *node,
				   struct event_category *category,
				   bool add)
{
	if (node == NULL)
		return;

	switch (node->type) {
	case EVENT_FILTER_NODE_TYPE_LOGIC:
		event_filter_query_update_category(query, node->children[0], category, add);
		event_filter_query_update_category(query, node->children[1], category, add);
		break;
	case EVENT_FILTER_NODE_TYPE_EVENT_NAME:
	case EVENT_FILTER_NODE_TYPE_EVENT_SOURCE_LOCATION:
	case EVENT_FILTER_NODE_TYPE_EVENT_FIELD:
		break;
	case EVENT_FILTER_NODE_TYPE_EVENT_CATEGORY:
		if (node->category.name == NULL)
			break; /* log type */

		if (add) {
			if (node->category.ptr != NULL)
				break;

			if (strcmp(node->category.name, category->name) == 0)
				node->category.ptr = category;
		} else {
			if (node->category.ptr == category)
				node->category.ptr = NULL;
		}
		break;
	}
}

static void event_filter_category_registered(struct event_category *category)
{
	const bool add = category->internal != NULL;
	struct event_filter_query_internal *query;
	struct event_filter *filter;

	for (filter = event_filters; filter != NULL; filter = filter->next) {
		array_foreach_modifiable(&filter->queries, query) {
			event_filter_query_update_category(query, query->expr,
							   category, add);
		}
	}
}

void event_filter_init(void)
{
	event_category_register_callback(event_filter_category_registered);
}

void event_filter_deinit(void)
{
	event_category_unregister_callback(event_filter_category_registered);
}

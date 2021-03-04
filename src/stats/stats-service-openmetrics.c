/* Copyright (c) 2019 Dovecot authors, see the included COPYING file */

#include "stats-common.h"
#include "dovecot-version.h"
#include "str.h"
#include "array.h"
#include "json-parser.h"
#include "ioloop.h"
#include "ostream.h"
#include "stats-dist.h"
#include "http-server.h"
#include "client-http.h"
#include "stats-settings.h"
#include "stats-metrics.h"
#include "stats-service-private.h"

#define OPENMETRICS_CONTENT_VERSION "0.0.1"

#ifdef DOVECOT_REVISION
#define OPENMETRICS_BUILD_INFO \
	"version=\""DOVECOT_VERSION"\"," \
	"revision=\""DOVECOT_REVISION"\""
#else
#define OPENMETRICS_BUILD_INFO \
	"version=\""DOVECOT_VERSION"\""
#endif

enum openmetrics_metric_type {
	OPENMETRICS_METRIC_TYPE_COUNT,
	OPENMETRICS_METRIC_TYPE_DURATION,
	OPENMETRICS_METRIC_TYPE_HISTOGRAM,
};

enum openmetrics_request_state {
	OPENMETRICS_REQUEST_STATE_INIT = 0,
	OPENMETRICS_REQUEST_STATE_METRIC,
	OPENMETRICS_REQUEST_STATE_METRIC_HEADER,
	OPENMETRICS_REQUEST_STATE_SUB_METRICS,
	OPENMETRICS_REQUEST_STATE_METRIC_BODY,
	OPENMETRICS_REQUEST_STATE_FINISHED,
};

struct openmetrics_request_sub_metric {
	size_t labels_pos;
	const struct metric *metric;
	unsigned int sub_index;
};

struct openmetrics_request {
	struct ostream *output;

	enum openmetrics_request_state state;
	struct stats_metrics_iter *stats_iter;
	const struct metric *metric;
	enum openmetrics_metric_type metric_type;
	string_t *labels;
	size_t labels_pos;
	ARRAY(struct openmetrics_request_sub_metric) sub_metric_stack;

	bool has_submetric:1;
};

/* https://prometheus.io/docs/concepts/data_model/#metric-names-and-labels:

   Every time series is uniquely identified by its metric name and optional
   key-value pairs called labels.

   The metric name specifies the general feature of a system that is measured
   (e.g. http_requests_total - the total number of HTTP requests received). It
   may contain ASCII letters and digits, as well as underscores and colons. It
   must match the regex [a-zA-Z_:][a-zA-Z0-9_:]*.
 */

static bool openmetrics_check_name(const char *name)
{
	const unsigned char *p, *pend;

	p = (const unsigned char *)name;
	pend = p + strlen(name);

	if (p == pend)
		return FALSE;

	if (!(*p >= 'a' && *p <= 'z') && !(*p >= 'A' && *p <= 'Z') &&
	    *p != '_' && *p != ':')
		return FALSE;
	p++;
	while (p < pend) {
		if (!(*p >= 'a' && *p <= 'z') && !(*p >= 'A' && *p <= 'Z') &&
		    !(*p >= '0' && *p <= '9') && *p != '_' && *p != ':')
			return FALSE;
		p++;
	}
	return TRUE;
}

static void openmetrics_export_dovecot(string_t *out)
{
	i_assert(stats_startup_time <= ioloop_time);
	str_append(out, "# HELP process_start_time_seconds "
			"Timestamp of service start\n");
	str_append(out, "# TYPE process_start_time_seconds gauge\n");
	str_printfa(out, "process_start_time_seconds %"PRIdTIME_T"\n",
		    stats_startup_time);

	str_append(out, "# HELP dovecot_build "
			"Dovecot build information\n");
	str_append(out, "# TYPE dovecot_build info\n");
	str_append(out, "dovecot_build_info{"OPENMETRICS_BUILD_INFO"} 1\n");
}

static void openmetrics_export_eof(string_t *out)
{
	str_append(out, "# EOF\n");
}

static void
openmetrics_export_metric_value(struct openmetrics_request *req, string_t *out,
				const struct metric *metric)
{
	/* Metric name */
	str_append(out, "dovecot_");
	str_append(out, req->metric->name);
	switch (req->metric_type) {
	case OPENMETRICS_METRIC_TYPE_COUNT:
		if (req->metric->group_by != NULL && str_len(req->labels) == 0)
			str_append(out, "_count");
		else
			str_append(out, "_total");
		break;
	case OPENMETRICS_METRIC_TYPE_DURATION:
		if (req->metric->group_by != NULL && str_len(req->labels) == 0)
			str_append(out, "_duration_seconds_sum");
		else
			str_append(out, "_duration_seconds_total");
		break;
	case OPENMETRICS_METRIC_TYPE_HISTOGRAM:
		i_unreached();
	}
	/* Labels */
	if (str_len(req->labels) > 0) {
		str_append_c(out, '{');
		str_append_str(out, req->labels);
		str_append_c(out, '}');
	}
	/* Value */
	switch (req->metric_type) {
	case OPENMETRICS_METRIC_TYPE_COUNT:
		str_printfa(out, " %u\n",
			    stats_dist_get_count(metric->duration_stats));
		break;
	case OPENMETRICS_METRIC_TYPE_DURATION:
		/* Convert from microseconds to seconds */
		str_printfa(out, " %.6f\n",
			    stats_dist_get_sum(metric->duration_stats)/1e6F);
		break;
	case OPENMETRICS_METRIC_TYPE_HISTOGRAM:
		i_unreached();
	}
}

static const struct metric *
openmetrics_find_histogram_bucket(const struct metric *metric,
				 unsigned int index)
{
	struct metric *const *sub_metric_p;

	if (!array_is_created(&metric->sub_metrics))
		return NULL;

	array_foreach(&metric->sub_metrics, sub_metric_p) {
		struct metric *sub_metric = *sub_metric_p;

		if (sub_metric->group_value.type !=
		    METRIC_VALUE_TYPE_BUCKET_INDEX)
			continue;
		if (sub_metric->group_value.intmax == index)
			return sub_metric;
	}

	return NULL;
}

static void
openmetrics_export_histogram_bucket(struct openmetrics_request *req,
				    string_t *out, const struct metric *metric,
				    intmax_t bucket_limit, int64_t count)
{
	/* Metric name */
	str_append(out, "dovecot_");
	str_append(out, metric->name);
	str_append(out, "_bucket");
	/* Labels */
	str_append_c(out, '{');
	if (str_len(req->labels) > 0) {
		str_append_str(out, req->labels);
		str_append_c(out, ',');
	}
	if (bucket_limit == INTMAX_MAX)
		str_append(out, "le=\"+Inf\"");
	else if (strcmp(metric->group_by->field,
			STATS_EVENT_FIELD_NAME_DURATION) == 0) {
		/* Convert from microseconds to seconds */
		str_printfa(out, "le=\"%.6f\"", bucket_limit/1e6F);
	} else {
		str_printfa(out, "le=\"%jd\"", bucket_limit);
	}
	str_printfa(out, "} %"PRIu64"\n", count);
}

static void
openmetrics_export_histogram(struct openmetrics_request *req, string_t *out,
			     const struct metric *metric)
{
	const struct stats_metric_settings_group_by *group_by =
		metric->group_by;
	float sum = 0;
	uint64_t count = 0;

	/* Buckets */
	for (unsigned int i = 0; i < group_by->num_ranges; i++) {
		const struct metric *sub_metric =
			openmetrics_find_histogram_bucket(metric, i);

		if (sub_metric != NULL) {
			sum += stats_dist_get_sum(sub_metric->duration_stats);
			count += stats_dist_get_count(
				sub_metric->duration_stats);
		}

		openmetrics_export_histogram_bucket(req, out, metric,
						    group_by->ranges[i].max,
						    count);
	}

	/* There is either no data in histogram, which adding the optional
	   sum and count metrics doesn't add any new information or
	   these have already been exported for submetrics. */
	if (count == 0)
		return;

	/* Sum */
	str_append(out, "dovecot_");
	str_append(out, metric->name);
	str_append(out, "_sum");
	/* Labels */
	if (str_len(req->labels) > 0) {
		str_append_c(out, '{');
		str_append_str(out, req->labels);
		str_append_c(out, '}');
	}
	if (strcmp(metric->group_by->field,
		   STATS_EVENT_FIELD_NAME_DURATION) == 0) {
		/* Convert from microseconds to seconds */
		sum /= 1e6F;
	}
	str_printfa(out, " %.6f\n", sum);
	/* Count */
	str_append(out, "dovecot_");
	str_append(out, metric->name);
	str_append(out, "_count");
	/* Labels */
	if (str_len(req->labels) > 0) {
		str_append_c(out, '{');
		str_append_str(out, req->labels);
		str_append_c(out, '}');
	}
	str_printfa(out, " %"PRIu64"\n", count);
}

static void
openmetrics_export_metric_header(struct openmetrics_request *req, string_t *out)
{
	const struct metric *metric = req->metric;

	/* Description */
	str_append(out, "# HELP dovecot_");
	str_append(out, metric->name);
	switch (req->metric_type) {
	case OPENMETRICS_METRIC_TYPE_COUNT:
		str_append(out, " Total number of all events of this kind");
		break;
	case OPENMETRICS_METRIC_TYPE_DURATION:
		str_append(out, "_duration_seconds Total duration of all events of this kind");
		break;
	case OPENMETRICS_METRIC_TYPE_HISTOGRAM:
		str_append(out, " Histogram");
		break;
	}
	if (*metric->set->description != '\0') {
		str_append(out, " of ");
		str_append(out, metric->set->description);
	}
	str_append_c(out, '\n');
	/* Type */
	str_append(out, "# TYPE dovecot_");
	str_append(out, metric->name);
	switch (req->metric_type) {
	case OPENMETRICS_METRIC_TYPE_COUNT:
		str_append(out, " counter\n");
		break;
	case OPENMETRICS_METRIC_TYPE_DURATION:
		str_append(out, "_duration_seconds counter\n");
		break;
	case OPENMETRICS_METRIC_TYPE_HISTOGRAM:
		str_append(out, " histogram\n");
		break;
	}
}

static void
openmetrics_export_submetric(struct openmetrics_request *req, string_t *out,
			     const struct metric *metric)
{
	/* This metric may be a submetric and therefore have a label
	   associated with it. */
	if (metric->sub_name != NULL) {
		str_append_c(req->labels, '"');
		json_append_escaped(req->labels, metric->sub_name);
		str_append_c(req->labels, '"');
	}

	if (req->metric_type == OPENMETRICS_METRIC_TYPE_HISTOGRAM) {
		if (metric->group_by == NULL ||
		    metric->group_by[0].func != STATS_METRIC_GROUPBY_QUANTIZED)
			return;

		openmetrics_export_histogram(req, out, metric);
		return;
	}

	openmetrics_export_metric_value(req, out, metric);

	req->has_submetric = TRUE;
}

static const struct metric *
openmetrics_export_sub_metric_get(struct openmetrics_request_sub_metric *reqsm)
{
	struct metric *const *sub_metric;

	if (reqsm->sub_index >= array_count(&reqsm->metric->sub_metrics))
		return NULL;

	sub_metric = array_idx(&reqsm->metric->sub_metrics, reqsm->sub_index);
	return *sub_metric;
}

static const struct metric *
openmetrics_export_sub_metric_get_next(
	struct openmetrics_request_sub_metric *reqsm)
{
	/* Get the next valid sub-metric */
	reqsm->sub_index++;
	return openmetrics_export_sub_metric_get(reqsm);
}

static struct openmetrics_request_sub_metric *
openmetrics_export_sub_metric_down(struct openmetrics_request *req)
{
	struct openmetrics_request_sub_metric *reqsm =
		array_back_modifiable(&req->sub_metric_stack);
	const struct metric *sub_metric;

	/* Descend further into sub-metric tree */

	if (reqsm->metric->group_by == NULL ||
	    !openmetrics_check_name(reqsm->metric->group_by->field) ||
	    !array_is_created(&reqsm->metric->sub_metrics) ||
	    array_count(&reqsm->metric->sub_metrics) == 0)
		return NULL;
	if (reqsm->metric->group_by[0].func == STATS_METRIC_GROUPBY_QUANTIZED) {
		/* Never descend into quantized group_by sub-metrics.
		   Histograms are exported as a single blob. */
		return NULL;
	}

	/* Find sub-metric to descend into */
	sub_metric = openmetrics_export_sub_metric_get(reqsm);
	if (sub_metric == NULL) {
		/* None valid */
		return NULL;
	}

	if (str_len(req->labels) > 0)
		str_append_c(req->labels, ',');
	str_append(req->labels, reqsm->metric->group_by->field);
	str_append_c(req->labels, '=');
	reqsm->labels_pos = str_len(req->labels);

	/* Descend */
	reqsm = array_append_space(&req->sub_metric_stack);
	reqsm->metric = sub_metric;

	return reqsm;
}

static struct openmetrics_request_sub_metric *
openmetrics_export_sub_metric_up_next(struct openmetrics_request *req)
{
	struct openmetrics_request_sub_metric *reqsm;
	const struct metric *sub_metric = NULL;

	/* Ascend to next sub-metric of an ancestor */

	while (array_count(&req->sub_metric_stack) > 1) {
		/* Ascend */
		array_pop_back(&req->sub_metric_stack);
		reqsm = array_back_modifiable(&req->sub_metric_stack);
		str_truncate(req->labels, reqsm->labels_pos);

		/* Find next sub-metric */
		sub_metric = openmetrics_export_sub_metric_get_next(reqsm);
		if (sub_metric != NULL) {
			/* None valid */
			break;
		}
	}
	if (sub_metric == NULL) {
		/* End of sub-metric tree */
		return NULL;
	}

	/* Descend */
	reqsm = array_append_space(&req->sub_metric_stack);
	reqsm->metric = sub_metric;
	return reqsm;
}

static struct openmetrics_request_sub_metric *
openmetrics_export_sub_metric_current(struct openmetrics_request *req)
{
	struct openmetrics_request_sub_metric *reqsm;

	/* Get state for current sub-metric */

	if (!array_is_created(&req->sub_metric_stack))
		i_array_init(&req->sub_metric_stack, 8);
	if (array_count(&req->sub_metric_stack) >= 2) {
		/* Already walking the sub-metric tree */
		return array_back_modifiable(&req->sub_metric_stack);
	}

	/* Start tree walking */

	reqsm = array_append_space(&req->sub_metric_stack);
	reqsm->metric = req->metric;
	reqsm->labels_pos = str_len(req->labels);

	return openmetrics_export_sub_metric_down(req);
}

static bool
openmetrics_export_sub_metrics(struct openmetrics_request *req, string_t *out)
{
	struct openmetrics_request_sub_metric *reqsm = NULL;

	if (!array_is_created(&req->metric->sub_metrics))
		return TRUE;

	reqsm = openmetrics_export_sub_metric_current(req);
	if (reqsm == NULL) {
		/* No valid sub-metrics to export */
		return TRUE;
	}
	openmetrics_export_submetric(req, out, reqsm->metric);

	/* Try do descend into sub-metrics tree for next sub-metric to export.
	 */
	reqsm = openmetrics_export_sub_metric_down(req);
	if (reqsm == NULL) {
		/* Sub-metrics of this metric exhausted; ascend to the next
		   parent sub-metric.
		 */
		reqsm = openmetrics_export_sub_metric_up_next(req);
	}

	if (reqsm == NULL) {
		/* Finished */
		array_clear(&req->sub_metric_stack);
		return TRUE;
	}
	return FALSE;
}

static void
openmetrics_export_metric_body(struct openmetrics_request *req, string_t *out)
{
	openmetrics_export_metric_value(req, out, req->metric);
}

static int
openmetrics_send_buffer(struct openmetrics_request *req, buffer_t *buffer)
{
	ssize_t sent;

	if (buffer->used == 0)
		return 1;

	sent = o_stream_send(req->output, buffer->data, buffer->used);
	if (sent < 0)
		return -1;

	/* Max buffer size is enormous */
	i_assert((size_t)sent == buffer->used);

	if (o_stream_get_buffer_used_size(req->output) >= IO_BLOCK_SIZE)
		return 0;
	return 1;
}

static bool openmetrics_export_has_histogram(struct openmetrics_request *req)
{
	const struct metric *metric = req->metric;
	unsigned int i;

	if (metric->group_by_count == 0) {
		/* No group_by */
		return FALSE;
	}

	/* We can only support quantized group_by when it is the last group
	   item. */
	for (i = 0; i < (metric->group_by_count - 1); i++) {
		if (metric->group_by[i].func ==
		    STATS_METRIC_GROUPBY_QUANTIZED)
			return FALSE;
	}

	return (metric->group_by[metric->group_by_count - 1].func ==
		STATS_METRIC_GROUPBY_QUANTIZED);
}

static void openmetrics_export_next(struct openmetrics_request *req)
{
	/* Determine what to export next. */
	switch (req->metric_type) {
	case OPENMETRICS_METRIC_TYPE_COUNT:
		/* Continue with duration output for this metric. */
		req->metric_type = OPENMETRICS_METRIC_TYPE_DURATION;
		req->state = OPENMETRICS_REQUEST_STATE_METRIC_HEADER;
		break;
	case OPENMETRICS_METRIC_TYPE_DURATION:
		if (openmetrics_export_has_histogram(req)) {
			/* Continue with histogram output for this metric. */
			req->metric_type = OPENMETRICS_METRIC_TYPE_HISTOGRAM;
			req->state = OPENMETRICS_REQUEST_STATE_METRIC_HEADER;
		} else {
			/* No histogram; continue with next metric */
			req->state = OPENMETRICS_REQUEST_STATE_METRIC;
		}
		break;
	case OPENMETRICS_METRIC_TYPE_HISTOGRAM:
		/* Continue with next metric */
		req->state = OPENMETRICS_REQUEST_STATE_METRIC;
		break;
	}
}

static void
openmetrics_export_continue(struct openmetrics_request *req, string_t *out)
{
	switch (req->state) {
	case OPENMETRICS_REQUEST_STATE_INIT:
		/* Export the Dovecot base metrics. */
		i_assert(req->stats_iter == NULL);
		req->stats_iter = stats_metrics_iterate_init(stats_metrics);
		openmetrics_export_dovecot(out);
		req->state = OPENMETRICS_REQUEST_STATE_METRIC;
		break;
	case OPENMETRICS_REQUEST_STATE_METRIC:
		/* Export the next metric. */
		i_assert(req->stats_iter != NULL);
		do {
			req->metric = stats_metrics_iterate(req->stats_iter);
		} while (req->metric != NULL &&
			 !openmetrics_check_name(req->metric->name));
		if (req->metric == NULL) {
			/* Finished exporting metrics. */
			req->state = OPENMETRICS_REQUEST_STATE_FINISHED;
			break;
		}

		if (req->labels == NULL)
			req->labels = str_new(default_pool, 32);
		else
			str_truncate(req->labels, 0);
		req->labels_pos = 0;

		/* Start with count output for this metric if the type
		   is not histogram. If the metric is of type histogram,
		   start with quantiles. */
		if (openmetrics_export_has_histogram(req))
			req->metric_type = OPENMETRICS_METRIC_TYPE_HISTOGRAM;
		else
			req->metric_type = OPENMETRICS_METRIC_TYPE_COUNT;
		req->state = OPENMETRICS_REQUEST_STATE_METRIC_HEADER;
		/* Fall through */
	case OPENMETRICS_REQUEST_STATE_METRIC_HEADER:
		/* Export the HELP/TYPE header for the current metric */
		str_truncate(req->labels, req->labels_pos);
		req->has_submetric = FALSE;
		openmetrics_export_metric_header(req, out);
		req->state = OPENMETRICS_REQUEST_STATE_SUB_METRICS;
		break;
	case OPENMETRICS_REQUEST_STATE_SUB_METRICS:
		/* Export the sub-metrics for the current metric. This will
		   return for each sub-metric, so that the out string buffer
		   stays small. */
		if (!openmetrics_export_sub_metrics(req, out))
			break;
		/* All sub-metrics written. */
		req->state = OPENMETRICS_REQUEST_STATE_METRIC_BODY;
		break;
	case OPENMETRICS_REQUEST_STATE_METRIC_BODY:
		/* Export the body of the current metric. */
		str_truncate(req->labels, req->labels_pos);
		if (req->metric_type == OPENMETRICS_METRIC_TYPE_HISTOGRAM)
			openmetrics_export_histogram(req, out, req->metric);
		else
			openmetrics_export_metric_body(req, out);
		openmetrics_export_next(req);
		break;
	case OPENMETRICS_REQUEST_STATE_FINISHED:
		i_unreached();
	}
}

static void openmetrics_handle_write_error(struct openmetrics_request *req)
{
	i_info("openmetrics: write(%s) failed: %s",
	       o_stream_get_name(req->output),
	       o_stream_get_error(req->output));
	o_stream_destroy(&req->output);
}

static void openmetrics_request_deinit(struct openmetrics_request *req)
{
	stats_metrics_iterate_deinit(&req->stats_iter);
	str_free(&req->labels);
	array_free(&req->sub_metric_stack);
}

static int openmetrics_export(struct openmetrics_request *req)
{
	string_t *out;
	int ret;

	ret = o_stream_flush(req->output);
	if (ret < 0) {
		openmetrics_handle_write_error(req);
		return -1;
	}
	if (ret == 0) {
		/* Output stream buffer needs to be flushed further */
		return 0;
	}

	if (req->state == OPENMETRICS_REQUEST_STATE_FINISHED) {
		/* All metrics were exported already, so we can finish the
		   HTTP request now. */
		o_stream_destroy(&req->output);
		return 1;
	}

	/* Export metrics into a string buffer and write that buffer to the
	   output stream after each (sub-)metric, so that the string buffer
	   stays small. The output stream buffer can grow bigger, but writing is
	   stopped for later resumption when the output stream buffer has grown
	   beyond an optimal size. */
	out = t_str_new(1024);
	for (;;) {
		str_truncate(out, 0);

		openmetrics_export_continue(req, out);

		ret = openmetrics_send_buffer(req, out);
		if (ret < 0) {
			openmetrics_handle_write_error(req);
			return -1;
		}
		if (req->state == OPENMETRICS_REQUEST_STATE_FINISHED) {
			/* Finished export of metrics, but the output stream
			   buffer may still contain data. */
			break;
		}
		if (ret == 0) {
			/* Output stream buffer is filled up beyond the optimal
			   size; wait until we can write more. */
			return ret;
		}
	}

	/* Send EOF */
	str_truncate(out, 0);
	openmetrics_export_eof(out);
        ret = openmetrics_send_buffer(req, out);
        if (ret < 0) {
            openmetrics_handle_write_error(req);
            return -1;
        }

	/* Cleanup everything except the output stream */
	openmetrics_request_deinit(req);

	/* Finished; flush output */
	ret = o_stream_finish(req->output);
	if (ret < 0) {
		openmetrics_handle_write_error(req);
		return -1;
	}
	return ret;
}

static void openmetrics_request_destroy(struct openmetrics_request *req)
{
	o_stream_destroy(&req->output);
	openmetrics_request_deinit(req);
}

static void
stats_service_openmetrics_request(void *context ATTR_UNUSED,
				  struct http_server_request *hsreq,
				  const char *sub_path)
{
	const struct http_request *hreq = http_server_request_get(hsreq);
	struct http_server_response *hsresp;
	struct openmetrics_request *req;
	pool_t pool;

	if (strcmp(hreq->method, "OPTIONS") == 0) {
		hsresp = http_server_response_create(hsreq, 200, "OK");
		http_server_response_add_header(hsresp, "Allow", "GET");
		http_server_response_submit(hsresp);
		return;
	}
	if (strcmp(hreq->method, "GET") != 0) {
		http_server_request_fail_bad_method(hsreq, "GET");
		return;
	}
	if (*sub_path != '\0') {
		http_server_request_fail(hsreq, 404, "Not Found");
		return;
	}

	pool = http_server_request_get_pool(hsreq);
	req = p_new(pool, struct openmetrics_request, 1);

	http_server_request_set_destroy_callback(
		hsreq, openmetrics_request_destroy, req);

	hsresp = http_server_response_create(hsreq, 200, "OK");
	http_server_response_add_header(
		hsresp, "Content-Type",
		"application/openmetrics-text; version="OPENMETRICS_CONTENT_VERSION"; "
		"charset=utf-8");

	req->output = http_server_response_get_payload_output(
		hsresp, SIZE_MAX, FALSE);

	o_stream_set_flush_callback(req->output, openmetrics_export, req);
	o_stream_set_flush_pending(req->output, TRUE);
}

void stats_service_openmetrics_init(void)
{
	struct stats_metrics_iter *iter;
	const struct metric *metric;

	iter = stats_metrics_iterate_init(stats_metrics);
	while ((metric = stats_metrics_iterate(iter)) != NULL) {
		if (!openmetrics_check_name(metric->name)) {
			i_warning(
				"stats: openmetrics: "
				"Metric `%s' is not valid for OpenMetrics"
				"(invalid metric name; skipped)",
				metric->name);
		}
	}
	stats_metrics_iterate_deinit(&iter);

	stats_http_resource_add("/metrics", "OpenMetrics",
				stats_service_openmetrics_request, NULL);
}

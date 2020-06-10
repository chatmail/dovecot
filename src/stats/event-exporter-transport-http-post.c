/* Copyright (c) 2019 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "str.h"
#include "event-exporter.h"
#include "http-client.h"
#include "iostream-ssl.h"
#include "master-service.h"
#include "master-service-ssl-settings.h"

/* the http client used to export all events with exporter=http-post */
static struct http_client *exporter_http_client;

void event_export_transport_http_post_deinit(void)
{
	if (exporter_http_client != NULL)
		http_client_deinit(&exporter_http_client);
}

static void response_fxn(const struct http_response *response,
			 void *context ATTR_UNUSED)
{
	static time_t last_log;
	static unsigned suppressed;

	if (http_response_is_success(response))
		return;

	if (last_log == ioloop_time) {
		suppressed++;
		return; /* don't spam the log */
	}

	if (suppressed == 0)
		i_error("Failed to export event via HTTP POST: %d %s",
			response->status, response->reason);
	else
		i_error("Failed to export event via HTTP POST: %d %s (%u more errors suppressed)",
			response->status, response->reason, suppressed);

	last_log = ioloop_time;
	suppressed = 0;
}

void event_export_transport_http_post(const struct exporter *exporter,
				      const buffer_t *buf)
{
	struct http_client_request *req;

	if (exporter_http_client == NULL) {
		const struct master_service_ssl_settings *master_ssl_set =
			master_service_ssl_settings_get(master_service);
		struct ssl_iostream_settings ssl_set;
		i_zero(&ssl_set);
		if (master_ssl_set != NULL) {
			master_service_ssl_settings_to_iostream_set(master_ssl_set,
				pool_datastack_create(),
				MASTER_SERVICE_SSL_SETTINGS_TYPE_CLIENT,
				&ssl_set);
		}
		const struct http_client_settings set = {
			.dns_client_socket_path = "dns-client",
			.ssl = &ssl_set,
		};
		exporter_http_client = http_client_init(&set);
	}

	req = http_client_request_url_str(exporter_http_client, "POST",
					  exporter->transport_args,
					  response_fxn, NULL);
	http_client_request_add_header(req, "Content-Type", exporter->format_mime_type);
	http_client_request_set_payload_data(req, buf->data, buf->used);

	http_client_request_set_timeout_msecs(req, exporter->transport_timeout);
	http_client_request_submit(req);
}

/* Copyright (c) 2017-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "ioloop.h"
#include "istream.h"
#include "http-client.h"
#include "http-url.h"
#include "json-parser.h"
#include "oauth2.h"
#include "oauth2-private.h"

static void
oauth2_introspection_callback(struct oauth2_request *req,
			      struct oauth2_introspection_result *res)
{
	i_assert(res->success == (res->error == NULL));
	i_assert(req->is_callback != NULL);
	oauth2_introspection_callback_t *callback = req->is_callback;
	req->is_callback = NULL;
	callback(res, req->is_context);
	oauth2_request_free_internal(req);
}

static void
oauth2_introspect_continue(struct oauth2_request *req, bool success,
			   const char *error)
{
	struct oauth2_introspection_result res;
	i_zero(&res);

	res.success = success;
	res.error = error;
	res.fields = &req->fields;

	oauth2_introspection_callback(req, &res);
}

static void
oauth2_introspect_response(const struct http_response *response,
			   struct oauth2_request *req)
{
	if (response->status / 100 != 2) {
		oauth2_introspect_continue(req, FALSE, response->reason);
	} else {
		if (response->payload == NULL) {
			oauth2_introspect_continue(req, FALSE, "Missing response body");
			return;
		}
		p_array_init(&req->fields, req->pool, 1);
		req->is = response->payload;
		i_stream_ref(req->is);
		req->parser = json_parser_init(req->is);
		req->json_parsed_cb = oauth2_introspect_continue;
		req->io = io_add_istream(req->is, oauth2_parse_json, req);
		oauth2_parse_json(req);
	}
}

static void oauth2_introspection_delayed_error(struct oauth2_request *req)
{
	struct oauth2_introspection_result fail = {
		.success = FALSE,
		.error = req->delayed_error
	};
	oauth2_introspection_callback(req, &fail);
}

#undef oauth2_introspection_start
struct oauth2_request*
oauth2_introspection_start(const struct oauth2_settings *set,
			   const struct oauth2_request_input *input,
			   oauth2_introspection_callback_t *callback,
			   void *context)
{
	i_assert(oauth2_valid_token(input->token));

	pool_t pool = pool_alloconly_create_clean("oauth2 introspection", 1024);
	struct oauth2_request *req =
		p_new(pool, struct oauth2_request, 1);
	struct http_url *url;
	const char *error;

	req->pool = pool;
	req->set = set;
	req->is_callback = callback;
	req->is_context = context;

	string_t *enc = t_str_new(64);
	str_append(enc, req->set->introspection_url);

	if (set->introspection_mode == INTROSPECTION_MODE_GET) {
		http_url_escape_param(enc, input->token);
	}

	if (http_url_parse(str_c(enc), NULL, HTTP_URL_ALLOW_USERINFO_PART, pool,
			   &url, &error) < 0) {
		req->delayed_error = p_strdup_printf(pool,
			"http_url_parse(%s) failed: %s", str_c(enc), error);
		req->to_delayed_error = timeout_add_short(0,
			oauth2_introspection_delayed_error, req);
		return req;
	}

	if (set->introspection_mode == INTROSPECTION_MODE_POST) {
		req->req = http_client_request_url(req->set->client, "POST", url,
						   oauth2_introspect_response,
						   req);
		/* add token */
		enc = t_str_new(strlen(input->token)+6);
		str_append(enc, "token=");
		http_url_escape_param(enc, input->token);
		http_client_request_add_header(req->req, "Content-Type",
					       "application/x-www-form-urlencoded");
		http_client_request_set_payload_data(req->req, enc->data, enc->used);
	} else {
		req->req = http_client_request_url(req->set->client, "GET", url,
						   oauth2_introspect_response,
						   req);
	}

	if (url->user != NULL)
		http_client_request_set_auth_simple(req->req, url->user, url->password);
	else if (set->introspection_mode == INTROSPECTION_MODE_GET_AUTH)
		http_client_request_add_header(req->req,
					       "Authorization",
					       t_strdup_printf("Bearer %s",
							       input->token));
	oauth2_request_set_headers(req, input);

	http_client_request_set_timeout_msecs(req->req,
					      req->set->timeout_msecs);
	http_client_request_submit(req->req);

	return req;
}


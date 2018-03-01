/* Copyright (c) 2017-2018 Dovecot authors, see the included COPYING file */
#ifndef OAUTH2_H
#define OAUTH2_H

#include "net.h"

struct oauth2_request;

struct oauth2_field {
	const char *name;
	const char *value;
};

ARRAY_DEFINE_TYPE(oauth2_field, struct oauth2_field);

struct oauth2_settings {
	struct http_client *client;
	/* GET tokeninfo from this URL, token is appended to URL
	   http://some.host/path?access_token= */
	const char *tokeninfo_url;
	/* GET more information from this URL, uses Bearer authentication */
	const char *introspection_url;
	/* POST refresh here, needs refresh token and client_* settings */
	const char *refresh_url;
	const char *client_id;
	const char *client_secret;
	enum {
		INTROSPECTION_MODE_GET_AUTH,
		INTROSPECTION_MODE_GET,
		INTROSPECTION_MODE_POST
	} introspection_mode;
	unsigned int timeout_msecs;
	/* Should X-Dovecot-Auth-* headers be sent */
	bool send_auth_headers;
};

struct oauth2_token_validation_result {
	ARRAY_TYPE(oauth2_field) *fields;
	const char *error;
	time_t expires_at;
	bool success:1;
	bool valid:1;
};

struct oauth2_introspection_result {
	ARRAY_TYPE(oauth2_field) *fields;
	const char *error;
	bool success:1;
};

struct oauth2_refresh_result {
	ARRAY_TYPE(oauth2_field) *fields;
	const char *bearer_token;
	const char *error;
	time_t expires_at;
	bool success:1;
};

struct oauth2_request_input {
	const char *token;
	const char *service;
	struct ip_addr local_ip, real_local_ip, remote_ip, real_remote_ip;
	in_port_t local_port, real_local_port, remote_port, real_remote_port;
};

typedef void
oauth2_token_validation_callback_t(struct oauth2_token_validation_result*, void*);

typedef void
oauth2_introspection_callback_t(struct oauth2_introspection_result*, void*);

typedef void
oauth2_refresh_callback_t(struct oauth2_refresh_result*, void*);

bool oauth2_valid_token(const char *token);

struct oauth2_request*
oauth2_token_validation_start(const struct oauth2_settings *set,
			      const struct oauth2_request_input *input,
			      oauth2_token_validation_callback_t *callback,
			      void *context);
#define oauth2_token_validation_start(set, input, callback, context) \
	oauth2_token_validation_start(set, input + \
		CALLBACK_TYPECHECK(callback, void(*)(struct oauth2_token_validation_result*, typeof(context))), \
		(oauth2_token_validation_callback_t*)callback, (void*)context);

struct oauth2_request*
oauth2_introspection_start(const struct oauth2_settings *set,
			   const struct oauth2_request_input *input,
			   oauth2_introspection_callback_t *callback,
			   void *context);
#define oauth2_introspection_start(set, input, callback, context) \
	oauth2_introspection_start(set, input + \
		CALLBACK_TYPECHECK(callback, void(*)(struct oauth2_introspection_result*, typeof(context))), \
		(oauth2_introspection_callback_t*)callback, (void*)context);

struct oauth2_request*
oauth2_refresh_start(const struct oauth2_settings *set,
		     const struct oauth2_request_input *input,
		     oauth2_refresh_callback_t *callback,
		     void *context);
#define oauth2_refresh_start(set, input, callback, context) \
	oauth2_refresh_start(set, input + \
		CALLBACK_TYPECHECK(callback, void(*)(struct oauth2_refresh_result*, typeof(context))), \
		(oauth2_refresh_callback_t*)callback, (void*)context);

/* abort without calling callback, use this to cancel the request */
void oauth2_request_abort(struct oauth2_request **);

#endif

#ifndef SASL_SERVER_H
#define SASL_SERVER_H

struct client;

enum sasl_server_reply {
	SASL_SERVER_REPLY_SUCCESS,
	SASL_SERVER_REPLY_AUTH_FAILED,
	SASL_SERVER_REPLY_AUTH_ABORTED,
	SASL_SERVER_REPLY_MASTER_FAILED,
	SASL_SERVER_REPLY_CONTINUE
};

enum sasl_server_auth_flags {
	/* Allow the use of private mechanism */
	SASL_SERVER_AUTH_FLAG_PRIVATE = BIT(0),
	/* Signal to the post-login service that this is an implicit login,
	   meaning that no command success reply is expected. */
	SASL_SERVER_AUTH_FLAG_IMPLICIT = BIT(1),
};

typedef void sasl_server_callback_t(struct client *client,
				    enum sasl_server_reply reply,
				    const char *data, const char *const *args);

const struct auth_mech_desc *
sasl_server_get_advertised_mechs(struct client *client, unsigned int *count_r);
const struct auth_mech_desc *
sasl_server_find_available_mech(struct client *client, const char *name);

void sasl_server_auth_begin(struct client *client,
			    const char *service, const char *mech_name,
			    enum sasl_server_auth_flags flags,
			    const char *initial_resp_base64,
			    sasl_server_callback_t *callback);
void sasl_server_auth_failed(struct client *client, const char *reason,
	const char *code) ATTR_NULL(3);
void sasl_server_auth_abort(struct client *client);

#endif

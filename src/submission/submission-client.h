#ifndef CLIENT_H
#define CLIENT_H

#include "net.h"

struct smtp_reply;

struct submission_recipient;
struct submission_backend;
struct submission_backend_relay;
struct client;

struct client_state {
	pool_t pool;
	enum smtp_server_state state;
	char *args;

	struct submission_backend *backend;
	struct istream *data_input;
	uoff_t data_size;

	bool anonymous_allowed:1;
};

struct client_extra_capability {
	const char *capability;
	const char *params;
};

struct submission_client_vfuncs {
	void (*destroy)(struct client *client);

	void (*trans_start)(struct client *client,
			    struct smtp_server_transaction *trans);
	void (*trans_free)(struct client *client,
			   struct smtp_server_transaction *trans);

	/* Command handlers:

	   These implement the behavior of the various core SMTP commands.
	   SMTP commands are handled asynchronously, which means that the
	   command is not necessarily finished when these handlers end. A
	   command is finished either when 1 is returned or a reply is submitted
	   for it. When a handler returns 0, the command implementation is
	   waiting for an external event and when it returns -1 an error
	   occurred. When 1 is returned, a default success reply is submitted
	   implicitly. Not submitting an error reply when -1 is returned causes
	   an assert fail. See src/lib-smtp/smtp-server.h for details.

	   When overriding these handler vfuncs, the base implementation should
	   usually be called at some point. When it is called immediately, its
	   result can be returned as normal. When the override returns 0, the
	   base implementation would be called at a later time when some
	   external state is achieved. Note that the overriding function then
	   assumes the responsibility to submit the default reply when none is
	   submitted and the base implementation returns 1.
	  */
	int (*cmd_helo)(struct client *client, struct smtp_server_cmd_ctx *cmd,
			struct smtp_server_cmd_helo *data);

	int (*cmd_mail)(struct client *client, struct smtp_server_cmd_ctx *cmd,
			struct smtp_server_cmd_mail *data);
	int (*cmd_rcpt)(struct client *client,
			struct smtp_server_cmd_ctx *cmd,
			struct submission_recipient *srcpt);
	int (*cmd_rset)(struct client *client, struct smtp_server_cmd_ctx *cmd);
	int (*cmd_data)(struct client *client,
			struct smtp_server_cmd_ctx *cmd,
			struct smtp_server_transaction *trans,
			struct istream *data_input, uoff_t data_size);

	int (*cmd_vrfy)(struct client *client, struct smtp_server_cmd_ctx *cmd,
			const char *param);

	int (*cmd_noop)(struct client *client, struct smtp_server_cmd_ctx *cmd);
	int (*cmd_quit)(struct client *client, struct smtp_server_cmd_ctx *cmd);
};

struct client {
	struct client *prev, *next;
	pool_t pool;

	struct submission_client_vfuncs v;

	const struct setting_parser_info *user_set_info;
	const struct submission_settings *set;

	struct smtp_server_connection *conn;
	struct client_state state;
	ARRAY(struct submission_backend *) pending_backends;
	ARRAY(struct submission_recipient *) rcpt_to;
	ARRAY(struct submission_backend *) rcpt_backends;

	struct mail_storage_service_user *service_user;
	struct mail_user *user;

	/* IMAP URLAUTH context (RFC4467) for BURL (RFC4468) */
	struct imap_urlauth_context *urlauth_ctx;

	struct timeout *to_quit;

	enum smtp_capability backend_capabilities;
	struct submission_backend *backend_default;
	struct submission_backend_relay *backend_default_relay;
	struct submission_backend *backends;
	unsigned int backends_count;

	/* Extra (non-standard) capabilities */
	ARRAY(struct client_extra_capability) extra_capabilities;

	/* Module-specific contexts. */
	ARRAY(union submission_module_context *) module_contexts;

	bool standalone:1;
	bool disconnected:1;
	bool destroyed:1;
	bool anvil_sent:1;
	bool backend_capabilities_configured:1;
	bool anonymous_allowed:1;
};

struct submission_module_register {
	unsigned int id;
};

union submission_module_context {
	struct submission_client_vfuncs super;
	struct submission_module_register *reg;
};
extern struct submission_module_register submission_module_register;

extern struct client *submission_clients;
extern unsigned int submission_client_count;

struct client *client_create(int fd_in, int fd_out,
			     struct mail_user *user,
			     struct mail_storage_service_user *service_user,
			     const struct submission_settings *set,
			     const char *helo,
			     const unsigned char *pdata,
			     unsigned int pdata_len);
void client_destroy(struct client **client, const char *prefix,
		    const char *reason) ATTR_NULL(2, 3);

typedef void (*client_input_callback_t)(struct client *context);

void client_apply_backend_capabilities(struct client *client);
void client_default_backend_started(struct client *client,
				    enum smtp_capability caps);

uoff_t client_get_max_mail_size(struct client *client);

void client_add_extra_capability(struct client *client, const char *capability,
				 const char *params) ATTR_NULL(2);

int client_input_read(struct client *client);
int client_handle_input(struct client *client);

void clients_destroy_all(void);

#endif

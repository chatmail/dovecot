/* Copyright (c) 2018 Dovecot authors, see the included COPYING file */

#include "submission-common.h"

#include "submission-backend.h"
#include "submission-recipient.h"

struct submission_recipient_module_register
submission_recipient_module_register = { 0 };

static void
submission_recipient_approved(struct smtp_server_recipient *rcpt ATTR_UNUSED,
			      struct submission_recipient *srcpt);

struct submission_recipient *
submission_recipient_create(struct client *client,
			    struct smtp_server_recipient *rcpt)
{
	struct submission_recipient *srcpt;

	srcpt = p_new(rcpt->pool, struct submission_recipient, 1);
	srcpt->rcpt = rcpt;
	srcpt->backend = client->state.backend;

	rcpt->context = srcpt;

	p_array_init(&srcpt->module_contexts, rcpt->pool, 5);

	smtp_server_recipient_add_hook(
		rcpt, SMTP_SERVER_RECIPIENT_HOOK_APPROVED,
		submission_recipient_approved, srcpt);

	return srcpt;
}

static void
submission_recipient_approved(struct smtp_server_recipient *rcpt ATTR_UNUSED,
			      struct submission_recipient *srcpt)
{
	struct submission_backend *backend = srcpt->backend;
	struct client *client = backend->client;
	struct submission_backend *rcpt_backend;
	bool backend_found = FALSE;

	array_push_back(&client->rcpt_to, &srcpt);

	array_foreach_elem(&client->rcpt_backends, rcpt_backend) {
		if (rcpt_backend == backend) {
			backend_found = TRUE;
			break;
		}
	}
	if (!backend_found)
		array_push_back(&client->rcpt_backends, &backend);
}

/* Copyright (c) 2015-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "hash.h"
#include "istream.h"
#include "mail-storage.h"

#include "push-notification-drivers.h"
#include "push-notification-events.h"
#include "push-notification-event-message-common.h"
#include "push-notification-event-messageappend.h"
#include "push-notification-txn-msg.h"


#define EVENT_NAME "MessageAppend"

static struct push_notification_event_messageappend_config default_config;


static void *push_notification_event_messageappend_default_config(void)
{
    i_zero(&default_config);

    return &default_config;
}

static void push_notification_event_messageappend_debug_msg
(struct push_notification_txn_event *event)
{
    struct push_notification_event_messageappend_data *data = event->data;

    if (data->from != NULL) {
        i_debug("%s: From [%s]", EVENT_NAME, data->from);
    }

    if (data->snippet != NULL) {
        i_debug("%s: Snippet [%s]", EVENT_NAME, data->snippet);
    }

    if (data->subject != NULL) {
        i_debug("%s: Subject [%s]", EVENT_NAME, data->subject);
    }

    if (data->to != NULL) {
        i_debug("%s: To [%s]", EVENT_NAME, data->to);
    }
}

static void
push_notification_event_messageappend_event(struct push_notification_txn *ptxn,
                                            struct push_notification_event_config *ec,
                                            struct push_notification_txn_msg *msg,
                                            struct mail *mail)
{
    struct push_notification_event_messageappend_config *config =
        (struct push_notification_event_messageappend_config *)ec->config;
    struct push_notification_event_messageappend_data *data;
    const char *value;

    if (config->flags == 0) {
        return;
    }

    data = push_notification_txn_msg_get_eventdata(msg, EVENT_NAME);
    if (data == NULL) {
        data = p_new(ptxn->pool,
                     struct push_notification_event_messageappend_data, 1);
        push_notification_txn_msg_set_eventdata(ptxn, msg, ec, data);
    }

    if ((data->to == NULL) &&
        (config->flags & PUSH_NOTIFICATION_MESSAGE_HDR_TO) != 0 &&
        (mail_get_first_header(mail, "To", &value) >= 0)) {
        data->to = p_strdup(ptxn->pool, value);
    }

    if ((data->from == NULL) &&
        (config->flags & PUSH_NOTIFICATION_MESSAGE_HDR_FROM) != 0 &&
        (mail_get_first_header(mail, "From", &value) >= 0)) {
        data->from = p_strdup(ptxn->pool, value);
    }

    if ((data->subject == NULL) &&
        (config->flags & PUSH_NOTIFICATION_MESSAGE_HDR_SUBJECT) != 0 &&
        (mail_get_first_header(mail, "Subject", &value) >= 0)) {
        data->subject = p_strdup(ptxn->pool, value);
    }

    if ((data->snippet == NULL) &&
        (config->flags & PUSH_NOTIFICATION_MESSAGE_BODY_SNIPPET) != 0 &&
        (mail_get_special(mail, MAIL_FETCH_BODY_SNIPPET, &value) >= 0)) {
        /* [0] contains the snippet algorithm, skip over it */
        i_assert(value[0] != '\0');
        data->snippet = p_strdup(ptxn->pool, value + 1);
    }
}


/* Event definition */

extern struct push_notification_event push_notification_event_messageappend;

struct push_notification_event push_notification_event_messageappend = {
    .name = EVENT_NAME,
    .init = {
        .default_config = push_notification_event_messageappend_default_config
    },
    .msg = {
        .debug_msg = push_notification_event_messageappend_debug_msg
    },
    .msg_triggers = {
        .append = push_notification_event_messageappend_event
    }
};

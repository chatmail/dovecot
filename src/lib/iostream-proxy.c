/* Copyright (c) 2002-2018 Dovecot authors, see the included COPYING file
 */
#include "lib.h"
#include "buffer.h"
#include "str.h"
#include "iostream-pump.h"
#include "iostream-proxy.h"
#include <unistd.h>

#undef iostream_proxy_set_completion_callback

struct iostream_proxy {
	struct iostream_pump *ltr;
	struct iostream_pump *rtl;

	unsigned int ref;

	iostream_proxy_callback_t *callback;
	void *context;
};

static void
iostream_proxy_completion(struct iostream_proxy *proxy,
			  enum iostream_proxy_side side,
			  enum iostream_pump_status pump_status)
{
	enum iostream_proxy_status status;

	switch (pump_status) {
	case IOSTREAM_PUMP_STATUS_INPUT_EOF:
		status = IOSTREAM_PROXY_STATUS_INPUT_EOF;
		break;
	case IOSTREAM_PUMP_STATUS_INPUT_ERROR:
		status = IOSTREAM_PROXY_STATUS_INPUT_ERROR;
		break;
	case IOSTREAM_PUMP_STATUS_OUTPUT_ERROR:
		status = IOSTREAM_PROXY_STATUS_OTHER_SIDE_OUTPUT_ERROR;
		break;
	default:
		i_unreached();
	}
	proxy->callback(side, status, proxy->context);
}

static
void iostream_proxy_rtl_completion(enum iostream_pump_status status,
				   struct iostream_proxy *proxy)
{
	iostream_proxy_completion(proxy, IOSTREAM_PROXY_SIDE_RIGHT, status);
}

static
void iostream_proxy_ltr_completion(enum iostream_pump_status status,
				   struct iostream_proxy *proxy)
{
	iostream_proxy_completion(proxy, IOSTREAM_PROXY_SIDE_LEFT, status);
}

struct iostream_proxy *
iostream_proxy_create(struct istream *left_input, struct ostream *left_output,
		      struct istream *right_input, struct ostream *right_output)
{
	i_assert(left_input != NULL &&
		 right_input != NULL &&
		 left_output != NULL &&
		 right_output != NULL);

	/* create proxy */
	struct iostream_proxy *proxy = i_new(struct iostream_proxy, 1);

	proxy->ltr = iostream_pump_create(left_input, right_output);
	proxy->rtl = iostream_pump_create(right_input, left_output);

	iostream_pump_set_completion_callback(proxy->ltr, iostream_proxy_ltr_completion, proxy);
	iostream_pump_set_completion_callback(proxy->rtl, iostream_proxy_rtl_completion, proxy);

	proxy->ref = 1;

	return proxy;
}

void iostream_proxy_start(struct iostream_proxy *proxy)
{
	i_assert(proxy != NULL);
	i_assert(proxy->callback != NULL);

	iostream_pump_start(proxy->rtl);
	iostream_pump_start(proxy->ltr);
}

void iostream_proxy_set_completion_callback(struct iostream_proxy *proxy,
					    iostream_proxy_callback_t *callback,
					    void *context)
{
	i_assert(proxy != NULL);

	proxy->callback = callback;
	proxy->context = context;
}

struct istream *iostream_proxy_get_istream(struct iostream_proxy *proxy, enum iostream_proxy_side side)
{
	i_assert(proxy != NULL);

	switch(side) {
	case IOSTREAM_PROXY_SIDE_LEFT: return iostream_pump_get_input(proxy->ltr);
	case IOSTREAM_PROXY_SIDE_RIGHT: return iostream_pump_get_input(proxy->rtl);
	default: i_unreached();
	}
}

struct ostream *iostream_proxy_get_ostream(struct iostream_proxy *proxy, enum iostream_proxy_side side)
{
	i_assert(proxy != NULL);

	switch(side) {
	case IOSTREAM_PROXY_SIDE_LEFT: return iostream_pump_get_output(proxy->ltr);
	case IOSTREAM_PROXY_SIDE_RIGHT: return iostream_pump_get_output(proxy->rtl);
	default: i_unreached();
	}
}

void iostream_proxy_ref(struct iostream_proxy *proxy)
{
	i_assert(proxy != NULL && proxy->ref > 0);
	proxy->ref++;
}

void iostream_proxy_unref(struct iostream_proxy **proxy_r)
{
	struct iostream_proxy *proxy;

	if (proxy_r == NULL || *proxy_r == NULL)
		return;

	proxy = *proxy_r;
	*proxy_r = NULL;

	i_assert(proxy->ref > 0);
	if (--proxy->ref == 0) {
		/* pumps will call stop internally
		   if refcount drops to 0 */
		iostream_pump_unref(&proxy->ltr);
		iostream_pump_unref(&proxy->rtl);
		i_free(proxy);
	}
}

void iostream_proxy_stop(struct iostream_proxy *proxy)
{
	i_assert(proxy != NULL);
	iostream_pump_stop(proxy->ltr);
	iostream_pump_stop(proxy->rtl);
}

bool iostream_proxy_is_waiting_output(struct iostream_proxy *proxy,
				      enum iostream_proxy_side side)
{
	switch (side) {
	case IOSTREAM_PROXY_SIDE_LEFT:
		return iostream_pump_is_waiting_output(proxy->ltr);
	case IOSTREAM_PROXY_SIDE_RIGHT:
		return iostream_pump_is_waiting_output(proxy->rtl);
	}
	i_unreached();
}

void iostream_proxy_switch_ioloop(struct iostream_proxy *proxy)
{
	i_assert(proxy != NULL);
	iostream_pump_switch_ioloop(proxy->ltr);
	iostream_pump_switch_ioloop(proxy->rtl);
}

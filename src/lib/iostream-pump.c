/* Copyright (c) 2002-2018 Dovecot authors, see the included COPYING file
 */
#include "lib.h"
#include "buffer.h"
#include "str.h"
#include "iostream-pump.h"
#include "istream.h"
#include "ostream.h"
#include <unistd.h>

#undef iostream_pump_set_completion_callback

struct iostream_pump {
	struct istream *input;
	struct ostream *output;

	struct io *io;

	unsigned int ref;

	iostream_pump_callback_t *callback;
	void *context;

	bool waiting_output;
	bool completed;
};

static
void iostream_pump_copy(struct iostream_pump *pump)
{
	enum ostream_send_istream_result res;

	o_stream_cork(pump->output);
	size_t old_size = o_stream_get_max_buffer_size(pump->output);
	o_stream_set_max_buffer_size(pump->output,
				     I_MIN(IO_BLOCK_SIZE,
					   o_stream_get_max_buffer_size(pump->output)));
	res = o_stream_send_istream(pump->output, pump->input);
	o_stream_set_max_buffer_size(pump->output, old_size);
	o_stream_uncork(pump->output);

	switch(res) {
	case OSTREAM_SEND_ISTREAM_RESULT_ERROR_INPUT:
		io_remove(&pump->io);
		pump->callback(IOSTREAM_PUMP_STATUS_INPUT_ERROR, pump->context);
		return;
	case OSTREAM_SEND_ISTREAM_RESULT_ERROR_OUTPUT:
		io_remove(&pump->io);
		pump->callback(IOSTREAM_PUMP_STATUS_OUTPUT_ERROR, pump->context);
		return;
	case OSTREAM_SEND_ISTREAM_RESULT_WAIT_OUTPUT:
		pump->waiting_output = TRUE;
		io_remove(&pump->io);
		return;
	case OSTREAM_SEND_ISTREAM_RESULT_FINISHED:
		pump->waiting_output = FALSE;
		io_remove(&pump->io);
		/* flush it */
		switch (o_stream_flush(pump->output)) {
		case -1:
			pump->callback(IOSTREAM_PUMP_STATUS_OUTPUT_ERROR, pump->context);
			break;
		case 0:
			pump->waiting_output = TRUE;
			pump->completed = TRUE;
			break;
		default:
			pump->callback(IOSTREAM_PUMP_STATUS_INPUT_EOF, pump->context);
			break;
		}
		return;
	case OSTREAM_SEND_ISTREAM_RESULT_WAIT_INPUT:
		pump->waiting_output = FALSE;
		return;
	}
	i_unreached();
}

static
int iostream_pump_flush(struct iostream_pump *pump)
{
	int ret;
	if ((ret = o_stream_flush(pump->output)) <= 0) {
		if (ret < 0)
			pump->callback(IOSTREAM_PUMP_STATUS_OUTPUT_ERROR, pump->context);
		return ret;
	}
	pump->waiting_output = FALSE;
	if (pump->completed) {
		pump->callback(IOSTREAM_PUMP_STATUS_INPUT_EOF, pump->context);
		return 1;
	}

	if (pump->io == NULL) {
		pump->io = io_add_istream(pump->input, iostream_pump_copy, pump);
		io_set_pending(pump->io);
	}
	return ret;
}

struct iostream_pump *
iostream_pump_create(struct istream *input, struct ostream *output)
{
	i_assert(input != NULL &&
		 output != NULL);

	/* ref streams */
	i_stream_ref(input);
	o_stream_ref(output);

	/* create pump */
	struct iostream_pump *pump = i_new(struct iostream_pump, 1);
	pump->input = input;
	pump->output = output;

	pump->ref = 1;

	return pump;
}

void iostream_pump_start(struct iostream_pump *pump)
{
	i_assert(pump != NULL);
	i_assert(pump->callback != NULL);

	/* add flush handler */
	o_stream_set_flush_callback(pump->output, iostream_pump_flush, pump);

	/* make IO objects */
	pump->io = io_add_istream(pump->input, iostream_pump_copy, pump);

	/* make sure we do first read right away */
	io_set_pending(pump->io);
}

struct istream *iostream_pump_get_input(struct iostream_pump *pump)
{
	i_assert(pump != NULL);
	return pump->input;
}

struct ostream *iostream_pump_get_output(struct iostream_pump *pump)
{
	i_assert(pump != NULL);
	return pump->output;
}

void iostream_pump_set_completion_callback(struct iostream_pump *pump,
					   iostream_pump_callback_t *callback, void *context)
{
	i_assert(pump != NULL);
	pump->callback = callback;
	pump->context = context;
}

void iostream_pump_ref(struct iostream_pump *pump)
{
	i_assert(pump != NULL && pump->ref > 0);
	pump->ref++;
}

void iostream_pump_unref(struct iostream_pump **pump_r)
{
	i_assert(pump_r != NULL && *pump_r != NULL);
	struct iostream_pump *pump = *pump_r;
	*pump_r = NULL;

	i_assert(pump->ref > 0);
	if (--pump->ref == 0) {
		iostream_pump_stop(pump);
		o_stream_unref(&pump->output);
		i_stream_unref(&pump->input);
		i_free(pump);
	}
}

void iostream_pump_stop(struct iostream_pump *pump)
{
	i_assert(pump != NULL);

	o_stream_unset_flush_callback(pump->output);

	io_remove(&pump->io);
}

bool iostream_pump_is_waiting_output(struct iostream_pump *pump)
{
	return pump->waiting_output;
}

void iostream_pump_switch_ioloop(struct iostream_pump *pump)
{
	i_assert(pump != NULL);
	if (pump->io != NULL)
		pump->io = io_loop_move_io(&pump->io);
	o_stream_switch_ioloop(pump->output);
	i_stream_switch_ioloop(pump->input);
}

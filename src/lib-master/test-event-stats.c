/* Copyright (c) 2018 Dovecot authors, see the included COPYING file */

#include "test-lib.h"
#include "lib.h"
#include "time-util.h"
#include "lib-event-private.h"
#include "str.h"
#include "sleep.h"
#include "ioloop.h"
#include "connection.h"
#include "ostream.h"
#include "istream.h"
#include "stats-client.h"
#include "test-common.h"
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>

#define TST_BEGIN(test_name)				\
	test_begin(test_name);				\
	ioloop_timeval.tv_sec = 0;			\
	ioloop_timeval.tv_usec = 0;

#define BASE_DIR "."
#define SOCK_PATH ".test-temp-stats-event-sock"

#define SOCK_FULL BASE_DIR "/" SOCK_PATH

static struct event_category test_cats[5] = {
	{.name = "test1"},
	{.name = "test2"},
	{.name = "test3"},
	{.name = "test4"},
	{.name = "test5"},
};

static struct event_field test_fields[5] = {
	{.key = "key1",
	 .value_type = EVENT_FIELD_VALUE_TYPE_STR,
	 .value = {.str = "str1"}},

	{.key = "key2",
	 .value_type = EVENT_FIELD_VALUE_TYPE_INTMAX,
	 .value = {.intmax = 20}},

	{.key = "key3",
	 .value_type = EVENT_FIELD_VALUE_TYPE_TIMEVAL,
	 .value = {.timeval = {.tv_sec = 10}}},

	{.key = "key4",
	 .value = {.str = "str4"}},

	{.key = "key5",
	 .value = {.intmax = 50}},
};

static void stats_conn_accept(void *context ATTR_UNUSED);
static void stats_conn_destroy(struct connection *_conn);
static void stats_conn_input(struct connection *_conn);

static bool compare_test_stats_to(const char *format, ...) ATTR_FORMAT(1, 2);

static struct connection_settings stats_conn_set = {
	.input_max_size = SIZE_MAX,
	.output_max_size = SIZE_MAX,
	.client = FALSE
};

static const struct connection_vfuncs stats_conn_vfuncs = {
	.destroy = stats_conn_destroy,
	.input = stats_conn_input
};

struct server_connection {
	struct connection conn;

	pool_t pool;
	bool handshake_sent:1;
};

static int stats_sock_fd;
static struct connection_list *stats_conn_list;
static struct ioloop *ioloop;

static pid_t stats_pid;

static int run_tests(void);
static void signal_process(const char *signal_file);
static void wait_for_signal(const char *signal_file);
static void kill_stats_child(void);

static const char *stats_ready = ".test-temp-stats-event-stats-ready";
static const char *test_done = ".test-temp-stats-event-test-done";
static const char *exit_stats = ".test-temp-stats-event-exit-stats";
static const char *stats_data_file = ".test-temp-stats-event-test_stats";

static void kill_stats_child(void)
{
	i_assert(stats_pid != 0);
	(void)kill(stats_pid, SIGKILL);
	(void)waitpid(stats_pid, NULL, 0);
}

static void stats_proc(void)
{
	struct io *io_listen;
	/* Make sure socket file not existing */
	i_unlink_if_exists(SOCK_FULL);
	stats_sock_fd = net_listen_unix(SOCK_FULL, 128);
	if (stats_sock_fd == -1)
		i_fatal("listen(%s) failed: %m", SOCK_FULL);
	ioloop = io_loop_create();
	io_listen = io_add(stats_sock_fd, IO_READ, stats_conn_accept, NULL);
	stats_conn_list = connection_list_init(&stats_conn_set,
					       &stats_conn_vfuncs);
	signal_process(stats_ready);
	io_loop_run(ioloop);
	io_remove(&io_listen);
	connection_list_deinit(&stats_conn_list);
	io_loop_destroy(&ioloop);
	i_close_fd(&stats_sock_fd);
	i_unlink(SOCK_FULL);
}

static void stats_conn_accept(void *context ATTR_UNUSED)
{
	int fd;
	struct server_connection *conn;
	pool_t pool;
	fd = net_accept(stats_sock_fd, NULL, NULL);
	if (stats_sock_fd == -1)
		return;
	if (stats_sock_fd == -2)
		i_fatal("test stats: accept() failed: %m");
	net_set_nonblock(fd, TRUE);
	pool = pool_alloconly_create("stats connection", 512);
	conn = p_new(pool, struct server_connection, 1);
	conn->pool = pool;
	connection_init_server(stats_conn_list,
			       &conn->conn,
			       "stats connection", fd, fd);
}

static void stats_conn_destroy(struct connection *_conn)
{
	struct server_connection *conn =
		(struct server_connection *)_conn;
	connection_deinit(&conn->conn);
	pool_unref(&conn->pool);
}

static void stats_conn_input(struct connection *_conn)
{
	int fd;
	struct ostream *stats_data_out;
	struct server_connection *conn = (struct server_connection *)_conn;
	const char *handshake = "VERSION\tstats-server\t3\t0\n"
		"FILTER\tcategory=test1 OR category=test2 OR category=test3 OR "
		"category=test4 OR category=test5\n";
	const char *line = NULL;
	if (!conn->handshake_sent) {
		conn->handshake_sent = TRUE;
		o_stream_nsend_str(conn->conn.output, handshake);
	}
	while (access(exit_stats, F_OK) < 0) {
		/* Test process haven't signal yet about end of the tests */
		while (access(test_done, F_OK) < 0 ||
		       ((line=i_stream_read_next_line(conn->conn.input)) != NULL)) {
			if (line != NULL) {
				if (str_begins(line, "VERSION"))
					continue;

				if ((fd=open(stats_data_file, O_WRONLY | O_CREAT | O_APPEND, 0600)) < 0) {
					i_fatal("failed create stats data file %m");
				}

				stats_data_out = o_stream_create_fd_autoclose(&fd, SIZE_MAX);
				o_stream_nsend_str(stats_data_out, line);
				o_stream_nsend_str(stats_data_out, "\n");

				o_stream_set_no_error_handling(stats_data_out, TRUE);
				o_stream_unref(&stats_data_out);
			}
		}
		i_unlink(test_done);
		signal_process(stats_ready);
	}
	i_unlink(exit_stats);
	i_unlink_if_exists(test_done);
	io_loop_stop(ioloop);
}

static void wait_for_signal(const char *signal_file)
{
	struct timeval start, now;
	i_gettimeofday(&start);
	while (access(signal_file, F_OK) < 0) {
		i_sleep_msecs(10);
		i_gettimeofday(&now);
		if (timeval_diff_usecs(&now, &start) > 10000000) {
			kill_stats_child();
			i_fatal("wait_for_signal has timed out");
		}
	}
	i_unlink(signal_file);
}

static void signal_process(const char *signal_file)
{
	int fd;
	if ((fd = open(signal_file, O_CREAT, 0666)) < 0) {
		if (stats_pid != 0) {
			kill_stats_child();
		}
		i_fatal("Failed to create signal file %s", signal_file);
	}
	i_close_fd(&fd);
}

static bool compare_test_stats_data_line(const char *reference, const char *actual)
{
	const char *const *ref_args = t_strsplit(reference, "\t");
	const char *const *act_args = t_strsplit(actual, "\t");
	unsigned int max = str_array_length(ref_args);

	/* different lengths imply not equal */
	if (str_array_length(ref_args) != str_array_length(act_args))
		return FALSE;

	for (size_t i = 0; i < max; i++) {
		if (i > 1 && i < 6) continue;
		if (*(ref_args[i]) == 'l') {
			i++;
			continue;
		}
		if (strcmp(ref_args[i], act_args[i]) != 0) {
			return FALSE;
		}
	}
	return TRUE;
}

static bool compare_test_stats_data_lines(const char *actual, const char *reference)
{
	const char *const *lines_ref = t_strsplit(reference, "\n");
	const char *const *lines_act = t_strsplit(actual, "\n");
	for(size_t i = 0; *lines_ref != NULL && *lines_act != NULL; i++, lines_ref++, lines_act++) {
		if (!compare_test_stats_data_line(*lines_ref, *lines_act))
			return FALSE;
	}
	return *lines_ref == *lines_act;
}

static bool compare_test_stats_to(const char *format, ...)
{
	bool res;
	string_t *reference = t_str_new(1024);
	struct istream *input;
	va_list args;
	va_start (args, format);
	str_vprintfa (reference, format, args);
	va_end (args);
	/* signal stats process to receive and record stats data */
	signal_process(test_done);
	/* Wait stats data to be recorded by stats process */
	wait_for_signal(stats_ready);

	input = i_stream_create_file(stats_data_file, SIZE_MAX);
	while (i_stream_read(input) > 0) ;
	if (input->stream_errno != 0) {
		i_fatal("stats data file read failed: %s",
			i_stream_get_error(input));
		res = FALSE;
	} else {
		size_t size;
		const unsigned char *data = i_stream_get_data(input, &size);
		res = compare_test_stats_data_lines(t_strdup_until(data, data+size), str_c(reference));
	}
	i_stream_unref(&input);
	i_unlink(stats_data_file);
	return res;
}

static void test_fail_callback(const struct failure_context *ctx ATTR_UNUSED,
			       const char *format ATTR_UNUSED,
			       va_list args ATTR_UNUSED)
{
	/* ignore message, all we need is stats */
}

static void register_all_categories(void)
{
	/* Run this before all the tests,
	   so stats client doesn't send CATEGORY\ttestx anymore,
	   so test will produce stats records independent of test order */
	struct event *ev;
	int i;
	for (i = 0; i < 5; i++) {
		ev = event_create(NULL);
		event_add_category(ev, &test_cats[i]);
		e_info(ev, "message");
		event_unref(&ev);
	}
	signal_process(test_done);
}

static void test_no_merging1(void)
{
	/* NULL parent */
	int l;
	TST_BEGIN("no merging parent is NULL");
	struct event *single_ev = event_create(NULL);
	event_add_category(single_ev, &test_cats[0]);
	event_add_str(single_ev, test_fields[0].key, test_fields[0].value.str);
	e_info(single_ev, "info message");
	l = __LINE__ - 1;
	event_unref(&single_ev);
	test_assert(
		compare_test_stats_to(
			"EVENT	0	1	0	0"
			"	s"__FILE__"	%d"
			"	l0	0	ctest1	Skey1	str1\n", l));
	test_end();
}

static void test_no_merging2(void)
{
	/* Parent sent to stats */
	int l;
	uint64_t id;
	TST_BEGIN("no merging parent sent to stats");
	struct event *parent_ev = event_create(NULL);
	event_add_category(parent_ev, &test_cats[0]);
	parent_ev->sent_to_stats_id = parent_ev->change_id;
	id = parent_ev->id;
	struct event *child_ev = event_create(parent_ev);
	event_add_category(child_ev, &test_cats[1]);
	e_info(child_ev, "info message");
	l = __LINE__ - 1;
	event_unref(&parent_ev);
	event_unref(&child_ev);
	test_assert(
		compare_test_stats_to(
			"EVENT	%"PRIu64"	1	0	0"
			"	s"__FILE__"	%d"
			"	l0	0	ctest2\n"
			"END	9\n", id, l));
	test_end();
}

static void test_no_merging3(void)
{
	/* Parent have different timestamp */
	int l, lp;
	uint64_t idp;
	TST_BEGIN("no merging parent timestamp differs");
	struct event *parent_ev = event_create(NULL);
	lp = __LINE__ - 1;
	idp = parent_ev->id;
	event_add_category(parent_ev, &test_cats[0]);
	parent_ev->sent_to_stats_id = 0;
	ioloop_timeval.tv_sec++;
	struct event *child_ev = event_create(parent_ev);
	event_add_category(child_ev, &test_cats[1]);
	e_info(child_ev, "info message");
	l = __LINE__ - 1;
	event_unref(&parent_ev);
	event_unref(&child_ev);
	test_assert(
		compare_test_stats_to(
			"BEGIN	%"PRIu64"	0	1	0	0"
			"	s"__FILE__"	%d	ctest1\n"
			"EVENT	%"PRIu64"	1	1	0"
			"	s"__FILE__"	%d"
			"	l1	0	ctest2\n"
			"END\t%"PRIu64"\n", idp, lp, idp, l, idp));
	test_end();
}

static void test_merge_events1(void)
{
	int l;
	TST_BEGIN("merge events parent NULL");
	struct event *merge_ev1 = event_create(NULL);
	event_add_category(merge_ev1, &test_cats[0]);
	event_add_category(merge_ev1, &test_cats[1]);
	event_add_str(merge_ev1,test_fields[0].key, test_fields[0].value.str);
	event_add_int(merge_ev1,test_fields[1].key, test_fields[1].value.intmax);
	struct event *merge_ev2 = event_create(merge_ev1);
	event_add_category(merge_ev2, &test_cats[2]);
	event_add_category(merge_ev2, &test_cats[1]);
	event_add_timeval(merge_ev2,test_fields[2].key,
			  &test_fields[2].value.timeval);
	event_add_int(merge_ev2,test_fields[1].key, test_fields[1].value.intmax);
	e_info(merge_ev2, "info message");
	l = __LINE__ - 1;
	event_unref(&merge_ev1);
	event_unref(&merge_ev2);
	test_assert(
		compare_test_stats_to(
			"EVENT	0	1	0	0"
			"	s"__FILE__"	%d	l0	0"
			"	ctest3	ctest2	ctest1	Tkey3"
			"	10	0	Ikey2	20"
			"	Skey1	str1\n", l));
	test_end();
}

static void test_merge_events2(void)
{
	int l;
	uint64_t id;
	TST_BEGIN("merge events parent sent to stats");
	struct event *parent_ev = event_create(NULL);
	event_add_category(parent_ev, &test_cats[3]);
	parent_ev->sent_to_stats_id = parent_ev->change_id;
	struct event *merge_ev1 = event_create(parent_ev);
	event_add_category(merge_ev1, &test_cats[0]);
	event_add_category(merge_ev1, &test_cats[1]);
	event_add_str(merge_ev1,test_fields[0].key, test_fields[0].value.str);
	event_add_int(merge_ev1,test_fields[1].key, test_fields[1].value.intmax);
	struct event *merge_ev2 = event_create(merge_ev1);
	event_add_category(merge_ev2, &test_cats[2]);
	event_add_category(merge_ev2, &test_cats[1]);
	event_add_timeval(merge_ev2,test_fields[2].key,
			  &test_fields[2].value.timeval);
	event_add_int(merge_ev2,test_fields[1].key, test_fields[1].value.intmax);
	e_info(merge_ev2, "info message");
	l = __LINE__ - 1;
	id = parent_ev->id;
	event_unref(&parent_ev);
	event_unref(&merge_ev1);
	event_unref(&merge_ev2);
	test_assert(
		compare_test_stats_to(
			"EVENT	%"PRIu64"	1	0	0"
			"	s"__FILE__"	%d	l0	0"
			"	ctest3	ctest2	ctest1	Tkey3"
			"	10	0	Ikey2	20"
			"	Skey1	str1\n"
			"END	16\n", id, l));
	test_end();
}

static void test_skip_parents(void)
{
	int l, lp;
	uint64_t id;
	TST_BEGIN("skip empty parents");
	struct event *parent_to_log = event_create(NULL);
	lp = __LINE__ - 1;
	id = parent_to_log->id;
	event_add_category(parent_to_log, &test_cats[0]);
	ioloop_timeval.tv_sec++;
	struct event *empty_parent1 = event_create(parent_to_log);
	ioloop_timeval.tv_sec++;
	struct event *empty_parent2 = event_create(empty_parent1);
	ioloop_timeval.tv_sec++;
	struct event *child_ev = event_create(empty_parent2);
	event_add_category(child_ev, &test_cats[1]);
	e_info(child_ev, "info message");
	l = __LINE__ - 1;
	event_unref(&parent_to_log);
	event_unref(&empty_parent1);
	event_unref(&empty_parent2);
	event_unref(&child_ev);
	test_assert(
		compare_test_stats_to(
			"BEGIN	%"PRIu64"	0	1	0	0"
			"	s"__FILE__"	%d	ctest1\n"
			"EVENT	%"PRIu64"	1	3	0	"
			"s"__FILE__"	%d	l3	0"
			"	ctest2\nEND\t%"PRIu64"\n", id, lp, id, l, id));
	test_end();
}

static void test_merge_events_skip_parents(void)
{
	int lp, l;
	uint64_t id;
	TST_BEGIN("merge events and skip empty parents");
	struct event *parent_to_log = event_create(NULL);
	lp = __LINE__ - 1;
	id = parent_to_log->id;
	event_add_category(parent_to_log, &test_cats[0]);
	ioloop_timeval.tv_sec++;
	struct event *empty_parent1 = event_create(parent_to_log);
	ioloop_timeval.tv_sec++;
	struct event *empty_parent2 = event_create(empty_parent1);
	ioloop_timeval.tv_sec++;
	struct event *child1_ev = event_create(empty_parent2);
	event_add_category(child1_ev, &test_cats[1]);
	event_add_category(child1_ev, &test_cats[2]);
	event_add_int(child1_ev,test_fields[1].key, test_fields[1].value.intmax);
	event_add_str(child1_ev,test_fields[0].key, test_fields[0].value.str);
	struct event *child2_ev = event_create(empty_parent2);
	event_add_category(child2_ev, &test_cats[3]);
	event_add_category(child2_ev, &test_cats[4]);
	event_add_timeval(child2_ev,test_fields[2].key,
			  &test_fields[2].value.timeval);
	event_add_str(child2_ev,test_fields[3].key, test_fields[3].value.str);
	e_info(child2_ev, "info message");
	l = __LINE__ - 1;
	event_unref(&parent_to_log);
	event_unref(&empty_parent1);
	event_unref(&empty_parent2);
	event_unref(&child1_ev);
	event_unref(&child2_ev);
	test_assert(
		compare_test_stats_to(
			"BEGIN	%"PRIu64"	0	1	0	0"
			"	s"__FILE__"	%d	ctest1\n"
			"EVENT	%"PRIu64"	1	3	0	"
			"s"__FILE__"	%d	l3	0	"
			"ctest4	ctest5	Tkey3	10	0	Skey4"
			"	str4\nEND\t%"PRIu64"\n", id, lp, id, l, id));
	test_end();
}

static struct event *make_event(struct event *parent,
				struct event_category *cat,
				int *line_r, uint64_t *id_r)
{
	struct event *event;
	int line;

	event = event_create(parent);
	line = __LINE__ -1;

	if (line_r != NULL)
		*line_r = line;
	if (id_r != NULL)
		*id_r = event->id;

	/* something in the test infrastructure assumes that at least one
	   category is always present - make it happy */
	event_add_category(event, cat);

	/* advance the clock to avoid event sending optimizations */
	ioloop_timeval.tv_sec++;

	return event;
}

static void test_parent_update_post_send(void)
{
	struct event *a, *b, *c;
	uint64_t id;
	int line, line_log1, line_log2;

	TST_BEGIN("parent updated after send");

	a = make_event(NULL, &test_cats[0], &line, &id);
	b = make_event(a, &test_cats[1], NULL, NULL);
	c = make_event(b, &test_cats[2], NULL, NULL);

	/* set initial field values */
	event_add_int(a, "a", 1);
	event_add_int(b, "b", 2);
	event_add_int(c, "c", 3);

	/* force 'a' event to be sent */
	e_info(b, "field 'a' should be 1");
	line_log1 = __LINE__ - 1;

	event_add_int(a, "a", 1000); /* update parent */

	/* log child, which should re-sent parent */
	e_info(c, "field 'a' should be 1000");
	line_log2 = __LINE__ - 1;

	event_unref(&a);
	event_unref(&b);
	event_unref(&c);

	/* EVENT <parent> <type> ... */
	/* BEGIN <id> <parent> <type> ... */
	/* END <id> */
	test_assert(
		compare_test_stats_to(
			/* first e_info() */
			"BEGIN	%"PRIu64"	0	1	0	0"
			"	s"__FILE__"	%d	ctest1"
			"	Ia	1\n"
			"EVENT	%"PRIu64"	1	1	0"
			"	s"__FILE__"	%d"
			"	l1	0	ctest2" "	Ib	2\n"
			/* second e_info() */
			"UPDATE	%"PRIu64"	0	0	0"
			"	s"__FILE__"	%d	ctest1"
			"	Ia	1000\n"
			"BEGIN	%"PRIu64"	%"PRIu64"	1	0	0"
			"	s"__FILE__"	%d"
			"	l0	0	ctest2	Ib	2\n"
			"EVENT	%"PRIu64"	1	1	0"
			"	s"__FILE__"	%d"
			"	l1	0	ctest3"
			"	Ic	3\n"
			"END\t%"PRIu64"\n"
			"END\t%"PRIu64"\n",
			id, line, /* BEGIN */
			id, line_log1, /* EVENT */
			id, line, /* UPDATE */
			id + 1, id, line, /* BEGIN */
			id + 1, line_log2, /* EVENT */
			id + 1 /* END */,
			id /* END */));

	test_end();
}

static void test_large_event_id(void)
{
	TST_BEGIN("large event id");
	int line, line_log1, line_log2, line_log3;
	struct event *a, *b;
	uint64_t id;

	a = make_event(NULL, &test_cats[0], &line, &id);
	a->id += 1000000;
	a->change_id++;
	b = make_event(a, &test_cats[1], NULL, NULL);

	ioloop_timeval.tv_sec++;
	e_info(a, "emit");
	line_log1 = __LINE__-1;
	ioloop_timeval.tv_sec++;
	e_info(b, "emit");
	line_log2 = __LINE__-1;
	event_add_int(a, "test1", 1);
	e_info(b, "emit");
	line_log3 = __LINE__-1;

	test_assert(
		compare_test_stats_to(
			/* first e_info() */
			"EVENT	%"PRIu64"	1	1	0"
			"	s"__FILE__"	%d"
			"	l1	0	ctest1\n"
			"BEGIN	%"PRIu64"	0	1	0	0"
			"	s"__FILE__"	%d"
			"	l0	0	ctest1\n"
			"EVENT	%"PRIu64"	1	1	0"
			"	s"__FILE__"	%d"
			"	l1	0	ctest2\n"
			"UPDATE	%"PRIu64"	0	1	0"
			"	s"__FILE__"	%d"
			"	l1	0	ctest1	Itest1	1\n"
			"EVENT	%"PRIu64"	1	1	0"
			"	s"__FILE__"	%d"
			"	l1	0	ctest2\n",
			(uint64_t)0, line_log1,
			a->id, line,
			a->id, line_log2,
			a->id, line,
			a->id, line_log3
		)
	);

	event_unref(&b);
	event_unref(&a);

	test_end();
}

static int run_tests(void)
{
	int ret;
	void (*const tests[])(void) = {
		test_no_merging1,
		test_no_merging2,
		test_no_merging3,
		test_merge_events1,
		test_merge_events2,
		test_skip_parents,
		test_merge_events_skip_parents,
		test_parent_update_post_send,
		test_large_event_id,
		NULL
	};
	struct ioloop *ioloop = io_loop_create();
	struct stats_client *stats_client = stats_client_init(SOCK_FULL, FALSE);
	register_all_categories();
	wait_for_signal(stats_ready);
	/* Remove stats data file containing register categories related stuff */
	i_unlink(stats_data_file);
	ret = test_run(tests);
	stats_client_deinit(&stats_client);
	signal_process(exit_stats);
	signal_process(test_done);
	(void)waitpid(stats_pid, NULL, 0);
	io_loop_destroy(&ioloop);
	return ret;
}

static void cleanup_test_stats(void)
{
	i_unlink_if_exists(SOCK_FULL);
	i_unlink_if_exists(stats_data_file);
	i_unlink_if_exists(test_done);
	i_unlink_if_exists(exit_stats);
	i_unlink_if_exists(stats_ready);
}

static int launch_test_stats(void)
{
	int ret;

	/* Make sure files are not existing */
	cleanup_test_stats();

	if ((stats_pid = fork()) == (pid_t)-1)
		i_fatal("fork() failed: %m");
	if (stats_pid == 0) {
		stats_proc();
		return 0;
	}
	wait_for_signal(stats_ready);
	ret = run_tests();

	/* Make sure we don't leave anything behind */
	cleanup_test_stats();

	return ret;
}

int main(void)
{
	int ret;
	i_set_info_handler(test_fail_callback);
	lib_init();
	ret = launch_test_stats();
	lib_deinit();
	return ret;
}

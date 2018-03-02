/* Copyright (c) 2007-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "test-common.h"

#include <stdio.h>
#include <unistd.h> /* _exit() */
#include <setjmp.h> /* for fatal tests */

static bool test_deinit_lib;

/* To test the firing of i_assert, we need non-local jumps, i.e. setjmp */
static volatile bool expecting_fatal = FALSE;
static jmp_buf fatal_jmpbuf;

#define OUT_NAME_ALIGN 70

static char *test_prefix;
static bool test_success;
static unsigned int failure_count;
static unsigned int total_count;
static unsigned int expected_errors;
static char *expected_error_str;

void test_begin(const char *name)
{
	test_success = TRUE;
	if (!expecting_fatal)
		i_assert(test_prefix == NULL);
	else
		test_assert((test_success = (test_prefix == NULL)));
	test_prefix = i_strdup(name);
}

bool test_has_failed(void)
{
	return !test_success;
}

void test_assert_failed(const char *code, const char *file, unsigned int line)
{
	printf("%s:%u: Assert failed: %s\n", file, line, code);
	fflush(stdout);
	test_success = FALSE;
}

void test_assert_failed_idx(const char *code, const char *file, unsigned int line, long long i)
{
	printf("%s:%u: Assert(#%lld) failed: %s\n", file, line, i, code);
	fflush(stdout);
	test_success = FALSE;
}

void test_assert_failed_strcmp(const char *code, const char *file, unsigned int line,
				const char * src, const char * dst)
{
	printf("%s: Assert(#%u) failed: %s\n", file, line, code);
	printf("        \"%s\" != \"%s\"\n", src, dst);
	fflush(stdout);
	test_success = FALSE;
}

static void
test_dump_rand_state(void)
{
	static int seen_count = -1;
	int count = rand_get_seed_count();
	if (count == seen_count)
		return;
	seen_count = count;
	if (count > 0)
		printf("test: random seed #%i was %u\n", 
		       rand_get_seed_count(),
		       rand_get_last_seed());
	else
		printf("test: random seed unknown\n");
}

void test_end(void)
{
	if (!expecting_fatal)
		i_assert(test_prefix != NULL);
	else
		test_assert(test_prefix != NULL);

	test_out("", test_success);
	if (!test_success)
		test_dump_rand_state();
	i_free_and_null(test_prefix);
	test_success = FALSE;
}

void test_out(const char *name, bool success)
{
	test_out_reason(name, success, NULL);
}

void test_out_quiet(const char *name, bool success)
{
	if (success) {
		total_count++;
		return;
	}
	test_out(name, success);
}

void test_out_reason(const char *name, bool success, const char *reason)
{
	int i = 0;

	if (test_prefix != NULL) {
		fputs(test_prefix, stdout);
		i += strlen(test_prefix);
		if (*name != '\0') {
			putchar(':');
			i++;
		}
		putchar(' ');
		i++;
	}
	if (*name != '\0') {
		fputs(name, stdout);
		putchar(' ');
		i += strlen(name) + 1;
	}
	for (; i < OUT_NAME_ALIGN; i++)
		putchar('.');
	fputs(" : ", stdout);
	if (success)
		fputs("ok", stdout);
	else {
		fputs("FAILED", stdout);
		test_success = FALSE;
		failure_count++;
	}
	if (reason != NULL && *reason != '\0')
		printf(": %s", reason);
	putchar('\n');
	fflush(stdout);
	total_count++;
}

void
test_expect_error_string(const char *substr)
{
	i_assert(expected_errors == 0);
	expected_errors = 1;
	expected_error_str = i_strdup(substr);
}
void
test_expect_errors(unsigned int expected)
{
	i_assert(expected_errors == 0);
	expected_errors = expected;
}
void
test_expect_no_more_errors(void)
{
	test_assert(expected_errors == 0 && expected_error_str == NULL);
	i_free_and_null(expected_error_str);
	expected_errors = 0;
}

static void ATTR_FORMAT(2, 0)
test_error_handler(const struct failure_context *ctx,
		   const char *format, va_list args)
{
	bool suppress = FALSE;

#ifdef DEBUG
	if (ctx->type == LOG_TYPE_WARNING &&
	    strstr(format, "Growing") != NULL) {
		/* ignore "Growing memory pool" and "Growing data stack"
		   warnings */
		return;
	}
#endif
	if (expected_errors > 0) {
		if (expected_error_str != NULL) T_BEGIN {
			/* test_assert() will reset test_success if need be. */
			va_list args2;
			VA_COPY(args2, args);
			const char *str = t_strdup_vprintf(format, args2);
			suppress = strstr(str, expected_error_str) != NULL;
			test_assert(suppress == TRUE);
			i_free_and_null(expected_error_str);
			va_end(args2);
		} T_END;
		expected_errors--;
	} else {
		test_success = FALSE;
	}

	if (!suppress) {
		test_dump_rand_state();
		default_error_handler(ctx, format, args);
	}
}

static void ATTR_FORMAT(2, 0) ATTR_NORETURN
test_fatal_handler(const struct failure_context *ctx,
		   const char *format, va_list args)
{
	/* Prevent recursion, we can't handle our own errors */
	i_set_fatal_handler(default_fatal_handler);
	i_assert(expecting_fatal); /* if not at the right time, bail */
	i_set_fatal_handler(test_fatal_handler);
	longjmp(fatal_jmpbuf, 1);
	/* we simply can't get here - will the compiler complain? */
	default_fatal_handler(ctx, format, args);
}

static void test_init(void)
{
	test_prefix = NULL;
	failure_count = 0;
	total_count = 0;

	if (!lib_is_initialized()) {
		lib_init();
		test_deinit_lib = TRUE;
	} else
		test_deinit_lib = FALSE;

	i_set_error_handler(test_error_handler);
	/* Don't set fatal handler until actually needed for fatal testing */
}

static int test_deinit(void)
{
	i_assert(test_prefix == NULL);
	printf("%u / %u tests failed\n", failure_count, total_count);
	if (test_deinit_lib)
		lib_deinit();
	return failure_count == 0 ? 0 : 1;
}

static void test_run_funcs(void (*test_functions[])(void))
{
	unsigned int i;

	for (i = 0; test_functions[i] != NULL; i++) {
		T_BEGIN {
			test_functions[i]();
		} T_END;
	}
}
static void test_run_named_funcs(struct named_test tests[], const char *match)
{
	unsigned int i;

	for (i = 0; tests[i].func != NULL; i++) {
		if (strstr(tests[i].name, match) != NULL) T_BEGIN {
			tests[i].func();
		} T_END;
	}
}

static void run_one_fatal(test_fatal_func_t *fatal_function)
{
	static unsigned int index = 0;
	for (;;) {
		volatile int jumped = setjmp(fatal_jmpbuf);
		if (jumped == 0) {
			/* normal flow */
			expecting_fatal = TRUE;
			enum fatal_test_state ret = fatal_function(index);
			expecting_fatal = FALSE;
			if (ret == FATAL_TEST_FINISHED) {
				/* ran out of tests - good */
				index = 0;
				break;
			} else if (ret == FATAL_TEST_FAILURE) {
				/* failed to fire assert - bad, but can continue */
				test_success = FALSE;
				i_error("Desired assert failed to fire at step %i", index);
				index++;
			} else { /* FATAL_TEST_ABORT or other value */
				test_success = FALSE;
				test_end();
				index = 0;
				break;
			}
		} else {
			/* assert fired, continue with next test */
			index++;
		}
	}
}
static void test_run_fatals(test_fatal_func_t *const fatal_functions[])
{
	unsigned int i;

	for (i = 0; fatal_functions[i] != NULL; i++) {
		T_BEGIN {
			run_one_fatal(fatal_functions[i]);
		} T_END;
	}
}
static void test_run_named_fatals(const struct named_fatal fatals[], const char *match)
{
	unsigned int i;

	for (i = 0; fatals[i].func != NULL; i++) {
		if (strstr(fatals[i].name, match) != NULL) T_BEGIN {
			run_one_fatal(fatals[i].func);
		} T_END;
	}
}

int test_run(void (*test_functions[])(void))
{
	test_init();
	test_run_funcs(test_functions);
	return test_deinit();
}
int test_run_named(struct named_test tests[], const char *match)
{
	test_init();
	test_run_named_funcs(tests, match);
	return test_deinit();
}
int test_run_with_fatals(void (*test_functions[])(void),
			 test_fatal_func_t *const fatal_functions[])
{
	test_init();
	test_run_funcs(test_functions);
	i_set_fatal_handler(test_fatal_handler);
	test_run_fatals(fatal_functions);
	return test_deinit();
}
int test_run_named_with_fatals(const char *match, struct named_test tests[],
			       struct named_fatal fatals[])
{
	test_init();
	test_run_named_funcs(tests, match);
	i_set_fatal_handler(test_fatal_handler);
	test_run_named_fatals(fatals, match);
	return test_deinit();
}

void ATTR_NORETURN
test_exit(int status)
{
	i_free_and_null(expected_error_str);
	i_free_and_null(test_prefix);
	(void)t_pop(); /* as we were within a T_BEGIN { tests[i].func(); } T_END */
	lib_deinit();
	_exit(status);
}

/* Copyright (c) 2009-2017 Dovecot authors, see the included COPYING file */

#include "test-lib.h"
#include "str.h"
#include "env-util.h"
#include "hostpid.h"
#include "var-expand.h"
#include "var-expand-private.h"

struct var_expand_test {
	const char *in;
	const char *out;
};

struct var_get_key_range_test {
	const char *in;
	unsigned int idx, size;
};

static void test_var_expand_ranges(void)
{
	static struct var_expand_test tests[] = {
		{ "%v", "value1234" },
		{ "%3v", "val" },
		{ "%3.2v", "ue" },
		{ "%3.-2v", "ue12" },
		{ "%-3.2v", "23" },
		{ "%0.-1v", "value123" },
		{ "%-4.-1v", "123" }
	};
	static struct var_expand_table table[] = {
		{ 'v', "value1234", NULL },
		{ '\0', NULL, NULL }
	};
	string_t *str = t_str_new(128);
	unsigned int i;

	test_begin("var_expand - ranges");
	for (i = 0; i < N_ELEMENTS(tests); i++) {
		str_truncate(str, 0);
		var_expand(str, tests[i].in, table);
		test_assert(strcmp(tests[i].out, str_c(str)) == 0);
	}
	test_end();
}

static void test_var_expand_builtin(void)
{
	static struct var_expand_test tests[] = {
		{ "%{hostname}", NULL },
		{ "%{pid}", NULL },
		{ "a%{env:FOO}b", "abaRb" },
		{ "%50Hv", "1f" },
		{ "%50Hw", "2e" },
		{ "%50Nv", "25" },
		{ "%50Nw", "e" },

		{ "%{nonexistent}", "UNSUPPORTED_VARIABLE_nonexistent" },
		{ "%{nonexistent:default}", "UNSUPPORTED_VARIABLE_nonexistent" },
	};
	static struct var_expand_table table[] = {
		{ 'v', "value", NULL },
		{ 'w', "value2", NULL },
		{ '\0', NULL, NULL }
	};
	string_t *str = t_str_new(128);
	unsigned int i;

	tests[0].out = my_hostname;
	tests[1].out = my_pid;
	env_put("FOO=baR");

	test_begin("var_expand - builtin");
	for (i = 0; i < N_ELEMENTS(tests); i++) {
		str_truncate(str, 0);
		var_expand(str, tests[i].in, table);
		test_assert_idx(strcmp(tests[i].out, str_c(str)) == 0, i);
	}
	test_end();
}

static void test_var_get_key_range(void)
{
	static struct var_get_key_range_test tests[] = {
		{ "", 0, 0 },
		{ "{", 1, 0 },
		{ "k", 0, 1 },
		{ "{key}", 1, 3 },
		{ "5.5Rk", 4, 1 },
		{ "5.5R{key}", 5, 3 },
		{ "{key", 1, 3 }
	};
	unsigned int i, idx, size;

	test_begin("var_get_key_range");
	for (i = 0; i < N_ELEMENTS(tests); i++) {
		var_get_key_range(tests[i].in, &idx, &size);
		test_assert_idx(tests[i].idx == idx, i);
		test_assert_idx(tests[i].size == size, i);

		if (tests[i].size == 1)
			test_assert_idx(tests[i].in[idx] == var_get_key(tests[i].in), i);
	}
	test_end();
}

static const char *test_var_expand_func1(const char *data, void *context)
{
	test_assert(*(int *)context == 0xabcdef);
	return t_strdup_printf("<%s>", data);
}

static const char *test_var_expand_func2(const char *data ATTR_UNUSED,
					 void *context ATTR_UNUSED)
{
	return "";
}

static const char *test_var_expand_func3(const char *data ATTR_UNUSED,
					 void *context ATTR_UNUSED)
{
	return NULL;
}

static void test_var_expand_with_funcs(void)
{
	static struct var_expand_test tests[] = {
		{ "%{func1}", "<>" },
		{ "%{func1:foo}", "<foo>" },
		{ "%{func2}", "" },
		{ "%{func3}", "" }
	};
	static struct var_expand_table table[] = {
		{ '\0', NULL, NULL }
	};
	static const struct var_expand_func_table func_table[] = {
		{ "func1", test_var_expand_func1 },
		{ "func2", test_var_expand_func2 },
		{ "func3", test_var_expand_func3 },
		{ NULL, NULL }
	};
	string_t *str = t_str_new(128);
	unsigned int i;
	int ctx = 0xabcdef;

	test_begin("var_expand_with_funcs");
	for (i = 0; i < N_ELEMENTS(tests); i++) {
		str_truncate(str, 0);
		var_expand_with_funcs(str, tests[i].in, table, func_table, &ctx);
		test_assert_idx(strcmp(tests[i].out, str_c(str)) == 0, i);
	}
	test_end();
}

static void test_var_get_key(void)
{
	static struct {
		const char *str;
		char key;
	} tests[] = {
		{ "x", 'x' },
		{ "2.5Mx", 'x' },
		{ "200MDx", 'x' },
		{ "200MD{foo}", '{' },
		{ "{foo}", '{' },
		{ "", '\0' },
	};

	test_begin("var_get_key");
	for (unsigned int i = 0; i < N_ELEMENTS(tests); i++)
		test_assert_idx(var_get_key(tests[i].str) == tests[i].key, i);
	test_end();
}

static void test_var_has_key(void)
{
	static struct {
		const char *str;
		char key;
		const char *long_key;
		bool result;
	} tests[] = {
		{ "%x%y", 'x', NULL, TRUE },
		{ "%x%y", 'y', NULL, TRUE },
		{ "%x%y", 'z', NULL, FALSE },
		{ "%{foo}", 'f', NULL, FALSE },
		{ "%{foo}", 'o', NULL, FALSE },
		{ "%{foo}", '\0', "foo", TRUE },
		{ "%{foo}", 'o', "foo", TRUE },
		{ "%2.5Mx%y", 'x', NULL, TRUE },
		{ "%2.5M{foo}", '\0', "foo", TRUE },
	};

	test_begin("var_has_key");
	for (unsigned int i = 0; i < N_ELEMENTS(tests); i++)
		test_assert_idx(var_has_key(tests[i].str, tests[i].key, tests[i].long_key) == tests[i].result, i);
	test_end();
}

static const char *test_var_expand_hashing_func1(const char *data,
						 void *context ATTR_UNUSED)
{
	return data;
}

static int test_var_expand_bad_func(struct var_expand_context *ctx ATTR_UNUSED,
				    const char *key,
				    const char *field ATTR_UNUSED,
				    const char **result_r ATTR_UNUSED,
				    const char **error_r)
{
	if (strcmp(key, "notfound") == 0) return 0;
	*error_r = "Bad parameters";
	return -1;
}

static const struct var_expand_extension_func_table test_extension_funcs[] = {
	{ "notfound", test_var_expand_bad_func },
	{ "badparam", test_var_expand_bad_func },
	{ NULL, NULL }
};

static void test_var_expand_extensions(void)
{
	test_begin("var_expand_extensions");

	var_expand_register_func_array(test_extension_funcs);

	static struct var_expand_table table[] = {
		{'\0', "example", "value" },
		{'\0', "other-example", "other-value" },
		{'\0', NULL, NULL}
	};

	static struct {
		const char *in;
		const char *out;
	} tests[] = {
		{ "md5: %M{value} %{md5:value}", "md5: 1a79a4d60de6718e8e5b326e338ae533 1a79a4d60de6718e8e5b326e338ae533" },
		{ "sha1: %{sha1:value}", "sha1: c3499c2729730a7f807efb8676a92dcb6f8a3f8f" },
		{ "sha1: %{sha1:func1:example}", "sha1: c3499c2729730a7f807efb8676a92dcb6f8a3f8f" },
		{ "truncate: %{sha1;truncate=12:value}", "truncate: 0c34" },
		{ "truncate: %{sha1;truncate=16:value}", "truncate: c349" },
		{ "rounds,salt: %{sha1;rounds=1000,salt=seawater:value}", "rounds,salt: b515c85884f6b82dc7588279f3643a73e55d2289" },
		{ "rounds,salt,expand: %{sha1;rounds=1000,salt=%{other-value}:value} %{other-value}", "rounds,salt,expand: 49a598ee110af615e175f2e4511cc5d7ccff96ab other-example" },
		{ "format: %4.8{sha1:value}", "format: 9c272973" },
		{ "base64: %{sha1;format=base64:value}", "base64: w0mcJylzCn+AfvuGdqkty2+KP48=" },
	};

	static const struct var_expand_func_table func_table[] = {
		{ "func1", test_var_expand_hashing_func1 },
		{ NULL, NULL }
	};

	string_t *str = t_str_new(128);

	for (unsigned int i = 0; i < N_ELEMENTS(tests); i++) {
		str_truncate(str, 0);
		var_expand_with_funcs(str, tests[i].in, table,
				      func_table, NULL);
		test_assert_idx(strcmp(str_c(str), tests[i].out) == 0, i);
	}

	var_expand_with_funcs(str, "notfound: %{notfound:field}",
		    	      table, func_table, NULL);
	/* expect error */
	test_expect_errors(1);
	var_expand_with_funcs(str, "notfound: %{badparam:field}",
			      table, func_table, NULL);

	var_expand_unregister_func_array(test_extension_funcs);

	test_end();
}

static void test_var_expand_if(void)
{
	static const struct var_expand_table table[] = {
		{ 'a', "alpha", "alpha" },
		{ 'b', "beta", "beta" },
		{ 'o', "1", "one" },
		{ 't', "2", "two" },
		{ '\0', ";:", "evil1" },
		{ '\0', ";test;", "evil2" },
		{ '\0', NULL, NULL }
	};
	string_t *dest = t_str_new(64);
	test_begin("var_expand_if");

	static const struct var_expand_test tests[] = {
		/* basic numeric operand test */
		{ "%{if;1;==;1;yes;no}", "yes"},
		{ "%{if;1;==;2;yes;no}", "no"},
		{ "%{if;1;<;1;yes;no}", "no"},
		{ "%{if;1;<;2;yes;no}", "yes"},
		{ "%{if;1;<=;1;yes;no}", "yes"},
		{ "%{if;1;<=;2;yes;no}", "yes"},
		{ "%{if;1;>;1;yes;no}", "no"},
		{ "%{if;1;>;2;yes;no}", "no"},
		{ "%{if;1;>=;1;yes;no}", "yes"},
		{ "%{if;1;>=;2;yes;no}", "no"},
		{ "%{if;1;!=;1;yes;no}", "no"},
		{ "%{if;1;!=;2;yes;no}", "yes"},
		/* basic string operand test */
		{ "%{if;a;eq;a;yes;no}", "yes"},
		{ "%{if;a;eq;b;yes;no}", "no"},
		{ "%{if;a;lt;a;yes;no}", "no"},
		{ "%{if;a;lt;b;yes;no}", "yes"},
		{ "%{if;a;le;a;yes;no}", "yes"},
		{ "%{if;a;le;b;yes;no}", "yes"},
		{ "%{if;a;gt;a;yes;no}", "no"},
		{ "%{if;a;gt;b;yes;no}", "no"},
		{ "%{if;a;ge;a;yes;no}", "yes"},
		{ "%{if;a;ge;b;yes;no}", "no"},
		{ "%{if;a;ne;a;yes;no}", "no"},
		{ "%{if;a;ne;b;yes;no}", "yes"},
		{ "%{if;a;*;a;yes;no}", "yes"},
		{ "%{if;a;*;b;yes;no}", "no"},
		{ "%{if;a;*;*a*;yes;no}", "yes"},
		{ "%{if;a;*;*b*;yes;no}", "no"},
		{ "%{if;a;*;*;yes;no}", "yes"},
		{ "%{if;a;!*;a;yes;no}", "no"},
		{ "%{if;a;!*;b;yes;no}", "yes"},
		{ "%{if;a;!*;*a*;yes;no}", "no"},
		{ "%{if;a;!*;*b*;yes;no}", "yes"},
		{ "%{if;a;!*;*;yes;no}", "no"},
		{ "%{if;a;~;a;yes;no}", "yes"},
		{ "%{if;a;~;b;yes;no}", "no"},
		{ "%{if;a;~;.*a.*;yes;no}", "yes"},
		{ "%{if;a;~;.*b.*;yes;no}", "no"},
		{ "%{if;a;~;.*;yes;no}", "yes"},
		{ "%{if;a;!~;a;yes;no}", "no"},
		{ "%{if;a;!~;b;yes;no}", "yes"},
		{ "%{if;a;!~;.*a.*;yes;no}", "no"},
		{ "%{if;a;!~;.*b.*;yes;no}", "yes"},
		{ "%{if;a;!~;.*;yes;no}", "no"},
		{ "%{if;this is test;~;^test;yes;no}", "no"},
		{ "%{if;this is test;~;.*test;yes;no}", "yes"},
		/* variable expansion */
		{ "%{if;%a;eq;%a;yes;no}", "yes"},
		{ "%{if;%a;eq;%b;yes;no}", "no"},
		{ "%{if;%{alpha};eq;%{alpha};yes;no}", "yes"},
		{ "%{if;%{alpha};eq;%{beta};yes;no}", "no"},
		{ "%{if;%o;eq;%o;yes;no}", "yes"},
		{ "%{if;%o;eq;%t;yes;no}", "no"},
		{ "%{if;%{one};eq;%{one};yes;no}", "yes"},
		{ "%{if;%{one};eq;%{two};yes;no}", "no"},
		{ "%{if;%{one};eq;%{one};%{one};%{two}}", "1"},
		{ "%{if;%{one};gt;%{two};%{one};%{two}}", "2"},
		{ "%{if;%{evil1};eq;\\;\\:;%{evil2};no}", ";test;"},
		/* inner if */
		{ "%{if;%{if;%{one};eq;1;1;0};eq;%{if;%{two};eq;2;2;3};yes;no}", "no"},
		/* no false */
		{ "%{if;1;==;1;yes}", "yes"},
		{ "%{if;1;==;2;yes}", ""},
		/* invalid input */
		{ "%{if;}", ""},
		{ "%{if;1;}", ""},
		{ "%{if;1;==;}", ""},
		{ "%{if;1;==;2;}", ""},
		{ "%{if;1;fu;2;yes;no}", ""},
		/* missing variables */
		{ "%{if;%{missing1};==;%{missing2};yes;no}", ""},
	};

	test_expect_errors(6);

	for(size_t i = 0; i < N_ELEMENTS(tests); i++) {
		str_truncate(dest, 0);
		var_expand(dest, tests[i].in, table);
		test_assert_idx(strcmp(tests[i].out, str_c(dest)) == 0, i);
	}

	test_expect_no_more_errors();

	test_end();
}

void test_var_expand(void)
{
	test_var_expand_ranges();
	test_var_expand_builtin();
	test_var_get_key_range();
	test_var_expand_with_funcs();
	test_var_get_key();
	test_var_has_key();
	test_var_expand_extensions();
	test_var_expand_if();
}

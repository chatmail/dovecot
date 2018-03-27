/* Copyright (c) 2012-2018 Dovecot authors, see the included COPYING file */

#include "test-lib.h"
#include "str.h"

static void test_str_append(void)
{
	string_t *str = t_str_new(32);
	string_t *str2 = t_str_new(32);

	test_begin("str_append_*()");
	str_append(str, "foo");
	str_append_c(str, '|');
	str_append_c(str, '\0');
	test_assert(str->used == 5 && memcmp(str_data(str), "foo|\0", 5) == 0);

	str_append(str2, "sec");
	str_append_c(str2, '\0');
	str_append(str2, "ond");
	str_append_str(str, str2);
	test_assert(str->used == 5+7 && memcmp(str_data(str), "foo|\0sec\0ond", 5+7) == 0);

	test_end();
}

static void test_str_c(void)
{
	string_t *str;
	unsigned int i, j;

	test_begin("str_c()");
	str = t_str_new(0);
	T_BEGIN {
		(void)str_c(str);
	} T_END;

	for (i = 0; i < 32; i++) T_BEGIN {
		str = t_str_new(15);
		for (j = 0; j < i; j++)
			str_append_c(str, 'x');
		T_BEGIN {
			(void)str_c(str);
		} T_END;
	} T_END;
	test_end();
}

static void test_str_insert(void)
{
	string_t *str = t_str_new(32);

	test_begin("str_insert()");
	str_insert(str, 0, "foo");
	str_insert(str, 3, ">");
	str_insert(str, 3, "bar");
	str_insert(str, 0, "<");
	test_assert(str->used == 8 && memcmp(str_data(str), "<foobar>", 8) == 0);

	str_insert(str, 10, "!");
	test_assert(str->used == 11 && memcmp(str_data(str), "<foobar>\0\0!", 11) == 0);

	test_end();
}

static void test_str_delete(void)
{
	string_t *str = t_str_new(32);

	test_begin("str_delete()");
	str_delete(str, 0, 100);
	str_append(str, "123456");
	str_delete(str, 0, 1);
	str_delete(str, 4, 1);
	str_delete(str, 1, 1);
	test_assert(str->used == 3 && memcmp(str_data(str), "245", 3) == 0);

	str_delete(str, 1, 2);
	test_assert(str->used == 1 && memcmp(str_data(str), "2", 1) == 0);

	str_append(str, "bar");
	str_delete(str, 1, 100);
	test_assert(str->used == 1 && memcmp(str_data(str), "2", 1) == 0);

	test_end();
}

static void test_str_append_n(void)
{
	string_t *str = t_str_new(32);

	test_begin("str_append_n()");
	str_append_n(str, "foo", 0);
	test_assert(str->used == 0);

	str_append_n(str, "\0foo", 4);
	test_assert(str->used == 0);

	str_append_n(str, "foo", 3);
	test_assert(str->used == 3 && memcmp(str_data(str), "foo", 3) == 0);
	str_truncate(str, 0);

	str_append_n(str, "foo", 2);
	test_assert(str->used == 2 && memcmp(str_data(str), "fo", 2) == 0);
	str_truncate(str, 0);

	str_append_n(str, "foo\0bar", 7);
	test_assert(str->used == 3 && memcmp(str_data(str), "foo", 3) == 0);
	str_truncate(str, 0);
	test_end();
}

static void test_str_truncate(void)
{
	string_t *str = t_str_new(8);
	int i;

	test_begin("str_truncate()");
	str_append(str, "123456");
	for (i = 100; i >= 6; i--) {
		str_truncate(str, i);
		test_assert_idx(str_len(str) == 6, i);
	}
	for (; i >= 0; i--) {
		str_truncate(str, i);
		test_assert_idx(str_len(str) == (unsigned int)i, i);
	}
	test_end();
}

void test_str(void)
{
	test_str_append();
	test_str_c();
	test_str_insert();
	test_str_delete();
	test_str_append_n();
	test_str_truncate();
}

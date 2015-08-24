/* Copyright (c) 2014-2015 Dovecot authors, see the included COPYING file */

/* Wrap srand() so that we can reproduce fuzzed tests */

#include "lib.h"
#include <stdlib.h>

static int seeded = 0;
static unsigned int seed;
static char const *env_seed;

int rand_get_seed_count(void)
{
	return seeded;
}
unsigned int rand_get_last_seed(void)
{
	i_assert(seeded > 0);
	return seed;
}
void rand_set_seed(unsigned int s)
{
	if (seeded == 0) {
		env_seed = getenv("DOVECOT_SRAND");
		if (env_seed != NULL)
			seed = strtoul(env_seed, NULL, 0);
	}
	seeded++;
	if (env_seed == NULL)
		seed = s;

	srand(seed);
}

/* Copyright (c) 2002-2007 Dovecot authors, see the included COPYING file */

#ifndef __SIEVE_H
#define __SIEVE_H

#include "lib.h"

#include <stdio.h>

struct sieve_binary;
struct sieve_script;

#include "sieve-error.h"

bool sieve_init(const char *plugins);
void sieve_deinit(void);

struct sieve_binary *sieve_compile_script
    (struct sieve_script *script, struct sieve_error_handler *ehandler);

const char *sieve_get_capabilities(void);

#endif

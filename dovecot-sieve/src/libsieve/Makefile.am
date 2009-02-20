pkglibexecdir = $(libexecdir)/dovecot

noinst_LTLIBRARIES = libsieve.la

AM_YFLAGS = -d -p $*

AM_CPPFLAGS = \
	-I$(dovecot_incdir) \
	-I$(dovecot_incdir)/src/lib \
	-I$(top_srcdir)/src

addr-lex.c: addr-lex.l
	$(LEX) -t -Paddr addr-lex.l > addr-lex.c

sieve-lex.c: sieve-lex.l
	$(LEX) -t sieve-lex.l > sieve-lex.c

libsieve_la_SOURCES = \
	addr.y \
	sieve.y \
	addr-lex.l \
	sieve-lex.l \
	bc_dump.c \
	bc_emit.c \
	bc_eval.c \
	bc_generate.c \
	comparator.c \
	interp.c \
	message.c \
	parseaddr.c \
	script.c \
	sieve_err.c \
	tree.c

noinst_HEADERS = \
	addr.h \
	bytecode.h \
	comparator.h \
	interp.h \
	message.h \
	parseaddr.h \
	script.h \
	sieve.h \
	sieve_err.h \
	sieve_interface.h \
	tree.h

if HAVE_DOVECOT_LIBS
pkglibexec_PROGRAMS = sievec sieved

sievec_SOURCES = \
	sievec.c \
	../map.c \
	../imparse.c

sieved_SOURCES = \
	sieved.c \
	../map.c \
	../imparse.c

sievec_LDADD = \
	libsieve.la \
	$(dovecotdir)/src/lib/liblib.a

sieved_LDADD = \
	libsieve.la \
	$(dovecotdir)/src/lib/liblib.a

notbuilt_sources =
else
notbuilt_sources = sievec.c sieved.c
endif

EXTRA_DIST = \
	addr-lex.l \
	sieve-lex.l \
	AUTHORS \
	COPYING \
	NEWS \
	README \
	$(notbuilt_sources)

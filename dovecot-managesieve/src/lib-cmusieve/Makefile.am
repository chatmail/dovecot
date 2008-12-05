noinst_LTLIBRARIES = libsieve_cmu.la

MOSTLYCLEANFILES = imparse.c map.c

AM_CPPFLAGS = \
	-I$(dovecot_incdir) \
	-I$(dovecot_incdir)/src/lib \
	-I$(dovecot_sievedir)/src/ \
	-I$(dovecot_sievedir)/src/libsieve 

sieve_plugin=$(dovecot_sievedir)/src/libsieve/libsieve.la

libsieve_cmu_la_DEPENDENCIES = $(sieve_plugin)
libsieve_cmu_la_LIBADD = $(sieve_plugin)

libsieve_cmu_la_SOURCES = \
	imparse.c \
	map.c \
	sieve-error.c \
	sieve-script.c \
	sieve.c 

noinst_HEADERS = \
	sieve-common.h \
	sieve-error.h \
	sieve-error-private.h \
	sieve-script.h \
	sieve-script-private.h \
	sieve.h

imparse.c map.c: $(dovecot_sievedir)/src/$@
	cp $(dovecot_sievedir)/src/$@ $@



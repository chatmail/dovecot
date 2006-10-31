SUBDIRS = libsieve

AM_CPPFLAGS = \
	-I$(dovecotdir) \
	-I$(dovecotdir)/src/lib \
	-I$(dovecotdir)/src/lib-dict \
	-I$(dovecotdir)/src/lib-mail \
	-I$(dovecotdir)/src/lib-storage \
	-I$(dovecotdir)/src/deliver

lda_moduledir = $(libexecdir)/dovecot/lda

lib90_cmusieve_plugin_la_LDFLAGS = -module -avoid-version

lda_module_LTLIBRARIES = \
	lib90_cmusieve_plugin.la

lib90_cmusieve_plugin_la_LIBADD = \
	libsieve/libsieve.la

lib90_cmusieve_plugin_la_SOURCES = \
	cmusieve-plugin.c \
	imparse.c \
	map.c \
	sieve-cmu.c

noinst_HEADERS = \
	cmusieve-plugin.h \
	imparse.h \
	libconfig.h \
	map.h \
	xmalloc.h

SUBDIRS = libsieve

AM_CPPFLAGS = \
	-I$(dovecot_incdir) \
	-I$(dovecot_incdir)/src/lib \
	-I$(dovecot_incdir)/src/lib-dict \
	-I$(dovecot_incdir)/src/lib-mail \
	-I$(dovecot_incdir)/src/lib-storage \
	-I$(dovecot_incdir)/src/deliver

lda_moduledir = $(libexecdir)/dovecot/modules/lda

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

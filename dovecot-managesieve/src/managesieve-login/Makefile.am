pkglibexecdir = $(libexecdir)/dovecot

pkglibexec_PROGRAMS = managesieve-login

AM_CPPFLAGS = \
	-I$(dovecot_incdir) \
	-I$(dovecot_incdir)/src/lib \
	-I$(dovecot_incdir)/src/lib-auth \
	-I$(dovecot_incdir)/src/lib-mail \
	-I$(dovecot_incdir)/src/lib-index \
	-I$(dovecot_incdir)/src/lib-storage \
	-I$(dovecot_incdir)/src/login-common \
	-I$(top_srcdir)/src/lib-managesieve \
	-I$(SIEVE_PLUGIN_INCLUDE)

managesieve_login_LDADD = \
	$(SIEVE_PLUGIN_LIB) \
	$(dovecot_incdir)/src/login-common/liblogin-common.a \
	../lib-managesieve/libmanagesieve.a \
	../lib-sievestorage/libsievestorage.a \
	$(dovecot_incdir)/src/lib-storage/libstorage.a \
	$(dovecot_incdir)/src/lib-index/libindex.a \
	$(dovecot_incdir)/src/lib-imap/libimap.a \
	$(dovecot_incdir)/src/lib-mail/libmail.a \
	$(dovecot_incdir)/src/lib-charset/libcharset.a \
	$(dovecot_incdir)/src/lib-auth/libauth.a \
	$(dovecot_incdir)/src/lib/liblib.a \
	$(SSL_LIBS)

managesieve_login_SOURCES = \
	client.c \
	client-authenticate.c \
	managesieve-proxy.c

noinst_HEADERS = \
	client.h \
	client-authenticate.h \
	managesieve-proxy.h

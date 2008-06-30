pkglibexecdir = $(libexecdir)/dovecot

pkglibexec_PROGRAMS = managesieve

AM_CPPFLAGS = \
	-I$(dovecot_incdir) \
	-I$(dovecot_incdir)/src/lib \
	-I$(dovecot_incdir)/src/lib-dict \
	-I$(dovecot_incdir)/src/lib-mail \
	-I$(dovecot_incdir)/src/lib-index \
	-I$(dovecot_incdir)/src/lib-storage \
	-DMODULEDIR=\""$(moduledir)"\" \
	-I$(top_srcdir)/src/lib-managesieve \
	-I$(top_srcdir)/src/lib-sievestorage \
	-I$(SIEVE_PLUGIN_INCLUDE)

managesieve_LDFLAGS = -export-dynamic

libs = \
	../lib-managesieve/libmanagesieve.a \
	../lib-sievestorage/libsievestorage.a \
	$(SIEVE_PLUGIN_LIB) \
	$(dovecot_incdir)/src/lib-storage/libstorage.a \
	$(dovecot_incdir)/src/lib-imap/libimap.a \
	$(dovecot_incdir)/src/lib-index/libindex.a \
	$(dovecot_incdir)/src/lib-mail/libmail.a \
	$(dovecot_incdir)/src/lib-charset/libcharset.a \
	$(dovecot_incdir)/src/lib-dict/libdict.a \
	$(dovecot_incdir)/src/lib-charset/libcharset.a \
	$(dovecot_incdir)/src/lib/liblib.a

managesieve_LDADD = \
	$(libs) \
	$(LIBICONV) \
	$(RAND_LIBS) \
	$(MODULE_LIBS) 

managesieve_DEPENDENCIES = $(libs)

cmds = \
	cmd-capability.c \
	cmd-logout.c \
	cmd-putscript.c \
	cmd-getscript.c \
	cmd-setactive.c \
	cmd-deletescript.c \
	cmd-listscripts.c \
	cmd-havespace.c 

managesieve_SOURCES = \
	$(cmds) \
	client.c \
	commands.c \
	main.c 

noinst_HEADERS = \
	client.h \
	commands.h \
	common.h 

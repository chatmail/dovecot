pkglibexecdir = $(libexecdir)/dovecot

pkglibexec_PROGRAMS = \
	authtest \
	rawlog \
	gdbhelper \
	idxview \
	imap-utf7 \
	listview \
	logview \
	maildirlock \
	threadview

sbin_PROGRAMS = dovecotpw

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-auth \
	-I$(top_srcdir)/src/lib-mail \
	-I$(top_srcdir)/src/lib-imap \
	-I$(top_srcdir)/src/lib-index \
	-I$(top_srcdir)/src/lib-storage/index/maildir \
	-I$(top_srcdir)/src/auth \
	-DPKG_RUNDIR=\""$(rundir)"\"

authtest_LDADD = \
	../lib-auth/libauth.a \
	../lib/liblib.a
authtest_SOURCES = \
	authtest.c

rawlog_LDADD = \
	../lib/liblib.a
rawlog_SOURCES = \
	rawlog.c

gdbhelper_LDADD = \
	../lib/liblib.a
gdbhelper_SOURCES = \
	gdbhelper.c

idxview_LDADD = \
	../lib-index/libindex.a \
	../lib/liblib.a
idxview_SOURCES = \
	idxview.c

imap_utf7_LDADD = \
	../lib-imap/imap-utf7.o \
	../lib/liblib.a
imap_utf7_SOURCES = \
	imap-utf7.c

listview_LDADD = \
	../lib/liblib.a
listview_SOURCES = \
	listview.c

logview_LDADD = \
	../lib/liblib.a
logview_SOURCES = \
	logview.c

maildirlock_LDADD = \
	../lib/liblib.a
maildirlock_SOURCES = \
	maildirlock.c

threadview_LDADD = \
	../lib/liblib.a
threadview_SOURCES = \
	threadview.c

dovecotpw_LDADD = \
	../auth/libpassword.a \
	../lib-ntlm/libntlm.a \
	../lib-otp/libotp.a \
	../lib/liblib.a \
	$(AUTH_LIBS) \
	$(MODULE_LIBS)

dovecotpw_SOURCES = \
	dovecotpw.c

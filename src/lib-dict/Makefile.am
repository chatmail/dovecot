noinst_LIBRARIES = libdict.a

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-sql \
	-DPKG_RUNDIR=\""$(rundir)"\" \
	$(SQL_CFLAGS)

libdict_a_SOURCES = \
	dict.c \
	dict-client.c \
	dict-sql.c

headers = \
	dict.h \
	dict-client.h \
	dict-private.h \
	dict-sql.h

if INSTALL_HEADERS
  pkginc_libdir=$(pkgincludedir)/src/lib-dict
  pkginc_lib_HEADERS = $(headers)
else
  noinst_HEADERS = $(headers)
endif

noinst_LIBRARIES = libstorage_subscription_file.a

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-storage \
	-I$(top_srcdir)/src/lib-mail

libstorage_subscription_file_a_SOURCES = \
	subscription-file.c

headers = \
	subscription-file.h

if INSTALL_HEADERS
  pkginc_libdir=$(pkgincludedir)/src/lib-storage/subscription-file
  pkginc_lib_HEADERS = $(headers)
else
  noinst_HEADERS = $(headers)
endif

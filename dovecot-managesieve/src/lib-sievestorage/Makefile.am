noinst_LIBRARIES = libsievestorage.a

INCLUDES = \
	-I$(dovecot_incdir) \
	-I$(dovecot_incdir)/src/lib \
	-I$(docecot_incdir)/src/lib-mail \
	-I$(SIEVE_PLUGIN_INCLUDE)

libsievestorage_a_SOURCES = \
	sieve-storage-save.c \
	sieve-storage-script.c \
	sieve-storage-list.c \
	sieve-storage.c 

noinst_HEADERS = \
	sieve-storage-save.h \
	sieve-storage-script.h \
	sieve-storage-list.h \
	sieve-storage-private.h \
	sieve-storage.h

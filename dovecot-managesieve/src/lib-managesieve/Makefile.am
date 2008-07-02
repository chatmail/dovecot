noinst_LIBRARIES = libmanagesieve.a

AM_CPPFLAGS = \
	-I$(dovecot_incdir) \
	-I$(dovecot_incdir)/src/lib \
	-I$(dovecot_incdir)/src/lib-charset \
	-I$(dovecot_incdir)/src/lib-mail

libmanagesieve_a_SOURCES = \
	managesieve-quote.c \
	managesieve-parser.c 

noinst_HEADERS = \
	managesieve-quote.h \
	managesieve-parser.h 

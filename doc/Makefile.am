SUBDIRS = wiki

docfiles = \
	auth-protocol.txt \
	documentation.txt \
	securecoding.txt \
	thread-refs.txt

if BUILD_DOCS
doc_DATA = $(docfiles)
endif

confdir = $(sysconfdir)
conf_DATA = \
	dovecot-db-example.conf \
	dovecot-dict-sql-example.conf \
	dovecot-ldap-example.conf \
	dovecot-sql-example.conf

EXTRA_DIST = \
	dovecot-initd.sh \
	mkcert.sh \
	dovecot-openssl.cnf \
	solr-schema.xml \
	$(docfiles) \
	$(conf_DATA)

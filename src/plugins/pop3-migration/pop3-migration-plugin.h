#ifndef POP3_MIGRATION_PLUGIN_H
#define POP3_MIGRATION_PLUGIN_H

struct module;

void pop3_migration_plugin_init(struct module *module);
void pop3_migration_plugin_deinit(void);

int pop3_migration_get_hdr_sha1(uint32_t mail_seq, struct istream *input,
				uoff_t hdr_size,
				unsigned char sha1_r[SHA1_RESULTLEN],
				bool *have_eoh_r);

#endif

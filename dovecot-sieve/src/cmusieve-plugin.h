#ifndef __CMUSIEVE_PLUGIN_H
#define __CMUSIEVE_PLUGIN_H

int cmu_sieve_run(struct mail_namespace *namespaces,
		  struct mail_storage **storage_r, struct mail *mail,
		  const char *script_path, const char *destaddr,
		  const char *username, const char *mailbox);

void cmusieve_plugin_init(void);
void cmusieve_plugin_deinit(void);

#endif

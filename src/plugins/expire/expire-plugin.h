#ifndef EXPIRE_PLUGIN_H
#define EXPIRE_PLUGIN_H

extern uid_t global_mail_uid;
extern gid_t global_mail_gid;

void expire_plugin_init(void);
void expire_plugin_deinit(void);

#endif

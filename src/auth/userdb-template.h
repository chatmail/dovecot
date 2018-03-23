#ifndef USERDB_TEMPLATE_H
#define USERDB_TEMPLATE_H

struct userdb_template *
userdb_template_build(pool_t pool, const char *userdb_name, const char *args);
int userdb_template_export(struct userdb_template *tmpl,
			   struct auth_request *auth_request,
			   const char **error_r);
bool userdb_template_remove(struct userdb_template *tmpl,
			    const char *key, const char **value_r);
bool userdb_template_is_empty(struct userdb_template *tmpl);
const char *const *userdb_template_get_args(struct userdb_template *tmpl,
					    unsigned int *count_r);

#endif

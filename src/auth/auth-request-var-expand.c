/* Copyright (c) 2002-2018 Dovecot authors, see the included COPYING file */

#include "auth-common.h"
#include "str.h"
#include "strescape.h"
#include "auth-request.h"

struct auth_request_var_expand_ctx {
	const struct auth_request *auth_request;
	auth_request_escape_func_t *escape_func;
};

const struct var_expand_table
auth_request_var_expand_static_tab[AUTH_REQUEST_VAR_TAB_COUNT+1] = {
	{ 'u', NULL, "user" },
	{ 'n', NULL, "username" },
	{ 'd', NULL, "domain" },
	{ 's', NULL, "service" },
	{ 'h', NULL, "home" },
	{ 'l', NULL, "lip" },
	{ 'r', NULL, "rip" },
	{ 'p', NULL, "pid" },
	{ 'w', NULL, "password" },
	{ '!', NULL, NULL },
	{ 'm', NULL, "mech" },
	{ 'c', NULL, "secured" },
	{ 'a', NULL, "lport" },
	{ 'b', NULL, "rport" },
	{ 'k', NULL, "cert" },
	{ '\0', NULL, "login_user" },
	{ '\0', NULL, "login_username" },
	{ '\0', NULL, "login_domain" },
	{ '\0', NULL, "session" },
	{ '\0', NULL, "real_lip" },
	{ '\0', NULL, "real_rip" },
	{ '\0', NULL, "real_lport" },
	{ '\0', NULL, "real_rport" },
	{ '\0', NULL, "domain_first" },
	{ '\0', NULL, "domain_last" },
	{ '\0', NULL, "master_user" },
	{ '\0', NULL, "session_pid" },
	{ '\0', NULL, "orig_user" },
	{ '\0', NULL, "orig_username" },
	{ '\0', NULL, "orig_domain" },
	{ '\0', NULL, "auth_user" },
	{ '\0', NULL, "auth_username" },
	{ '\0', NULL, "auth_domain" },
	{ '\0', NULL, "local_name" },
	{ '\0', NULL, "client_id" },

	/* aliases: */
	{ '\0', NULL, "local_ip" },
	{ '\0', NULL, "remote_ip" },
	{ '\0', NULL, "local_port" },
	{ '\0', NULL, "remote_port" },
	{ '\0', NULL, "real_local_ip" },
	{ '\0', NULL, "real_remote_ip" },
	{ '\0', NULL, "real_local_port" },
	{ '\0', NULL, "real_remote_port" },
	{ '\0', NULL, "mechanism" },
	{ '\0', NULL, "original_user" },
	{ '\0', NULL, "original_username" },
	{ '\0', NULL, "original_domain" },

	/* be sure to update AUTH_REQUEST_VAR_TAB_COUNT */
	{ '\0', NULL, NULL }
};

static const char *
escape_none(const char *string,
	    const struct auth_request *request ATTR_UNUSED)
{
	return string;
}

const char *
auth_request_str_escape(const char *string,
			const struct auth_request *request ATTR_UNUSED)
{
	return str_escape(string);
}

struct var_expand_table *
auth_request_get_var_expand_table_full(const struct auth_request *auth_request,
				       const char *username,
				       auth_request_escape_func_t *escape_func,
				       unsigned int *count)
{
	const struct auth_request_fields *fields = &auth_request->fields;
	const unsigned int auth_count =
		N_ELEMENTS(auth_request_var_expand_static_tab);
	struct var_expand_table *tab, *ret_tab;
	const char *orig_user, *auth_user;

	if (escape_func == NULL)
		escape_func = escape_none;

	/* keep the extra fields at the beginning. the last static_tab field
	   contains the ending NULL-fields. */
	tab = ret_tab = t_new(struct var_expand_table,
			      MALLOC_ADD(*count, auth_count));
	tab += *count;
	*count += auth_count;

	memcpy(tab, auth_request_var_expand_static_tab,
	       auth_count * sizeof(*tab));

	if (username == NULL)
		username = "";
	tab[0].value = escape_func(username, auth_request);
	tab[1].value = escape_func(t_strcut(username, '@'),
				   auth_request);
	tab[2].value = i_strchr_to_next(username, '@');
	if (tab[2].value != NULL)
		tab[2].value = escape_func(tab[2].value, auth_request);
	tab[3].value = escape_func(fields->service, auth_request);
	/* tab[4] = we have no home dir */
	if (fields->local_ip.family != 0)
		tab[5].value = tab[35].value =
			net_ip2addr(&fields->local_ip);
	if (fields->remote_ip.family != 0)
		tab[6].value = tab[36].value =
			net_ip2addr(&fields->remote_ip);
	tab[7].value = dec2str(auth_request->client_pid);
	if (auth_request->mech_password != NULL) {
		tab[8].value = escape_func(auth_request->mech_password,
					   auth_request);
	}
	if (auth_request->userdb_lookup) {
		tab[9].value = auth_request->userdb == NULL ? "" :
			dec2str(auth_request->userdb->userdb->id);
	} else {
		tab[9].value = auth_request->passdb == NULL ? "" :
			dec2str(auth_request->passdb->passdb->id);
	}
	tab[10].value = tab[43].value = fields->mech_name == NULL ? "" :
		escape_func(fields->mech_name, auth_request);
	switch (fields->secured) {
	case AUTH_REQUEST_SECURED_NONE: tab[11].value = ""; break;
	case AUTH_REQUEST_SECURED: tab[11].value = "secured"; break;
	case AUTH_REQUEST_SECURED_TLS: tab[11].value = "TLS"; break;
	default: tab[11].value = ""; break;
	};
	tab[12].value = tab[37].value = dec2str(fields->local_port);
	tab[13].value = tab[38].value = dec2str(fields->remote_port);
	tab[14].value = fields->valid_client_cert ? "valid" : "";

	if (fields->requested_login_user != NULL) {
		const char *login_user = fields->requested_login_user;

		tab[15].value = escape_func(login_user, auth_request);
		tab[16].value = escape_func(t_strcut(login_user, '@'),
					    auth_request);
		tab[17].value = i_strchr_to_next(login_user, '@');
		if (tab[17].value != NULL) {
			tab[17].value = escape_func(tab[17].value,
						    auth_request);
		}
	}
	tab[18].value = fields->session_id == NULL ? NULL :
		escape_func(fields->session_id, auth_request);
	if (fields->real_local_ip.family != 0)
		tab[19].value = tab[39].value =
			net_ip2addr(&fields->real_local_ip);
	if (fields->real_remote_ip.family != 0)
		tab[20].value = tab[40].value =
			net_ip2addr(&fields->real_remote_ip);
	tab[21].value = tab[41].value = dec2str(fields->real_local_port);
	tab[22].value = tab[42].value = dec2str(fields->real_remote_port);
	tab[23].value = i_strchr_to_next(username, '@');
	if (tab[23].value != NULL) {
		tab[23].value = escape_func(t_strcut(tab[23].value, '@'),
					    auth_request);
	}
	tab[24].value = strrchr(username, '@');
	if (tab[24].value != NULL)
		tab[24].value = escape_func(tab[24].value+1, auth_request);
	tab[25].value = fields->master_user == NULL ? NULL :
		escape_func(fields->master_user, auth_request);
	tab[26].value = auth_request->session_pid == (pid_t)-1 ? NULL :
		dec2str(auth_request->session_pid);

	orig_user = fields->original_username != NULL ?
		fields->original_username : username;
	tab[27].value = tab[44].value = escape_func(orig_user, auth_request);
	tab[28].value = tab[45].value = escape_func(t_strcut(orig_user, '@'), auth_request);
	tab[29].value = tab[46].value = i_strchr_to_next(orig_user, '@');
	if (tab[29].value != NULL)
		tab[29].value = tab[46].value =
			escape_func(tab[29].value, auth_request);

	if (fields->master_user != NULL)
		auth_user = fields->master_user;
	else
		auth_user = orig_user;
	tab[30].value = escape_func(auth_user, auth_request);
	tab[31].value = escape_func(t_strcut(auth_user, '@'), auth_request);
	tab[32].value = i_strchr_to_next(auth_user, '@');
	if (tab[32].value != NULL)
		tab[32].value = escape_func(tab[32].value, auth_request);
	if (fields->local_name != NULL)
		tab[33].value = escape_func(fields->local_name, auth_request);
	if (fields->client_id != NULL)
		tab[34].value = escape_func(fields->client_id, auth_request);
	return ret_tab;
}

const struct var_expand_table *
auth_request_get_var_expand_table(const struct auth_request *auth_request,
				  auth_request_escape_func_t *escape_func)
{
	unsigned int count = 0;

	return auth_request_get_var_expand_table_full(auth_request,
		auth_request->fields.user, escape_func, &count);
}

static const char *field_get_default(const char *data)
{
	const char *p;

	p = strchr(data, ':');
	if (p == NULL)
		return "";
	else {
		/* default value given */
		return p+1;
	}
}

static int
auth_request_var_expand_func_passdb(const char *data, void *context,
				    const char **value_r,
				    const char **error_r ATTR_UNUSED)
{
	struct auth_request_var_expand_ctx *ctx = context;
	const char *field_name = t_strcut(data, ':');
	const char *value;

	value = auth_fields_find(ctx->auth_request->fields.extra_fields, field_name);
	*value_r = ctx->escape_func(value != NULL ? value : field_get_default(data),
				    ctx->auth_request);
	return 1;
}

static int
auth_request_var_expand_func_userdb(const char *data, void *context,
				    const char **value_r,
				    const char **error_r ATTR_UNUSED)
{
	struct auth_request_var_expand_ctx *ctx = context;
	const char *field_name = t_strcut(data, ':');
	const char *value;

	value = ctx->auth_request->fields.userdb_reply == NULL ? NULL :
		auth_fields_find(ctx->auth_request->fields.userdb_reply, field_name);
	*value_r = ctx->escape_func(value != NULL ? value : field_get_default(data),
				    ctx->auth_request);
	return 1;
}

const struct var_expand_func_table auth_request_var_funcs_table[] = {
	{ "passdb", auth_request_var_expand_func_passdb },
	{ "userdb", auth_request_var_expand_func_userdb },
	{ NULL, NULL }
};

int auth_request_var_expand(string_t *dest, const char *str,
			    const struct auth_request *auth_request,
			    auth_request_escape_func_t *escape_func,
			    const char **error_r)
{
	return auth_request_var_expand_with_table(dest, str, auth_request,
		auth_request_get_var_expand_table(auth_request, escape_func),
		escape_func, error_r);
}

int auth_request_var_expand_with_table(string_t *dest, const char *str,
				       const struct auth_request *auth_request,
				       const struct var_expand_table *table,
				       auth_request_escape_func_t *escape_func,
				       const char **error_r)
{
	struct auth_request_var_expand_ctx ctx;

	i_zero(&ctx);
	ctx.auth_request = auth_request;
	ctx.escape_func = escape_func == NULL ? escape_none : escape_func;
	return var_expand_with_funcs(dest, str, table,
				     auth_request_var_funcs_table, &ctx, error_r);
}

int t_auth_request_var_expand(const char *str,
			      const struct auth_request *auth_request ATTR_UNUSED,
			      auth_request_escape_func_t *escape_func ATTR_UNUSED,
			      const char **value_r, const char **error_r)
{
	string_t *dest = t_str_new(128);
	int ret = auth_request_var_expand(dest, str, auth_request,
					  escape_func, error_r);
	*value_r = str_c(dest);
	return ret;
}

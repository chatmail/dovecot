/* Copyright (c) 2008-2015 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "hostpid.h"
#include "net.h"
#include "module-dir.h"
#include "home-expand.h"
#include "safe-mkstemp.h"
#include "str.h"
#include "strescape.h"
#include "var-expand.h"
#include "settings-parser.h"
#include "iostream-ssl.h"
#include "fs-api.h"
#include "auth-master.h"
#include "master-service.h"
#include "dict.h"
#include "mail-storage-settings.h"
#include "mail-storage-private.h"
#include "mail-storage-service.h"
#include "mail-namespace.h"
#include "mail-storage.h"
#include "mail-autoexpunge.h"
#include "mail-user.h"


struct mail_user_module_register mail_user_module_register = { 0 };
struct auth_master_connection *mail_user_auth_master_conn;

static void mail_user_deinit_base(struct mail_user *user)
{
	if (user->_attr_dict != NULL) {
		(void)dict_wait(user->_attr_dict);
		dict_deinit(&user->_attr_dict);
	}
	mail_namespaces_deinit(&user->namespaces);
}

static void mail_user_stats_fill_base(struct mail_user *user ATTR_UNUSED,
				      struct stats *stats ATTR_UNUSED)
{
}

struct mail_user *mail_user_alloc(const char *username,
				  const struct setting_parser_info *set_info,
				  const struct mail_user_settings *set)
{
	struct mail_user *user;
	const char *error;
	pool_t pool;

	i_assert(username != NULL);
	i_assert(*username != '\0');

	pool = pool_alloconly_create(MEMPOOL_GROWING"mail user", 16*1024);
	user = p_new(pool, struct mail_user, 1);
	user->pool = pool;
	user->refcount = 1;
	user->username = p_strdup(pool, username);
	user->set_info = set_info;
	user->unexpanded_set = settings_dup(set_info, set, pool);
	user->set = settings_dup(set_info, set, pool);
	user->service = master_service_get_name(master_service);
	user->default_normalizer = uni_utf8_to_decomposed_titlecase;

	/* check settings so that the duplicated structure will again
	   contain the parsed fields */
	if (!settings_check(set_info, pool, user->set, &error))
		i_panic("Settings check unexpectedly failed: %s", error);

	user->v.deinit = mail_user_deinit_base;
	user->v.stats_fill = mail_user_stats_fill_base;
	p_array_init(&user->module_contexts, user->pool, 5);
	return user;
}

static void
mail_user_expand_plugins_envs(struct mail_user *user)
{
	const char **envs, *home;
	string_t *str;
	unsigned int i, count;

	if (!array_is_created(&user->set->plugin_envs))
		return;

	str = t_str_new(256);
	envs = array_get_modifiable(&user->set->plugin_envs, &count);
	i_assert((count % 2) == 0);
	for (i = 0; i < count; i += 2) {
		if (user->_home == NULL &&
		    var_has_key(envs[i+1], 'h', "home") &&
		    mail_user_get_home(user, &home) <= 0) {
			user->error = p_strdup_printf(user->pool,
				"userdb didn't return a home directory, "
				"but plugin setting %s used it (%%h): %s",
				envs[i], envs[i+1]);
			return;
		}
		str_truncate(str, 0);
		var_expand_with_funcs(str, envs[i+1],
				      mail_user_var_expand_table(user),
				      mail_user_var_expand_func_table, user);
		envs[i+1] = p_strdup(user->pool, str_c(str));
	}
}

int mail_user_init(struct mail_user *user, const char **error_r)
{
	const struct mail_storage_settings *mail_set;
	const char *home, *key, *value;
	bool need_home_dir;

	need_home_dir = user->_home == NULL &&
		settings_vars_have_key(user->set_info, user->set,
				       'h', "home", &key, &value);
	if (need_home_dir && mail_user_get_home(user, &home) <= 0) {
		user->error = p_strdup_printf(user->pool,
			"userdb didn't return a home directory, "
			"but %s used it (%%h): %s", key, value);
	}

	/* expand settings after we can expand %h */
	settings_var_expand_with_funcs(user->set_info, user->set,
				       user->pool, mail_user_var_expand_table(user),
				       mail_user_var_expand_func_table, user);
	user->settings_expanded = TRUE;
	mail_user_expand_plugins_envs(user);

	/* autocreated users for shared mailboxes need to be fully initialized
	   if they don't exist, since they're going to be used anyway */
	if (user->error == NULL || user->nonexistent) {
		mail_set = mail_user_set_get_storage_set(user);
		user->mail_debug = mail_set->mail_debug;

		user->initialized = TRUE;
		hook_mail_user_created(user);
	}

	if (user->error != NULL) {
		*error_r = t_strdup(user->error);
		return -1;
	}
	return 0;
}

void mail_user_ref(struct mail_user *user)
{
	i_assert(user->refcount > 0);

	user->refcount++;
}

void mail_user_unref(struct mail_user **_user)
{
	struct mail_user *user = *_user;

	i_assert(user->refcount > 0);

	*_user = NULL;
	if (user->refcount > 1) {
		user->refcount--;
		return;
	}

	mail_user_autoexpunge(user);

	user->deinitializing = TRUE;

	/* call deinit() with refcount=1, otherwise we may assert-crash in
	   mail_user_ref() that is called by some deinit() handler. */
	user->v.deinit(user);
	i_assert(user->refcount == 1);
	pool_unref(&user->pool);
}

struct mail_user *mail_user_find(struct mail_user *user, const char *name)
{
	struct mail_namespace *ns;

	for (ns = user->namespaces; ns != NULL; ns = ns->next) {
		if (ns->owner != NULL && strcmp(ns->owner->username, name) == 0)
			return ns->owner;
	}
	return NULL;
}

void mail_user_set_vars(struct mail_user *user, const char *service,
			const struct ip_addr *local_ip,
			const struct ip_addr *remote_ip)
{
	i_assert(service != NULL);

	user->service = p_strdup(user->pool, service);
	if (local_ip != NULL && local_ip->family != 0) {
		user->local_ip = p_new(user->pool, struct ip_addr, 1);
		*user->local_ip = *local_ip;
	}
	if (remote_ip != NULL && remote_ip->family != 0) {
		user->remote_ip = p_new(user->pool, struct ip_addr, 1);
		*user->remote_ip = *remote_ip;
	}
}

const struct var_expand_table *
mail_user_var_expand_table(struct mail_user *user)
{
	static struct var_expand_table static_tab[] = {
		{ 'u', NULL, "user" },
		{ 'n', NULL, "username" },
		{ 'd', NULL, "domain" },
		{ 's', NULL, "service" },
		{ 'h', NULL, "home" },
		{ 'l', NULL, "lip" },
		{ 'r', NULL, "rip" },
		{ 'p', NULL, "pid" },
		{ 'i', NULL, "uid" },
		{ '\0', NULL, "gid" },
		{ '\0', NULL, "session" },
		{ '\0', NULL, "auth_user" },
		{ '\0', NULL, "auth_username" },
		{ '\0', NULL, "auth_domain" },
		/* NOTE: keep this synced with imap-hibernate's
		   imap_client_var_expand_table() */
		{ '\0', NULL, NULL }
	};
	struct var_expand_table *tab;

	/* use a cached table, unless home directory has been set afterwards */
	if (user->var_expand_table != NULL &&
	    user->var_expand_table[4].value == user->_home)
		return user->var_expand_table;

	tab = p_malloc(user->pool, sizeof(static_tab));
	memcpy(tab, static_tab, sizeof(static_tab));

	tab[0].value = user->username;
	tab[1].value = p_strdup(user->pool, t_strcut(user->username, '@'));
	tab[2].value = strchr(user->username, '@');
	if (tab[2].value != NULL) tab[2].value++;
	tab[3].value = user->service;
	tab[4].value = user->_home; /* don't look it up unless we need it */
	tab[5].value = user->local_ip == NULL ? NULL :
		p_strdup(user->pool, net_ip2addr(user->local_ip));
	tab[6].value = user->remote_ip == NULL ? NULL :
		p_strdup(user->pool, net_ip2addr(user->remote_ip));
	tab[7].value = my_pid;
	tab[8].value = p_strdup(user->pool, dec2str(user->uid));
	tab[9].value = p_strdup(user->pool, dec2str(user->gid));
	tab[10].value = user->session_id;
	if (user->auth_user == NULL) {
		tab[11].value = tab[0].value;
		tab[12].value = tab[1].value;
		tab[13].value = tab[2].value;
	} else {
		tab[11].value = user->auth_user;
		tab[12].value = p_strdup(user->pool, t_strcut(user->auth_user, '@'));
		tab[13].value = strchr(user->auth_user, '@');
	}

	user->var_expand_table = tab;
	return user->var_expand_table;
}

static const char *
mail_user_var_expand_func_userdb(const char *data, void *context)
{
	struct mail_user *user = context;
	const char *field_name = data;
	unsigned int i, field_name_len;

	if (user->userdb_fields == NULL)
		return NULL;

	field_name_len = strlen(field_name);
	for (i = 0; user->userdb_fields[i] != NULL; i++) {
		if (strncmp(user->userdb_fields[i], field_name,
			    field_name_len) == 0 &&
		    user->userdb_fields[i][field_name_len] == '=')
			return user->userdb_fields[i] + field_name_len+1;
	}
	return NULL;
}

void mail_user_set_home(struct mail_user *user, const char *home)
{
	user->_home = p_strdup(user->pool, home);
	user->home_looked_up = TRUE;
}

void mail_user_add_namespace(struct mail_user *user,
			     struct mail_namespace **namespaces)
{
	struct mail_namespace **tmp, *next, *ns = *namespaces;

	for (; ns != NULL; ns = next) {
		next = ns->next;

		tmp = &user->namespaces;
		for (; *tmp != NULL; tmp = &(*tmp)->next) {
			if (strlen(ns->prefix) < strlen((*tmp)->prefix))
				break;
		}
		ns->next = *tmp;
		*tmp = ns;
	}
	*namespaces = user->namespaces;

	T_BEGIN {
		hook_mail_namespaces_added(user->namespaces);
	} T_END;
}

void mail_user_drop_useless_namespaces(struct mail_user *user)
{
	struct mail_namespace *ns, *next;

	/* drop all autocreated unusable (typically shared) namespaces.
	   don't drop the autocreated prefix="" namespace that we explicitly
	   created for being the fallback namespace. */
	for (ns = user->namespaces; ns != NULL; ns = next) {
		next = ns->next;

		if ((ns->flags & NAMESPACE_FLAG_USABLE) == 0 &&
		    (ns->flags & NAMESPACE_FLAG_AUTOCREATED) != 0 &&
		    ns->prefix_len > 0)
			mail_namespace_destroy(ns);
	}
}

const char *mail_user_home_expand(struct mail_user *user, const char *path)
{
	(void)mail_user_try_home_expand(user, &path);
	return path;
}

static int mail_user_userdb_lookup_home(struct mail_user *user)
{
	struct auth_user_info info;
	struct auth_user_reply reply;
	pool_t userdb_pool;
	const char *username, *const *fields;
	int ret;

	i_assert(!user->home_looked_up);

	memset(&info, 0, sizeof(info));
	info.service = user->service;
	if (user->local_ip != NULL)
		info.local_ip = *user->local_ip;
	if (user->remote_ip != NULL)
		info.remote_ip = *user->remote_ip;

	userdb_pool = pool_alloconly_create("userdb lookup", 2048);
	ret = auth_master_user_lookup(mail_user_auth_master_conn,
				      user->username, &info, userdb_pool,
				      &username, &fields);
	if (ret > 0) {
		auth_user_fields_parse(fields, userdb_pool, &reply);
		user->_home = p_strdup(user->pool, reply.home);
	}
	pool_unref(&userdb_pool);
	return ret;
}

static void mail_user_get_mail_home(struct mail_user *user)
{
	const char *home = user->set->mail_home;
	string_t *str;

	if (user->settings_expanded) {
		user->_home = home[0] != '\0' ? home : NULL;
		return;
	}
	/* we're still initializing user. need to do the expansion ourself. */
	i_assert(home[0] == SETTING_STRVAR_UNEXPANDED[0]);
	home++;
	if (home[0] == '\0')
		return;

	str = t_str_new(128);
	var_expand_with_funcs(str, home,
			      mail_user_var_expand_table(user),
			      mail_user_var_expand_func_table, user);
	user->_home = p_strdup(user->pool, str_c(str));
}

int mail_user_get_home(struct mail_user *user, const char **home_r)
{
	int ret;

	if (user->home_looked_up) {
		*home_r = user->_home;
		return user->_home != NULL ? 1 : 0;
	}

	if (mail_user_auth_master_conn == NULL) {
		/* no userdb connection. we can only use mail_home setting. */
		mail_user_get_mail_home(user);
	} else if ((ret = mail_user_userdb_lookup_home(user)) < 0) {
		/* userdb lookup failed */
		return -1;
	} else if (ret == 0) {
		/* user doesn't exist */
		user->nonexistent = TRUE;
	} else if (user->_home == NULL) {
		/* no home returned by userdb lookup, fallback to
		   mail_home setting. */
		mail_user_get_mail_home(user);
	}
	user->home_looked_up = TRUE;

	*home_r = user->_home;
	return user->_home != NULL ? 1 : 0;
}

bool mail_user_is_plugin_loaded(struct mail_user *user, struct module *module)
{
	const char *const *plugins;
	bool ret;

	T_BEGIN {
		plugins = t_strsplit_spaces(user->set->mail_plugins, ", ");
		ret = str_array_find(plugins, module_get_plugin_name(module));
	} T_END;
	return ret;
}

const char *mail_user_plugin_getenv(struct mail_user *user, const char *name)
{
	return mail_user_set_plugin_getenv(user->set, name);
}

const char *mail_user_set_plugin_getenv(const struct mail_user_settings *set,
					const char *name)
{
	const char *const *envs;
	unsigned int i, count;

	if (!array_is_created(&set->plugin_envs))
		return NULL;

	envs = array_get(&set->plugin_envs, &count);
	for (i = 0; i < count; i += 2) {
		if (strcmp(envs[i], name) == 0)
			return envs[i+1];
	}
	return NULL;
}

int mail_user_try_home_expand(struct mail_user *user, const char **pathp)
{
	const char *home, *path = *pathp;

	if (*path != '~') {
		/* no need to expand home */
		return 0;
	}

	if (mail_user_get_home(user, &home) <= 0)
		return -1;

	path = home_expand_tilde(path, home);
	if (path == NULL)
		return -1;

	*pathp = path;
	return 0;
}

void mail_user_set_get_temp_prefix(string_t *dest,
				   const struct mail_user_settings *set)
{
	str_append(dest, set->mail_temp_dir);
	str_append(dest, "/dovecot.");
	str_append(dest, master_service_get_name(master_service));
	str_append_c(dest, '.');
}

const char *mail_user_get_anvil_userip_ident(struct mail_user *user)
{
	if (user->remote_ip == NULL)
		return NULL;
	return t_strconcat(net_ip2addr(user->remote_ip), "/",
			   str_tabescape(user->username), NULL);
}

static void
mail_user_try_load_class_plugin(struct mail_user *user, const char *name)
{
	struct module_dir_load_settings mod_set;
	struct module *module;
	unsigned int name_len = strlen(name);

	memset(&mod_set, 0, sizeof(mod_set));
	mod_set.abi_version = DOVECOT_ABI_VERSION;
	mod_set.binary_name = master_service_get_name(master_service);
	mod_set.setting_name = "<built-in storage lookup>";
	mod_set.require_init_funcs = TRUE;
	mod_set.debug = user->mail_debug;

	mail_storage_service_modules =
		module_dir_load_missing(mail_storage_service_modules,
					user->set->mail_plugin_dir,
					name, &mod_set);
	/* initialize the module (and only this module!) immediately so that
	   the class gets registered */
	for (module = mail_storage_service_modules; module != NULL; module = module->next) {
		if (strncmp(module->name, name, name_len) == 0 &&
		    strcmp(module->name + name_len, "_plugin") == 0) {
			if (!module->initialized) {
				module->initialized = TRUE;
				module->init(module);
			}
			break;
		}
	}
}

struct mail_storage *
mail_user_get_storage_class(struct mail_user *user, const char *name)
{
	struct mail_storage *storage;

	storage = mail_storage_find_class(name);
	if (storage == NULL || storage->v.alloc != NULL)
		return storage;

	/* it's implemented by a plugin. load it and check again. */
	mail_user_try_load_class_plugin(user, name);

	storage = mail_storage_find_class(name);
	if (storage != NULL && storage->v.alloc == NULL) {
		i_error("Storage driver '%s' exists as a stub, "
			"but its plugin couldn't be loaded", name);
		return NULL;
	}
	return storage;
}

struct mail_user *mail_user_dup(struct mail_user *user)
{
	struct mail_user *user2;

	user2 = mail_user_alloc(user->username, user->set_info,
				user->unexpanded_set);
	user2->_service_user = user->_service_user;
	if (user->_home != NULL)
		mail_user_set_home(user2, user->_home);
	mail_user_set_vars(user2, user->service,
			   user->local_ip, user->remote_ip);
	user2->uid = user->uid;
	user2->gid = user->gid;
	user2->anonymous = user->anonymous;
	user2->admin = user->admin;
	user2->auth_token = p_strdup(user2->pool, user->auth_token);
	user2->auth_user = p_strdup(user2->pool, user->auth_user);
	user2->session_id = p_strdup(user2->pool, user->session_id);
	return user2;
}

void mail_user_init_fs_settings(struct mail_user *user,
				struct fs_settings *fs_set,
				struct ssl_iostream_settings *ssl_set)
{
	const struct mail_storage_settings *mail_set =
		mail_user_set_get_storage_set(user);

	fs_set->username = user->username;
	fs_set->session_id = user->session_id;
	fs_set->base_dir = user->set->base_dir;
	fs_set->temp_dir = user->set->mail_temp_dir;
	fs_set->debug = user->mail_debug;
	fs_set->enable_timing = user->stats_enabled;

	fs_set->ssl_client_set = ssl_set;
	ssl_set->ca_dir = mail_set->ssl_client_ca_dir;
	ssl_set->ca_file = mail_set->ssl_client_ca_file;
}

void mail_user_stats_fill(struct mail_user *user, struct stats *stats)
{
	user->v.stats_fill(user, stats);
}

static const struct var_expand_func_table mail_user_var_expand_func_table_arr[] = {
	{ "userdb", mail_user_var_expand_func_userdb },
	{ NULL, NULL }
};
const struct var_expand_func_table *mail_user_var_expand_func_table =
	mail_user_var_expand_func_table_arr;

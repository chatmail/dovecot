#ifndef MAIL_USER_H
#define MAIL_USER_H

struct mail_user;

struct mail_user_vfuncs {
	void (*deinit)(struct mail_user *user);
};

struct mail_user {
	pool_t pool;
	struct mail_user_vfuncs v;
	int refcount;

	const char *username;
	/* don't access the home directly. It may be set lazily. */
	const char *_home;

	struct mail_namespace *namespaces;

	/* Module-specific contexts. See mail_storage_module_id. */
	ARRAY_DEFINE(module_contexts, union mail_user_module_context *);

	/* Either home is set or there is no home for the user. */
	unsigned int home_looked_up:1;
	/* User is an administrator. Allow operations not normally allowed
	   for other people. */
	unsigned int admin:1;
};

struct mail_user_module_register {
	unsigned int id;
};

union mail_user_module_context {
	struct mail_user_vfuncs super;
	struct mail_user_module_register *reg;
};
extern struct mail_user_module_register mail_user_module_register;

/* Called after user has been created */
extern void (*hook_mail_user_created)(struct mail_user *user);

void mail_users_init(const char *auth_socket_path, bool debug);
void mail_users_deinit(void);

struct mail_user *mail_user_init(const char *username);
void mail_user_ref(struct mail_user *user);
void mail_user_unref(struct mail_user **user);

/* Find another user from the given user's namespaces. */
struct mail_user *mail_user_find(struct mail_user *user, const char *name);

/* Specify the user's home directory. This should be called also when it's
   known that the user doesn't have a home directory to avoid the internal
   lookup. */
void mail_user_set_home(struct mail_user *user, const char *home);
/* Get the home directory for the user. Returns 1 if home directory looked up
   successfully, 0 if there is no home directory (either user doesn't exist or
   has no home directory) or -1 if lookup failed. */
int mail_user_get_home(struct mail_user *user, const char **home_r);
/* Returns path + file prefix for creating a temporary file. Uses home
   directory if possible, fallbacks to mail directory. */
const char *mail_user_get_temp_prefix(struct mail_user *user);

/* Add more namespaces to user's namespaces. The ->next pointers may be
   changed, so the namespaces pointer will be updated to user->namespaces. */
void mail_user_add_namespace(struct mail_user *user,
			     struct mail_namespace **namespaces);
/* Drop autocreated shared namespaces that don't have any "usable" mailboxes. */
void mail_user_drop_useless_namespaces(struct mail_user *user);

/* Replace ~/ at the beginning of the path with the user's home directory. */
const char *mail_user_home_expand(struct mail_user *user, const char *path);
/* Returns 0 if ok, -1 if home directory isn't set. */
int mail_user_try_home_expand(struct mail_user *user, const char **path);

#endif
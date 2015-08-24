/* Copyright (c) 2015 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "module-context.h"
#include "mail-user.h"
#include "fts-language.h"
#include "fts-filter.h"
#include "fts-tokenizer.h"
#include "fts-user.h"

#define FTS_USER_CONTEXT(obj) \
	MODULE_CONTEXT(obj, fts_user_module)

#define FTS_DEFAULT_TOKENIZERS "generic email-address"
#define FTS_DEFAULT_FILTERS "normalizer-icu snowball"

struct fts_user {
	union mail_user_module_context module_ctx;

	struct fts_language_list *lang_list;
	struct fts_tokenizer *index_tokenizer, *search_tokenizer;
	struct fts_user_language *data_lang;
	ARRAY_TYPE(fts_user_language) languages;
};

static MODULE_CONTEXT_DEFINE_INIT(fts_user_module,
				  &mail_user_module_register);

static const char *const *str_keyvalues_to_array(const char *str)
{
	const char *key, *value, *const *keyvalues;
	ARRAY_TYPE(const_string) arr;
	unsigned int i;

	if (str == NULL)
		return NULL;

	t_array_init(&arr, 8);
	keyvalues = t_strsplit_spaces(str, " ");
	for (i = 0; keyvalues[i] != NULL; i++) {
		value = strchr(keyvalues[i], '=');
		if (value != NULL)
			key = t_strdup_until(keyvalues[i], value++);
		else {
			key = keyvalues[i];
			value = "";
		}
		array_append(&arr, &key, 1);
		array_append(&arr, &value, 1);
	}
	array_append_zero(&arr);
	return array_idx(&arr, 0);
}

static int
fts_user_init_languages(struct mail_user *user, struct fts_user *fuser,
			const char **error_r)
{
	const char *languages, *unknown;
	const char *lang_config[3] = {NULL, NULL, NULL};

	languages = mail_user_plugin_getenv(user, "fts_languages");
	if (languages == NULL) {
		*error_r = "fts_languages setting is missing";
		return -1;
	}

	lang_config[1] = mail_user_plugin_getenv(user, "fts_language_config");
	if (lang_config[1] != NULL)
		lang_config[0] = "fts_language_config";
	if (fts_language_list_init(lang_config, &fuser->lang_list, error_r) < 0)
		return -1;

	if (!fts_language_list_add_names(fuser->lang_list, languages, &unknown)) {
		*error_r = t_strdup_printf(
			"fts_languages: Unknown language '%s'", unknown);
		return -1;
	}
	if (array_count(fts_language_list_get_all(fuser->lang_list)) == 0) {
		*error_r = "fts_languages setting is empty";
		return -1;
	}
	return 0;
}

static int
fts_user_create_filters(struct mail_user *user, const struct fts_language *lang,
			struct fts_filter **filter_r, const char **error_r)
{
	const struct fts_filter *filter_class;
	struct fts_filter *filter = NULL, *parent = NULL;
	const char *filters_key, *const *filters, *filter_set_name;
	const char *str, *error, *set_key;
	unsigned int i;
	int ret = 0;

	/* try to get the language-specific filters first */
	filters_key = t_strconcat("fts_filters_", lang->name, NULL);
	str = mail_user_plugin_getenv(user, filters_key);
	if (str == NULL) {
		/* fallback to global filters */
		filters_key = "fts_filters";
		str = mail_user_plugin_getenv(user, filters_key);
		if (str == NULL) {
			str = FTS_DEFAULT_FILTERS;
			filters_key = "fts_filters(built-in default)";
		}
	}

	filters = t_strsplit_spaces(str, " ");
	for (i = 0; filters[i] != NULL; i++) {
		filter_class = fts_filter_find(filters[i]);
		if (filter_class == NULL) {
			*error_r = t_strdup_printf("%s: Unknown filter '%s'",
						   filters_key, filters[i]);
			ret = -1;
			break;
		}

		/* try the language-specific setting first */
		filter_set_name = t_str_replace(filters[i], '-', '_');
		set_key = t_strdup_printf("fts_filter_%s_%s",
					  lang->name, filter_set_name);
		str = mail_user_plugin_getenv(user, set_key);
		if (str == NULL) {
			set_key = t_strdup_printf("fts_filter_%s", filter_set_name);
			str = mail_user_plugin_getenv(user, set_key);
		}

		if (fts_filter_create(filter_class, parent, lang,
				      str_keyvalues_to_array(str),
				      &filter, &error) < 0) {
			*error_r = t_strdup_printf("%s: %s", set_key, error);
			ret = -1;
			break;
		}
		if (parent != NULL)
			fts_filter_unref(&parent);
		parent = filter;
	}
	if (ret < 0) {
		if (parent != NULL)
			fts_filter_unref(&parent);
		return -1;
	}
	*filter_r = filter;
	return 0;
}

static int
fts_user_create_tokenizer(struct mail_user *user,
			  struct fts_tokenizer **tokenizer_r, bool search,
			  const char **error_r)
{
	const struct fts_tokenizer *tokenizer_class;
	struct fts_tokenizer *tokenizer = NULL, *parent = NULL;
	const char *tokenizers_key, *const *tokenizers, *tokenizer_set_name;
	const char *str, *error, *set_key;
	unsigned int i;
	int ret = 0;

	tokenizers_key = "fts_tokenizers";
	str = mail_user_plugin_getenv(user, tokenizers_key);
	if (str == NULL)
		str = FTS_DEFAULT_TOKENIZERS;

	tokenizers = t_strsplit_spaces(str, " ");

	for (i = 0; tokenizers[i] != NULL; i++) {
		tokenizer_class = fts_tokenizer_find(tokenizers[i]);
		if (tokenizer_class == NULL) {
			*error_r = t_strdup_printf("%s: Unknown tokenizer '%s'",
						   tokenizers_key, tokenizers[i]);
			ret = -1;
			break;
		}

		tokenizer_set_name = t_str_replace(tokenizers[i], '-', '_');
		set_key = t_strdup_printf("fts_tokenizer_%s", tokenizer_set_name);
		str = mail_user_plugin_getenv(user, set_key);

		/* tell the tokenizers that we're tokenizing a search string
		   (instead of tokenizing indexed data) */
		if (search)
			str = t_strconcat("search=yes ", str, NULL);

		if (fts_tokenizer_create(tokenizer_class, parent,
					 str_keyvalues_to_array(str),
					 &tokenizer, &error) < 0) {
			*error_r = t_strdup_printf("%s: %s", set_key, error);
			ret = -1;
			break;
		}
		if (parent != NULL)
			fts_tokenizer_unref(&parent);
		parent = tokenizer;
	}
	if (ret < 0) {
		if (parent != NULL)
			fts_tokenizer_unref(&parent);
		return -1;
	}
	*tokenizer_r = tokenizer;
	return 0;
}

static int fts_user_init_tokenizers(struct mail_user *user,
				    struct fts_user *fuser,
				    const char **error_r)
{
	if (fts_user_create_tokenizer(user, &fuser->index_tokenizer, FALSE,
	                              error_r) < 0)
		return -1;

	if (fts_user_create_tokenizer(user, &fuser->search_tokenizer, TRUE,
	                              error_r) < 0)
		return -1;

	return 0;
}

struct fts_user_language *
fts_user_language_find(struct mail_user *user,
		       const struct fts_language *lang)
{
	struct fts_user_language *const *user_langp;
	struct fts_user *fuser = FTS_USER_CONTEXT(user);
		
	array_foreach(&fuser->languages, user_langp) {
		if (strcmp((*user_langp)->lang->name, lang->name) == 0)
			return *user_langp;
	}
	return NULL;
}

struct fts_tokenizer *fts_user_get_index_tokenizer(struct mail_user *user)
{
	struct fts_user *fuser = FTS_USER_CONTEXT(user);

	return fuser->index_tokenizer;
}

struct fts_tokenizer *fts_user_get_search_tokenizer(struct mail_user *user)
{
	struct fts_user *fuser = FTS_USER_CONTEXT(user);

	return fuser->search_tokenizer;
}

static int fts_user_language_create(struct mail_user *user,
                                    struct fts_user *fuser,
				    const struct fts_language *lang,
				    const char **error_r)
{
	struct fts_filter *filter;
	struct fts_user_language *user_lang;
	if (fts_user_create_filters(user, lang, &filter, error_r) < 0)
		return -1;

	user_lang = p_new(user->pool, struct fts_user_language, 1);
	user_lang->lang = lang;
	user_lang->filter = filter;
	array_append(&fuser->languages, &user_lang, 1);

	return 0;
}

static int fts_user_languages_fill_all(struct mail_user *user,
                                       struct fts_user *fuser,
                                       const char **error_r)
{
	const struct fts_language *const *langp;

	array_foreach(fts_language_list_get_all(fuser->lang_list), langp) {
		if (fts_user_language_create(user, fuser, *langp, error_r) < 0)
			return -1;
	}
	return 0;
}

struct fts_language_list *fts_user_get_language_list(struct mail_user *user)
{
	struct fts_user *fuser = FTS_USER_CONTEXT(user);

	return fuser->lang_list;
}

const ARRAY_TYPE(fts_user_language) *
fts_user_get_all_languages(struct mail_user *user)
{
	struct fts_user *fuser = FTS_USER_CONTEXT(user);

	return &fuser->languages;
}

struct fts_user_language *fts_user_get_data_lang(struct mail_user *user)
{
	struct fts_user *fuser = FTS_USER_CONTEXT(user);
	struct fts_user_language *lang;
	const char *error;

	if (fuser->data_lang != NULL)
		return fuser->data_lang;

	lang = p_new(user->pool, struct fts_user_language, 1);
	lang->lang = &fts_language_data;

	if (fts_filter_create(fts_filter_lowercase, NULL, lang->lang, NULL,
			      &lang->filter, &error) < 0)
		i_unreached();
	i_assert(lang->filter != NULL);
	fuser->data_lang = lang;
	return fuser->data_lang;
}

static void fts_user_free(struct fts_user *fuser)
{
	struct fts_user_language *const *user_langp;

	if (fuser->lang_list != NULL)
		fts_language_list_deinit(&fuser->lang_list);

	array_foreach(&fuser->languages, user_langp) {
		if ((*user_langp)->filter != NULL)
			fts_filter_unref(&(*user_langp)->filter);
	}
	if (fuser->data_lang != NULL && fuser->data_lang->filter != NULL)
		fts_filter_unref(&fuser->data_lang->filter);

	if (fuser->index_tokenizer != NULL)
		fts_tokenizer_unref(&fuser->index_tokenizer);
	if (fuser->search_tokenizer != NULL)
		fts_tokenizer_unref(&fuser->search_tokenizer);
}

int fts_mail_user_init(struct mail_user *user, const char **error_r)
{
	struct fts_user *fuser;

	fuser = p_new(user->pool, struct fts_user, 1);
	p_array_init(&fuser->languages, user->pool, 4);

	if (fts_user_init_languages(user, fuser, error_r) < 0) {
		fts_user_free(fuser);
		return -1;
	}
	if (fts_user_languages_fill_all(user, fuser, error_r) < 0 ||
	    fts_user_init_tokenizers(user, fuser, error_r) < 0) {
		fts_user_free(fuser);
		return -1;
	}

	MODULE_CONTEXT_SET(user, fts_user_module, fuser);
	return 0;
}

void fts_mail_user_deinit(struct mail_user *user)
{
	struct fts_user *fuser = FTS_USER_CONTEXT(user);

	if (fuser != NULL)
		fts_user_free(fuser);
}

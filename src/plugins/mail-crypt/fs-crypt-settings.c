/* Copyright (c) 2010-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "buffer.h"
#include "settings-parser.h"
#include "service-settings.h"
#include "mail-storage-settings.h"
#include "fs-crypt-settings.h"

static const struct setting_define fs_crypt_setting_defines[] = {
	{ .type = SET_STRLIST, .key = "plugin",
	  .offset = offsetof(struct fs_crypt_settings, plugin_envs) },

	SETTING_DEFINE_LIST_END
};

const struct fs_crypt_settings fs_crypt_default_settings = {
	.plugin_envs = ARRAY_INIT
};

static const struct setting_parser_info *fs_crypt_setting_dependencies[] = {
	NULL
};

const struct setting_parser_info fs_crypt_setting_parser_info = {
	.module_name = "fs-crypt",
	.defines = fs_crypt_setting_defines,
	.defaults = &fs_crypt_default_settings,

	.type_offset = SIZE_MAX,
	.struct_size = sizeof(struct fs_crypt_settings),

	.parent_offset = SIZE_MAX,
	.dependencies = fs_crypt_setting_dependencies
};

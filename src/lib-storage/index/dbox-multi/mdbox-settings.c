/* Copyright (c) 2006-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "settings-parser.h"
#include "mail-storage-settings.h"
#include "mdbox-settings.h"

#include <stddef.h>

#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type(#name, name, struct mdbox_settings)

static const struct setting_define mdbox_setting_defines[] = {
	DEF(BOOL, mdbox_preallocate_space),
	DEF(SIZE, mdbox_rotate_size),
	DEF(TIME, mdbox_rotate_interval),

	SETTING_DEFINE_LIST_END
};

static const struct mdbox_settings mdbox_default_settings = {
	.mdbox_preallocate_space = FALSE,
	.mdbox_rotate_size = 10*1024*1024,
	.mdbox_rotate_interval = 0
};

static const struct setting_parser_info mdbox_setting_parser_info = {
	.module_name = "mdbox",
	.defines = mdbox_setting_defines,
	.defaults = &mdbox_default_settings,

	.type_offset = SIZE_MAX,
	.struct_size = sizeof(struct mdbox_settings),

	.parent_offset = SIZE_MAX,
	.parent = &mail_user_setting_parser_info
};

const struct setting_parser_info *mdbox_get_setting_parser_info(void)
{
	return &mdbox_setting_parser_info;
}

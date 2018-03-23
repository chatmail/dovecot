#ifndef SUBMISSION_LOGIN_SETTINGS_H
#define SUBMISSION_LOGIN_SETTINGS_H

struct submission_login_settings {
	const char *hostname;

	/* submission: */
	size_t submission_max_mail_size;
};

extern const struct setting_parser_info *submission_login_setting_roots[];

#endif

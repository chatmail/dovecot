#ifndef MAILBOX_ATTRIBUTE_H
#define MAILBOX_ATTRIBUTE_H

struct mailbox;
struct mailbox_transaction_context;

/* RFC 5464 specifies that this is vendor/<vendor-token>/. The registered
   vendor-tokens always begin with "vendor." so there's some redundancy.. */
#define MAILBOX_ATTRIBUTE_PREFIX_DOVECOT "vendor/vendor.dovecot/"
/* Prefix used for attributes reserved for Dovecot's internal use. Normal
   users cannot access these in any way. */
#define MAILBOX_ATTRIBUTE_PREFIX_DOVECOT_PVT \
	MAILBOX_ATTRIBUTE_PREFIX_DOVECOT"pvt/"
/* Server attributes are currently stored in INBOX under this private prefix.
   They're under the pvt/ prefix so they won't be listed as regular INBOX
   attributes, but unlike other pvt/ attributes it's actually possible to
   access these attributes as regular users.

   If INBOX is deleted, attributes under this prefix are preserved. */
#define MAILBOX_ATTRIBUTE_PREFIX_DOVECOT_PVT_SERVER \
	MAILBOX_ATTRIBUTE_PREFIX_DOVECOT_PVT"server/"

/* User can get/set all non-pvt/ attributes and also pvt/server/ attributes. */
#define MAILBOX_ATTRIBUTE_KEY_IS_USER_ACCESSIBLE(key) \
	(strncmp(key, MAILBOX_ATTRIBUTE_PREFIX_DOVECOT_PVT, \
		 strlen(MAILBOX_ATTRIBUTE_PREFIX_DOVECOT_PVT)) != 0 || \
	 strncmp(key, MAILBOX_ATTRIBUTE_PREFIX_DOVECOT_PVT_SERVER, \
		 strlen(MAILBOX_ATTRIBUTE_PREFIX_DOVECOT_PVT_SERVER)) == 0)

enum mail_attribute_type {
	MAIL_ATTRIBUTE_TYPE_PRIVATE,
	MAIL_ATTRIBUTE_TYPE_SHARED
};
enum mail_attribute_value_flags {
	MAIL_ATTRIBUTE_VALUE_FLAG_READONLY	= 0x01,
	MAIL_ATTRIBUTE_VALUE_FLAG_INT_STREAMS	= 0x02
};

struct mail_attribute_value {
	/* mailbox_attribute_set() can set either value or value_stream.
	   mailbox_attribute_get() returns only values, but
	   mailbox_attribute_get_stream() may return either value or
	   value_stream. The caller must unreference the returned streams. */
	const char *value;
	struct istream *value_stream;

	/* Last time the attribute was changed (0 = unknown). This may be
	   returned even for values that don't exist anymore. */
	time_t last_change;

	enum mail_attribute_value_flags flags;
};

/*
 * Attribute API
 */

/* Set mailbox attribute key to value. The key should be compatible with
   IMAP METADATA, so for Dovecot-specific keys use
   MAILBOX_ATTRIBUTE_PREFIX_DOVECOT. */
int mailbox_attribute_set(struct mailbox_transaction_context *t,
			  enum mail_attribute_type type, const char *key,
			  const struct mail_attribute_value *value);
/* Delete mailbox attribute key. This is just a wrapper to
   mailbox_attribute_set() with value->value=NULL. */
int mailbox_attribute_unset(struct mailbox_transaction_context *t,
			    enum mail_attribute_type type, const char *key);
/* Returns value for mailbox attribute key. Returns 1 if value was returned,
   0 if value wasn't found (set to NULL), -1 if error */
int mailbox_attribute_get(struct mailbox_transaction_context *t,
			  enum mail_attribute_type type, const char *key,
			  struct mail_attribute_value *value_r);
/* Same as mailbox_attribute_get(), but the returned value may be either an
   input stream or a string. */
int mailbox_attribute_get_stream(struct mailbox_transaction_context *t,
				 enum mail_attribute_type type, const char *key,
				 struct mail_attribute_value *value_r);

/* Iterate through mailbox attributes of the given type. The prefix can be used
   to restrict what attributes are returned. */
struct mailbox_attribute_iter *
mailbox_attribute_iter_init(struct mailbox *box, enum mail_attribute_type type,
			    const char *prefix);
/* Returns the attribute key or NULL if there are no more attributes. */
const char *mailbox_attribute_iter_next(struct mailbox_attribute_iter *iter);
int mailbox_attribute_iter_deinit(struct mailbox_attribute_iter **iter);

#endif

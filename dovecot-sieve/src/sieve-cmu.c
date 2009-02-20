/* Copyright (C) 2005-2006 Timo Sirainen */

#include "lib.h"
#include "ioloop.h"
#include "array.h"
#include "hostpid.h"
#include "str.h"
#include "str-sanitize.h"
#include "istream.h"
#include "write-full.h"
#include "rfc822-parser.h"
#include "message-date.h"
#include "message-parser.h"
#include "message-decoder.h"
#include "mail-storage.h"
#include "deliver.h"
#include "duplicate.h"
#include "mail-send.h"
#include "smtp-client.h"
#include "libsieve/sieve_interface.h"
#include "cmusieve-plugin.h"

#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/wait.h>

/* data per script */
typedef struct script_data {
	const char *username;
	struct mail_namespace *namespaces;
	struct mail_storage **storage_r;

	sieve_interp_t *interp;
	string_t *errors;
} script_data_t;

struct sieve_body_part {
	const char *content_type;

	const char *raw_body;
	const char *decoded_body;
	size_t raw_body_size;
	size_t decoded_body_size;
	bool have_body; /* there's the empty end-of-headers line */
};

typedef struct {
	struct mail *mail;
	const char *mailbox;
	const char *id;
	const char *return_path;
	const char *authuser;
	const char *destaddr;

	pool_t body_parts_pool;
	ARRAY_DEFINE(body_parts, struct sieve_body_part);
	ARRAY_DEFINE(return_body_parts, sieve_bodypart_t);

	const char *temp[10];
	buffer_t *tmp_buffer;
} sieve_msgdata_t;

static int
dovecot_sieve_compile(script_data_t *sdata, const char *script_path,
		      const char *compiled_path);

static const char *unfold_header(const char *str)
{
	char *new_str;
	unsigned int i, j;

	for (i = 0; str[i] != '\0'; i++) {
		if (str[i] == '\n')
			break;
	}
	if (str[i] == '\0')
		return str;

	/* @UNSAFE */
	new_str = t_malloc(i + strlen(str+i) + 1);
	memcpy(new_str, str, i);
	for (j = i; str[i] != '\0'; i++) {
		if (str[i] == '\n') {
			new_str[j++] = ' ';
			i++;
			i_assert(str[i] == ' ' || str[i] == '\t');
		} else {
			new_str[j++] = str[i];
		}
	}
	new_str[j] = '\0';
	return new_str;
}

static const char *const *
unfold_multiline_headers(const char *const *headers)
{
	const char **new_headers;
	unsigned int i;

	/* see if there are any multiline headers */
	for (i = 0; headers[i] != NULL; i++) {
		if (strchr(headers[i], '\n') != NULL)
			break;
	}
	if (headers[i] == NULL) {
		/* no multilines */
		return headers;
	}

	/* @UNSAFE */
	for (; headers[i] != NULL; i++) ;
	new_headers = t_new(const char *, i + 1);
	for (i = 0; headers[i] != NULL; i++)
		new_headers[i] = unfold_header(headers[i]);
	return new_headers;
}

/* gets the header "head" from msg. */
static int getheader(void *v, const char *phead, const char ***body)
{
    sieve_msgdata_t *m = v;
    const char *const *headers;

    if (phead==NULL) return SIEVE_FAIL;
    if (mail_get_headers_utf8(m->mail, phead, &headers) < 0)
	    return SIEVE_FAIL;
    headers = unfold_multiline_headers(headers);
    *body = (const char **)headers;

    if (**body) {
	return SIEVE_OK;
    } else {
	return SIEVE_FAIL;
    }
}

static int getsize(void *mc, int *size)
{
    sieve_msgdata_t *md = mc;
    uoff_t psize;

    if (mail_get_physical_size(md->mail, &psize) < 0)
	    return SIEVE_FAIL;

    *size = psize;
    return SIEVE_OK;
}

/* we use the temp field in message_data to avoid having to malloc memory
   to return, and we also can't expose our the receipients to the message */
static int getenvelope(void *mc, const char *field, const char ***contents)
{
    sieve_msgdata_t *m = (sieve_msgdata_t *) mc;

    if (!strcasecmp(field, "from")) {
	if (m->return_path == NULL) {
	    /* invalid or missing return path */
	    *contents = NULL;
	    return SIEVE_FAIL;
	}
	*contents = m->temp;
	m->temp[0] = m->return_path;
	m->temp[1] = NULL;
	return SIEVE_OK;
    } else if (!strcasecmp(field, "to")) {
	*contents = m->temp;
	m->temp[0] = m->destaddr;
	m->temp[1] = NULL;
	return SIEVE_OK;
    } else if (!strcasecmp(field, "auth") && m->authuser) {
	*contents = m->temp;
	m->temp[0] = m->authuser;
	m->temp[1] = NULL;
	return SIEVE_OK;
    } else {
	*contents = NULL;
	return SIEVE_FAIL;
    }
}

static bool
is_wanted_content_type(const char **wanted_types, const char *content_type)
{
	const char *subtype = strchr(content_type, '/');
	size_t type_len;

	type_len = subtype == NULL ? strlen(content_type) :
		(size_t)(subtype - content_type);

	for (; *wanted_types != NULL; wanted_types++) {
		const char *wanted_subtype = strchr(*wanted_types, '/');

		if (**wanted_types == '\0') {
			/* empty string matches everything */
			return TRUE;
		}
		if (wanted_subtype == NULL) {
			/* match only main type */
			if (strlen(*wanted_types) == type_len &&
			    strncasecmp(*wanted_types, content_type,
					type_len) == 0)
				return TRUE;
		} else {
			/* match whole type/subtype */
			if (strcasecmp(*wanted_types, content_type) == 0)
				return TRUE;
		}
	}
	return FALSE;
}

static bool get_return_body_parts(sieve_msgdata_t *m, const char **wanted_types,
				  bool decode_to_plain)
{
	const struct sieve_body_part *body_parts;
	unsigned int i, count;
	sieve_bodypart_t *sieve_part;

	body_parts = array_get(&m->body_parts, &count);
	if (count == 0)
		return FALSE;

	array_clear(&m->return_body_parts);
	for (i = 0; i < count; i++) {
		if (!body_parts[i].have_body) {
			/* doesn't match anything */
			continue;
		}

		if (!is_wanted_content_type(wanted_types,
					    body_parts[i].content_type))
			continue;

		sieve_part = array_append_space(&m->return_body_parts);
		if (decode_to_plain) {
			if (body_parts[i].decoded_body == NULL)
				return FALSE;
			sieve_part->content = body_parts[i].decoded_body;
			sieve_part->size = body_parts[i].decoded_body_size;
		} else {
			if (body_parts[i].raw_body == NULL)
				return FALSE;
			sieve_part->content = body_parts[i].raw_body;
			sieve_part->size = body_parts[i].raw_body_size;
		}
	}
	return TRUE;
}

static void part_save(sieve_msgdata_t *m, struct message_part *part,
		      struct sieve_body_part *body_part, bool decoded)
{
	buffer_t *buf = m->tmp_buffer;

	buffer_append_c(buf, '\0');
	if (!decoded) {
		body_part->raw_body = p_strdup(m->body_parts_pool, buf->data);
		body_part->raw_body_size = buf->used - 1;
		i_assert(buf->used - 1 == part->body_size.physical_size);
	} else {
		body_part->decoded_body =
			p_strdup(m->body_parts_pool, buf->data);
		body_part->decoded_body_size = buf->used - 1;
	}
	buffer_set_used_size(buf, 0);
}

static const char *parse_content_type(const struct message_header_line *hdr)
{
	struct rfc822_parser_context parser;
	string_t *content_type;

	rfc822_parser_init(&parser, hdr->full_value, hdr->full_value_len, NULL);
	(void)rfc822_skip_lwsp(&parser);

	content_type = t_str_new(64);
	if (rfc822_parse_content_type(&parser, content_type) < 0)
		return "";
	return str_c(content_type);
}

static int
parts_add_missing(sieve_msgdata_t *m, const char **content_types,
		  bool decode_to_plain)
{
	struct sieve_body_part *body_part = NULL;
	struct message_parser_ctx *parser;
	struct message_decoder_context *decoder;
	struct message_block block, decoded;
	const struct message_part *const_parts;
	struct message_part *parts, *prev_part = NULL;
	struct istream *input;
	unsigned int idx = 0;
	bool save_body = FALSE, have_all;
	int ret;

	if (get_return_body_parts(m, content_types, decode_to_plain))
		return 0;

	if (mail_get_stream(m->mail, NULL, NULL, &input) < 0)
		return -1;
	if (mail_get_parts(m->mail, &const_parts) < 0)
		return -1;
	parts = (struct message_part *)const_parts;

	buffer_set_used_size(m->tmp_buffer, 0);
	decoder = decode_to_plain ? message_decoder_init(FALSE) : NULL;
	parser = message_parser_init_from_parts(parts, input, 0, 0);
	while ((ret = message_parser_parse_next_block(parser, &block)) > 0) {
		if (block.part != prev_part) {
			if (body_part != NULL && save_body) {
				part_save(m, prev_part, body_part,
					  decoder != NULL);
			}
			prev_part = block.part;
			body_part = array_idx_modifiable(&m->body_parts, idx);
			idx++;
			body_part->content_type = "text/plain";
		}
		if (block.hdr != NULL || block.size == 0) {
			/* reading headers */
			if (decoder != NULL) {
				(void)message_decoder_decode_next_block(decoder,
							&block, &decoded);
			}

			if (block.hdr == NULL) {
				/* save bodies only if we have a wanted
				   content-type */
				save_body = is_wanted_content_type(
						content_types,
						body_part->content_type);
				continue;
			}
			if (block.hdr->eoh)
				body_part->have_body = TRUE;
			/* We're interested of only Content-Type: header */
			if (strcasecmp(block.hdr->name, "Content-Type") != 0)
				continue;

			if (block.hdr->continues) {
				block.hdr->use_full_value = TRUE;
				continue;
			}
			t_push();
			body_part->content_type =
				p_strdup(m->body_parts_pool,
					 parse_content_type(block.hdr));
			t_pop();
			continue;
		}

		/* reading body */
		if (save_body) {
			if (decoder != NULL) {
				(void)message_decoder_decode_next_block(decoder,
							&block, &decoded);
				buffer_append(m->tmp_buffer,
					      decoded.data, decoded.size);
			} else {
				buffer_append(m->tmp_buffer,
					      block.data, block.size);
			}
		}
	}

	if (body_part != NULL && save_body)
		part_save(m, prev_part, body_part, decoder != NULL);

	have_all = get_return_body_parts(m, content_types, decode_to_plain);
	i_assert(have_all);

	if (message_parser_deinit(&parser, &parts) < 0)
		i_unreached();
	if (decoder != NULL)
		message_decoder_deinit(&decoder);
	return input->stream_errno == 0 ? 0 : -1;
}

static int getbody(void *mc, const char **content_types,
		   int decode_to_plain, sieve_bodypart_t **parts_r)
{
    sieve_msgdata_t *m = (sieve_msgdata_t *) mc;
    int r = SIEVE_OK;

    if (!array_is_created(&m->body_parts)) {
	    m->body_parts_pool =
		    pool_alloconly_create("sieve body parts", 1024*256);

	    i_array_init(&m->body_parts, 8);
	    i_array_init(&m->return_body_parts, array_count(&m->body_parts));
	    m->tmp_buffer = buffer_create_dynamic(default_pool, 1024*64);
    }

    t_push();
    if (parts_add_missing(m, content_types, decode_to_plain != 0) < 0)
	    r = SIEVE_FAIL;
    t_pop();

    (void)array_append_space(&m->return_body_parts); /* NULL-terminate */
    *parts_r = array_idx_modifiable(&m->return_body_parts, 0);

    return r;
}

static int getinclude(void *sc, const char *script, int isglobal,
		      char *fname, size_t size)
{
	script_data_t *sdata = (script_data_t *) sc;
	const char *script_path, *compiled_path, *home, *script_dir;
	int ret;

	if (strchr(script, '/') != NULL) {
		i_info("include: '/' not allowed in script names (%s)",
		       str_sanitize(script, 80));
		return SIEVE_FAIL;
	}

	if (isglobal) {
		script_dir = getenv("SIEVE_GLOBAL_DIR");
		if (script_dir == NULL) {
			i_info("include: sieve_global_dir not set "
			       "(wanted script %s)", str_sanitize(script, 80));
			return SIEVE_FAIL;
		}
		script_path = t_strdup_printf("%s/%s", script_dir, script);
	} else {
		home = getenv("SIEVE_DIR");
		if (home == NULL)
			home = getenv("HOME");
		if (home == NULL) {
			i_info("include: sieve_dir and home not set "
			       "(wanted script %s)", str_sanitize(script, 80));
			return SIEVE_FAIL;
		}
		script_path = t_strdup_printf("%s/%s", home, script);
	}

	compiled_path = t_strconcat(script_path, "c", NULL);
	ret = dovecot_sieve_compile(sdata, script_path, compiled_path);
	if (ret < 0) {
		i_info("include: Error compiling script '%s'",
		       str_sanitize(script, 80));
		return SIEVE_FAIL;
	}
	if (ret == 0) {
		i_info("include: Script not found: '%s'",
		       str_sanitize(script, 80));
		return SIEVE_FAIL;
	}

	if (i_strocpy(fname, compiled_path, size) < 0) {
		i_info("include: Script path too long: '%s'",
		       str_sanitize(script, 80));
		return SIEVE_FAIL;
	}
	return SIEVE_OK;
}

static int sieve_redirect(void *ac, 
			  void *ic ATTR_UNUSED, 
			  void *sc, void *mc, const char **errmsg)
{
    sieve_redirect_context_t *rc = (sieve_redirect_context_t *) ac;
    script_data_t *sd = (script_data_t *) sc;
    sieve_msgdata_t *m = mc;
    const char *dupeid;
    int res;

    /* if we have a msgid, we can track our redirects */
    dupeid = m->id == NULL ? NULL : t_strdup_printf("%s-%s", m->id, rc->addr);
    if (dupeid != NULL) {
	/* ok, let's see if we've redirected this message before */
	if (duplicate_check(dupeid, strlen(dupeid), sd->username)) {
	    /*duplicate_log(m->id, sd->username, "redirect");*/
	    i_info("msgid=%s: discarded duplicate forward to <%s>",
		   str_sanitize(m->id, 80), str_sanitize(rc->addr, 80));
            return SIEVE_OK;
	}
    }

    if ((res = mail_send_forward(m->mail, rc->addr)) == 0) {
	/* mark this message as redirected */
	i_info("msgid=%s: forwarded to <%s>",
	       m->id == NULL ? "" : str_sanitize(m->id, 80),
	       str_sanitize(rc->addr, 80));
        if (dupeid != NULL) {
            duplicate_mark(dupeid, strlen(dupeid), sd->username,
                           ioloop_time + DUPLICATE_DEFAULT_KEEP);
        }
	return SIEVE_OK;
    } else {
	*errmsg = "Error sending mail";
	return SIEVE_FAIL;
    }
}

static int sieve_discard(void *ac ATTR_UNUSED, 
			 void *ic ATTR_UNUSED, 
			 void *sc ATTR_UNUSED, void *mc,
			 const char **errmsg ATTR_UNUSED)
{
    sieve_msgdata_t *md = mc;

    /* ok, we won't file it, but log it */
    i_info("msgid=%s: discarded",
	   md->id == NULL ? "" : str_sanitize(md->id, 80));
    return SIEVE_OK;
}

static int sieve_reject(void *ac, 
			void *ic ATTR_UNUSED, 
			void *sc, void *mc, const char **errmsg)
{
    sieve_reject_context_t *rc = (sieve_reject_context_t *) ac;
    script_data_t *sd = (script_data_t *) sc;
    sieve_msgdata_t *md = (sieve_msgdata_t *) mc;
    int res;

    if (md->return_path == NULL) {
	/* return message to who?!? */
	*errmsg = "No return-path for reply";
	return SIEVE_FAIL;
    }

    if (strlen(md->return_path) == 0) {
        i_info("msgid=%s: discarded reject to <>",
	       md->id == NULL ? "" : str_sanitize(md->id, 80));
        return SIEVE_OK;
    }

    if ((res = mail_send_rejection(md->mail, sd->username, rc->msg)) == 0) {
        i_info("msgid=%s: rejected",
	       md->id == NULL ? "" : str_sanitize(md->id, 80));
	return SIEVE_OK;
    } else {
	*errmsg = "Error sending mail";
	return SIEVE_FAIL;
    }
    return SIEVE_FAIL;
}

static void get_flags(const sieve_imapflags_t *sieve_flags,
		      enum mail_flags *flags_r, const char *const **keywords_r)
{
	ARRAY_DEFINE(keywords, const char *);
        const char *name;
	int i;

	*flags_r = 0;

	t_array_init(&keywords, 16);
	for (i = 0; i < sieve_flags->nflags; i++) {
		name = sieve_flags->flag[i];

		if (name != NULL && *name != '\\') {
			/* keyword */
			array_append(&keywords, &name, 1);
		} else {
			/* system flag */
			if (name == NULL || strcasecmp(name, "\\flagged") == 0)
				*flags_r |= MAIL_FLAGGED;
			else if (strcasecmp(name, "\\answered") == 0)
				*flags_r |= MAIL_ANSWERED;
			else if (strcasecmp(name, "\\deleted") == 0)
				*flags_r |= MAIL_DELETED;
			else if (strcasecmp(name, "\\seen") == 0)
				*flags_r |= MAIL_SEEN;
			else if (strcasecmp(name, "\\draft") == 0)
				*flags_r |= MAIL_DRAFT;
		}
	}

	name = NULL;
	array_append(&keywords, &name, 1);

	*keywords_r = array_count(&keywords) == 1 ? NULL :
		array_idx(&keywords, 0);
}

static int sieve_fileinto(void *ac, 
			  void *ic ATTR_UNUSED,
			  void *sc, 
			  void *mc,
			  const char **errmsg ATTR_UNUSED)
{
    sieve_fileinto_context_t *fc = (sieve_fileinto_context_t *) ac;
    script_data_t *sd = (script_data_t *) sc;
    sieve_msgdata_t *md = (sieve_msgdata_t *) mc;
    enum mail_flags flags;
    const char *const *keywords;

    get_flags(fc->imapflags, &flags, &keywords);

    if (deliver_save(sd->namespaces, sd->storage_r, fc->mailbox,
		     md->mail, flags, keywords) < 0)
	    return SIEVE_FAIL;

    return SIEVE_OK;
}

static int sieve_keep(void *ac, 
		      void *ic ATTR_UNUSED,
		      void *sc, void *mc, const char **errmsg ATTR_UNUSED)
{
    sieve_keep_context_t *kc = (sieve_keep_context_t *) ac;
    script_data_t *sd = (script_data_t *) sc;
    sieve_msgdata_t *md = (sieve_msgdata_t *) mc;
    enum mail_flags flags;
    const char *const *keywords;

    get_flags(kc->imapflags, &flags, &keywords);

    if (deliver_save(sd->namespaces, sd->storage_r, md->mailbox, md->mail, flags, keywords) < 0)
	    return SIEVE_FAIL;

    return SIEVE_OK;
}

static bool contains_8bit(const char *msg)
{
	const unsigned char *s = (const unsigned char *)msg;

	for (; *s != '\0'; s++) {
		if ((*s & 0x80) != 0)
			return TRUE;
	}
	return FALSE;
}

static int sieve_notify(void *ac,
			void *ic ATTR_UNUSED,
			void *sc ATTR_UNUSED,
			void *mc,
			const char **errmsg)
{
    sieve_notify_context_t *nc = (sieve_notify_context_t *) ac;
    sieve_msgdata_t *m = mc;

    int nopt = 0;
    FILE *f;
    struct smtp_client *smtp_client;
    const char *outmsgid;

    /* "default" is "mailto" as only one... */
    if (!strcasecmp(nc->method, "default")) nc->method = "mailto";
    /* check method */
    if (strcasecmp(nc->method, "mailto")) { 
        *errmsg = "Unknown [unimplemented] notify method";
	/* just log error, failed notify is not reason to abort all script. */
        i_info("SIEVE ERROR: Unknown [unimplemented] notify method <%s>", 
	nc->method);
	return SIEVE_OK;
    }    
    /* count options */
    while (nc->options[nopt]) {
	smtp_client = smtp_client_open(nc->options[nopt], NULL, &f);
	outmsgid = deliver_get_new_message_id();
	fprintf(f, "Message-ID: %s\r\n", outmsgid);
	fprintf(f, "Date: %s\r\n", message_date_create(ioloop_time));
	fprintf(f, "X-Sieve: %s\r\n", SIEVE_VERSION);
	if ( strcasecmp(nc->priority, "high") == 0 ) {
            fprintf(f, "X-Priority: 1 (Highest)\r\n");
	    fprintf(f, "Importance: High\r\n");
        } else if ( strcasecmp(nc->priority, "normal") == 0 ) {
            fprintf(f, "X-Priority: 3 (Normal)\r\n");
	    fprintf(f, "Importance: Normal\r\n");
	} else if ( strcasecmp(nc->priority, "low") == 0 ) {
	    fprintf(f, "X-Priority: 5 (Lowest)\r\n");
	    fprintf(f, "Importance: Low\r\n");
	/* RFC: If no importance is given, the default value is "2 (Normal)" */
	} else {
	    fprintf(f, "X-Priority: 3 (Normal)\r\n");
	    fprintf(f, "Importance: Normal\r\n");
	} 
	fprintf(f, "From: Postmaster <%s>\r\n",
		deliver_set->postmaster_address);
	fprintf(f, "To: <%s>\r\n", nc->options[nopt]);
	fprintf(f, "Subject: [SIEVE] New mail notification\r\n");
        fprintf(f, "Auto-Submitted: auto-generated (notify)\r\n");
	fprintf(f, "Precedence: bulk\r\n");
        if (contains_8bit(nc->message)) {
            fprintf(f, "MIME-Version: 1.0\r\n");
	    fprintf(f, "Content-Type: text/plain; charset=UTF-8\r\n");
	    fprintf(f, "Content-Transfer-Encoding: 8bit\r\n");
	}
	fprintf(f, "\r\n");
	fprintf(f, "%s\r\n", nc->message);
	if (smtp_client_close(smtp_client) == 0) {
		i_info("msgid=%s: sent notification to <%s> (method=%s)",
		       m->id == NULL ? "" : str_sanitize(m->id, 80),
		       str_sanitize(nc->options[nopt], 80), nc->method);
	} else {
		i_info("msgid=%s: ERROR sending notification to <%s> "
		       "(method=%s)",
		       m->id == NULL ? "" : str_sanitize(m->id, 80),
		       str_sanitize(nc->options[nopt], 80), nc->method);
		*errmsg = "Error sending notify mail";
	}
	nopt = nopt + 1;
    }
    return SIEVE_OK;
}

static int autorespond(void *ac, 
		       void *ic ATTR_UNUSED,
		       void *sc,
		       void *mc,
		       const char **errmsg ATTR_UNUSED)
{
    sieve_autorespond_context_t *arc = (sieve_autorespond_context_t *) ac;
    script_data_t *sd = (script_data_t *) sc;
    sieve_msgdata_t *md = mc;

    /* ok, let's see if we've responded before */
    if (duplicate_check(arc->hash, SIEVE_HASHLEN, sd->username)) {
	i_info("msgid=%s: discarded duplicate vacation response to <%s>",
	       md->id == NULL ? "" : str_sanitize(md->id, 80),
	       str_sanitize(md->return_path, 80));
	return SIEVE_DONE;
    }

    duplicate_mark(arc->hash, SIEVE_HASHLEN, sd->username,
                   ioloop_time + arc->days * (24 * 60 * 60));

    return SIEVE_OK;
}

static int send_response(void *ac, 
			 void *ic ATTR_UNUSED, 
			 void *sc, void *mc,
			 const char **errmsg)
{
    struct smtp_client *smtp_client;
    FILE *f;
    const char *outmsgid;
    sieve_send_response_context_t *src = (sieve_send_response_context_t *) ac;
    script_data_t *sdata = (script_data_t *) sc;
    sieve_msgdata_t *md = mc;

    smtp_client = smtp_client_open(src->addr, NULL, &f);

    outmsgid = deliver_get_new_message_id();
    fprintf(f, "Message-ID: %s\r\n", outmsgid);
    fprintf(f, "Date: %s\r\n", message_date_create(ioloop_time));
    
    fprintf(f, "X-Sieve: %s\r\n", SIEVE_VERSION);
    fprintf(f, "From: <%s>\r\n", src->fromaddr);
    fprintf(f, "To: <%s>\r\n", src->addr);
    fprintf(f, "Subject: %s\r\n", str_sanitize(src->subj, 80));
    if (md->id) fprintf(f, "In-Reply-To: %s\r\n", md->id);
    fprintf(f, "Auto-Submitted: auto-replied (vacation)\r\n");
    fprintf(f, "Precedence: bulk\r\n");
    fprintf(f, "MIME-Version: 1.0\r\n");
    if (src->mime) {
	fprintf(f, "Content-Type: multipart/mixed;"
		"\r\n\tboundary=\"%s/%s\"\r\n", my_pid, deliver_set->hostname);
	fprintf(f, "\r\nThis is a MIME-encapsulated message\r\n\r\n");
	fprintf(f, "--%s/%s\r\n", my_pid, deliver_set->hostname);
    } else {
	fprintf(f, "Content-Type: text/plain; charset=utf-8\r\n");
	fprintf(f, "Content-Transfer-Encoding: 8bit\r\n");
	fprintf(f, "\r\n");
    }

    fprintf(f, "%s\r\n", src->msg);
    if (src->mime)
	fprintf(f, "\r\n--%s/%s--\r\n", my_pid, deliver_set->hostname);

    if (smtp_client_close(smtp_client) == 0) {
        duplicate_mark(outmsgid, strlen(outmsgid),
                       sdata->username, ioloop_time + DUPLICATE_DEFAULT_KEEP);
	i_info("msgid=%s: sent vacation response to <%s>",
	       md->id == NULL ? "" : str_sanitize(md->id, 80),
	       str_sanitize(md->return_path, 80));
	return SIEVE_OK;
    } else {
	*errmsg = "Error sending mail";
	return SIEVE_FAIL;
    }
}

/* vacation support */
sieve_vacation_t vacation = {
    1,				/* min response */
    31,				/* max response */
    &autorespond,		/* autorespond() */
    &send_response		/* send_response() */
};

/* imapflags support */
static char *markflags[] = { "\\flagged" };
static sieve_imapflags_t mark = { markflags, 1 };

static int sieve_parse_error_handler(int lineno, const char *msg, 
				     void *ic ATTR_UNUSED,
				     void *sc)
{
    script_data_t *sd = (script_data_t *) sc;

    if (sd->errors == NULL)
	    sd->errors = str_new(default_pool, 1024);

    str_printfa(sd->errors, "line %d: %s\n", lineno, msg);
    return SIEVE_OK;
}

static int sieve_execute_error_handler(const char *msg, 
				       void *ic ATTR_UNUSED,
				       void *sc ATTR_UNUSED,
				       void *mc ATTR_UNUSED)
{
    i_info("sieve runtime error: %s", msg);
    return SIEVE_OK;
}
 
static sieve_interp_t *setup_sieve(void)
{
    sieve_interp_t *interp = NULL;
    int res;

    res = sieve_interp_alloc(&interp, NULL);
    if (res != SIEVE_OK)
	i_fatal("sieve_interp_alloc() returns %d\n", res);

    res = sieve_register_redirect(interp, &sieve_redirect);
    if (res != SIEVE_OK)
	i_fatal("sieve_register_redirect() returns %d\n", res);
    res = sieve_register_discard(interp, &sieve_discard);
    if (res != SIEVE_OK)
	i_fatal("sieve_register_discard() returns %d\n", res);
    res = sieve_register_reject(interp, &sieve_reject);
    if (res != SIEVE_OK)
	i_fatal("sieve_register_reject() returns %d\n", res);
    res = sieve_register_fileinto(interp, &sieve_fileinto);
    if (res != SIEVE_OK)
	i_fatal("sieve_register_fileinto() returns %d\n", res);
    res = sieve_register_keep(interp, &sieve_keep);
    if (res != SIEVE_OK)
	i_fatal("sieve_register_keep() returns %d\n", res);
    res = sieve_register_imapflags(interp, &mark);
    if (res != SIEVE_OK)
	i_fatal("sieve_register_imapflags() returns %d\n", res);
    res = sieve_register_notify(interp, &sieve_notify);
    if (res != SIEVE_OK)
	i_fatal("sieve_register_notify() returns %d\n", res);
    res = sieve_register_size(interp, &getsize);
    if (res != SIEVE_OK)
	i_fatal("sieve_register_size() returns %d\n", res);
    res = sieve_register_header(interp, &getheader);
    if (res != SIEVE_OK)
	i_fatal("sieve_register_header() returns %d\n", res);

    res = sieve_register_envelope(interp, &getenvelope);
    if (res != SIEVE_OK)
	i_fatal("sieve_register_envelope() returns %d\n", res);
    res = sieve_register_body(interp, &getbody);
    if (res != SIEVE_OK)
	i_fatal("sieve_register_body() returns %d\n", res);
    res = sieve_register_include(interp, &getinclude);
    if (res != SIEVE_OK)
	i_fatal("sieve_registerinclude() returns %d\n", res);
    res = sieve_register_vacation(interp, &vacation);
    if (res != SIEVE_OK)
	i_fatal("sieve_register_vacation() returns %d\n", res);
    res = sieve_register_parse_error(interp, &sieve_parse_error_handler);
    if (res != SIEVE_OK)
	i_fatal("sieve_register_parse_error() returns %d\n", res);
    res = sieve_register_execute_error(interp,  &sieve_execute_error_handler);
    if (res != SIEVE_OK)
	i_fatal("sieve_register_execute_error() returns %d\n", res);

    return interp;
}

static void
dovecot_sieve_write_error_file(script_data_t *sdata, const char *path)
{
	int fd;

	fd = open(path, O_CREAT | O_TRUNC | O_WRONLY, 0600);
	if (fd == -1) {
		i_error("open(%s) failed: %m", path);
		return;
	}

	if (write_full(fd, str_data(sdata->errors), str_len(sdata->errors)) < 0)
		i_error("write_full(%s) failed: %m", path);

	if (close(fd) < 0)
		i_error("close() failed: %m");
}

static int
dovecot_sieve_compile(script_data_t *sdata, const char *script_path,
		      const char *compiled_path)
{
	struct stat st, st2;
	sieve_script_t *script;
	bytecode_info_t *bc;
	const char *temp_path;
	FILE *f;
	int fd, ret;

	if (stat(script_path, &st) < 0) {
		if (errno == ENOENT) {
			if (getenv("DEBUG") != NULL) {
				i_info("cmusieve: Script not found: %s",
				       script_path);
			}
			return 0;
		}
		i_error("stat(%s) failed: %m", script_path);
		return -1;
	}
	if (S_ISDIR(st.st_mode)) {
		i_error("%s should be a file, not a directory", script_path);
		return -1;
	}
	if (stat(compiled_path, &st2) < 0) {
		if (errno != ENOENT) {
			i_error("stat(%s) failed: %m", script_path);
			return -1;
		}
	} else {
		if (st.st_mtime <= st2.st_mtime)
			return 1;
	}

	/* need to compile */
	f = fopen(script_path, "r");
	if (f == NULL) {
		i_error("fopen(%s) failed: %m", script_path);
		return -1;
	}

	temp_path = t_strconcat(script_path, ".err", NULL);
	ret = sieve_script_parse(sdata->interp, f, sdata, &script);
	if (ret != SIEVE_OK) {
		if (sdata->errors == NULL) {
			sdata->errors = str_new(default_pool, 128);
			str_printfa(sdata->errors, "parse error %d", ret);
		}

		if (getenv("DEBUG") != NULL) {
			i_info("cmusieve: Compilation failed for %s: %s",
			       script_path,
			       str_sanitize(str_c(sdata->errors), 80));
		}
		dovecot_sieve_write_error_file(sdata, temp_path);
		str_free(&sdata->errors);
		return -1;
	} else {
		if (unlink(temp_path) < 0 && errno != ENOENT)
			i_error("unlink(%s) failed: %m", temp_path);
	}

	if (sieve_generate_bytecode(&bc, script) < 0) {
		i_error("sieve_generate_bytecode() failed");
		return -1;
	}

	/* write to temp file */
	temp_path = t_strconcat(compiled_path, ".tmp", NULL);
	fd = open(temp_path, O_CREAT | O_TRUNC | O_WRONLY, 0600);
	if(fd == -1) {
		i_error("open(%s) failed: %m", temp_path);
		return -1;
	}

	if (sieve_emit_bytecode(fd, bc) < 0) {
		i_error("sieve_emit_bytecode() failed");
		return -1;
	}

	if (close(fd) < 0)
		i_error("close() failed: %m");

	/* and finally replace the script */
	if (rename(temp_path, compiled_path) < 0) {
		i_error("rename(%s, %s) failed: %m", temp_path, compiled_path);
		return -1;
	}
	return 1;
}

int cmu_sieve_run(struct mail_namespace *namespaces,
		  struct mail_storage **storage_r, struct mail *mail,
		  const char *script_path, const char *destaddr,
		  const char *username, const char *mailbox)
{
	sieve_execute_t *bytecode = NULL;
	script_data_t sdata;
	sieve_msgdata_t mdata;
	const char *compiled_path;
	int ret;

	memset(&sdata, 0, sizeof(sdata));
	sdata.username = username;
	sdata.namespaces = namespaces;
	sdata.storage_r = storage_r;
	sdata.interp = setup_sieve();

	compiled_path = t_strconcat(script_path, "c", NULL);
	ret = dovecot_sieve_compile(&sdata, script_path, compiled_path);
	if (ret <= 0)
		return ret;

	memset(&mdata, 0, sizeof(mdata));
	mdata.mail = mail;
	mdata.mailbox = mailbox;
	mdata.authuser = username;
	mdata.destaddr = destaddr;
	(void)mail_get_first_header(mail, "Message-ID", &mdata.id);
	mdata.return_path = deliver_get_return_address(mail);

	if ((ret = sieve_script_load(compiled_path, &bytecode)) != SIEVE_OK) {
		i_error("sieve_script_load(%s) failed: %d", compiled_path, ret);
		return -1;
	}

	if (getenv("DEBUG") != NULL)
		i_info("cmusieve: Executing script %s", compiled_path);

	ret = 1;
	if (sieve_execute_bytecode(bytecode, sdata.interp,
				   &sdata, &mdata) != SIEVE_OK) {
		i_error("sieve_execute_bytecode(%s) failed", compiled_path);
		ret = -1;
	}

	if (array_is_created(&mdata.body_parts)) {
		array_free(&mdata.body_parts);
		array_free(&mdata.return_body_parts);
		buffer_free(&mdata.tmp_buffer);
		pool_unref(&mdata.body_parts_pool);
	}
	return ret;
}

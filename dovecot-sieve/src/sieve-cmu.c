/* Copyright (C) 2005-2006 Timo Sirainen */

#include "lib.h"
#include "ioloop.h"
#include "array.h"
#include "hostpid.h"
#include "str.h"
#include "str-sanitize.h"
#include "write-full.h"
#include "message-date.h"
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
	struct mail_storage *storage;
	string_t *errors;
} script_data_t;

typedef struct {
	struct mail *mail;
	const char *mailbox;
	const char *id;
	const char *return_path;
	const char *authuser;

	const char *temp[10];
} sieve_msgdata_t;

/* gets the header "head" from msg. */
static int getheader(void *v, const char *phead, const char ***body)
{
    sieve_msgdata_t *m = v;

    if (phead==NULL) return SIEVE_FAIL;
    *body = (const char **)mail_get_headers(m->mail, phead);

    if (*body) {
	return SIEVE_OK;
    } else {
	return SIEVE_FAIL;
    }
}

static int getsize(void *mc, int *size)
{
    sieve_msgdata_t *md = mc;
    uoff_t psize;

    psize = mail_get_physical_size(md->mail);
    if (psize == (uoff_t)-1)
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
	m->temp[0] = /*FIXME:msg_getrcptall(m, m->cur_rcpt)*/m->authuser;
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

static int sieve_redirect(void *ac, 
			  void *ic __attr_unused__, 
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

static int sieve_discard(void *ac __attr_unused__, 
			 void *ic __attr_unused__, 
			 void *sc __attr_unused__, void *mc,
			 const char **errmsg __attr_unused__)
{
    sieve_msgdata_t *md = mc;

    /* ok, we won't file it, but log it */
    i_info("msgid=%s: discarded",
	   md->id == NULL ? "" : str_sanitize(md->id, 80));
    return SIEVE_OK;
}

static int sieve_reject(void *ac, 
			void *ic __attr_unused__, 
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
	array_t ARRAY_DEFINE(keywords, const char *);
        const char *name;
	int i;

	*flags_r = 0;

	ARRAY_CREATE(&keywords, default_pool, const char *, 16);
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
		array_get(&keywords, 0);
}

static int sieve_fileinto(void *ac, 
			  void *ic __attr_unused__,
			  void *sc, 
			  void *mc,
			  const char **errmsg __attr_unused__)
{
    sieve_fileinto_context_t *fc = (sieve_fileinto_context_t *) ac;
    script_data_t *sd = (script_data_t *) sc;
    sieve_msgdata_t *md = (sieve_msgdata_t *) mc;
    enum mail_flags flags;
    const char *const *keywords;

    get_flags(fc->imapflags, &flags, &keywords);

    if (deliver_save(sd->storage, fc->mailbox, md->mail, flags, keywords) < 0)
	    return SIEVE_FAIL;

    return SIEVE_OK;
}

static int sieve_keep(void *ac, 
		      void *ic __attr_unused__,
		      void *sc, void *mc, const char **errmsg __attr_unused__)
{
    sieve_keep_context_t *kc = (sieve_keep_context_t *) ac;
    script_data_t *sd = (script_data_t *) sc;
    sieve_msgdata_t *md = (sieve_msgdata_t *) mc;
    enum mail_flags flags;
    const char *const *keywords;

    get_flags(kc->imapflags, &flags, &keywords);

    if (deliver_save(sd->storage, md->mailbox, md->mail, flags, keywords) < 0)
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
			void *ic __attr_unused__,
			void *sc __attr_unused__,
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
		       void *ic __attr_unused__,
		       void *sc,
		       void *mc __attr_unused__,
		       const char **errmsg __attr_unused__)
{
    sieve_autorespond_context_t *arc = (sieve_autorespond_context_t *) ac;
    script_data_t *sd = (script_data_t *) sc;
    int ret;

    /* ok, let's see if we've responded before */
    ret = duplicate_check(arc->hash, arc->len,  sd->username) ?
	    SIEVE_DONE : SIEVE_OK;

    if (ret == SIEVE_OK) {
	duplicate_mark(arc->hash, arc->len, sd->username,
		       ioloop_time + arc->days * (24 * 60 * 60));
    }

    return ret;
}

static int send_response(void *ac, 
			 void *ic __attr_unused__, 
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
				     void *ic __attr_unused__,
				     void *sc)
{
    script_data_t *sd = (script_data_t *) sc;

    if (sd->errors == NULL) {
	    sd->errors = str_new(default_pool, 1024);
	    i_info("sieve parse error: line %d: %s", lineno, msg);
    }

    str_printfa(sd->errors, "line %d: %s\n", lineno, msg);
    return SIEVE_OK;
}

static int sieve_execute_error_handler(const char *msg, 
				       void *ic __attr_unused__,
				       void *sc __attr_unused__,
				       void *mc __attr_unused__)
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

static int
dovecot_sieve_compile(sieve_interp_t *interp, script_data_t *sdata,
		      const char *script_path, const char *compiled_path)
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
	if (stat(compiled_path, &st2) < 0) {
		if (errno != ENOENT) {
			i_error("stat(%s) failed: %m", script_path);
			return -1;
		}
	} else {
		if (st.st_mtime < st2.st_mtime)
			return 1;
	}

	/* need to compile */
	f = fopen(script_path, "r");
	if (f == NULL) {
		i_error("fopen(%s) failed: %m", script_path);
		return -1;
	}

	ret = sieve_script_parse(interp, f, sdata, &script);
	if (ret != SIEVE_OK) {
		if (sdata->errors == NULL) {
			sdata->errors = str_new(default_pool, 128);
			str_printfa(sdata->errors, "parse error %d", ret);
		}
		return -1;
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

int cmu_sieve_run(struct mail_storage *storage, struct mail *mail,
		  const char *script_path, const char *username,
		  const char *mailbox)
{
	sieve_interp_t *interp;
	sieve_bytecode_t *bytecode;
	script_data_t sdata;
	sieve_msgdata_t mdata;
	const char *compiled_path, *path;
	int ret;

	interp = setup_sieve();

	memset(&sdata, 0, sizeof(sdata));
	sdata.username = username;
	sdata.storage = storage;

	compiled_path = t_strconcat(script_path, "c", NULL);
	ret = dovecot_sieve_compile(interp, &sdata, script_path, compiled_path);

	if (sdata.errors != NULL) {
		if (getenv("DEBUG") != NULL) {
			i_info("cmusieve: Compilation failed for %s: %s",
			       script_path,
			       str_sanitize(str_c(sdata.errors), 80));
		}
		path = t_strconcat(script_path, ".err", NULL);
		dovecot_sieve_write_error_file(&sdata, path);
		str_free(&sdata.errors);
	}
	if (ret <= 0)
		return ret;

	memset(&mdata, 0, sizeof(mdata));
	mdata.mail = mail;
	mdata.mailbox = mailbox;
	mdata.authuser = username;
	mdata.id = mail_get_first_header(mail, "Message-ID");
	mdata.return_path = deliver_get_return_address(mail);

	if ((ret = sieve_script_load(compiled_path, &bytecode)) != SIEVE_OK) {
		i_error("sieve_script_load(%s) failed: %d", compiled_path, ret);
		return -1;
	}

	if (getenv("DEBUG") != NULL)
		i_info("cmusieve: Executing script %s", compiled_path);

	if (sieve_execute_bytecode(bytecode, interp,
				   &sdata, &mdata) != SIEVE_OK) {
		i_error("sieve_execute_bytecode(%s) failed", compiled_path);
		return -1;
	}

	return 1;
}

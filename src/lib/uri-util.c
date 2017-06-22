/* Copyright (c) 2010-2017 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "str.h"
#include "net.h"
#include "uri-util.h"

#include <ctype.h>

/*
 * Generic URI parsing.
 *
 * [URI-GEN] RFC3986 Appendix A:
 *
 * host             = IP-literal / IPv4address / reg-name
 * port             = *DIGIT
 * reg-name         = *( unreserved / pct-encoded / sub-delims )
 * unreserved       = ALPHA / DIGIT / "-" / "." / "_" / "~"
 * pct-encoded      = "%" HEXDIG HEXDIG
 * sub-delims       = "!" / "$" / "&" / "'" / "(" / ")"
 *                  / "*" / "+" / "," / ";" / "="
 * IP-literal       = "[" ( IPv6address / IPvFuture  ) "]"
 * IPvFuture        = "v" 1*HEXDIG "." 1*( unreserved / sub-delims / ":" )
 * IPv6address      =                            6( h16 ":" ) ls32
 *                  /                       "::" 5( h16 ":" ) ls32
 *                  / [               h16 ] "::" 4( h16 ":" ) ls32
 *                  / [ *1( h16 ":" ) h16 ] "::" 3( h16 ":" ) ls32
 *                  / [ *2( h16 ":" ) h16 ] "::" 2( h16 ":" ) ls32
 *                  / [ *3( h16 ":" ) h16 ] "::"    h16 ":"   ls32
 *                  / [ *4( h16 ":" ) h16 ] "::"              ls32
 *                  / [ *5( h16 ":" ) h16 ] "::"              h16
 *                  / [ *6( h16 ":" ) h16 ] "::"
 * h16              = 1*4HEXDIG
 * ls32             = ( h16 ":" h16 ) / IPv4address
 * IPv4address      = dec-octet "." dec-octet "." dec-octet "." dec-octet
 * dec-octet        = DIGIT                 ; 0-9
 *                  / %x31-39 DIGIT         ; 10-99
 *                  / "1" 2DIGIT            ; 100-199
 *                  / "2" %x30-34 DIGIT     ; 200-249
 *                  / "25" %x30-35          ; 250-255
 */

#define URI_MAX_SCHEME_NAME_LEN 64

/* Character lookup table
 *
 * unreserved    = ALPHA / DIGIT / "-" / "." / "_" / "~"     [bit0]
 * sub-delims    = "!" / "$" / "&" / "'" / "(" / ")"
 *               / "*" / "+" / "," / ";" / "="               [bit1]
 * gen-delims    = ":" / "/" / "?" / "#" / "[" / "]" / "@"   [bit2]
 * pchar         = unreserved / sub-delims / ":" / "@"       [bit0|bit1|bit3]
 * 'pfchar'      = unreserved / sub-delims / ":" / "@" / "/" 
 *                                                      [bit0|bit1|bit3|bit5]
 * 'uchar'       = unreserved / sub-delims / ":"             [bit0|bit1|bit4]
 * 'qchar'       = pchar / "/" / "?"               [bit0|bit1|bit3|bit5|bit6]
 *
 */

#define CHAR_MASK_UNRESERVED (1<<0)
#define CHAR_MASK_SUB_DELIMS (1<<1)
#define CHAR_MASK_PCHAR ((1<<0)|(1<<1)|(1<<3))
#define CHAR_MASK_PFCHAR ((1<<0)|(1<<1)|(1<<3)|(1<<5))
#define CHAR_MASK_UCHAR ((1<<0)|(1<<1)|(1<<4))
#define CHAR_MASK_QCHAR ((1<<0)|(1<<1)|(1<<3)|(1<<5)|(1<<6))

static unsigned const char _uri_char_lookup[256] = {
	 0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  // 00
	 0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  // 10
	 0,  2,  0,  4,  2,  0,  2,  2,  2,  2,  2,  2,  2,  1,  1, 36,  // 20
	 1,  1,  1,  1,  1,  1,  1,  1,  1,  1, 28,  2,  0,  2,  0, 68,  // 30
	12,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  // 40
	 1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  4,  0,  4,  0,  1,  // 50
	 0,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  // 60
	 1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  0,  0,  0,  1,  0,  // 70
};

static inline int _decode_hex_digit(const unsigned char digit)
{
	switch (digit) {
	case '0': case '1': case '2': case '3': case '4':
	case '5': case '6': case '7': case '8': case '9':
		return digit - '0';

	case 'a': case 'b': case 'c': case 'd': case 'e': case 'f':
		return digit - 'a' + 0x0a;

	case 'A': case 'B': case 'C': case 'D': case 'E': case 'F':
		return digit - 'A' + 0x0A;
	}
	return -1;
}

static int
uri_parse_pct_encoded_data(struct uri_parser *parser,
		      const unsigned char **p, const unsigned char *pend,
		      unsigned char *ch_r) ATTR_NULL(3)
{
	int value;

	if (**p != '%' || (pend != NULL && *p >= pend))
		return 0;
	*p += 1;

	if (**p == 0 || *(*p+1) == 0 || (pend != NULL && *p+1 >= pend)) {
		parser->error = "Unexpected URI boundary after '%'";
		return -1;
	}

	if ((value = _decode_hex_digit(**p)) < 0) {
		parser->error = p_strdup_printf(parser->pool,
			"Expecting hex digit after '%%', but found '%c'", **p);
		return -1;
	}
	
	*ch_r = (value & 0x0f) << 4;
	*p += 1;
	
	if ((value = _decode_hex_digit(**p)) < 0) {
		parser->error = p_strdup_printf(parser->pool,
			"Expecting hex digit after '%%%c', but found '%c'",	*((*p)-1), **p);
		return -1;
	}

	*ch_r |= (value & 0x0f);
	*p += 1;

	if (!parser->allow_pct_nul && *ch_r == '\0') {
		parser->error =
			"Percent encoding is not allowed to encode NUL character";
		return -1;
	}
	return 1;	
}

int uri_parse_pct_encoded(struct uri_parser *parser,
		      unsigned char *ch_r)
{
	return uri_parse_pct_encoded_data
		(parser, &parser->cur, parser->end, ch_r);
}

static int
uri_parse_unreserved_char(struct uri_parser *parser, unsigned char *ch_r)
{
	int ret;

	if ((ret=uri_parse_pct_encoded(parser, ch_r)) != 0)
		return ret;

	if ((*parser->cur & 0x80) != 0)
		return 0;

	if ((_uri_char_lookup[*parser->cur] & CHAR_MASK_UNRESERVED) != 0) {
		*ch_r = *parser->cur;
		parser->cur++;
		return 1;
	}			
	return 0;
}

int uri_parse_unreserved(struct uri_parser *parser, string_t *part)
{
	int len = 0;

	while (parser->cur < parser->end) {
		int ret;
		unsigned char ch = 0;

		if ((ret = uri_parse_unreserved_char(parser, &ch)) < 0)
			return -1;
		if (ret == 0)
			break;

		if (part != NULL)
			str_append_c(part, ch);
		len++;
	}

	return len > 0 ? 1 : 0;
}

bool uri_data_decode(struct uri_parser *parser, const char *data,
		     const char *until, const char **decoded_r)
{
	const unsigned char *p = (const unsigned char *)data;
	const unsigned char *pend = (const unsigned char *)until;
	string_t *decoded;
	int ret;

	if (pend == NULL) {
		/* NULL means unlimited; solely rely on '\0' */
		pend = (const unsigned char *)(size_t)-1;
	}
	
	if (p >= pend || *p == '\0') {
		if (decoded_r != NULL)
			*decoded_r = "";
		return TRUE;
	}
	
	decoded = uri_parser_get_tmpbuf(parser, 256);
	while (p < pend && *p != '\0') {
		unsigned char ch;

		if ((ret=uri_parse_pct_encoded_data
			(parser, &p, NULL, &ch)) != 0) {
			if (ret < 0)
				return FALSE;
			str_append_c(decoded, ch);
		} else {
			str_append_c(decoded, *p);
			p++;
		}
	}

	if (decoded_r != NULL)
		*decoded_r = p_strdup(parser->pool, str_c(decoded));
	return TRUE;
}

int uri_cut_scheme(const char **uri_p, const char **scheme_r)
{
	const char *p = *uri_p;
	size_t len = 1;
	
	/* RFC 3968:
	 *   scheme  = ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )
	 */
	
	if (!i_isalpha(*p))
		return -1;
	p++;
		
	while (len < URI_MAX_SCHEME_NAME_LEN && *p != '\0') {			
		if (!i_isalnum(*p) && *p != '+' && *p != '-' && *p != '.')
			break;
		p++;
		len++;
	}
	
	if (*p != ':')
		return -1;
	
	if (scheme_r != NULL)
		*scheme_r = t_strdup_until(*uri_p, p);
	*uri_p = p + 1;
	return 0;
}

int uri_parse_scheme(struct uri_parser *parser, const char **scheme_r)
{
	const char *p;

	if (parser->cur >= parser->end)
		return 0;

	p = (const char *)parser->cur;
	if (uri_cut_scheme(&p, scheme_r) < 0)
		return 0;

	parser->cur = (const unsigned char *)p;
	if (!parser->pool->datastack_pool)
		*scheme_r = p_strdup(parser->pool, *scheme_r);
	return 1;
}

static int
uri_parse_dec_octet(struct uri_parser *parser, string_t *literal,
		    uint8_t *octet_r) ATTR_NULL(2)
{
	unsigned int octet = 0;
	int count = 0;

	/* RFC 3986:
	 *
	 * dec-octet     = DIGIT                 ; 0-9
	 *               / %x31-39 DIGIT         ; 10-99
	 *               / "1" 2DIGIT            ; 100-199
	 *               / "2" %x30-34 DIGIT     ; 200-249
	 *               / "25" %x30-35          ; 250-255
	 */

	while (parser->cur < parser->end && i_isdigit(*parser->cur)) {
		octet = octet * 10 + (parser->cur[0] - '0');
		if (octet > 255)
			return -1;

		if (literal != NULL)
			str_append_c(literal, *parser->cur);

		parser->cur++;
		count++;
	}

	if (count > 0) {
		*octet_r = octet;
		return 1;
	}
	return 0;
}

static int
uri_parse_ipv4address(struct uri_parser *parser, string_t *literal,
		      struct in_addr *ip4_r) ATTR_NULL(2,3)
{
	uint8_t octet;
	uint32_t ip = 0;
	int ret;
	int i;

	/* RFC 3986:
	 *
	 * IPv4address   = dec-octet "." dec-octet "." dec-octet "." dec-octet
	 */

	if ((ret = uri_parse_dec_octet(parser, literal, &octet)) <= 0)
		return ret;
	ip = octet;
	
	for (i = 0; i < 3 && parser->cur < parser->end; i++) {
		if (*parser->cur != '.')
			return -1;

		if (literal != NULL)
			str_append_c(literal, '.');
		parser->cur++;

		if ((ret = uri_parse_dec_octet(parser, literal, &octet)) <= 0)
			return -1;
		ip = (ip << 8) + octet;
	}
	
	if (ip4_r != NULL)
		ip4_r->s_addr = htonl(ip);
	return 1;
}

static int
uri_parse_reg_name(struct uri_parser *parser,
	string_t *reg_name) ATTR_NULL(2)
{
	/* RFC 3986:
	 *
	 * reg-name      = *( unreserved / pct-encoded / sub-delims )
	*/

	while (parser->cur < parser->end) {
		int ret;
		unsigned char c;

		/* unreserved / pct-encoded */
		if ((ret = uri_parse_unreserved_char(parser, &c)) < 0)
			return -1;

		if (ret > 0) {
			if (reg_name != NULL)
				str_append_c(reg_name, c);
			continue;
		}

		/* sub-delims */
		c = *parser->cur;
		if ((c & 0x80) == 0 && (_uri_char_lookup[c] & CHAR_MASK_SUB_DELIMS) != 0) {
			if (reg_name != NULL)
				str_append_c(reg_name, *parser->cur);
			parser->cur++;
			continue;
		}
		break;
	}
	return 0;
}

#ifdef HAVE_IPV6
static int
uri_parse_ip_literal(struct uri_parser *parser, string_t *literal,
		     struct in6_addr *ip6_r) ATTR_NULL(2,3)
{
	const unsigned char *p;
	const char *address;
	struct in6_addr ip6;
	int ret;

	/* IP-literal    = "[" ( IPv6address / IPvFuture  ) "]"
	 * IPvFuture     = "v" 1*HEXDIG "." 1*( unreserved / sub-delims / ":" )
	 * IPv6address   = ; Syntax not relevant: parsed using inet_pton()
	 */

	/* "[" already verified */

	/* Scan for end of address */
	for (p = parser->cur+1; p < parser->end; p++) {
		if (*p == ']')
			break;
	}

	if (p >= parser->end || *p != ']') {
		parser->error = "Expecting ']' at end of IP-literal";
		return -1;
	}

	if (literal != NULL)
		str_append_n(literal, parser->cur, p-parser->cur+1);
	address = t_strdup_until(parser->cur+1, p);
	parser->cur = p + 1;	

	if (*address == '\0') {
		parser->error = "Empty IPv6 host address";
		return -1;
	}
	if (*address == 'v') {
		parser->error = p_strdup_printf(parser->pool,
			"Future IP host address '%s' not supported", address);
		return -1;
	}
	if ((ret = inet_pton(AF_INET6, address, &ip6)) <= 0) {
		parser->error = p_strdup_printf(parser->pool,
			"Invalid IPv6 host address '%s'", address);
		return -1;
	}
	if (ip6_r != NULL)
		*ip6_r = ip6;
	return 1;
}
#endif

static int 
uri_parse_host(struct uri_parser *parser,
	struct uri_authority *auth) ATTR_NULL(2)
{
	const unsigned char *preserve;
	struct in_addr ip4;
	struct in6_addr ip6;
	string_t *literal = NULL;
	int ret;

	/* RFC 3986:
	 *
	 * host          = IP-literal / IPv4address / reg-name
	 */

	literal = uri_parser_get_tmpbuf(parser, 256);

	/* IP-literal / */
	if (parser->cur < parser->end && *parser->cur == '[') {
#ifdef HAVE_IPV6
		if ((ret=uri_parse_ip_literal(parser, literal, &ip6)) <= 0)
			return -1;

		if (auth != NULL) {
			auth->host_literal = p_strdup(parser->pool, str_c(literal));
			auth->host_ip.family = AF_INET6;
			auth->host_ip.u.ip6 = ip6;
			auth->have_host_ip = TRUE;
		}
		return 1;
#else
		parser->error = "IPv6 host address is not supported";
		return -1;
#endif
	}

	/* IPv4address /
	 *
	 * If it fails to parse, we try to parse it as a reg-name
	 */
	preserve = parser->cur;
	if ((ret = uri_parse_ipv4address(parser, literal, &ip4)) > 0) {
		if (auth != NULL) {
			auth->host_literal = p_strdup(parser->pool, str_c(literal));
			auth->host_ip.family = AF_INET;
			auth->host_ip.u.ip4 = ip4;
			auth->have_host_ip = TRUE;
		}
		return ret;
	}
	parser->cur = preserve;
	str_truncate(literal, 0);

	/* reg-name */
	if (uri_parse_reg_name(parser, literal) < 0)
		return -1;
	if (auth != NULL) {
		auth->host_literal = p_strdup(parser->pool, str_c(literal));
		auth->have_host_ip = FALSE;
	}
	return 0;
}

static int
uri_parse_port(struct uri_parser *parser,
	struct uri_authority *auth) ATTR_NULL(2)
{
	const unsigned char *first;
	in_port_t port;

	/* RFC 3986:
	 *
	 * port        = *DIGIT
	 */

	first = parser->cur;
	while (parser->cur < parser->end && i_isdigit(*parser->cur))
		parser->cur++;

	if (parser->cur == first)
		return 0;
	if (net_str2port(t_strdup_until(first, parser->cur), &port) < 0) {
		parser->error = "Invalid port number";
		return -1;
	}

	if (auth != NULL) {
		auth->port = port;
		auth->have_port = TRUE;
	}
	return 1;
}

int uri_parse_authority(struct uri_parser *parser,
	struct uri_authority *auth)
{
	const unsigned char *p;
	int ret;
	
	/*
	 * authority     = [ userinfo "@" ] host [ ":" port ]
	 */

	if (auth != NULL)
		i_zero(auth);

	/* Scan ahead to check whether there is a [userinfo "@"] uri component */
	for (p = parser->cur; p < parser->end; p++){
		/* refuse 8bit characters */
		if ((*p & 0x80) != 0)
			break;

		/* break at first delimiter */
		if (*p != '%' && (_uri_char_lookup[*p] & CHAR_MASK_UCHAR) == 0)
			break;
	}

	/* Extract userinfo */	
	if (p < parser->end && *p == '@') {
		if (auth != NULL)
			auth->enc_userinfo = p_strdup_until(parser->pool, parser->cur, p);
		parser->cur = p+1;
	}

	/* host */
	if (uri_parse_host(parser, auth) < 0)
		return -1;
	if (parser->cur == parser->end)
		return 1;
	switch (*parser->cur) {
	case ':': case '/': case '?': case '#':
		break;
	default:
		parser->error = "Invalid host identifier";
		return -1;
	}

	/* [":" port] */
	if (*parser->cur == ':') {
		parser->cur++;
	
		if ((ret = uri_parse_port(parser, auth)) < 0)
			return ret;
		if (parser->cur == parser->end)
			return 1;
		switch (*parser->cur) {
		case '/': case '?': case '#':
			break;
		default:
			parser->error = "Invalid host port";
			return -1;
		}
	}

	return 1;
}

int uri_parse_slashslash_authority(struct uri_parser *parser,
	struct uri_authority *auth)
{
	/* "//" authority */

	if ((parser->end - parser->cur) <= 2 || parser->cur[0] != '/' ||
	    parser->cur[1] != '/')
		return 0;

	parser->cur += 2;
	return uri_parse_authority(parser, auth);
}

int uri_parse_path_segment(struct uri_parser *parser, const char **segment_r)
{
	const unsigned char *first = parser->cur;
	int ret;

	while (parser->cur < parser->end) {
		if (*parser->cur == '%') {
			unsigned char ch = 0;
			if ((ret=uri_parse_pct_encoded(parser, &ch)) < 0)
				return -1;
			if (ret > 0)
				continue;
		}

		if ((*parser->cur & 0x80) != 0 ||
			(_uri_char_lookup[*parser->cur] & CHAR_MASK_PCHAR) == 0)
			break;

		parser->cur++;
	}

	if (parser->cur < parser->end &&
		*parser->cur != '/' && *parser->cur != '?' && *parser->cur != '#' ) {
		parser->error =
			"Path component contains invalid character";
		return -1;
	}

	if (first == parser->cur)
		return 0;

	if (segment_r != NULL)
		*segment_r = p_strdup_until(parser->pool, first, parser->cur);
	return 1;
}

int uri_parse_path(struct uri_parser *parser,
		   int *relative_r, const char *const **path_r)
{
	const unsigned char *pbegin = parser->cur;
	ARRAY_TYPE(const_string) segments;
	const char *segment = NULL;
	unsigned int count;
	int relative = 1;
	int ret;

	count = 0;
	if (path_r != NULL)
		p_array_init(&segments, parser->pool, 16);
	else
		i_zero(&segments);

	/* check for a leading '/' and indicate absolute path
	   when it is present
	 */
	if (parser->cur < parser->end && *parser->cur == '/') {
		parser->cur++;
		relative = 0;
	}
	
	/* parse first segment */
	if ((ret = uri_parse_path_segment(parser, &segment)) < 0)
		return -1;
	
	for (;;) {
		if (ret > 0) {
			/* strip dot segments */
			if (segment[0] == '.') {
				if (segment[1] == '.') {
					if (segment[2] == '\0') {
						/* '..' -> skip and... */
						segment = NULL;

						/* ... pop last segment (if any) */
						if (count > 0) {
							if (path_r != NULL) {
								i_assert(count == array_count(&segments));
								array_delete(&segments, count-1, 1);
							}
							count--;
						} else if ( relative > 0 ) {
							relative++;
						}
					}
				} else if (segment[1] == '\0') {
					/* '.' -> skip */
					segment = NULL;
				}
			}
		} else {
			segment = "";
		}

		if (segment != NULL) {
			if (path_r != NULL)
				array_append(&segments, &segment, 1);
			count++;
		}

		if (parser->cur >= parser->end || *parser->cur != '/')
			break;
		parser->cur++;

		/* parse next path segment */
		if ((ret = uri_parse_path_segment(parser, &segment)) < 0)
			return -1;
	}

	if (relative_r != NULL)
		*relative_r = relative;
	if (path_r != NULL)
		*path_r = NULL;

	if (parser->cur == pbegin) {
		/* path part of URI is empty */
		return 0;
	}

	if (path_r != NULL) {
		/* special treatment for a trailing '..' or '.' */
		if (segment == NULL) {
			segment = "";
			array_append(&segments, &segment, 1);
		}
		array_append_zero(&segments);
		*path_r = array_get(&segments, &count);
	}
	if (parser->cur < parser->end &&
		*parser->cur != '?' && *parser->cur != '#') {
		parser->error = "Path component contains invalid character";
		return -1;
	}
	return 1;
}

int uri_parse_query(struct uri_parser *parser, const char **query_r)
{
	const unsigned char *first = parser->cur;
	int ret;

	/* RFC 3986:
	 *
	 * URI           = { ... } [ "?" query ] { ... }
	 * query         = *( pchar / "/" / "?" )
	 * pchar         = unreserved / pct-encoded / sub-delims / ":" / "@"
	 */
	if (parser->cur >= parser->end || *parser->cur != '?')
		return 0;
	parser->cur++;

	while (parser->cur < parser->end) {
		if (*parser->cur == '%') {
			unsigned char ch = 0;
			if ((ret=uri_parse_pct_encoded(parser, &ch)) < 0)
				return -1;
			if (ret > 0)
				continue;
		}

		if ((*parser->cur & 0x80) != 0 ||
			(_uri_char_lookup[*parser->cur] & CHAR_MASK_QCHAR) == 0)
			break;
		parser->cur++;
	}

	if (parser->cur < parser->end && *parser->cur != '#') {
		parser->error = "Query component contains invalid character";
		return -1;
	}

	if (query_r != NULL)
		*query_r = p_strdup_until(parser->pool, first+1, parser->cur);
	return 1;
}

int uri_parse_fragment(struct uri_parser *parser, const char **fragment_r)
{
	const unsigned char *first = parser->cur;
	int ret;

	/* RFC 3986:
	 *
	 * URI           = { ... } [ "#" fragment ]
	 * fragment      = *( pchar / "/" / "?" )
	 * pchar         = unreserved / pct-encoded / sub-delims / ":" / "@"
	 */

	if (parser->cur >= parser->end || *parser->cur != '#')
		return 0;
	parser->cur++;

	while (parser->cur < parser->end) {
		if (*parser->cur == '%') {
			unsigned char ch = 0;
			if ((ret=uri_parse_pct_encoded(parser, &ch)) < 0)
				return -1;
			if (ret > 0)
				continue;
		}

		if ((*parser->cur & 0x80) != 0 ||
			(_uri_char_lookup[*parser->cur] & CHAR_MASK_QCHAR) == 0)
			break;
		parser->cur++;
	}

	if (parser->cur < parser->end) {
		parser->error = "Fragment component contains invalid character";
		return -1;
	}

	if (fragment_r != NULL)
		*fragment_r = p_strdup_until(parser->pool, first+1, parser->cur);
	return 1;
}

void uri_parser_init(struct uri_parser *parser, pool_t pool, const char *data)
{
	parser->pool = pool;
	parser->begin = parser->cur = (unsigned char *)data;
	parser->end = (unsigned char *)data + strlen(data);
	parser->error = NULL;
	parser->tmpbuf = NULL;
}

string_t *uri_parser_get_tmpbuf(struct uri_parser *parser, size_t size)
{
	if (parser->tmpbuf == NULL)
		parser->tmpbuf = str_new(parser->pool, size);
	else
		str_truncate(parser->tmpbuf, 0);
	return parser->tmpbuf;
}

/*
 * Generic URI construction
 */

static void
uri_data_encode(string_t *out, const unsigned char esc_table[256],
		unsigned char esc_mask, const char *esc_extra, const char *data)
{
	const unsigned char *p = (const unsigned char *)data;

	while (*p != '\0') {
		if ((*p & 0x80) != 0 || (esc_table[*p] & esc_mask) == 0 ||
		    strchr(esc_extra, (char)*p) != NULL) {
			str_printfa(out, "%%%02x", *p);
		} else {
			str_append_c(out, *p);
		}
		p++;
	}
}

void uri_append_scheme(string_t *out, const char *scheme)
{
	str_append(out, scheme);
	str_append_c(out, ':');
}

void uri_append_user_data(string_t *out, const char *esc,
	const char *data)
{
	uri_data_encode(out, _uri_char_lookup, CHAR_MASK_UCHAR, esc, data);
}

void uri_append_userinfo(string_t *out, const char *userinfo)
{
	uri_append_user_data(out, "", userinfo);
	str_append_c(out, '@');
}

void uri_append_host_name(string_t *out, const char *name)
{
	uri_data_encode(out, _uri_char_lookup,
			CHAR_MASK_UNRESERVED | CHAR_MASK_SUB_DELIMS, "", name);
}

void uri_append_host_ip(string_t *out, const struct ip_addr *host_ip)
{
	const char *addr = net_ip2addr(host_ip);

	if (host_ip->family == AF_INET) {
		str_append(out, addr);
		return;
	}

	i_assert(host_ip->family == AF_INET6);
	str_append_c(out, '[');
	str_append(out, addr);
	str_append_c(out, ']');
}

void uri_append_port(string_t *out, in_port_t port)
{
	str_printfa(out, ":%u", port);
}

void uri_append_path_segment_data(string_t *out, const char *esc,
				  const char *data)
{
	uri_data_encode(out, _uri_char_lookup, CHAR_MASK_PCHAR, esc, data);
}

void uri_append_path_segment(string_t *out, const char *segment)
{
	str_append_c(out, '/');
	if (*segment != '\0')
		uri_append_path_data(out, "", segment);
}

void uri_append_path_data(string_t *out, const char *esc,
			  const char *data)
{
	uri_data_encode(out, _uri_char_lookup, CHAR_MASK_PFCHAR, esc, data);
}

void uri_append_path(string_t *out, const char *path)
{
	str_append_c(out, '/');
	if (*path != '\0')
		uri_append_path_data(out, "", path);
}

void uri_append_query_data(string_t *out, const char *esc,
			   const char *data)
{
	uri_data_encode(out, _uri_char_lookup, CHAR_MASK_QCHAR, esc, data);
}

void uri_append_query(string_t *out, const char *query)
{
	str_append_c(out, '?');
	if (*query != '\0')
		uri_append_query_data(out, "", query);
}

void uri_append_fragment_data(string_t *out, const char *esc,
			      const char *data)
{
	uri_data_encode(out, _uri_char_lookup, CHAR_MASK_QCHAR, esc, data);
}

void uri_append_fragment(string_t *out, const char *fragment)
{
	str_append_c(out, '#');
	if (*fragment != '\0')
		uri_append_fragment_data(out, "", fragment);
}

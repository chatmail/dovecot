#ifndef COMPRESSION_H
#define COMPRESSION_H

/* Compressed input is always detected once at maximum this many bytes have
   been read. This value must be smaller than a typical istream max buffer
   size. */
#define COMPRESSION_HDR_MAX_SIZE 128

struct compression_handler {
	const char *name;
	const char *ext;
	bool (*is_compressed)(struct istream *input);
	struct istream *(*create_istream)(struct istream *input,
					  bool log_errors);
	struct ostream *(*create_ostream)(struct ostream *output, int level);
};

extern const struct compression_handler compression_handlers[];

/* Returns 1 if compression handler was found and is usable, 0 if support isn't
   compiled in, -1 if unknown. */
int compression_lookup_handler(const char *name,
			       const struct compression_handler **handler_r);
/* Detect handler by looking at the first few bytes of the input stream. */
const struct compression_handler *
compression_detect_handler(struct istream *input);
/* Lookup handler based on filename extension in the path, returns the same
 * values as compression_lookup_handler. */
int compression_lookup_handler_from_ext(const char *path,
					const struct compression_handler **handler_r);

#endif

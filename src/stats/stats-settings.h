#ifndef STATS_SETTINGS_H
#define STATS_SETTINGS_H

/* <settings checks> */
/*
 * We allow a selection of a timestamp format.
 *
 * The 'time-unix' format generates a number with the number of seconds
 * since 1970-01-01 00:00 UTC.
 *
 * The 'time-rfc3339' format uses the YYYY-MM-DDTHH:MM:SS.uuuuuuZ format as
 * defined by RFC 3339.
 *
 * The special native format (not explicitly selectable in the config, but
 * default if no time-* token is used) uses the format's native timestamp
 * format.  Note that not all formats have a timestamp data format.
 *
 * The native format and the rules below try to address the question: can a
 * parser that doesn't have any knowledge of fields' values' types losslessly
 * reconstruct the fields?
 *
 * For example, JSON only has strings and numbers, so it cannot represent a
 * timestamp in a "context-free lossless" way.  Therefore, when making a
 * JSON blob, we need to decide which way to serialize timestamps.  No
 * matter how we do it, we incur some loss.  If a decoder sees 1557232304 in
 * a field, it cannot be certain if the field is an integer that just
 * happens to be a reasonable timestamp, or if it actually is a timestamp.
 * Same goes with RFC3339 - it could just be that the user supplied a string
 * that looks like a timestamp, and that string made it into an event field.
 *
 * Other common serialization formats, such as CBOR, have a lossless way of
 * encoding timestamps.
 *
 * Note that there are two concepts at play: native and default.
 *
 * The rules for how the format's timestamp formats are used:
 *
 * 1. The default time format is the native format.
 * 2. The native time format may or may not exist for a given format (e.g.,
 *    in JSON)
 * 3. If the native format doesn't exist and no time format was specified in
 *    the config, it is a config error.
 *
 * We went with these rules because:
 *
 * 1. It prevents type information loss by default.
 * 2. It completely isolates the policy from the algorithm.
 * 3. It defers the decision whether each format without a native timestamp
 *    type should have a default acting as native until after we've had some
 *    operational experience.
 * 4. A future decision to add a default (via 3. point) will be 100% compatible.
 */
enum event_exporter_time_fmt {
	EVENT_EXPORTER_TIME_FMT_NATIVE = 0,
	EVENT_EXPORTER_TIME_FMT_UNIX,
	EVENT_EXPORTER_TIME_FMT_RFC3339,
};
/* </settings checks> */

struct stats_exporter_settings {
	const char *name;
	const char *transport;
	const char *transport_args;
	const char *format;
	const char *format_args;

	/* parsed values */
	enum event_exporter_time_fmt parsed_time_format;
};

struct stats_metric_settings {
	const char *name;
	const char *event_name;
	const char *source_location;
	const char *categories;
	const char *fields;
	ARRAY(const char *) filter;

	unsigned int parsed_source_linenum;

	/* exporter related fields */
	const char *exporter;
	const char *exporter_include;
};

struct stats_settings {
	ARRAY(struct stats_exporter_settings *) exporters;
	ARRAY(struct stats_metric_settings *) metrics;
};

extern const struct setting_parser_info stats_setting_parser_info;

#endif

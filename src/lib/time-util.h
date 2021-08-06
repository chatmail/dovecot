#ifndef TIME_UTIL_H
#define TIME_UTIL_H

#include <sys/time.h> /* for struct timeval */

/* Same as gettimeofday(), but call i_fatal() if the call fails. */
void i_gettimeofday(struct timeval *tv_r);
/* Return nanoseconds since UNIX epoch (1970-01-01). */
uint64_t i_nanoseconds(void);
/* Return microseconds since UNIX epoch (1970-01-01). */
static inline uint64_t i_microseconds(void) {
	return i_nanoseconds() / 1000;
}

/* Returns -1 if tv1<tv2, 1 if tv1>tv2, 0 if they're equal. */
int timeval_cmp(const struct timeval *tv1, const struct timeval *tv2);
/* Same as timeval_cmp, but tv->usecs must differ by at least usec_margin */
int timeval_cmp_margin(const struct timeval *tv1, const struct timeval *tv2,
		       unsigned int usec_margin);
/* Returns tv1-tv2 in milliseconds. */
int timeval_diff_msecs(const struct timeval *tv1, const struct timeval *tv2);
/* Returns tv1-tv2 in microseconds. */
long long timeval_diff_usecs(const struct timeval *tv1,
			     const struct timeval *tv2);

static inline void
timeval_add_usecs(struct timeval *tv, long long usecs)
{
	i_assert(usecs >= 0);
	tv->tv_sec += usecs / 1000000;
	tv->tv_usec += (usecs % 1000000);
	if (tv->tv_usec >= 1000000) {
		tv->tv_sec++;
		tv->tv_usec -= 1000000;
	}
}

static inline void
timeval_sub_usecs(struct timeval *tv, long long usecs)
{
	i_assert(usecs >= 0);
	tv->tv_sec -= usecs / 1000000;
	tv->tv_usec -= (usecs % 1000000);
	if (tv->tv_usec < 0) {
		tv->tv_sec--;
		tv->tv_usec += 1000000;
	}
}

static inline void
timeval_add_msecs(struct timeval *tv, unsigned int msecs)
{
	tv->tv_sec += msecs / 1000;
	tv->tv_usec += (msecs % 1000) * 1000;
	if (tv->tv_usec >= 1000000) {
		tv->tv_sec++;
		tv->tv_usec -= 1000000;
	}
}

static inline void
timeval_sub_msecs(struct timeval *tv, unsigned int msecs)
{
	tv->tv_sec -= msecs / 1000;
	tv->tv_usec -= (msecs % 1000) * 1000;
	if (tv->tv_usec < 0) {
		tv->tv_sec--;
		tv->tv_usec += 1000000;
	}
}

static inline void timeval_add(struct timeval *tv, const struct timeval *val)
{
	i_assert(val->tv_usec < 1000000);
	tv->tv_sec += val->tv_sec;
	tv->tv_usec += val->tv_usec;
	if (tv->tv_usec >= 1000000) {
		tv->tv_sec++;
		tv->tv_usec -= 1000000;
	}
}

static inline time_t timeval_round(struct timeval *tv)
{
	return (tv->tv_usec < 500000 ? tv->tv_sec : tv->tv_sec + 1);
}

/* Convert t to local time and return timestamp on that day at 00:00:00. */
time_t time_to_local_day_start(time_t t);

/* Wrappers to strftime() */
const char *t_strftime(const char *fmt, const struct tm *tm) ATTR_STRFTIME(1);
const char *t_strflocaltime(const char *fmt, time_t t) ATTR_STRFTIME(1);
const char *t_strfgmtime(const char *fmt, time_t t) ATTR_STRFTIME(1);

/* Parse string as <unix timestamp>[.<usecs>] into timeval. <usecs> must not
   have higher precision time, i.e. a maximum of 6 digits is allowed. Note that
   ".1" is handled as ".1000000" so the string should have been written using
   "%06u" printf format. */
int str_to_timeval(const char *str, struct timeval *tv_r)
	ATTR_WARN_UNUSED_RESULT;

#endif

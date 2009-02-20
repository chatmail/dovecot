#include "lib.h"
#include "map.h"

#include <unistd.h>

static ssize_t read_full_n(int fd, void *data, size_t size)
{
	ssize_t ret, all_ret = 0;

	while (size > 0) {
		ret = read(fd, data, size);
		if (ret <= 0)
			return ret;

		data = PTR_OFFSET(data, ret);
		all_ret += ret;
		size -= ret;
	}

	return all_ret;
}

void map_refresh(int fd, int onceonly ATTR_UNUSED, const char **base,
		 unsigned long *len, unsigned long newlen,
		 const char *name, const char *mboxname ATTR_UNUSED)
{
	ssize_t ret;
	void *p;

	if (newlen == 0) {
		/* the file is a broken zero-byte file */
		*len = 0;
		return;
	}

	*base = p = i_malloc(newlen);
	*len = newlen;

	ret = read_full_n(fd, p, newlen);
	if (ret < 0) {
		i_error("read_full_n(%s) failed: %m", name);
		ret = 0;
	}

	*len = ret;
}

void map_free(const char **base, unsigned long *len ATTR_UNUSED)
{
	char *x = (char *) *base;

	i_free(x);
	*base = NULL;
}


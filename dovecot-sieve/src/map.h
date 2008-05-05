#ifndef __MAP_H
#define __MAP_H

extern void map_refresh(int fd, int onceonly, const char **base,
			unsigned long *len, unsigned long newlen,
			const char *name, const char *mboxname);

extern void map_free(const char **base, unsigned long *len);

#endif

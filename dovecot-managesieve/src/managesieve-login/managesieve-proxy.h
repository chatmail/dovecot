#ifndef __MANAGESIEVE_PROXY_H
#define __MANAGESIEVE_PROXY_H

#include "login-proxy.h"

int managesieve_proxy_new(struct managesieve_client *client, const char *host,
		   unsigned int port, const char *user, const char *password);

#endif

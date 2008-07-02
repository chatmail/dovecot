#ifndef __CLIENT_AUTHENTICATE_H
#define __CLIENT_AUTHENTICATE_H

const char *client_authenticate_get_capabilities(bool secured);

int cmd_login(struct managesieve_client *client, struct managesieve_arg *args);
int cmd_authenticate(struct managesieve_client *client, struct managesieve_arg *args);

#endif

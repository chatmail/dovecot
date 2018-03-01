#ifndef AUTH_WORKER_CLIENT_H
#define AUTH_WORKER_CLIENT_H

#define AUTH_WORKER_PROTOCOL_MAJOR_VERSION 1
#define AUTH_WORKER_PROTOCOL_MINOR_VERSION 0
#define AUTH_WORKER_MAX_LINE_LENGTH 8192

extern struct auth_worker_client *auth_worker_client;

struct auth_worker_client *auth_worker_client_create(struct auth *auth, int fd);
bool auth_worker_auth_request_new(struct auth_worker_client *client, unsigned int id,
				  const char *const *args, struct auth_request **request_r);
void auth_worker_client_destroy(struct auth_worker_client **client);
void auth_worker_client_unref(struct auth_worker_client **client);

void auth_worker_client_send_error(void);
void auth_worker_client_send_success(void);
void auth_worker_client_send_shutdown(void);

#endif

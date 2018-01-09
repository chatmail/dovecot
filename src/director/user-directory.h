#ifndef USER_DIRECTORY_H
#define USER_DIRECTORY_H

#define USER_IS_BEING_KILLED(user) \
	((user)->kill_ctx != NULL)

struct user {
	/* Approximately sorted by time (except during handshaking).
	   The sorting order may be constantly wrong a few seconds here and
	   there. */
	struct user *prev, *next;

	/* first 32 bits of MD5(username). collisions are quite unlikely, but
	   even if they happen it doesn't matter - the users are just
	   redirected to same server */
	unsigned int username_hash;
	unsigned int timestamp;

	struct mail_host *host;

	/* If non-NULL, don't allow new connections until all
	   directors have killed the user's connections. */
	struct director_kill_context *kill_ctx;

	/* TRUE, if the user's timestamp was close to being expired and we're
	   now doing a ring-wide sync for this user to make sure we don't
	   assign conflicting hosts to it */
	bool weak:1;
};

typedef void user_free_hook_t(struct user *);

/* Create a new directory. Users are dropped if their time gets older
   than timeout_secs. */
struct user_directory *
user_directory_init(unsigned int timeout_secs,
		    user_free_hook_t *user_free_hook);
void user_directory_deinit(struct user_directory **dir);

/* Returns the number of users currently in directory. */
unsigned int user_directory_count(struct user_directory *dir);
/* Look up username from directory. Returns NULL if not found. */
struct user *user_directory_lookup(struct user_directory *dir,
				   unsigned int username_hash);
/* Add a user to directory and return it. */
struct user *
user_directory_add(struct user_directory *dir, unsigned int username_hash,
		   struct mail_host *host, time_t timestamp);
/* Refresh user's timestamp */
void user_directory_refresh(struct user_directory *dir, struct user *user);

/* Remove all users that have pointers to given host */
void user_directory_remove_host(struct user_directory *dir,
				struct mail_host *host);
/* Sort users based on the timestamp. This is called only after updating
   timestamps based on remote director's user list after handshake. */
void user_directory_sort(struct user_directory *dir);

bool user_directory_user_is_recently_updated(struct user_directory *dir,
					     struct user *user);
bool user_directory_user_is_near_expiring(struct user_directory *dir,
					  struct user *user);

/* Iterate through users in the directory. It's safe to modify user directory
   while iterators are running. The removed users will just be skipped over.
   Users that are refreshed (= moved to end of list) may be processed twice.

   Using iter_until_current_tail=TRUE causes the iterator to not iterate
   through any users that were added/refreshed since the iteration began.
   Note that this may skip some users entirely. */
struct user_directory_iter *
user_directory_iter_init(struct user_directory *dir,
			 bool iter_until_current_tail);
struct user *user_directory_iter_next(struct user_directory_iter *iter);
void user_directory_iter_deinit(struct user_directory_iter **iter);

#endif

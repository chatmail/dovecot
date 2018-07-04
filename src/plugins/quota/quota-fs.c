/* Copyright (c) 2005-2018 Dovecot authors, see the included COPYING file */

/* Only for reporting filesystem quota */

#include "lib.h"
#include "array.h"
#include "str.h"
#include "hostpid.h"
#include "mountpoint.h"
#include "quota-private.h"
#include "quota-fs.h"

#ifdef HAVE_FS_QUOTA

#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#ifdef HAVE_LINUX_DQBLK_XFS_H
#  include <linux/dqblk_xfs.h>
#  define HAVE_XFS_QUOTA
#elif defined (HAVE_XFS_XQM_H)
#  include <xfs/xqm.h> /* CentOS 4.x at least uses this */
#  define HAVE_XFS_QUOTA
#endif

#ifdef HAVE_RQUOTA
#  include "rquota.h"
#  define RQUOTA_GETQUOTA_TIMEOUT_SECS 10
#endif

#ifndef DEV_BSIZE
#  ifdef DQBSIZE
#    define DEV_BSIZE DQBSIZE /* AIX */
#  else
#    define DEV_BSIZE 512
#  endif
#endif

#ifdef HAVE_STRUCT_DQBLK_CURSPACE
#  define dqb_curblocks dqb_curspace
#endif

/* Very old sys/quota.h doesn't define _LINUX_QUOTA_VERSION at all, which means
   it supports only v1 quota. However, new sys/quota.h (glibc 2.25) removes
   support for v1 entirely and again it doesn't define it. I guess we can just
   assume v2 now, and if someone still wants v1 support they can add
   -D_LINUX_QUOTA_VERSION=1 to CFLAGS. */
#ifndef _LINUX_QUOTA_VERSION
#  define _LINUX_QUOTA_VERSION 2
#endif

#define mount_type_is_nfs(mount) \
	(strcmp((mount)->type, "nfs") == 0 || \
	 strcmp((mount)->type, "nfs4") == 0)

struct fs_quota_mountpoint {
	int refcount;

	char *mount_path;
	char *device_path;
	char *type;
	unsigned int block_size;

#ifdef FS_QUOTA_SOLARIS
	int fd;
	char *path;
#endif
};

struct fs_quota_root {
	struct quota_root root;
	char *storage_mount_path;

	uid_t uid;
	gid_t gid;
	struct fs_quota_mountpoint *mount;

	bool inode_per_mail:1;
	bool user_disabled:1;
	bool group_disabled:1;
#ifdef FS_QUOTA_NETBSD
	struct quotahandle *qh;
#endif
};

extern struct quota_backend quota_backend_fs;

static struct quota_root *fs_quota_alloc(void)
{
	struct fs_quota_root *root;

	root = i_new(struct fs_quota_root, 1);
	root->uid = geteuid();
	root->gid = getegid();

	return &root->root;
}

static void handle_user_param(struct quota_root *_root, const char *param_value ATTR_UNUSED)
{
	((struct fs_quota_root *)_root)->group_disabled = TRUE;
}

static void handle_group_param(struct quota_root *_root, const char *param_value ATTR_UNUSED)
{
	((struct fs_quota_root *)_root)->user_disabled = TRUE;
}

static void handle_inode_param(struct quota_root *_root, const char *param_value ATTR_UNUSED)
{
	((struct fs_quota_root *)_root)->inode_per_mail = TRUE;
}

static void handle_mount_param(struct quota_root *_root, const char *param_value)
{
	struct fs_quota_root *root = (struct fs_quota_root *)_root;
	i_free(root->storage_mount_path);
	root->storage_mount_path = i_strdup(param_value);
}

static int fs_quota_init(struct quota_root *_root, const char *args,
			 const char **error_r)
{
	const struct quota_param_parser fs_params[] = {
		{.param_name = "user", .param_handler = handle_user_param},
		{.param_name = "group", .param_handler = handle_group_param},
		{.param_name = "mount=", .param_handler = handle_mount_param},
		{.param_name = "inode_per_mail", .param_handler = handle_inode_param},
		quota_param_hidden, quota_param_noenforcing, quota_param_ns,
		{.param_name = NULL}
	};

	if (quota_parse_parameters(_root, &args, error_r, fs_params, TRUE) < 0)
		return -1;
	_root->auto_updating = TRUE;
	return 0;
}

static void fs_quota_mountpoint_free(struct fs_quota_mountpoint *mount)
{
	if (--mount->refcount > 0)
		return;

#ifdef FS_QUOTA_SOLARIS
	i_close_fd_path(&mount->fd, mount->path);
	i_free(mount->path);
#endif

	i_free(mount->device_path);
	i_free(mount->mount_path);
	i_free(mount->type);
	i_free(mount);
}

static void fs_quota_deinit(struct quota_root *_root)
{
	struct fs_quota_root *root = (struct fs_quota_root *)_root;

	if (root->mount != NULL)
		fs_quota_mountpoint_free(root->mount);
	i_free(root->storage_mount_path);
	i_free(root);
}

static struct fs_quota_mountpoint *fs_quota_mountpoint_get(const char *dir)
{
	struct fs_quota_mountpoint *mount;
	struct mountpoint point;
	int ret;

	ret = mountpoint_get(dir, default_pool, &point);
	if (ret <= 0)
		return NULL;

	mount = i_new(struct fs_quota_mountpoint, 1);
	mount->refcount = 1;
	mount->device_path = point.device_path;
	mount->mount_path = point.mount_path;
	mount->type = point.type;
	mount->block_size = point.block_size;
#ifdef FS_QUOTA_SOLARIS
	mount->fd = -1;
#endif

	if (mount_type_is_nfs(mount)) {
		if (strchr(mount->device_path, ':') == NULL) {
			i_error("quota-fs: %s is not a valid NFS device path",
				mount->device_path);
			fs_quota_mountpoint_free(mount);
			return NULL;
		}
	}
	return mount;
}

#define QUOTA_ROOT_MATCH(root, mount) \
	((root)->root.backend.name == quota_backend_fs.name && \
	 ((root)->storage_mount_path == NULL || \
	  strcmp((root)->storage_mount_path, (mount)->mount_path) == 0))

static struct fs_quota_root *
fs_quota_root_find_mountpoint(struct quota *quota,
			      const struct fs_quota_mountpoint *mount)
{
	struct quota_root *const *roots;
	struct fs_quota_root *empty = NULL;
	unsigned int i, count;

	roots = array_get(&quota->roots, &count);
	for (i = 0; i < count; i++) {
		struct fs_quota_root *root = (struct fs_quota_root *)roots[i];
		if (QUOTA_ROOT_MATCH(root, mount)) {
			if (root->mount == NULL)
				empty = root;
			else if (strcmp(root->mount->mount_path,
					mount->mount_path) == 0)
				return root;
		}
	}
	return empty;
}

static void
fs_quota_mount_init(struct fs_quota_root *root,
		    struct fs_quota_mountpoint *mount, const char *dir)
{
	struct quota_root *const *roots;
	unsigned int i, count;

#ifdef FS_QUOTA_SOLARIS
#ifdef HAVE_RQUOTA
	if (mount_type_is_nfs(mount)) {
		/* using rquota for this mount */
	} else
#endif
	if (mount->path == NULL) {
		mount->path = i_strconcat(mount->mount_path, "/quotas", NULL);
		mount->fd = open(mount->path, O_RDONLY);
		if (mount->fd == -1 && errno != ENOENT)
			i_error("open(%s) failed: %m", mount->path);
	}
#endif
	root->mount = mount;

	if (root->root.quota->set->debug) {
		i_debug("fs quota add mailbox dir = %s", dir);
		i_debug("fs quota block device = %s", mount->device_path);
		i_debug("fs quota mount point = %s", mount->mount_path);
		i_debug("fs quota mount type = %s", mount->type);
	}

	/* if there are more unused quota roots, copy this mount to them */
	roots = array_get(&root->root.quota->roots, &count);
	for (i = 0; i < count; i++) {
		root = (struct fs_quota_root *)roots[i];
		if (QUOTA_ROOT_MATCH(root, mount) && root->mount == NULL) {
			mount->refcount++;
			root->mount = mount;
		}
	}
}

static void fs_quota_add_missing_mounts(struct quota *quota)
{
	struct fs_quota_mountpoint *mount;
	struct quota_root *const *roots;
	unsigned int i, count;

	roots = array_get(&quota->roots, &count);
	for (i = 0; i < count; i++) {
		struct fs_quota_root *root = (struct fs_quota_root *)roots[i];

		if (root->root.backend.name != quota_backend_fs.name ||
		    root->storage_mount_path == NULL || root->mount != NULL)
			continue;

		mount = fs_quota_mountpoint_get(root->storage_mount_path);
		if (mount != NULL) {
			fs_quota_mount_init(root, mount,
					    root->storage_mount_path);
		}
	}
}

static void fs_quota_namespace_added(struct quota *quota,
				     struct mail_namespace *ns)
{
	struct fs_quota_mountpoint *mount;
	struct fs_quota_root *root;
	const char *dir;

	if (!mailbox_list_get_root_path(ns->list, MAILBOX_LIST_PATH_TYPE_MAILBOX,
					&dir))
		mount = NULL;
	else
		mount = fs_quota_mountpoint_get(dir);
	if (mount != NULL) {
		root = fs_quota_root_find_mountpoint(quota, mount);
		if (root != NULL && root->mount == NULL)
			fs_quota_mount_init(root, mount, dir);
		else
			fs_quota_mountpoint_free(mount);
	}

	/* we would actually want to do this only once after all quota roots
	   are created, but there's no way to do this right now */
	fs_quota_add_missing_mounts(quota);
}

static const char *const *
fs_quota_root_get_resources(struct quota_root *_root)
{
	struct fs_quota_root *root = (struct fs_quota_root *)_root;
	static const char *resources_kb[] = {
		QUOTA_NAME_STORAGE_KILOBYTES,
		NULL
	};
	static const char *resources_kb_messages[] = {
		QUOTA_NAME_STORAGE_KILOBYTES,
		QUOTA_NAME_MESSAGES,
		NULL
	};

	return root->inode_per_mail ? resources_kb_messages : resources_kb;
}

#if defined(FS_QUOTA_LINUX) || defined(FS_QUOTA_BSDAIX) || \
    defined(FS_QUOTA_NETBSD) || defined(HAVE_RQUOTA)
static void fs_quota_root_disable(struct fs_quota_root *root, bool group)
{
	if (group)
		root->group_disabled = TRUE;
	else
		root->user_disabled = TRUE;
}
#endif

#ifdef HAVE_RQUOTA
static void
rquota_get_result(const rquota *rq,
		  uint64_t *bytes_value_r, uint64_t *bytes_limit_r,
		  uint64_t *count_value_r, uint64_t *count_limit_r)
{
	/* use soft limits if they exist, fallback to hard limits */

	/* convert the results from blocks to bytes */
	*bytes_value_r = (uint64_t)rq->rq_curblocks *
		(uint64_t)rq->rq_bsize;
	if (rq->rq_bsoftlimit != 0) {
		*bytes_limit_r = (uint64_t)rq->rq_bsoftlimit *
			(uint64_t)rq->rq_bsize;
	} else {
		*bytes_limit_r = (uint64_t)rq->rq_bhardlimit *
			(uint64_t)rq->rq_bsize;
	}

	*count_value_r = rq->rq_curfiles;
	if (rq->rq_fsoftlimit != 0)
		*count_limit_r = rq->rq_fsoftlimit;
	else
		*count_limit_r = rq->rq_fhardlimit;
}

static int
do_rquota_user(struct fs_quota_root *root,
	       uint64_t *bytes_value_r, uint64_t *bytes_limit_r,
	       uint64_t *count_value_r, uint64_t *count_limit_r,
	       const char **error_r)
{
	struct getquota_rslt result;
	struct getquota_args args;
	struct timeval timeout;
	enum clnt_stat call_status;
	CLIENT *cl;
	struct fs_quota_mountpoint *mount = root->mount;
	const char *host;
	char *path;

	path = strchr(mount->device_path, ':');
	i_assert(path != NULL);

	host = t_strdup_until(mount->device_path, path);
	path++;

	/* For NFSv4, we send the filesystem path without initial /. Server
	   prepends proper NFS pseudoroot automatically and uses this for
	   detection of NFSv4 mounts. */
	if (strcmp(root->mount->type, "nfs4") == 0) {
		while (*path == '/')
			path++;
	}

	if (root->root.quota->set->debug) {
		i_debug("quota-fs: host=%s, path=%s, uid=%s",
			host, path, dec2str(root->uid));
	}

	/* clnt_create() polls for a while to establish a connection */
	cl = clnt_create(host, RQUOTAPROG, RQUOTAVERS, "udp");
	if (cl == NULL) {
		*error_r = t_strdup_printf(
			"could not contact RPC service on %s", host);
		return -1;
	}

	/* Establish some RPC credentials */
	auth_destroy(cl->cl_auth);
	cl->cl_auth = authunix_create_default();

	/* make the rquota call on the remote host */
	args.gqa_pathp = path;
	args.gqa_uid = root->uid;

	timeout.tv_sec = RQUOTA_GETQUOTA_TIMEOUT_SECS;
	timeout.tv_usec = 0;
	call_status = clnt_call(cl, RQUOTAPROC_GETQUOTA,
				(xdrproc_t)xdr_getquota_args, (char *)&args,
				(xdrproc_t)xdr_getquota_rslt, (char *)&result,
				timeout);

	/* the result has been deserialized, let the client go */
	auth_destroy(cl->cl_auth);
	clnt_destroy(cl);

	if (call_status != RPC_SUCCESS) {
		const char *rpc_error_msg = clnt_sperrno(call_status);

		*error_r = t_strdup_printf(
			"remote rquota call failed: %s",
			rpc_error_msg);
		return -1;
	}

	switch (result.status) {
	case Q_OK: {
		rquota_get_result(&result.getquota_rslt_u.gqr_rquota,
				  bytes_value_r, bytes_limit_r,
				  count_value_r, count_limit_r);
		if (root->root.quota->set->debug) {
			i_debug("quota-fs: uid=%s, bytes=%"PRIu64"/%"PRIu64" "
				"files=%"PRIu64"/%"PRIu64,
				dec2str(root->uid),
				*bytes_value_r, *bytes_limit_r,
				*count_value_r, *count_limit_r);
		}
		return 1;
	}
	case Q_NOQUOTA:
		if (root->root.quota->set->debug) {
			i_debug("quota-fs: uid=%s, limit=unlimited",
				dec2str(root->uid));
		}
		fs_quota_root_disable(root, FALSE);
		return 0;
	case Q_EPERM:
		*error_r = "permission denied to rquota service";
		return -1;
	default:
		*error_r = t_strdup_printf(
			"unrecognized status code (%d) from rquota service",
			result.status);
		return -1;
	}
}

static int
do_rquota_group(struct fs_quota_root *root ATTR_UNUSED,
		uint64_t *bytes_value_r ATTR_UNUSED,
		uint64_t *bytes_limit_r ATTR_UNUSED,
		uint64_t *count_value_r ATTR_UNUSED,
		uint64_t *count_limit_r ATTR_UNUSED,
		const char **error_r)
{
#if defined(EXT_RQUOTAVERS) && defined(GRPQUOTA)
	struct getquota_rslt result;
	ext_getquota_args args;
	struct timeval timeout;
	enum clnt_stat call_status;
	CLIENT *cl;
	struct fs_quota_mountpoint *mount = root->mount;
	const char *host;
	char *path;

	path = strchr(mount->device_path, ':');
	i_assert(path != NULL);

	host = t_strdup_until(mount->device_path, path);
	path++;

	if (root->root.quota->set->debug) {
		i_debug("quota-fs: host=%s, path=%s, gid=%s",
			host, path, dec2str(root->gid));
	}

	/* clnt_create() polls for a while to establish a connection */
	cl = clnt_create(host, RQUOTAPROG, EXT_RQUOTAVERS, "udp");
	if (cl == NULL) {
		*error_r = t_strdup_printf(
			"could not contact RPC service on %s (group)", host);
		return -1;
	}

	/* Establish some RPC credentials */
	auth_destroy(cl->cl_auth);
	cl->cl_auth = authunix_create_default();

	/* make the rquota call on the remote host */
	args.gqa_pathp = path;
	args.gqa_id = root->gid;
	args.gqa_type = GRPQUOTA;
	timeout.tv_sec = RQUOTA_GETQUOTA_TIMEOUT_SECS;
	timeout.tv_usec = 0;

	call_status = clnt_call(cl, RQUOTAPROC_GETQUOTA,
				(xdrproc_t)xdr_ext_getquota_args, (char *)&args,
				(xdrproc_t)xdr_getquota_rslt, (char *)&result,
				timeout);

	/* the result has been deserialized, let the client go */
	auth_destroy(cl->cl_auth);
	clnt_destroy(cl);

	if (call_status != RPC_SUCCESS) {
		const char *rpc_error_msg = clnt_sperrno(call_status);

		*error_r = t_strdup_printf(
			"remote ext rquota call failed: %s", rpc_error_msg);
		return -1;
	}

	switch (result.status) {
	case Q_OK: {
		rquota_get_result(&result.getquota_rslt_u.gqr_rquota,
				  bytes_value_r, bytes_limit_r,
				  count_value_r, count_limit_r);
		if (root->root.quota->set->debug) {
			i_debug("quota-fs: gid=%s, bytes=%"PRIu64"/%"PRIu64" "
				"files=%"PRIu64"/%"PRIu64,
				dec2str(root->gid),
				*bytes_value_r, *bytes_limit_r,
				*count_value_r, *count_limit_r);
		}
		return 1;
	}
	case Q_NOQUOTA:
		if (root->root.quota->set->debug) {
			i_debug("quota-fs: gid=%s, limit=unlimited",
				dec2str(root->gid));
		}
		fs_quota_root_disable(root, TRUE);
		return 0;
	case Q_EPERM:
		*error_r = "permission denied to ext rquota service";
		return -1;
	default:
		*error_r = t_strdup_printf(
			"unrecognized status code (%d) from ext rquota service",
			result.status);
		return -1;
	}
#else
	*error_r = "rquota not compiled with group support";
	return -1;
#endif
}
#endif

#ifdef FS_QUOTA_LINUX
static int
fs_quota_get_linux(struct fs_quota_root *root, bool group,
		   uint64_t *bytes_value_r, uint64_t *bytes_limit_r,
		   uint64_t *count_value_r, uint64_t *count_limit_r,
		   const char **error_r)
{
	struct dqblk dqblk;
	int type, id;

	type = group ? GRPQUOTA : USRQUOTA;
	id = group ? root->gid : root->uid;

#ifdef HAVE_XFS_QUOTA
	if (strcmp(root->mount->type, "xfs") == 0) {
		struct fs_disk_quota xdqblk;

		if (quotactl(QCMD(Q_XGETQUOTA, type),
			     root->mount->device_path,
			     id, (caddr_t)&xdqblk) < 0) {
			if (errno == ESRCH) {
				fs_quota_root_disable(root, group);
				return 0;
			}
			*error_r = t_strdup_printf(
				"errno=%d, quotactl(Q_XGETQUOTA, %s) failed: %m",
				errno, root->mount->device_path);
			return -1;
		}

		/* values always returned in 512 byte blocks */
		*bytes_value_r = xdqblk.d_bcount * 512ULL;
		*bytes_limit_r = xdqblk.d_blk_softlimit * 512ULL;
		if (*bytes_limit_r == 0) {
			*bytes_limit_r = xdqblk.d_blk_hardlimit * 512ULL;
		}
		*count_value_r = xdqblk.d_icount;
		*count_limit_r = xdqblk.d_ino_softlimit;
		if (*count_limit_r == 0) {
			*count_limit_r = xdqblk.d_ino_hardlimit;
		}
	} else
#endif
	{
		/* ext2, ext3 */
		if (quotactl(QCMD(Q_GETQUOTA, type),
			     root->mount->device_path,
			     id, (caddr_t)&dqblk) < 0) {
			if (errno == ESRCH) {
				fs_quota_root_disable(root, group);
				return 0;
			}
			*error_r = t_strdup_printf(
				"quotactl(Q_GETQUOTA, %s) failed: %m",
				root->mount->device_path);
			if (errno == EINVAL) {
				*error_r = t_strdup_printf("%s, "
					"Dovecot was compiled with Linux quota "
					"v%d support, try changing it "
					"(CPPFLAGS=-D_LINUX_QUOTA_VERSION=%d configure)",
					*error_r,
					_LINUX_QUOTA_VERSION,
					_LINUX_QUOTA_VERSION == 1 ? 2 : 1);
			}
			return -1;
		}

#if _LINUX_QUOTA_VERSION == 1
		*bytes_value_r = dqblk.dqb_curblocks * 1024ULL;
#else
		*bytes_value_r = dqblk.dqb_curblocks;
#endif
		*bytes_limit_r = dqblk.dqb_bsoftlimit * 1024ULL;
		if (*bytes_limit_r == 0) {
			*bytes_limit_r = dqblk.dqb_bhardlimit * 1024ULL;
		}
		*count_value_r = dqblk.dqb_curinodes;
		*count_limit_r = dqblk.dqb_isoftlimit;
		if (*count_limit_r == 0) {
			*count_limit_r = dqblk.dqb_ihardlimit;
		}
	}
	return 1;
}
#endif

#ifdef FS_QUOTA_BSDAIX
static int
fs_quota_get_bsdaix(struct fs_quota_root *root, bool group,
		    uint64_t *bytes_value_r, uint64_t *bytes_limit_r,
		    uint64_t *count_value_r, uint64_t *count_limit_r,
		    const char **error_r)
{
	struct dqblk dqblk;
	int type, id;

	type = group ? GRPQUOTA : USRQUOTA;
	id = group ? root->gid : root->uid;

	if (quotactl(root->mount->mount_path, QCMD(Q_GETQUOTA, type),
		     id, (void *)&dqblk) < 0) {
		if (errno == ESRCH) {
			fs_quota_root_disable(root, group);
			return 0;
		}
		*error_r = t_strdup_printf(
			"quotactl(Q_GETQUOTA, %s) failed: %m",
			root->mount->mount_path);
		return -1;
	}
	*bytes_value_r = (uint64_t)dqblk.dqb_curblocks * DEV_BSIZE;
	*bytes_limit_r = (uint64_t)dqblk.dqb_bsoftlimit * DEV_BSIZE;
	if (*bytes_limit_r == 0) {
		*bytes_limit_r = (uint64_t)dqblk.dqb_bhardlimit * DEV_BSIZE;
	}
	*count_value_r = dqblk.dqb_curinodes;
	*count_limit_r = dqblk.dqb_isoftlimit;
	if (*count_limit_r == 0) {
		*count_limit_r = dqblk.dqb_ihardlimit;
	}
	return 1;
}
#endif

#ifdef FS_QUOTA_NETBSD
static int
fs_quota_get_netbsd(struct fs_quota_root *root, bool group,
		    uint64_t *bytes_value_r, uint64_t *bytes_limit_r,
		    uint64_t *count_value_r, uint64_t *count_limit_r,
		    const char **error_r)
{
	struct quotakey qk;
	struct quotaval qv;
	struct quotahandle *qh;
	int ret;

	if ((qh = quota_open(root->mount->mount_path)) == NULL) {
		*error_r = t_strdup_printf("cannot open quota for %s: %m",
					   root->mount->mount_path);
		fs_quota_root_disable(root, group);
		return 0;
	}

	qk.qk_idtype = group ? QUOTA_IDTYPE_GROUP : QUOTA_IDTYPE_USER;
	qk.qk_id = group ? root->gid : root->uid;

	for (int i = 0; i < 2; i++) {
		qk.qk_objtype = i == 0 ? QUOTA_OBJTYPE_BLOCKS : QUOTA_OBJTYPE_FILES;

		if (quota_get(qh, &qk, &qv) != 0) {
			if (errno == ESRCH) {
				fs_quota_root_disable(root, group);
				return 0;
			}
			*error_r = t_strdup_printf(
				"quotactl(Q_GETQUOTA, %s) failed: %m",
				root->mount->mount_path);
			ret = -1;
			break;
		}
		if (i == 0) {
			*bytes_value_r = qv.qv_usage * DEV_BSIZE;
			*bytes_limit_r = qv.qv_softlimit * DEV_BSIZE;
		} else {
			*count_value_r = qv.qv_usage;
			*count_limit_r = qv.qv_softlimit;
		}
		ret = 1;
	}
	quota_close(qh);
	return ret;
}
#endif

#ifdef FS_QUOTA_HPUX
static int
fs_quota_get_hpux(struct fs_quota_root *root,
		  uint64_t *bytes_value_r, uint64_t *bytes_limit_r,
		  uint64_t *count_value_r, uint64_t *count_limit_r,
		  const char **error_r)
{
	struct dqblk dqblk;

	if (quotactl(Q_GETQUOTA, root->mount->device_path,
		     root->uid, &dqblk) < 0) {
		if (errno == ESRCH) {
			root->user_disabled = TRUE;
			return 0;
		}
		*error_r = t_strdup_printf(
			"quotactl(Q_GETQUOTA, %s) failed: %m",
			root->mount->device_path);
		return -1;
	}

	*bytes_value_r = (uint64_t)dqblk.dqb_curblocks *
		root->mount->block_size;
	*bytes_limit_r = (uint64_t)dqblk.dqb_bsoftlimit *
		root->mount->block_size;
	if (*bytes_limit_r == 0) {
		*bytes_limit_r = (uint64_t)dqblk.dqb_bhardlimit *
			root->mount->block_size;
	}
	*count_value_r = dqblk.dqb_curfiles;
	*count_limit_r = dqblk.dqb_fsoftlimit;
	if (*count_limit_r == 0) {
		*count_limit_r = dqblk.dqb_fhardlimit;
	}
	return 1;
}
#endif

#ifdef FS_QUOTA_SOLARIS
static int
fs_quota_get_solaris(struct fs_quota_root *root,
		     uint64_t *bytes_value_r, uint64_t *bytes_limit_r,
		     uint64_t *count_value_r, uint64_t *count_limit_r,
		     const char **error_r)
{
	struct dqblk dqblk;
	struct quotctl ctl;

	if (root->mount->fd == -1)
		return 0;

	ctl.op = Q_GETQUOTA;
	ctl.uid = root->uid;
	ctl.addr = (caddr_t)&dqblk;
	if (ioctl(root->mount->fd, Q_QUOTACTL, &ctl) < 0) {
		*error_r = t_strdup_printf(
			"ioctl(%s, Q_QUOTACTL) failed: %m",
			root->mount->path);
		return -1;
	}
	*bytes_value_r = (uint64_t)dqblk.dqb_curblocks * DEV_BSIZE;
	*bytes_limit_r = (uint64_t)dqblk.dqb_bsoftlimit * DEV_BSIZE;
	if (*bytes_limit_r == 0) {
		*bytes_limit_r = (uint64_t)dqblk.dqb_bhardlimit * DEV_BSIZE;
	}
	*count_value_r = dqblk.dqb_curfiles;
	*count_limit_r = dqblk.dqb_fsoftlimit;
	if (*count_limit_r == 0) {
		*count_limit_r = dqblk.dqb_fhardlimit;
	}
	return 1;
}
#endif

static int
fs_quota_get_resources(struct fs_quota_root *root, bool group,
		       uint64_t *bytes_value_r, uint64_t *bytes_limit_r,
		       uint64_t *count_value_r, uint64_t *count_limit_r,
		       const char **error_r)
{
	if (group) {
		if (root->group_disabled)
			return 0;
	} else {
		if (root->user_disabled)
			return 0;
	}
#ifdef FS_QUOTA_LINUX
	return fs_quota_get_linux(root, group, bytes_value_r, bytes_limit_r,
				  count_value_r, count_limit_r, error_r);
#elif defined (FS_QUOTA_NETBSD)
	return fs_quota_get_netbsd(root, group, bytes_value_r, bytes_limit_r,
				   count_value_r, count_limit_r, error_r);
#elif defined (FS_QUOTA_BSDAIX)
	return fs_quota_get_bsdaix(root, group, bytes_value_r, bytes_limit_r,
				   count_value_r, count_limit_r, error_r);
#else
	if (group) {
		/* not supported */
		return 0;
	}
#ifdef FS_QUOTA_HPUX
	return fs_quota_get_hpux(root, bytes_value_r, bytes_limit_r,
				 count_value_r, count_limit_r, error_r);
#else
	return fs_quota_get_solaris(root, bytes_value_r, bytes_limit_r,
				    count_value_r, count_limit_r, error_r);
#endif
#endif
}

static bool fs_quota_match_box(struct quota_root *_root, struct mailbox *box)
{
	struct fs_quota_root *root = (struct fs_quota_root *)_root;
	struct stat mst, rst;
	const char *mailbox_path;
	bool match;

	if (root->storage_mount_path == NULL)
		return TRUE;

	if (mailbox_get_path_to(box, MAILBOX_LIST_PATH_TYPE_MAILBOX,
				&mailbox_path) <= 0)
		return FALSE;
	if (stat(mailbox_path, &mst) < 0) {
		if (errno != ENOENT)
			i_error("stat(%s) failed: %m", mailbox_path);
		return FALSE;
	}
	if (stat(root->storage_mount_path, &rst) < 0) {
		if (_root->quota->set->debug) {
			i_debug("stat(%s) failed: %m",
				root->storage_mount_path);
		}
		return FALSE;
	}
	match = CMP_DEV_T(mst.st_dev, rst.st_dev);
	if (_root->quota->set->debug) {
		i_debug("box=%s mount=%s match=%s", mailbox_path,
			root->storage_mount_path, match ? "yes" : "no");
	}
	return match;
}

static enum quota_get_result
fs_quota_get_resource(struct quota_root *_root, const char *name,
		      uint64_t *value_r, const char **error_r)
{
	struct fs_quota_root *root = (struct fs_quota_root *)_root;
	uint64_t bytes_value, count_value;
	uint64_t bytes_limit = 0, count_limit = 0;
	int ret;

	*value_r = 0;

	if (root->mount == NULL) {
		if (root->storage_mount_path != NULL)
			*error_r = t_strdup_printf(
				"Mount point unknown for path %s",
				root->storage_mount_path);
		else
			*error_r = "Mount point unknown";
		return QUOTA_GET_RESULT_INTERNAL_ERROR;
	}
	if (strcasecmp(name, QUOTA_NAME_STORAGE_BYTES) != 0 &&
	    strcasecmp(name, QUOTA_NAME_MESSAGES) != 0) {
		*error_r = QUOTA_UNKNOWN_RESOURCE_ERROR_STRING;
		return QUOTA_GET_RESULT_UNKNOWN_RESOURCE;
	}

#ifdef HAVE_RQUOTA
	if (mount_type_is_nfs(root->mount)) {
		ret = root->user_disabled ? 0 :
			do_rquota_user(root, &bytes_value, &bytes_limit,
				       &count_value, &count_limit, error_r);
		if (ret == 0 && !root->group_disabled)
			ret = do_rquota_group(root, &bytes_value,
					      &bytes_limit, &count_value,
					      &count_limit, error_r);
	} else
#endif
	{
		ret = fs_quota_get_resources(root, FALSE, &bytes_value,
					     &bytes_limit, &count_value,
					     &count_limit, error_r);
		if (ret == 0) {
			/* fallback to group quota */
			ret = fs_quota_get_resources(root, TRUE, &bytes_value,
						     &bytes_limit, &count_value,
						     &count_limit, error_r);
		}
	}
	if (ret < 0)
		return QUOTA_GET_RESULT_INTERNAL_ERROR;
	else if (ret == 0)
		return QUOTA_GET_RESULT_LIMITED;

	if (strcasecmp(name, QUOTA_NAME_STORAGE_BYTES) == 0)
		*value_r = bytes_value;
	else
		*value_r = count_value;
	if (_root->bytes_limit != (int64_t)bytes_limit ||
	    _root->count_limit != (int64_t)count_limit) {
		/* update limit */
		_root->bytes_limit = bytes_limit;
		_root->count_limit = count_limit;

		/* limits have changed, so we'll need to recalculate
		   relative quota rules */
		quota_root_recalculate_relative_rules(_root->set, bytes_limit, count_limit);
	}
	return QUOTA_GET_RESULT_LIMITED;
}

static int
fs_quota_update(struct quota_root *root ATTR_UNUSED,
		struct quota_transaction_context *ctx ATTR_UNUSED,
		const char **error_r ATTR_UNUSED)
{
	return 0;
}

struct quota_backend quota_backend_fs = {
	.name = "fs",

	.v = {
		.alloc = fs_quota_alloc,
		.init = fs_quota_init,
		.deinit = fs_quota_deinit,

		.namespace_added = fs_quota_namespace_added,

		.get_resources = fs_quota_root_get_resources,
		.get_resource = fs_quota_get_resource,
		.update = fs_quota_update,

		.match_box = fs_quota_match_box,
	}
};

#endif

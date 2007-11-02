/* config.h.  Generated from config.h.in by configure.  */
/* config.h.in.  Generated from configure.in by autoheader.  */

/* Define if you have buggy CMSG macros */
/* #undef BUGGY_CMSG_MACROS */

/* Built-in MySQL support */
#define BUILD_MYSQL 

/* Built-in PostgreSQL support */
#define BUILD_PGSQL 

/* Built-in SQLite support */
#define BUILD_SQLITE 

/* IMAP capabilities */
#define CAPABILITY_STRING "IMAP4rev1 SASL-IR SORT THREAD=REFERENCES MULTIAPPEND UNSELECT LITERAL+ IDLE CHILDREN NAMESPACE LOGIN-REFERRALS"

/* Define if _XPG6 macro is needed for crypt() */
#define CRYPT_USE_XPG6 

/* Build with extra debugging checks */
#define DEBUG 

/* Define if your dev_t is a structure instead of integer type */
/* #undef DEV_T_STRUCT */

/* Disable asserts */
/* #undef DISABLE_ASSERTS */

/* Define to 1 if you have the `backtrace_symbols' function. */
#define HAVE_BACKTRACE_SYMBOLS 1

/* Define if you have /dev/urandom */
#define HAVE_DEV_URANDOM 

/* Define if you have struct dirent->d_type */
#define HAVE_DIRENT_D_TYPE 

/* Define to 1 if you have the <dirent.h> header file. */
#define HAVE_DIRENT_H 1

/* Define to 1 if you have the `dirfd' function. */
#define HAVE_DIRFD 1

/* Define to 1 if you have the <dlfcn.h> header file. */
#define HAVE_DLFCN_H 1

/* Define to 1 if you have the <execinfo.h> header file. */
#define HAVE_EXECINFO_H 1

/* Define to 1 if you have the `fcntl' function. */
#define HAVE_FCNTL 1

/* Define if you have fdatasync() */
#define HAVE_FDATASYNC 

/* Define to 1 if you have the `flock' function. */
#define HAVE_FLOCK 1

/* Define if you have FreeBSD-compatible sendfile() */
/* #undef HAVE_FREEBSD_SENDFILE */

/* Define to 1 if you have the <gc/gc.h> header file. */
/* #undef HAVE_GC_GC_H */

/* Define to 1 if you have the <gc.h> header file. */
/* #undef HAVE_GC_H */

/* Define to 1 if you have the `getmntent' function. */
#define HAVE_GETMNTENT 1

/* Define to 1 if you have the `getpagesize' function. */
#define HAVE_GETPAGESIZE 1

/* Define to 1 if you have the `getrusage' function. */
#define HAVE_GETRUSAGE 1

/* Build with GNUTLS support */
/* #undef HAVE_GNUTLS */

/* Define to 1 if you have the <gnutls/gnutls.h> header file. */
/* #undef HAVE_GNUTLS_GNUTLS_H */

/* Build with GSSAPI support */
/* #undef HAVE_GSSAPI */

/* GSSAPI headers in gssapi/gssapi.h */
/* #undef HAVE_GSSAPI_GSSAPI_H */

/* GSSAPI headers in gssapi.h */
/* #undef HAVE_GSSAPI_H */

/* Define if you have the iconv() function. */
#define HAVE_ICONV 1

/* Define to 1 if you have the `inet_aton' function. */
#define HAVE_INET_ATON 1

/* Define to 1 if you have the <inttypes.h> header file. */
#define HAVE_INTTYPES_H 1

/* Build with IPv6 support */
#define HAVE_IPV6 

/* Define to 1 if you have the <jfs/quota.h> header file. */
/* #undef HAVE_JFS_QUOTA_H */

/* Define to 1 if you have the `kevent' function. */
/* #undef HAVE_KEVENT */

/* Define to 1 if you have the `kqueue' function. */
/* #undef HAVE_KQUEUE */

/* Define to 1 if you have the <libgen.h> header file. */
#define HAVE_LIBGEN_H 1

/* Define to 1 if you have the <linux/dqblk_xfs.h> header file. */
#define HAVE_LINUX_DQBLK_XFS_H 1

/* Define if you have Linux-compatible mremap() */
#define HAVE_LINUX_MREMAP 

/* Define if you have Linux-compatible sendfile() */
#define HAVE_LINUX_SENDFILE 

/* Define to 1 if you have the `lockf' function. */
#define HAVE_LOCKF 1

/* Define to 1 if you have the `madvise' function. */
#define HAVE_MADVISE 1

/* Define to 1 if you have the <memory.h> header file. */
#define HAVE_MEMORY_H 1

/* Define to 1 if you have the <mntent.h> header file. */
#define HAVE_MNTENT_H 1

/* Define if you have dynamic module support */
#define HAVE_MODULES 

/* Build with MySQL support */
#define HAVE_MYSQL 

/* Define if your MySQL library has SSL functions */
#define HAVE_MYSQL_SSL 

/* Define if your MySQL library supports setting cipher */
#define HAVE_MYSQL_SSL_CIPHER 

/* Build with OpenSSL support */
#define HAVE_OPENSSL 

/* Define to 1 if you have the <openssl/err.h> header file. */
/* #undef HAVE_OPENSSL_ERR_H */

/* Define if you have openssl/rand.h */
/* #undef HAVE_OPENSSL_RAND_H */

/* Define to 1 if you have the <openssl/ssl.h> header file. */
/* #undef HAVE_OPENSSL_SSL_H */

/* Define if you have pam/pam_appl.h */
/* #undef HAVE_PAM_PAM_APPL_H */

/* Define if you have pam_setcred() */
#define HAVE_PAM_SETCRED 

/* Build with PostgreSQL support */
#define HAVE_PGSQL 

/* Define if libpq has PQescapeStringConn function */
#define HAVE_PQESCAPE_STRING_CONN 

/* Define to 1 if you have the `pread' function. */
#define HAVE_PREAD 1

/* Define to 1 if you have the `quotactl' function. */
#define HAVE_QUOTACTL 1

/* Define if Q_QUOTACTL exists */
/* #undef HAVE_Q_QUOTACTL */

/* Define if you have RLIMIT_AS for setrlimit() */
#define HAVE_RLIMIT_AS 

/* Define if you have RLIMIT_NPROC for setrlimit() */
#define HAVE_RLIMIT_NPROC 

/* Define to 1 if you have the <sasl.h> header file. */
/* #undef HAVE_SASL_H */

/* Define to 1 if you have the <sasl/sasl.h> header file. */
#define HAVE_SASL_SASL_H 1

/* Define if you have security/pam_appl.h */
#define HAVE_SECURITY_PAM_APPL_H 

/* Define to 1 if you have the `setegid' function. */
#define HAVE_SETEGID 1

/* Define to 1 if you have the `seteuid' function. */
#define HAVE_SETEUID 1

/* Define to 1 if you have the `setpriority' function. */
#define HAVE_SETPRIORITY 1

/* Define to 1 if you have the `setproctitle' function. */
/* #undef HAVE_SETPROCTITLE */

/* Define to 1 if you have the `setresgid' function. */
#define HAVE_SETRESGID 1

/* Define to 1 if you have the `setreuid' function. */
#define HAVE_SETREUID 1

/* Define to 1 if you have the `setrlimit' function. */
#define HAVE_SETRLIMIT 1

/* Define to 1 if you have the `sigaction' function. */
#define HAVE_SIGACTION 1

/* Define to 'int' if you don't have socklen_t */
#define HAVE_SOCKLEN_T 

/* Define if you have Solaris-compatible sendfile() */
/* #undef HAVE_SOLARIS_SENDFILE */

/* Build with SQLite3 support */
#define HAVE_SQLITE 

/* Build with SSL/TLS support */
#define HAVE_SSL 

/* Define if you have statfs.f_mntfromname */
/* #undef HAVE_STATFS_MNTFROMNAME */

/* Define if you have statvfs.f_mntfromname */
/* #undef HAVE_STATVFS_MNTFROMNAME */

/* Define if you have tv_nsec fields in struct stat */
#define HAVE_STAT_TV_NSEC 

/* Define to 1 if you have the <stdint.h> header file. */
#define HAVE_STDINT_H 1

/* Define to 1 if you have the <stdlib.h> header file. */
#define HAVE_STDLIB_H 1

/* Define to 1 if you have the `strcasecmp' function. */
#define HAVE_STRCASECMP 1

/* Define to 1 if you have the `stricmp' function. */
/* #undef HAVE_STRICMP */

/* Define to 1 if you have the <strings.h> header file. */
#define HAVE_STRINGS_H 1

/* Define to 1 if you have the <string.h> header file. */
#define HAVE_STRING_H 1

/* Define to 1 if you have the `strtoull' function. */
#define HAVE_STRTOULL 1

/* Define to 1 if you have the `strtouq' function. */
#define HAVE_STRTOUQ 1

/* Define if struct sqblk.dqb_curblocks exists */
/* #undef HAVE_STRUCT_DQBLK_CURBLOCKS */

/* Define if struct sqblk.dqb_curspace exists */
#define HAVE_STRUCT_DQBLK_CURSPACE 

/* Define if you have struct iovec */
#define HAVE_STRUCT_IOVEC 

/* Define to 1 if you have the <sys/event.h> header file. */
/* #undef HAVE_SYS_EVENT_H */

/* Define to 1 if you have the <sys/fs/ufs_quota.h> header file. */
/* #undef HAVE_SYS_FS_UFS_QUOTA_H */

/* Define to 1 if you have the <sys/mkdev.h> header file. */
/* #undef HAVE_SYS_MKDEV_H */

/* Define to 1 if you have the <sys/mnttab.h> header file. */
/* #undef HAVE_SYS_MNTTAB_H */

/* Define to 1 if you have the <sys/quota.h> header file. */
#define HAVE_SYS_QUOTA_H 1

/* Define to 1 if you have the <sys/resource.h> header file. */
#define HAVE_SYS_RESOURCE_H 1

/* Define to 1 if you have the <sys/select.h> header file. */
#define HAVE_SYS_SELECT_H 1

/* Define to 1 if you have the <sys/stat.h> header file. */
#define HAVE_SYS_STAT_H 1

/* Define to 1 if you have the <sys/sysmacros.h> header file. */
#define HAVE_SYS_SYSMACROS_H 1

/* Define to 1 if you have the <sys/time.h> header file. */
#define HAVE_SYS_TIME_H 1

/* Define to 1 if you have the <sys/types.h> header file. */
#define HAVE_SYS_TYPES_H 1

/* Define to 1 if you have the <sys/uio.h> header file. */
#define HAVE_SYS_UIO_H 1

/* Define if you have struct tm->tm_gmtoff */
#define HAVE_TM_GMTOFF 

/* Define to 1 if you have the <ucontext.h> header file. */
#define HAVE_UCONTEXT_H 1

/* Define to 1 if you have the <ufs/ufs/quota.h> header file. */
/* #undef HAVE_UFS_UFS_QUOTA_H */

/* Define if you have uintmax_t (C99 type) */
#define HAVE_UINTMAX_T 

/* Define if you have uint_fast32_t (C99 type) */
#define HAVE_UINT_FAST32_T 

/* Define to 1 if you have the <unistd.h> header file. */
#define HAVE_UNISTD_H 1

/* Define if you have a native uoff_t type */
/* #undef HAVE_UOFF_T */

/* Define to 1 if you have the `vsnprintf' function. */
#define HAVE_VSNPRINTF 1

/* Define to 1 if you have the `vsyslog' function. */
#define HAVE_VSYSLOG 1

/* Define to 1 if you have the `walkcontext' function. */
/* #undef HAVE_WALKCONTEXT */

/* Define to 1 if you have the `writev' function. */
#define HAVE_WRITEV 1

/* Define to 1 if you have the <xfs/xqm.h> header file. */
/* #undef HAVE_XFS_XQM_H */

/* Define to 1 if the system has the type `_Bool'. */
#define HAVE__BOOL 1

/* Define as const if the declaration of iconv() needs const. */
#define ICONV_CONST 

/* Implement I/O loop with Linux 2.6 epoll() */
/* #undef IOLOOP_EPOLL */

/* Implement I/O loop with BSD kqueue() */
/* #undef IOLOOP_KQUEUE */

/* Use Linux dnotify */
/* #undef IOLOOP_NOTIFY_DNOTIFY */

/* Use Linux inotify */
#define IOLOOP_NOTIFY_INOTIFY 

/* Use BSD kqueue directory changes notificaton */
/* #undef IOLOOP_NOTIFY_KQUEUE */

/* No special notify support */
/* #undef IOLOOP_NOTIFY_NONE */

/* Implement I/O loop with poll() */
#define IOLOOP_POLL 

/* Implement I/O loop with select() */
/* #undef IOLOOP_SELECT */

/* Define if you have ldap_initialize */
#define LDAP_HAVE_INITIALIZE 

/* Define if you have ldap_start_tls_s */
#define LDAP_HAVE_START_TLS_S 

/* Index file compatibility flags */
#define MAIL_INDEX_COMPAT_FLAGS 1

/* Required memory alignment */
#define MEM_ALIGN_SIZE 8

/* Define if shared mmaps don't get updated by write()s */
/* #undef MMAP_CONFLICTS_WRITE */

/* Maximum value of off_t */
#define OFF_T_MAX LONG_MAX

/* Name of package */
#define PACKAGE "dovecot"

/* Define to the address where bug reports for this package should be sent. */
#define PACKAGE_BUGREPORT "dovecot@dovecot.org"

/* Define to the full name of this package. */
#define PACKAGE_NAME "dovecot"

/* Define to the full name and version of this package. */
#define PACKAGE_STRING "dovecot 1.0.7"

/* Define to the one symbol short name of this package. */
#define PACKAGE_TARNAME "dovecot"

/* Define to the version of this package. */
#define PACKAGE_VERSION "1.0.7"

/* Build with BSD authentication support */
/* #undef PASSDB_BSDAUTH */

/* Build with checkpassword passdb support */
#define PASSDB_CHECKPASSWORD 

/* Build with LDAP support */
#define PASSDB_LDAP 

/* Build with PAM support */
#define PASSDB_PAM 

/* Build with passwd support */
#define PASSDB_PASSWD 

/* Build with passwd-file support */
#define PASSDB_PASSWD_FILE 

/* Build with shadow support */
#define PASSDB_SHADOW 

/* Build with Tru64 SIA support */
/* #undef PASSDB_SIA */

/* Build with SQL support */
#define PASSDB_SQL 

/* Build with vpopmail support */
/* #undef PASSDB_VPOPMAIL */

/* Define if pread/pwrite needs _XOPEN_SOURCE 500 */
#define PREAD_WRAPPERS 

/* printf() format for size_t */
#define PRIuSIZE_T "lu"

/* printf() format for uoff_t */
#define PRIuUOFF_T "lu"

/* The size of `int', as computed by sizeof. */
#define SIZEOF_INT 4

/* The size of `long', as computed by sizeof. */
#define SIZEOF_LONG 8

/* The size of `long long', as computed by sizeof. */
#define SIZEOF_LONG_LONG 8

/* The size of `void *', as computed by sizeof. */
#define SIZEOF_VOID_P 8

/* Maximum value of ssize_t */
#define SSIZE_T_MAX LONG_MAX

/* Define to 1 if you have the ANSI C header files. */
#define STDC_HEADERS 1

/* max. time_t bits gmtime() can handle */
#define TIME_T_MAX_BITS 40

/* Define if off_t is int */
/* #undef UOFF_T_INT */

/* Define if off_t is long */
#define UOFF_T_LONG 

/* Define if off_t is long long */
/* #undef UOFF_T_LONG_LONG */

/* Build with checkpassword userdb support */
#define USERDB_CHECKPASSWORD 

/* Build with LDAP support */
#define USERDB_LDAP 

/* Build with passwd support */
#define USERDB_PASSWD 

/* Build with passwd-file support */
#define USERDB_PASSWD_FILE 

/* Build with prefetch userdb support */
#define USERDB_PREFETCH 

/* Build with SQL support */
#define USERDB_SQL 

/* Build with static userdb support */
#define USERDB_STATIC 

/* Build with vpopmail support */
/* #undef USERDB_VPOPMAIL */

/* Define if you want to use Boehm GC */
/* #undef USE_GC */

/* A 'va_copy' style function */
#define VA_COPY va_copy

/* 'va_lists' cannot be copies as values */
#define VA_COPY_AS_ARRAY 1

/* Version number of package */
#define VERSION "1.0.7"

/* Define to 1 if your processor stores words with the most significant byte
   first (like Motorola and SPARC, unlike Intel and VAX). */
/* #undef WORDS_BIGENDIAN */

/* If set to 64, enables 64bit off_t for some systems (eg. Linux, Solaris) */
#define _FILE_OFFSET_BITS 64

/* Linux quota version to use */
/* #undef _LINUX_QUOTA_VERSION */

/* Define to `__inline__' or `__inline' if that's what the C compiler
   calls it, or to nothing if 'inline' is not supported under any name.  */
#ifndef __cplusplus
/* #undef inline */
#endif

/* Define to 'unsigned int' if you don't have it */
/* #undef size_t */

/* Define to 'int' if you don't have it */
/* #undef ssize_t */

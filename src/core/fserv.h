/**
Copyright 2014 Simon Zolin.
*/

#pragma once

#include <FFOS/time.h>
#include <FF/array.h>
#include <FF/data/parse.h>
#include <FF/timer-queue.h>
#include <FF/taskqueue.h>
#include <FF/sendfile.h>


#define FSV_VER "0.24"

typedef struct fsv_main fsv_main;
typedef struct fsv_core fsv_core;
typedef struct fsv_mod fsv_mod;
typedef struct fsv_log fsv_log;
typedef struct fsv_logctx fsv_logctx;
typedef struct fsv_cache fsv_cache;
typedef struct fsv_fcache fsv_fcache;
typedef struct fsv_listen fsv_listen;
typedef struct fsv_connect fsv_connect;
typedef struct fsv_resolver fsv_resolver;
typedef struct fsv_status fsv_status;

/** Get module interface by name.
A module implements the function fsv_getmod() and exports it.
Return NULL on error. */
typedef const fsv_mod * (*fsv_getmod_t)(const char *name);

/* ====================================================================== */

enum FSVMAIN_ESIG {
	FSVMAIN_RUN
	, FSVMAIN_STOP
	, FSVMAIN_REOPEN
	, FSVMAIN_RECONFIG
};

struct fsv_main {
	/** Return NULL on error. */
	void * (*create)(void);

	void (*destroy)(void);

	/** Return 0 on success. */
	int (*readconf)(const char *fn);

	/** Send signal.
	@signo: enum FSVMAIN_ESIG.
	Return -1 on error. */
	int (*sig)(int signo);

	const char * (*errstr)(void);
};

enum FSV_TIME {
	FSV_TIME_YMD
	, FSV_TIME_YMD_LOCAL
	, FSV_TIME_WDMY
	, FSV_TIME_ADDMS = 0x10
};

typedef struct fsv_modinfo {
	const char *name;
	void *instance;
	void *binary;
	const fsv_mod *f;
} fsv_modinfo;

typedef struct fsvcore_config {
	const char *root; //server root path
	fsv_logctx *logctx; //global log
	fffd queue;
	uint pagesize;
} fsvcore_config;

enum FSVCORE_TASK {
	FSVCORE_TASKADD //add a task into the queue
	, FSVCORE_TASKDEL //remove a task from the queue
	, FSVCORE_TASKQUEUED //utask() returns 1 if a task is in the queue
};

typedef fftask fsv_task;
typedef fftmrq_entry fsv_timer;
typedef ssize_t (*fsv_getvar_t)(void *udata, const char *name, size_t namelen, void *dst, size_t cap);

#define fsv_getvarcz(udata, namecz, dst, cap) \
	getvar(udata, namecz, FFSLEN(namecz), dst, cap)

struct fsv_core {
	const fsvcore_config * (*conf)(void);

	/** Get local filesystem path.  Allocate memory if needed.
	Return an absolute normalized path without the last slash, e.g. "/path/path2"
	Return NULL on error. */
	char* (*getpath)(char *dst, size_t *dstlen, const char *path, size_t len);

	/** Return NULL if not found. */
	const fsv_modinfo * (*findmod)(const char *name, size_t namelen);

	/** Return -1 on error. */
	ssize_t (*getvar)(const char *name, size_t namelen, void *dst, size_t cap);

	/** Process dynamic variables.  @dst is reused.
	Return 0 on success.  Free @dst with ffarr_free(). */
	int (*process_vars)(ffstr3 *dst, const ffstr *src, fsv_getvar_t getvar, void *udata, fsv_logctx *logctx);

	/** Get current time.
	@dt, @dst: optional.
	@flags: enum FSV_TIME. */
	fftime (*gettime4)(ffdtm *dt, char *dst, size_t cap, uint flags);

	/** Start/stop timer.
	@interval_ms
		Start periodic timer if >0.
		Start one-shot timer if <0.
		Stop timer if =0. */
	void (*timer)(fsv_timer *tmr, int64 interval_ms, fftmrq_handler func, void *param);

	/** Control user-level tasks.
	@op: enum FSVCORE_TASK. */
	int (*utask)(fsv_task *task, int op);
};

#define fsv_gettime()  gettime4(NULL, NULL, 0, 0)

#define fsv_timerstop(tmr)  timer(tmr, 0, NULL, NULL)

#define fsv_taskpost(srv, task, func, _param) \
do { \
	(task)->handler = func; \
	(task)->param = _param; \
	(srv)->utask(task, FSVCORE_TASKADD); \
} while (0)

enum FSVCORE_SIG {
	FSVCORE_SIGSTART = 1
	, FSVCORE_SIGSTOP
	, FSVCORE_SIGSTATUS
	, FSVCORE_SIGREOPEN
};

struct fsv_mod {
	/** Return module instance or NULL on error. */
	void * (*create)(const fsv_core *srv, ffpars_ctx *ctx, fsv_modinfo *m);

	void (*destroy)(void);

	/** Send signal to a module.
	@signo: enum FSVCORE_SIG
	Return 0 on success. */
	int (*sig)(int signo);

	/** Get interface by name. */
	const void * (*iface)(const char *name);
};

/* ====================================================================== */

enum FSV_LOG_LEV {
	FSV_LOG_NONE
	, FSV_LOG_ERR
	, FSV_LOG_WARN
	, FSV_LOG_INFO
	, FSV_LOG_DBG
	, FSV_LOG_MASK = 0x0f

	, FSV_LOG_DBGFLOW = 0x10
	, FSV_LOG_DBGNET = 0x20
	, FSV_LOG_HTTPFILT = 0x40
	, FSV_LOG_DBGMASK = 0xfff0

	, FSV_LOG_ACCESS = 0x10000
};

struct fsv_log {
	fsv_logctx * (*newctx)(ffpars_ctx *a, fsv_logctx *parent);

	/** @level: enum FSV_LOG_LEV. */
	int (*add)(fsv_logctx *ctx, int level, const char *modname, const ffstr *trxn, const char *fmt, ...);
	int (*addv)(fsv_logctx *ctx, int level, const char *modname, const ffstr *trxn, const char *fmt, va_list va);
};

struct _fsv_logctx {
	int level;
	const fsv_log *mlog;
};

#define fsv_logctx_get(logctx)  ((struct _fsv_logctx*)(logctx))

/** Return TRUE if messages of this level are logged. */
#define fsv_log_checklevel(ctx, lev) \
	((fsv_logctx_get(ctx)->level & FSV_LOG_MASK) >= ((lev) & FSV_LOG_MASK))

#define fsv_log_checkdbglevel(ctx, dbglevel) \
	(0 != (fsv_logctx_get(ctx)->level & (dbglevel)))

#define fsv_errlog(ctx, level, modname, txn, ...) \
do { \
	if (fsv_log_checklevel(ctx, level)) \
		fsv_logctx_get(ctx)->mlog->add(ctx, level, modname, txn, __VA_ARGS__); \
} while (0)

#define fsv_syserrlog(ctx, level, modname, txn, fmt, ...) \
do { \
	if (fsv_log_checklevel(ctx, level)) \
		fsv_logctx_get(ctx)->mlog->add(ctx, level, modname, txn, fmt ": %E", __VA_ARGS__, fferr_last()); \
} while (0)

#define fsv_dbglog(ctx, level, modname, txn, ...) \
do { \
	if (fsv_log_checkdbglevel(ctx, level)) \
		fsv_logctx_get(ctx)->mlog->add(ctx, FSV_LOG_DBG | (level), modname, txn, __VA_ARGS__); \
} while (0)

#define fsv_accesslog(ctx, modname, txn, ...) \
do { \
	if (fsv_logctx_get(ctx)->level & FSV_LOG_ACCESS) \
		fsv_logctx_get(ctx)->mlog->add(ctx, FSV_LOG_ACCESS, modname, txn, __VA_ARGS__); \
} while (0)

/* ====================================================================== */

typedef struct fsv_cachectx fsv_cachectx;
typedef struct fsv_cacheitem_id fsv_cacheitem_id;

enum FSV_CACH_E {
	FSV_CACH_OK
	, FSV_CACH_ESYS
	, FSV_CACH_EEXISTS
	, FSV_CACH_ENOTFOUND
	, FSV_CACH_ECOLL
	, FSV_CACH_ENUMLIMIT
	, FSV_CACH_EMEMLIMIT
	, FSV_CACH_ESZLIMIT
	, FSV_CACH_ELOCKED
};

typedef struct fsv_cacheitem {
	fsv_cacheitem_id *id;
	uint hash[1];
	fsv_logctx *logctx;

	size_t keylen;
	const char *key;

	size_t datalen;
	const char *data;

	uint refs;
	uint expire; //max-age, in sec
} fsv_cacheitem;

static FFINL void fsv_cache_init(fsv_cacheitem *ca) {
	ffmem_tzero(ca);
	ca->refs = 1;
}

enum FSV_CACH_NEWCTX {
	FSV_CACH_KEYICASE = 1 //case-insensitive keys
	, FSV_CACH_MULTI = 2 //support several items with the same key
};

enum FSV_CACH_FETCH {
	FSV_CACH_NEXT = 1 //fetch the next item with the same key, for FSV_CACH_MULTI
	, FSV_CACH_ACQUIRE = 2 //acquire the item (fetch and remove from the cache)
};

enum FSV_CACH_UNREF {
	FSV_CACH_UNLINK = 1
};

// enum FSV_CACH_STORE {
// };

enum FSV_CACH_CB {
	FSV_CACH_ONDELETE
};

typedef struct fsv_cach_cb {
	/** @flags: enum FSV_CACH_CB. */
	int (*onchange)(fsv_cachectx *ctx, fsv_cacheitem *ca, int flags);
} fsv_cach_cb;

struct fsv_cache {
	/** @flags: enum FSV_CACH_NEWCTX. */
	fsv_cachectx * (*newctx)(ffpars_ctx *a, const fsv_cach_cb *cb, int flags);

	/** @flags: enum FSV_CACH_FETCH.
	Return enum FSV_CACH_E. */
	int (*fetch)(fsv_cachectx *ctx, fsv_cacheitem *ca, int flags);

	/** @flags: enum FSV_CACH_STORE.
	Return enum FSV_CACH_E. */
	int (*store)(fsv_cachectx *ctx, fsv_cacheitem *ca, int flags);

	/** Return enum FSV_CACH_E. */
	int (*update)(fsv_cacheitem *ca, int flags);

	/** @flags: enum FSV_CACH_UNREF.
	Return enum FSV_CACH_E. */
	int (*unref)(fsv_cacheitem *ca, int flags);
};

/* ====================================================================== */

typedef struct fsv_fcacheitem {
	fsv_cacheitem_id *id;
	uint hash[1];
	fsv_logctx *logctx; //[in]
	void *userptr;

	size_t keylen;
	const char *key;

	uint64 len;
	const void *data; //[in]
	uint fdoff; //[out]
	fffd fd; //[out]

	size_t hdrlen;
	const void *hdr;

	uint64 total_size; //[in] reserve disk space
	uint expire; //expiration time. 0 - default
	uint cretm; //[out] creation time
} fsv_fcacheitem;

static FFINL void fsv_fcache_init(fsv_fcacheitem *fca) {
	ffmem_tzero(fca);
	fca->fd = FF_BADFD;
}

enum FSV_FCACH {
	// store/update:
	FSV_FCACH_LOCK = 1 //lock for update

	// update:
	, FSV_FCACH_UNLOCK = 2
	, FSV_FCACH_APPEND = 4 //append data into file
	, FSV_FCACH_REFRESH = 8 //only update "expire" value

	// unref:
	, FSV_FCACH_UNLINK = 1
};

typedef struct fsv_fcach_cb {
	/**
	@result: 0 on success. */
	void (*onwrite)(void *userptr, fsv_fcacheitem *ca, int result);
} fsv_fcach_cb;

struct fsv_fcache {
	fsv_cachectx * (*newctx)(ffpars_ctx *a, const fsv_fcach_cb *cb, int flags);

	/** Return enum FSV_CACH_E. */
	int (*fetch)(fsv_cachectx *ctx, fsv_fcacheitem *ca, int flags);

	/** @flags: enum FSV_FCACH.
	Return FSV_CACH_OK on success.  fsv_fcach_cb.onwrite() is called.
	Return enum FSV_CACH_E. */
	int (*store)(fsv_cachectx *ctx, fsv_fcacheitem *ca, int flags);

	/** @flags: enum FSV_FCACH.
	Return enum FSV_CACH_E. */
	int (*update)(fsv_fcacheitem *ca, int flags);

	/** @flags: enum FSV_FCACH.
	Return enum FSV_CACH_E. */
	int (*unref)(fsv_fcacheitem *ca, int flags);
};

/* ====================================================================== */

typedef struct fsv_lsnctx fsv_lsnctx;
typedef struct fsv_lsncon fsv_lsncon;

// enum FSV_LISN_SIG {
// };

typedef struct fsv_listen_cb {
	void (*onaccept)(void *userctx, fsv_lsncon *conn);

	/** @sig: enum FSV_LISN_SIG. */
	int (*onsig)(fsv_lsncon *conn, void *userptr, int sig);
} fsv_listen_cb;

enum FSV_IO_E {
	FSV_IO_ESHUT = 0 //peer closed the writing channel
	, FSV_IO_ERR = -1 //I/O error occurred
	, FSV_IO_EAGAIN = -2 //I/O operation would block
	, FSV_IO_ASYNC = -3 //async I/O operation was started
};

enum FSV_LISN_FIN {
	FSV_LISN_LINGER = 1
};

enum FSV_LISN_OPT {
	FSV_LISN_OPT_USERPTR = 1 //void*
	, FSV_LISN_OPT_LOG //fsv_logctx*
};

struct fsv_listen {
	fsv_lsnctx * (*newctx)(ffpars_ctx *a, const fsv_listen_cb *h, void *userctx);
	fsv_lsnctx * (*findctx)(const char *name, size_t len);

	ssize_t (*getvar)(fsv_lsncon *conn, const char *name, size_t namelen, void *dst, size_t cap);

	/** Set option on a connection object.
	@opt: enum FSV_LISN_OPT. */
	int (*setopt)(fsv_lsncon *conn, int opt, void *data);

	/**
	@flags: enum FSV_LISN_FIN */
	void (*fin)(fsv_lsncon *conn, int flags);

	/** Receive/send data.
	@udata: opaque value passed to handler().
	@handler: if NULL, perform operation synchronously.  If not NULL, asynchronously.
	Return >0 or enum FSV_IO_E. */
	ssize_t (*recv)(fsv_lsncon *conn, void *buf, size_t size, ffaio_handler handler, void *udata);
	ssize_t (*send)(fsv_lsncon *conn, const void *buf, size_t len, ffaio_handler handler, void *udata);
	ssize_t (*sendfile)(fsv_lsncon *conn, ffsf *sf, ffaio_handler handler, void *udata);

	/** Cancel asynchronous read/send.
	@op: enum FFAIO_CANCEL. */
	int (*cancelio)(fsv_lsncon *conn, int op, ffaio_handler handler, void *udata);
};

/* ====================================================================== */

typedef struct fsv_conctx fsv_conctx;
typedef struct fsv_conn fsv_conn;

enum FSV_CONN_E {
	FSV_CONN_OK
	, FSV_CONN_ESYS
	, FSV_CONN_EURL
	, FSV_CONN_EDNS
	, FSV_CONN_ENOADDR
	, FSV_CONN_ENOSERV
};

enum FSV_CONN_FIN {
	FSV_CONN_KEEPALIVE = 1 //store socket in cache
};

typedef struct fsv_connect_cb {
	void (*onconnect)(void *userptr, int result);
	ssize_t (*getvar)(void *obj, const char *name, size_t namelen, void *dst, size_t cap);
} fsv_connect_cb;

typedef struct fsv_conn_new {
	fsv_conn *con; //in/out
	void *userptr;
	fsv_logctx *logctx;
	ffstr url; //out
} fsv_conn_new;

struct fsv_connect {
	fsv_conctx * (*newctx)(ffpars_ctx *a, const fsv_connect_cb *cb);
	ssize_t (*getvar)(void *c, const char *name, size_t namelen, void *dst, size_t cap);

	int (*getserv)(fsv_conctx *cx, fsv_conn_new *nc, int flags);

	/** onconnect() will be called with the result of connect operation. */
	void (*connect)(fsv_conn *c, int flags);

	/** @flags: enum FSV_CONN_FIN. */
	int (*fin)(fsv_conn *c, int flags);

	/** Return >0 or enum FSV_IO_E. */
	ssize_t (*recv)(fsv_conn *c, void *buf, size_t size, ffaio_handler handler, void *udata);
	ssize_t (*send)(fsv_conn *c, const void *buf, size_t len, ffaio_handler handler, void *udata);
	ssize_t (*sendfile)(fsv_conn *c, ffsf *sf, ffaio_handler handler, void *udata);

	int (*cancelio)(fsv_conn *c, int op, ffaio_handler handler, void *udata);
};

/* ====================================================================== */

/** Resolver calls this function to report the final status of the query.
@status: enum FFDNS_R. */
typedef void (*fsv_resolv_cb)(void *udata, int status, const ffaddrinfo *ai[2]);

typedef struct fsv_resolv_ctx fsv_resolv_ctx;

enum FSV_RESOLV_F {
	FSV_RESOLV_CANCEL = 1
};

struct fsv_resolver {
	fsv_resolv_ctx * (*newctx)(ffpars_ctx *a);

	/** Asynchronous DNS resolve.
	@handler: on-completion callback.  If NULL, cancel the pending task that is linked with name and udata.
	@udata: opaque value passed to handler().
	@flags: enum FSV_RESOLV_F. */
	int (*resolve)(fsv_resolv_ctx *ctx, const char *name, size_t len, fsv_resolv_cb handler, void *udata, int flags);

	void (*unref)(const ffaddrinfo *ai);
};

/* ====================================================================== */

struct fsv_status {
	int (*setdata)(const char *s, size_t len, int flags);
};

typedef struct fsv_status_handler {
	void (*get)(const fsv_status *statusmod);
} fsv_status_handler;

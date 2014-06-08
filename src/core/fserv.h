/**
Copyright 2014 Simon Zolin.
*/

#pragma once

#include <FFOS/time.h>
#include <FF/array.h>
#include <FF/parse.h>
#include <FF/timer-queue.h>
#include <FF/taskqueue.h>


#define FSV_VER "0.16"

typedef struct fsv_main fsv_main;
typedef struct fsv_core fsv_core;
typedef struct fsv_mod fsv_mod;
typedef struct fsv_log fsv_log;
typedef struct fsv_logctx fsv_logctx;

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

FF_EXTN const fsv_main * fsv_getmain(void);

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
} fsvcore_config;

enum FSVCORE_TASK {
	FSVCORE_TASKADD //add a task into the queue
	, FSVCORE_TASKDEL //remove a task from the queue
	, FSVCORE_TASKQUEUED //utask() returns 1 if a task is in the queue
};

typedef fftask fsv_task;
typedef fftmrq_entry fsv_timer;

struct fsv_core {
	const fsvcore_config * (*conf)(void);

	/** Get local filesystem path.
	If @dst is NULL, the function returns the maximum number of characters needed.
	Return the number of characters written.
		@dst will contain an absolute normalized path without the last slash, e.g. "/path/path2"
		"/" is translated into ""
	Return -1 on error. */
	ssize_t (*getpath)(char *dst, size_t cap, const char *path, size_t len);

	/** Return NULL if not found. */
	const fsv_modinfo * (*findmod)(const char *name, size_t namelen);

	/** Return -1 on error. */
	int (*getvar)(const char *name, size_t namelen, ffstr *dst);

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
	, FSV_LOG_DBGMASK = 0xfff0
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

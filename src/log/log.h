/**
Copyright (c) 2014 Simon Zolin
*/

#pragma once

#include <core/fserv.h>
#include <FFOS/file.h>
#include <FFOS/atomic.h>
#include <FF/list.h>


typedef struct fsv_log_outptr fsv_log_outptr;

enum FSV_LOG_OPEN_F {
	LOG_OPEN
	, LOG_FLUSH
	, LOG_REOPEN
};

typedef struct fsv_log_output {
	fsv_log_outptr * (*create)(ffpars_ctx *a);
	void (*free)(fsv_log_outptr *instance);

	/** @flags: enum FSV_LOG_OPEN_F. */
	int (*open)(fsv_log_outptr *instance, int flags);

	int (*write)(fsv_log_outptr *instance, int level, const char *buf, size_t len);
} fsv_log_output;


FF_EXTN const fsv_log_output logf_output;
FF_EXTN const fsv_log_output logz_output;


typedef struct logmodule {
	//conf:
	uint flush_delay; //ms
	uint use_time;

	const fsv_core *srv;
	fflist ctxs;
	fsv_timer flush_timer;
	char pid[FFINT_MAXCHARS];

	//status:
	ffatomic stat_written;
	ffatomic stat_messages;
} logmodule;

FF_EXTN logmodule *logm;

typedef struct logoutput {
	const fsv_log_output *iface;
	fsv_log_outptr *instance;
	uint level;
} logoutput;

struct fsv_logctx {
	// struct _fsv_logctx:
	uint level;
	const fsv_log *mlog;

	fflist_item sib;
	fsv_logctx *parent;
	struct { FFARR(logoutput) } outs;

	//conf:
	byte pass_to_std;
};

FF_EXTN void logm_err(const char *fmt, ...);

#define logm_errsys(fmt, ...) \
	logm_err(fmt ": %E", __VA_ARGS__, fferr_last())

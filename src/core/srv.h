/**
Copyright 2014 Simon Zolin
*/

#pragma once

#include <core/fserv.h>
#include <FFOS/process.h>
#include <FFOS/sig.h>
#include <FF/timer-queue.h>
#include <FF/time.h>


enum TM_E {
	TM_YMD = 1
	, TM_WDMY = 2
	, TM_YMD_LOCAL = 4
	, TM_MSEC = 1 << 31
};

typedef struct curtime_t {
	fftime time;
	ffdtm dt
		, dt_lo;
	char ymd[32]; // yyyy-MM-dd...
	char wdmy[32]; // Wed, 07 Sep...
	char ymd_lo[32]; // yyyy-MM-dd...
	uint flags; //enum TM_E
} curtime_t;


typedef struct fmodule {
	fsv_modinfo mod;
	fflist_item sib;
	char name[1];
} fmodule;

/** Manages configuration, modules, timer, signals and event loop. */
typedef struct fserver {
	fffd kq;
	ffkqu_time quTm;
	const ffkqu_time *pquTm;

	fsv_timer tmr;
	fftimer_queue tmrqu;
	curtime_t time;

	fftaskmgr taskmgr;
	ffaio_task sigs_task;

	int state;
	fflist mods;
	ffstr3 errstk;

	fsv_logctx *logctx;
	struct _fsv_logctx logctx_empty;

	fsvcore_config cfg;
	union {
		ffstr pid_fn;
		ffstr pid_fn_conf;
	};
	ffstr rootdir; ///< e.g. "/path/path2/"
	ushort events_count;
	ushort timer_resol; //in ms
	uint page_size;
} fserver;

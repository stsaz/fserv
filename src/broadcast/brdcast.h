/**
Copyright 2014 Simon Zolin.
*/

#pragma once

#include <core/fserv.h>
#include <http/iface.h>

#include <FF/list.h>
#include <FF/net/http.h>
#include <FF/audio/mpeg.h>
#include <FF/audio/icy.h>


typedef struct bcastmodule {
	const fsv_core *core;
	fsv_logctx *logctx;
	fflist ctxs; //bcastctx[]
	size_t pagesize;
	uint timer_interval;
	uint64 lastUpdOutputBPS;
	fsv_timer status_tmr;
} bcastmodule;

extern bcastmodule *bcastm;

#define BCAST_MODNAME "BCST"

#define errlog(lx, lev, ...) \
	fsv_errlog(lx, lev, BCAST_MODNAME, NULL, __VA_ARGS__)

#define syserrlog(lx, lev, fmt, ...) \
	fsv_syserrlog(lx, lev, BCAST_MODNAME, NULL, fmt, __VA_ARGS__)

#define dbglog(lx, lev, ...) \
	fsv_dbglog(lx, lev, BCAST_MODNAME, NULL, __VA_ARGS__)

enum BCST_STATUS {
	ST_STOPPED = 0
	, ST_STARTING
	, ST_BUFFERING
	, ST_READY
};

typedef struct bcast_prov_iface {
	ffbool (*start)(void *p);
	void (*stop)(void *p);
	void (*addhdrs)(void *p, ffhttp_cook *cook);
	int (*getbuf)(void *prov, size_t ibuf, ffstr *buf);
	void (*played)(void *prov, uint iplayed);
	void (*fin)(void *p);
} bcast_prov_iface;

typedef struct bcastctx {
	fsv_logctx *logctx;
	fsv_logctx *lx;
	struct _fsv_logctx lctx;

	void *prov;
	fsv_timer startstop_tmr;
	fsv_timer update_tmr;
	unsigned status : 3
		, err :1
		, stopping :1 //we gonna stop the stream soon
		, updatetime_set :1
		;

	fflist_item sib;
	uint buf_size;
	uint buf_size_conf;
	uint icy_meta_int;
	ffstr name;
	ffstr genre;
	ffstr url;
	byte always_on;
	ushort reconnect_timeout;
	ushort stop_delay;
	ushort buf_ms;

	uint64 outTraffic;
	uint64 outTrafficLastSec;
	uint64 outputBPS;

	uint curBuf; //the buffer which is currently being played
	uint usage[10];
	fflist users[10];
	uint byterate; //bytes/sec
	uint64 tmStartPlay;
	uint64 bytesPlayed;
	uint nbufs;
	fflist suspendedClients;

	char meta[FFICY_MAXMETA];
	uint szmeta; //size of meta including trailing zeroes
	uint lastMetaChange;
	int metaChangeIdx;
	ffstr title;

	uint64 nclients;

	const bcast_prov_iface *iface;
} bcastctx;

extern int icyx_conf_init(bcastctx *bx, ffpars_ctx *ctx);
extern int icy3_conf_init(bcastctx *bx, ffpars_ctx *ctx);

extern void bcastx_reset(bcastctx *bx);
extern void bcast_update(bcastctx *bx);

/** Set new meta data. */
extern void bcast_metaupdate(bcastctx *bx, const char *title, size_t len);

static FFINL uint int_cycleinc(uint i, uint sz) {
	return (i + 1) % sz;
}

#define bcast_now  bcastm->core->fsv_gettime

/** Get time duration (in msec).
secs = bytes / bytes/s. */
static FFINL uint64 mm_duration(uint byterate, uint64 bytes) {
	return bytes * 1000 / byterate;
}

/** Get data size (in bytes). */
static FFINL uint64 mm_datasize(uint byterate, uint64 ms) {
	return ms * byterate / 1000;
}

#define mm_tokbps(byte_rate)  ((byte_rate) * 8 / 1000)

/** Search for a valid MPEG frame.
flags & 0x07 - number of valid sequential frames to succeed.  Default is 1. */
FF_EXTN ffmpg_hdr* ffmpg_findframe(const void *d, size_t sz, uint flags);


typedef struct mp3store mp3store;
extern mp3store * mp3stor_init(ffpars_ctx *ctx, fsv_logctx *lx);
extern void mp3stor_free(mp3store *stor);
extern void mp3stor_name(mp3store *stor, const char *name, size_t namelen);
extern void mp3stor_write(mp3store *stor, const char *data, size_t len);
extern void mp3stor_stop(mp3store *stor);

/**
Copyright 2014 Simon Zolin.
*/

#pragma once

#include <core/fserv.h>
#include <core/sktopt.h>
#include <http/iface.h>
#include <FFOS/atomic.h>


typedef struct httpcon httpcon;
typedef struct httphost httphost;
typedef struct httptarget httptarget;

typedef struct hostbyname {
	ffstr name;
	httphost *host;
} hostbyname;

typedef struct http_submod {
	const char *modname;
	void *hctx;
	const fsv_http_cb *handler;
} http_submod;

typedef struct httpfilter {
	fsv_httpfilter hf;

	fflist_item sib;
	const http_submod *sm;
	httpcon *con;

	ffsf input;
	ffiovec iov;
	int flags;
	unsigned reqfilt :1
		, ismain :1
		, sentdata :1
		, fin :1;
} httpfilter;

typedef struct httpmodule {
	const fsv_core *core;
	fsv_logctx *logctx;
	const fsv_listen *lisn;

	fflist hosts; //httphost[]
	struct { FFARR(hostbyname) } hbn_arr;
	ffhstab ht_hbn; //hostname => httphost*

	http_submod err_hdler;
	fflist cons; //httpcon[]

	// conf:
	ushort read_header_tmout
		, keepalive_tmout;
	uint max_header_size
		, read_header_growby;
	uint max_keepalive_requests;
	uint pagesize;
	fsv_sktopt sktopt;

	//status:
	ffatomic nrequests
		, req_count
		, allread
		, allwritten;
	size_t read_bps
		, write_bps;
	fsv_timer status_tmr;

	ffhstab hstvars;
} httpmodule;

extern httpmodule *httpm;

struct httphost {
	fflist_item sib;
	fsv_logctx *logctx;
	http_submod err_hdler;

	struct { FFARR(fsv_lsnctx*) } listeners; //the list of servers on which this host is available

	void *sslctx;

	ffstr3 names;
	ffstr name;

	ffstr resp_hdrs; //ffbstr[]

	struct { FFARR(http_submod) } resp_filters;

	fflist routes; //httptarget[]
	ffhstab hstroute;
	httptarget *anytarget;

	size_t reqbody_buf_size;
	uint64 max_reqbody;
	ffstr def_mime_type;
	ffstr accesslog_info;
	ushort read_body_tmout
		, write_tmout;
	byte linger;
	unsigned accesslog_info_static :1;
};

/** Defines HTTP handler for a particular request path. */
struct httptarget {
	fflist_item sib;
	ffstr path; //full path or regexp

	httphost *host;
	fsv_logctx *logctx;
	ffstr3 index;
	fflist rxroutes; //httptarget[]

	http_submod file_hdler;
	http_submod dir_hdler;

	unsigned ispath :1;

	char path_s[1];
};

struct httpcon {
	fflist_item sib;
	fsv_logctx *logctx;
	struct _fsv_logctx lctx;
	fsv_task rtask;

	fsv_lsncon *conn;
	httphost *defhost; //default host for this server address
	uint keepalive_cnt;

	char id[FFSLEN("*") + FFINT_MAXCHARS];
	ffstr sid;

	fsv_timer tmr;
	time_t tmr_when;
	uint tmr_flags;

	ffchain filters;
	ffchain respfilters;

	//request:
	httphost *host;
	httptarget *tgt;
	fftime start_time;
	ffhttp_request req;
	ffstr3 reqhdrbuf;
	ffstr3 reqbodybuf;
	struct { FFARR(httpfilter) } reqchain;
	ffhttp_chunked chunked;
	fsv_httpfilter *hfrecv;

	//response:
	ffhttp_cook resp;
	uint resplen;
	struct { FFARR(httpfilter) } respchain;
	ffiovec *hdr_iovs;
	struct { FFARR(ffiovec) } chunked_iovs;
	char chunk_hdr[FFINT_MAXCHARS];
	fsv_httpfilter *hfsend;

	uint64 nread //the number of bytes read in this session
		, nwrite;

	unsigned notstarted :1 //request hasn't been started yet
		, pipelined :1 //if set, there's pipelined data in request buffers
		, err :1 //if set, we're trying to send error response
		, req_fin :1
		, resp_fin :1
		, respmain_fin :1
		, keep_alive :1
		, skshut :1 //socket was shut down
		;

	// request body:
	unsigned want_readbody :1
		, body_fin :1
		, body_ready :1
		, body_skip :1
		;
};


#define HTTP_MODNAME  "HTTP"

#define dbglog(logctx, lev, ...) \
	fsv_dbglog(logctx, lev, HTTP_MODNAME, NULL, __VA_ARGS__)

#define errlog(logctx, lev, ...) \
	fsv_errlog(logctx, lev, HTTP_MODNAME, NULL, __VA_ARGS__)

#define syserrlog(logctx, lev, fmt, ...) \
	fsv_syserrlog(logctx, lev, HTTP_MODNAME, NULL, fmt, __VA_ARGS__)

enum HTTP_CONF_E {
	HTTP_CONF_ENOMOD = 0x8000
	, HTTP_CONF_ENOIFACE
	, HTTP_CONF_EMODCTX
};

enum {
	HTTP_LOG_READ_DATAWND = 16
};

enum HTTP_TMR {
	TMR_READHDR = 1, TMR_KEEPALIVE = 2, TMR_READBODY = 4, TMR_WRITE = 8
};

extern const fsv_http fsv_http_iface;
extern void http_setlog(httpcon *c, fsv_logctx *logctx);
extern void http_close(httpcon *c);
extern httphost * http_gethost(fsv_lsncon *conn, const ffstr *name);
extern void http_accesslog(httpcon *c);
extern void http_reset(httpcon *c);

extern void http_get_def_reqfilts(const http_submod **sm, size_t *n);
extern void http_get_def_respfilts(const http_submod **sm, size_t *n);
extern void http_bodyprovide_continue(httpcon *c);

extern void http_start(httpcon *c);
extern int http_init_respchain(httpcon *c, const http_submod *mainhandler);
extern void http_resptask(void *param);
extern void http_chain_fin(httpcon *c);

/**
Copyright 2014 Simon Zolin.
*/

#pragma once

#include <core/fserv.h>
#include <core/sktopt.h>
#include <http/iface.h>

#include <FF/net/http.h>
#include <FF/list.h>
#include <FFOS/atomic.h>


typedef struct htpxcon htpxcon;

typedef struct http_submod {
	const char *modname;
	void *hctx;
	const fsv_http_cb *handler;
} http_submod;

typedef struct htpxfilter {
	fsv_httpfilter hf;

	fflist_item sib;
	const http_submod *sm;
	htpxcon *con;

	ffsf input;
	ffiovec iov;
	int flags;
	unsigned reqfilt :1
		, sentdata :1;
} htpxfilter;

typedef struct htpxmodule {
	const fsv_core *core;
	fsv_logctx *logctx;
	fsv_timer status_tmr;
	uint page_size;
	fflist ctxs; //htpxctx[]
	fsv_sktopt sktopt;
	fflist cons; //htpxcon[]

	//status:
	ffatomic hits
		, nrequests
		, allread
		, allwritten;
	size_t read_bps
		, write_bps;
} htpxmodule;

extern htpxmodule *htpxm;

typedef struct htpxctx {
	fflist_item sib;

	const fsv_connect *conn;
	fsv_conctx *conctx;

	const fsv_http *client_http;

	ffstr conf_req_hdrs; //ffbstr[]
	ffstr req_host;
	ffstr conf_resp_hdrs; //ffbstr[]
	uint max_header_size
		, read_header_growby;
	uint respbody_buf_size;
	ushort write_timeout
		, read_timeout;
	byte httptunnel;
	byte stream_response;
	byte try_next_server;
	byte pass_query_string;
	byte pass_client_hdrs;
	unsigned conf_req_host :1
		, req_host_static :1;
} htpxctx;

struct htpxcon {
	htpxctx *px;

	fsv_logctx *logctx;
	fsv_httpcon *http;
	fsv_httpfilter *hf;
	ffhttp_cook *clientresp;
	ffhttp_request *clientreq;

	fsv_timer tmr;
	uint tmr_when;
	uint tmr_flags;

	//filter-connect:
	fsv_task rtsk;
	fsv_conn *serv_id;
	ffstr serv_url //upstream server URL
		, serv_host;

	//request:
	ffstr req_hdrs;
	uint nreqline; //length of request line
	uint64 req_cont_len;
	struct { FFARR(ffiovec) } iovs;
	ffiovec iov;
	ffsf *sf;
	fsv_httpfilter *hfsend;

	//response:
	ffstr3 hdr;
	ffstr3 body;
	ffhttp_response resp; //parsed response from the upstream server
	fftime conn_acq_time;
	ffhttp_chunked chunked;
	fsv_httpfilter *hfrecv;

	uint64 nread
		, nwrite;

	struct { FFARR(htpxfilter) } reqchain;
	struct { FFARR(htpxfilter) } respchain;

	fsv_httpfilter *hfconn;
	fsv_httpfilter *hfhttpin;
	fsv_httpfilter *hfhttpout;

	unsigned clientreq_fin :1 //request from parent module is completed
		, req_fin :1
		, resp_fin :1; //response is completed
	unsigned tunnel :1
		, nextsrv :1
		;
};


#define HTPX_MODNAME "HTPX"

#define dbglog(lx, lev, ...)\
	fsv_dbglog(lx, lev, HTPX_MODNAME, NULL, __VA_ARGS__)

#define errlog(lx, lev, ...)\
	fsv_errlog(lx, lev, HTPX_MODNAME, NULL, __VA_ARGS__)

#define syserrlog(lx, lev, fmt, ...) \
	fsv_syserrlog(lx, lev, HTPX_MODNAME, NULL, fmt, __VA_ARGS__)

extern const fsv_http htpx_http;
extern void htpx_errlog(htpxcon *c, int lev, const char *fmt, ...);
extern void htpx_accesslog(htpxcon *c);
extern int htpx_trynextserv(htpxcon *c);
extern void htpx_callmod(htpxcon *c, htpxfilter *hf);

extern void htpx_getreqfilters(htpxcon *c, const http_submod **sm, size_t *n);
extern void htpx_getrespfilters(htpxcon *c, const http_submod **sm, size_t *n);
extern void htpx_onconnect(void *obj, int result);
extern int htpx_mkresp(htpxcon *c, ffhttp_cook *cook, const ffhttp_response *resp);
extern int htpx_freeconn(htpxcon *c, int nextsrv);

enum HTPX_NEXTSRV {
	HTPX_NEXTSRV_OFF
	, HTPX_NEXTSRV_CONNECT = 1
	, HTPX_NEXTSRV_IO = 2
	, HTPX_NEXTSRV_BAD = 4
	, HTPX_NEXTSRV_5XX = 8
	, HTPX_NEXTSRV_DEF = 0x80
};

/** HTTP module interface.
Copyright 2014 Simon Zolin.
*/

#pragma once

#include <FF/data/parse.h>
#include <FF/net/http.h>


typedef struct fsv_http fsv_http;
typedef struct fsv_http_cb fsv_http_cb;
typedef struct fsv_httpcon fsv_httpcon;

typedef struct fsv_httpfilter {
	void *udata; //opaque data set by a filter
} fsv_httpfilter;

typedef struct fsv_http_hdlctx {
	//out:
	const fsv_http_cb *handler;
	void *hctx;

	const fsv_http *http;
	ffpars_ctx *args;
} fsv_http_hdlctx;

typedef struct fsv_httphandler_iface {
	/** Create context for a filter. */
	int (*newctx)(fsv_http_hdlctx *ctx);
} fsv_httphandler_iface;

enum FSV_HTTP_CB {
	FSV_HTTP_LAST = 1 //last chunk of input data
	, FSV_HTTP_SENT = 2 //FSV_HTTP_MORE was set and a chunk of data was processed
	, FSV_HTTP_FIN = 4
	// FSV_HTTP_PUSH
	// FSV_HTTP_ASIS
};

typedef struct fsv_httphandler {
	fsv_httpfilter *id;
	void *hctx;
	const fsv_http *http;
	fsv_httpcon *httpcon;
	fsv_logctx *logctx;
	ffhttp_request *req;
	ffhttp_cook *resp;
	ffsf *data;
	uint flags; //enum FSV_HTTP_CB
} fsv_httphandler;

struct fsv_http_cb {
	void (*onevent)(fsv_httphandler *h);
	void (*ondone)(fsv_httphandler *h); //destructor that is called if h->id->udata is not NULL.
};

enum FSV_HTTP_F {
	// FSV_HTTP_NOMORE = 0 //default: filter will be called when more input data is available
	FSV_HTTP_MORE = 1 //the same filter will be called once again after its output data is processed
	, FSV_HTTP_ERROR = 2 //send error response to a client, if possible, or close connection
	, FSV_HTTP_DONE = 4 //filter is removed from chain and won't be called again
	, FSV_HTTP_BACK = 8 //wait for more input data
	, FSV_HTTP_NOINPUT = 0x10 //remove all previous modules from chain
	, FSV_HTTP_NONEXT = 0x20 //remove all next modules from chain
	, FSV_HTTP_PASS = 0x40 //pass input data to the next filter
	, FSV_HTTP_PUSH = 0x80 //data will be sent to client immediately
	, FSV_HTTP_ASIS = 0x100 //no filters that modify content
};

struct fsv_http {
	ssize_t (*getvar)(void *httpcon, const char *name, size_t namelen, void *dst, size_t cap);

	/** Pass the control to other filters in chain.
	@flags: enum FSV_HTTP_F. */
	void (*send)(fsv_httpfilter *hf, const void *buf, size_t len, int flags);
	void (*sendv)(fsv_httpfilter *hf, ffiovec *iovs, size_t n, int flags);
	void (*sendfile)(fsv_httpfilter *hf, fffd fd, uint64 fsize, uint64 foffset, sf_hdtr *hdtr, int flags);
};

#define fsv_http_err(hf) \
	send(hf, NULL, 0, FSV_HTTP_ERROR)

#define fsv_http_sendfile(hf, sf, flags) \
	sendfile(hf, (sf)->fm.fd, (sf)->fm.fsize, (sf)->fm.foff, &(sf)->ht, flags)

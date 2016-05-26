/** Handle outgoing HTTP connections.
Copyright 2014 Simon Zolin.
*/

#include <http-proxy/proxy.h>

#include <FF/time.h>
#include <FF/data/json.h>
#include <FFOS/error.h>
#include <FFOS/process.h>


htpxmodule *htpxm;

// FSERV MODULE
static void * htpxm_create(const fsv_core *core, ffpars_ctx *c, fsv_modinfo *m);
static void htpxm_destroy(void);
static int htpxm_sig(int signo);
static const void * htpxm_iface(const char *name);
static const fsv_mod fsv_htpx_mod = {
	&htpxm_create, &htpxm_destroy, &htpxm_sig, &htpxm_iface
};

// HTTP IFACE
static int htpx_newctx(fsv_http_hdlctx *hc);
static const fsv_httphandler_iface htpx_httpiface = {
	&htpx_newctx
};

// HTTP HANDLER
static void htpx_onevent(fsv_httphandler *h);
static void htpx_ondone(fsv_httphandler *h);
static const fsv_http_cb htpx_httphandler = {
	&htpx_onevent, &htpx_ondone
};

// HTTP
static void htpx_send(fsv_httpfilter *_hf, const void *buf, size_t len, int flags);
static void htpx_sendfile(fsv_httpfilter *_hf, fffd fd, uint64 fsize, uint64 foffset, sf_hdtr *hdtr, int flags);
static ssize_t htpx_getvar(void *obj, const char *name, size_t namelen, void *dst, size_t cap);
const fsv_http htpx_http = {
	&htpx_getvar, &htpx_send, NULL, &htpx_sendfile
};

// CONNECT CALLBACK
static const fsv_connect_cb fsv_prox_connect_cb = {
	&htpx_onconnect, &htpx_getvar
};

// STATUS
static void htpxm_status(const fsv_status *statusmod);
static const fsv_status_handler htpx_stat_iface = {
	&htpxm_status
};

// CONFIG
static int htpxm_conf_log(ffparser_schem *ps, void *unused, ffpars_ctx *confctx);
static int htpxm_conf_sktops(ffparser_schem *ps, void *unused, ffpars_ctx *confctx);

static const ffpars_enumlist htpx_conf_tunnel;
static int htpx_conf_connectto(ffparser_schem *ps, htpxctx *px, ffpars_ctx *confctx);
static int htpx_conf_cache(ffparser_schem *ps, htpxctx *px, ffpars_ctx *args);
static int htpx_conf_trynext(ffparser_schem *ps, htpxctx *px, const ffstr *val);
static int htpx_conf_reqhdrs(ffparser_schem *ps, htpxctx *px, ffpars_ctx *confctx);
static int htpx_conf_resphdrs(ffparser_schem *ps, htpxctx *px, ffpars_ctx *confctx);
static int htpx_conf_reqhdrs_item(ffparser_schem *ps, htpxctx *px, const ffstr *val);
static int htpx_conf_resphdrs_item(ffparser_schem *ps, htpxctx *px, const ffstr *val);
static int htpx_conf_end(ffparser_schem *ps, htpxctx *px);

static void htpx_statustimer(const fftime *now, void *param);
static void * htpx_newcon(fsv_httphandler *h);
static int htpx_connect_allowed(fsv_httphandler *h);

static int htpx_conf_denyurl(ffparser_schem *ps, htpxctx *px, const ffstr *val);
static int htpx_htdenyurls_cmpkey(void *udata, const char *key, size_t keylen, void *param);
static int htpx_htdenyurls_init(htpxctx *px);
static int htpx_checkdeny(htpxctx *px, const ffhttp_request *req, fsv_logctx *logctx);

static void htpx_chain_init(htpxcon *c);
static int htpx_chain_process(htpxcon *c, htpxfilter **phf, uint flags);
static void htpx_chain_error(htpxcon *c, htpxfilter *hf);
static void htpx_finfilter(htpxcon *c, htpxfilter *hf);
static void htpx_chain_free(htpxcon *c);

static const char *const filt_type_str[] = { "response", "request" };
#define FILT_TYPE(t)  filt_type_str[t]


static void oninit(void)
{
	ffmem_init();
	if (0 != ffskt_init(FFSKT_WSAFUNCS)
		|| 0 != ffhttp_initheaders())
		ffps_exit(1);
	//ffhttp_freeheaders()
}

FFDL_ONINIT(oninit, NULL)

FF_EXTN FF_EXP const fsv_mod * fsv_getmod(const char *name)
{
	if (!ffsz_cmp(name, "proxy"))
		return &fsv_htpx_mod;
	return NULL;
}


static const ffpars_arg htpxm_conf_args[] = {
	{ "log",  FFPARS_TOBJ | FFPARS_FOBJ1,  FFPARS_DST(&htpxm_conf_log) }
	, { "socket_option",  FFPARS_TOBJ,  FFPARS_DST(&htpxm_conf_sktops) }
};

static const ffpars_arg htpx_conf_args[] = {
	{ "connect_to",  FFPARS_TOBJ | FFPARS_FOBJ1 | FFPARS_FREQUIRED,  FFPARS_DST(&htpx_conf_connectto) }
	, { "document_cache",  FFPARS_TOBJ,  FFPARS_DST(&htpx_conf_cache) }
	, { "stream_response",  FFPARS_TBOOL | FFPARS_F8BIT,  FFPARS_DSTOFF(htpxctx, stream_response) }
	, { "response_body_buffer",  FFPARS_TSIZE | FFPARS_FNOTZERO,  FFPARS_DSTOFF(htpxctx, respbody_buf_size) }
	, { "http_tunnel",  FFPARS_TENUM | FFPARS_F8BIT,  FFPARS_DST(&htpx_conf_tunnel) }
	, { "deny_url",  FFPARS_TSTR | FFPARS_FLIST,  FFPARS_DST(&htpx_conf_denyurl) }
	, { "try_next_server",  FFPARS_TSTR | FFPARS_FLIST,  FFPARS_DST(&htpx_conf_trynext) }
	, { "pass_query_string",  FFPARS_TBOOL | FFPARS_F8BIT,  FFPARS_DSTOFF(htpxctx, pass_query_string) }
	, { "pass_client_headers",  FFPARS_TBOOL | FFPARS_F8BIT,  FFPARS_DSTOFF(htpxctx, pass_client_hdrs) }

	, { "read_header_growby",  FFPARS_TSIZE | FFPARS_FNOTZERO,  FFPARS_DSTOFF(htpxctx, read_header_growby) }
	, { "max_header_size",  FFPARS_TSIZE | FFPARS_FNOTZERO,  FFPARS_DSTOFF(htpxctx, max_header_size) }
	, { "request_headers",  FFPARS_TOBJ,  FFPARS_DST(&htpx_conf_reqhdrs) }
	, { "response_headers",  FFPARS_TOBJ,  FFPARS_DST(&htpx_conf_resphdrs) }

	, { "write_timeout",  FFPARS_TINT | FFPARS_F16BIT | FFPARS_FNOTZERO,  FFPARS_DSTOFF(htpxctx, write_timeout) }
	, { "read_timeout",  FFPARS_TINT | FFPARS_F16BIT | FFPARS_FNOTZERO,  FFPARS_DSTOFF(htpxctx, read_timeout) }

	, { NULL,  FFPARS_TCLOSE,  FFPARS_DST(&htpx_conf_end) }
};


static int htpxm_conf_log(ffparser_schem *ps, void *unused, ffpars_ctx *confctx)
{
	const ffstr *modname = &ps->vals[0];
	const fsv_log *log_iface;
	const fsv_modinfo *m = htpxm->core->findmod(modname->ptr, modname->len);
	if (m == NULL)
		return FFPARS_EBADVAL;

	log_iface = m->f->iface("log");
	if (log_iface == NULL)
		return FFPARS_EBADVAL;

	htpxm->logctx = log_iface->newctx(confctx, htpxm->logctx);
	if (htpxm->logctx == NULL)
		return FFPARS_EBADVAL;

	return 0;
}

static int htpxm_conf_sktops(ffparser_schem *ps, void *unused, ffpars_ctx *confctx)
{
	ffpars_setargs(confctx, &htpxm->sktopt, fsv_sktopt_conf, FFCNT(fsv_sktopt_conf));
	return 0;
}


static int htpx_conf_connectto(ffparser_schem *ps, htpxctx *px, ffpars_ctx *confctx)
{
	const ffstr *modname = &ps->vals[0];
	const fsv_modinfo *m = htpxm->core->findmod(modname->ptr, modname->len);
	if (m == NULL)
		return FFPARS_EBADVAL;

	px->conn = m->f->iface("connect");
	if (px->conn == NULL)
		return FFPARS_EBADVAL;

	px->conctx = px->conn->newctx(confctx, &fsv_prox_connect_cb);
	if (px->conctx == NULL)
		return FFPARS_EBADVAL;
	return 0;
}

static int htpx_conf_denyurl(ffparser_schem *ps, htpxctx *px, const ffstr *val)
{
	ffstr *denyurls = &px->denyurls;
	if (val->ptr + val->len != ffs_findof(val->ptr, val->len, "*?", 2))
		denyurls = &px->denyurls_wild;
	if (NULL == ffbstr_push(denyurls, val->ptr, val->len))
		return FFPARS_ESYS;
	return 0;
}

static int htpx_conf_reqhdrs_item(ffparser_schem *ps, htpxctx *px, const ffstr *val)
{
	//'Host' header is stored separately
	if (px->conf_req_host) {
		px->conf_req_host = 0;
		ffstr_free(&px->req_host);
		if (NULL == ffstr_copy(&px->req_host, val->ptr, val->len))
			return FFPARS_ESYS;
		return 0;

	} else if (ffstr_ieqcz(val, "host")) {
		px->conf_req_host = 1;
		return 0;
	}

	if (NULL == ffbstr_push(&px->conf_req_hdrs, val->ptr, val->len))
		return FFPARS_ESYS;
	return 0;
}

static const ffpars_arg htpx_conf_args_reqhdrs[] = {
	{ "*", FFPARS_TSTR,  FFPARS_DST(&htpx_conf_reqhdrs_item) }
};

static int htpx_conf_reqhdrs(ffparser_schem *ps, htpxctx *px, ffpars_ctx *confctx)
{
	ffpars_setargs(confctx, px, htpx_conf_args_reqhdrs, FFCNT(htpx_conf_args_reqhdrs));
	return 0;
}

static int htpx_conf_resphdrs_item(ffparser_schem *ps, htpxctx *px, const ffstr *val)
{
	if (NULL == ffbstr_push(&px->conf_resp_hdrs, val->ptr, val->len))
		return FFPARS_ESYS;
	return 0;
}

static const ffpars_arg htpx_conf_args_resphdrs[] = {
	{ "*", FFPARS_TSTR,  FFPARS_DST(&htpx_conf_resphdrs_item) }
};

static int htpx_conf_resphdrs(ffparser_schem *ps, htpxctx *px, ffpars_ctx *confctx)
{
	ffpars_setargs(confctx, px, htpx_conf_args_resphdrs, FFCNT(htpx_conf_args_resphdrs));
	return 0;
}

enum HTPX_TUNNEL {
	HTPX_TUNNEL_OFF
	, HTPX_TUNNEL_ON
	, HTPX_TUNNEL_443
};
static const char *const htpx_tunnel_str[] = { "off", "on", "only443" };
static const ffpars_enumlist htpx_conf_tunnel = {
	htpx_tunnel_str, FFCNT(htpx_tunnel_str), FFPARS_DSTOFF(htpxctx, httptunnel)
};

static const char *const htpx_conf_nextsrv_str[] = {
	"off", "connect_error", "io_error", "bad_response", "5xx_response"
};

static int htpx_conf_trynext(ffparser_schem *ps, htpxctx *px, const ffstr *val)
{
	int i = (int)ffs_findarrz(htpx_conf_nextsrv_str, FFCNT(htpx_conf_nextsrv_str), val->ptr, val->len);
	if (i == -1)
		return FFPARS_EBADVAL;
	if (i == 0) {
		px->try_next_server = HTPX_NEXTSRV_OFF;
		return 0;
	}

	px->try_next_server |= FF_BIT64(i - 1);
	return 0;
}

static int htpx_conf_cache(ffparser_schem *ps, htpxctx *px, ffpars_ctx *args)
{
	htcache_conf_newctx(&px->fcache, args);
	return 0;
}

static int htpx_htdenyurls_init(htpxctx *px)
{
	ffbstr *bs;
	uint hash;
	size_t off = 0;

	if (0 != ffhst_init(&px->htdenyurls, px->denyurls.len))
		return 1;
	px->htdenyurls.cmpkey = &htpx_htdenyurls_cmpkey;

	while (NULL != (bs = ffbstr_next(px->denyurls.ptr, px->denyurls.len, &off, NULL))) {
		hash = ffcrc32_get(bs->data, bs->len, 0);
		if (ffhst_ins(&px->htdenyurls, hash, bs) < 0)
			return 1;
	}

	return 0;
}

static int htpx_conf_end(ffparser_schem *ps, htpxctx *px)
{
	if (px->try_next_server == HTPX_NEXTSRV_DEF)
		px->try_next_server = HTPX_NEXTSRV_CONNECT | HTPX_NEXTSRV_IO;

	if (px->req_host.len == 0) {
		ffstr_setcz(&px->req_host, "$upstream_host");
		px->req_host_static = 1;
	}

	if (px->denyurls.len != 0 && 0 != htpx_htdenyurls_init(px))
		return FFPARS_ESYS;
	return 0;
}


static void * htpxm_create(const fsv_core *core, ffpars_ctx *c, fsv_modinfo *m)
{
	htpxm = ffmem_tcalloc1(htpxmodule);
	if (htpxm == NULL)
		return NULL;
	fflist_init(&htpxm->ctxs);
	fflist_init(&htpxm->cons);
	fsv_sktopt_init(&htpxm->sktopt);
	htpxm->core = core;
	htpxm->page_size = core->conf()->pagesize;
	htpxm->logctx = core->conf()->logctx;

	ffpars_setargs(c, htpxm, htpxm_conf_args, FFCNT(htpxm_conf_args));
	return htpxm;
}

static void htpxctx_free(htpxctx *px)
{
	if (!px->req_host_static)
		ffstr_free(&px->req_host);

	ffhst_free(&px->htdenyurls);
	ffstr_free(&px->denyurls);
	ffstr_free(&px->denyurls_wild);

	ffstr_free(&px->conf_req_hdrs);
	ffstr_free(&px->conf_resp_hdrs);
	ffmem_free(px);
}

static void htpxm_destroy(void)
{
	FFLIST_ENUMSAFE(&htpxm->ctxs, htpxctx_free, htpxctx, sib);
	ffmem_free(htpxm);
	htpxm = NULL;
}

static int htpxm_sig(int signo)
{
	switch (signo) {
	case FSVCORE_SIGSTART:
		htpxm->core->timer(&htpxm->status_tmr, 1000, &htpx_statustimer, htpxm);
		break;

	case FSVCORE_SIGSTOP:
		htpxm->core->timer(&htpxm->status_tmr, 0, NULL, NULL);
		break;
	}

	return 0;
}

static const void * htpxm_iface(const char *name)
{
	if (!ffsz_cmp(name, "http-handler"))
		return &htpx_httpiface;
	else if (!ffsz_cmp(name, "json-status"))
		return &htpx_stat_iface;
	return NULL;
}


static const int htpx_status_jsonmeta[] = {
	FFJSON_TOBJ
	, FFJSON_FKEYNAME, FFJSON_FINTVAL
	, FFJSON_FKEYNAME, FFJSON_FINTVAL
	, FFJSON_FKEYNAME, FFJSON_FINTVAL
	, FFJSON_FKEYNAME, FFJSON_FINTVAL
	, FFJSON_TOBJ
};

static void htpxm_status(const fsv_status *statusmod)
{
	ffjson_cook status_json;
	char buf[4096];
	ffjson_cookinit(&status_json, buf, sizeof(buf));

	ffjson_bufaddv(&status_json, htpx_status_jsonmeta, FFCNT(htpx_status_jsonmeta)
		, FFJSON_CTXOPEN
		, "hits", (int64)ffatom_get(&htpxm->hits)
		, "requests", (int64)ffatom_get(&htpxm->nrequests)
		, "input/sec", (int64)htpxm->read_bps
		, "output/sec", (int64)htpxm->write_bps
		, FFJSON_CTXCLOSE
		, NULL);

	statusmod->setdata(status_json.buf.ptr, status_json.buf.len, 0);
	ffjson_cookfin(&status_json);
}

static void htpx_statustimer(const fftime *now, void *param)
{
	htpxm->write_bps = ffatom_xchg(&htpxm->allwritten, 0);
	htpxm->read_bps = ffatom_xchg(&htpxm->allread, 0);
}


static int htpx_newctx(fsv_http_hdlctx *hc)
{
	htpxctx *px = ffmem_tcalloc1(htpxctx);
	if (px == NULL)
		return 1;
	fflist_ins(&htpxm->ctxs, &px->sib);

	px->read_timeout = px->write_timeout = 65;
	px->max_header_size = 8 * 1024;
	px->read_header_growby = 1024;
	px->respbody_buf_size = 32 * 1024;
	px->httptunnel = HTPX_TUNNEL_OFF;
	px->try_next_server = HTPX_NEXTSRV_DEF;
	px->pass_query_string = 1;
	px->pass_client_hdrs = 1;

	hc->handler = &htpx_httphandler;
	hc->hctx = px;
	px->client_http = hc->http;

	ffpars_setargs(hc->args, px, htpx_conf_args, FFCNT(htpx_conf_args));
	return 0;
}

/** Decide whether request with a CONNECT method can be processed. */
static int htpx_connect_allowed(fsv_httphandler *h)
{
	ffstr host = ffhttp_requrl(h->req, FFURL_PATH);
	ffurl url;
	int er;
	htpxctx *px = h->hctx;

	if (px->httptunnel == HTPX_TUNNEL_OFF) {
		errlog(h->logctx, FSV_LOG_ERR, "CONNECT: not allowed");
		return FFHTTP_405_METHOD_NOT_ALLOWED;
	}

	ffurl_init(&url);
	er = ffurl_parse(&url, host.ptr, host.len);
	if (er != FFURL_EOK) {
		errlog(h->logctx, FSV_LOG_ERR, "CONNECT: invalid URL \"%S\": %s"
			, &host, ffurl_errstr(er));
		return FFHTTP_400_BAD_REQUEST;
	}

	if (px->httptunnel == HTPX_TUNNEL_443 && url.port != 443) {
		errlog(h->logctx, FSV_LOG_ERR, "Rejected CONNECT on port %u", (int)url.port);
		return FFHTTP_403_FORBIDDEN;
	}

	ffurl_rebase(&url, host.ptr, h->req->h.base);
	h->req->url = url;
	return FFHTTP_SLAST;
}

static int htpx_htdenyurls_cmpkey(void *udata, const char *key, size_t keylen, void *param)
{
	const ffbstr *bs = udata;
	return keylen == bs->len && ffs_cmp(key, bs->data, keylen);
}

/** Check whether it's allowed to connect to a requested host. */
static int htpx_checkdeny(htpxctx *px, const ffhttp_request *req, fsv_logctx *logctx)
{
	ffstr host = ffhttp_requrl(req, FFURL_HOST);
	size_t off = 0;
	ffstr wcard;
	uint hash;

	if ('.' == ffarr_back(&host))
		host.len--; //remove the trailing dot in case the host is "host.com."

	hash = ffcrc32_get(host.ptr, host.len, 0);
	if (NULL != ffhst_find(&px->htdenyurls, hash, host.ptr, host.len, NULL))
		goto denied;

	while (0 != ffbstr_next(px->denyurls_wild.ptr, px->denyurls_wild.len, &off, &wcard)) {
		if (0 == ffs_wildcard(wcard.ptr, wcard.len, host.ptr, host.len, 0))
			goto denied;
	}

	return FFHTTP_SLAST;

denied:
	dbglog(logctx, FSV_LOG_DBGFLOW, "the requested URL is forbidden: %S"
		, &host);
	return FFHTTP_403_FORBIDDEN;
}

static void * htpx_newcon(fsv_httphandler *h)
{
	htpxctx *px = h->hctx;
	htpxcon *c = NULL;
	int er = 0, st;

	if (h->req->method == FFHTTP_CONNECT) {
		st = htpx_connect_allowed(h);
		if (st != FFHTTP_SLAST) {
			ffhttp_setstatus(h->resp, st);
			return NULL;
		}
	}

	if (px->denyurls.len != 0 || px->denyurls_wild.len != 0) {
		st = htpx_checkdeny(px, h->req, h->logctx);
		if (st != FFHTTP_SLAST) {
			ffhttp_setstatus(h->resp, st);
			return NULL;
		}
	}

	c = ffmem_tcalloc1(htpxcon);
	if (c == NULL) {
		er = FFERR_BUFALOC;
		st = FFHTTP_500_INTERNAL_SERVER_ERROR;
		goto fin;
	}

	c->hf = h->id;
	c->http = h->httpcon;
	c->logctx = h->logctx;
	c->clientreq = h->req;
	c->clientresp = h->resp;

	c->px = px;
	c->tunnel = (h->req->method == FFHTTP_CONNECT);

	ffatom_inc(&htpxm->hits);
	return c;

fin:
	syserrlog(h->logctx, FSV_LOG_ERR, "%e", er);
	ffhttp_setstatus(h->resp, st);
	return NULL;
}

/** Prepare request-response chain. */
static void htpx_chain_init(htpxcon *c)
{
	const http_submod *sm, *smend;
	htpxfilter *hf;
	size_t n;

	htpx_getreqfilters(c, &sm, &n);
	smend = sm + n;

	if (NULL == ffarr_realloc(&c->reqchain, smend - sm)) {
		syserrlog(c->logctx, FSV_LOG_ERR, "%e", FFERR_BUFALOC);
		c->px->client_http->send(c->hf, NULL, 0, FSV_HTTP_ERROR);
		return;
	}
	ffmem_zero(c->reqchain.ptr, c->reqchain.cap * sizeof(htpxfilter));
	c->reqchain.len = c->reqchain.cap;

	hf = c->reqchain.ptr;
	for (;  sm != smend;  sm++) {
		ffsf_init(&hf->input);
		hf->con = c;
		hf->sm = sm;
		hf->reqfilt = 1;
		if (hf != c->reqchain.ptr)
			fflist_link(&hf->sib, &(hf-1)->sib);
		hf++;
	}

	htpx_getrespfilters(c, &sm, &n);
	smend = sm + n;

	if (NULL == ffarr_realloc(&c->respchain, smend - sm)) {
		syserrlog(c->logctx, FSV_LOG_ERR, "%e", FFERR_BUFALOC);
		c->px->client_http->send(c->hf, NULL, 0, FSV_HTTP_ERROR);
		return;
	}
	ffmem_zero(c->respchain.ptr, c->respchain.cap * sizeof(htpxfilter));
	c->respchain.len = c->respchain.cap;

	hf = c->respchain.ptr;
	for (;  sm != smend;  sm++) {
		ffsf_init(&hf->input);
		hf->con = c;
		hf->sm = sm;
		if (hf != c->respchain.ptr)
			fflist_link(&hf->sib, &(hf-1)->sib);
		hf++;
	}
}

static void htpx_onevent(fsv_httphandler *h)
{
	htpxcon *c = h->id->udata;

	if (h->id->udata == NULL) {
		c = htpx_newcon(h);
		if (c == NULL) {
			h->http->send(h->id, NULL, 0, FSV_HTTP_ERROR);
			return;
		}

		h->id->udata = c;

		c->clientreq_fin = (h->flags & FSV_HTTP_LAST) != 0;
		htpx_chain_init(c);
		c->reqchain.ptr->input = *h->data;
		htpx_callmod(c, c->reqchain.ptr);
		return;
	}

	if (h->flags & FSV_HTTP_SENT) {
		//'http-out' sent some data
		htpx_http.send(c->hfhttpout, NULL, 0, 0);
		return;
	}

	//'http-in': more data is available
	c->clientreq_fin = (h->flags & FSV_HTTP_LAST) != 0;
	((htpxfilter*)c->hfhttpin)->input = *h->data;
	htpx_callmod(c, (htpxfilter*)c->hfhttpin);
}

static void htpx_ondone(fsv_httphandler *h)
{
	htpxcon *c = h->id->udata;

	htpx_chain_free(c);
	ffmem_free(c);
}

/** Print information about the request to an upstream server. */
void htpx_accesslog(htpxcon *c)
{
	ffstr3 addinfo = {0};
	ffstr accesslog_info, srvname = {0}, status = ffhttp_firstline(&c->resp.h);
	fftime stop = {0};
	uint64 sent_body = 0, recvd_body = 0;

	if (c->conn_acq_time.s != 0) {
		stop = htpxm->core->fsv_gettime();
		fftime_diff(&c->conn_acq_time, &stop);
	}

	if (c->nwrite > c->req_hdrs.len)
		sent_body = c->nwrite - c->req_hdrs.len;

	if ((c->resp.h.has_body || c->clientreq->method == FFHTTP_CONNECT)
		&& c->nread > c->resp.h.len)
		recvd_body = c->nread - c->resp.h.len;

	ffhttp_findihdr(&c->resp.h, FFHTTP_SERVER, &srvname);

	ffstr_setcz(&accesslog_info, "\"$upstream_host\" \"$upstream_addr\"");
	(void)htpxm->core->process_vars(&addinfo, &accesslog_info, c->px->conn->getvar, c->serv_id, c->logctx);

	fsv_accesslog(c->logctx, HTPX_MODNAME, NULL,
		"[%L+%U] \"%*s\"" //request
		" [%L+%U] \"%S\"" //response
		" %S \"%S\"" //additional info and "Server"
		" cache:%s"
		"  %Ums" //response time
		//request:
		, (size_t)c->req_hdrs.len, sent_body, (size_t)c->nreqline, c->req_hdrs.ptr
		//response:
		, (size_t)c->resp.h.len, recvd_body, &status
		, &addinfo
		, &srvname
		, (c->cach != NULL) ? htcache_status(c->cach) : ""
		, fftime_ms(&stop));

	ffarr_free(&addinfo);
}

void htpx_errlog(htpxcon *c, int lev, const char *fmt, ...)
{
	char buf[4 * 1024];
	ffstr omsg, status, reqln;
	va_list va;

	va_start(va, fmt);
	omsg.ptr = buf;
	omsg.len = ffs_fmtv(buf, buf + sizeof(buf), fmt, va);
	va_end(va);

	status = ffhttp_firstline(&c->resp.h);
	ffstr_set(&reqln, c->req_hdrs.ptr, c->nreqline);

	if (c->serv_host.len == 0) {
		//'serv_host' isn't assigned in HTTP tunnel mode
		ffurl url;
		ffurl_init(&url);
		if (FFURL_EOK == ffurl_parse(&url, c->serv_url.ptr, c->serv_url.len))
			c->serv_host = ffurl_get(&url, c->serv_url.ptr, FFURL_FULLHOST);
	}

	errlog(c->logctx, lev, "%S.  Upstream server: \"%S\",  request: \"%S\",  response: \"%S\""
		, &omsg, &c->serv_host, &reqln, &status);
}

enum {
	CHAIN_NOP = 1
	, CHAIN_NEXT = 2
};

static void htpx_send(fsv_httpfilter *_hf, const void *buf, size_t len, int flags)
{
	htpxfilter *hf = (htpxfilter*)_hf;
	htpxcon *c = (htpxcon*)hf->con;
	int r = htpx_chain_process(c, &hf, flags);
	if (r == CHAIN_NOP)
		return;

	else if (r == CHAIN_NEXT && !(flags & FSV_HTTP_PASS)) {
		if (len != 0) {
			ffiov_set(&hf->iov, buf, len);
			ffsf_sethdtr(&hf->input.ht, &hf->iov, 1, NULL, 0);
		}
		if (!(flags & FSV_HTTP_MORE))
			ffsf_init(&((htpxfilter*)_hf)->input);
	}

	htpx_callmod(c, hf);
}

static void htpx_sendfile(fsv_httpfilter *_hf, fffd fd, uint64 fsize, uint64 foffset, sf_hdtr *hdtr, int flags)
{
	htpxfilter *hf = (htpxfilter*)_hf;
	htpxcon *c = (htpxcon*)hf->con;
	int r = htpx_chain_process(c, &hf, flags);
	if (r == CHAIN_NOP)
		return;

	else if (r == CHAIN_NEXT && !(flags & FSV_HTTP_PASS)) {
		fffile_mapset(&hf->input.fm, htpxm->page_size, fd, foffset, fsize);
		if (hdtr != NULL)
			hf->input.ht = *hdtr;
		if (!(flags & FSV_HTTP_MORE))
			ffsf_init(&((htpxfilter*)_hf)->input);
	}

	htpx_callmod(c, hf);
}

static void htpx_chain_error(htpxcon *c, htpxfilter *hf)
{
	dbglog(c->logctx, FSV_LOG_HTTPFILT, "%s: '%s' reported error"
		, FILT_TYPE(hf->reqfilt), hf->sm->modname);
	htpx_chain_free(c);
	c->px->client_http->send(c->hf, NULL, 0, FSV_HTTP_ERROR);
}

static int htpx_chain_process(htpxcon *c, htpxfilter **phf, uint flags)
{
	htpxfilter *hf = *phf;
	fflist_cursor cur;
	uint r;

	hf->flags = flags | (hf->flags & (FSV_HTTP_ASIS | FSV_HTTP_PUSH));

	if (hf->flags & FSV_HTTP_ERROR) {
		htpx_chain_error(c, hf);
		return 1;
	}

	dbglog(c->logctx, FSV_LOG_HTTPFILT, "%s: '%s' returned: back:%u, more:%u, done:%u"
		, FILT_TYPE(hf->reqfilt), hf->sm->modname
		, (hf->flags & FSV_HTTP_BACK) != 0, (hf->flags & FSV_HTTP_MORE) != 0, (hf->flags & FSV_HTTP_DONE) != 0);

	if (flags & FSV_HTTP_BACK)
		r = FFLIST_CUR_PREV;
	else
		r = FFLIST_CUR_NEXT | FFLIST_CUR_BOUNCE
			| ((flags & FSV_HTTP_MORE) ? FFLIST_CUR_SAMEIFBOUNCE : 0);

	if (flags & FSV_HTTP_NOINPUT)
		r |= FFLIST_CUR_RMPREV;
	if (flags & FSV_HTTP_NONEXT)
		r |= FFLIST_CUR_RMNEXT;
	if (flags & FSV_HTTP_DONE)
		r |= FFLIST_CUR_RM;
	else if (!(flags & FSV_HTTP_MORE))
		r |= FFLIST_CUR_RMFIRST;

	cur = &hf->sib;
	r = fflist_curshift(&cur, r, fflist_sentl(&cur));

	switch (r) {
	case FFLIST_CUR_NONEXT:
		goto done;

	case FFLIST_CUR_NOPREV:
		errlog(c->logctx, FSV_LOG_ERR, "%s: no more input data for '%s'"
			, FILT_TYPE(hf->reqfilt), hf->sm->modname);
		htpx_chain_error(c, hf);
		return CHAIN_NOP;

	case FFLIST_CUR_NEXT:
		*phf = FF_GETPTR(htpxfilter, sib, cur);
		(*phf)->flags |= (hf->flags & (FSV_HTTP_PUSH | FSV_HTTP_ASIS));

		FF_ASSERT(ffsf_empty(&(*phf)->input));
		if (flags & FSV_HTTP_PASS) {
			(*phf)->input = hf->input;
			ffsf_init(&hf->input);
		}

		return CHAIN_NEXT;
	}

	ffsf_init(&hf->input);

	// find the filter to the left that has more output data
	for (;;) {
		hf = FF_GETPTR(htpxfilter, sib, cur);
		if (hf->flags & FSV_HTTP_MORE) {
			*phf = hf;
			break;
		}
		r = fflist_curshift(&cur, FFLIST_CUR_PREV, fflist_sentl(&cur));
	}
	hf->sentdata = 1;
	return 0;

done:
	if (hf->reqfilt)
		c->req_fin = 1;

	dbglog(c->logctx, FSV_LOG_HTTPFILT, "%s: done"
		, FILT_TYPE(hf->reqfilt));

	if (c->resp_fin)
		c->px->client_http->send(c->hf, NULL, 0, 0);

	return 1;
}

void htpx_callmod(htpxcon *c, htpxfilter *hf)
{
	fsv_httphandler p = {0};

	p.id = (fsv_httpfilter*)hf;
	p.data = &hf->input;
	p.flags = (hf->sib.prev == NULL) ? FSV_HTTP_LAST : 0;
	p.flags |= (hf->flags & (FSV_HTTP_PUSH | FSV_HTTP_ASIS));

	if (hf->sentdata) {
		hf->sentdata = 0;
		p.flags |= FSV_HTTP_SENT;
	}

	p.hctx = hf->sm->hctx;
	p.http = &htpx_http;
	p.httpcon = (fsv_httpcon*)c;
	p.logctx = c->logctx;
	p.req = NULL;
	p.resp = NULL;

	dbglog(c->logctx, FSV_LOG_HTTPFILT, "%s: calling '%s'. data: %U. last:%u"
		, FILT_TYPE(hf->reqfilt), hf->sm->modname, ffsf_len(p.data)
		, (p.flags & FSV_HTTP_LAST) != 0);

	hf->sm->handler->onevent(&p);
}

static void htpx_finfilter(htpxcon *c, htpxfilter *hf)
{
	if (hf->hf.udata != NULL) {
		fsv_httphandler p = {0};
		p.id = (fsv_httpfilter*)hf;
		p.data = &hf->input;
		p.hctx = hf->sm->hctx;
		p.http = &htpx_http;
		p.httpcon = (fsv_httpcon*)c;
		p.logctx = c->logctx;
		p.req = NULL;
		p.resp = NULL;

		dbglog(c->logctx, FSV_LOG_HTTPFILT, "%s: closing '%s'"
			, FILT_TYPE(hf->reqfilt), hf->sm->modname);

		hf->sm->handler->ondone(&p);
		hf->hf.udata = NULL;
	}

	ffsf_close(&hf->input);
}

static ssize_t htpx_getvar(void *obj, const char *name, size_t namelen, void *dst, size_t cap)
{
	htpxcon *c = obj;
	return c->px->client_http->getvar(c->http, name, namelen, dst, cap);
}

static void htpx_chain_free(htpxcon *c)
{
	htpxfilter *hf;

	FFARR_WALK(&c->reqchain, hf) {
		htpx_finfilter(c, hf);
	}
	ffarr_free(&c->reqchain);

	FFARR_WALK(&c->respchain, hf) {
		htpx_finfilter(c, hf);
	}
	ffarr_free(&c->respchain);
}

/** Re-initialize and restart filter chain using the next upstream server. */
int htpx_trynextserv(htpxcon *c)
{
	if (0 != htpx_freeconn(c, 1))
		return 1; //no more servers to try

	htpx_chain_free(c);
	c->nwrite = 0;
	c->nread = 0;
	htpx_chain_init(c);
	htpx_callmod(c, c->reqchain.ptr);
	return 0;
}

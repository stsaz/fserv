/** Default request-response filters for HTTP client.
Copyright 2014 Simon Zolin.
*/

#include <http-proxy/proxy.h>


/*
http-in -> connect -> send-req
recv-resp -> parse-resp -> recv-body -> cont-len|chunked -> http-out

CACHE, no-revalidate:
http-in -> cache-req

CACHE, full cycle:
http-in -> cache-req -> connect -> send-req
recv-resp -> parse-resp -> recv-body -> cont-len|chunked -> cache-resp -> http-out

TUNNEL:
http-in -> connect -> recv-io -> http-out
send-io -> http-out
*/


static void htpx_resettimer(htpxcon *c, int val);
static void htpx_stoptimer(htpxcon *c, int t);
static void htpx_onexpire(const fftime *now, void *tag);

static void htpx_connect(fsv_httphandler *h);
static void htpx_connect_done(fsv_httphandler *h);
static int htpx_getnextserv(htpxcon *c);
// htpx_onconnect()
static const fsv_http_cb htpx_connect_handler = {
	&htpx_connect, &htpx_connect_done
};

static void htpx_reqsend(fsv_httphandler *h);
static void htpx_reqsend_done(fsv_httphandler *h);
static void htpx_sendrequest(void *udata);
static int htpx_prepsf(htpxcon *c, ffsf *sf);
static void htpx_addhdrs_fromclient(htpxcon *c, ffhttp_cook *req);
static int htpx_addreqhdrs_fromconf(htpxcon *c, ffhttp_cook *req, ffstr3 *tmp);
static int htpx_mkreq(htpxcon *c, ffstr *dstbuf, uint64 cont_len);
static int htpx_mkreqline(htpxcon *c, ffhttp_cook *ck, const ffurl *serv);
static const fsv_http_cb htpx_reqsend_handler = {
	&htpx_reqsend, &htpx_reqsend_done
};

static void htpx_resprecv(fsv_httphandler *h);
static void htpx_resprecv_done(fsv_httphandler *h);
static void htpx_startrecv(void *udata);
static void htpx_readresponse(void *udata);
static const fsv_http_cb htpx_resprecv_handler = {
	&htpx_resprecv, &htpx_resprecv_done
};

static void htpx_respparse(fsv_httphandler *h);
static void htpx_respparse_done(fsv_httphandler *h);
static void htpx_printresp(htpxcon *c);
static const fsv_http_cb htpx_respparse_handler = {
	&htpx_respparse, &htpx_respparse_done
};

static void htpx_bodyrecv(fsv_httphandler *h);
static void htpx_bodyrecv_done(fsv_httphandler *h);
static void htpx_readbody(void *udata);
static const fsv_http_cb htpx_recvbody_handler = {
	&htpx_bodyrecv, &htpx_bodyrecv_done
};

static void htpx_contlen_req(fsv_httphandler *h);
static void htpx_contlen_req_done(fsv_httphandler *h);
static const fsv_http_cb htpx_contlen_recv_filter = {
	&htpx_contlen_req, &htpx_contlen_req_done
};

static void htpx_chunked_req(fsv_httphandler *h);
static void htpx_chunked_req_done(fsv_httphandler *h);
static const fsv_http_cb htpx_chunked_req_filter = {
	&htpx_chunked_req, &htpx_chunked_req_done
};

static void htpx_in(fsv_httphandler *h);
static const fsv_http_cb htpx_in_filter = {
	&htpx_in, NULL
};
static void htpx_out(fsv_httphandler *h);
static void htpx_out_done(fsv_httphandler *h);
static int htpx_addresphdrs_fromconf(htpxcon *c, ffhttp_cook *cook);
static const fsv_http_cb htpx_out_filter = {
	&htpx_out, &htpx_out_done
};

static void htpx_sendio(fsv_httphandler *h);
static void htpx_sendio_done(fsv_httphandler *h);
static const fsv_http_cb htpx_sendio_filter = {
	&htpx_sendio, &htpx_sendio_done
};

static void htpx_recvio(fsv_httphandler *h);
static void htpx_recvio_done(fsv_httphandler *h);
static void htpx_readdata(void *udata);
static const fsv_http_cb htpx_recvio_filter = {
	&htpx_recvio, &htpx_recvio_done
};

static const http_submod def_reqfilts[] = {
	{ "http-in", NULL, &htpx_in_filter }
	, { "connect", NULL, &htpx_connect_handler }
	, { "send-req", NULL, &htpx_reqsend_handler }
};
static const http_submod def_respfilts[] = {
	{ "recv-resp", NULL, &htpx_resprecv_handler }
	, { "parse-resp", NULL, &htpx_respparse_handler }
	, { "recv-body", NULL, &htpx_recvbody_handler }
	, { "cont-len", NULL, &htpx_contlen_recv_filter }
	, { "chunked", NULL, &htpx_chunked_req_filter }
	, { "http-out", NULL, &htpx_out_filter }
};

static const http_submod def_cache_reqfilts[] = {
	{ "http-in", NULL, &htpx_in_filter }
	, { "cache-req", NULL, &htcache_req_htpfilt }
	, { "connect", NULL, &htpx_connect_handler }
	, { "send-req", NULL, &htpx_reqsend_handler }
};
static const http_submod def_cache_respfilts[] = {
	{ "recv-resp", NULL, &htpx_resprecv_handler }
	, { "parse-resp", NULL, &htpx_respparse_handler }
	, { "recv-body", NULL, &htpx_recvbody_handler }
	, { "cont-len", NULL, &htpx_contlen_recv_filter }
	, { "chunked", NULL, &htpx_chunked_req_filter }
	, { "cache-resp", NULL, &htcache_resp_htpfilt }
	, { "http-out", NULL, &htpx_out_filter }
};

static const http_submod def_tunnel_reqfilts[] = {
	{ "http-in", NULL, &htpx_in_filter }
	, { "connect", NULL, &htpx_connect_handler }
	, { "send-data", NULL, &htpx_sendio_filter }
};
static const http_submod def_tunnel_respfilts[] = {
	{ "recv-data", NULL, &htpx_recvio_filter }
	, { "http-out", NULL, &htpx_out_filter }
};

void htpx_getreqfilters(htpxcon *c, const http_submod **sm, size_t *n)
{
	*sm = def_reqfilts;
	*n = FFCNT(def_reqfilts);

	if (c->tunnel) {
		*sm = def_tunnel_reqfilts;
		*n = FFCNT(def_tunnel_reqfilts);

	} else if (c->px->fcache.cache != NULL) {
		*sm = def_cache_reqfilts;
		*n = FFCNT(def_cache_reqfilts);
	}
}

void htpx_getrespfilters(htpxcon *c, const http_submod **sm, size_t *n)
{
	*sm = def_respfilts;
	*n = FFCNT(def_respfilts);

	if (c->tunnel) {
		*sm = def_tunnel_respfilts;
		*n = FFCNT(def_tunnel_respfilts);

	} else if (c->px->fcache.cache != NULL) {
		*sm = def_cache_respfilts;
		*n = FFCNT(def_cache_respfilts);
	}
}


/** I/O timer.
. Don't set the timer, if the channel's already active.
. If both channels are active, set timer_value = max(read_timeout, write_timeout).
  Then, when a read channel signals, set timer_value = write_timeout, and v.v.
. When a timer expires, cancel pending operations for both channels. */

enum HTPX_TMR {
	HTPX_TMR_READ = 1, HTPX_TMR_WRITE = 2
};

static const char *const stmr[] = { "read", "write" };
#define TMR_NAME(t)  stmr[(t) == HTPX_TMR_WRITE]

static void htpx_resettimer(htpxcon *c, int t)
{
	int val = 0;
	uint tmr_when;

	if (c->tmr_flags & t)
		return;

	if (t & HTPX_TMR_READ)
		val = c->px->read_timeout;
	else if (t & HTPX_TMR_WRITE)
		val = c->px->write_timeout;

	tmr_when = htpxm->core->fsv_gettime().s + val;
	if (tmr_when <= c->tmr_when)
		return;

	dbglog(c->logctx, FSV_LOG_DBGNET, "%s timer set: %us", TMR_NAME(t), val);

	c->tmr_flags = t;
	c->tmr_when = tmr_when;
	htpxm->core->timer(&c->tmr, -val * 1000, &htpx_onexpire, c);
}

static void htpx_stoptimer(htpxcon *c, int t)
{
	if (!(c->tmr_flags & t))
		return;

	c->tmr_when = 0;
	if (c->tmr_flags & ~t) {
		t = (c->tmr_flags & ~t);
		c->tmr_flags = 0;
		htpx_resettimer(c, t);
		return;
	}

	c->tmr_flags = 0;
	dbglog(c->logctx, FSV_LOG_DBGNET, "%s timer stop", TMR_NAME(t));
	htpxm->core->fsv_timerstop(&c->tmr);
}

static void htpx_onexpire(const fftime *now, void *tag)
{
	htpxcon *c = tag;
	c->tmr_when = 0;
	c->tmr_flags = 0;
	c->px->conn->cancelio(c->serv_id, FFAIO_RW, NULL, c);
}


/** Connect to an upstream server. */
static void htpx_connect(fsv_httphandler *h)
{
	htpxcon *c = (htpxcon*)h->httpcon;
	FF_ASSERT(h->id->udata == NULL);
	h->id->udata = (void*)1;
	c->hfconn = h->id;

	if (c->serv_id == NULL && 0 != htpx_getnextserv(c)) {
		ffhttp_setstatus(c->clientresp, FFHTTP_502_BAD_GATEWAY);
		h->http->send(h->id, NULL, 0, FSV_HTTP_ERROR);
		return;
	}

	if (c->nextsrv)
		c->nextsrv = 0;

	c->px->conn->connect(c->serv_id, 0);
}

static void htpx_connect_done(fsv_httphandler *h)
{
	htpxcon *c = (htpxcon*)h->httpcon;
	htpxm->core->utask(&c->rtsk, FSVCORE_TASKDEL);
	if (!c->nextsrv)
		htpx_freeconn(c, 0);
}

/** Release the connection object.
Mark the connection as 'keep-alive' if response was complete.
If nextsrv=1, the chain *must* be restarted, otherwise c->serv_id won't be released. */
int htpx_freeconn(htpxcon *c, int nextsrv)
{
	int f;

	if (c->serv_id == NULL)
		return 0; //already released

	htpx_accesslog(c);

	if (nextsrv) {
		if (0 != htpx_getnextserv(c))
			return 1;

		/* Make c->serv_id survive the reset of filter chain - it won't be released in htpx_connect_done().
		The new c->serv_id will be used in the next call to htpx_connect(). */
		c->nextsrv = 1;
		return 0;
	}

	f = 0;
	if (c->resp_fin && !c->resp.h.conn_close)
		f = FSV_CONN_KEEPALIVE;
	c->px->conn->fin(c->serv_id, f);
	c->serv_id = NULL;
	c->serv_url.len = 0;
	return 0;
}

/** Get the next valid upstream server. */
static int htpx_getnextserv(htpxcon *c)
{
	int rc;
	fsv_conn_new cn;

	cn.con = c->serv_id;
	cn.logctx = c->logctx;
	cn.userptr = c;
	rc = c->px->conn->getserv(c->px->conctx, &cn, 0);
	if (rc != 0) {
		c->serv_id = NULL;
		c->serv_url.len = 0;
		return rc;
	}

	c->serv_id = cn.con;
	c->serv_url = cn.url;
	return 0;
}

/** Process the result of connection. */
void htpx_onconnect(void *obj, int result)
{
	htpxcon *c = obj;

	if (result != 0) {

		if (!(c->px->try_next_server & HTPX_NEXTSRV_CONNECT)) {
			ffhttp_setstatus(c->clientresp, FFHTTP_504_GATEWAY_TIMEOUT);
			goto fail;
		}

		if (0 != htpx_getnextserv(c)) {
			ffhttp_setstatus(c->clientresp, FFHTTP_504_GATEWAY_TIMEOUT);
			goto fail;
		}

		c->px->conn->connect(c->serv_id, 0);
		return;
	}

	{
	ffskt sk;
	c->px->conn->fsv_getvarcz(c->serv_id, "socket_fd", &sk, sizeof(ffskt));
	if (!fsv_sktopt_set(&htpxm->sktopt, sk))
		syserrlog(c->logctx, FSV_LOG_ERR, "%e", FFERR_SKTOPT);
	}

	c->conn_acq_time = htpxm->core->fsv_gettime();
	fsv_taskpost(htpxm->core, &c->rtsk, &htpx_startrecv, c);

	htpx_http.send(c->hfconn, NULL, 0, FSV_HTTP_PASS | FSV_HTTP_DONE);
	return;

fail:
	htpx_http.send(c->hfconn, NULL, 0, FSV_HTTP_ERROR);
}


/** Pass input data from the parent module to the next filter in chain. */
static void htpx_in(fsv_httphandler *h)
{
	htpxcon *c = (htpxcon*)h->httpcon;
	c->hfhttpin = h->id;

	if (h->flags & FSV_HTTP_SENT) {
		c->px->client_http->send(c->hf, NULL, 0, FSV_HTTP_BACK | ((c->resp_fin) ? 0 : FSV_HTTP_MORE));
		return;
	}

	htpx_http.send(h->id, NULL, 0, FSV_HTTP_PASS | ((c->clientreq_fin) ? 0 : FSV_HTTP_MORE));
}


/** Prepare and send request. */
static void htpx_reqsend(fsv_httphandler *h)
{
	htpxcon *c = (htpxcon*)h->httpcon;

	c->sf = h->data;

	if (h->id->udata == NULL) {

		if (c->clientreq->h.has_body && !(h->flags & FSV_HTTP_LAST) && c->clientreq->h.cont_len == -1) {
			errlog(c->logctx, FSV_LOG_ERR, "chunked request body is not supported");
			ffhttp_setstatus(c->clientresp, FFHTTP_501_NOT_IMPLEMENTED);
			goto fail;
		}

		c->req_cont_len = c->clientreq->h.cont_len;
		if (c->clientreq->h.has_body && (h->flags & FSV_HTTP_LAST))
			c->req_cont_len = ffsf_len(c->sf);
		if (0 != htpx_mkreq(c, &c->req_hdrs, c->req_cont_len)) {
			goto fail;
		}
		dbglog(c->logctx, FSV_LOG_DBGNET, "sending request [%L] %S"
			, (size_t)c->req_hdrs.len, &c->req_hdrs);
		h->id->udata = (void*)1;

		if (0 != htpx_prepsf(c, h->data)) {
			syserrlog(c->logctx, FSV_LOG_ERR, "%e", FFERR_BUFALOC);
			goto fail;
		}

		ffatom_inc(&htpxm->nrequests);
	}

	if (c->clientreq->h.has_body) {
		dbglog(c->logctx, FSV_LOG_DBGNET, "sending data +%U, [%U/%D]..."
			, ffsf_len(c->sf), c->nwrite, c->req_cont_len);
	}
	c->hfsend = h->id;
	htpx_sendrequest(h->httpcon);
	return;

fail:
	htpx_http.send(h->id, NULL, 0, FSV_HTTP_ERROR);
}

static void htpx_reqsend_done(fsv_httphandler *h)
{
	htpxcon *c = (htpxcon*)h->httpcon;
	htpx_stoptimer(c, HTPX_TMR_WRITE);
	ffstr_free(&c->req_hdrs);
	ffarr_free(&c->iovs);
}

/** Join request headers with body into one ffsf structure. */
static int htpx_prepsf(htpxcon *c, ffsf *sf)
{
	if (ffsf_empty(sf)) {
		ffiov_set(&c->iov, c->req_hdrs.ptr, c->req_hdrs.len);
		sf->ht.headers = &c->iov;
		sf->ht.hdr_cnt = 1;
		return 0;
	}

	// alloc space for http headers
	if (NULL == ffarr_realloc(&c->iovs, 1 + sf->ht.hdr_cnt + sf->ht.trl_cnt)) {
		return 1;
	}
	ffiov_copyhdtr(c->iovs.ptr + 1, c->iovs.len - 1, &sf->ht);

	ffiov_set(c->iovs.ptr, c->req_hdrs.ptr, c->req_hdrs.len);
	sf->ht.headers = c->iovs.ptr;
	sf->ht.hdr_cnt++;
	sf->ht.trailers = c->iovs.ptr + sf->ht.hdr_cnt;
	//sf->ht.trl_cnt;
	return 0;
}

/** make request line: "METHOD SERVER_PATH/REQUEST_PATH [? REQUEST_QUERYSTRING] HTTP/1.1" */
static int htpx_mkreqline(htpxcon *c, ffhttp_cook *ck, const ffurl *serv)
{
	ffstr full_uri = {0}
		, serv_path = ffurl_get(serv, c->serv_url.ptr, FFURL_PATH)
		, req_path = ffhttp_reqpath(c->clientreq)
		, qs = ffhttp_requrl(c->clientreq, FFURL_QS)
		, meth = ffhttp_reqmethod(c->clientreq);
	size_t cap;

	cap = serv_path.len + ffuri_escape(NULL, 0, req_path.ptr, req_path.len, FFURI_ESC_WHOLE);
	if (c->px->pass_query_string)
		cap += FFSLEN("?") + qs.len;

	if (!ffstr_alloc(&full_uri, cap)) {
		syserrlog(c->logctx, FSV_LOG_ERR, "%e", FFERR_BUFALOC);
		return 1;
	}

	ffstr_cat(&full_uri, cap, serv_path.ptr, serv_path.len);

	//if server path is without last slash, e.g. "/path/file", and request path is "/", we don't append '/'
	if (full_uri.len == 0 || !ffstr_eqcz(&req_path, "/"))
		full_uri.len += ffuri_escape(ffarr_end(&full_uri), cap - full_uri.len
			, req_path.ptr, req_path.len, FFURI_ESC_WHOLE);

	if (c->px->pass_query_string && qs.len != 0)
		full_uri.len += ffs_fmt(ffarr_end(&full_uri), full_uri.ptr + cap, "?%S", &qs);

	ffhttp_addrequest(ck, meth.ptr, meth.len, full_uri.ptr, full_uri.len);
	c->nreqline = (uint)(ck->buf.len - FFSLEN(FFCRLF));

	ffstr_free(&full_uri);
	return 0;
}

//per-connection HTTP request headers
static const byte htpx_perconn_reqhdrs[] = {
	FFHTTP_HOST, FFHTTP_CONNECTION
	, FFHTTP_KEEPALIVE, FFHTTP_TE, FFHTTP_UPGRADE
	, FFHTTP_CONTENT_LENGTH, FFHTTP_TRANSFER_ENCODING
	, FFHTTP_PROXY_CONNECTION, FFHTTP_PROXY_AUTHORIZATION
};

/** Add headers from the client request. */
static void htpx_addhdrs_fromclient(htpxcon *c, ffhttp_cook *req)
{
	int i = 0;
	ffstr k, v;

	for (;;) {
		int ihdr = ffhttp_gethdr(&c->clientreq->h, i++, &k, &v);
		if (ihdr == FFHTTP_DONE)
			break;

		if (NULL != ffs_findc((char*)htpx_perconn_reqhdrs, FFCNT(htpx_perconn_reqhdrs), ihdr))
			continue;

		if (c->cach != NULL && htcache_ignorehdr(c->cach, ihdr))
			continue;

		ffhttp_addhdr_str(req, &k, &v);
	}
}

/** Add request headers specified in configuration. */
static int htpx_addreqhdrs_fromconf(htpxcon *c, ffhttp_cook *req, ffstr3 *tmp)
{
	ffstr k, v;
	size_t off = 0;

	for (;;) {

		if (0 == ffbstr_next(c->px->conf_req_hdrs.ptr, c->px->conf_req_hdrs.len, &off, &k)
			|| 0 == ffbstr_next(c->px->conf_req_hdrs.ptr, c->px->conf_req_hdrs.len, &off, &v))
			break;

		if (0 != htpxm->core->process_vars(tmp, &v, c->px->conn->getvar, c->serv_id, c->logctx))
			return FFERR_BUFALOC;

		ffhttp_addhdr_str(req, &k, (ffstr*)tmp);
	}

	return FFERR_OK;
}

/** Prepare HTTP request.
Add conditional headers, if we have to revalidate our cached document. */
static int htpx_mkreq(htpxcon *c, ffstr *dstbuf, uint64 cont_len)
{
	int er;
	int ret;
	ffstr3 tmp = {0};
	ffstr schem;
	ffhttp_cook req;
	ffurl url;

	ffhttp_cookinit(&req, NULL, 0);

	ffurl_init(&url);
	er = ffurl_parse(&url, c->serv_url.ptr, c->serv_url.len);
	if (er != FFURL_EOK) {
		errlog(c->logctx, FSV_LOG_ERR, "%S: invalid URL: %s", &c->serv_url, ffurl_errstr(er));
		ret = FFERR_INTERNAL;
		goto done;
	}

	er = htpx_mkreqline(c, &req, &url);
	if (er != 0) {
		ret = FFERR_BUFALOC;
		goto done;
	}
	c->serv_host = ffurl_get(&url, c->serv_url.ptr, FFURL_FULLHOST);
	schem = ffurl_get(&url, c->serv_url.ptr, FFURL_SCHEME);

	if (0 != htpxm->core->process_vars(&tmp, &c->px->req_host, c->px->conn->getvar, c->serv_id, c->logctx)) {
		ret = FFERR_BUFALOC;
		goto done;
	}
	/* Don't use port number in Host header field if the port matches the scheme.
	Since $upstream_host always contains port number, cut it off here. */
	if (url.portlen == 0)
		tmp.len = ffs_rfind(tmp.ptr, tmp.len, ':') - tmp.ptr;
	else if (c->px->req_host_static && url.port == ffuri_scheme2port(schem.ptr, schem.len))
		tmp.len -= FFSLEN(":") + url.portlen;
	ffhttp_addihdr(&req, FFHTTP_HOST, tmp.ptr, tmp.len);

	req.cont_len = cont_len;
	ffhttp_cookflush(&req);

	if (c->px->pass_client_hdrs)
		htpx_addhdrs_fromclient(c, &req);

	if (c->cach != NULL)
		htcache_addhdr(c->cach, &req);

	ret = htpx_addreqhdrs_fromconf(c, &req, &tmp);
	if (ret != 0)
		goto done;

	if (0 != ffhttp_cookfin(&req)) {
		ret = FFERR_BUFALOC;
		goto done;
	}

	ret = 0;

done:
	ffarr_free(&tmp);
	if (ret == FFERR_BUFALOC)
		syserrlog(c->logctx, FSV_LOG_ERR, "%e", ret);
	ffstr_acqstr3(dstbuf, &req.buf);
	ffhttp_cookdestroy(&req);
	return ret;
}

static void htpx_sendrequest(void *udata)
{
	htpxcon *c = udata;
	ssize_t r;

	for (;;) {

		r = c->px->conn->sendfile(c->serv_id, c->sf, &htpx_sendrequest, c);
		if (r == FSV_IO_ASYNC) {
			htpx_resettimer(c, HTPX_TMR_WRITE);
			return;
		}

		htpx_stoptimer(c, HTPX_TMR_WRITE);

		if (r == FSV_IO_ERR) {

			if (fferr_last() == ECANCELED) {
				htpx_errlog(c, FSV_LOG_ERR, "send data: timeout");
				ffhttp_setstatus(c->clientresp, FFHTTP_504_GATEWAY_TIMEOUT);
				goto fail;
			}

			syserrlog(c->logctx, FSV_LOG_ERR, "%e", FFERR_WRITE);

			if (!c->clientreq->h.has_body && !c->tunnel
				&& (c->px->try_next_server & HTPX_NEXTSRV_IO)) {

				if (0 == htpx_trynextserv(c))
					return;
			}

			ffhttp_setstatus(c->clientresp, FFHTTP_502_BAD_GATEWAY);
			goto fail;
		}

		c->nwrite += r;
		ffatom_add(&htpxm->allwritten, r);

		if (0 == ffsf_shift(c->sf, r))
			break;
	}

	htpx_http.send(c->hfsend, NULL, 0, (c->clientreq_fin) ? FSV_HTTP_DONE : FSV_HTTP_BACK);
	return;

fail:
	htpx_http.send(c->hfsend, NULL, 0, FSV_HTTP_ERROR);
}


static void htpx_startrecv(void *udata)
{
	htpxcon *c = udata;
	htpx_callmod(c, c->respchain.ptr);
}

static void htpx_resprecv(fsv_httphandler *h)
{
	htpxcon *c = (htpxcon*)h->httpcon;

	if (h->id->udata == NULL) {
		h->id->udata = (void*)1;
	}

	dbglog(c->logctx, FSV_LOG_DBGNET, "receiving data...");
	c->hfrecv = h->id;
	htpx_readresponse(h->httpcon);
}

static void htpx_resprecv_done(fsv_httphandler *h)
{
	htpxcon *c = (htpxcon*)h->httpcon;
	htpx_stoptimer(c, HTPX_TMR_READ);
	ffarr_free(&c->hdr);
}

void htpx_readresponse(void *udata)
{
	htpxcon *c = udata;
	ssize_t r;
	ffstr buf;

	if (ffarr_isfull(&c->hdr)
		&& NULL == ffarr_grow(&c->hdr, c->px->read_header_growby, 0)) {
		syserrlog(c->logctx, FSV_LOG_ERR, "%e", FFERR_BUFGROW);
		goto fail;
	}
	ffstr_set(&buf, ffarr_end(&c->hdr), ffarr_unused(&c->hdr));

	r = c->px->conn->recv(c->serv_id, buf.ptr, buf.len, &htpx_readresponse, c);
	if (r == FSV_IO_ASYNC) {
		htpx_resettimer(c, HTPX_TMR_READ);
		return;
	}

	htpx_stoptimer(c, HTPX_TMR_READ);

	if (r == FSV_IO_ESHUT)
		htpx_errlog(c, FSV_LOG_ERR, "read headers: the remote server closed the connection");

	else if (r == FSV_IO_ERR) {

		if (fferr_last() == ECANCELED) {
			htpx_errlog(c, FSV_LOG_ERR, "read headers: timeout");
			ffhttp_setstatus(c->clientresp, FFHTTP_504_GATEWAY_TIMEOUT);
			goto fail;
		}

		htpx_errlog(c, FSV_LOG_ERR, "read headers: %E", fferr_last());
	}

	if (r == FSV_IO_ESHUT || r == FSV_IO_ERR) {
		if (!c->clientreq->h.has_body && (c->px->try_next_server & HTPX_NEXTSRV_IO)) {
			if (0 == htpx_trynextserv(c))
				return;
		}

		ffhttp_setstatus(c->clientresp, FFHTTP_502_BAD_GATEWAY);
		goto fail;
	}

	c->hdr.len += r;
	c->nread += r;
	htpxm->allread += r;
	dbglog(c->logctx, FSV_LOG_DBGNET, "received: +%L [%U]", (size_t)r, (int64)c->nread);

	htpx_http.send(c->hfrecv, c->hdr.ptr, c->hdr.len, FSV_HTTP_MORE);
	return;

fail:
	htpx_http.send(c->hfrecv, NULL, 0, FSV_HTTP_ERROR);
}


static void htpx_respparse(fsv_httphandler *h)
{
	htpxcon *c = (htpxcon*)h->httpcon;
	ffstr respdata, body;
	int r = FFHTTP_OK;

	if (h->id->udata == NULL) {
		ffhttp_respinit(&c->resp);
		h->id->udata = (void*)1;
	}

	ffstr_setiovec(&respdata, &h->data->ht.headers[0]);

	if (c->resp.h.firstline_len == 0)
		r = ffhttp_respparse(&c->resp, respdata.ptr, respdata.len, FFHTTP_IGN_STATUS_PROTO);
	while (r == FFHTTP_OK) {
		r = ffhttp_respparsehdr(&c->resp, respdata.ptr, respdata.len);
	}

	if (r == FFHTTP_MORE) {
		if (c->hdr.len == c->px->max_header_size) {
			htpx_errlog(c, FSV_LOG_ERR, "reached max header size limit");
			ffhttp_setstatus(c->clientresp, FFHTTP_502_BAD_GATEWAY);
			goto fail;
		}

		h->http->send(h->id, NULL, 0, FSV_HTTP_BACK);
		return;
	}

	if (r != FFHTTP_DONE) {
		htpx_errlog(c, FSV_LOG_ERR, "%s", ffhttp_errstr(r));

		if (!c->clientreq->h.has_body && (c->px->try_next_server & HTPX_NEXTSRV_BAD)) {
			if (0 == htpx_trynextserv(c))
				return;
		}

		ffhttp_setstatus(c->clientresp, FFHTTP_502_BAD_GATEWAY);
		goto fail;
	}

	htpx_printresp(c);

	if (c->resp.h.has_body && c->clientreq->method == FFHTTP_HEAD)
		c->resp.h.has_body = 0;

	if (c->resp.code / 100 == 5 && (c->px->try_next_server & HTPX_NEXTSRV_5XX)
		&& !c->clientreq->h.has_body) {

		if (0 == htpx_trynextserv(c))
			return;
	}

	if (ffhttp_respnobody(c->resp.code))
		c->resp_fin = 1;

	ffstr_set(&body, c->resp.h.base + c->resp.h.len, respdata.len - c->resp.h.len);
	h->http->send(h->id, body.ptr, body.len, FSV_HTTP_NOINPUT | FSV_HTTP_DONE);
	return;

fail:
	h->http->send(h->id, NULL, 0, FSV_HTTP_ERROR);
}

static void htpx_respparse_done(fsv_httphandler *h)
{
	htpxcon *c = (htpxcon*)h->httpcon;
	ffhttp_respfree(&c->resp);
}

static void htpx_printresp(htpxcon *c)
{
	ffstr first_line = ffhttp_firstline(&c->resp.h);
	ffstr hdrs = ffhttp_hdrs(&c->resp.h);
	const char *n;

	dbglog(c->logctx, FSV_LOG_DBGNET, "response received: [%L] %S"
		, (size_t)c->resp.h.len, &first_line);

	for (;;) {
		n = ffs_findof(hdrs.ptr, hdrs.len, FFSTR("\r\n"));
		if (n == hdrs.ptr)
			break;

		dbglog(c->logctx, FSV_LOG_DBGNET, "response header: %*s"
			, n - hdrs.ptr, hdrs.ptr);

		n += (*n == '\r') ? FFSLEN("\r\n") : FFSLEN("\n");
		ffstr_shift(&hdrs, n - hdrs.ptr);
	}
}


static void htpx_bodyrecv(fsv_httphandler *h)
{
	htpxcon *c = (htpxcon*)h->httpcon;

	if (h->id->udata == NULL) {

		if (!c->resp.h.has_body) {
			h->http->send(h->id, NULL, 0, FSV_HTTP_PASS | FSV_HTTP_DONE);
			return;
		}

		if (!ffsf_empty(h->data)) {
			h->http->send(h->id, NULL, 0, FSV_HTTP_PASS | FSV_HTTP_MORE);
			return;
		}

		if (NULL == ffarr_alloc(&c->body, c->px->respbody_buf_size)) {
			syserrlog(c->logctx, FSV_LOG_ERR, "%e", FFERR_BUFALOC);
			h->http->send(h->id, NULL, 0, FSV_HTTP_ERROR);
			return;
		}

		h->id->udata = (void*)1;
	}

	c->body.len = 0;
	dbglog(c->logctx, FSV_LOG_DBGNET, "receiving body...");
	c->hfrecv = h->id;
	htpx_readbody(h->httpcon);
}

static void htpx_bodyrecv_done(fsv_httphandler *h)
{
	htpxcon *c = (htpxcon*)h->httpcon;
	htpx_stoptimer(c, HTPX_TMR_READ);
	ffarr_free(&c->body);
}

static void htpx_readbody(void *udata)
{
	htpxcon *c = udata;
	ssize_t r;
	ffstr buf;
	int f;

	ffstr_set(&buf, ffarr_end(&c->body), ffarr_unused(&c->body));
	FF_ASSERT(buf.len != 0);

	r = c->px->conn->recv(c->serv_id, buf.ptr, buf.len, &htpx_readbody, c);
	if (r == FSV_IO_ASYNC) {
		htpx_resettimer(c, HTPX_TMR_READ);
		return;
	}

	htpx_stoptimer(c, HTPX_TMR_READ);

	if (r == FSV_IO_ESHUT) {
		dbglog(c->logctx, FSV_LOG_DBGNET, "TCP FIN received");
		f = FSV_HTTP_DONE;
		goto done;

	} else if (r == FSV_IO_ERR) {

		if (fferr_last() == ECANCELED) {
			htpx_errlog(c, FSV_LOG_ERR, "read body: timeout");
			ffhttp_setstatus(c->clientresp, FFHTTP_504_GATEWAY_TIMEOUT);
			f = FSV_HTTP_ERROR;
			goto done;
		}

		htpx_errlog(c, FSV_LOG_ERR, "read body: %E", fferr_last());
		ffhttp_setstatus(c->clientresp, FFHTTP_502_BAD_GATEWAY);
		f = FSV_HTTP_ERROR;
		goto done;
	}

	c->nread += r;
	htpxm->allread += r;
	c->body.len += r;
	dbglog(c->logctx, FSV_LOG_DBGNET, "received body: +%L, %U/%D"
		, r, (uint64)(c->nread - c->resp.h.len), c->resp.h.cont_len);

	htpx_http.send(c->hfrecv, c->body.ptr, c->body.len, FSV_HTTP_MORE);
	return;

done:
	htpx_http.send(c->hfrecv, NULL, 0, f);
}


static void htpx_contlen_req(fsv_httphandler *h)
{
	htpxcon *c = (htpxcon*)h->httpcon;
	ffstr body = {0};
	uint64 body_recvd = c->nread - c->resp.h.len;
	uint64 cont_len = c->resp.h.cont_len;
	int f;

	if (h->id->udata == NULL) {
		if (c->resp.h.cont_len == -1 || c->resp.h.chunked) {
			f = FSV_HTTP_PASS | FSV_HTTP_DONE;
			goto done;
		}

		h->id->udata = (void*)1;
	}

	if (h->data->ht.hdr_cnt != 0) {
		ffstr_setiovec(&body, &h->data->ht.headers[0]);
		if (body_recvd > cont_len)
			body.len -= body_recvd - cont_len;
	}
	FF_ASSERT(h->data->fm.fsize == 0 && h->data->ht.trl_cnt == 0);

	f = 0;
	if (body_recvd == cont_len) {
		c->resp_fin = 1;
		f = FSV_HTTP_NOINPUT;

	} else if (body_recvd > cont_len) {
		htpx_errlog(c, FSV_LOG_INFO, "cont-len: server sent more data than expected: +%L"
			, (size_t)body_recvd - cont_len);
		f = FSV_HTTP_NOINPUT;

	} else if (h->flags & FSV_HTTP_LAST) {
		htpx_errlog(c, FSV_LOG_ERR, "cont-len: incomplete input data");
		f = FSV_HTTP_ERROR;
		goto done;
	}

	h->http->send(h->id, body.ptr, body.len, f);
	return;

done:
	h->http->send(h->id, NULL, 0, f);
}

static void htpx_contlen_req_done(fsv_httphandler *h)
{
}


/** Handle transfer-encoding:chunked in received data. */
static void htpx_chunked_req(fsv_httphandler *h)
{
	htpxcon *c = (htpxcon*)h->httpcon;
	ffstr chunk = {0};
	int r, f, havemore;
	size_t datalen;

	if (h->id->udata == NULL) {
		if (!c->resp.h.chunked) {
			f = FSV_HTTP_PASS | FSV_HTTP_DONE;
			goto done;
		}

		ffhttp_chunkinit(&c->chunked);
		h->id->udata = (void*)1;
	}

	FF_ASSERT(h->data->ht.hdr_cnt == 1);
	datalen = h->data->ht.headers[0].iov_len;
	r = ffhttp_chunkparse(&c->chunked, h->data->ht.headers[0].iov_base, &datalen, &chunk);
	havemore = ffsf_shift(h->data, datalen);

	switch (r) {
	case FFHTTP_OK:
		h->http->send(h->id, chunk.ptr, chunk.len, (havemore) ? FSV_HTTP_MORE : 0);
		return;

	case FFHTTP_MORE:
		f = 0;
		if (h->flags & FSV_HTTP_LAST) {
			errlog(h->logctx, FSV_LOG_ERR, "chunked: incomplete input data");
			f = FSV_HTTP_ERROR;
		}
		break;

	case FFHTTP_DONE:
		if (havemore) {
			htpx_errlog(c, FSV_LOG_INFO, "server has sent more data than expected: +%L"
				, (size_t)ffsf_len(h->data));
		} else
			c->resp_fin = 1;

		f = FSV_HTTP_NOINPUT;
		break;

	default:
		errlog(h->logctx, FSV_LOG_ERR, "chunked encoding parse: %s", ffhttp_errstr(r));
		f = FSV_HTTP_ERROR;
		break;
	}

done:
	h->http->send(h->id, NULL, 0, f);
}

static void htpx_chunked_req_done(fsv_httphandler *h)
{
}


static void htpx_out(fsv_httphandler *h)
{
	htpxcon *c = (htpxcon*)h->httpcon;
	int f;

	if (h->id->udata == NULL && !c->tunnel) {
		// the first answer to http module
		if (0 != htpx_mkresp(c, c->clientresp, &c->resp)) {
			h->http->send(h->id, NULL, 0, FSV_HTTP_ERROR);
			return;
		}
		h->id->udata = (void*)1;
	}
	c->hfhttpout = h->id;

	if ((h->flags & FSV_HTTP_LAST) && c->req_fin)
		htpx_freeconn(c, 0);

	f = (h->flags & FSV_HTTP_LAST) ? 0 : FSV_HTTP_MORE;
	if (c->px->stream_response)
		f |= FSV_HTTP_PUSH;
	if (c->tunnel)
		f |= FSV_HTTP_ASIS;

	c->px->client_http->fsv_http_sendfile(c->hf, h->data, f);
}

static void htpx_out_done(fsv_httphandler *h)
{
}

/** Add response headers specified in configuration. */
static int htpx_addresphdrs_fromconf(htpxcon *c, ffhttp_cook *cook)
{
	ffstr k, v;
	ffstr3 tmp = {0};
	int ret;
	size_t off = 0;

	for (;;) {

		if (0 == ffbstr_next(c->px->conf_resp_hdrs.ptr, c->px->conf_resp_hdrs.len, &off, &k)
			|| 0 == ffbstr_next(c->px->conf_resp_hdrs.ptr, c->px->conf_resp_hdrs.len, &off, &v))
			break;

		if (0 != htpxm->core->process_vars(&tmp, &v, htpx_http.getvar, c, c->logctx)) {
			ret = FFERR_BUFALOC;
			goto done;
		}

		ffhttp_addhdr_str(cook, &k, (ffstr*)&tmp);
	}

	ret = 0;

done:
	ffarr_free(&tmp);
	return ret;
}

/** Prepare response to a client. */
int htpx_mkresp(htpxcon *c, ffhttp_cook *cook, const ffhttp_response *resp)
{
	int i = 0, ret;
	ffstr key, val, st;

	st = ffhttp_respstatus(resp);
	ffhttp_setstatus4(cook, resp->code, st.ptr, st.len);

	cook->cont_len = resp->h.cont_len;

	for (;;) {
		int ihdr = ffhttp_gethdr(&resp->h, i++, &key, &val);
		if (ihdr == FFHTTP_DONE)
			break;

		switch (ihdr) {
		case FFHTTP_DATE:
			cook->date = val;
			continue;

		case FFHTTP_CONTENT_ENCODING:
			cook->cont_enc = val;
			continue;

		case FFHTTP_CONTENT_TYPE:
			cook->cont_type = val;
			continue;

		case FFHTTP_LAST_MODIFIED:
			cook->last_mod = val;
			continue;

		case FFHTTP_TRANSFER_ENCODING:
			if (!resp->h.chunked)
				cook->trans_enc = val; //pass transparently data with an unknown Transfer-Encoding
			continue;

		case FFHTTP_CONTENT_LENGTH:
		case FFHTTP_CONNECTION:
		case FFHTTP_KEEPALIVE:
		case FFHTTP_UPGRADE:
		case FFHTTP_PROXY_AUTHENTICATE:
			continue;
		}

		ffhttp_addhdr_str(cook, &key, &val);
	}

	ret = htpx_addresphdrs_fromconf(c, cook);
	if (ret != 0) {
		syserrlog(c->logctx, FSV_LOG_ERR, "%e", ret);
		return ret;
	}

	return 0;
}


static void htpx_sendio(fsv_httphandler *h)
{
	htpxcon *c = (htpxcon*)h->httpcon;

	if (h->id->udata == NULL) {
		h->id->udata = (void*)1;

		ffatom_inc(&htpxm->nrequests);
		c->resp.h.conn_close = 1; //the connection in HTTP tunnel mode is not keep-alive
	}

	if (h->flags & FSV_HTTP_LAST) {
		ffskt sk;

		FF_ASSERT(ffsf_empty(h->data));

		c->px->conn->fsv_getvarcz(c->serv_id, "socket_fd", &sk, sizeof(ffskt));
		dbglog(c->logctx, FSV_LOG_DBGNET, "disconnecting...");
		if (0 != ffskt_fin(sk))
			errlog(c->logctx, FSV_LOG_WARN, "%e", FFERR_SKTSHUT);

		h->http->send(h->id, NULL, 0, FSV_HTTP_DONE);
		return;
	}

	if (ffsf_empty(h->data)) {
		h->http->send(h->id, NULL, 0, FSV_HTTP_BACK);
		return;
	}

	c->sf = h->data;
	dbglog(c->logctx, FSV_LOG_DBGNET, "sending data +%U [%U]..."
		, ffsf_len(c->sf), c->nwrite);
	c->hfsend = h->id;
	htpx_sendrequest(c);
	return;
}

static void htpx_sendio_done(fsv_httphandler *h)
{
	htpxcon *c = (htpxcon*)h->httpcon;
	htpx_stoptimer(c, HTPX_TMR_WRITE);
}

static void htpx_recvio(fsv_httphandler *h)
{
	htpxcon *c = (htpxcon*)h->httpcon;

	if (h->id->udata == NULL) {
		if (NULL == ffarr_alloc(&c->body, c->px->respbody_buf_size)) {
			syserrlog(c->logctx, FSV_LOG_ERR, "%e", FFERR_BUFALOC);
			ffhttp_setstatus(c->clientresp, FFHTTP_500_INTERNAL_SERVER_ERROR);
			h->http->send(h->id, NULL, 0, FSV_HTTP_ERROR);
			return;
		}

		h->id->udata = (void*)1;
	}

	c->body.len = 0;
	dbglog(c->logctx, FSV_LOG_DBGNET, "receiving data...");
	c->hfrecv = h->id;
	htpx_readdata(c);
}

static void htpx_recvio_done(fsv_httphandler *h)
{
	htpxcon *c = (htpxcon*)h->httpcon;
	htpx_stoptimer(c, HTPX_TMR_READ);
	ffarr_free(&c->body);
}

static void htpx_readdata(void *udata)
{
	htpxcon *c = udata;
	ssize_t r;
	ffstr buf;
	int f;

	ffstr_set(&buf, ffarr_end(&c->body), ffarr_unused(&c->body));
	FF_ASSERT(buf.len != 0);

	r = c->px->conn->recv(c->serv_id, buf.ptr, buf.len, &htpx_readdata, c);
	if (r == FSV_IO_ASYNC) {

		htpx_resettimer(c, HTPX_TMR_READ);

		if (c->clientresp->code == 0) {
			// send headers to client
			ffhttp_setstatus(c->clientresp, FFHTTP_200_OK);
			f = FSV_HTTP_ASIS | FSV_HTTP_MORE;
			goto done;
		}

		return;
	}

	htpx_stoptimer(c, HTPX_TMR_READ);

	if (r == FSV_IO_ESHUT) {
		dbglog(c->logctx, FSV_LOG_DBGNET, "TCP FIN received");
		c->resp_fin = 1;

		if (c->clientresp->code == 0)
			ffhttp_setstatus(c->clientresp, FFHTTP_200_OK);

		f = FSV_HTTP_ASIS | FSV_HTTP_DONE;
		goto done;

	} else if (r == FSV_IO_ERR) {

		if (fferr_last() == ECANCELED) {
			htpx_errlog(c, FSV_LOG_ERR, "read data: timeout");
			ffhttp_setstatus(c->clientresp, FFHTTP_504_GATEWAY_TIMEOUT);
			f = FSV_HTTP_ERROR;
			goto done;
		}

		htpx_errlog(c, FSV_LOG_ERR, "read data: %E", fferr_last());
		ffhttp_setstatus(c->clientresp, FFHTTP_502_BAD_GATEWAY);
		f = FSV_HTTP_ERROR;
		goto done;
	}

	c->nread += r;
	htpxm->allread += r;
	dbglog(c->logctx, FSV_LOG_DBGNET, "received data: +%L [%U]"
		, r, c->nread);

	c->body.len += r;

	if (c->clientresp->code == 0)
		ffhttp_setstatus(c->clientresp, FFHTTP_200_OK);
	htpx_http.send(c->hfrecv, c->body.ptr, c->body.len, FSV_HTTP_ASIS | FSV_HTTP_MORE);
	return;

done:
	htpx_http.send(c->hfrecv, NULL, 0, f);
}

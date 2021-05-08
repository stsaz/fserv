/** HTTP document cache.
Copyright 2014 Simon Zolin.
*/

#include <http-proxy/proxy.h>

#include <FF/time.h>
#include <FF/path.h>
#include <FFOS/error.h>


struct htcache {
	htpx_cach_ctx *cx;
	htpxcon *con;

	int req_maxage; //if not -1, client has specified "max-age" in request

	ffhttp_response orig_resp;
	ffstr key;
	fsv_fcacheitem ca;

	time_t expires_at;
	ffstr lastmod
		, etag;

	fsv_httpfilter *hfid;
	const fsv_http *hfhttp;

	unsigned cacheable :1
		, must_revalidate :1
		, stored :1
		, store_incomplete :1
		, revalidated :1
		, iserr :1
		, lastchunk :1;
};

enum HTPX_CACHE_OPT {
	HTPX_USE_QUERYSTRING = 1
	, HTPX_KEEPDATE = 2
	, HTPX_IGN_REQ_CACHECTL = 4
	, HTPX_IGN_RESP_CACHECTL = 8
	, HTPX_IGN_NOSTORE = 0x10
	, HTPX_IGN_PRIVATE = 0x20
};


// HTTP FILTERS
static void htcache_req_ondata(fsv_httphandler *h);
static void htcache_resp_ondata(fsv_httphandler *h);
static void htcache_ondone(fsv_httphandler *h);
const fsv_http_cb htcache_req_htpfilt = {
	&htcache_req_ondata, &htcache_ondone
};
const fsv_http_cb htcache_resp_htpfilt = {
	&htcache_resp_ondata, NULL
};

// CONFIG
static int htcache_conf_cache(ffparser_schem *ps, htpx_cach_ctx *cx, ffpars_ctx *a);

// FILE CACHE
static ffbool htcache_getkey(htpx_cach_ctx *cx, const ffhttp_request *req, ffstr *dst);
static int htcache_fetch(htcache *c, const ffhttp_request *req);
static int htcache_store(htcache *c, const void *d, size_t sz, uint moredata);
static int htcache_refreshdoc(htcache *c);
static void htcache_sendcached(htcache *c, fsv_httphandler *h, const ffhttp_response *resp);
static void htcache_onwrite(void *userptr, fsv_fcacheitem *ca, int result);
static const fsv_fcach_cb htcache_fcache_cb = {
	&htcache_onwrite
};

static void htcache_free(htcache *c);
static int htcache_analyzereq(htcache *c, const ffhttp_request *req);
static int htcache_analyzeresp(htcache *c);
static ffbool htcache_if304(htcache *c, const ffhttp_response *resp);
static int htcache_getexpire(htcache *c, const ffhttp_response *resp);


static const ffpars_arg cache_args[] = {
	{ "cache",  FFPARS_TOBJ | FFPARS_FOBJ1 | FFPARS_FREQUIRED,  FFPARS_DST(&htcache_conf_cache) }
	, { "use_query_string",  FFPARS_TBOOL | FFPARS_SETBIT(0),  FFPARS_DSTOFF(htpx_cach_ctx, opts) }
	, { "keep_date",  FFPARS_TBOOL | FFPARS_SETBIT(1),  FFPARS_DSTOFF(htpx_cach_ctx, opts) }

	, { "ignore_request_cache_control",  FFPARS_TBOOL | FFPARS_SETBIT(2),  FFPARS_DSTOFF(htpx_cach_ctx, opts) }
	, { "ignore_response_cache_control",  FFPARS_TBOOL | FFPARS_SETBIT(3),  FFPARS_DSTOFF(htpx_cach_ctx, opts) }
	, { "ignore_nostore",  FFPARS_TBOOL | FFPARS_SETBIT(4),  FFPARS_DSTOFF(htpx_cach_ctx, opts) }
	, { "ignore_private",  FFPARS_TBOOL | FFPARS_SETBIT(5),  FFPARS_DSTOFF(htpx_cach_ctx, opts) }
};

void htcache_conf_newctx(htpx_cach_ctx *cx, ffpars_ctx *a)
{
	cx->opts = HTPX_USE_QUERYSTRING | HTPX_KEEPDATE;
	ffpars_setargs(a, cx, cache_args, FFCNT(cache_args));
}

static int htcache_conf_cache(ffparser_schem *ps, htpx_cach_ctx *cx, ffpars_ctx *a)
{
	const ffstr *modname = &ps->vals[0];
	const fsv_modinfo *m = htpxm->core->findmod(modname->ptr, modname->len);
	if (m == NULL)
		return FFPARS_EBADVAL;

	cx->cache = m->f->iface("file-cache");
	if (cx->cache == NULL)
		return FFPARS_EBADVAL;

	cx->cachectx = cx->cache->newctx(a, &htcache_fcache_cb, 0);
	if (cx->cachectx == NULL)
		return FFPARS_EBADVAL;

	return 0;
}


const char * htcache_status(htcache *c)
{
	if (c->iserr)
		return "error";
	else if (!c->cacheable)
		return "no";
	else if (c->stored)
		return "stored";
	else if (c->revalidated)
		return "revalidated";
	return "hit";
}

/** Don't pass these client's headers into request to upstream server. */
ffbool htcache_ignorehdr(htcache *c, int ihdr)
{
	return (ihdr == FFHTTP_IFMODIFIED_SINCE && c->lastmod.len != 0)
		|| (ihdr == FFHTTP_IFNONE_MATCH && c->etag.len != 0);
}

/** Add headers into request to upstream server. */
void htcache_addhdr(htcache *c, ffhttp_cook *req)
{
	if (c->lastmod.len != 0)
		ffhttp_addihdr(req, FFHTTP_IFMODIFIED_SINCE, c->lastmod.ptr, c->lastmod.len);
	if (c->etag.len != 0)
		ffhttp_addihdr(req, FFHTTP_IFNONE_MATCH, c->etag.ptr, c->etag.len);
}


/** Process client's request.
Send a cached copy of document if there's no need to check whether it's still fresh.
If revalidation is required, send request with the client's headers along with our conditional headers. */
static void htcache_req_ondata(fsv_httphandler *h)
{
	htpxcon *con = (htpxcon*)h->httpcon;
	htcache *c;

	c = ffmem_tcalloc1(htcache);
	if (c == NULL) {
		syserrlog(h->logctx, FSV_LOG_ERR, "%e", FFERR_BUFALOC);
		goto done;
	}

	c->con = con;
	c->cx = &con->px->fcache;
	ffhttp_respinit(&c->orig_resp);

	h->id->udata = c;
	con->cach = c;
	if (0 != htcache_analyzereq(c, c->con->clientreq))
		goto done;

	if (0 != htcache_fetch(c, c->con->clientreq))
		goto done;

	if (c->must_revalidate) {
		dbglog(h->logctx, FSV_LOG_DBGNET, "revalidating cache");

		//these headers will be used for a conditional request
		ffhttp_findihdr(&c->orig_resp.h, FFHTTP_LAST_MODIFIED, &c->lastmod);
		ffhttp_findihdr(&c->orig_resp.h, FFHTTP_ETAG, &c->etag);
		goto done;
	}

	htcache_sendcached(c, h, &c->orig_resp);
	return;

done:
	h->http->send(h->id, NULL, 0, FSV_HTTP_PASS | FSV_HTTP_DONE);
}

/** Process response from upstream server.
If revalidation has succeeded with code 304, send the cached document to client.  If it's expired - refresh it.
Otherwise overwrite it with the new data. */
static void htcache_resp_ondata(fsv_httphandler *h)
{
	htcache *c = ((htpxcon*)h->httpcon)->cach;
	ffstr body = {0};

	if (c == NULL)
		goto done; //there was an error in 'cache-req' filter

	if (h->data->ht.hdr_cnt != 0)
		ffstr_setiovec(&body, &h->data->ht.headers[0]);

	if (h->flags & FSV_HTTP_LAST)
		c->lastchunk = 1;
	c->hfid = h->id;
	c->hfhttp = h->http;

	if (!c->stored) {

		if (c->must_revalidate && c->con->resp.code == 304 && c->ca.id != NULL) {
			//the document in cache is still valid
			if (c->ca.expire <= htpxm->core->fsv_gettime().sec
				&& 0 != htcache_refreshdoc(c))
				goto err;

			htpx_freeconn(c->con, 0);
			htcache_sendcached(c, h, &c->orig_resp);
			return;
		}

		if (!c->cacheable || 0 != htcache_analyzeresp(c))
			goto done;

		if (0 != htcache_store(c, body.ptr, body.len, !(h->flags & FSV_HTTP_LAST))) {
			c->iserr = 1;
			goto done; //send the data as if cache was disabled
		}

	} else {
		//append more data to the file in cache
		int f = 0;

		c->ca.data = body.ptr;
		c->ca.len = body.len;
		if (h->flags & FSV_HTTP_LAST)
			f = FSV_FCACH_UNLOCK;
		if (0 != c->cx->cache->update(&c->ca, FSV_FCACH_APPEND | f))
			goto err;
	}

	return;

done:
	h->http->send(h->id, NULL, 0, FSV_HTTP_PASS | FSV_HTTP_DONE);
	return;

err:
	c->iserr = 1;
	h->http->send(h->id, NULL, 0, FSV_HTTP_ERROR);
}

static void htcache_ondone(fsv_httphandler *h)
{
	htcache *c = h->id->udata;
	c->con->cach = NULL;
	htcache_free(c);
}


static void htcache_free(htcache *c)
{
	if (c->ca.id != NULL) {
		int f = (c->store_incomplete) ? FSV_FCACH_UNLINK : 0;
		c->cx->cache->unref(&c->ca, f);
		c->ca.id = NULL;
	}

	ffstr_free(&c->key);
	ffhttp_respfree(&c->orig_resp);
	ffmem_free(c);
}

static const byte htpx_nocache_req_hdrs[] = {
	FFHTTP_RANGE, FFHTTP_COOKIE, FFHTTP_COOKIE2, FFHTTP_AUTHORIZATION
};

/** Determine whether a response to this request can be cached.
Don't cache response:
. if HTTP method is other than GET or HEAD
. if request has a body
. if a header is set that can affect response data
. if Cache-Control prevents this */
static int htcache_analyzereq(htcache *c, const ffhttp_request *req)
{
	size_t i;
	ffstr val;

	if ((req->method != FFHTTP_GET && req->method != FFHTTP_HEAD)
		|| req->h.has_body)
		goto nocache;

	for (i = 0;  i < FFCNT(htpx_nocache_req_hdrs);  i++) {
		if (0 != ffhttp_findihdr(&req->h, htpx_nocache_req_hdrs[i], &val))
			goto nocache;
	}

	c->req_maxage = -1;

	if (!(c->cx->opts & HTPX_IGN_REQ_CACHECTL)
		&& 0 != ffhttp_findihdr(&req->h, FFHTTP_CACHE_CONTROL, &val)) {

		ffhttp_cachectl cctl;
		int cc = ffhttp_parsecachctl(&cctl, val.ptr, val.len);
		if (cc & FFHTTP_CACH_NOSTORE)
			goto nocache;

		if (cc & FFHTTP_CACH_NOCACHE)
			c->must_revalidate = 1;

		else if (cc & FFHTTP_CACH_MAXAGE)
			c->req_maxage = cctl.maxage;
	}

	c->cacheable = 1;
	return 0;

nocache:
	dbglog(c->con->logctx, FSV_LOG_DBGFLOW, "not using cache for this request");
	return 1;
}

static const byte htpx_nocache_resp_hdrs[] = {
	FFHTTP_SETCOOKIE, FFHTTP_SETCOOKIE2, FFHTTP_AUTHORIZATION, FFHTTP_CONTENT_RANGE
};

/** Use s-max-age and max-age and Expires+Date to set document expiration time. */
static int htcache_getexpire(htcache *c, const ffhttp_response *resp)
{
	uint maxag = (uint)-1, fcc = 0;
	uint64 date, expires;
	ffdtm dt;
	fftime t;
	ffstr val;
	ffhttp_cachectl cctl;

	if (c->cx->opts & HTPX_IGN_RESP_CACHECTL)
		return 0;

	if (0 != ffhttp_findihdr(&resp->h, FFHTTP_CACHE_CONTROL, &val)) {

		fcc = ffhttp_parsecachctl(&cctl, val.ptr, val.len);

		if (fcc & FFHTTP_CACH_SMAXAGE)
			maxag = cctl.smaxage;
		else if (fcc & FFHTTP_CACH_MAXAGE)
			maxag = cctl.maxage;

		if ((fcc & (FFHTTP_CACH_NOCACHE | FFHTTP_CACH_REVALIDATE))
			|| maxag == 0)
			c->must_revalidate = 1;
	}

	if (0 != ffhttp_findihdr(&resp->h, FFHTTP_EXPIRES, &val)
		&& val.len == fftime_fromstr(&dt, val.ptr, val.len, FFTIME_WDMY)) {

		fftime_join(&t, &dt, FFTIME_TZUTC);
		expires = fftime_to_time_t(&t);

		if (0 != ffhttp_findihdr(&resp->h, FFHTTP_DATE, &val)
			&& val.len == fftime_fromstr(&dt, val.ptr, val.len, FFTIME_WDMY)) {

			fftime_join(&t, &dt, FFTIME_TZUTC);
			date = fftime_to_time_t(&t);

			if (date >= expires)
				maxag = 0;
			else if (expires - date < maxag)
				maxag = expires - date;
		}
	}

	if (maxag != (uint)-1)
		c->expires_at = htpxm->core->fsv_gettime().sec + maxag;

	if (((fcc & FFHTTP_CACH_NOSTORE) && !(c->cx->opts & HTPX_IGN_NOSTORE))
		|| ((fcc & FFHTTP_CACH_PRIVATE) && !(c->cx->opts & HTPX_IGN_PRIVATE)))
		return 1;

	return 0;
}

/**
Don't cache response:
. other than 200 or 301
. with no Content-Length and no chunked TE
. if content-encoding is unsupported
. if a header is set that can affect data
. if Cache-Control prevents this */
static int htcache_analyzeresp(htcache *c)
{
	size_t i;
	const ffhttp_response *resp = &c->con->resp;
	ffstr val;

	if ((resp->code != 200 && resp->code != 301)
		|| (resp->h.cont_len == -1 && !resp->h.chunked)
		|| (!resp->h.ce_identity && !resp->h.ce_gzip))
		goto nocache;

	for (i = 0;  i < FFCNT(htpx_nocache_resp_hdrs);  i++) {
		if (0 != ffhttp_findihdr(&resp->h, htpx_nocache_resp_hdrs[i], NULL))
			goto nocache;
	}

	if (0 != htcache_getexpire(c, resp))
		goto nocache;

	if (0 != ffhttp_findihdr(&resp->h, FFHTTP_VARY, &val)) {
		/* Note: Vary is not completely supported.
		Currently we don't cache the document if there's a value other than "Accept-Encoding". */
		ffstr v;
		while (val.len != 0) {
			ffstr_shift(&val, ffstr_nextval(val.ptr, val.len, &v, ','));
			if (!ffstr_ieqcz(&v, "Accept-Encoding"))
				goto nocache;
		}
	}

	return 0;

nocache:
	dbglog(c->con->logctx, FSV_LOG_DBGFLOW, "no cache for response");
	c->cacheable = 0;
	return 1;
}

/** Check whether the document cached on the client's side is still actual. */
static ffbool htcache_if304(htcache *c, const ffhttp_response *resp)
{
	ffbool r304 = 0;
	ffstr reqval, respval;

	if (0 != ffhttp_findihdr(&c->con->clientreq->h, FFHTTP_IFMODIFIED_SINCE, &reqval)
		&& 0 != ffhttp_findihdr(&resp->h, FFHTTP_LAST_MODIFIED, &respval)) {

		if (!ffstr_eq2(&reqval, &respval))
			return 0;

		r304 = 1;
	}

	if (0 != ffhttp_findihdr(&c->con->clientreq->h, FFHTTP_IFNONE_MATCH, &reqval)
		&& 0 != ffhttp_findihdr(&resp->h, FFHTTP_ETAG, &respval)) {

		if (ffhttp_ifnonematch(respval.ptr, respval.len, &reqval))
			return 0;

		r304 = 1;
	}

	return r304;
}


/** Make key string for cache: METHOD HOST:PORT PATH \0 QUERY_STRING.
"PATH" is decoded, therefore we use '\0' instead of '?' before query-string.
Note: query-string is NOT decoded, "?0" and "?%30" are different. */
static ffbool htcache_getkey(htpx_cach_ctx *cx, const ffhttp_request *req, ffstr *dst)
{
	ffstr meth, host, uri, qs = {0};
	size_t keylen;
	char *s;

	meth = ffhttp_reqmethod(req);
	keylen = meth.len + FFSLEN(" ");

	host = ffhttp_requrl(req, FFURL_FULLHOST);
	keylen += host.len + FFSLEN(":12345");

	uri = ffhttp_reqpath(req);
	keylen += uri.len;

	if (cx->opts & HTPX_USE_QUERYSTRING) {
		qs = ffhttp_requrl(req, FFURL_QS);
		if (qs.len != 0)
			keylen += FFSLEN("?") + qs.len;
	}

	if (NULL == ffstr_alloc(dst, keylen))
		return 0;
	s = dst->ptr;

	s = ffmem_copy(s, meth.ptr, meth.len);
	*s++ = ' ';

	if (req->url.portlen == 0)
		s += ffs_fmt(s, dst->ptr + keylen, "%S:%u", &host, 80);
	else
		s = ffmem_copy(s, host.ptr, host.len);

	s = ffmem_copy(s, uri.ptr, uri.len);

	if (qs.len != 0) {
		*s++ = '\0';
		s = ffmem_copy(s, qs.ptr, qs.len);
	}

	dst->len = s - dst->ptr;
	return 1;
}

static int htcache_fetch(htcache *c, const ffhttp_request *req)
{
	fsv_fcacheitem *ca = &c->ca;
	time_t now;

	if (!htcache_getkey(c->cx, req, &c->key)) {
		c->cacheable = 0;
		syserrlog(c->con->logctx, FSV_LOG_ERR, "%e", FFERR_BUFALOC);
		return 1;
	}

	fsv_fcache_init(ca);
	ca->logctx = c->con->logctx;
	ca->key = c->key.ptr;
	ca->keylen = c->key.len;
	if (0 != c->cx->cache->fetch(c->cx->cachectx, ca, 0))
		return 1;

	now = htpxm->core->fsv_gettime().sec;
	if (!c->must_revalidate
		&& (ca->expire <= now
			|| (c->req_maxage != -1 && (uint)c->req_maxage < now - ca->cretm)))
		c->must_revalidate = 1;

	ffhttp_respparse(&c->orig_resp, ca->hdr, ca->hdrlen, FFHTTP_IGN_STATUS_PROTO);
	ffhttp_respparsehdrs(&c->orig_resp, ca->hdr, ca->hdrlen);

	if (!req->accept_gzip && c->orig_resp.h.ce_gzip) {
		//the document is compressed, but the client does not support compression
		c->cx->cache->unref(ca, 0);
		fsv_fcache_init(ca);

		c->cacheable = 0;
		dbglog(c->con->logctx, FSV_LOG_DBGFLOW, "not using cache for this request");
		return 1;
	}

	return 0;
}

/** Store document in cache.  Overwrite data if revalidation hasn't succeeded. */
static int htcache_store(htcache *c, const void *d, size_t sz, uint moredata)
{
	uint f = 0;
	fsv_fcacheitem *ca = &c->ca;
	const ffhttp_response *prxresp = &c->con->resp;

	ca->userptr = c;
	ca->expire = c->expires_at;
	FF_ASSERT(prxresp->h.base == (void*)c->con->hdr.ptr);

	ca->hdr = prxresp->h.base;
	ca->hdrlen = prxresp->h.len;

	if (prxresp->h.cont_len != -1)
		ca->total_size = prxresp->h.cont_len;

	ca->data = d;
	ca->len = sz;
	ca->fd = FF_BADFD;

	if (moredata)
		f = FSV_FCACH_LOCK;

	if (c->ca.id != NULL) {
		//overwrite cached document
		if (0 != c->cx->cache->update(&c->ca, f)) {
			c->cx->cache->unref(&c->ca, FSV_FCACH_UNLINK); //delete the stale document
			fsv_fcache_init(&c->ca);
			c->iserr = 1;
			return 1;
		}
		return 0;
	}

	if (0 != c->cx->cache->store(c->cx->cachectx, &c->ca, f))
		return 1;

	return 0;
}

/** Cache module reports the result of write operation. */
static void htcache_onwrite(void *userptr, fsv_fcacheitem *ca, int result)
{
	htcache *c = userptr;
	c->ca = *ca;

	if (result != 0) {
		c->iserr = 1;
		c->hfhttp->send(c->hfid, NULL, 0, FSV_HTTP_ERROR);
		return;
	}

	c->stored = 1;
	c->store_incomplete = !c->lastchunk;

	if (!c->con->px->stream_response) {
		if (c->lastchunk) {
			fsv_httphandler h = {0};
			h.http = c->hfhttp;
			h.id = c->hfid;
			htpx_freeconn(c->con, 0);
			htcache_sendcached(c, &h, &c->con->resp);
			return;
		}
		c->hfhttp->send(c->hfid, NULL, 0, FSV_HTTP_BACK); //receive more until the whole response is cached
	} else
		c->hfhttp->send(c->hfid, NULL, 0, FSV_HTTP_PASS);
}

/** Set a new expiration date on a cached document.
Note: if according to the current configuration we must not cache the document at all (e.g. no-store is set)
 we don't delete it from cache anyway. */
static int htcache_refreshdoc(htcache *c)
{
	htcache_getexpire(c, &c->orig_resp);
	c->ca.expire = c->expires_at;
	if (0 == c->cx->cache->update(&c->ca, FSV_FCACH_REFRESH)) {
		c->revalidated = 1;
		return 0;
	}
	return 1;
}

/** Send cached data directly to the parent module.  We can't pass the data to 'http-out' filter because
 it works with the response received from upstream server. */
static void htcache_sendcached(htcache *c, fsv_httphandler *h, const ffhttp_response *resp)
{
	if (htcache_if304(c, resp)) {
		ffhttp_setstatus(c->con->clientresp, FFHTTP_304_NOT_MODIFIED);
		c->con->px->client_http->send(c->con->hf, NULL, 0, FSV_HTTP_DONE); //body is empty
		return;
	}

	if (0 != htpx_mkresp(c->con, c->con->clientresp, resp)) {
		h->http->send(h->id, NULL, 0, FSV_HTTP_ERROR);
		return;
	}

	if (!(c->cx->opts & HTPX_KEEPDATE))
		ffstr_null(&c->con->clientresp->date);

	if (c->ca.data == NULL)
		c->con->px->client_http->sendfile(c->con->hf, c->ca.fd, c->ca.len, c->ca.fdoff, NULL, FSV_HTTP_DONE);
	else
		c->con->px->client_http->send(c->con->hf, c->ca.data, (size_t)c->ca.len, FSV_HTTP_DONE);
}

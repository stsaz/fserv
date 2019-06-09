/** ICY client.
Copyright 2014 Simon Zolin.
*/

#include <broadcast/brdcast.h>

#include <FF/audio/mpeg.h>
#include <FF/data/utf8.h>


enum {
	TMPBUFSZ = 4 * 1024
	, NBUFS = 10
};

typedef struct icyclient {
	bcastctx *bx;
	fsv_logctx *lx;

	//request/response
	fsv_httpfilter hf;
	ffhttp_request req;
	ffhttp_cook resp;
	struct { FFARR(ffrange) } passed_icy_hdrs;

	fficy icy;

	ffmpg_hdr firstMpegHdr;
	ffstr bufs[NBUFS];
	fftime buf_fill_start_tm;
	uint iwbuf;
	ffstr indata
		, mediadata;
	fsv_task tsk;
	uint state;
	unsigned mpegHdr :1
		, nfyprx :1 //we have to notify proxy
		;

	//conf:
	mp3store *store;
	const fsv_http_cb *prxh;
	void *prxctx;
} icyclient;


// HTTP
static void icyx_http_ondata(fsv_httpfilter *hf, const void *buf, size_t len, int flags);
static void icyx_http_ondatasf(fsv_httpfilter *hf, fffd h, uint64 sz, uint64 offs, sf_hdtr *hdtr, int flags);
static ssize_t icyx_http_getvar(void *c, const char *name, size_t namelen, void *dst, size_t cap);
static void icyx_http_sendv(fsv_httpfilter *hf, ffiovec *iovs, size_t n, int flags);
static const fsv_http icyx_http = {
	&icyx_http_getvar, &icyx_http_ondata, &icyx_http_sendv, &icyx_http_ondatasf
};

// CONFIG
static int icyx_conf_proxy(ffparser_schem *ps, icyclient *c, ffpars_ctx *ctx);
static int icyx_conf_store(ffparser_schem *ps, icyclient *c, ffpars_ctx *ctx);

// BROADCAST IFACE
static ffbool icyx_start(void *prov);
static void icyx_addhdrs(void *prov, ffhttp_cook *cook);
static void icyx_stop(void *prov);
static int icyx_getbuf(void *prov, size_t ibuf, ffstr *buf);
static void icyx_played(void *prov, uint iplayed);
static void icyx_fin(void *prov);
static const bcast_prov_iface icyx_iface = {
	&icyx_start, &icyx_stop, &icyx_addhdrs, &icyx_getbuf, &icyx_played, &icyx_fin
};

static void icyx_fill_http_params(icyclient *c, fsv_httphandler *hp);
static int icyx_resp_parse(icyclient *c);
static int icyx_detectbitrate(icyclient *c, const char *data, size_t sz);
static void icyx_onresume(void *prov);
static void icyx_nfyproxy(void *t);
static void icyx_dometa(icyclient *c, const ffstr *data);

static ffbool icyx_isFilled(void *prov, size_t ibuf) {
	const icyclient *c = prov;
	return c->bufs[ibuf].len == c->bx->buf_size;
}

static int icyx_getbuf(void *prov, size_t ibuf, ffstr *buf)
{
	const icyclient *c = prov;
	if (!icyx_isFilled(prov, ibuf))
		return -1;

	*buf = c->bufs[ibuf];
	return (ibuf == c->iwbuf) ? 1 : 0;
}


static const ffpars_arg icyx_conf_args[] = {
	{ "proxy",  FFPARS_TOBJ | FFPARS_FOBJ1 | FFPARS_FREQUIRED,  FFPARS_DST(&icyx_conf_proxy) }
	, { "store",  FFPARS_TOBJ,  FFPARS_DST(&icyx_conf_store) }
};

static int icyx_conf_proxy(ffparser_schem *ps, icyclient *c, ffpars_ctx *ctx)
{
	const ffstr *modname = &ps->vals[0];
	const fsv_modinfo *m;
	fsv_http_hdlctx hc = { 0 };
	const fsv_httphandler_iface *hi;

	m = bcastm->core->findmod(modname->ptr, modname->len);
	if (m == NULL)
		return FFPARS_EBADVAL;
	hc.http = &icyx_http;
	hc.args = ctx;

	hi = m->f->iface("http-handler");
	if (hi == NULL)
		return FFPARS_EBADVAL;

	if (0 != hi->newctx(&hc))
		return FFPARS_EBADVAL;

	c->prxctx = hc.hctx;
	c->prxh = hc.handler;
	return 0;
}

static int icyx_conf_store(ffparser_schem *ps, icyclient *c, ffpars_ctx *ctx)
{
	c->store = mp3stor_init(ctx, c->lx);
	if (c->store == NULL)
		return FFPARS_ESYS;
	return 0;
}


int icyx_conf_init(bcastctx *bx, ffpars_ctx *ctx)
{
	icyclient *c = ffmem_tcalloc1(icyclient);
	if (c == NULL)
		return FFPARS_ESYS;

	c->bx = bx;
	c->lx = bx->lx;

	bx->prov = c;
	bx->nbufs = NBUFS;
	bx->iface = &icyx_iface;

	ffpars_setargs(ctx, c, icyx_conf_args, FFCNT(icyx_conf_args));
	return 0;
}

static void icyx_fin(void *prov)
{
	icyclient *c = prov;
	if (c->store != NULL)
		mp3stor_free(c->store);
	ffhttp_cookdestroy(&c->resp);
	ffmem_free(c);
}

static void icyx_fill_http_params(icyclient *c, fsv_httphandler *hp)
{
	ffmem_tzero(hp);
	hp->id = &c->hf;
	hp->hctx = c->prxctx;
	hp->logctx = c->lx;
	hp->http = &icyx_http;
	hp->httpcon = (fsv_httpcon*)c;
	hp->req = &c->req;
	hp->resp = &c->resp;
	hp->flags = FSV_HTTP_LAST;
}

/** Connect to a remote ICY stream */
ffbool icyx_start(void *prov)
{
	icyclient *c = prov;
	fsv_httphandler hp;
	ffsf reqbody;

	ffhttp_reqinit(&c->req);
	c->req.method = FFHTTP_GET;
	c->req.h.base = "GET /";
	c->req.methodlen = FFSLEN("GET");
	c->req.url.offpath = FFSLEN("GET ");
	c->req.url.pathlen = c->req.url.len = FFSLEN("/");

	ffhttp_cookinit(&c->resp, NULL, 0);
	icyx_fill_http_params(c, &hp);
	ffsf_init(&reqbody);
	hp.data = &reqbody;

	c->prxh->onevent(&hp);
	return 1;
}

/** Close connection with an upstream server. */
static void icyx_stop(void *prov)
{
	icyclient *c = prov;
	uint i;

	if (c->hf.udata != NULL) {
		fsv_httphandler hp;
		icyx_fill_http_params(c, &hp);
		c->prxh->ondone(&hp);
	}

	bcastm->core->utask(&c->tsk, FSVCORE_TASKDEL);

	if (c->store != NULL)
		mp3stor_stop(c->store);

	for (i = 0; i < NBUFS; ++i) {
		ffstr_free(&c->bufs[i]);
	}

	bcastx_reset(c->bx);

	{
	icyclient p2 = *c;
	ffmem_tzero(c);
	c->bx = p2.bx;
	c->lx = p2.lx;
	c->prxctx = p2.prxctx;
	c->prxh = p2.prxh;
	c->store = p2.store;
	c->resp = p2.resp;
	}
}



/** Pass ICY headers from upstream server to client. */
static void icyx_addhdrs(void *prov, ffhttp_cook *cook)
{
	icyclient *c = prov;
	const ffstr3 *hdr = &c->resp.buf;
	ffrange *rng;

	FFARR_WALK(&c->passed_icy_hdrs, rng) {
		ffstr key = ffrang_get(rng, hdr->ptr);
		ffstr val = ffrang_get(++rng, hdr->ptr);
		ffhttp_addhdr(cook, key.ptr, key.len, val.ptr, val.len);
	}
}

/** Parse HTTP response from a remote server.
Remember ICY headers that we'll pass to each client.  Skip those headers that are already set in configuration.*/
static int icyx_resp_parse(icyclient *c)
{
	const ffstr3 *hdr = &c->resp.buf;
	ffhttp_hdr h;
	ffrange *rng;
	uint meta_interval = FFICY_NOMETA;
	ffhttp_inithdr(&h);

	while (FFHTTP_OK == ffhttp_nexthdr(&h, hdr->ptr, hdr->len)) {

		ffstr key = ffrang_get(&h.key, hdr->ptr);
		ffstr val = ffrang_get(&h.val, hdr->ptr);

		if (ffstr_ieq2(&key, &fficy_shdr[FFICY_HMETAINT])) {

			if (meta_interval != FFICY_NOMETA) {
				errlog(c->lx, FSV_LOG_ERR, "duplicate icy-metaint header");
				return 1;
			}

			if (val.len != ffs_toint(val.ptr, val.len, &meta_interval, FFS_INT32)
				|| meta_interval == 0|| meta_interval == FFICY_NOMETA) {
				errlog(c->lx, FSV_LOG_ERR, "invalid icy-metaint: %S", &val);
				return 1;
			}
			continue;

		} else if (!ffstr_imatch(&key, "icy-", 4)
			|| (c->bx->name.len != 0 && ffstr_ieq2(&key, &fficy_shdr[FFICY_HNAME]))
			|| (c->bx->genre.len != 0 && ffstr_ieq2(&key, &fficy_shdr[FFICY_HGENRE]))
			|| (c->bx->url.len != 0 && ffstr_ieq2(&key, &fficy_shdr[FFICY_HURL])))
			continue;

		if (NULL == ffarr_grow(&c->passed_icy_hdrs, 2, 0))
			return 1;
		rng = c->passed_icy_hdrs.ptr;
		rng[c->passed_icy_hdrs.len++] = h.key;
		rng[c->passed_icy_hdrs.len++] = h.val;
	}

	dbglog(c->lx, FSV_LOG_DBGFLOW, "input data meta interval: %u"
		, (meta_interval != FFICY_NOMETA) ? meta_interval : 0);
	fficy_parseinit(&c->icy, meta_interval);
	return 0;
}

static void icyx_dometa(icyclient *c, const ffstr *data)
{
	fficymeta icymeta;
	ffstr m = *data;
	ffbool istitle = 0;

	fficy_metaparse_init(&icymeta);

	dbglog(c->lx, FSV_LOG_DBGFLOW, "received meta: [%L] %s", m.len, &m);

	while (m.len != 0) {
		size_t len = m.len;
		int r = fficy_metaparse(&icymeta, m.ptr, &len);
		ffstr_shift(&m, len);

		switch (r) {
		case FFPARS_KEY:
			if (ffstr_eqcz(&icymeta.val, "StreamTitle"))
				istitle = 1;
			break;

		case FFPARS_VAL:
			if (istitle) {
				ffarr utf = {0};
				ffutf8_strencode(&utf, icymeta.val.ptr, icymeta.val.len, FFU_WIN1252);
				bcast_metaupdate(c->bx, utf.ptr, utf.len);

				if (c->store != NULL)
					mp3stor_name(c->store, utf.ptr, utf.len);
				ffarr_free(&utf);
				return;
			}
			break;

		default:
			errlog(c->lx, FSV_LOG_ERR, "ICY meta parse error: %d", r);
			return;
		}
	}
}

enum {
	_Filled = 1
	, _Break = 2
};

static int icyx_dodata(icyclient *c, const ffstr *data, size_t *processed)
{
	int rc = 0;
	ffstr d = *data;

	while (d.len != 0) {

		ffstr *buf = &c->bufs[c->iwbuf];
		if (buf->len == c->bx->buf_size) {
			*processed = 0;
			return _Filled | _Break;
		}
		size_t n = ffmin(d.len, c->bx->buf_size - buf->len);

		ffmemcpy(buf->ptr + buf->len, d.ptr, n);
		buf->len += n;
		ffstr_shift(&d, n);

		dbglog(c->lx, FSV_LOG_DBGFLOW, "input buffer #%d: +%L [%u%%]"
			, c->iwbuf, (size_t)n, (int)(buf->len*100 / c->bx->buf_size));

		if (fsv_log_checkdbglevel(c->lx, FSV_LOG_DBGNET)) {
			if (buf->len == n)
				c->buf_fill_start_tm = bcast_now();

			if (buf->len == c->bx->buf_size) {
				fftime dif = bcast_now();
				fftime_diff(&c->buf_fill_start_tm, &dif);
				dbglog(c->lx, FSV_LOG_DBGNET, "input buffer #%d has been filled in %Ums"
					, c->iwbuf, (int64)fftime_ms(&dif));
			}
		}

		if (buf->len == c->bx->buf_size) {
			if (!c->mpegHdr) {
				rc = _Filled | _Break; //temp buffer has been filled
				break;
			}
			c->iwbuf = int_cycleinc(c->iwbuf, c->bx->nbufs);

			bcast_update(c->bx);

			if (icyx_isFilled(c, c->iwbuf)) {
				// all buffers are filled
				// if received size is bigger than free space in the buffers, save the data later for the timer
				rc = _Filled | _Break;
				break;
			}

			rc = _Filled;
		}
	}

	*processed = data->len - d.len;
	return rc;
}

static int icyx_process(icyclient *c, const char *d, size_t sz)
{
	size_t len, processed;
	int r, rc;
	ffstr dst;
	int filled = 0;
	ffbool newblock = 0;

	ffstr data;
	ffstr_set(&data, d, sz);

	while (data.len != 0) {

		if (c->mediadata.len == 0) {
			len = data.len;
			r = fficy_parse(&c->icy, data.ptr, &len, &dst);
			newblock = 1;

		} else {
			r = FFICY_RDATA;
			dst = c->mediadata;
			len = c->mediadata.len;
			c->mediadata.len = 0;
		}

		switch (r) {
		// case FFICY_RMETACHUNK:
		// 	break;

		case FFICY_RMETA:
			icyx_dometa(c, &dst);
			break;

		case FFICY_RDATA:
			rc = icyx_dodata(c, &dst, &processed);

			if (newblock && c->store != NULL)
				mp3stor_write(c->store, dst.ptr, dst.len);

			if (rc & _Filled)
				filled = 1;
			if (rc == (_Filled | _Break)) {
				//we couldn't process the whole data block
				c->mediadata = dst;
				ffstr_shift(&c->mediadata, processed);
				c->indata = data;
				ffstr_shift(&c->indata, len);
				ffstr_shift(&c->indata, -(ssize_t)c->mediadata.len);
				return 1;
			}
			break;
		}

		ffstr_shift(&data, len);
	}

	return filled;
}

static void icyx_nfyproxy(void *t)
{
	icyclient *c = t;
	ffsf reqbody;
	fsv_httphandler hp;

	icyx_fill_http_params(c, &hp);
	hp.flags |= FSV_HTTP_SENT;
	ffsf_init(&reqbody);
	hp.data = &reqbody;

	c->prxh->onevent(&hp);
}

static void icyx_played(void *prov, uint iplayed)
{
	icyclient *c = prov;

	c->bufs[iplayed].len = 0;

	if (c->indata.len != 0) {
		// we already have some data to process
		ffstr dd = c->indata;
		ffstr_null(&c->indata);
		icyx_process(c, dd.ptr, dd.len);

		if (c->indata.len == 0)
			icyx_onresume(c);
	}
}

ssize_t icyx_http_getvar(void *obj, const char *name, size_t namelen, void *dst, size_t cap)
{
	return -1;
}

static int icyx_detectbitrate(icyclient *c, const char *data, size_t sz)
{
	bcastctx *bx = c->bx;
	ffstr bbuf = {0}, tmp;
	const ffmpg_hdr *fr;
	const char *d = c->bufs[0].ptr;
	size_t i;
	size_t dsz = c->bufs[0].len;
	if (dsz == 0) {
		//the first block of data
		d = data;
		dsz = sz;
	}

	fr = ffmpg_findframe(d, dsz, 2);
	if (fr != NULL) {
	} else if (c->bufs[0].len == TMPBUFSZ) {
		// the whole buffer is filled, but no mpeg header
		errlog(c->lx, FSV_LOG_ERR, "couldn't find mpeg header in %ukb of data", TMPBUFSZ/1024);
		goto fail;

	} else if (c->bufs[0].ptr == NULL) {
		// alloc temp buffer to collect data until we find the first mpeg header
		if (NULL == ffstr_alloc(&c->bufs[0], TMPBUFSZ)) {
			syserrlog(c->lx, FSV_LOG_ERR, "%e", FFERR_BUFALOC);
			goto fail;
		}
		bx->buf_size = TMPBUFSZ;
		return 0;
	}

	c->firstMpegHdr = *fr;
	c->mpegHdr = 1;
	bx->byterate = ffmpg_hdr_bitrate(fr) / 8;
	dbglog(c->lx, FSV_LOG_DBGFLOW, "mpeg header found at pos %L.  %ukbps, %uKHz, %s, CRC:%u"
		, (size_t)((char*)fr - d), ffmpg_hdr_bitrate(fr)/1000, (int)ffmpg_hdr_sample_rate(fr)/1000
		, ffmpg_strchannel[fr->channel], !fr->noprotect);

	bbuf = c->bufs[0];
	tmp = bbuf;
	ffstr_null(&c->bufs[0]);

	bx->buf_size = (uint)mm_datasize(bx->byterate, bx->buf_ms/NBUFS);

	for (i = 0;  i < NBUFS;  i++) {
		if (NULL == ffstr_alloc(&c->bufs[i], bx->buf_size)) {
			syserrlog(c->lx, FSV_LOG_ERR, "%e", FFERR_BUFALOC);
			ffstr_free(&bbuf);
			goto fail;
		}

		if (tmp.len != 0) {
			ffstr_cat(&c->bufs[i], bx->buf_size, tmp.ptr, tmp.len); //copy what we've collected so far
			ffstr_shift(&tmp, c->bufs[i].len);
		}
	}

	ffstr_free(&bbuf);
	return 1;

fail:
	return -1;
}

static void icyx_http_sendv(fsv_httpfilter *hf, ffiovec *iovs, size_t n, int flags)
{
	ffstr d = { 0 };
	if (n != 0) {
		FF_ASSERT(n == 1);
		ffstr_setiovec(&d, &iovs[0]);
	}
	icyx_http_ondata(hf, d.ptr, d.len, flags);
}

void icyx_http_ondatasf(fsv_httpfilter *hf, fffd h, uint64 sz, uint64 offs, sf_hdtr *hdtr, int flags)
{
	ffstr d = { 0 };
	if (hdtr->hdr_cnt != 0) {
		FF_ASSERT(hdtr->hdr_cnt == 1);
		ffstr_setiovec(&d, &hdtr->headers[0]);
	}
	FF_ASSERT(sz == 0 && hdtr->trl_cnt == 0);
	icyx_http_ondata(hf, d.ptr, d.len, flags);
}

/** http-proxy calls this function when it has output data */
static void icyx_http_ondata(fsv_httpfilter *hf, const void *data, size_t sz, int flags)
{
	enum { I_RESP, I_HDR, I_HDR2, I_DATA };
	icyclient *c = FF_GETPTR(icyclient, hf, hf);
	bcastctx *bx = c->bx;
	int r;

	c->nfyprx = 1;

	if ((flags & (FSV_HTTP_ERROR | FSV_HTTP_BACK)) || c->resp.code != 200) {
		errlog(c->lx, FSV_LOG_ERR, "upstream server: %S", &c->resp.status);
		goto fail;
	}

	if (bx->err)
		goto fail;

	switch (c->state) {
	case I_RESP:
		if (0 != icyx_resp_parse(c))
			goto fail;
		c->state = I_HDR;
		bx->status = ST_BUFFERING;
		// break;

	case I_HDR:
		if (-1 == (r = icyx_detectbitrate(c, data, sz)))
			goto fail;
		if (r == 1) {
			c->state = I_DATA;
			break;
		}
		c->state = I_HDR2;
		// break;

	case I_HDR2:
		if (0 == icyx_process(c, data, sz))
			goto done; //wait for more data

		if (1 != icyx_detectbitrate(c, NULL, 0))
			goto fail;
		data = c->indata.ptr;
		sz = c->indata.len;
		ffstr_null(&c->indata);
		c->state = I_DATA;
		break;

	case I_DATA:
		break;
	}

	if (0 != icyx_process(c, data, sz)) {
	}

done:
	if (!(flags & FSV_HTTP_MORE)) {
		errlog(c->lx, FSV_LOG_WARN, "connection with an upstream server has been closed");
		goto fail;
	}

	if (c->indata.len == 0)
		icyx_onresume(c);
	return;

fail:
	icyx_stop(c);
}

/// The func is called after all suspended clients have been notified about the new data
static void icyx_onresume(void *prov)
{
	icyclient *c = prov;
	if (c->nfyprx) {
		c->nfyprx = 0;
		fsv_taskpost(bcastm->core, &c->tsk, &icyx_nfyproxy, c);
	}
}

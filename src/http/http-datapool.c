/** HTTP body filter: data pool.
Copyright (c) 2014 Simon Zolin
*/

#if 0
#include <core/fserv.h>
#include <http/iface.h>
#include <FFOS/dir.h>
#include <FFOS/error.h>
#include <FF/path.h>


typedef struct hdpl_mod {
	fflist ctxs;
	const fsv_core *srv;
} hdpl_mod;

static hdpl_mod *Mod;

typedef struct hdpl_ctx {
	fflist_item sib;
	const fsv_http *Http;

	ffstr Root;
	uint64 MaxFileSize;
	uint MaxBufSize;
} hdpl_ctx;

typedef struct hdpl_out {
	hdpl_ctx *cx;
	fffd fd;
	ffstr3 buf;
	uint64 fsiz;
	struct { FFARR(ffiovec) } iovs;
	sf_hdtr ht;
	unsigned fopen_failed : 1
		, cached : 1 //if set, input data from sf has been completely cached
		, fin :1;

	uint64 shf;
	uint64 all; //size of processed input data from sf

	// saved stuff from previous module:
	fsv_logctx *logctx;
	fsv_httpcon *htp;
	fsv_httpfilter *hf;
	ffhttp_request *req;
	ffsf *sf;
	int flags;
} hdpl_out;


static int hdpl_newctx(fsv_http_hdlctx *hc);

static void * hdpl_onstartsend(void *ctx);
static void hdpl_onsending(fsv_httphandler *h);
static void hdpl_ondone(fsv_httphandler *h);

static void hdpl_onsend(void *tag);
static void hdpl_dosf(void *tag);
static void hdpl_cached(void *tag);
static void hdpl_onfwrite(void *tag);
static void hdpl_flush(void *tag);


#define MOD_SHORT_NAME "HDPL"

#define syserrlog(lx, lev, fmt, ...) \
	fsv_syserrlog(lx, lev, MOD_SHORT_NAME, NULL, fmt, __VA_ARGS__)


static const fsv_httphandler_iface hdpl_httpctx = {
	&hdpl_newctx
};

static void * hdpl_creat(const fsv_core *srv, ffpars_ctx *c, fsv_modinfo *srvmod)
{
	hdpl_mod *m;

	FF_ASSERT(Mod == NULL);
	m = ffmem_tcalloc1(hdpl_mod);
	if (m == NULL)
		return NULL;
	Mod = m;
	Mod->srv = srv;
	fflist_init(&Mod->ctxs);
	ffpars_setargs(c, Mod, NULL, 0);
	return Mod;
}

static void hdpl_destroy(void)
{
	FFLIST_ENUMSAFE(&Mod->ctxs, ffmem_free, hdpl_ctx, sib);
	ffmem_free(Mod);
	Mod = NULL;
}

static int hdplm_sig(int sig)
{
	return 0;
}

static const void * hdplm_iface(const char *name)
{
	if (!ffsz_cmp(name, "http-handler"))
		return &hdpl_httpctx;
	return NULL;
}

const fsv_mod hdplm_funcs = {
	&hdpl_creat, &hdpl_destroy, &hdplm_sig, &hdplm_iface
};

static int hdpl_vRoot(ffparser_schem *p, void *obj, const ffstr *val)
{
	char path[FF_MAXPATH];
	hdpl_ctx *cx = obj;
	ssize_t r = Mod->srv->getpath(path, FFCNT(path), val->ptr, val->len);
	if (r == -1)
		return FFPARS_EBADVAL;
	if (NULL == ffstr_copy(&cx->Root, path, r))
		return FFPARS_ESYS;
	return 0;
}

static const ffpars_arg hdpl_args[] = {
	{ "Dir", FFPARS_TSTR, FFPARS_DST(&hdpl_vRoot) }
	, { "MaxFileSize", FFPARS_TSIZE | FFPARS_F64BIT | FFPARS_FNOTZERO, FFPARS_DSTOFF(hdpl_ctx, MaxFileSize) }
	, { "MaxBufSize", FFPARS_TSIZE, FFPARS_DSTOFF(hdpl_ctx, MaxBufSize) }
};

static const fsv_http_cb hdpl_httphdler = {
	&hdpl_onsending, &hdpl_ondone
};

static int hdpl_newctx(fsv_http_hdlctx *hc)
{
	hdpl_ctx *cx = ffmem_tcalloc1(hdpl_ctx);
	if (cx == NULL)
		return 1;

	fflist_ins(&Mod->ctxs, &cx->sib);
	cx->MaxFileSize = 50 * 1024 * 1024;
	cx->MaxBufSize = 8 * 1024;

	hc->handler = &hdpl_httphdler;
	hc->hctx = cx;
	cx->Http = hc->http;
	ffpars_setargs(hc->args, cx, hdpl_args, FFCNT(hdpl_args));
	return 0;
}

static void * hdpl_onstartsend(void *ctx)
{
	hdpl_out *c = ffmem_tcalloc1(hdpl_out);
	if (c == NULL)
		return NULL;
	c->cx = ctx;
	c->fd = FF_BADFD;
	if (NULL == ffarr_alloc(&c->buf, c->cx->MaxBufSize))
		goto fail;
	return c;

fail:
	ffmem_free(c);
	return NULL;
}

static void hdpl_onsending(fsv_httphandler *h)
{
	hdpl_out *c = h->id->udata;

	if (h->id->udata == NULL) {
		c = hdpl_onstartsend(h->hctx);
		if (c == NULL) {
			h->http->send(h->id, NULL, 0, FSV_HTTP_ERROR);
			return;
		}

		c->hf = h->id;
		c->htp = h->httpcon;
		c->req = h->req;
		c->logctx = h->logctx;
		h->id->udata = c;
	}

	c->sf = h->data;
	c->flags = (h->flags & FSV_HTTP_PUSH);

	if (h->flags & FSV_HTTP_SENT) {
		hdpl_onsend(c);
		return;
	}

	if (!(h->flags & FSV_HTTP_PUSH) && h->data->fm.fd == FF_BADFD) {
		if (h->flags & FSV_HTTP_LAST)
			c->fin = 1;
		hdpl_dosf(c);
	} else
		hdpl_flush(c);
}

static void hdpl_onsend(void *tag)
{
	hdpl_out *c = tag;

	if (c->fd != FF_BADFD) {
		c->fsiz = 0;
		if (0 != fffile_seek(c->fd, 0, SEEK_SET)) {
			syserrlog(c->logctx, FSV_LOG_ERR, "%e", (int)FFERR_FSEEK);
			c->cx->Http->send(c->hf, NULL, 0, FSV_HTTP_ERROR);
			return;
		}

		if (0 != fffile_trunc(c->fd, 0)) {
			syserrlog(c->logctx, FSV_LOG_ERR, "%e", (int)FFERR_WRITE);
			c->cx->Http->send(c->hf, NULL, 0, FSV_HTTP_ERROR);
			return;
		}
	}

	{
		ffsf *sf = c->sf;
		c->sf = NULL;
		c->cx->Http->sendfile(c->hf, sf->fm.fd, sf->fm.fsize, sf->fm.foff, &sf->ht, c->flags);
	}
}

void hdpl_ondone(fsv_httphandler *h)
{
	hdpl_out *c = h->id->udata;
	if (c->fd != FF_BADFD) {
		if (0 != fffile_close(c->fd))
			syserrlog(c->logctx, FSV_LOG_ERR, "%e", FFERR_FCLOSE);
	}
	ffarr_free(&c->buf);
	ffarr_free(&c->iovs);
	ffmem_free(c);
}

static int prepFn(hdpl_out *c, char *fn, size_t cap)
{
	ffstr meth;
	ffstr path;
	char sfn[FF_MAXPATH];
	size_t r;
	fftime t;

	meth = ffhttp_reqmethod(c->req);
	path = ffhttp_requrl(c->req, FFURL_PATH);
	t = Mod->srv->fsv_gettime();
	r = ffs_fmt(sfn, sfn + FFCNT(sfn), "%xu.%03u %S %S.body"
		, (int)t.s, (int)t.mcs / 1000, &meth, &path);
	r = ffpath_makefn(sfn, FFCNT(sfn), sfn, r, '_');

	r = ffs_fmt(fn, fn + cap, "%S%c%*s%Z"
		, &c->cx->Root, FFPATH_SLASH, r, sfn);
	return r != cap ? 0 : 1;
}

static void hdpl_add(hdpl_out *c, const char *d, size_t len)
{
	size_t n = ffmin(c->buf.cap - c->buf.len, len);
	ffstr3_cat(&c->buf, d, n);
	c->all += n;
	c->shf += n;

	if (c->buf.len != c->buf.cap) {
		ffsf_shift(c->sf, c->shf);
		c->shf = 0;
		hdpl_dosf(c); //the buffer is not full yet
		return;
	}

	if (c->fd == FF_BADFD && !c->fopen_failed) {
		char fn[FF_MAXPATH];

		if (0 != prepFn(c, fn, FFCNT(fn)))
			goto flush;

		c->fd = fffile_createtemp(fn, O_RDWR);
		if (c->fd == FF_BADFD) {
			syserrlog(c->logctx, FSV_LOG_ERR, "%s: %e"
				, fn, FFERR_FOPEN);
			c->fopen_failed = 1;
		}
	}

	if (c->fd == FF_BADFD) {
		goto flush;
	}

	if (c->buf.len != fffile_write(c->fd, FFSTR2(c->buf))) {
		syserrlog(c->logctx, FSV_LOG_ERR, "%e", FFERR_WRITE);
		goto flush;
	}

	ffsf_shift(c->sf, c->shf);
	c->shf = 0;
	hdpl_onfwrite(c);
	return;

flush:
	ffsf_shift(c->sf, c->shf);
	c->shf = 0;
	hdpl_cached(c);
}

static void hdpl_dosf(void *tag)
{
	hdpl_out *c = tag;
	int i;
	const ffiovec *iov;

	iov = c->sf->ht.headers;
	for (i = 0; i < c->sf->ht.hdr_cnt; i++, iov++) {
		hdpl_add(c, iov->iov_base, iov->iov_len);
		return;
	}

	iov = c->sf->ht.trailers;
	for (i = 0; i < c->sf->ht.trl_cnt; i++, iov++) {
		hdpl_add(c, iov->iov_base, iov->iov_len);
		return;
	}

	c->cached = 1;

	ffsf_shift(c->sf, c->shf);
	c->shf = 0;
	hdpl_cached(c);
}

static void hdpl_cached(void *tag)
{
	hdpl_out *c = tag;

	if (c->all != 0) {
		fsv_dbglog(c->logctx, FSV_LOG_DBGFLOW, MOD_SHORT_NAME, NULL, "cached more data: +%L [%L/%U]"
			, (size_t)c->all, (size_t)c->buf.len, (int64)c->fsiz);
		c->all = 0;
	}

	if (c->cached && !c->fin) {
		c->cached = 0;
		c->cx->Http->send(c->hf, NULL, 0, FSV_HTTP_BACK);
		return;
	}

	hdpl_flush(c);
}

static void hdpl_onfwrite(void *tag)
{
	hdpl_out *c = tag;

	fsv_dbglog(c->logctx, FSV_LOG_DBGFLOW, MOD_SHORT_NAME, NULL, "written to file: +%L"
		, (size_t)c->buf.len);
	c->fsiz += c->buf.len;
	c->buf.len = 0;

	if (c->fsiz >= c->cx->MaxFileSize) {
		hdpl_cached(c);
		return;
	}

	hdpl_dosf(c);
}

static void hdpl_flush(void *tag)
{
	hdpl_out *c = tag;

	if (c->fsiz != 0 || c->buf.len != 0) {
		size_t n;
		if (NULL == ffarr_realloc(&c->iovs, 1 + c->sf->ht.hdr_cnt + c->sf->ht.trl_cnt)) {
			c->cx->Http->send(c->hf, NULL, 0, FSV_HTTP_ERROR);
			return;
		}

		ffiov_set(&c->iovs.ptr[0], c->buf.ptr, c->buf.len);
		c->buf.len = 0;

		n = ffiov_copyhdtr(c->iovs.ptr + 1, c->iovs.cap - 1, &c->sf->ht);

		if (c->fd == FF_BADFD) {
			c->ht.headers = c->iovs.ptr;
			c->ht.hdr_cnt = 1 + (int)n;

		} else {
			c->ht.trailers = c->iovs.ptr;
			c->ht.trl_cnt = 1 + (int)n;
		}

		FF_ASSERT(c->sf->fm.fd == FF_BADFD);//^
		c->cx->Http->sendfile(c->hf, c->fd, c->fsiz, 0, &c->ht, 0);
		return;
	}

	hdpl_onsend(c);
}
#endif

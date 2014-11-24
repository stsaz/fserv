/** gzip compression of data via HTTP.
Copyright 2014 Simon Zolin.
*/

#include <core/fserv.h>
#include <http/iface.h>
#include <FF/gz.h>


typedef struct gz_module {
	const fsv_core *core;
	fflist ctxs; //gz_ctx[]
} gz_module;

static gz_module *gzm;

typedef struct gz_ctx {
	fflist_item sib;

	uint buf_size;
	uint min_contlen;
	ffstr mime;
	byte gzwbits;
	byte gzmemlev;
	byte gzlevel;
	unsigned mime_static :1;
} gz_ctx;

typedef struct gzcon {
	ffstr buf;
	ffgz gz;
	uint64 inall
		, outall;
} gzcon;


// FSERV MODULE
static void* gzm_create(const fsv_core *core, ffpars_ctx *pctx, fsv_modinfo *mi);
static void gzm_destroy(void);
static int gzm_sig(int sig);
static const void* gzm_iface(const char *name);
const fsv_mod fsv_http_gzip = {
	&gzm_create, &gzm_destroy, &gzm_sig, &gzm_iface
};

// HTTP
static int gz_newctx(fsv_http_hdlctx *ctx);
static const fsv_httphandler_iface z_httpiface = {
	&gz_newctx
};

// HTTP HANDLER
static void gz_onevent(fsv_httphandler *h);
static void gz_ondone(fsv_httphandler *h);
static const fsv_http_cb z_httphandler = {
	&gz_onevent, &gz_ondone
};

// CONFIG
static int gz_conf_gzipbufsize(ffparser_schem *ps, gz_ctx *zx, const int64 *n);
static int gz_conf_end(ffparser_schem *ps, gz_ctx *zx);

static gzcon* gz_newcon(gz_ctx *zx);


#define GZ_MODNAME "HTGZ"

const ffpars_arg gz_conf_args[] = {
	{ "min_content_length", FFPARS_TSIZE, FFPARS_DSTOFF(gz_ctx, min_contlen) }
	, { "content_type", FFPARS_TSTR | FFPARS_FCOPY, FFPARS_DSTOFF(gz_ctx, mime) }
	, { "buffer_size", FFPARS_TSIZE, FFPARS_DSTOFF(gz_ctx, buf_size) }
	, { "gzip_buffer_size", FFPARS_TSIZE, FFPARS_DST(&gz_conf_gzipbufsize) }
	, { "gzip_level", FFPARS_TINT | FFPARS_F8BIT, FFPARS_DSTOFF(gz_ctx, gzlevel) }
	, { NULL, FFPARS_TCLOSE, FFPARS_DST(&gz_conf_end) }
};

static int gz_conf_gzipbufsize(ffparser_schem *ps, gz_ctx *zx, const int64 *n)
{
	int i = ffgz_wbits((int)*n / 2);
	if (i == -1)
		return FFPARS_EBADVAL;
	zx->gzwbits = i;

	i = ffgz_memlevel((int)*n / 2);
	if (i == -1)
		return FFPARS_EBADVAL;
	zx->gzmemlev = i;

	return 0;
}

static int gz_conf_end(ffparser_schem *ps, gz_ctx *zx)
{
	if (zx->gzlevel > Z_BEST_COMPRESSION)
		return FFPARS_EBADVAL;

	if (zx->mime.ptr == NULL) {
		zx->mime_static = 1;
		ffstr_setcz(&zx->mime, "text/");
	}

	return 0;
}


static void* gzm_create(const fsv_core *core, ffpars_ctx *pctx, fsv_modinfo *mi)
{
	gzm = ffmem_tcalloc1(gz_module);
	if (gzm == NULL)
		return NULL;

	gzm->core = core;
	return gzm;
}

static void gzx_free(gz_ctx *zx)
{
	if (!zx->mime_static)
		ffstr_free(&zx->mime);
	ffmem_free(zx);
}

static void gzm_destroy(void)
{
	FFLIST_ENUMSAFE(&gzm->ctxs, gzx_free, gz_ctx, sib);
	ffmem_free(gzm);
	gzm = NULL;
}

static int gzm_sig(int sig)
{
	return 0;
}

static const void* gzm_iface(const char *name)
{
	if (!ffsz_cmp(name, "http-handler"))
		return &z_httpiface;
	return NULL;
}


static int gz_newctx(fsv_http_hdlctx *ctx)
{
	gz_ctx *zx = ffmem_tcalloc1(gz_ctx);
	if (zx == NULL)
		return 1;
	fflist_ins(&gzm->ctxs, &zx->sib);

	zx->buf_size = 16 * 1024;
	zx->min_contlen = 1024;
	zx->gzmemlev = ffgz_memlevel(32 * 1024);
	zx->gzwbits = ffgz_wbits(32 * 1024);
	zx->gzlevel = 6;

	ctx->hctx = zx;
	ctx->handler = &z_httphandler;
	ffpars_setargs(ctx->args, zx, gz_conf_args, FFCNT(gz_conf_args));
	return 0;
}


static gzcon* gz_newcon(gz_ctx *zx)
{
	int r;
	gzcon *c = ffmem_tcalloc1(gzcon);
	if (c == NULL)
		return NULL;

	if (NULL == ffstr_alloc(&c->buf, zx->buf_size))
		goto err;

	c->gz.opaque = c;
	r = ffgz_deflateinit(&c->gz, zx->gzlevel, zx->gzwbits + 16, zx->gzmemlev);
	if (r != Z_OK) {
		ffstr_free(&c->buf);
		goto err;
	}
	ffgz_setout(&c->gz, c->buf.ptr, zx->buf_size);

	return c;

err:
	ffmem_free(c);
	return NULL;
}

static FFINL ffbool gz_allow(fsv_httphandler *h)
{
	gz_ctx *zx = h->hctx;
	return !(h->flags & FSV_HTTP_ASIS)
		&& h->req->accept_gzip && h->resp->cont_enc.len == 0
		&& (h->resp->code == 200 || h->resp->code == 206)
		&& (h->resp->cont_len == -1 || (uint64)h->resp->cont_len > zx->min_contlen)
		&& (!(h->flags & FSV_HTTP_LAST) || ffsf_len(h->data) > zx->min_contlen)
		&& ffstr_match(&h->resp->cont_type, zx->mime.ptr, zx->mime.len);
}

static void gz_onevent(fsv_httphandler *h)
{
	gzcon *c = h->id->udata;
	gz_ctx *zx = h->hctx;
	ffstr chunk;
	int n, r, flush, f = 0;
	size_t rd, wr, datalen;

	if (h->id->udata == NULL) {

		if (!gz_allow(h)) {
			h->http->send(h->id, NULL, 0, FSV_HTTP_PASS | FSV_HTTP_DONE);
			return;
		}

		c = gz_newcon(h->hctx);
		if (c == NULL)
			goto err;

		h->id->udata = c;
		h->resp->cont_len = -1;
		ffstr_setcz(&h->resp->cont_enc, "gzip");
		ffhttp_addihdr(h->resp, FFHTTP_VARY, FFSTR("Accept-Encoding"));
	}

	for (;;) {

		n = ffsf_nextchunk(h->data, &chunk);
		if (n == -1) {
			fsv_syserrlog(h->logctx, FSV_LOG_ERR, GZ_MODNAME, NULL, "%e", FFERR_FMAP);
			goto fail;
		}

		ffgz_setin(&c->gz, chunk.ptr, chunk.len);

		flush = Z_NO_FLUSH;
		if (n == 0) {
			if (h->flags & FSV_HTTP_LAST)
				flush = Z_FINISH;
			else if (h->flags & FSV_HTTP_PUSH)
				flush = Z_SYNC_FLUSH;
		}

		r = ffgz_deflate(&c->gz, flush, &rd, &wr);
		c->inall += rd;
		c->outall += wr;

		if (r != Z_OK && r != Z_STREAM_END) {
			fsv_errlog(h->logctx, FSV_LOG_ERR, GZ_MODNAME, NULL, "deflate(): (%d) %s"
				, (int)r, ffgz_errstr(&c->gz));
			goto fail;
		}

		fsv_dbglog(h->logctx, FSV_LOG_DBGFLOW, GZ_MODNAME, NULL, "deflate() in: +%L [%U], out: +%L [%U], flush: %u"
			, rd, c->inall, wr, c->outall, flush);

		ffsf_shift(h->data, rd);
		c->buf.len += wr;

		if (r == Z_STREAM_END) {
			r = ffgz_deflatefin(&c->gz);
			if (r != 0) {
				fsv_errlog(h->logctx, FSV_LOG_WARN, GZ_MODNAME, NULL, "deflateEnd(): (%d) %s"
					, r, ffgz_errstr(&c->gz));
			}
			c->gz.opaque = NULL;
			break;
		}

		if (c->buf.len == zx->buf_size) {
			f = FSV_HTTP_MORE;
			break;
		}

		if (n == 0) {
			if (h->flags & FSV_HTTP_PUSH)
				break;
			h->http->send(h->id, NULL, 0, FSV_HTTP_BACK);
			return;
		}
	}

	datalen = c->buf.len;
	c->buf.len = 0;
	ffgz_setout(&c->gz, c->buf.ptr, zx->buf_size);

	h->http->send(h->id, c->buf.ptr, datalen, f);
	return;

fail:
	ffgz_deflatefin(&c->gz);
	c->gz.opaque = NULL;

err:
	ffhttp_setstatus(h->resp, FFHTTP_500_INTERNAL_SERVER_ERROR);
	h->http->fsv_http_err(h->id);
}

static void gz_ondone(fsv_httphandler *h)
{
	gzcon *c = h->id->udata;

	if (c->gz.opaque != NULL) {
		int r = ffgz_deflatefin(&c->gz);
		if (r != 0) {
			fsv_errlog(h->logctx, FSV_LOG_WARN, GZ_MODNAME, NULL, "deflateEnd(): (%d) %s"
				, r, ffgz_errstr(&c->gz));
		}
	}

	if (fsv_log_checkdbglevel(h->logctx, FSV_LOG_DBGFLOW)) {
		uint ratio = (c->inall == 0) ? 0
			: 100 - (uint)((c->outall * 100) / c->inall);
		fsv_dbglog(h->logctx, FSV_LOG_DBGFLOW, GZ_MODNAME, NULL, "input: %U, output: %U, ratio: %u%%"
			, c->inall, c->outall, ratio);
	}

	ffstr_free(&c->buf);
	ffmem_free(c);
}

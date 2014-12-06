/** Send static files over HTTP.
Copyright 2014 Simon Zolin.
*/

#include <core/fserv.h>
#include <http/iface.h>
#include <FF/path.h>
#include <FF/time.h>
#include <FFOS/file.h>
#include <FFOS/dir.h>


typedef struct mime_ext_t {
	uint mimeoff;
	char ext[0];
} mime_ext_t;

typedef struct stfl_module {
	const fsv_core *core;
	fflist ctxs; //stfl_ctx[]

	struct {FFARR(mime_ext_t)} mime_exts;
	ffstr3 mime_types; // "mime1" \0 "mime2" \0 ...
	uint mime_off_last;
	ffhstab htmime; //file extension => mime type

	const fsv_cache *cache;
	fsv_cachectx *cachectx;
} stfl_module;

static stfl_module *stflm;

typedef struct stfl_ctx {
	fflist_item sib;
	ffstr root;
	int maxage;
	ffstr indexes;
} stfl_ctx;

typedef struct stfl_obj {
	fffd f;
	uint64 fsize;
	uint modtm;
	const char *mime;

	fsv_cacheitem_id *cacheid;
} stfl_obj;


// FSERV MODULE
static void* stflm_create(const fsv_core *core, ffpars_ctx *pctx, fsv_modinfo *mi);
static void stflm_destroy(void);
static int stflm_sig(int sig);
static const void* stflm_iface(const char *name);
const fsv_mod fsv_http_stfl = {
	&stflm_create, &stflm_destroy, &stflm_sig, &stflm_iface
};

// HTTP
static int stfl_newctx(fsv_http_hdlctx *ctx);
static const fsv_httphandler_iface stfl_httpiface = {
	&stfl_newctx
};

// HTTP HANDLER
static void stfl_onevent(fsv_httphandler *h);
static void stfl_ondone(fsv_httphandler *h);
static const fsv_http_cb stfl_httphandler = {
	&stfl_onevent, &stfl_ondone
};

// CACHE
static int stfl_cache_onchange(fsv_cachectx *ctx, fsv_cacheitem *ca, int flags);
static const fsv_cach_cb stfl_cachecb = {
	&stfl_cache_onchange
};

// CONFIG
static int stflm_conf_cache(ffparser_schem *ps, stfl_module *mod, ffpars_ctx *args);
static int stflm_conf_mimetypes(ffparser_schem *ps, stfl_module *mod, ffpars_ctx *args);
static int stfl_mime_conf_add(ffparser_schem *ps, void *unused, const ffstr *ext);
static int stfl_mime_conf_end(ffparser_schem *ps, void *unused);
static int stflx_conf_index(ffparser_schem *ps, stfl_ctx *sx, const ffstr *idx);
static int stflx_conf_root(ffparser_schem *ps, stfl_ctx *sx, const ffstr *dir);
static int stfl_htmime_init(void);

static void stflx_destroy(stfl_ctx *sx);
static int stfl_getobj(fsv_httphandler *h, stfl_obj **o);
static int stfl_process_range(fsv_httphandler *h, int *status, uint64 *fsize, uint64 *foff);
static void stfl_add_hdrs(fsv_httphandler *h, const fftime *modtm);
static int stfl_redirect(fsv_httphandler *h);
static void stfl_free(stfl_obj *o);
static void stfl_fin(stfl_obj *o, fsv_logctx *logctx);
static int stfl_htmime_cmpkey(void *udata, const char *key, size_t keylen, void *param);


#define STFL_MODNAME "STFL"

#define syserrlog(logctx, lev, fmt, ...) \
	fsv_syserrlog(logctx, lev, STFL_MODNAME, NULL, fmt, __VA_ARGS__)


static const ffpars_arg stflm_conf_args[] = {
	{ "cache",  FFPARS_TOBJ | FFPARS_FOBJ1,  FFPARS_DST(&stflm_conf_cache) }
	, { "mime_types",  FFPARS_TOBJ | FFPARS_FOBJ1,  FFPARS_DST(&stflm_conf_mimetypes) }
};

static const ffpars_arg stflx_conf_args[] = {
	{ "root",  FFPARS_TSTR | FFPARS_FNOTEMPTY | FFPARS_FREQUIRED,  FFPARS_DST(&stflx_conf_root) }
	, { "max_age",  FFPARS_TINT,  FFPARS_DSTOFF(stfl_ctx, maxage) }
	, { "index",  FFPARS_TSTR | FFPARS_FLIST | FFPARS_FNONULL,  FFPARS_DST(&stflx_conf_index) }
};

const ffpars_arg stfl_mime_conf_args[] = {
	{ "*",  FFPARS_TSTR | FFPARS_FLIST,  FFPARS_DST(&stfl_mime_conf_add) }
	, { NULL,  FFPARS_TCLOSE,  FFPARS_DST(&stfl_mime_conf_end) }
};

static int stflm_conf_cache(ffparser_schem *ps, stfl_module *mod, ffpars_ctx *args)
{
	const ffstr *modname = &ps->vals[0];
	const fsv_modinfo *mi = stflm->core->findmod(modname->ptr, modname->len);
	if (mi == NULL)
		return FFPARS_EBADVAL;

	stflm->cache = mi->f->iface("cache");
	if (stflm->cache == NULL)
		return FFPARS_EBADVAL;

	stflm->cachectx = stflm->cache->newctx(args, &stfl_cachecb, (FFPATH_ICASE) ? FSV_CACH_KEYICASE : 0);
	if (stflm->cachectx == NULL)
		return FFPARS_EBADVAL;

	return 0;
}

static int stflm_conf_mimetypes(ffparser_schem *ps, stfl_module *mod, ffpars_ctx *args)
{
	ffpars_setargs(args, stflm, stfl_mime_conf_args, FFCNT(stfl_mime_conf_args));
	return 0;
}

static int stfl_mime_conf_add(ffparser_schem *ps, void *unused, const ffstr *ext)
{
	mime_ext_t *me;
	char *ar;
	size_t newcap;

	if (ps->p->ret == FFPARS_KEY) {
		// append mime type into array
		const ffstr *mime = ext;
		if (NULL == ffarr_grow(&stflm->mime_types, mime->len + 1, FFARR_GROWQUARTER))
			return FFPARS_ESYS;

		stflm->mime_off_last = (uint)stflm->mime_types.len;
		ffsz_copy(ffarr_end(&stflm->mime_types), ffarr_unused(&stflm->mime_types), mime->ptr, mime->len);
		stflm->mime_types.len += mime->len + 1;
		return 0;
	}

	// alloc storage for file extension and link it to the current mime type
	newcap = stflm->mime_exts.cap + sizeof(mime_ext_t) + ext->len + 1;
	ar = ffmem_realloc(stflm->mime_exts.ptr, newcap);
	if (ar == NULL)
		return FFPARS_ESYS;

	me = (mime_ext_t*)(ar + stflm->mime_exts.cap);
	me->mimeoff = stflm->mime_off_last;
	ffsz_copy(me->ext, ext->len + 1, ext->ptr, ext->len);

	stflm->mime_exts.ptr = (mime_ext_t*)ar;
	stflm->mime_exts.cap = newcap;
	stflm->mime_exts.len++;
	return 0;
}

static int stfl_htmime_init(void)
{
	mime_ext_t *me;
	uint hash;
	size_t i, len;

	if (0 != ffhst_init(&stflm->htmime, stflm->mime_exts.len))
		return 1;

	stflm->htmime.cmpkey = &stfl_htmime_cmpkey;
	me = stflm->mime_exts.ptr;

	for (i = 0;  i != stflm->mime_exts.len;  i++) {

		len = ffsz_len(me->ext);
		hash = ffcrc32_get(me->ext, len, (FFPATH_ICASE) ? FFCRC_ICASE : 0);
		if (ffhst_ins(&stflm->htmime, hash, me) < 0)
			return 1;
		me = (mime_ext_t*)((byte*)me + sizeof(mime_ext_t) + len + 1);
	}

	return 0;
}

static int stfl_mime_conf_end(ffparser_schem *ps, void *unused)
{
	if (0 != stfl_htmime_init())
		return FFPARS_ESYS;
	return 0;
}


static int stflx_conf_root(ffparser_schem *ps, stfl_ctx *sx, const ffstr *dir)
{
	char path[FF_MAXPATH];
	ssize_t r = stflm->core->getpath(path, FFCNT(path), dir->ptr, dir->len);
	if (r == -1)
		return FFPARS_EBADVAL;
	if (NULL == ffstr_copy(&sx->root, path, r))
		return FFPARS_ESYS;
	return 0;
}

static int stflx_conf_index(ffparser_schem *ps, stfl_ctx *sx, const ffstr *idx)
{
	char *s;

	if (ffpath_rfindslash(idx->ptr, idx->len) != ffarr_end(idx))
		return FFPARS_EBADVAL; //can't contain slash

	s = ffmem_realloc(sx->indexes.ptr, sx->indexes.len + idx->len + 1);
	if (s == NULL)
		return FFPARS_ESYS;
	sx->indexes.ptr = s;
	s = ffmem_copy(ffarr_end(&sx->indexes), idx->ptr, idx->len);
	*s = '\0';
	sx->indexes.len += idx->len + 1;
	return 0;
}


static void* stflm_create(const fsv_core *core, ffpars_ctx *pctx, fsv_modinfo *mi)
{
	stflm = ffmem_tcalloc1(stfl_module);
	if (stflm == NULL)
		return NULL;

	stflm->core = core;
	ffpars_setargs(pctx, stflm, stflm_conf_args, FFCNT(stflm_conf_args));
	return stflm;
}

static void stflx_destroy(stfl_ctx *sx)
{
	ffstr_free(&sx->root);
	ffstr_free(&sx->indexes);
	ffmem_free(sx);
}

static void stflm_destroy(void)
{
	FFLIST_ENUMSAFE(&stflm->ctxs, stflx_destroy, stfl_ctx, sib);
	ffhst_free(&stflm->htmime);
	ffarr_free(&stflm->mime_types);
	ffarr_free(&stflm->mime_exts);

	ffmem_free(stflm);
	stflm = NULL;
}

static int stflm_sig(int sig)
{
	return 0;
}

static const void* stflm_iface(const char *name)
{
	if (!ffsz_cmp(name, "http-handler"))
		return &stfl_httpiface;
	return NULL;
}


static int stfl_newctx(fsv_http_hdlctx *ctx)
{
	stfl_ctx *sx = ffmem_tcalloc1(stfl_ctx);
	if (sx == NULL)
		return 1;
	fflist_ins(&stflm->ctxs, &sx->sib);

	sx->maxage = 3600;

	ctx->hctx = sx;
	ctx->handler = &stfl_httphandler;
	ffpars_setargs(ctx->args, sx, stflx_conf_args, FFCNT(stflx_conf_args));
	return 0;
}


/** Handle Range HTTP header.
Note: multi-range is not supported. */
static int stfl_process_range(fsv_httphandler *h, int *status, uint64 *fsize, uint64 *foff)
{
	ffstr val, srange1;
	char rng[FFSLEN("bytes -/") + FFINT_MAXCHARS*3];
	uint64 off, sz, range[2] = {0};
	int st = -1;
	size_t n;

	if (0 == ffhttp_findihdr(&h->req->h, FFHTTP_RANGE, &val)
		|| !ffstr_imatch(&val, FFSTR("bytes=")))
		goto done;

	ffstr_shift(&val, FFSLEN("bytes="));
	if (val.len == 0)
		st = FFHTTP_416_REQUESTED_RANGE_NOT_SATISFIABLE;

	while (val.len != 0) {

		ffstr_shift(&val, ffstr_nextval(val.ptr, val.len, &srange1, ','));
		sz = *fsize;
		off = ffhttp_range(srange1.ptr, srange1.len, &sz);

		if (off == -1) {
			if (st == -1)
				st = FFHTTP_416_REQUESTED_RANGE_NOT_SATISFIABLE;

		} else if (sz == *fsize) {
			goto done;

		} else if (range[1] == 0) {
			st = FFHTTP_206_PARTIAL;
			range[0] = off;
			range[1] = sz;
		}
	}

	if (st == FFHTTP_416_REQUESTED_RANGE_NOT_SATISFIABLE) {
		*status = FFHTTP_416_REQUESTED_RANGE_NOT_SATISFIABLE;
		return 1;
	}

	n = ffs_fmt(rng, rng + sizeof(rng), "bytes %U-%U/%U"
		, range[0], range[0] + range[1] - 1, *fsize);
	ffhttp_addihdr(h->resp, FFHTTP_CONTENT_RANGE, rng, n);
	*fsize = range[1];
	*foff = range[0];

	*status = FFHTTP_206_PARTIAL;
	return 0;

done:
	ffhttp_addihdr(h->resp, FFHTTP_ACCEPT_RANGES, FFSTR("bytes"));
	return 0;
}

static int stfl_htmime_cmpkey(void *udata, const char *key, size_t keylen, void *param)
{
	const mime_ext_t *m = udata;
	if (FFPATH_ICASE)
		return ffs_icmpz(key, keylen, m->ext);
	return ffs_cmpz(key, keylen, m->ext);
}

static const char* stfl_findmime(const ffstr *ext)
{
	uint hash = ffcrc32_get(ext->ptr, ext->len, (FFPATH_ICASE) ? FFCRC_ICASE : 0);
	const mime_ext_t *m = ffhst_find(&stflm->htmime, hash, ext->ptr, ext->len, NULL);
	if (m == NULL)
		return NULL;
	return stflm->mime_types.ptr + m->mimeoff;
}

static void stfl_add_hdrs(fsv_httphandler *h, const fftime *modtm)
{
	stfl_ctx *sx = h->hctx;

	{
	char ma[128];
	size_t n = ffs_fmt(ma, ma + sizeof(ma), "max-age=%u", sx->maxage);
	ffhttp_addihdr(h->resp, FFHTTP_CACHE_CONTROL, ma, n);
	}

	{
	char stm[64];
	ffdtm dt;
	size_t n;
	fftime_split(&dt, modtm, FFTIME_TZUTC);
	n = fftime_tostr(&dt, stm, sizeof(stm), FFTIME_WDMY);
	ffhttp_addihdr(h->resp, FFHTTP_LAST_MODIFIED, stm, n);
	}
}

/** Set Location HTTP header. */
static int stfl_redirect(fsv_httphandler *h)
{
	char loc[4096];
	size_t sz;
	ffstr proto, host, port, path, qs;

	proto.len = h->http->getvar(h->httpcon, FFSTR("https"), &proto.ptr, 0);
	if (proto.len != -1 && ffstr_eqcz(&proto, "1"))
		ffstr_setcz(&proto, "https");
	else
		ffstr_setcz(&proto, "http");

	host = ffhttp_reqhost(h->req);
	if (host.len == 0) //HTTP/1.0 request without host
		host.len = h->http->getvar(h->httpcon, FFSTR("server_addr"), &host.ptr, 0);

	port.len = h->http->getvar(h->httpcon, FFSTR("server_port"), &port.ptr, 0);
	path = ffhttp_requrl(h->req, FFURL_PATH);
	qs = ffhttp_requrl(h->req, FFURL_QS);

	sz = ffs_fmt(loc, loc + sizeof(loc), "%S://%S:%S%S/"
		, &proto, &host, &port, &path);

	if (qs.len != 0) {
		sz += ffs_fmt(loc + sz, loc + sizeof(loc), "?%S"
			, &qs);
	}

	ffhttp_addihdr(h->resp, FFHTTP_LOCATION, loc, sz);
	return FFHTTP_301_MOVED_PERMANENTLY;
}

/** Get object for the requested file. */
static int stfl_getobj(fsv_httphandler *h, stfl_obj **po)
{
	stfl_ctx *sx = h->hctx;
	stfl_obj *o;
	fffd f = FF_BADFD;
	fffileinfo fi;
	ffstr reqpath, fn_ext;
	char fn_s[FF_MAXPATH];
	int st, isindex;
	size_t fnlen, pathlen, indexlen;
	fsv_cacheitem ca;
	const char *pindex = sx->indexes.ptr;

	// get full filename
	reqpath = ffhttp_reqpath(h->req);
	fnlen = ffs_fmt(fn_s, fn_s + sizeof(fn_s), "%S%S%Z"
		, &sx->root, &reqpath);
	if (fnlen-- == sizeof(fn_s)) {
		fsv_errlog(h->logctx, FSV_LOG_ERR, STFL_MODNAME, NULL, "too large filename");
		st = FFHTTP_400_BAD_REQUEST;
		goto fail;
	}
	pathlen = fnlen;

	isindex = ('/' == ffarr_back(&reqpath));

next_index:
	if (isindex) {
		if (pindex == ffarr_end(&sx->indexes)) {
			st = FFHTTP_404_NOT_FOUND;
			goto fail;
		}

		indexlen = ffsz_len(pindex);
		fnlen = ffsz_copy(fn_s + pathlen, sizeof(fn_s) - pathlen, pindex, indexlen) - fn_s;

		pindex += indexlen + 1;
		if (pathlen + indexlen + 1 == sizeof(fn_s))
			goto next_index;
	}

	// search in cache, check whether the file was modified
	if (stflm->cache != NULL) {
		fsv_cache_init(&ca);
		ca.logctx = h->logctx;
		ca.key = fn_s;
		ca.keylen = fnlen;
		if (FSV_CACH_OK == stflm->cache->fetch(stflm->cachectx, &ca, 0)) {
			fftime modtm;
			o = *(stfl_obj**)ca.data;

			if (0 == fffile_time(o->f, &modtm, NULL, NULL)
				&& o->modtm == modtm.s) {

				*po = o;
				return FFHTTP_200_OK;
			}

			stflm->cache->unref(&ca, FSV_CACH_UNLINK);
			o = NULL;
		}
	}

	if (isindex) {

		f = fffile_open(fn_s, FFO_OPEN | O_RDONLY | O_NOATIME | FFO_NODOSNAME);
		if (f == FF_BADFD)
			goto next_index;

		if (0 != fffile_info(f, &fi)
			|| fffile_isdir(fffile_infoattr(&fi))) {

			fffile_close(f);
			f = FF_BADFD;
			goto next_index;
		}

	} else {

		f = fffile_open(fn_s, FFO_OPEN | O_RDONLY | O_NOATIME | FFO_NODOSNAME);
		if (f == FF_BADFD) {

#ifdef FF_WIN
			if (fferr_last() == ERROR_ACCESS_DENIED) {
				int a = fffile_attrfn(fn_s);
				if (fffile_isdir(a))
					goto redirect;
			}
#endif

			st = FFHTTP_500_INTERNAL_SERVER_ERROR;
			if (fferr_nofile(fferr_last()))
				st = FFHTTP_404_NOT_FOUND;
			syserrlog(h->logctx, FSV_LOG_ERR, "%s: %e", fn_s, FFERR_FOPEN);
			goto fail;
		}

		if (0 != fffile_info(f, &fi)) {
			syserrlog(h->logctx, FSV_LOG_ERR, "get file info: %s", fn_s);
			st = FFHTTP_403_FORBIDDEN;
			goto fail;
		}

		if (fffile_isdir(fffile_infoattr(&fi)))
			goto redirect;
	}

	o = ffmem_tcalloc1(stfl_obj);
	if (o == NULL) {
		syserrlog(h->logctx, FSV_LOG_ERR, "%e", FFERR_BUFALOC);
		st = FFHTTP_500_INTERNAL_SERVER_ERROR;
		goto fail;
	}
	o->f = f;
	f = FF_BADFD;
	o->fsize = fffile_infosize(&fi);
	o->modtm = fffile_infotimew(&fi).s;

	fn_ext = ffpath_fileext(fn_s, fnlen);
	o->mime = stfl_findmime(&fn_ext);

	if (stflm->cache != NULL) {
		ca.key = fn_s;
		ca.keylen = fnlen;
		ca.data = (void*)&o;
		ca.datalen = sizeof(stfl_obj*);
		ca.id = NULL;
		ca.expire = sx->maxage;
		ca.refs = 1;
		if (FSV_CACH_OK == stflm->cache->store(stflm->cachectx, &ca, 0)) {
			o->cacheid = ca.id;
		}
	}

	*po = o;
	return FFHTTP_200_OK;

redirect:
	fsv_dbglog(h->logctx, FSV_LOG_DBGFLOW, STFL_MODNAME, NULL, "the requested file is a directory");
	st = stfl_redirect(h);

fail:
	if (f != FF_BADFD)
		fffile_close(f);
	*po = NULL;
	return st;
}

static void stfl_onevent(fsv_httphandler *h)
{
	stfl_obj *o = NULL;
	uint64 fsize, foff;
	fftime modtm;
	ffstr ifmod;
	int st, f;

	st = stfl_getobj(h, &o);
	if (st == FFHTTP_301_MOVED_PERMANENTLY) {
		f = 0;
		goto done;
	}

	if (st != FFHTTP_200_OK) {
		f = FSV_HTTP_ERROR;
		goto done;
	}

	if (0 != ffhttp_findihdr(&h->req->h, FFHTTP_IFMODIFIED_SINCE, &ifmod)
		&& o->modtm == fftime_strtounix(ifmod.ptr, ifmod.len, FFTIME_WDMY)) {
		st = FFHTTP_304_NOT_MODIFIED;
		f = 0;
		goto done;
	}

	fsize = o->fsize;
	foff = 0;
	modtm.s = o->modtm;
	modtm.mcs = 0;
	if (0 != stfl_process_range(h, &st, &fsize, &foff)) {
		f = FSV_HTTP_ERROR;
		goto done;
	}

	if (o->mime != NULL)
		ffstr_setz(&h->resp->cont_type, o->mime);

	stfl_add_hdrs(h, &modtm);

	h->id->udata = o;
	ffhttp_setstatus(h->resp, st);
	h->http->sendfile(h->id, o->f, fsize, foff, NULL, FSV_HTTP_NOINPUT);
	return;

done:
	if (o != NULL)
		stfl_fin(o, h->logctx);
	ffhttp_setstatus(h->resp, st);
	h->http->send(h->id, NULL, 0, f);
}

static void stfl_ondone(fsv_httphandler *h)
{
	stfl_fin(h->id->udata, h->logctx);
}

static void stfl_fin(stfl_obj *o, fsv_logctx *logctx)
{
	if (o->cacheid != NULL) {
		fsv_cacheitem ca;
		fsv_cache_init(&ca);
		ca.logctx = logctx;
		ca.id = o->cacheid;
		stflm->cache->unref(&ca, 0);
		return;
	}

	stfl_free(o);
}

static void stfl_free(stfl_obj *o)
{
	fffile_close(o->f);
	ffmem_free(o);
}


static int stfl_cache_onchange(fsv_cachectx *ctx, fsv_cacheitem *ca, int flags)
{
	if (flags == FSV_CACH_ONDELETE)
		stfl_free(*(stfl_obj**)ca->data);
	return 0;
}

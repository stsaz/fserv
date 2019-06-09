/** Directory autoindex.
Copyright 2014 Simon Zolin.
*/

#include <core/fserv.h>
#include <http/iface.h>
#include <FFOS/dir.h>
#include <FF/time.h>
#include <FF/crc.h>
#include <FF/data/xml.h>


typedef struct drix_module {
	const fsv_core *core;
	fflist ctxs; //drix_ctx[]
	ffstr template;
	byte show_hidden;

	const fsv_cache *cache;
	fsv_cachectx *cachectx;
} drix_module;

static drix_module *drixm;

typedef struct drix_ctx {
	fflist_item sib;
	ffstr root;
	int maxage; //in seconds
} drix_ctx;

typedef struct drix_obj {
	ffstr data;
	uint crc;
	fsv_cacheitem_id *cacheid;
} drix_obj;

typedef struct drix_con {
	fsv_httphandler *h;
	drix_obj *obj;
	ffstr3 page;
	ffiovec iovs[3]; //header + contents + footer
} drix_con;

typedef struct direntry {
	ffstr fn;
	ffdir_einfo fi;
} direntry;

typedef struct direntries {
	ffdir dir;
	ffdirentry de;
	struct {FFARR(direntry)} ents;
	uint crc;
	uint show_hidden :1
		, use_crc :1;
} direntries;


// FSERV MODULE
static void* drixm_create(const fsv_core *core, ffpars_ctx *pctx, fsv_modinfo *mi);
static void drixm_destroy(void);
static int drixm_sig(int sig);
static const void* drixm_iface(const char *name);
const fsv_mod fsv_http_drix = {
	&drixm_create, &drixm_destroy, &drixm_sig, &drixm_iface
};

// HTTP
static int drix_newctx(fsv_http_hdlctx *ctx);
static const fsv_httphandler_iface drix_httpiface = {
	&drix_newctx
};

// HTTP HANDLER
static void drix_onevent(fsv_httphandler *h);
static void drix_ondone(fsv_httphandler *h);
static const fsv_http_cb drix_httphandler = {
	&drix_onevent, &drix_ondone
};

// CACHE
static int drix_cache_onchange(fsv_cachectx *ctx, fsv_cacheitem *ca, int flags);
static const fsv_cach_cb drix_cachecb = {
	&drix_cache_onchange
};

// CONFIG
static int drixm_conf_cache(ffparser_schem *ps, drix_module *mod, ffpars_ctx *args);
static int drixm_conf_template(ffparser_schem *ps, drix_module *mod, const ffstr *fn);
static int drix_conf_root(ffparser_schem *ps, drix_ctx *dx, const ffstr *dir);

static void drix_free(drix_obj *o);
static void drix_fin(drix_obj *o, fsv_logctx *logctx);
static int drix_getobj(fsv_httphandler *h, drix_obj **po);
static ssize_t drix_getvar(void *con, const char *name, size_t namelen, void *dst, size_t cap);
static int drix_ents_sortfunc(const void *a, const void *b, void *udata);
static void drix_ifmatch(drix_obj *o, fsv_httphandler *h, int *st);

enum DRIX_ITEM_FLAGS {
	F_INIT = 1
};
static int drix_html_additem(ffstr3 *buf, const direntry *ent, int f);


static const ffpars_arg drixm_conf_args[] = {
	{ "cache",  FFPARS_TOBJ | FFPARS_FOBJ1,  FFPARS_DST(&drixm_conf_cache) }
	, { "template",  FFPARS_TSTR | FFPARS_FNOTEMPTY,  FFPARS_DST(&drixm_conf_template) }
	, { "show_hidden",  FFPARS_TBOOL | FFPARS_F8BIT,  FFPARS_DSTOFF(drix_module, show_hidden) }
};

static const ffpars_arg drix_conf_args[] = {
	{ "root",  FFPARS_TSTR | FFPARS_FNOTEMPTY | FFPARS_FREQUIRED,  FFPARS_DST(&drix_conf_root) }
	, { "max_age",  FFPARS_TINT,  FFPARS_DSTOFF(drix_ctx, maxage) }
};

#define DRIX_MODNAME "DRIX"

#define syserrlog(logctx, lev, fmt, ...) \
	fsv_syserrlog(logctx, lev, DRIX_MODNAME, NULL, fmt, __VA_ARGS__)


static int drixm_conf_cache(ffparser_schem *ps, drix_module *mod, ffpars_ctx *args)
{
	const ffstr *modname = &ps->vals[0];
	const fsv_modinfo *mi = drixm->core->findmod(modname->ptr, modname->len);
	if (mi == NULL)
		return FFPARS_EBADVAL;

	drixm->cache = mi->f->iface("cache");
	if (drixm->cache == NULL)
		return FFPARS_EBADVAL;

	drixm->cachectx = drixm->cache->newctx(args, &drix_cachecb, (FFPATH_ICASE) ? FSV_CACH_KEYICASE : 0);
	if (drixm->cachectx == NULL)
		return FFPARS_EBADVAL;

	return 0;
}

/** Read the whole file into memory buffer. */
void* http_loadfile(const char *fn, size_t *size)
{
	ffarr a = {0};
	if (0 != fffile_readall(&a, fn, 1 * 1024 * 1024)) {
		ffarr_free(&a);
		return NULL;
	}
	*size = a.len;
	return a.ptr;
}

static int drixm_conf_template(ffparser_schem *ps, drix_module *mod, const ffstr *fn)
{
	char *path = drixm->core->getpath(NULL, NULL, fn->ptr, fn->len);
	if (path == NULL)
		return FFPARS_EBADVAL;
	drixm->template.ptr = (char*)http_loadfile(path, &drixm->template.len);
	ffmem_free(path);
	if (drixm->template.ptr == NULL)
		return FFPARS_ESYS;
	return 0;
}

static int drix_conf_root(ffparser_schem *ps, drix_ctx *dx, const ffstr *dir)
{
	dx->root.ptr = drixm->core->getpath(NULL, &dx->root.len, dir->ptr, dir->len);
	if (dx->root.ptr == NULL)
		return FFPARS_EBADVAL;
	return 0;
}


static void* drixm_create(const fsv_core *core, ffpars_ctx *pctx, fsv_modinfo *mi)
{
	drixm = ffmem_tcalloc1(drix_module);
	if (drixm == NULL)
		return NULL;

	drixm->show_hidden = 0;
	fflist_init(&drixm->ctxs);

	drixm->core = core;
	ffpars_setargs(pctx, drixm, drixm_conf_args, FFCNT(drixm_conf_args));
	return drixm;
}

static void drix_destroy(drix_ctx *dx)
{
	ffstr_free(&dx->root);
	ffmem_free(dx);
}

static void drixm_destroy(void)
{
	FFLIST_ENUMSAFE(&drixm->ctxs, drix_destroy, drix_ctx, sib);
	ffstr_free(&drixm->template);
	ffmem_free(drixm);
	drixm = NULL;
}

static int drixm_sig(int sig)
{
	return 0;
}

static const void* drixm_iface(const char *name)
{
	if (!ffsz_cmp(name, "http-handler"))
		return &drix_httpiface;
	return NULL;
}


static int drix_newctx(fsv_http_hdlctx *ctx)
{
	drix_ctx *dx = ffmem_tcalloc1(drix_ctx);
	if (dx == NULL)
		return 1;
	fflist_ins(&drixm->ctxs, &dx->sib);

	dx->maxage = 1 * 60;

	ctx->hctx = dx;
	ctx->handler = &drix_httphandler;
	ffpars_setargs(ctx->args, dx, drix_conf_args, FFCNT(drix_conf_args));
	return 0;
}


static void dirents_free(direntries *e)
{
	direntry *ent;
	FFARR_WALK(&e->ents, ent) {
		ffstr_free(&ent->fn);
	}
	ffarr_free(&e->ents);
}

/** Get list of files in directory. */
static int dirents_fill(direntries *e)
{
	const ffdir_einfo *fi;
	direntry *ent;
	ffsyschar *name;
	char *fn;

	if (e->use_crc)
		e->crc = ffcrc32_start();

	for (;;) {

		if (0 != ffdir_read(e->dir, &e->de)) {
			if (fferr_last() != ENOMOREFILES)
				return FFERR_SYSTEM;
			break;
		}

		name = ffdir_entryname(&e->de);
		if ((e->de.namelen == 1 && name[0] == '.') // ".."
			|| ((name[0] == '.') && !e->show_hidden)) // ".*"
			continue;

		fi = ffdir_entryinfo(&e->de);
		if (fi == NULL)
			return FFERR_SYSTEM;

		if (NULL == ffarr_grow(&e->ents, 1, FFARR_GROWQUARTER))
			return FFERR_BUFGROW;

		fn = (char*)ffmem_alloc(e->de.namelen + 1);
		if (fn == NULL)
			return FFERR_BUFALOC;

		ent = ffarr_push(&e->ents, direntry);
		ffstr_set(&ent->fn, fn, e->de.namelen);
		ffs_copyq(ent->fn.ptr, ent->fn.ptr + e->de.namelen + 1, name, e->de.namelen + 1);

		ent->fi = *fi;

		if (e->use_crc) {
			ffcrc32_updatestr(&e->crc, ent->fn.ptr, ent->fn.len);
			ffcrc32_updatestr(&e->crc, (char*)fi, sizeof(ffdir_einfo));
		}
	}

	if (e->use_crc)
		ffcrc32_finish(&e->crc);

	return FFERR_OK;
}


/** Alpha-sort filenames, directories first. */
static int drix_ents_sortfunc(const void *a, const void *b, void *udata)
{
	const direntry *e1 = a;
	const direntry *e2 = b;
	unsigned dir1 = fffile_isdir(fffile_infoattr(&e1->fi))
		, dir2 = fffile_isdir(fffile_infoattr(&e2->fi));

	if (dir1 && !dir2)
		return -1;
	if (!dir1 && dir2)
		return 1;

	return ffsz_icmp(e1->fn.ptr, e2->fn.ptr);
}

static ssize_t drix_getvar(void *con, const char *name, size_t namelen, void *dst, size_t cap)
{
	drix_con *c = con;
	ffstr s;

	if (ffs_eqcz(name, namelen, "dir_content"))
		ffstr_setcz(&s, "$dir_content"); //substitute later

	else if (ffs_eqcz(name, namelen, "dir_name"))
		s = ffhttp_reqpath(c->h->req);

	else
		return c->h->http->getvar(c->h->httpcon, name, namelen, dst, cap);

	*(char**)dst = s.ptr;
	return s.len;
}

/** Get contents of a directory. */
static int drix_getobj(fsv_httphandler *h, drix_obj **po)
{
	drix_ctx *dx = h->hctx;
	drix_obj *o = NULL;
	ffstr3 fn = {0}, buf = {0};
	ffstr reqpath;
	direntries e = {0};
	direntry *ent;
	fsv_cacheitem ca;
	int r, st = FFHTTP_500_INTERNAL_SERVER_ERROR;

	// get full filename
	reqpath = ffhttp_reqpath(h->req);
	if (NULL == ffarr_alloc(&fn, dx->root.len + reqpath.len + FF_MAXFN + 1)) {
		syserrlog(h->logctx, FSV_LOG_ERR, "%e", FFERR_BUFALOC);
		goto fail;
	}
	fn.len = ffs_fmt(fn.ptr, fn.ptr + fn.cap, "%S%S%Z", &dx->root, &reqpath) - 1;

	// search in cache
	if (drixm->cache != NULL) {
		fsv_cache_init(&ca);
		ca.logctx = h->logctx;
		ca.key = fn.ptr;
		ca.keylen = fn.len;
		if (FSV_CACH_OK == drixm->cache->fetch(drixm->cachectx, &ca, 0)) {
			o = *(drix_obj**)ca.data;
		}
	}

	e.dir = ffdir_open(fn.ptr, fn.cap, &e.de);
	if (e.dir == 0) {
		if (fferr_nofile(fferr_last()))
			st = FFHTTP_404_NOT_FOUND;
		syserrlog(h->logctx, FSV_LOG_ERR, "%e: %s", FFERR_DIROPEN, fn.ptr);
		if (o != NULL)
			drixm->cache->unref(drixm->cachectx, &ca, FSV_CACH_UNLINK);
		goto fail;
	}

	e.show_hidden = (drixm->show_hidden) ? 1 : 0;
	e.use_crc = 1;
	r = dirents_fill(&e);
	ffdir_close(e.dir);
	if (r != FFERR_OK) {
		syserrlog(h->logctx, FSV_LOG_ERR, "%e", (int)r);
		if (o != NULL)
			drixm->cache->unref(drixm->cachectx, &ca, FSV_CACH_UNLINK);
		goto fail;
	}

	// check if stale data
	if (o != NULL) {
		if (e.crc == o->crc) {
			*po = o;
			st = FFHTTP_200_OK;
			goto done;
		}

		drixm->cache->unref(drixm->cachectx, &ca, FSV_CACH_UNLINK);
		o = NULL;
	}

	ffsort(e.ents.ptr, e.ents.len, sizeof(direntry), &drix_ents_sortfunc, NULL);

	if (0 != drix_html_additem(&buf, NULL, F_INIT))
		goto fail;
	FFARR_WALK(&e.ents, ent) {
		if (0 != drix_html_additem(&buf, ent, 0))
			goto fail;
	}

	o = ffmem_tcalloc1(drix_obj);
	if (o == NULL) {
		syserrlog(h->logctx, FSV_LOG_ERR, "%e", FFERR_BUFALOC);
		goto fail;
	}
	ffstr_acqstr3(&o->data, &buf);
	o->crc = e.crc;

	if (drixm->cache != NULL) {
		ca.data = (void*)&o;
		ca.datalen = sizeof(drix_obj*);
		ca.id = NULL;
		ca.expire = dx->maxage;
		ca.refs = 1;
		if (FSV_CACH_OK == drixm->cache->store(drixm->cachectx, &ca, 0)) {
			o->cacheid = ca.id;
		}
	}

	*po = o;
	st = FFHTTP_200_OK;
	goto done;

fail:
	*po = NULL;

done:
	dirents_free(&e);
	ffarr_free(&fn);
	ffarr_free(&buf);
	return st;
}

/** Set 304 response code if appropriate. */
static void drix_ifmatch(drix_obj *o, fsv_httphandler *h, int *st)
{
	char etag[64];
	size_t n = ffs_fmt(etag, etag + sizeof(etag), "\"%u\"", o->crc);
	ffstr val;

	if (0 == ffhttp_findihdr(&h->req->h, FFHTTP_IFNONE_MATCH, &val)) {
		ffhttp_addihdr(h->resp, FFHTTP_ETAG, etag, n);
		return;
	}

	if (0 == ffhttp_ifnonematch(etag, n, &val))
		*st = FFHTTP_304_NOT_MODIFIED;
}

static void drix_onevent(fsv_httphandler *h)
{
	drix_ctx *dx = h->hctx;
	drix_obj *o = NULL;
	drix_con *c = NULL;
	int niovs, st, f = FSV_HTTP_ERROR;
	size_t content_off;
	ffstr ftr;

	st = drix_getobj(h, &o);
	if (st != FFHTTP_200_OK)
		goto done;

	drix_ifmatch(o, h, &st);
	if (st == FFHTTP_304_NOT_MODIFIED) {
		f = 0;
		goto done;
	}

	c = ffmem_tcalloc1(drix_con);
	if (c == NULL) {
		syserrlog(h->logctx, FSV_LOG_ERR, "%e", FFERR_BUFALOC);
		st = FFHTTP_500_INTERNAL_SERVER_ERROR;
		goto done;
	}

	c->h = h;
	c->obj = o;
	if (0 != drixm->core->process_vars(&c->page, &drixm->template, &drix_getvar, c, h->logctx)) {
		st = FFHTTP_500_INTERNAL_SERVER_ERROR;
		goto done;
	}
	c->h = NULL;

	{
	char cc[128];
	size_t n = ffs_fmt(cc, cc + sizeof(cc), "max-age=%u", dx->maxage);
	ffhttp_addihdr(h->resp, FFHTTP_CACHE_CONTROL, cc, n);
	}

	ffstr_setcz(&h->resp->cont_type, "text/html; charset=UTF-8");

	h->id->udata = c;
	ffhttp_setstatus(h->resp, st);

	content_off = ffs_finds(c->page.ptr, c->page.len, "$dir_content", FFSLEN("$dir_content")) - c->page.ptr;
	niovs = 0;
	ffiov_set(&c->iovs[niovs++], c->page.ptr, content_off);
	ffiov_set(&c->iovs[niovs++], c->obj->data.ptr, c->obj->data.len);
	if (content_off != c->page.len) {
		ffstr_set2(&ftr, &c->page);
		ffstr_shift(&ftr, content_off + FFSLEN("$dir_content"));
		ffiov_set(&c->iovs[niovs++], ftr.ptr, ftr.len);
	}
	h->http->sendv(h->id, c->iovs, niovs, FSV_HTTP_NOINPUT);
	return;

done:
	if (o != NULL)
		drix_fin(o, h->logctx);
	if (c != NULL)
		ffmem_free(c);
	ffhttp_setstatus(h->resp, st);
	h->http->send(h->id, NULL, 0, f);
}

static void drix_ondone(fsv_httphandler *h)
{
	drix_con *c = h->id->udata;
	drix_obj *o = c->obj;

	ffarr_free(&c->page);
	ffmem_free(c);

	drix_fin(o, h->logctx);
}

static void drix_free(drix_obj *o)
{
	ffstr_free(&o->data);
	ffmem_free(o);
}

static void drix_fin(drix_obj *o, fsv_logctx *logctx)
{
	if (o->cacheid != NULL) {
		fsv_cacheitem ca;
		fsv_cache_init(&ca);
		ca.logctx = logctx;
		ca.id = o->cacheid;
		drixm->cache->unref(drixm->cachectx, &ca, 0);
		return;
	}

	drix_free(o);
}


static int drix_html_additem(ffstr3 *buf, const direntry *ent, int f)
{
	ffstr html_esc, uri_esc, sfsize;
	char sdt[64], sfsize_s[FFINT_MAXCHARS]
		, uri_esc_s[255 * FFSLEN("%0")]
		, html_esc_s[255 * FFSLEN("&quot")];
	size_t nsdt = 0, n;
	ffbool isdir;

	if (f & F_INIT) {
		ffstr_setcz(&html_esc, "../");
		ffstr_setcz(&uri_esc, "../");
		ffstr_setcz(&sfsize, "&lt;DIR&gt;");
		goto fin;
	}

	isdir = fffile_isdir(fffile_infoattr(&ent->fi));
	if (isdir)
		ffstr_setcz(&sfsize, "&lt;DIR&gt;");
	else {
		int r = ffs_fromint(fffile_infosize(&ent->fi), sfsize_s, sizeof(sfsize_s), 0);
		ffstr_set(&sfsize, sfsize_s, r);
	}

	{
	ffdtm dt;
	fftime lwtm = fffile_infomtime(&ent->fi);
	fftime_split(&dt, &lwtm, FFTIME_TZUTC);
	nsdt = fftime_tostr(&dt, sdt, sizeof(sdt), FFTIME_WDMY);
	}

	html_esc.len = ffxml_escape(html_esc_s, sizeof(html_esc_s) - 1, ent->fn.ptr, ent->fn.len);
	html_esc.ptr = html_esc_s;
	uri_esc.len = ffuri_escape(uri_esc_s, sizeof(uri_esc_s) - 1, ent->fn.ptr, ent->fn.len, FFURI_ESC_PATHSEG);
	uri_esc.ptr = uri_esc_s;
	if (html_esc.len == sizeof(html_esc_s) - 1
		|| uri_esc.len == sizeof(uri_esc_s) - 1)
		return 1;

	if (isdir) {
		html_esc.ptr[html_esc.len++] = '/';
		uri_esc.ptr[uri_esc.len++] = '/';
	}

fin:
	n = ffstr_catfmt(buf,
"<tr>"
"<td><a href=\"%S\">%S</a></td>"
"<td>%*s</td>"
"<td class=\"size\">%S</td>"
"</tr>"
		, &uri_esc, &html_esc
		, nsdt, sdt
		, &sfsize);

	return (n != 0) ? 0 : 1;
}


static int drix_cache_onchange(fsv_cachectx *ctx, fsv_cacheitem *ca, int flags)
{
	if (flags == FSV_CACH_ONDELETE)
		drix_free(*(drix_obj**)ca->data);
	return 0;
}

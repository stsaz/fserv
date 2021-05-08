/** In-memory cache.
Copyright 2014 Simon Zolin.
*/

#include <core/fserv.h>
#include <FF/cache.h>
#include <FF/rbtree.h>
#include <FF/list.h>
#include <FF/data/json.h>
#include <FFOS/file.h>


typedef struct cachemodule {
	const fsv_core *srv;
	fsv_logctx *logctx;
	fflist ctxs; //cachectx[]
} cachemodule;

typedef struct cachectx {
	ffcache *x;
	fflist_item sib;
	ffrbtree items;
	fflist lastused;
	const fsv_cach_cb *cb;
	size_t memsize; //length of keys and data

	ffcache_conf conf;
	//conf:
	char sname[FFINT_MAXCHARS];
	ffstr name;
	uint max_items
		, max_data
		, mem_limit
		, def_expire
		, max_expire;
	unsigned key_icase :1
		, multi :1;
} cachectx;

static cachemodule *cachm;

#define CACH_MODNAME  "CACH"


// FSERV MODULE
static void * cachm_create(const fsv_core *srv, ffpars_ctx *c, fsv_modinfo *m);
static void cachm_destroy(void);
static int cachm_sig(int sig);
static const void * cachm_iface(const char *name);
static const fsv_mod fsv_cache_mod = {
	&cachm_create, &cachm_destroy, &cachm_sig, &cachm_iface
};

// FSERV CACHE
static fsv_cachectx * cach_newctx(ffpars_ctx *a, const fsv_cach_cb *cb, int flags);
static int cach_fetch(fsv_cachectx *cx, fsv_cacheitem *ca, int flags);
static int cach_store(fsv_cachectx *cx, fsv_cacheitem *ca, int flags);
static int cach_update(fsv_cachectx *cx, fsv_cacheitem *ca, int flags);
static int cach_unref(fsv_cachectx *cx, fsv_cacheitem *ca, int flags);
static const fsv_cache fsv_cach_iface = {
	&cach_newctx, &cach_fetch, &cach_store, &cach_update, &cach_unref
};

// STATUS
static void cach_status(const fsv_status *statusmod);
static const fsv_status_handler cach_stat_iface = {
	&cach_status
};

static void cachm_clear(void);


static void oninit(void)
{
	ffmem_init();
}
FFDL_ONINIT(oninit, NULL)


FF_EXTN const fsv_mod fsv_cach_file;

FF_EXTN FF_EXP const fsv_mod * fsv_getmod(const char *name)
{
	if (!ffsz_cmp(name, "mem"))
		return &fsv_cache_mod;
	else if (!ffsz_cmp(name, "file"))
		return &fsv_cach_file;
	return NULL;
}

static void timer(fftmrq_entry *tmr, uint value_ms)
{
	cachm->srv->timer(tmr, -(int)value_ms, tmr->handler, tmr->param);
}

static int onchange(ffcache *c, ffcache_item *ci, uint flags)
{
	cachectx *cx = ffcache_udata(c);

	fsv_dbglog(cachm->logctx, FSV_LOG_DBGFLOW, CACH_MODNAME, &cx->name
		, "deleted: \"%S\""
		, &ci->key);

	fsv_cacheitem ca = {};
	ca.id = ci->id;
	ca.hash[0] = ci->keyhash[0];
	ca.key = ci->key.ptr,  ca.keylen = ci->key.len;
	ca.data = ci->data.ptr,  ca.datalen = ci->data.len;
	return cx->cb->onchange((fsv_cachectx*)cx, &ca, flags);
}

static int conf_done(ffparser_schem *ps, void *obj)
{
	cachectx *cx = obj;
	ffcache_conf conf;
	ffcache_conf_init(&conf);
	conf.timer = &timer;
	conf.onchange = &onchange;

	conf.name = cx->name;
	conf.max_items = cx->max_items;
	conf.max_data = cx->max_data;
	conf.mem_limit = cx->mem_limit;
	conf.def_expire = cx->def_expire;
	conf.max_expire = cx->max_expire;
	conf.key_icase = cx->key_icase;
	conf.multi = cx->multi;
	conf.udata = cx;

	if (NULL == (cx->x = ffcache_create(&conf)))
		return FFPARS_EBADVAL;
	return 0;
}

static const ffpars_arg cachx_conf_args[] = {
	{ "max_items",  FFPARS_TINT | FFPARS_FNOTZERO,  FFPARS_DSTOFF(cachectx, max_items) }
	, { "expiry",  FFPARS_TINT,  FFPARS_DSTOFF(cachectx, def_expire) }
	, { "max_age",  FFPARS_TINT,  FFPARS_DSTOFF(cachectx, max_expire) }
	, { "max_data",  FFPARS_TSIZE | FFPARS_FNOTZERO,  FFPARS_DSTOFF(cachectx, max_data) }
	, { "mem_limit",  FFPARS_TSIZE | FFPARS_FNOTZERO,  FFPARS_DSTOFF(cachectx, mem_limit) }
	, { NULL,  FFPARS_TCLOSE,  FFPARS_DST(&conf_done) }
};


static void * cachm_create(const fsv_core *srv, ffpars_ctx *c, fsv_modinfo *m)
{
	const fsvcore_config *conf = srv->conf();

	cachm = ffmem_tcalloc1(cachemodule);
	if (cachm == NULL)
		return NULL;

	fflist_init(&cachm->ctxs);
	cachm->srv = srv;
	cachm->logctx = conf->logctx;

	ffpars_setargs(c, cachm, NULL, 0);
	return cachm;
}

static void cachx_fin(cachectx *cx)
{
	ffcache_free(cx->x);
}

static void cachm_destroy(void)
{
	FFLIST_ENUMSAFE(&cachm->ctxs, cachx_fin, cachectx, sib);
	ffmem_free(cachm);
	cachm = NULL;
}

static int cachm_sig(int sig)
{
	switch (sig) {
	case FSVCORE_SIGSTART:
		break;

	case FSVCORE_SIGSTOP:
		cachm_clear();
		break;

	case FSVCORE_SIGREOPEN:
		cachm_clear();
		break;
	}

	return 0;
}

static const void * cachm_iface(const char *name)
{
	if (0 == ffsz_cmp(name, "cache"))
		return &fsv_cach_iface;
	else if (0 == ffsz_cmp(name, "json-status"))
		return &cach_stat_iface;
	return NULL;
}

static void cachm_clear(void)
{
	cachectx *cx;
	_FFLIST_WALK(&cachm->ctxs, cx, sib) {
		ffcache_reset(cx->x);
	}
}

static const int cach_status_jsonmeta[] = {
	FFJSON_TOBJ
	, FFJSON_FKEYNAME, FFJSON_FSTRZ
	, FFJSON_FKEYNAME, FFJSON_FINTVAL
	, FFJSON_FKEYNAME, FFJSON_FINTVAL
	, FFJSON_FKEYNAME, FFJSON_FINTVAL
	, FFJSON_FKEYNAME, FFJSON_FINTVAL
	, FFJSON_TOBJ
};

static void cach_status(const fsv_status *statusmod)
{
	const cachectx *cx;
	ffjson_cook status_json;
	char buf[4096];
	ffjson_cookinit(&status_json, buf, sizeof(buf));

	_FFLIST_WALK(&cachm->ctxs, cx, sib) {
		struct ffcache_stat st;
		ffcache_stat(cx->x, &st);
		ffjson_addv(&status_json, cach_status_jsonmeta, FFCNT(cach_status_jsonmeta)
			, FFJSON_CTXOPEN
			, "id", cx->sname
			, "items", (int64)cx->items.len
			, "hits", (int64)st.hits
			, "misses", (int64)st.misses
			, "memory", (int64)cx->memsize
			, FFJSON_CTXCLOSE
			, NULL);
	}

	statusmod->setdata(status_json.buf.ptr, status_json.buf.len, 0);
	ffjson_cookfin(&status_json);
}


static fsv_cachectx * cach_newctx(ffpars_ctx *a, const fsv_cach_cb *cb, int flags)
{
	cachectx *cx = ffmem_tcalloc1(cachectx);
	if (cx == NULL)
		return NULL;
	fflist_ins(&cachm->ctxs, &cx->sib);

	ffrbt_init(&cx->items);
	fflist_init(&cx->lastused);
	cx->max_items = 64 * 1000;
	cx->mem_limit = 200 * 1024 * 1024;
	cx->max_data = 1 * 1024 * 1024;
	cx->def_expire = 1 * 60 * 60;
	cx->max_expire = 24 * 60 * 60;
	cx->cb = cb;
	cx->name.len = ffs_fmt(cx->sname, cx->sname + FFCNT(cx->sname), "#%L%Z", cachm->ctxs.len) - 1;
	cx->name.ptr = cx->sname;

	if (flags & FSV_CACH_KEYICASE)
		cx->key_icase = 1;

	if (flags & FSV_CACH_MULTI)
		cx->multi = 1;

	ffpars_setargs(a, cx, cachx_conf_args, FFCNT(cachx_conf_args));
	return (fsv_cachectx*)cx;
}


static int cach_fetch(fsv_cachectx *fcx, fsv_cacheitem *ca, int flags)
{
	cachectx *cx = (cachectx*)fcx;
	void *logctx = (ca->logctx != NULL) ? ca->logctx : cachm->logctx;

	ffcache_item ci = {};
	ci.id = ca->id;
	ci.keyhash[0] = ca->hash[0];
	ci.refs = ca->refs;
	ffstr_set(&ci.key, ca->key, ca->keylen);
	ffstr_set(&ci.data, ca->data, ca->datalen);

	uint f = flags;
	int r = ffcache_fetch(cx->x, &ci, f);
	if (r != 0) {

		if (r == FFCACHE_ENOTFOUND) {
			fsv_dbglog(logctx, FSV_LOG_DBGFLOW, CACH_MODNAME, &cx->name
				, "fetch: \"%S\": %s"
				, &ci.key, ffcache_errstr(r));

		} else {
			fsv_errlog(logctx, FSV_LOG_WARN, CACH_MODNAME, &cx->name
				, (r == FFCACHE_ESYS) ? "fetch: \"%S\": %s: %E" : "fetch: \"%*s\": %s"
				, &ci.key, ffcache_errstr(r), fferr_last());
		}
		return r;
	}

	fsv_dbglog(logctx, FSV_LOG_DBGFLOW, CACH_MODNAME, &cx->name
		, "fetch: \"%S\"; data size: %L; usage: %u"
		, &ci.key, ci.data.len, ci.refs);

	ca->id = ci.id;
	ca->hash[0] = ci.keyhash[0];
	ca->key = ci.key.ptr,  ca->keylen = ci.key.len;
	ca->data = ci.data.ptr,  ca->datalen = ci.data.len;
	ca->refs = 0;
	ca->expire = 0;
	return 0;
}

static int cach_store(fsv_cachectx *fcx, fsv_cacheitem *ca, int flags)
{
	cachectx *cx = (cachectx*)fcx;
	void *logctx = (ca->logctx != NULL) ? ca->logctx : cachm->logctx;

	ffcache_item ci = {};
	ci.keyhash[0] = ca->hash[0];
	ffstr_set(&ci.key, ca->key, ca->keylen);
	ffstr_set(&ci.data, ca->data, ca->datalen);
	ci.expire = ca->expire;

	uint f = flags;
	int r = ffcache_store(cx->x, &ci, f);
	if (r != 0) {
		fsv_errlog(logctx, FSV_LOG_ERR, CACH_MODNAME, &cx->name
			, (r != FFCACHE_ESYS) ? "store: \"%S\": %s" : "store: \"%*s\": %s: %E"
			, &ci.key, ffcache_errstr(r), fferr_last());
		return r;
	}

	fsv_dbglog(logctx, FSV_LOG_DBGFLOW, CACH_MODNAME, &cx->name
		, "store: \"%S\"; max-age: %us; data size: %L; usage: %u"
		, &ci.key, ci.expire, ci.data.len, ci.refs);

	ca->id = ci.id;
	ca->hash[0] = ci.keyhash[0];
	ca->key = ci.key.ptr,  ca->keylen = ci.key.len;
	ca->data = ci.data.ptr,  ca->datalen = ci.data.len;
	ca->refs = 0;
	ca->expire = 0;
	return 0;
}

static int cach_update(fsv_cachectx *fcx, fsv_cacheitem *ca, int flags)
{
	cachectx *cx = (cachectx*)fcx;
	void *logctx = (ca->logctx != NULL) ? ca->logctx : cachm->logctx;

	ffcache_item ci = {};
	ci.id = ca->id;
	ci.keyhash[0] = ca->hash[0];
	ffstr_set(&ci.key, ca->key, ca->keylen);
	ffstr_set(&ci.data, ca->data, ca->datalen);
	ci.expire = ca->expire;

	int r = ffcache_update(cx->x, &ci, 0);
	if (r != 0) {
		fsv_errlog(logctx, FSV_LOG_ERR, CACH_MODNAME, &cx->name
			, (r != FSV_CACH_ESYS) ? "update: \"%S\": %s" : "update: \"%*s\": %s: %E"
			, &ci.key, ffcache_errstr(r), fferr_last());
		return r;
	}

	fsv_dbglog(logctx, FSV_LOG_DBGFLOW, CACH_MODNAME, &cx->name
		, "update: \"%S\"; max-age: %us; data size: %L"
		, &ci.key, ci.expire, ci.data.len);
	return 0;
}

static int cach_unref(fsv_cachectx *fcx, fsv_cacheitem *ca, int flags)
{
	cachectx *cx = (cachectx*)fcx;
	uint f = flags;
	return ffcache_unref(cx->x, ca->id, f);
}

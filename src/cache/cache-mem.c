/** In-memory cache.
Copyright 2014 Simon Zolin.
*/

#include <core/fserv.h>
#include <FF/rbtree.h>
#include <FF/list.h>
#include <FF/data/json.h>
#include <FF/crc.h>
#include <FFOS/file.h>


enum {
	MAX_KEYLEN = 64*1024
	, DATA_S_SIZE = sizeof(void*)
};

typedef struct cachemodule {
	const fsv_core *srv;
	fsv_logctx *logctx;
	fflist ctxs; //cachectx[]
} cachemodule;

typedef struct cachectx {
	fflist_item sib;
	ffrbtree items;
	fflist lastused;
	const fsv_cach_cb *cb;
	size_t memsize; //length of keys and data

	//conf:
	char sname[FFINT_MAXCHARS];
	ffstr name;
	uint max_items
		, max_data
		, mem_limit
		, def_expiry
		, max_expire;
	unsigned key_icase :1
		, multi :1;

	//status:
	uint hits
		, misses;
} cachectx;

/** Keys are shared within a multi-item context.
Every such item holds a reference to the instance of this struct. */
typedef struct cach_key {
	size_t len; //length of 'd[]'
	uint usage;
	char d[0];
} cach_key;

typedef struct cach_item {
	cachectx *cx;
	ffrbtl_node rbtnod;

	fflist_item lastused_li;

	cach_key *ckey;

	ffstr data;
	char data_s[DATA_S_SIZE]; //static data, saves the call to mem_alloc()

	time_t cretime; //the time when the item was stored
	uint usage; //the number of external references
	unsigned unlinked :1; //set when the item is no longer referenced by the cache
	fsv_timer tmr; //expiration timer
} cach_item;

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
static int cach_update(fsv_cacheitem *ca, int flags);
static int cach_unref(fsv_cacheitem *ca, int flags);
static const fsv_cache fsv_cach_iface = {
	&cach_newctx, &cach_fetch, &cach_store, &cach_update, &cach_unref
};

// STATUS
static void cach_status(const fsv_status *statusmod);
static const fsv_status_handler cach_stat_iface = {
	&cach_status
};

static void cachm_clear(void);
static const char * cach_errstr(int code);

static void cachx_fin(cachectx *cx);
static int cach_rmitems_mem(cachectx *cx, size_t memneeded, fsv_logctx *logctx);
static int cach_rm1(cachectx *cx, fsv_logctx *logctx);

static int cach_copydata(cach_item *cit, fsv_cacheitem *ca);
static void cach_fin(cach_item *cit);
static void cach_destroy(cach_item *cit);
static void cach_onexpire(void *param);
static uint cach_tmrreset(cach_item *cit, uint expire);
static void cach_rlz(cach_item *cit, fsv_logctx *logctx);
static void cach_fillitem(fsv_cacheitem *ca, cach_item *cit);

/** Return TRUE if hash is not set. */
#define KEYHASH_EMPTY(hash)  ((hash)[0] == 0)

#define KEYHASH_SET(hash, key, len, key_icase) \
	(*(hash) = (key_icase) ? ffcrc32_iget(key, len) : ffcrc32_get(key, len))

static cach_key * cach_key_alloc(const char *key, size_t len, int key_icase);
static ffbool cach_key_equal(const cach_key *ckey, const char *key, size_t len, int key_icase);


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

static const ffpars_arg cachx_conf_args[] = {
	{ "max_items",  FFPARS_TINT | FFPARS_FNOTZERO,  FFPARS_DSTOFF(cachectx, max_items) }
	, { "expiry",  FFPARS_TINT,  FFPARS_DSTOFF(cachectx, def_expiry) }
	, { "max_age",  FFPARS_TINT,  FFPARS_DSTOFF(cachectx, max_expire) }
	, { "max_data",  FFPARS_TSIZE | FFPARS_FNOTZERO,  FFPARS_DSTOFF(cachectx, max_data) }
	, { "mem_limit",  FFPARS_TSIZE | FFPARS_FNOTZERO,  FFPARS_DSTOFF(cachectx, mem_limit) }
};


/** Error strings for enum FSV_CACH_E. */
static const char *const cach_serr[] = {
	""
	, "system"
	, "already exists"
	, "not found"
	, "key hash collision"
	, "items number limit"
	, "memory limit"
	, "size limit"
	, "locked"
};

static const char * cach_errstr(int code)
{
	FF_ASSERT(code < FFCNT(cach_serr));
	return cach_serr[code];
}


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

static void cach_delitem(void *obj)
{
	cach_item *cit = obj;
	cach_fin(cit);
}

static void cachx_fin(cachectx *cx)
{
	ffrbtl_freeall(&cx->items, &cach_delitem, FFOFF(cach_item, rbtnod));
	ffmem_free(cx);
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

static void cach_onclear(void *obj)
{
	cach_item *cit = obj;
	cach_rlz(cit, cachm->logctx);
}

/**
The function is only safe if ffrbtl_rm() is called before ffmem_free(). */
static void ffrbtl_enumsafe(ffrbtree *tr, ffrbt_free_t func, size_t off)
{
	ffrbt_node *n, *next;
	ffrbtl_node *nl;
	fflist_item *li;

	FFTREE_FOR(tr, n) {
		nl = (void*)n;
		FFCHAIN_FOR(&nl->sib, li) {
			void *n2 = FF_PTR(ffrbtl_nodebylist(li), -(ssize_t)off);
			li = li->next;
			func(n2);
		}
		next = ffrbt_successor(tr, n);
		void *p = FF_PTR(n, -(ssize_t)off);
		func(p);
		n = next;
	}
}

static void cachm_clear(void)
{
	cachectx *cx;
	FFLIST_WALK(&cachm->ctxs, cx, sib) {
		ffrbtl_enumsafe(&cx->items, &cach_onclear, FFOFF(cach_item, rbtnod));
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

	FFLIST_WALK(&cachm->ctxs, cx, sib) {
		ffjson_addv(&status_json, cach_status_jsonmeta, FFCNT(cach_status_jsonmeta)
			, FFJSON_CTXOPEN
			, "id", cx->sname
			, "items", (int64)cx->items.len
			, "hits", (int64)cx->hits
			, "misses", (int64)cx->misses
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
	cx->def_expiry = 1 * 60 * 60;
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


/** Create a shared key. */
static cach_key * cach_key_alloc(const char *key, size_t len, int key_icase)
{
	cach_key *ckey = ffmem_alloc(sizeof(cach_key) + len);
	if (ckey == NULL)
		return NULL;

	if (!key_icase)
		ffmemcpy(ckey->d, key, len);
	else
		ffs_lower(ckey->d, ckey->d + len, key, len);

	ckey->len = len;
	ckey->usage = 1;
	return ckey;
}

static FFINL void cach_key_ref(cach_key *ckey)
{
	ckey->usage++;
}

/** Decrease refcount and return data size if it's the last reference. */
static FFINL size_t cach_key_unref(cach_key *ckey)
{
	if (--ckey->usage == 0) {
		size_t n = ckey->len;
		ffmem_free(ckey);
		return n;
	}
	return 0;
}

/** Return TRUE if keys are equal. */
static ffbool cach_key_equal(const cach_key *ckey, const char *key, size_t len, int key_icase)
{
	if (ckey->len != len)
		return 0;

	if (!key_icase)
		return !ffs_cmp(ckey->d, key, len);
	return !ffs_icmp(ckey->d, key, len);
}


/** @expire: in sec. */
static uint cach_tmrreset(cach_item *cit, uint expire)
{
	expire = ((expire == 0) ? cit->cx->def_expiry : (uint)ffmin(expire, cit->cx->max_expire));
	cachm->srv->timer(&cit->tmr, -(int64)expire * 1000, &cach_onexpire, cit);
	return expire;
}

static int cach_copydata(cach_item *cit, fsv_cacheitem *ca)
{
	void *p;

	if (ca->datalen <= DATA_S_SIZE) {
		p = cit->data_s;

		if (cit->data.len > DATA_S_SIZE)
			ffstr_free(&cit->data);

	} else {

		if (cit->data.len > DATA_S_SIZE)
			p = ffmem_realloc(cit->data.ptr, ca->datalen);
		else
			p = ffmem_alloc(ca->datalen);
		if (p == NULL)
			return 1;
	}

	ffmemcpy(p, ca->data, ca->datalen);
	ffstr_set(&cit->data, p, ca->datalen);
	return 0;
}

static void cach_fillitem(fsv_cacheitem *ca, cach_item *cit)
{
	ca->id = (fsv_cacheitem_id*)cit;
	ca->key = cit->ckey->d;
	ca->keylen = cit->ckey->len;
	ca->data = cit->data.ptr;
	ca->datalen = cit->data.len;
	ca->refs = 0;
}

static int cach_fetch(fsv_cachectx *fcx, fsv_cacheitem *ca, int flags)
{
	cachectx *cx = (cachectx*)fcx;
	ffrbt_node *found;
	cach_item *cit;
	enum FSV_CACH_E er;
	fsv_logctx *logctx = ((ca->logctx != NULL) ? ca->logctx : cachm->logctx);

	if (flags & FSV_CACH_NEXT) {

		if (!cx->multi
			|| ca->id == NULL) {
			fferr_set(EINVAL);
			return FSV_CACH_ESYS; //misuse
		}

		cit = (cach_item*)ca->id;
		if (cit->rbtnod.sib.next == &cit->rbtnod.sib) {
			fsv_dbglog(logctx, FSV_LOG_DBGFLOW, CACH_MODNAME, &cx->name
				, "fetch next: \"%*s\": %s"
				, cit->ckey->len, cit->ckey->d, cach_errstr(FSV_CACH_ENOTFOUND));
			return FSV_CACH_ENOTFOUND;
		}

		cit = FF_GETPTR(cach_item, rbtnod, ffrbtl_nodebylist(cit->rbtnod.sib.next));

	} else if (ca->id != NULL) {
		// get the item by its ID
		cit = (cach_item*)ca->id;

	} else {
		// search for an item by name

		if (KEYHASH_EMPTY(ca->hash))
			KEYHASH_SET(ca->hash, ca->key, ca->keylen, cx->key_icase);

		found = ffrbt_find(&cx->items, ca->hash[0], NULL);
		if (found == NULL) {
			cx->misses++;
			er = FSV_CACH_ENOTFOUND;
			goto fail;
		}

		cit = FF_GETPTR(cach_item, rbtnod, found);
		if (!cach_key_equal(cit->ckey, ca->key, ca->keylen, cx->key_icase)) {
			cx->misses++;
			fsv_errlog(logctx, FSV_LOG_ERR, CACH_MODNAME, &cx->name
				, "fetch: \"%*s\": %s with \"%*s\""
				, ca->keylen, ca->key, cach_errstr(FSV_CACH_ECOLL), cit->ckey->len, cit->ckey->d);
			return FSV_CACH_ECOLL;
		}

		cx->hits++;
	}

	if (flags & FSV_CACH_ACQUIRE) {

		if (cit->usage != 0) {
			er = FSV_CACH_ELOCKED; //the item must not have any references
			goto fail;
		}

		cit->usage++;
		cach_rlz(cit, logctx);

	} else {

		if (ca->refs == 0) {
			fferr_set(EINVAL);
			er = FSV_CACH_ESYS; //misuse
			goto fail;
		}

		cit->usage += ca->refs;
		fflist_moveback(&cx->lastused, &cit->lastused_li);
	}

	cach_fillitem(ca, cit);

	fsv_dbglog(logctx, FSV_LOG_DBGFLOW, CACH_MODNAME, &cx->name
		, "fetch: \"%*s\"; age: %Us; data size: %L; usage: %u"
		, cit->ckey->len, cit->ckey->d, cachm->srv->fsv_gettime().sec - cit->cretime
		, cit->data.len, cit->usage);

	return FSV_CACH_OK;

fail:
	if (er == FSV_CACH_ENOTFOUND) {
		fsv_dbglog(logctx, FSV_LOG_DBGFLOW, CACH_MODNAME, &cx->name
			, "fetch: \"%*s\": %s"
			, ca->keylen, ca->key, cach_errstr(er));

	} else {
		fsv_errlog(logctx, FSV_LOG_ERR, CACH_MODNAME, &cx->name
			, ((er == FSV_CACH_ESYS) ? "fetch: \"%*s\": %s: %E" : "fetch: \"%*s\": %s")
			, ca->keylen, ca->key, cach_errstr(er), fferr_last());
	}

	return er;
}

/** Delete 1 unused item. */
static int cach_rm1(cachectx *cx, fsv_logctx *logctx)
{
	cach_item *cit;

	FFLIST_WALK(&cx->lastused, cit, lastused_li) {

		if (cit->usage == 0) {
			cach_rlz(cit, logctx);
			return 0;
		}
	}

	return 1;
}

/** Delete unused items until there is enough free memory. */
static int cach_rmitems_mem(cachectx *cx, size_t memneeded, fsv_logctx *logctx)
{
	cach_item *cit;

	FFLIST_WALK(&cx->lastused, cit, lastused_li) {

		if (cit->usage == 0) {
			cach_rlz(cit, logctx);

			if (cx->memsize + memneeded <= cx->mem_limit)
				return 0;
		}
	}

	return 1;
}

static int cach_store(fsv_cachectx *fcx, fsv_cacheitem *ca, int flags)
{
	cachectx *cx = (cachectx*)fcx;
	int er;
	cach_item *cit = NULL;
	fsv_logctx *logctx = ((ca->logctx != NULL) ? ca->logctx : cachm->logctx);
	ffrbt_node *found, *parent;

	if (ca->keylen > MAX_KEYLEN) {
		er = FSV_CACH_ESZLIMIT;
		goto fail;
	}

	if (ca->datalen > cx->max_data) {
		er = FSV_CACH_ESZLIMIT;
		goto fail;
	}

	if (cx->items.len == cx->max_items) {
		if (0 != cach_rm1(cx, logctx)) {
			er = FSV_CACH_ENUMLIMIT;
			goto fail;
		}
	}

	/* Note: we should not add 'ca->keylen' if an item with the same key already exists,
	   but that would require us to perform a tree lookup first. */
	if (cx->memsize + ca->keylen + ca->datalen > cx->mem_limit) {
		if (0 != cach_rmitems_mem(cx, ca->keylen + ca->datalen, logctx)) {
			er = FSV_CACH_EMEMLIMIT;
			goto fail;
		}
	}

	if (KEYHASH_EMPTY(ca->hash))
		KEYHASH_SET(ca->hash, ca->key, ca->keylen, cx->key_icase);

	cit = ffmem_tcalloc1(cach_item);
	if (cit == NULL) {
		er = FSV_CACH_ESYS;
		goto fail;
	}
	cit->cx = cx;

	if (0 != cach_copydata(cit, ca)) {
		er = FSV_CACH_ESYS;
		goto fail;
	}

	cit->usage = ca->refs;

	found = ffrbt_find(&cx->items, ca->hash[0], &parent);
	if (found == NULL) {

		cit->ckey = cach_key_alloc(ca->key, ca->keylen, cx->key_icase);
		if (cit->ckey == NULL) {
			er = FSV_CACH_ESYS;
			goto fail;
		}
		cx->memsize += ca->keylen;

		cit->rbtnod.key = ca->hash[0];
		ffrbtl_insert3(&cx->items, &cit->rbtnod, parent);

	} else {

		cach_item *fcit = FF_GETPTR(cach_item, rbtnod, found);
		if (!cach_key_equal(fcit->ckey, ca->key, ca->keylen, cx->key_icase)) {
			er = FSV_CACH_ECOLL;
			fsv_errlog(logctx, FSV_LOG_ERR, CACH_MODNAME, &cx->name
				, "store: \"%*s\": %s with \"%*s\""
				, ca->keylen, ca->key, cach_errstr(FSV_CACH_ECOLL), fcit->ckey->len, fcit->ckey->d);
			goto end;
		}

		if (!cx->multi) {
			er = FSV_CACH_EEXISTS;
			goto fail;
		}

		cach_key_ref(fcit->ckey);
		cit->ckey = fcit->ckey;

		ffchain_append(&cit->rbtnod.sib, fcit->rbtnod.sib.prev); //'prev' points to the last item in chain
		cx->items.len++;
	}

	cx->memsize += cit->data.len;
	ca->expire = cach_tmrreset(cit, ca->expire);
	fflist_ins(&cx->lastused, &cit->lastused_li);
	cit->cretime = cachm->srv->fsv_gettime().sec;

	fsv_dbglog(logctx, FSV_LOG_DBGFLOW, CACH_MODNAME, &cx->name
		, "store: \"%*s\"; max-age: %us; data size: %L; usage: %u;  [%L]"
		, cit->ckey->len, cit->ckey->d, ca->expire, cit->data.len, cit->usage, cx->items.len);

	if (ca->refs != 0)
		cach_fillitem(ca, cit);
	else
		ca->id = (fsv_cacheitem_id*)cit;
	return FSV_CACH_OK;

fail:
	fsv_errlog(logctx, FSV_LOG_ERR, CACH_MODNAME, &cx->name
		, ((er != FSV_CACH_ESYS) ? "store: \"%*s\": %s" : "store: \"%*s\": %s: %E")
		, ca->keylen, ca->key, cach_errstr(er), fferr_last());

end:
	if (cit != NULL)
		cach_destroy(cit);

	return er;
}

static int cach_update(fsv_cacheitem *ca, int flags)
{
	cachectx *cx;
	int er;
	cach_item *cit;
	fsv_logctx *logctx = ((ca->logctx != NULL) ? ca->logctx : cachm->logctx);
	ssize_t memsize_delta;

	if (ca->id == NULL) {
		fferr_set(EINVAL);
		return FSV_CACH_ESYS; //item id must be set
	}
	cit = (cach_item*)ca->id;
	cx = cit->cx;

	if (ca->datalen > cx->max_data) {
		er = FSV_CACH_ESZLIMIT;
		goto fail;
	}

	if (cit->unlinked) {
		er = FSV_CACH_ENOTFOUND; //the item was expired
		goto fail;
	}

	if (cit->usage != 1) {
		er = FSV_CACH_ELOCKED; //the item must be exclusively owned by the caller
		goto fail;
	}

	memsize_delta = (ssize_t)ca->datalen - cit->data.len;
	if (cx->memsize + memsize_delta > cx->mem_limit) {
		if (0 != cach_rmitems_mem(cx, memsize_delta, logctx)) {
			er = FSV_CACH_EMEMLIMIT;
			goto fail;
		}
	}

	//replace data
	if (0 != cach_copydata(cit, ca)) {
		er = FSV_CACH_ESYS;
		goto fail;
	}

	cx->memsize += memsize_delta;
	fflist_moveback(&cx->lastused, &cit->lastused_li);
	ca->expire = cach_tmrreset(cit, ca->expire);

	fsv_dbglog(logctx, FSV_LOG_DBGFLOW, CACH_MODNAME, &cx->name
		, "update: \"%*s\"; max-age: %us; data size: %L"
		, cit->ckey->len, cit->ckey->d, ca->expire, cit->data.len);

	cach_fillitem(ca, cit);
	return FSV_CACH_OK;

fail:
	fsv_errlog(logctx, FSV_LOG_ERR, CACH_MODNAME, &cx->name
		, ((er != FSV_CACH_ESYS) ? "update: \"%*s\": %s" : "update: \"%*s\": %s: %E")
		, ca->keylen, ca->key, cach_errstr(er), fferr_last());

	return er;
}

static int cach_unref(fsv_cacheitem *ca, int flags)
{
	cach_item *cit;
	fsv_logctx *logctx = ((ca->logctx != NULL) ? ca->logctx : cachm->logctx);

	if (ca->id == NULL) {
		fferr_set(EINVAL);
		return FSV_CACH_ESYS; //item id must be set
	}

	cit = (cach_item*)ca->id;

	FF_ASSERT(cit->usage != 0);
	cit->usage--;

	if ((flags & FSV_CACH_UNLINK) && !cit->unlinked) {
		cach_rlz(cit, logctx);
		return FSV_CACH_OK;
	}

	fsv_dbglog(logctx, FSV_LOG_DBGFLOW, CACH_MODNAME, &cit->cx->name
		, "%s: \"%*s\""
		, ((cit->unlinked && cit->usage == 0) ? "deleted" : "unref"), cit->ckey->len, cit->ckey->d);

	if (cit->unlinked && cit->usage == 0)
		cach_fin(cit);

	return FSV_CACH_OK;
}

/** Timer expired. */
static void cach_onexpire(void *param)
{
	cach_item *cit = param;
	cach_rlz(cit, cachm->logctx);
}

/** Delete the item. */
static void cach_fin(cach_item *cit)
{
	if (cit->cx->cb->onchange != NULL) {
		fsv_cacheitem ca;
		fsv_cache_init(&ca);
		cach_fillitem(&ca, cit);
		cit->cx->cb->onchange((fsv_cachectx*)cit->cx, &ca, FSV_CACH_ONDELETE);
	}

	cit->cx->memsize -= cach_key_unref(cit->ckey) + cit->data.len;

	cach_destroy(cit);
}

/** Free resources owned by the item. */
static void cach_destroy(cach_item *cit)
{
	if (cit->data.len > DATA_S_SIZE)
		ffstr_free(&cit->data);

	ffmem_free(cit);
}

/** Unlink the item from the cache. */
static void cach_rlz(cach_item *cit, fsv_logctx *logctx)
{
	FF_ASSERT(!cit->unlinked);

	cachm->srv->fsv_timerstop(&cit->tmr);
	ffrbtl_rm(&cit->cx->items, &cit->rbtnod);
	fflist_rm(&cit->cx->lastused, &cit->lastused_li);
	cit->unlinked = 1;

	fsv_dbglog(logctx, FSV_LOG_DBGFLOW, CACH_MODNAME, &cit->cx->name
		, "%s: \"%*s\"; age: %Us;  [%L]"
		, ((cit->usage == 0) ? "deleted" : "unlinked"), cit->ckey->len, cit->ckey->d
		, cachm->srv->fsv_gettime().sec - cit->cretime, cit->cx->items.len);

	if (cit->usage == 0)
		cach_fin(cit);
}

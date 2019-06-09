/** Resolve IPv4/IPv6 addresses.
Copyright 2014 Simon Zolin.
*/

#include <core/fserv.h>
#include <FF/net/dns-client.h>
#include <FF/net/dns.h>
#include <FF/data/json.h>
#include <FFOS/random.h>


struct ffdnsclient;
struct resolverx {
	const fsv_core *core;
	fsv_logctx *logctx;
	const fsv_cache *cachmod;
	fsv_cachectx *cachctx;
	struct ffdnsclient *r;

	//conf:
	byte max_tries;
	ushort retry_timeout; //in msec
	byte enable_ipv6;
	byte edns;
	uint buf_size;

	ffarr servs; //ffstr[]
};

static struct resolverx *resvm;


#define RESV_MODNAME "RESV"


// FSERV MODULE
static void * resvm_create(const fsv_core *core, ffpars_ctx *c, fsv_modinfo *m);
static void resvm_destroy(void);
static int resvm_sig(int signo);
static const void * resvm_iface(const char *name);
const fsv_mod fsv_reslv_mod = {
	&resvm_create, &resvm_destroy, &resvm_sig, &resvm_iface
};

// FSERV RESOLVE
static fsv_resolv_ctx * resv_newctx(ffpars_ctx *a);
static int resv_resolve(fsv_resolv_ctx *r, const char *name, size_t len, fsv_resolv_cb ondone, void *udata, int flags);
static void resv_unref(const ffaddrinfo *ai);
static const fsv_resolver fsv_resolv_iface = {
	&resv_newctx, &resv_resolve, &resv_unref
};

// STATUS
static void resv_status(const fsv_status *statusmod);
static const fsv_status_handler resv_stat_iface = {
	&resv_status
};

// CONF
static int resvm_conf_log(ffparser_schem *ps, struct resolverx *rs, ffpars_ctx *a);
static int resvm_conf_cache(ffparser_schem *ps, struct resolverx *rs, ffpars_ctx *a);
static int resvm_conf_server(ffparser_schem *ps, struct resolverx *rs, const ffstr *saddr);
static int resvm_conf_end(ffparser_schem *ps, struct resolverx *rs);

static int resvm_start();

// ANSWERS CACHE
static int resv_cache_add(ffdnsclient *r, ffdnscl_res *res, const ffstr *name, uint refcount, uint ttl);
static int resv_fromcache(const ffstr *name, const ffaddrinfo **ai);
static int resv_cache_onchange(fsv_cachectx *ctx, fsv_cacheitem *ca, int flags);
static const fsv_cach_cb resolver_cache_cb = {
	&resv_cache_onchange
};


static const ffpars_arg resvm_conf_args[] = {
	{ "log",  FFPARS_TOBJ | FFPARS_FOBJ1,  FFPARS_DST(&resvm_conf_log) }
	, { "server",  FFPARS_TSTR | FFPARS_FCOPY | FFPARS_FNOTEMPTY | FFPARS_FREQUIRED | FFPARS_FMULTI,  FFPARS_DST(&resvm_conf_server) }
	, { "cache",  FFPARS_TOBJ | FFPARS_FOBJ1,  FFPARS_DST(&resvm_conf_cache) }
	, { "max_tries",  FFPARS_TINT | FFPARS_F8BIT | FFPARS_FNOTZERO,  FFPARS_DSTOFF(struct resolverx, max_tries) }
	, { "retry_timeout",  FFPARS_TINT | FFPARS_F16BIT | FFPARS_FNOTZERO,  FFPARS_DSTOFF(struct resolverx, retry_timeout) }
	, { "ipv6",  FFPARS_TBOOL | FFPARS_F8BIT,  FFPARS_DSTOFF(struct resolverx, enable_ipv6) }
	, { "edns",  FFPARS_TBOOL | FFPARS_F8BIT,  FFPARS_DSTOFF(struct resolverx, edns) }
	, { "buffer_size",  FFPARS_TSIZE | FFPARS_FNOTZERO,  FFPARS_DSTOFF(struct resolverx, buf_size) }

	, { NULL,  FFPARS_TCLOSE,  FFPARS_DST(&resvm_conf_end) }
};

static int resvm_conf_log(ffparser_schem *ps, struct resolverx *rs, ffpars_ctx *a)
{
	const ffstr *name = &ps->vals[0];
	const fsv_log *log_iface;
	const fsv_modinfo *m = rs->core->findmod(name->ptr, name->len);
	if (m == NULL)
		return FFPARS_EBADVAL;

	log_iface = m->f->iface("log");
	if (log_iface == NULL)
		return FFPARS_EBADVAL;

	rs->logctx = log_iface->newctx(a, rs->logctx);
	if (rs->logctx == NULL)
		return FFPARS_EINTL;

	return 0;
}

static int resvm_conf_cache(ffparser_schem *ps, struct resolverx *rs, ffpars_ctx *a)
{
	const ffstr *name = &ps->vals[0];
	const fsv_modinfo *m = rs->core->findmod(name->ptr, name->len);
	if (m == NULL)
		return FFPARS_EBADVAL;

	rs->cachmod = m->f->iface("cache");
	if (rs->cachmod == NULL)
		return FFPARS_EINTL;

	rs->cachctx = rs->cachmod->newctx(a, &resolver_cache_cb, FSV_CACH_MULTI | FSV_CACH_KEYICASE);
	if (rs->cachctx == NULL)
		return FFPARS_EINTL;

	return 0;
}

static int resvm_conf_server(ffparser_schem *ps, struct resolverx *rs, const ffstr *saddr)
{
	ffstr *s = ffarr_pushT(&rs->servs, ffstr);
	if (s == NULL)
		return FFPARS_ESYS;
	*s = *saddr;
	return 0;
}

static int resvm_conf_end(ffparser_schem *ps, struct resolverx *rs)
{
	if (rs->buf_size < 512)
		rs->buf_size = 512;
	return 0;
}


static void * resvm_create(const fsv_core *core, ffpars_ctx *c, fsv_modinfo *m)
{
	const fsvcore_config *conf = core->conf();

	resvm = ffmem_new(struct resolverx);
	if (resvm == NULL)
		return NULL;

	resvm->max_tries = 3;
	resvm->retry_timeout = 1000;
	resvm->edns = 0;
	resvm->enable_ipv6 = 1;
	resvm->buf_size = 512;
	resvm->core = core;
	resvm->logctx = conf->logctx;

	ffpars_setargs(c, resvm, resvm_conf_args, FFCNT(resvm_conf_args));
	return resvm;
}

static void resvm_destroy(void)
{
	ffdnscl_free(resvm->r);
	FFARR_FREE_ALL(&resvm->servs, ffstr_free, ffstr);
	ffmem_free(resvm);
	resvm = NULL;
}

static int resvm_sig(int signo)
{
	switch (signo) {
	case FSVCORE_SIGSTART:
		return resvm_start();
	}

	return 0;
}

static int resvm_start()
{
	ffrnd_seed(resvm->core->fsv_gettime().sec);
	return 0;
}

static const void * resvm_iface(const char *name)
{
	if (0 == ffsz_cmp(name, "resolve"))
		return &fsv_resolv_iface;
	else if (0 == ffsz_cmp(name, "json-status"))
		return &resv_stat_iface;
	return NULL;
}

static const int resvm_status_json_meta[] = {
	FFJSON_TOBJ
	, FFJSON_FKEYNAME, FFJSON_TSTR
	, FFJSON_FKEYNAME, FFJSON_FINTVAL
	, FFJSON_TOBJ
};

static void resv_status(const fsv_status *statusmod)
{
	ffdnscl_serv *serv;
	ffjson_cook status_json;
	char buf[4096];
	ffjson_cookinit(&status_json, buf, sizeof(buf));

	FFLIST_WALK(&resvm->r->servs, serv, sib) {
		ffjson_addv(&status_json, resvm_status_json_meta, FFCNT(resvm_status_json_meta)
			, FFJSON_CTXOPEN
			, "server", &serv->saddr
			, "queries", (int64)serv->nqueries
			, FFJSON_CTXCLOSE
			, NULL);
	}

	statusmod->setdata(status_json.buf.ptr, status_json.buf.len, 0);
	ffjson_cookfin(&status_json);
}

static void resv_log(uint level, const ffstr *trxn, const char *fmt, ...)
{
	uint lev;
	switch (level & 0x0f) {
	case FFDNSCL_LOG_ERR:
		lev = FSV_LOG_ERR; break;
	case FFDNSCL_LOG_WARN:
		lev = FSV_LOG_WARN; break;
	case FFDNSCL_LOG_DBG:
		lev = FSV_LOG_DBG; break;
	default:
		return;
	}

	if (!fsv_log_checklevel(resvm->logctx, lev))
		return;
	if (level & FFDNSCL_LOG_SYS)
		lev |= FSV_LOG_SYS;

	va_list va;
	va_start(va, fmt);
	fsv_logctx_get(resvm->logctx)->mlog->addv(resvm->logctx, lev, RESV_MODNAME, trxn, fmt, va);
	va_end(va);
}

static void resv_timer(fftmrq_entry *tmr, uint value_ms)
{
	resvm->core->timer(tmr, -(int)value_ms, tmr->handler, tmr->param);
}

static fftime resv_time(void)
{
	return resvm->core->fsv_gettime();
}

static fsv_resolv_ctx * resv_newctx(ffpars_ctx *a)
{
	FF_ASSERT(resvm->r == NULL);

	ffdnscl_conf conf = {};

	conf.kq = resvm->core->conf()->queue;
	conf.oncomplete = &resv_cache_add;
	conf.log = &resv_log;
	conf.timer = &resv_timer;
	conf.time = &resv_time;

	conf.debug_log = fsv_log_checklevel(resvm->logctx, FSV_LOG_DBG);
	conf.max_tries = resvm->max_tries;
	conf.retry_timeout = resvm->retry_timeout;
	conf.enable_ipv6 = resvm->enable_ipv6;
	conf.edns = resvm->edns;
	conf.buf_size = resvm->buf_size;

	ffdnsclient *r;
	if (NULL == (r = ffdnscl_new(&conf)))
		return NULL;

	ffstr *s;
	FFARR_WALKT(&resvm->servs, s, ffstr) {
		ffdnscl_serv_add(r, s);
	}
	FFARR_FREE_ALL(&resvm->servs, ffstr_free, ffstr);

	resvm->r = r;
	return (fsv_resolv_ctx*)r;
}

static int resv_resolve(fsv_resolv_ctx *rctx, const char *name, size_t namelen, fsv_resolv_cb ondone, void *udata, int flags)
{
	// search for answers in cache
	if (!(flags & FFDNSCL_CANCEL) && resvm->cachctx != NULL) {
		const ffaddrinfo *ai[2] = {0};
		ffstr host;
		ffstr_set(&host, name, namelen);
		if (0 == resv_fromcache(&host, ai)) {
			ondone(udata, FFDNS_NOERROR, ai);
			return 0;
		}
	}

	int r = ffdnscl_resolve(resvm->r, name, namelen, ondone, udata, flags);
	return r;
}

static void resv_unref(const ffaddrinfo *ai)
{
	ffdnscl_res *res = ffdnscl_res_by_ai(ai);
	void *cached_id = ffdnscl_res_udata(res);

	if (cached_id != NULL) {
		fsv_cacheitem ca;
		fsv_cache_init(&ca);
		ca.logctx = resvm->logctx;
		ca.id = cached_id;
		resvm->cachmod->unref(resvm->cachctx, &ca, 0);
		return;
	}

	ffdnscl_unref(resvm->r, ai);
}


static int resv_cache_onchange(fsv_cachectx *ctx, fsv_cacheitem *ca, int flags)
{
	ffdnscl_res *res = *(ffdnscl_res**)ca->data;
	if (flags == FSV_CACH_ONDELETE) {
		void *cached_id = ffdnscl_res_udata(res);
		(void)cached_id;
		FF_ASSERT(cached_id == ca->id);
		ffdnscl_res_free(res);
	}
	return 0;
}

static int resv_cache_add(ffdnsclient *r, ffdnscl_res *res, const ffstr *name, uint refcount, uint ttl)
{
	if (resvm->cachctx == NULL)
		return 1;

	fsv_cacheitem ca;
	fsv_cache_init(&ca);
	ca.logctx = resvm->logctx;
	ca.key = name->ptr;
	ca.keylen = name->len;
	ca.data = (char*)&res;
	ca.datalen = sizeof(ffdnscl_res*);
	ca.refs = refcount;
	ca.expire = ttl;
	if (0 == resvm->cachmod->store(resvm->cachctx, &ca, 0)) {
		ffdnscl_res_setudata(res, ca.id);
		return 1;
	}
	return 0;
}

/** Fetch addresses from cache. */
static int resv_fromcache(const ffstr *host, const ffaddrinfo **ai)
{
	fsv_cacheitem ca;
	fsv_cache_init(&ca);
	ca.logctx = resvm->logctx;
	ca.key = host->ptr;
	ca.keylen = host->len;

	if (0 == resvm->cachmod->fetch(resvm->cachctx, &ca, 0)) {
		ffdnscl_res *res = *(ffdnscl_res**)ca.data;
		ai[0] = ffdnscl_res_ai(res);

		void *id = ca.id;
		// get the next item
		fsv_cache_init(&ca);
		ca.logctx = resvm->logctx;
		ca.id = id;

		if (0 == resvm->cachmod->fetch(resvm->cachctx, &ca, FSV_CACH_NEXT)) {
			res = *(ffdnscl_res**)ca.data;
			ai[1] = ffdnscl_res_ai(res);
		}

		return 0;
	}
	return 1;
}

/** Resolve IPv4/IPv6 addresses.
Copyright 2014 Simon Zolin.
*/

#include <core/fserv.h>
#include <FF/rbtree.h>
#include <FF/data/json.h>
#include <FF/crc.h>
#include <FF/net/url.h>
#include <FF/net/dns.h>
#include <FFOS/socket.h>
#include <FFOS/error.h>
#include <FFOS/random.h>


typedef struct dns_serv dns_serv;

typedef struct resolver {
	const fsv_core *core;
	fsv_logctx *logctx;
	const fsv_cache *cachmod;
	fsv_cachectx *cachctx;
	fffd kq;

	//conf:
	byte max_tries;
	ushort retry_timeout; //in msec
	byte enable_ipv6;
	byte edns;
	uint buf_size;

	ffrbtree queries; //active queries by hostname.  dns_query[]

	fflist servs; //dns_serv[]
	dns_serv *curserv;
} resolver;

static resolver *resvm;

struct dns_serv {
	fflist_item sib;

	ffskt sk;
	ffaio_task aiotask;
	ffaddr addr;
	char saddr_s[FF_MAXIP4];
	ffstr saddr;
	char *ansbuf;
	unsigned connected :1;

	uint nqueries;
};

typedef struct dns_a {
	ffaddrinfo ainfo;
	struct sockaddr_in addr;
} dns_a;

typedef struct dns_a6 {
	ffaddrinfo ainfo;
	struct sockaddr_in6 addr;
} dns_a6;

typedef struct dns_res {
	fsv_cacheitem_id *cached_id;
	uint usage; //reference count.  0 if stored in cache.

	uint naddrs;
	union {
		dns_a addrs[0];
		dns_a6 addrs6[0];
	};
} dns_res;

typedef struct dns_quser {
	fsv_resolv_cb ondone;
	void *udata;
} dns_quser;

typedef struct dns_query {
	ffrbt_node rbtnod;
	fsv_timer tmr;
	uint tries_left;
	ffstr name; //hostname to be resolved

	dns_res *res[2];
	uint ttl[2];
	int status; //aggregated status of both IPv4/6 queries
	fftime firstsend;

	struct { FFARR(dns_quser) } users; //requestors waiting for this query
	ushort txid4;
	ushort txid6;
	unsigned need4 :1
		, need6 :1;
	byte nres; //number of elements in res[2]
	ushort ques_len4;
	ushort ques_len6;
	char question[0];
} dns_query;

#define RESV_MODNAME "RESV"

#define errlogmod(lev, ...) \
	fsv_errlog(resvm->logctx, lev, RESV_MODNAME, NULL, __VA_ARGS__)

#define syserrlog_srv(serv, lev, fmt, ...) \
	fsv_syserrlog(resvm->logctx, lev, RESV_MODNAME, &(serv)->saddr, fmt, __VA_ARGS__)

#define errlog_q(q, lev, ...) \
	fsv_errlog(resvm->logctx, lev, RESV_MODNAME, &(q)->name, __VA_ARGS__)

#define dbglog_q(q, lev, ...) \
	fsv_dbglog(resvm->logctx, lev, RESV_MODNAME, &(q)->name, __VA_ARGS__)


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
static int resvm_conf_log(ffparser_schem *ps, resolver *rs, ffpars_ctx *a);
static int resvm_conf_cache(ffparser_schem *ps, resolver *rs, ffpars_ctx *a);
static int resvm_conf_server(ffparser_schem *ps, resolver *rs, const ffstr *saddr);
static int resvm_conf_end(ffparser_schem *ps, resolver *rs);

static int resvm_start();

static int dns_serv_init(dns_serv *serv);
static void dns_serv_fin(dns_serv *serv);
static dns_serv * resv_nextserv(resolver *r);

// QUERY
#define resv_query_sib(pnod)  FF_GETPTR(dns_query, rbtnod, pnod)
static int resv_addusr(dns_query *q, fsv_resolv_cb ondone, void *udata);
static int resv_rmuser(resolver *r, const ffstr *host, fsv_resolv_cb ondone, void *udata);
static size_t resv_prepquery(char *buf, size_t cap, uint txid, const ffstr *nm, int type);
static void resv_sendquery(dns_query *q, int resend);
static int resv_sendquery1(dns_query *q, dns_serv *serv, int resend);
static void resv_onexpire(void *param);
static void resv_notifyfin(dns_query *q, int status);
static void resv_finquery(void *param);

// ANSWERS CACHE
static void resv_cacheresp(dns_query *q);
static int resv_fromcache(const ffstr *name, const ffaddrinfo **ai);
static int resv_cache_onchange(fsv_cachectx *ctx, fsv_cacheitem *ca, int flags);
static const fsv_cach_cb resolver_cache_cb = {
	&resv_cache_onchange
};

// RESPONSE
static void resv_read_data(void *udata);
static void resv_proc_data(dns_serv *serv, const ffstr *resp);
static dns_query * resv_find_query(dns_serv *serv, ffdns_hdr_host *h, const ffstr *resp);
static uint resv_nrecs(dns_query *q, ffdns_hdr_host *h, const ffstr *resp, const char *pbuf, int is4);
static dns_res * resv_proc_resp(dns_query *q, ffdns_hdr_host *h, const ffstr *resp, int is4);
static void dns_res_fin(dns_res *dr);


static const ffpars_arg resvm_conf_args[] = {
	{ "log",  FFPARS_TOBJ | FFPARS_FOBJ1,  FFPARS_DST(&resvm_conf_log) }
	, { "server",  FFPARS_TSTR | FFPARS_FNOTEMPTY | FFPARS_FREQUIRED | FFPARS_FMULTI,  FFPARS_DST(&resvm_conf_server) }
	, { "cache",  FFPARS_TOBJ | FFPARS_FOBJ1,  FFPARS_DST(&resvm_conf_cache) }
	, { "max_tries",  FFPARS_TINT | FFPARS_F8BIT | FFPARS_FNOTZERO,  FFPARS_DSTOFF(resolver, max_tries) }
	, { "retry_timeout",  FFPARS_TINT | FFPARS_F16BIT | FFPARS_FNOTZERO,  FFPARS_DSTOFF(resolver, retry_timeout) }
	, { "ipv6",  FFPARS_TBOOL | FFPARS_F8BIT,  FFPARS_DSTOFF(resolver, enable_ipv6) }
	, { "edns",  FFPARS_TBOOL | FFPARS_F8BIT,  FFPARS_DSTOFF(resolver, edns) }
	, { "buffer_size",  FFPARS_TSIZE | FFPARS_FNOTZERO,  FFPARS_DSTOFF(resolver, buf_size) }

	, { NULL,  FFPARS_TCLOSE,  FFPARS_DST(&resvm_conf_end) }
};

static int resvm_conf_log(ffparser_schem *ps, resolver *rs, ffpars_ctx *a)
{
	const ffstr *name = &ps->vals[0];
	const fsv_log *log_iface;
	const fsv_modinfo *m = resvm->core->findmod(name->ptr, name->len);
	if (m == NULL)
		return FFPARS_EBADVAL;

	log_iface = m->f->iface("log");
	if (log_iface == NULL)
		return FFPARS_EBADVAL;

	resvm->logctx = log_iface->newctx(a, resvm->logctx);
	if (resvm->logctx == NULL)
		return FFPARS_EINTL;

	return 0;
}

static int resvm_conf_cache(ffparser_schem *ps, resolver *rs, ffpars_ctx *a)
{
	const ffstr *name = &ps->vals[0];
	const fsv_modinfo *m = resvm->core->findmod(name->ptr, name->len);
	if (m == NULL)
		return FFPARS_EBADVAL;

	resvm->cachmod = m->f->iface("cache");
	if (resvm->cachmod == NULL)
		return FFPARS_EINTL;

	resvm->cachctx = resvm->cachmod->newctx(a, &resolver_cache_cb, FSV_CACH_MULTI | FSV_CACH_KEYICASE);
	if (resvm->cachctx == NULL)
		return FFPARS_EINTL;

	return 0;
}

static int resvm_conf_server(ffparser_schem *ps, resolver *rs, const ffstr *saddr)
{
	dns_serv *serv;
	char *s;

	serv = ffmem_tcalloc1(dns_serv);
	if (serv == NULL)
		return FFPARS_ESYS;

	fflist_ins(&resvm->servs, &serv->sib);

	ffaddr_init(&serv->addr);
	ffaddr_set(&serv->addr, saddr->ptr, saddr->len, NULL, 0);
	ffip_setport(&serv->addr, FFDNS_PORT);

	s = ffs_copy(serv->saddr_s, serv->saddr_s + FFCNT(serv->saddr_s), saddr->ptr, saddr->len);
	ffstr_set(&serv->saddr, serv->saddr_s, s - serv->saddr_s);
	return 0;
}

static int resvm_conf_end(ffparser_schem *ps, resolver *rs)
{
	if (resvm->buf_size < 512)
		resvm->buf_size = 512;
	resvm->curserv = FF_GETPTR(dns_serv, sib, resvm->servs.first);
	return 0;
}


static void * resvm_create(const fsv_core *core, ffpars_ctx *c, fsv_modinfo *m)
{
	const fsvcore_config *conf = core->conf();

	resvm = ffmem_tcalloc1(resolver);
	if (resvm == NULL)
		return NULL;

	resvm->max_tries = 3;
	resvm->retry_timeout = 1000;
	resvm->edns = 0;
	resvm->enable_ipv6 = 1;
	resvm->buf_size = 512;
	ffrbt_init(&resvm->queries);
	fflist_init(&resvm->servs);
	resvm->core = core;
	resvm->logctx = conf->logctx;

	ffpars_setargs(c, resvm, resvm_conf_args, FFCNT(resvm_conf_args));
	return resvm;
}

static void resv_finquery(void *param)
{
	dns_query *q = param;
	ffstr_free(&q->name);
	ffarr_free(&q->users);
	ffmem_free(q);
}

static void resvm_destroy(void)
{
	ffrbt_freeall(&resvm->queries, &resv_finquery, FFOFF(dns_query, rbtnod));
	FFLIST_ENUMSAFE(&resvm->servs, dns_serv_fin, dns_serv, sib);
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
	resvm->kq = resvm->core->conf()->queue;

	{
		dns_serv *serv;
		FFLIST_WALK(&resvm->servs, serv, sib) {
			serv->ansbuf = ffmem_alloc(resvm->buf_size);
			if (serv->ansbuf == NULL)
				return -1;
		}
	}
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
	dns_serv *serv;
	ffjson_cook status_json;
	char buf[4096];
	ffjson_cookinit(&status_json, buf, sizeof(buf));

	FFLIST_WALK(&resvm->servs, serv, sib) {
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


static fsv_resolv_ctx * resv_newctx(ffpars_ctx *a)
{
	return (fsv_resolv_ctx*)resvm;
}

static int resv_resolve(fsv_resolv_ctx *rctx, const char *name, size_t namelen, fsv_resolv_cb ondone, void *udata, int flags)
{
	uint namecrc;
	char buf4[FFDNS_MAXMSG], buf6[FFDNS_MAXMSG];
	size_t ibuf4, ibuf6 = 0;
	ffrbt_node *found_query, *parent;
	dns_query *q = NULL;
	ffstr host;
	resolver *r = (resolver*)rctx;
	ushort txid4, txid6 = 0;

	ffstr_set(&host, name, namelen);

	if (flags & FSV_RESOLV_CANCEL)
		return resv_rmuser(r, &host, ondone, udata);

	// search for answers in cache
	if (resvm->cachctx != NULL) {
		const ffaddrinfo *ai[2] = {0};
		if (0 == resv_fromcache(&host, ai)) {
			ondone(udata, FFDNS_NOERROR, ai);
			return 0;
		}
	}

	namecrc = ffcrc32_iget(name, namelen);

	// determine whether the needed query is already pending and if so, attach to it
	found_query = ffrbt_find(&r->queries, namecrc, &parent);
	if (found_query != NULL) {
		q = resv_query_sib(found_query);

		if (!ffstr_eq2(&q->name, &host)) {
			errlogmod(FSV_LOG_ERR, "%S: CRC collision with %S", &host, &q->name);
			goto fail;
		}

		dbglog_q(q, FSV_LOG_DBGFLOW, "query hit");
		if (0 != resv_addusr(q, ondone, udata))
			goto nomem;

		return 0;
	}

	// prepare DNS queries: A and AAAA
	txid4 = ffrnd_get() & 0xffff;
	ibuf4 = resv_prepquery(buf4, FFCNT(buf4), txid4, &host, FFDNS_A);
	if (ibuf4 == 0) {
		errlogmod(FSV_LOG_ERR, "invalid hostname: %S", &host);
		goto fail;
	}

	if (r->enable_ipv6) {
		txid6 = ffrnd_get() & 0xffff;
		ibuf6 = resv_prepquery(buf6, FFCNT(buf6), txid6, &host, FFDNS_AAAA);
	}

	// initialize DNS query object
	q = ffmem_alloc(sizeof(dns_query) + ibuf4 + ibuf6);
	if (q == NULL)
		goto nomem;
	ffmem_zero(q, sizeof(dns_query));

	if (0 != resv_addusr(q, ondone, udata))
		goto nomem;

	if (NULL == ffstr_copy(&q->name, name, namelen))
		goto nomem;

	q->need4 = 1;
	ffmemcpy(q->question, buf4, ibuf4);
	q->ques_len4 = (ushort)ibuf4;
	q->txid4 = txid4;

	if (r->enable_ipv6) {
		q->need6 = 1;
		ffmemcpy(q->question + ibuf4, buf6, ibuf6);
		q->ques_len6 = (ushort)ibuf6;
		q->txid6 = txid6;
	}

	q->rbtnod.key = namecrc;
	ffrbt_insert(&r->queries, &q->rbtnod, parent);
	q->tries_left = resvm->max_tries;
	q->firstsend = resvm->core->fsv_gettime();

	resv_sendquery(q, 0);
	return 0;

nomem:
	fsv_syserrlog(resvm->logctx, FSV_LOG_ERR, RESV_MODNAME, NULL, "%e", FFERR_BUFALOC);

fail:
	if (q != NULL)
		resv_finquery(q);

	ondone(udata, -1, NULL);
	return 0;
}

static void resv_unref(const ffaddrinfo *ai)
{
	dns_a *paddrs = FF_GETPTR(dns_a, ainfo, ai);
	dns_res *res = FF_GETPTR(dns_res, addrs, paddrs);

	if (res->cached_id != NULL) {
		fsv_cacheitem ca;
		fsv_cache_init(&ca);
		ca.logctx = resvm->logctx;
		ca.id = res->cached_id;
		resvm->cachmod->unref(&ca, 0);

	} else {
		FF_ASSERT(res->usage != 0);
		if (--res->usage == 0)
			dns_res_fin(res);
	}
}


/** Timer expired. */
static void resv_onexpire(void *param)
{
	dns_query *q = param;

	if (q->tries_left == 0) {
		errlog_q(q, FSV_LOG_ERR, "reached max_tries limit");
		resv_notifyfin(q, -1);
		return;
	}

	resv_sendquery(q, 1);
}

/** One more user wants to send the same query. */
static int resv_addusr(dns_query *q, fsv_resolv_cb ondone, void *udata)
{
	dns_quser *quser;

	if (NULL == ffarr_grow(&q->users, 1, FFARR_GROWQUARTER))
		return 1;
	quser = ffarr_push(&q->users, dns_quser);
	quser->ondone = ondone;
	quser->udata = udata;
	return 0;
}

/** User doesn't want to wait for this query anymore. */
static int resv_rmuser(resolver *r, const ffstr *host, fsv_resolv_cb ondone, void *udata)
{
	ffrbt_node *found;
	dns_query *q;
	dns_quser *quser;
	uint namecrc;

	namecrc = ffcrc32_iget(host->ptr, host->len);
	found = ffrbt_find(&r->queries, namecrc, NULL);
	if (found == NULL) {
		errlogmod(FSV_LOG_ERR, "cancel: no query for %S", host);
		return 1;
	}

	q = resv_query_sib(found);

	if (!ffstr_eq2(&q->name, host)) {
		errlogmod(FSV_LOG_ERR, "%S: CRC collision with %S", host, &q->name);
		return 1;
	}

	FFARR_WALK(&q->users, quser) {

		if (udata == quser->udata && ondone == quser->ondone) {
			ffarr_rmswap(&q->users, quser);
			dbglog_q(q, FSV_LOG_DBGFLOW, "cancel: unref query");
			return 0;
		}
	}

	errlog_q(q, FSV_LOG_ERR, "cancel: no matching reference for the query");
	return 1;
}

static void resv_sendquery(dns_query *q, int resend)
{
	dns_serv *serv;

	for (;;) {

		if (q->tries_left == 0) {
			errlog_q(q, FSV_LOG_ERR, "reached max_tries limit");
			resv_notifyfin(q, -1);
			return;
		}

		q->tries_left--;
		serv = resv_nextserv(resvm);
		if (0 == resv_sendquery1(q, serv, resend))
			return;
	}
}

/** Send query to server. */
static int resv_sendquery1(dns_query *q, dns_serv *serv, int resend)
{
	ssize_t rc;
	int er;

	if (!serv->connected) {
		if (0 != dns_serv_init(serv))
			return 1;

		if (0 != ffskt_connect(serv->sk, &serv->addr.a, serv->addr.len)) {
			er = FFERR_SKTCONN;
			goto fail;
		}
		serv->connected = 1;
		resv_read_data(serv);
	}

	if (q->need6) {
		rc = ffskt_send(serv->sk, q->question + q->ques_len4, q->ques_len6, 0);
		if (rc != q->ques_len6) {
			er = FFERR_WRITE;
			goto fail;
		}

		serv->nqueries++;

		dbglog_q(q, FSV_LOG_DBGNET, "%ssent %s query #%u.  [%L]"
			, (resend ? "re" : ""), "AAAA", (int)q->txid6, (size_t)resvm->queries.len + (resend ? 0 : 1));
	}

	if (q->need4) {
		rc = ffskt_send(serv->sk, q->question, q->ques_len4, 0);
		if (rc != q->ques_len4) {
			er = FFERR_WRITE;
			goto fail;
		}

		serv->nqueries++;

		dbglog_q(q, FSV_LOG_DBGNET, "%ssent %s query #%u.  [%L]"
			, (resend ? "re" : ""), "A", (int)q->txid4, (size_t)resvm->queries.len + (resend ? 0 : 1));
	}

	resvm->core->timer(&q->tmr, -(int)resvm->retry_timeout, &resv_onexpire, q);
	return 0;

fail:
	syserrlog_srv(serv, FSV_LOG_ERR, "%e", er);
	if (er == FFERR_WRITE) {
		ffskt_close(serv->sk);
		serv->sk = FF_BADSKT;
		ffaio_fin(&serv->aiotask);
		serv->connected = 0;
	}
	return 1;
}

/** Prepare DNS query. */
static size_t resv_prepquery(char *buf, size_t cap, uint txid, const ffstr *host, int type)
{
	char *pbuf;
	uint n;
	ffdns_hdr *h = (ffdns_hdr*)buf;

	ffdns_initquery(h, txid, 1);
	pbuf = buf + sizeof(ffdns_hdr);

	n = ffdns_addquery(pbuf, (buf + cap) - pbuf, host->ptr, host->len, type);
	if (n == 0)
		return 0;
	pbuf += n;

	if (resvm->edns) {
		h->arcount[1] = 1;
		*pbuf++ = '\x00';
		ffdns_optinit((ffdns_opt*)pbuf, resvm->buf_size);
		pbuf += sizeof(ffdns_opt);
	}

	return pbuf - buf;
}


/** Receive data from DNS server. */
static void resv_read_data(void *udata)
{
	dns_serv *serv = udata;
	ssize_t r;
	ffstr resp;

	for (;;) {
		r = ffaio_recv(&serv->aiotask, &resv_read_data, serv->ansbuf, resvm->buf_size);
		if (r == FFAIO_ASYNC)
			return;
		else if (r == FFAIO_ERROR) {
			syserrlog_srv(serv, FSV_LOG_ERR, "%e", FFERR_READ);
			return;
		}

		fsv_dbglog(resvm->logctx, FSV_LOG_DBGNET, RESV_MODNAME, &serv->saddr
			, "received response (%L bytes)", r);

		ffstr_set(&resp, serv->ansbuf, r);
		resv_proc_data(serv, &resp);
	}
}

/** Process response and notify users waiting for it. */
static void resv_proc_data(dns_serv *serv, const ffstr *resp)
{
	ffdns_hdr_host h;
	dns_query *q;
	int is4, i;

	q = resv_find_query(serv, &h, resp);
	if (q == NULL)
		return;

	if (q->need4 && h.id == q->txid4) {
		q->need4 = 0;
		is4 = 1;

	} else if (q->need6 && h.id == q->txid6) {
		q->need6 = 0;
		is4 = 0;

	} else {
		errlog_q(q, FSV_LOG_ERR, "request/response IDs don't match.  Response ID: #%u", h.id);
		return;
	}

	if (h.rcode != FFDNS_NOERROR) {
		errlog_q(q, FSV_LOG_ERR, "#%u: DNS response: (%u) %s"
			, h.id, h.rcode, ffdns_errstr(h.rcode));
		if (q->nres == 0)
			q->status = h.rcode; //set error only from the first response

	} else if (NULL != resv_proc_resp(q, &h, resp, is4))
		q->status = FFDNS_NOERROR;
	else if (q->nres == 0)
		q->status = -1;

	if (fsv_log_checkdbglevel(resvm->logctx, FSV_LOG_DBGNET)) {
		fftime t = resvm->core->fsv_gettime();
		fftime_diff(&q->firstsend, &t);
		dbglog_q(q, FSV_LOG_DBGNET, "resolved IPv%u in %u.%03us"
			, (is4) ? 4 : 6, (int)fftime_sec(&t), (int)fftime_msec(&t));
	}

	if (q->need4 || q->need6)
		return; //waiting for the second response

	resvm->core->fsv_timerstop(&q->tmr);

	// store in cache
	if (resvm->cachctx != NULL) {
		resv_cacheresp(q);
	}

	// if cache is disabled or we failed to store in cache, just set the appropriate refcount
	for (i = 0;  i < q->nres;  i++) {
		dns_res *res = q->res[i];
		if (res->cached_id == NULL)
			res->usage = (uint)q->users.len;
	}

	resv_notifyfin(q, q->status);
}

/** Find query by a response from DNS server. */
static dns_query * resv_find_query(dns_serv *serv, ffdns_hdr_host *h, const ffstr *resp)
{
	dns_query *q;
	const char *end = resp->ptr + resp->len;
	const char *pbuf;
	ffdns_hdr *hdr;
	char qname[FFDNS_MAXNAME];
	const char *errmsg = NULL;
	uint namecrc;
	ffstr name;
	ffrbt_node *found_query;
	uint resp_id = 0;

	if (resp->len < sizeof(ffdns_hdr)) {
		errmsg = "too small response";
		goto fail;
	}

	hdr = (ffdns_hdr*)resp->ptr;
	ffdns_hdrtohost(h, hdr);
	if (hdr->qr != 1) {
		errmsg = "received invalid response";
		goto fail;
	}

	resp_id = h->id;

	if (h->qdcount != 1) {
		errmsg = "number of questions in response is not 1";
		goto fail;
	}

	pbuf = resp->ptr + sizeof(ffdns_hdr);

	name.len = ffdns_name(qname, sizeof(qname), resp->ptr, resp->len, &pbuf);
	if (name.len == 0) {
		errmsg = "invalid name in question";
		goto fail;
	}
	name.len--;
	name.ptr = qname;

	fsv_dbglog(resvm->logctx, FSV_LOG_DBGNET, RESV_MODNAME, &name
		, "DNS response #%u.  Status: %u.  AA: %u, RA: %u.  Q: %u, A: %u, N: %u, R: %u."
		, h->id, hdr->rcode, hdr->aa, hdr->ra
		, h->qdcount, h->ancount, h->nscount, h->arcount);

	if (pbuf + sizeof(ffdns_ques) > end) {
		errmsg = "too small response";
		goto fail;
	}

	{
		ffdns_ques_host qh;
		ffdns_questohost(&qh, pbuf);
		if (qh.clas != FFDNS_IN) {
			fsv_errlog(resvm->logctx, FSV_LOG_ERR, RESV_MODNAME, &name
				, "#%u: invalid class %u in DNS response"
				, h->id, qh.clas);
			goto fail;
		}
	}

	namecrc = ffcrc32_get(qname, name.len);

	found_query = ffrbt_find(&resvm->queries, namecrc, NULL);
	if (found_query == NULL) {
		errmsg = "unexpected DNS response";
		goto fail;
	}

	q = resv_query_sib(found_query);
	if (!ffstr_eq2(&q->name, &name)) {
		errmsg = "unexpected DNS response";
		goto fail;
	}

	return q;

fail:
	if (errmsg != NULL)
		fsv_errlog(resvm->logctx, FSV_LOG_ERR, RESV_MODNAME, &serv->saddr
			, "%s. ID: #%u. Name: %S", errmsg, resp_id, &name);

	return NULL;
}

/** Get the number of useful records.  Print debug info about the records in response. */
static uint resv_nrecs(dns_query *q, ffdns_hdr_host *h, const ffstr *resp, const char *pbuf, int is4)
{
	uint nrecs = 0;
	uint ir;
	char qname[FFDNS_MAXNAME];
	const char *end = resp->ptr + resp->len;
	ffdns_ans_host ans;
	ffstr name;

	for (ir = 0;  ir < h->ancount;  ir++) {
		name.len = ffdns_name(qname, sizeof(qname), resp->ptr, resp->len, &pbuf);
		if (name.len == 0) {
			errlog_q(q, FSV_LOG_WARN, "#%u: invalid name in answer", h->id);
			break;
		}
		name.ptr = qname;
		name.len--;

		if (pbuf + sizeof(ffdns_ans) > end) {
			errlog_q(q, FSV_LOG_INFO, "#%u: incomplete response", h->id);
			break;
		}

		ffdns_anstohost(&ans, (ffdns_ans*)pbuf);
		pbuf += sizeof(ffdns_ans) + ans.len;
		if (pbuf > end) {
			errlog_q(q, FSV_LOG_INFO, "#%u: incomplete response", h->id);
			break;
		}

		switch (ans.type) {

		case FFDNS_A:
			if (ans.clas != FFDNS_IN) {
				errlog_q(q, FSV_LOG_ERR, "#%u: invalid class in %s record: %u", h->id, "A", ans.clas);
				continue;
			}
			if (ans.len != sizeof(ffip4)) {
				errlog_q(q, FSV_LOG_ERR, "#%u: invalid %s address length: %u", h->id, "A", ans.len);
				continue;
			}

			if (fsv_log_checkdbglevel(resvm->logctx, FSV_LOG_DBGFLOW)) {
				char ip[FFIP4_STRLEN];
				size_t iplen = ffip4_tostr(ip, FFCNT(ip), (void*)ans.data);
				dbglog_q(q, FSV_LOG_DBGFLOW, "%s for %S : %*s, TTL: %u"
					, "A", &name, (size_t)iplen, ip, ans.ttl);
			}

			if (is4)
				nrecs++;
			break;

		case FFDNS_AAAA:
			if (ans.clas != FFDNS_IN) {
				errlog_q(q, FSV_LOG_ERR, "#%u: invalid class in %s record: %u", h->id, "AAAA", ans.clas);
				continue;
			}
			if (ans.len != sizeof(ffip6)) {
				errlog_q(q, FSV_LOG_ERR, "#%u: invalid %s address length: %u", h->id, "AAAA", ans.len);
				continue;
			}

			if (fsv_log_checkdbglevel(resvm->logctx, FSV_LOG_DBGFLOW)) {
				char ip[FFIP6_STRLEN];
				size_t iplen = ffip6_tostr(ip, FFCNT(ip), (void*)ans.data);
				dbglog_q(q, FSV_LOG_DBGFLOW, "%s for %S : %*s, TTL: %u"
					, "AAAA", &name, (size_t)iplen, ip, ans.ttl);
			}

			if (!is4)
				nrecs++;
			break;

		case FFDNS_CNAME:
			if (fsv_log_checkdbglevel(resvm->logctx, FSV_LOG_DBGFLOW)) {
				ffstr scname;
				char cname[NI_MAXHOST];
				const char *tbuf = pbuf;

				scname.len = ffdns_name(cname, sizeof(cname), resp->ptr, resp->len, &tbuf);
				if (scname.len == 0 || tbuf > pbuf + ans.len) {
					errlog_q(q, FSV_LOG_ERR, "invalid CNAME");
					continue;
				}
				scname.ptr = cname;
				scname.len--;

				dbglog_q(q, FSV_LOG_DBGFLOW, "CNAME for %S : %S", &name, &scname);
			}
			break;

		default:
			dbglog_q(q, FSV_LOG_DBGFLOW, "record of type %u, length %u", ans.type, ans.len);
			break;
		}
	}

	return nrecs;
}

/** Set the linked list of addresses. */
static void resv_addr_setlist4(dns_a *a, dns_a *end)
{
	for (;;) {
		if (a + 1 == end) {
			a->ainfo.ai_next = NULL;
			break;
		}
		a->ainfo.ai_next = &(a + 1)->ainfo;
		a++;
	}
}

static void resv_addr_setlist6(dns_a6 *a6, dns_a6 *end)
{
	for (;;) {
		if (a6 + 1 == end) {
			a6->ainfo.ai_next = NULL;
			break;
		}
		a6->ainfo.ai_next = &(a6 + 1)->ainfo;
		a6++;
	}
}

/** Create DNS resource object. */
static dns_res * resv_proc_resp(dns_query *q, ffdns_hdr_host *h, const ffstr *resp, int is4)
{
	const char *end = resp->ptr + resp->len;
	const char *pbuf;
	uint nrecs = 0;
	uint ir;
	dns_res *res = NULL;
	dns_a *acur;
	dns_a6 *a6cur;
	uint minttl = (uint)-1;

	pbuf = resp->ptr + sizeof(ffdns_hdr);
	ffdns_skipname(resp->ptr, resp->len, &pbuf);
	pbuf += sizeof(ffdns_ques);

	nrecs = resv_nrecs(q, h, resp, pbuf, is4);

	if (nrecs == 0) {
		dbglog_q(q, FSV_LOG_DBGFLOW, "#%u: no useful records in response", h->id);
		return NULL;
	}

	{
		uint adr_sz = (is4 ? sizeof(dns_a) : sizeof(dns_a6));
		res = ffmem_alloc(sizeof(dns_res) + adr_sz * nrecs);
		if (res == NULL) {
			fsv_syserrlog(resvm->logctx, FSV_LOG_ERR, RESV_MODNAME, NULL, "%e", FFERR_BUFALOC);
			return NULL;
		}
		res->naddrs = nrecs;
		acur = res->addrs;
		a6cur = res->addrs6;
	}

	// set addresses and get the minimum TTL value
	for (ir = 0;  ir < h->ancount;  ir++) {
		ffdns_ans_host ans;

		ffdns_skipname(resp->ptr, resp->len, &pbuf);

		if (pbuf + sizeof(ffdns_ans) > end)
			break;

		ffdns_anstohost(&ans, (ffdns_ans*)pbuf);
		pbuf += sizeof(ffdns_ans) + ans.len;
		if (pbuf > end)
			break;

		if (is4 && ans.type == FFDNS_A) {
			if (ans.clas != FFDNS_IN || ans.len != sizeof(struct in_addr))
				continue;

			acur->addr.sin_family = AF_INET;
			acur->ainfo.ai_family = AF_INET;
			acur->ainfo.ai_addr = (struct sockaddr*)&acur->addr;
			acur->ainfo.ai_addrlen = sizeof(struct sockaddr_in);
			ffmemcpy(&acur->addr.sin_addr, ans.data, sizeof(struct in_addr));
			acur++;

			minttl = (uint)ffmin(minttl, ans.ttl);

		} else if (!is4 && ans.type == FFDNS_AAAA) {
			if (ans.clas != FFDNS_IN || ans.len != sizeof(struct in6_addr))
				continue;

			a6cur->addr.sin6_family = AF_INET6;
			a6cur->ainfo.ai_family = AF_INET6;
			a6cur->ainfo.ai_addr = (struct sockaddr*)&a6cur->addr;
			a6cur->ainfo.ai_addrlen = sizeof(struct sockaddr_in6);
			ffmemcpy(&a6cur->addr.sin6_addr, ans.data, sizeof(struct in6_addr));
			a6cur++;

			minttl = (uint)ffmin(minttl, ans.ttl);
		}
	}

	if (is4)
		resv_addr_setlist4(res->addrs, acur);
	else
		resv_addr_setlist6(res->addrs6, a6cur);

	ir = q->nres++;
	q->res[ir] = res;
	q->ttl[ir] = minttl;
	return res;
}

static void dns_res_fin(dns_res *dr)
{
	ffmem_free(dr);
}

/** Notify users, waiting for this question.  Free query object. */
static void resv_notifyfin(dns_query *q, int status)
{
	dns_quser *quser;
	const ffaddrinfo *ai[2] = {0};
	uint i;

	ffrbt_rm(&resvm->queries, &q->rbtnod);

	for (i = 0;  i < q->nres;  i++) {
		ai[i] = &q->res[i]->addrs[0].ainfo;
	}

	FFARR_WALK(&q->users, quser) {
		quser->ondone(quser->udata, status, ai);
	}

	resv_finquery(q);
}


/** Prepare socket to connect to a DNS server. */
static int dns_serv_init(dns_serv *serv)
{
	int er;
	ffskt sk;

	sk = ffskt_create(ffaddr_family(&serv->addr), SOCK_DGRAM | SOCK_NONBLOCK, IPPROTO_UDP);
	if (sk == FF_BADSKT) {
		er = FFERR_SKTCREAT;
		goto fail;
	}

	{
		ffaddr la;
		ffaddr_init(&la);
		ffaddr_setany(&la, ffaddr_family(&serv->addr));
		if (0 != ffskt_bind(sk, &la.a, la.len)) {
			er = FFERR_SKTLISTEN;
			goto fail;
		}
	}

	ffaio_init(&serv->aiotask);
	serv->aiotask.udata = serv;
	serv->aiotask.sk = sk;
	serv->aiotask.udp = 1;
	if (0 != ffaio_attach(&serv->aiotask, resvm->kq, FFKQU_READ)) {
		er = FFERR_KQUATT;
		goto fail;
	}

	serv->sk = sk;
	return 0;

fail:
	syserrlog_srv(serv, FSV_LOG_ERR, "%e", er);

	if (sk != FF_BADSKT)
		ffskt_close(sk);

	return 1;
}

static void dns_serv_fin(dns_serv *serv)
{
	FF_SAFECLOSE(serv->sk, FF_BADSKT, ffskt_close);
	FF_SAFECLOSE(serv->ansbuf, NULL, ffmem_free);
	ffmem_free(serv);
}

/** Round-robin balancer. */
static dns_serv * resv_nextserv(resolver *r)
{
	dns_serv *serv = r->curserv;
	fflist_item *next = ((serv->sib.next != fflist_sentl(&r->servs)) ? serv->sib.next : r->servs.first);
	r->curserv = FF_GETPTR(dns_serv, sib, next);
	return serv;
}


static int resv_cache_onchange(fsv_cachectx *ctx, fsv_cacheitem *ca, int flags)
{
	dns_res *res = *(dns_res**)ca->data;
	if (flags == FSV_CACH_ONDELETE) {
		FF_ASSERT(res->cached_id == ca->id);
		dns_res_fin(res);
	}
	return 0;
}

/** Store addresses in cache. */
static void resv_cacheresp(dns_query *q)
{
	uint i;
	fsv_cacheitem ca;

	fsv_cache_init(&ca);
	ca.logctx = resvm->logctx;

	for (i = 0;  i < q->nres;  i++) {
		dns_res *res = q->res[i];

		ca.key = q->name.ptr;
		ca.keylen = q->name.len;
		ca.data = (char*)&res;
		ca.datalen = sizeof(dns_res*);
		ca.refs = (uint)q->users.len;
		ca.expire = (uint)ffmin(q->ttl[0], q->ttl[q->nres - 1]);

		if (0 == resvm->cachmod->store(resvm->cachctx, &ca, 0)) {
			res->cached_id = ca.id;
		}
	}
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
		dns_res *res = *(dns_res**)ca.data;
		ai[0] = &res->addrs[0].ainfo;

		// get the next item
		fsv_cache_init(&ca);
		ca.logctx = resvm->logctx;
		ca.id = res->cached_id;

		if (0 == resvm->cachmod->fetch(resvm->cachctx, &ca, FSV_CACH_NEXT)) {
			res = *(dns_res**)ca.data;
			ai[1] = &res->addrs[0].ainfo;
		}

		return 0;
	}
	return 1;
}

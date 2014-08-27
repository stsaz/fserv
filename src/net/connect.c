/** Handle connections with remote servers.
Copyright 2014 Simon Zolin.
*/

#include <core/fserv.h>
#include <FF/list.h>
#include <FF/json.h>
#include <FF/net/url.h>
#include <FF/net/dns.h>


typedef struct conmodule {
	const fsv_core *core;
	fsv_logctx *logctx;
	fflist ctxs; //connctx[]
	fflist cons; //active connections.  fsv_conn[]
	fflist recycled_cons; //empty objects for reuse.  fsv_conn[]
	fffd kq;

	//conf:
	uint max_cons;
	fsv_resolv_ctx *dnsctx;
	const fsv_resolver *dns;
} conmodule;

static conmodule *conm;

typedef struct conn_serv {
	fflist_item sib;
	ffstr surl;
	ffurl parsed_url;
	byte weight;
	uint down_until; //recheck the down server at this time.  UNIX timestamp.

	unsigned dynamic_url :1; //'surl' contains $vars
} conn_serv;

struct fsv_conctx {
	fflist_item sib;

	fflist upstm; //conn_serv[]
	conn_serv *curserv;
	uint eff_weight; //effective weight of 'curserv'

	//conf:
	uint connect_timeout;
	uint down_time;
	const fsv_cache *cachmod;
	fsv_cachectx *cachctx;
	const fsv_connect_cb *cb;

	//status:
	uint connected
		, active;
};

struct fsv_conn {
	fflist_item sib;
	fsv_conctx *cx;
	ffskt sk;
	ffaio_task aiotask;
	fsv_timer tmr;

	void *userptr; //opaque value set by the caller
	fsv_logctx *logctx;

	ffstr surl; //"http://host/path"
	ffstr host; //"host:port"
	uint hostlen; //length of host without ":port"
	uint port;

	ffaddrinfo *addrinfo; //for a system resolver
	const ffaddrinfo *ai[2]; //for module net.resolve
	const ffaddrinfo *cur_ai;

	fsv_cacheitem_id *kalive_id;
	conn_serv *curserv
		, *firstserv;
	uint status; //enum CONN_ST
	unsigned dynamic_url :1
		, dynamic_host :1
		, ipv4 :1
		, ipv6 :1
		, second_ai :1 //if set, 'cur_ai' points to an element in the list 'ai[1]'
		;
};

enum CONN_ST {
	ST_NONE
	, ST_RESOLVING
	, ST_CONNECTING
	, ST_KEEPALIVE
};

#define CONN_MODNAME "CONN"

#define errlog(lgx, lev, ...) \
	fsv_errlog(lgx, lev, CONN_MODNAME, NULL, __VA_ARGS__)

#define syserrlog(lgx, lev, fmt, ...) \
	fsv_syserrlog(lgx, lev, CONN_MODNAME, NULL, fmt, __VA_ARGS__)

#define dbglog(lgx, lev, ...) \
	fsv_dbglog(lgx, lev, CONN_MODNAME, NULL, __VA_ARGS__)

// FSERV MODULE
static void * conm_create(const fsv_core *core, ffpars_ctx *a, fsv_modinfo *m);
static void conm_destroy(void);
static int conm_sig(int sig);
static const void * conm_iface(const char *name);
const fsv_mod fsv_conn_mod = {
	&conm_create, &conm_destroy, &conm_sig, &conm_iface
};

// FSERV CONNECT
static fsv_conctx * conn_newctx(ffpars_ctx *a, const fsv_connect_cb *cb);
static ssize_t conn_getvar(fsv_conn *c, const char *name, size_t namelen, void *dst, size_t cap);
static int conn_getserv(fsv_conctx *cx, fsv_conn_new *nc, int flags);
static void conn_connect(fsv_conn *c, int flags);
static int conn_disconnect(fsv_conn *c, int flags);
static ssize_t conn_recv(fsv_conn *c, void *buf, size_t size, ffaio_handler handler, void *udata);
static ssize_t conn_send(fsv_conn *c, const void *buf, size_t len, ffaio_handler handler, void *udata);
static ssize_t conn_sendfile(fsv_conn *c, ffsf *sf, ffaio_handler handler, void *udata);
static int conn_cancelio(fsv_conn *c, int op, ffaio_handler handler, void *udata);
static const fsv_connect fsv_conn_iface = {
	&conn_newctx, &conn_getvar
	, &conn_getserv, &conn_connect, &conn_disconnect
	, &conn_recv, &conn_send, &conn_sendfile, &conn_cancelio
};

// CONF
static int conm_conf_log(ffparser_schem *ps, conmodule *m, ffpars_ctx *a);
static int conm_conf_resolver(ffparser_schem *ps, conmodule *m, ffpars_ctx *a);
static int conx_conf_upstream(ffparser_schem *ps, fsv_conctx *cx, ffpars_ctx *a);
static int conx_conf_end(ffparser_schem *ps, fsv_conctx *cx);
static int conx_conf_kacache(ffparser_schem *ps, fsv_conctx *cx, ffpars_ctx *a);

static void conx_fin(fsv_conctx *cx);

// KEEP-ALIVE
static int conn_testcon(fsv_conn *c);
#ifdef FF_UNIX
static void conn_onrsig(void *udata);
#endif
static void conn_store_keepalive(fsv_conn *c);
static fsv_conn * conn_find_keepalive(fsv_conctx *cx, const ffstr *host, fsv_logctx *logctx);
static int conn_cach_cb(fsv_cachectx *ctx, fsv_cacheitem *ca, int flags);
static const fsv_cach_cb fsv_conn_cach_cb = {
	&conn_cach_cb
};

static conn_serv * conx_getserv(fsv_conctx *cx, conn_serv *cur, conn_serv *first, fsv_logctx *logctx);
static void conx_serv_mark_down(fsv_conctx *cx, conn_serv *cs);
static void conn_serv_fin(conn_serv *cs);

// ADDR RESOLVE
static void conn_resolve(fsv_conn *c);
static void conn_onresolve(void *udata, int status, const ffaddrinfo *ai[2]);
static void conn_freeaddr(fsv_conn *c);

static fsv_conn * conn_getconn(fsv_conctx *cx, fsv_logctx *logctx);
static void conn_connectai(fsv_conn *c);
static void conn_connectnextaddr(fsv_conn *c);
static void conn_connectaddr(fsv_conn *c, ffaddr *adr);
static void conn_onconnect(void *udata);
static void conn_resettimer(fsv_conn *c, uint t);
static void conn_onexpire(const fftime *now, void *param);
static void conn_notify(fsv_conn *c, int result);
static void conn_recycle(fsv_conn *c);
static void conn_fin(fsv_conn *c);
static void conn_oncancel(void *udata);


static const ffpars_arg conm_conf_args[] = {
	{ "log",  FFPARS_TOBJ | FFPARS_FOBJ1,  FFPARS_DST(&conm_conf_log) }
	, { "max_connections",  FFPARS_TINT | FFPARS_FNOTZERO,  FFPARS_DSTOFF(conmodule, max_cons) }
	, { "dns_resolver",  FFPARS_TOBJ | FFPARS_FOBJ1,  FFPARS_DST(&conm_conf_resolver) }
};

static const ffpars_arg conx_conf_args[] = {
	{ "server",  FFPARS_TOBJ | FFPARS_FREQUIRED | FFPARS_FMULTI,  FFPARS_DST(&conx_conf_upstream) }
	, { "connect_timeout",  FFPARS_TINT | FFPARS_FNOTZERO,  FFPARS_DSTOFF(fsv_conctx, connect_timeout) }
	, { "down_time",  FFPARS_TINT | FFPARS_FNOTZERO,  FFPARS_DSTOFF(fsv_conctx, down_time) }
	, { "keepalive_cache",  FFPARS_TOBJ | FFPARS_FOBJ1,  FFPARS_DST(&conx_conf_kacache) }
	, { NULL,  FFPARS_TCLOSE,  FFPARS_DST(&conx_conf_end) }
};

static const ffpars_arg conn_serv_conf_args[] = {
	{ "url",  FFPARS_TSTR | FFPARS_FCOPY | FFPARS_FNOTEMPTY | FFPARS_FREQUIRED,  FFPARS_DSTOFF(conn_serv, surl) }
	, { "weight",  FFPARS_TINT | FFPARS_F8BIT | FFPARS_FNOTZERO,  FFPARS_DSTOFF(conn_serv, weight) }
};

static int conm_conf_log(ffparser_schem *ps, conmodule *mod, ffpars_ctx *a)
{
	const ffstr *name = &ps->vals[0];
	const fsv_log *log_iface;
	const fsv_modinfo *m = conm->core->findmod(name->ptr, name->len);
	if (m == NULL)
		return FFPARS_EBADVAL;

	log_iface = m->f->iface("log");
	if (log_iface == NULL)
		return FFPARS_EBADVAL;

	conm->logctx = log_iface->newctx(a, conm->logctx);
	if (conm->logctx == NULL)
		return FFPARS_EINTL;

	return 0;
}

static int conm_conf_resolver(ffparser_schem *ps, conmodule *mod, ffpars_ctx *a)
{
	const ffstr *name = &ps->vals[0];
	const fsv_modinfo *m = conm->core->findmod(name->ptr, name->len);
	if (m == NULL)
		return FFPARS_EBADVAL;

	conm->dns = m->f->iface("resolve");
	if (conm->dns == NULL)
		return FFPARS_EBADVAL;

	conm->dnsctx = conm->dns->newctx(a);
	if (conm->dnsctx == NULL)
		return FFPARS_EINTL;

	return 0;
}

static int conx_conf_upstream(ffparser_schem *ps, fsv_conctx *cx, ffpars_ctx *a)
{
	conn_serv *serv = ffmem_tcalloc1(conn_serv);
	if (serv == NULL)
		return FFPARS_ESYS;
	fflist_ins(&cx->upstm, &serv->sib);
	serv->weight = 1;

	ffpars_setargs(a, serv, conn_serv_conf_args, FFCNT(conn_serv_conf_args));
	return 0;
}

static int conx_conf_kacache(ffparser_schem *ps, fsv_conctx *cx, ffpars_ctx *a)
{
	const ffstr *name = &ps->vals[0];
	const fsv_modinfo *m = conm->core->findmod(name->ptr, name->len);
	if (m == NULL)
		return FFPARS_EBADVAL;

	cx->cachmod = m->f->iface("cache");
	if (cx->cachmod == NULL)
		return FFPARS_EINTL;

	cx->cachctx = cx->cachmod->newctx(a, &fsv_conn_cach_cb, FSV_CACH_MULTI | FSV_CACH_KEYICASE);
	if (cx->cachctx == NULL)
		return FFPARS_EINTL;

	return 0;
}

/** Parse static URLs. */
static int conx_conf_end(ffparser_schem *ps, fsv_conctx *cx)
{
	conn_serv *serv;
	FFLIST_WALK(&cx->upstm, serv, sib) {

		if (NULL != ffs_findc(serv->surl.ptr, serv->surl.len, '$'))
			serv->dynamic_url = 1;

		else {
			int er = ffurl_parse(&serv->parsed_url, serv->surl.ptr, serv->surl.len);
			if (er != 0) {
				errlog(conm->logctx, FSV_LOG_ERR, "%S: URL parse: %s", &serv->surl, ffurl_errstr(er));
				return FFPARS_EBADVAL;
			}
		}
	}

	cx->curserv = FF_GETPTR(conn_serv, sib, cx->upstm.first);
	cx->eff_weight = cx->curserv->weight;

	return 0;
}


static const void * conm_iface(const char *name)
{
	if (0 == ffsz_cmp(name, "connect"))
		return &fsv_conn_iface;
	return NULL;
}

static void * conm_create(const fsv_core *core, ffpars_ctx *a, fsv_modinfo *mi)
{
	const fsvcore_config *conf = core->conf();

	conm = ffmem_tcalloc1(conmodule);
	if (conm == NULL)
		return NULL;

	fflist_init(&conm->ctxs);
	fflist_init(&conm->cons);
	fflist_init(&conm->recycled_cons);
	conm->max_cons = 10000;
	conm->core = core;
	conm->logctx = conf->logctx;

	ffpars_setargs(a, conm, conm_conf_args, FFCNT(conm_conf_args));
	return conm;
}

static void conn_fin(fsv_conn *c)
{
	ffmem_free(c);
}

static void conn_serv_fin(conn_serv *serv)
{
	ffstr_free(&serv->surl);
	ffmem_free(serv);
}

static void conx_fin(fsv_conctx *cx)
{
	FFLIST_ENUMSAFE(&cx->upstm, conn_serv_fin, conn_serv, sib);
	ffmem_free(cx);
}

static void conm_destroy(void)
{
	FFLIST_ENUMSAFE(&conm->ctxs, conx_fin, fsv_conctx, sib);
	FFLIST_ENUMSAFE(&conm->cons, conn_recycle, fsv_conn, sib);
	FFLIST_ENUMSAFE(&conm->recycled_cons, conn_fin, fsv_conn, sib);
	ffmem_free(conm);
	conm = NULL;
}

static int conm_sig(int sig)
{
	switch (sig) {
	case FSVCORE_SIGSTART:
		conm->kq = conm->core->conf()->queue;
		return 0;
	}
	return 0;
}

static fsv_conctx * conn_newctx(ffpars_ctx *a, const fsv_connect_cb *cb)
{
	fsv_conctx *cx = ffmem_tcalloc1(fsv_conctx);
	if (cx == NULL)
		return NULL;
	fflist_ins(&conm->ctxs, &cx->sib);

	fflist_init(&cx->upstm);
	cx->connect_timeout = 65;
	cx->down_time = 5;
	cx->cb = cb;

	ffpars_setargs(a, cx, conx_conf_args, FFCNT(conx_conf_args));
	return cx;
}

static ssize_t conn_getvar(fsv_conn *c, const char *name, size_t namelen, void *dst, size_t cap)
{
	if (ffs_eqcz(name, namelen, "socket_fd")) {
		if (cap != sizeof(ffskt))
			return -1;
		*(ffskt*)dst = c->sk;
		return sizeof(ffskt);

	} else
		return -1;
	return 0;
}

static void conn_resettimer(fsv_conn *c, uint t)
{
	conm->core->timer(&c->tmr, -(int64)t * 1000, &conn_onexpire, c);
}

/** Get recycled connection or allocate new. */
static fsv_conn * conn_getconn(fsv_conctx *cx, fsv_logctx *logctx)
{
	fsv_conn *c;

	if (conm->recycled_cons.len != 0) {
		c = FF_GETPTR(fsv_conn, sib, conm->recycled_cons.last);
		fflist_rm(&conm->recycled_cons, &c->sib);
		return c;
	}

	if (conm->cons.len == conm->max_cons) {
		errlog(logctx, FSV_LOG_ERR, "reached max_connections limit");
		return NULL;
	}

	c = ffmem_tcalloc1(fsv_conn);
	if (c == NULL) {
		syserrlog(logctx, FSV_LOG_ERR, "%e", FFERR_BUFALOC);
		return NULL;
	}
	c->sk = FF_BADSKT;

	return c;
}

static int conn_getserv(fsv_conctx *cx, fsv_conn_new *nc, int flags)
{
	fsv_conn *c;
	fsv_logctx *logctx = ((nc->logctx != NULL) ? nc->logctx : conm->logctx);
	conn_serv *cs, *firstserv;
	ffstr surl = {0};
	ffbool dynamic_url = 0
		, dynamic_host = 0;
	int er;
	uint port;
	ffstr host;
	ffurl u = {0};

	if (nc->con != NULL) {
		// get the next server
		cs = conx_getserv(cx, nc->con->curserv, nc->con->firstserv, logctx);
		firstserv = nc->con->firstserv;
		conn_recycle(nc->con);
		nc->con = NULL;

	} else {
		cs = conx_getserv(cx, NULL, NULL, logctx);
		firstserv = cs;
	}

	if (cs == NULL) {
		er = FSV_CONN_ENOSERV;
		goto fail;
	}

	// get URL
	if (!cs->dynamic_url) {
		surl = cs->surl;
		u = cs->parsed_url;

	} else {

		if (0 != conm->core->process_vars(&surl, &cs->surl, cx->cb->getvar, nc->userptr, logctx)) {
			er = FSV_CONN_ESYS;
			goto fail;
		}
		dynamic_url = 1;

		er = ffurl_parse(&u, surl.ptr, surl.len);
		if (er != 0) {
			errlog(logctx, FSV_LOG_ERR, "%S: URL parse: %s", &surl, ffurl_errstr(er));
			er = FSV_CONN_EURL;
			goto fail;
		}
	}

	port = u.port;

	// get hostname with port number
	host = ffurl_get(&u, surl.ptr, FFURL_FULLHOST);
	if (u.port == 0) {
		ffstr3 dhost = {0};
		ffstr schem;

		schem = ffurl_get(&u, surl.ptr, FFURL_SCHEME);
		port = ffuri_scheme2port(schem.ptr, schem.len);
		if (port == 0) {
			errlog(logctx, FSV_LOG_ERR, "%S: unknown scheme '%S' in URL", &surl, &schem);
			er = FSV_CONN_EURL;
			goto fail;
		}

		if (0 == ffstr_catfmt(&dhost, "%S:%u", &host, port)) {
			er = FSV_CONN_ESYS;
			goto fail;
		}
		ffstr_acqstr3(&host, &dhost);
		dynamic_host = 1;
	}

	c = NULL;
	if (cx->cachctx != NULL)
		c = conn_find_keepalive(cx, &host, logctx);

	if (c == NULL) {
		c = conn_getconn(cx, logctx);
		if (c == NULL) {
			er = FSV_CONN_ESYS;
			goto fail;
		}

		c->cx = cx;
	}

	c->userptr = nc->userptr;
	c->logctx = logctx;

	c->firstserv = firstserv;
	c->curserv = cs;

	ffstr_acq(&c->surl, &surl);
	c->dynamic_url = dynamic_url;

	ffstr_acq(&c->host, &host);
	c->dynamic_host = dynamic_host;

	c->hostlen = u.hostlen;
	c->port = port;
	c->ipv4 = u.ipv4;
	c->ipv6 = u.ipv6;
	c->second_ai = 0;

	nc->con = c;
	nc->url = c->surl;
	return FSV_CONN_OK;

fail:
	if (dynamic_url)
		ffstr_free(&surl);
	if (dynamic_host)
		ffstr_free(&host);

	return er;
}

/** Module net.resolve notifies about the result of DNS query. */
static void conn_onresolve(void *udata, int result, const ffaddrinfo *ai[2])
{
	fsv_conn *c = udata;
	c->status = ST_NONE;

	if (result != 0) {
		errlog(c->logctx, FSV_LOG_ERR, "%S: resolve: (%d) %s"
			, &c->host, result, ffdns_errstr(result));
		conx_serv_mark_down(c->cx, c->curserv);
		conn_notify(c, FSV_CONN_EDNS);
		return;
	}

	c->ai[0] = ai[0];
	c->ai[1] = ai[1];
	c->cur_ai = c->ai[0];
	conn_connectai(c);
}

/** Resolve hostname using mod-resolve or system function. */
static void conn_resolve(fsv_conn *c)
{
	char hostz[NI_MAXHOST];
	int r;

	ffsz_copy(hostz, FFCNT(hostz), c->host.ptr, c->hostlen);

	dbglog(c->logctx, FSV_LOG_DBGNET, "resolving %s...", hostz);

	if (conm->dns != NULL) {
		c->status = ST_RESOLVING;
		conm->dns->resolve(conm->dnsctx, c->host.ptr, c->hostlen, &conn_onresolve, c, 0);
		return;
	}

	r = ffaddr_info(&c->addrinfo, hostz, NULL, 0);
	if (r != 0) {
		char ser_s[255];
		const char *ser = ffaddr_errstr(r, ser_s, FFCNT(ser_s));
		errlog(c->logctx, FSV_LOG_ERR, "%S: resolve: (%u) %s"
			, &c->host, r, ser);
		conx_serv_mark_down(c->cx, c->curserv);
		conn_notify(c, FSV_CONN_EDNS);
		return;
	}

	c->cur_ai = c->addrinfo;
	conn_connectai(c);
}

static void conn_freeaddr(fsv_conn *c)
{
	FF_SAFECLOSE(c->addrinfo, NULL, ffaddr_free);
	FF_SAFECLOSE(c->ai[0], NULL, conm->dns->unref);
	FF_SAFECLOSE(c->ai[1], NULL, conm->dns->unref);
	c->cur_ai = NULL;
}

static void conn_connect(fsv_conn *c, int flags)
{
	ffaddr adr;

	if (c->sk != FF_BADSKT) {
		// the connection was taken from keep-alive cache
		c->cx->active++;
		conn_notify(c, FSV_CONN_OK);
		return;
	}

	ffaddr_init(&adr);
	ffip_setport(&adr, c->port);

	if (c->ipv4) {

		struct in_addr ip4;
		if (0 != ffip4_parse(&ip4, c->host.ptr, c->hostlen)) {
			errlog(c->logctx, FSV_LOG_ERR, "invalid IPv4 address: %*s"
				, (size_t)c->hostlen, c->host.ptr);
			conn_notify(c, FSV_CONN_EURL);
			return;
		}

		ffip4_set(&adr, &ip4);

	} else if (c->ipv6) {

		struct in6_addr ip6;
		ffstr s;

		ffstr_set(&s, c->host.ptr, c->hostlen);
		// [::1] -> ::1
		if (c->hostlen > 2 && c->host.ptr[0] == '[') {
			s.ptr++;
			s.len -= 2;
		}

		if (0 != ffip6_parse(&ip6, s.ptr, s.len)) {
			errlog(c->logctx, FSV_LOG_ERR, "invalid IPv6 address: %S", &s);
			conn_notify(c, FSV_CONN_EURL);
			return;
		}

		ffip6_set(&adr, &ip6);

	} else {
		conn_resolve(c);
		return;
	}

	conn_connectaddr(c, &adr);
}

/** Connect to the next address. */
static void conn_connectnextaddr(fsv_conn *c)
{
	if (c->cur_ai != NULL)
		c->cur_ai = c->cur_ai->ai_next;
	conn_connectai(c);
}

/** Convert address from type ffaddrinfo into ffaddr and connect. */
static void conn_connectai(fsv_conn *c)
{
	ffaddr adr;

	if (conm->dns != NULL) {
		if (c->cur_ai == NULL && !c->second_ai) {
			c->cur_ai = c->ai[1];
			c->second_ai = 1;
		}
	}

	if (c->cur_ai == NULL) {
		errlog(c->logctx, FSV_LOG_ERR, "%S: no next address to connect", &c->host);
		conn_notify(c, FSV_CONN_ENOADDR);
		return;
	}

	ffaddr_copy(&adr, c->cur_ai->ai_addr, c->cur_ai->ai_addrlen);
	ffip_setport(&adr, c->port);

	conn_connectaddr(c, &adr);
}

/** Connect to a server. */
static void conn_connectaddr(fsv_conn *c, ffaddr *adr)
{
	c->sk = ffskt_create(ffaddr_family(adr), SOCK_STREAM, IPPROTO_TCP);
	if (c->sk == FF_BADSKT) {
		int lev = ((fferr_last() == EINVAL) ? FSV_LOG_WARN : FSV_LOG_ERR);

		syserrlog(c->logctx, lev, "%S: %e, family %u"
			, &c->host, FFERR_SKTCREAT, (int)ffaddr_family(adr));

		if (fferr_last() == EINVAL) {
			conn_connectnextaddr(c);
			return;
		}

		conn_notify(c, FSV_CONN_ESYS);
		return;
	}

	if (fsv_log_checkdbglevel(c->logctx, FSV_LOG_DBGNET)) {
		char saddr[FF_MAXIP6];
		size_t n = ffaddr_tostr(adr, saddr, FFCNT(saddr), FFADDR_USEPORT);
		saddr[n] = '\0';
		dbglog(c->logctx, FSV_LOG_DBGNET, "trying address %s...", saddr);
	}

	if (0 != ffskt_nblock(c->sk, 1)) {
		syserrlog(c->logctx, FSV_LOG_ERR, "%S: %e", &c->host, FFERR_NBLOCK);
		goto fail;
	}

	ffaio_init(&c->aiotask);
	c->aiotask.sk = c->sk;
	if (0 != ffaio_attach(&c->aiotask, conm->kq, FFKQU_READ | FFKQU_WRITE)) {
		syserrlog(c->logctx, FSV_LOG_ERR, "%S: %e", &c->host, FFERR_KQUATT);
		goto fail;
	}

	c->status = ST_CONNECTING;
	if (FFAIO_ASYNC == ffaio_connect(&c->aiotask, &conn_onconnect, &adr->a, adr->len)) {
		conn_resettimer(c, c->cx->connect_timeout);
		c->aiotask.udata = c;
		return;
	}

	conn_onconnect(c);
	return;

fail:
	ffskt_close(c->sk);
	c->sk = FF_BADSKT;
	conn_notify(c, FSV_CONN_ESYS);
}

/** Notify parent module. */
static void conn_notify(fsv_conn *c, int result)
{
	conn_freeaddr(c);
	c->cx->cb->onconnect(c->userptr, result);
}

static void conn_onconnect(void *udata)
{
	fsv_conn *c = udata;
	c->status = ST_NONE;
	conm->core->fsv_timerstop(&c->tmr);

	if (0 != ffaio_result(&c->aiotask)) {

		ffaddr adr;
		char saddr[FF_MAXIP6];
		size_t n;

		if (c->ipv4 || c->ipv6)
			n = ffs_fmt(saddr, saddr + FFCNT(saddr), "%*s:%u", (size_t)c->hostlen, c->host.ptr, c->port);

		else {
			ffaddr_copy(&adr, c->cur_ai->ai_addr, c->cur_ai->ai_addrlen);
			ffip_setport(&adr, c->port);
			n = ffaddr_tostr(&adr, saddr, FFCNT(saddr), FFADDR_USEPORT);
		}

		syserrlog(c->logctx, FSV_LOG_ERR, "%S: %*s: %e", &c->host, n, saddr, FFERR_SKTCONN);
		ffskt_close(c->sk);
		c->sk = FF_BADSKT;

		conx_serv_mark_down(c->cx, c->curserv);
		conn_connectnextaddr(c);
		return;
	}

	dbglog(c->logctx, FSV_LOG_DBGNET, "%S: connected (socket %L)", &c->host, (size_t)c->sk);

	fflist_ins(&conm->cons, &c->sib);
	c->cx->connected++;
	c->cx->active++;
	conn_notify(c, FSV_CONN_OK);
}

static void conn_recycle(fsv_conn *c)
{
	ffaio_fin(&c->aiotask);
	if (c->sk != FF_BADSKT) {
		ffskt_close(c->sk);
		c->sk = FF_BADSKT;
		c->cx->connected--;
		fflist_rm(&conm->cons, &c->sib);
	}

	FF_ASSERT(c->addrinfo == NULL && c->ai[0] == NULL && c->ai[1] == NULL);
	FF_ASSERT(c->kalive_id == NULL);

	if (c->dynamic_url)
		ffstr_free(&c->surl);
	if (c->dynamic_host)
		ffstr_free(&c->host);
	c->firstserv = c->curserv = NULL;
	c->userptr = NULL;
	c->status = ST_NONE;
	c->logctx = NULL;
	c->cx = NULL;
	fflist_ins(&conm->recycled_cons, &c->sib);
}

static void conn_oncancel(void *udata)
{
	fsv_conn *c = udata;
	conn_freeaddr(c);
	conn_recycle(c);
}

static int conn_disconnect(fsv_conn *c, int flags)
{
	conm->core->fsv_timerstop(&c->tmr);

	switch (c->status) {

	case ST_RESOLVING:
		conm->dns->resolve(conm->dnsctx, c->host.ptr, c->hostlen, &conn_onresolve, c, FSV_RESOLV_CANCEL);
		conn_recycle(c);
		return 0;

	case ST_CONNECTING:
		ffaio_cancelasync(&c->aiotask, FFAIO_CONNECT, &conn_oncancel);
		return 0;

	case ST_NONE:
		break;

	default:
		return -1;
	}

	if (c->sk != FF_BADSKT) {
		c->cx->active--;

		if ((flags & FSV_CONN_KEEPALIVE) && c->cx->cachctx != NULL) {
			conn_store_keepalive(c);
			return 0;
		}

		dbglog(c->logctx, FSV_LOG_DBGNET, "%S: disconnected", &c->host);
	}

	conn_recycle(c);
	return 0;
}

/** I/O operation timed out. */
static void conn_onexpire(const fftime *now, void *param)
{
	fsv_conn *c = param;
	dbglog(c->logctx, FSV_LOG_DBGNET, "timer expired");
	ffaio_cancelasync(&c->aiotask, FFAIO_CONNECT, NULL);
}

static ssize_t conn_recv(fsv_conn *c, void *buf, size_t size, ffaio_handler handler, void *udata)
{
	if (handler == NULL) {
		ssize_t r = ffaio_result(&c->aiotask);

		if (r == 0) {
			r = ffskt_recv(c->sk, buf, size, 0);
			if (r == -1 && fferr_again(fferr_last()))
				r = FSV_IO_EAGAIN;
		}
		return r;
	}

	if (FFAIO_ASYNC == ffaio_recv(&c->aiotask, handler, NULL, 0)) {
		c->aiotask.udata = udata;
		return FSV_IO_ASYNC;
	}

	return FSV_IO_ERR;
}

static ssize_t conn_send(fsv_conn *c, const void *buf, size_t len, ffaio_handler handler, void *udata)
{
	ffsf sf;
	ffiovec iov;
	ffiov_set(&iov, buf, len);
	ffsf_init(&sf);
	ffsf_sethdtr(&sf.ht, &iov, 1, NULL, 0);
	return conn_sendfile(c, &sf, handler, udata);
}

static ssize_t conn_sendfile(fsv_conn *c, ffsf *sf, ffaio_handler handler, void *udata)
{
	if (handler == NULL) {
		ssize_t r = ffaio_result(&c->aiotask);

		if (r == 0) {
			r = (ssize_t)ffsf_send(sf, c->sk, 0);
			if (r == -1 && fferr_again(fferr_last()))
				r = FSV_IO_EAGAIN;
		}
		return r;
	}

	if (FFAIO_ASYNC == ffsf_sendasync(sf, &c->aiotask, handler)) {
		c->aiotask.udata = udata;
		return FSV_IO_ASYNC;
	}

	return FSV_IO_ERR;
}

static int conn_cancelio(fsv_conn *c, int op, ffaio_handler handler, void *udata)
{
	(void)ffaio_result(&c->aiotask);

	if (ffaio_active(&c->aiotask)) {
		c->aiotask.udata = udata;
		ffaio_cancelasync(&c->aiotask, op, handler);
		return FSV_IO_ASYNC;
	}

	return FSV_IO_ERR;
}


#ifdef FF_UNIX
/** Keep-alive connection signaled.  Remove the connection from cache. */
static void conn_onrsig(void *udata)
{
	fsv_conn *c = udata;
	fsv_cacheitem ca;

	if (0 == ffaio_result(&c->aiotask)) {

		if (0 == conn_testcon(c)) {
			if (FFAIO_ASYNC == ffaio_recv(&c->aiotask, &conn_onrsig, NULL, 0)) {
				c->aiotask.udata = c;
				return;
			}

			syserrlog(conm->logctx, FSV_LOG_ERR, "%S: keep-alive connection: %e", &c->host, FFERR_READ);
		}

	} else {
		if (fferr_last() == ECANCELED)
			return;
		syserrlog(conm->logctx, FSV_LOG_ERR, "%S: keep-alive connection: %e", &c->host, FFERR_READ);
	}

	fsv_cache_init(&ca);
	ca.logctx = conm->logctx;
	ca.id = c->kalive_id;
	if (FSV_CACH_OK != c->cx->cachmod->fetch(c->cx->cachctx, &ca, FSV_CACH_ACQUIRE)) {
		FF_ASSERT(0); //no such connection in cache, must not happen
		return;
	}

	c->status = ST_NONE; //don't do anything in conn_cach_cb()
	c->cx->cachmod->unref(&ca, FSV_CACH_UNLINK);
	c->kalive_id = NULL;
	conn_recycle(c);
}

#define conn_cancelread(aiotask) \
	(aiotask)->rhandler = NULL

#endif

/** Store keep-alive connection in cache. */
static void conn_store_keepalive(fsv_conn *c)
{
	fsv_cacheitem ca;

	if (0 != conn_testcon(c))
		goto fail;

#ifdef FF_UNIX
	if (FFAIO_ASYNC != ffaio_recv(&c->aiotask, &conn_onrsig, NULL, 0)) {
		syserrlog(conm->logctx, FSV_LOG_ERR, "%S: %e", &c->host, FFERR_READ);
		goto fail;
	}
	c->aiotask.udata = c;
#endif

	if (c->dynamic_url)
		ffstr_free(&c->surl);
	c->firstserv = c->curserv = NULL;
	c->userptr = NULL;
	c->status = ST_KEEPALIVE;
	c->logctx = conm->logctx;

	fsv_cache_init(&ca);
	ca.key = c->host.ptr;
	ca.keylen = c->host.len;
	ca.data = (char*)&c;
	ca.datalen = sizeof(fsv_conn*);
	ca.logctx = conm->logctx;
	ca.refs = 0;
	if (FSV_CACH_OK == c->cx->cachmod->store(c->cx->cachctx, &ca, 0)) {
		c->kalive_id = ca.id;
		return;
	}

#ifdef FF_UNIX
	conn_cancelread(&c->aiotask);
#endif

fail:
	conn_recycle(c);
}

/** Return 0 if the connection is ok and there is no unread data. */
static int conn_testcon(fsv_conn *c)
{
	const char *status;
	byte d;
	ssize_t r = ffskt_recv(c->sk, &d, 1, 0);
	if (r == -1 && fferr_again(fferr_last()))
		return 0;

	status = ((r == 0) ? "closed"
		: ((r > 0) ? "signalled" : "error"));

	dbglog(conm->logctx, FSV_LOG_DBGNET, "%S: keep-alive connection: %s"
		, &c->host, status);
	return 1;
}

/** Find keep-alive connection in cache. */
static fsv_conn * conn_find_keepalive(fsv_conctx *cx, const ffstr *host, fsv_logctx *logctx)
{
	fsv_cacheitem ca;
	fsv_conn *c;

	fsv_cache_init(&ca);
	ca.key = host->ptr;
	ca.keylen = host->len;
	ca.logctx = logctx;

	for (;;) {

		if (FSV_CACH_OK != cx->cachmod->fetch(cx->cachctx, &ca, FSV_CACH_ACQUIRE))
			return NULL;

		FF_ASSERT(ca.datalen == sizeof(fsv_conn*));
		c = *(fsv_conn**)ca.data;
		c->status = ST_NONE;
		FF_ASSERT(c->kalive_id == ca.id);
		c->cx->cachmod->unref(&ca, FSV_CACH_UNLINK);
		c->kalive_id = NULL;

#ifdef FF_UNIX
		conn_cancelread(&c->aiotask);
		break;

#else
		if (0 == conn_testcon(c))
			break;
		conn_recycle(c);
#endif
	}

	if (c->dynamic_host)
		ffstr_free(&c->host);
	return c;
}

/** Notification from mod-cache. */
static int conn_cach_cb(fsv_cachectx *ctx, fsv_cacheitem *ca, int flags)
{
	fsv_conn *c = *(fsv_conn**)ca->data;

	if (flags == FSV_CACH_ONDELETE
		&& c->status == ST_KEEPALIVE) {

		dbglog(c->logctx, FSV_LOG_DBGNET, "%S: keep-alive connection: %s"
			, &c->host, "expired");

#ifdef FF_UNIX
		conn_cancelread(&c->aiotask);
#endif

		c->kalive_id = NULL;
		conn_recycle(c);
	}

	return 0;
}


static void conx_serv_mark_down(fsv_conctx *cx, conn_serv *cs)
{
	if (cs->dynamic_url)
		return;

	cs->down_until = conm->core->fsv_gettime().s + cx->down_time;
	errlog(conm->logctx, FSV_LOG_ERR, "%S: marked server as 'down'", &cs->surl);
}

static FFINL conn_serv * conx_nextserv(fsv_conctx *cx, conn_serv *cs)
{
	fflist_item *next = ((cs->sib.next != NULL) ? cs->sib.next : cx->upstm.first);
	return FF_GETPTR(conn_serv, sib, next);
}

/** Round-robin balancer.
Get server and shift to the next in the list according to the 'weight' property.
Servers marked as 'down' are either skipped or rechecked.
@cur:	if set, get the server next in the list starting at @cur. */
static conn_serv * conx_getserv(fsv_conctx *cx, conn_serv *cur, conn_serv *first, fsv_logctx *logctx)
{
	conn_serv *cs = cx->curserv;

	if (cur != NULL)
		cs = conx_nextserv(cx, cur);

	for (;;) {

		if (cs == first) {
			dbglog(logctx, FSV_LOG_DBGFLOW, "all servers were processed");
			return NULL;
		}

		if (cs->down_until == 0) {
			dbglog(logctx, FSV_LOG_DBGFLOW, "using upstream server %S", &cs->surl);
			break;
		}

		if (cs->down_until <= conm->core->fsv_gettime().s) {
			dbglog(logctx, FSV_LOG_DBGFLOW, "recheck upstream server %S", &cs->surl);
			cs->down_until = 0;
			break;
		}

		cs = conx_nextserv(cx, cs);
		if (cs == cx->curserv) {
			errlog(logctx, FSV_LOG_ERR, "all servers are down");
			return NULL;
		}
	}

	if (cur == NULL) {
		if (cs != cx->curserv) {
			cx->curserv = cs;
			cx->eff_weight = cx->curserv->weight;
		}

		if (--cx->eff_weight == 0) {
			cx->curserv = conx_nextserv(cx, cs);
			cx->eff_weight = cx->curserv->weight;
		}
	}

	return cs;
}

/** Handle connections with remote servers.
Copyright 2014 Simon Zolin.
*/

#include <core/fserv.h>
#include <FF/list.h>
#include <FF/data/json.h>
#include <FF/net/url.h>
#include <FF/net/dns.h>
#include <FF/net/dns-client.h>


typedef struct conmodule {
	const fsv_core *core;
	fsv_logctx *logctx;
	fflist ctxs; //connctx[]
	fflist cons; //active connections.  fsv_conn[]
	fflist1 recycled_cons; //empty objects for reuse.  fsv_conn[]
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
	time_t down_until; //recheck the down server at this time.  UNIX timestamp.

	unsigned dynamic_url :1; //'surl' contains $vars

	const fsv_ssl *modssl;
	void *sslctx;
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
	union {
	fflist_item sib;
	fflist1_item recycled;
	};
	fsv_conctx *cx;
	ffskt sk;
	ffaio_task aiotask;
	fsv_timer tmr;
	fsv_sslcon *sslcon;

	void *userptr; //opaque value set by the caller
	fsv_logctx *logctx;

	ffstr surl; //"http://host/path"
	ffstr host; //"host:port"
	uint hostlen; //length of host without ":port"
	uint port;

	ffaddrinfo *addrinfo; //for a system resolver
	const ffaddrinfo *ai[2]; //for module net.resolve
	const ffaddrinfo *cur_ai;
	char saddr[FF_MAXIP6];
	ffaddr adr;

	fsv_cacheitem_id *kalive_id;
	conn_serv *curserv
		, *firstserv;
	uint status; //enum CONN_ST
	unsigned dynamic_url :1
		, dynamic_host :1
		, ipv4 :1
		, ipv6 :1
		, second_ai :1 //if set, 'cur_ai' points to an element in the list 'ai[1]'
		, isactive :1
		;
};

enum CONN_ST {
	ST_NONE
	, ST_RESOLVING
	, ST_CONNECTING
	, ST_HANDSHAKING
	, ST_KEEPALIVE
};

enum {
	CONN_SSL_RECV_TM = 65,
	CONN_SSL_SEND_TM = 65,
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
static ssize_t conn_getvar(void *obj, const char *name, size_t namelen, void *dst, size_t cap);
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

// STATUS
static void conn_status(const fsv_status *statusmod);
static const fsv_status_handler conn_stat_iface = {
	&conn_status
};

// CONF
static int conm_conf_log(ffparser_schem *ps, conmodule *m, ffpars_ctx *a);
static int conm_conf_resolver(ffparser_schem *ps, conmodule *m, ffpars_ctx *a);
static int conn_serv_conf_ssl(ffparser_schem *ps, conn_serv *serv, ffpars_ctx *a);
static int conx_conf_upstream(ffparser_schem *ps, fsv_conctx *cx, ffpars_ctx *a);
static int conx_conf_end(ffparser_schem *ps, fsv_conctx *cx);
static int conx_conf_kacache(ffparser_schem *ps, fsv_conctx *cx, ffpars_ctx *a);

static void conx_fin(fsv_conctx *cx);

// KEEP-ALIVE
static int conn_testcon(fsv_conn *c);
#ifdef FF_UNIX
static void conn_onrsig(void *udata);
#endif
static void conn_close_keepalive(fsv_conn *c);
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
static void conn_onexpire(void *param);
static void conn_notify(fsv_conn *c, int result);
static void conn_recycle(fsv_conn *c);
static void conn_fin(fsv_conn *c);
static void conn_oncancel(void *udata);
static void conn_stop(fsv_conn *c);

// SSL
static void conn_ssl_handshake(void *udata);
static ssize_t conn_ssl_recv(fsv_conn *c, void *buf, size_t size, ffaio_handler handler, void *udata);
static ssize_t conn_ssl_sendfile(fsv_conn *c, ffsf *sf, ffaio_handler handler, void *udata);


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
	, { "ssl",  FFPARS_TOBJ | FFPARS_FOBJ1,  FFPARS_DST(&conn_serv_conf_ssl) }
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

static int conn_serv_conf_ssl(ffparser_schem *ps, conn_serv *serv, ffpars_ctx *a)
{
	const ffstr *name = &ps->vals[0];
	const fsv_modinfo *m = conm->core->findmod(name->ptr, name->len);
	if (m == NULL)
		return FFPARS_EBADVAL;

	serv->modssl = m->f->iface("ssl");
	if (serv->modssl == NULL )
		return FFPARS_EBADVAL;

	serv->sslctx = serv->modssl->newctx(a);
	if (serv->sslctx == NULL)
		return FFPARS_EBADVAL;
	return 0;
}

/** Parse static URLs. */
static int conx_conf_end(ffparser_schem *ps, fsv_conctx *cx)
{
	conn_serv *serv;
	_FFLIST_WALK(&cx->upstm, serv, sib) {

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

	cx->curserv = FF_GETPTR(conn_serv, sib, fflist_first(&cx->upstm));
	cx->eff_weight = cx->curserv->weight;

	return 0;
}


static const void * conm_iface(const char *name)
{
	if (0 == ffsz_cmp(name, "connect"))
		return &fsv_conn_iface;
	else if (0 == ffsz_cmp(name, "json-status"))
		return &conn_stat_iface;
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

	fsv_conn *c;
	while (NULL != (c = (void*)fflist1_pop(&conm->recycled_cons))) {
		conn_fin(FF_GETPTR(fsv_conn, recycled, c));
	}

	ffmem_free(conm);
	conm = NULL;
}

/** Close a keep-alive connection.
UNIX: if a connection is still active, then a higher level module has a memory leak.
Windows: a connection may be still active while we're waiting for asynchronous cancel callback. */
static void conn_stop(fsv_conn *c)
{
	if (c->kalive_id == NULL) {

#ifdef FF_WIN
		if (!ffaio_active(&c->aiotask))
#endif
			errlog(conm->logctx, FSV_LOG_ERR, "module stop: connection with %S is still active"
				, &c->host);

		c->aiotask.whandler = c->aiotask.rhandler = NULL;
		conn_disconnect(c, 0);
		return;
	}

	conn_close_keepalive(c);
}

static int conm_sig(int sig)
{
	switch (sig) {
	case FSVCORE_SIGSTART:
		conm->kq = conm->core->conf()->queue;
		return 0;

	case FSVCORE_SIGSTOP:
		FFLIST_ENUMSAFE(&conm->cons, conn_stop, fsv_conn, sib);
		break;
	}
	return 0;
}

static const int conm_status_json_meta[] = {
	FFJSON_TOBJ
	, FFJSON_FKEYNAME, FFJSON_TSTR
	, FFJSON_FKEYNAME, FFJSON_FINTVAL
	, FFJSON_FKEYNAME, FFJSON_FINTVAL
	, FFJSON_TOBJ
};

static void conn_status(const fsv_status *statusmod)
{
	const fsv_conctx *cx;
	ffjson_cook status_json;
	char buf[4096];
	ffjson_cookinit(&status_json, buf, sizeof(buf));

	_FFLIST_WALK(&conm->ctxs, cx, sib) {
		ffjson_addv(&status_json, conm_status_json_meta, FFCNT(conm_status_json_meta)
			, FFJSON_CTXOPEN
			, "id", &FF_GETPTR(conn_serv, sib, fflist_first(&cx->upstm))->surl
			, "connected", (int64)cx->connected
			, "active", (int64)cx->active
			, FFJSON_CTXCLOSE
			, NULL);
	}

	statusmod->setdata(status_json.buf.ptr, status_json.buf.len, 0);
	ffjson_cookfin(&status_json);
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

static const ffstr conn_vars[] = {
	FFSTR_INIT("socket_fd") //ffskt

	//char*:
	, FFSTR_INIT("upstream_host")
	, FFSTR_INIT("upstream_addr")
};

enum CONN_VAR {
	CONN_VAR_SOCKET_FD
	, CONN_VAR_UPSTREAM_HOST
	, CONN_VAR_UPSTREAM_ADDR
};

static ssize_t conn_getvar(void *obj, const char *name, size_t namelen, void *dst, size_t cap)
{
	fsv_conn *c = obj;
	void *p = NULL;
	size_t n = 0;
	ssize_t v = ffstr_findarr(conn_vars, FFCNT(conn_vars), name, namelen);
	if (v == -1)
		return c->cx->cb->getvar(c->userptr, name, namelen, dst, cap);

	switch (v) {

	case CONN_VAR_SOCKET_FD:
		if (cap != sizeof(ffskt))
			return -1;
		*(ffskt*)dst = c->sk;
		return sizeof(ffskt);

	case CONN_VAR_UPSTREAM_HOST:
		p = c->host.ptr;
		n = c->host.len;
		break;

	case CONN_VAR_UPSTREAM_ADDR:
		p = c->saddr;
		n = ffsz_len(c->saddr);
		break;
	}

	*(char**)dst = p;
	return n;
}

static void conn_resettimer(fsv_conn *c, uint t)
{
	dbglog(c->logctx, FSV_LOG_DBGNET, "timer set: %us", t);
	conm->core->timer(&c->tmr, -(int64)t * 1000, &conn_onexpire, c);
}

/** Get recycled connection or allocate new. */
static fsv_conn * conn_getconn(fsv_conctx *cx, fsv_logctx *logctx)
{
	fsv_conn *c;

	if (NULL != (c = (void*)fflist1_pop(&conm->recycled_cons))) {
		return FF_GETPTR(fsv_conn, recycled, c);
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
	ffstr3 surl = {0};
	ffbool dynamic_host = 0;
	int er;
	uint port;
	ffstr host;
	ffurl u = {0};

	if (nc->con != NULL) {
		// get the next server
		cs = conx_getserv(cx, nc->con->curserv, nc->con->firstserv, logctx);
		firstserv = nc->con->firstserv;
		conn_disconnect(nc->con, 0);
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
		ffarr_set(&surl, cs->surl.ptr, cs->surl.len);
		u = cs->parsed_url;

	} else {

		if (0 != conm->core->process_vars(&surl, &cs->surl, cx->cb->getvar, nc->userptr, logctx)) {
			er = FSV_CONN_ESYS;
			goto fail;
		}
		FF_ASSERT(surl.cap != 0);

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

	ffstr_acqstr3(&c->surl, &surl);
	c->dynamic_url = cs->dynamic_url;

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
	ffarr_free(&surl);
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
		conn_notify(c, FSV_CONN_OK);
		return;
	}

	ffaddr_init(&adr);
	ffip_setport(&adr, c->port);

	if (c->ipv4) {

		ffip4 ip4;
		if (0 != ffip4_parse(&ip4, c->host.ptr, c->hostlen)) {
			errlog(c->logctx, FSV_LOG_ERR, "invalid IPv4 address: %*s"
				, (size_t)c->hostlen, c->host.ptr);
			conn_notify(c, FSV_CONN_EURL);
			return;
		}

		ffip4_set(&adr, (void*)&ip4);

	} else if (c->ipv6) {

		ffip6 ip6;
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

		ffip6_set(&adr, (struct in6_addr*)&ip6);

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
		dbglog(c->logctx, FSV_LOG_DBGNET, "%S: no next address to connect", &c->host);
		conx_serv_mark_down(c->cx, c->curserv);
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
	if (c->ipv4 || c->ipv6)
		ffsz_copy(c->saddr, sizeof(c->saddr), c->host.ptr, c->host.len);
	else {
		size_t n = ffaddr_tostr(adr, c->saddr, sizeof(c->saddr), FFADDR_USEPORT);
		c->saddr[n] = '\0';
	}

	c->sk = ffskt_create(ffaddr_family(adr), SOCK_STREAM | SOCK_NONBLOCK, IPPROTO_TCP);
	if (c->sk == FF_BADSKT) {
		int lev = ((fferr_last() == EINVAL) ? FSV_LOG_WARN : FSV_LOG_ERR);

		syserrlog(c->logctx, lev, "%S: %s: %e", &c->host, c->saddr, FFERR_SKTCREAT);

		if (fferr_last() == EINVAL) {
			conn_connectnextaddr(c);
			return;
		}

		conn_notify(c, FSV_CONN_ESYS);
		return;
	}

	dbglog(c->logctx, FSV_LOG_DBGNET, "trying address %s...", c->saddr);

	ffaio_init(&c->aiotask);
	c->aiotask.sk = c->sk;
	if (0 != ffaio_attach(&c->aiotask, conm->kq, FFKQU_READ | FFKQU_WRITE)) {
		syserrlog(c->logctx, FSV_LOG_ERR, "%S: %e", &c->host, FFERR_KQUATT);
		goto fail;
	}

	if (c->curserv->modssl != NULL) {
		fsv_ssl_newcon opts = {0};
		opts.logctx = c->logctx;
		c->sslcon = c->curserv->modssl->newcon(c->curserv->sslctx, &opts, FSV_SSL_CONNECT);
		if (c->sslcon == NULL)
			goto fail;
	}

	c->status = ST_CONNECTING;
	c->adr = *adr;
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
	if (result == FSV_CONN_OK) {
		c->isactive = 1;
		c->cx->active++;
	}

	conn_freeaddr(c);
	c->cx->cb->onconnect(c->userptr, result);
}

static void conn_onconnect(void *udata)
{
	fsv_conn *c = udata;
	c->status = ST_NONE;
	conm->core->fsv_timerstop(&c->tmr);

	int r = ffaio_connect(&c->aiotask, &conn_onconnect, &c->adr.a, c->adr.len);
	if (r == FFAIO_ASYNC) {
		conn_resettimer(c, c->cx->connect_timeout);
		c->aiotask.udata = c;
		return;
	} else if (r != 0) {
		syserrlog(c->logctx, FSV_LOG_ERR, "%S: %s: %e", &c->host, c->saddr, FFERR_SKTCONN);
		ffskt_close(c->sk);
		c->sk = FF_BADSKT;

		conn_connectnextaddr(c);
		return;
	}

	dbglog(c->logctx, FSV_LOG_DBGNET, "%S: connected (socket %L)  [%L]"
		, &c->host, (size_t)c->sk, conm->cons.len + 1);

	conn_freeaddr(c);
	fflist_ins(&conm->cons, &c->sib);
	c->cx->connected++;

	if (c->sslcon != NULL) {
		c->status = ST_HANDSHAKING;
		conn_ssl_handshake(c);
		return;
	}

	conn_notify(c, FSV_CONN_OK);
}

static void conn_recycle(fsv_conn *c)
{
	if (c->sslcon != NULL) {
		c->curserv->modssl->fin(c->sslcon);
		c->sslcon = NULL;
	}

	ffaio_fin(&c->aiotask);
	if (c->sk != FF_BADSKT) {
		ffskt_close(c->sk);
		c->sk = FF_BADSKT;
		c->cx->connected--;
		dbglog(conm->logctx, FSV_LOG_DBGNET, "%S: disconnected  [%L]"
			, &c->host, conm->cons.len - 1);
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
	fflist1_push(&conm->recycled_cons, &c->recycled);
}

static void conn_oncancel(void *udata)
{
	fsv_conn *c = udata;
	conn_recycle(c);
}

static void conn_oncancel2(void *udata)
{
	conn_disconnect(udata, 0);
}

static int conn_disconnect(fsv_conn *c, int flags)
{
	if (c->logctx != conm->logctx)
		c->logctx = conm->logctx;

	switch (c->status) {

	case ST_RESOLVING:
		conm->dns->resolve(conm->dnsctx, c->host.ptr, c->hostlen, &conn_onresolve, c, FFDNSCL_CANCEL);
		conn_recycle(c);
		return 0;

	case ST_CONNECTING:
		conm->core->fsv_timerstop(&c->tmr);
		conn_freeaddr(c);
		ffskt_close(c->sk);
		c->sk = FF_BADSKT;
		ffaio_cancelasync(&c->aiotask, FFAIO_CONNECT, &conn_oncancel);
		return 0;

	case ST_HANDSHAKING:
		conm->core->fsv_timerstop(&c->tmr);
		ffaio_cancelasync(&c->aiotask, FFAIO_RW, &conn_oncancel);
		return 0;

	case ST_NONE:
		break;

	default:
		FF_ASSERT(0);
		return -1;
	}

	if (c->sk != FF_BADSKT) {

		if (FSV_IO_ASYNC == conn_cancelio(c, FFAIO_RW, &conn_oncancel2, c))
			return 0; //wait until async operations on both channels are completed

		c->isactive = 0;
		c->cx->active--;

		if ((flags & FSV_CONN_KEEPALIVE) && c->cx->cachctx != NULL) {
			conn_store_keepalive(c);
			return 0;
		}
	}

	conn_recycle(c);
	return 0;
}

/** I/O operation timed out. */
static void conn_onexpire(void *param)
{
	fsv_conn *c = param;
	dbglog(c->logctx, FSV_LOG_DBGNET, "timer expired");
	ffaio_cancelasync(&c->aiotask, FFAIO_RW, NULL);
}

static ssize_t conn_recv(fsv_conn *c, void *buf, size_t size, ffaio_handler handler, void *udata)
{
	if (c->aiotask.ev == NULL && c->aiotask.rpending) {
		c->aiotask.rhandler = handler;
		c->aiotask.udata = udata;
		return FSV_IO_ASYNC;
	}

	if (c->curserv->modssl != NULL)
		return conn_ssl_recv(c, buf, size, handler, udata);

	ssize_t r = ffaio_recv(&c->aiotask, handler, buf, size);
	if (r == FFAIO_ASYNC) {
		c->aiotask.udata = udata;
		return FSV_IO_ASYNC;
	}

	return r;
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
	if (c->curserv->modssl != NULL)
		return conn_ssl_sendfile(c, sf, handler, udata);

	ssize_t r = ffsf_sendasync(sf, &c->aiotask, handler);
	if (r == FFAIO_ASYNC) {
		c->aiotask.udata = udata;
		return FSV_IO_ASYNC;
	}

	return r;
}

static int conn_cancelio(fsv_conn *c, int op, ffaio_handler handler, void *udata)
{
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
	byte d;

	int r = ffaio_recv(&c->aiotask, &conn_onrsig, &d, 1);
	if (r == FFAIO_ASYNC) {
		c->aiotask.udata = c;
		return;
	} else if (r < 0 && fferr_last() == ECANCELED)
		return;

	const char *status = (r == 0) ? "closed"
		: ((r > 0) ? "signalled" : "error");
	dbglog(conm->logctx, FSV_LOG_DBGNET, "%S: keep-alive connection: %s", &c->host, status);
	conn_close_keepalive(c);
}

#define conn_cancelread(aiotask) \
	(aiotask)->rhandler = NULL

#endif

static void conn_close_keepalive(fsv_conn *c)
{
	fsv_cacheitem ca;
	FF_ASSERT(c->cx->cachctx != NULL && c->kalive_id != NULL);
	fsv_cache_init(&ca);
	ca.logctx = conm->logctx;
	ca.id = c->kalive_id;
	if (FSV_CACH_OK != c->cx->cachmod->fetch(c->cx->cachctx, &ca, FSV_CACH_ACQUIRE)) {
		FF_ASSERT(0); //no such connection in cache, must not happen
		return;
	}

	c->status = ST_NONE; //don't do anything in conn_cach_cb()
	c->cx->cachmod->unref(c->cx->cachctx, &ca, FSV_CACH_UNLINK);
	c->kalive_id = NULL;
	conn_recycle(c);
}

/** Store keep-alive connection in cache. */
static void conn_store_keepalive(fsv_conn *c)
{
	fsv_cacheitem ca;

	if (0 != conn_testcon(c))
		goto fail;

#ifdef FF_UNIX
	c->aiotask.rhandler = &conn_onrsig;
	c->aiotask.udata = c;
	c->aiotask.rpending = 1;
#endif

	if (c->dynamic_url)
		ffstr_free(&c->surl);
	c->firstserv = NULL;
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

	for (;;) {

		fsv_cache_init(&ca);
		ca.key = host->ptr;
		ca.keylen = host->len;
		ca.logctx = logctx;

		if (FSV_CACH_OK != cx->cachmod->fetch(cx->cachctx, &ca, FSV_CACH_ACQUIRE))
			return NULL;

		FF_ASSERT(ca.datalen == sizeof(fsv_conn*));
		c = *(fsv_conn**)ca.data;
		c->status = ST_NONE;
		FF_ASSERT(c->kalive_id == ca.id);
		c->cx->cachmod->unref(cx->cachctx, &ca, FSV_CACH_UNLINK);
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

	cs->down_until = conm->core->fsv_gettime().sec + cx->down_time;
	errlog(conm->logctx, FSV_LOG_ERR, "%S: marked server as 'down'", &cs->surl);
}

static FFINL conn_serv * conx_nextserv(fsv_conctx *cx, conn_serv *cs)
{
	fflist_item *next = ((cs->sib.next != fflist_sentl(&cx->upstm)) ? cs->sib.next : fflist_first(&cx->upstm));
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

		if (cs->down_until <= conm->core->fsv_gettime().sec) {
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


static void conn_ssl_handshake(void *udata)
{
	fsv_conn *c = udata;
	int r;
	void *sslbuf_ptr;
	ssize_t sslbuf_len = -1;

	conm->core->fsv_timerstop(&c->tmr);

	for (;;) {
		r = c->curserv->modssl->handshake(c->sslcon, &sslbuf_ptr, &sslbuf_len);

		switch (r) {
		case FSV_SSL_WANTREAD:
			r = ffaio_recv(&c->aiotask, &conn_ssl_handshake, sslbuf_ptr, sslbuf_len);
			if (r == FFAIO_ASYNC) {
				c->aiotask.udata = udata;
				conn_resettimer(c, CONN_SSL_RECV_TM);
				return;
			}
			break;

		case FSV_SSL_WANTWRITE:
			r = ffaio_send(&c->aiotask, &conn_ssl_handshake, sslbuf_ptr, sslbuf_len);
			if (r == FFAIO_ASYNC) {
				c->aiotask.udata = udata;
				conn_resettimer(c, CONN_SSL_SEND_TM);
				return;
			}
			break;

		case FSV_SSL_ERR:
			goto fail;

		default:
			goto done;
		}

		if (r < 0)
			goto fail;
		sslbuf_len = r;
	}
	//unreachable

done:
	c->status = ST_NONE;
	conn_notify(c, FSV_CONN_OK);
	return;

fail:
	ffskt_close(c->sk);
	c->sk = FF_BADSKT;
	c->status = ST_NONE;
	errlog(c->logctx, FSV_LOG_ERR, "%S: SSL handshake", &c->host);
	conn_notify(c, FSV_CONN_ESYS);
}

static ssize_t conn_ssl_recv(fsv_conn *c, void *buf, size_t size, ffaio_handler handler, void *udata)
{
	void *sslbuf_ptr;
	ssize_t r, sslbuf_len = -1;

	for (;;) {
		r = c->curserv->modssl->recv(c->sslcon, buf, size, &sslbuf_ptr, &sslbuf_len);
		switch (r) {
		case FSV_SSL_WANTREAD:
			r = ffaio_recv(&c->aiotask, handler, sslbuf_ptr, sslbuf_len);
			break;

		case FSV_SSL_WANTWRITE:
			r = ffaio_send(&c->aiotask, handler, sslbuf_ptr, sslbuf_len);
			break;

		case FSV_SSL_ERR:
			return FSV_IO_ERR;

		default:
			return r;
		}

		if (r == FFAIO_ASYNC) {
			c->aiotask.udata = udata;
			return FSV_IO_ASYNC;
		} else if (r == -1)
			return FSV_IO_ERR;

		sslbuf_len = r;
	}
	//unreachable
}

static ssize_t conn_ssl_sendfile(fsv_conn *c, ffsf *sf, ffaio_handler handler, void *udata)
{
	void *sslbuf_ptr;
	ssize_t r, sslbuf_len = -1;

	for (;;) {
		r = c->curserv->modssl->sendfile(c->sslcon, sf, &sslbuf_ptr, &sslbuf_len);
		switch (r) {
		case FSV_SSL_WANTREAD:
			r = ffaio_recv(&c->aiotask, handler, sslbuf_ptr, sslbuf_len);
			break;

		case FSV_SSL_WANTWRITE:
			r = ffaio_send(&c->aiotask, handler, sslbuf_ptr, sslbuf_len);
			break;

		case FSV_SSL_ERR:
			return FSV_IO_ERR;

		default:
			return r;
		}

		if (r == FFAIO_ASYNC) {
			c->aiotask.udata = udata;
			return FSV_IO_ASYNC;
		} else if (r == -1)
			return FSV_IO_ERR;

		sslbuf_len = r;
	}
	//unreachable
}

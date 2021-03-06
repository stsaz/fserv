/** Accept and handle incoming connections.
Copyright 2014 Simon Zolin.
*/

#include <core/fserv.h>
#include <FF/list.h>
#include <FF/data/json.h>
#include <FF/net/url.h>


typedef struct lisnmod {
	const fsv_core *core;
	fsv_logctx *logctx;
	fflist ctxs; //lisnctx[]
	fflist cons; //active connections.  fsv_lsncon[]
	fflist1 recycled_cons; //fsv_lsncon[]
	fffd kq;
	fsv_timer queued_cons_timer;
	unsigned fd_limit :1;

	//conf:
	uint max_cons;
} lisnmod;

static lisnmod *lsnm;

typedef struct lisnctx {
	fflist_item sib;
	fsv_logctx *logctx;

	const fsv_listen_cb *cb;
	void *userctx;

	ffskt lsk;
	ffaio_acceptor acc;
	fsv_task task_accept;
	unsigned queued :1;

	//conf:
	uint max_cons;
	uint backlog;
	ffstr saddr;
	ffaddr addr;
	ushort tmout_linger;
	byte defer_accept;
	byte saddr_portlen;
	unsigned ip6dual :1 //listen on both IPv4 and IPv6
		, acc_init :1; //if set, 'acc' is initialized
	const fsv_ssl *modssl;

	//status:
	uint connected
		, max_connected;
} lisnctx;

struct fsv_lsncon {
	union {
	fflist_item sib;
	fflist1_item recycled;
	};
	lisnctx *lx;
	fsv_logctx *logctx;
	ffskt sk;
	fsv_timer tmr;
	ffaio_task aiotask;
	ffstr saddr_local //local address as a string
		, saddr_peer; //peer address as a string
	void *userptr;
	fsv_sslcon *sslcon;
	unsigned ssl_init :1;
};

enum {
	FDLIM_TIMER_INTERVAL = 4000
	, NOMEM_TIMER_INTERVAL = 4000
	, LISN_SSL_RECV_TM = 65
	, LISN_SSL_SEND_TM = 65
};

#define LSN_MODNAME "LISN"

#define lx_errlog(lx, lev, ...) \
	fsv_errlog((lx)->logctx, lev, LSN_MODNAME, &(lx)->saddr, __VA_ARGS__)

#define lx_syserrlog(lx, lev, fmt, ...) \
	fsv_syserrlog((lx)->logctx, lev, LSN_MODNAME, &(lx)->saddr, fmt, __VA_ARGS__)

#define lx_dbglog(lx, lev, ...) \
	fsv_dbglog((lx)->logctx, lev, LSN_MODNAME, &(lx)->saddr, __VA_ARGS__)


// FSERV MODULE
static void * lsnm_create(const fsv_core *core, ffpars_ctx *a, fsv_modinfo *m);
static void lsnm_destroy(void);
static int lsnm_sig(int signo);
static const void * lsnm_iface(const char *name);
const fsv_mod fsv_lsn_mod = {
	&lsnm_create, &lsnm_destroy, &lsnm_sig, &lsnm_iface
};

// FSERV LISTENER
static fsv_lsnctx * lsn_newctx(ffpars_ctx *a, const fsv_listen_cb *cb, void *userctx);
static fsv_lsnctx * lsn_findctx(const char *name, size_t len);
static ssize_t lsn_getvar(fsv_lsncon *c, const char *name, size_t namelen, void *dst, size_t cap);
static void lsn_closecon(fsv_lsncon *c, int flags);
static ssize_t lsn_recv(fsv_lsncon *c, void *buf, size_t size, ffaio_handler handler, void *udata);
static ssize_t lsn_send(fsv_lsncon *c, const void *buf, size_t len, ffaio_handler handler, void *udata);
static ssize_t lsn_sendfile(fsv_lsncon *c, ffsf *sf, ffaio_handler handler, void *udata);
static int lsn_cancel(fsv_lsncon *c, int op, ffaio_handler handler, void *udata);
static int lsn_setopt(fsv_lsncon *c, int opt, void *data);
static const fsv_listen fsv_lsn_iface = {
	&lsn_newctx, &lsn_findctx, &lsn_getvar, &lsn_setopt
	, &lsn_closecon, &lsn_recv, &lsn_send, &lsn_sendfile, &lsn_cancel
};

// STATUS
static void lisn_status(const fsv_status *statusmod);
static const fsv_status_handler lisn_stat_iface = {
	&lisn_status
};

// CONF
static int lsnm_conf_log(ffparser_schem *ps, lisnmod *lm, ffpars_ctx *a);
static int lsnx_conf_log(ffparser_schem *ps, lisnctx *lx, ffpars_ctx *a);
static int lsnx_conf_listen(ffparser_schem *ps, lisnctx *lx, const ffstr *s);
static int lsnx_conf_ssl(ffparser_schem *ps, lisnctx *lx, const ffstr *s);

static int lsnm_start(void);
static int lsnm_stop(void);
static void lsnm_process_queued_cons(void *param);

static int lsnx_start(lisnctx *lx);
static void lsnx_fin(lisnctx *lx);
static void lsn_onaccept(void *udata);
static int lsn_accept1(lisnctx *lx);
static fsv_lsncon * lsn_getconn(lisnctx *lx);

static int lsn_addrstr(fsv_lsncon *c, ffaddr *a, ffstr *dst, int flags);
static void lsn_fincon(fsv_lsncon *c);
static void lsn_recycle(fsv_lsncon *c);
static void lsn_linger(void *udata);
static void lsn_onexpire(void *param);
static void lsn_callmod(fsv_lsncon *c);
static void lsn_resettimer(fsv_lsncon *c, uint t);

static void lsn_ssl_newcon(fsv_lsncon *c, void *sslctx);
static void lsn_ssl_finaccept(fsv_lsncon *c);
static int lsn_ssl_srvname(void *udata);
static void lsn_ssl_handshake(void *udata);
static ssize_t lsn_ssl_recv(fsv_lsncon *c, void *buf, size_t size, ffaio_handler handler, void *udata);
static ssize_t lsn_ssl_sendfile(fsv_lsncon *c, ffsf *sf, ffaio_handler handler, void *udata);
static void lsn_ssl_shut(void *udata);


static const ffpars_arg lsnm_conf_args[] = {
	{ "log",  FFPARS_TOBJ | FFPARS_FOBJ1,  FFPARS_DST(&lsnm_conf_log) }
	, { "max_clients",  FFPARS_TINT | FFPARS_FNOTZERO,  FFPARS_DSTOFF(lisnmod, max_cons) }
};

static const ffpars_arg lsnx_conf_args[] = {
	{ "listen",  FFPARS_TSTR | FFPARS_FREQUIRED,  FFPARS_DST(&lsnx_conf_listen) }
	, { "log",  FFPARS_TOBJ,  FFPARS_DST(&lsnx_conf_log) }
	, { "max_clients",  FFPARS_TINT | FFPARS_FNOTZERO,  FFPARS_DSTOFF(lisnctx, max_cons) }
	, { "backlog",  FFPARS_TINT,  FFPARS_DSTOFF(lisnctx, backlog) }
	, { "linger_timeout",  FFPARS_TINT | FFPARS_F16BIT,  FFPARS_DSTOFF(lisnctx, tmout_linger) }
	, { "tcp_defer_accept",  FFPARS_TBOOL | FFPARS_F8BIT,  FFPARS_DSTOFF(lisnctx, defer_accept) }
	, { "ssl",  FFPARS_TSTR,  FFPARS_DST(&lsnx_conf_ssl) }
};

static int lsnm_conf_log(ffparser_schem *ps, lisnmod *lm, ffpars_ctx *a)
{
	const ffstr *name = &ps->vals[0];
	const fsv_log *log_iface;
	const fsv_modinfo *m = lsnm->core->findmod(name->ptr, name->len);
	if (m == NULL)
		return FFPARS_EBADVAL;

	log_iface = m->f->iface("log");
	if (log_iface == NULL)
		return FFPARS_EBADVAL;

	lsnm->logctx = log_iface->newctx(a, lsnm->logctx);
	if (lsnm->logctx == NULL)
		return FFPARS_EINTL;

	return 0;
}

static int lsnx_conf_log(ffparser_schem *ps, lisnctx *lx, ffpars_ctx *a)
{
	lx->logctx = fsv_logctx_get(lsnm->logctx)->mlog->newctx(a, lsnm->logctx);
	if (lx->logctx == NULL)
		return FFPARS_EINTL;
	return 0;
}

/* "127.0.0.1:80", "[::1]:80", ":80". */
static int lsnx_conf_listen(ffparser_schem *ps, lisnctx *lx, const ffstr *s)
{
	ffstr ip, port;
	if (0 != ffip_split(s->ptr, s->len, &ip, &port))
		return FFPARS_EBADVAL;

	if (ip.len == 0)
		lx->ip6dual = 1;

	if (0 != ffaddr_set(&lx->addr, ip.ptr, ip.len, port.ptr, port.len))
		return FFPARS_EBADVAL;

	if (NULL == ffstr_dup(&lx->saddr, s->ptr, s->len))
		return FFPARS_ESYS;
	lx->saddr_portlen = (byte)port.len;

	return 0;
}

static int lsnx_conf_ssl(ffparser_schem *ps, lisnctx *lx, const ffstr *s)
{
	const fsv_modinfo *m;

	m = lsnm->core->findmod(s->ptr, s->len);
	if (m == NULL)
		return FFPARS_EBADVAL;

	lx->modssl = m->f->iface("ssl");
	if (lx->modssl == NULL)
		return FFPARS_EBADVAL;
	return 0;
}


static void * lsnm_create(const fsv_core *core, ffpars_ctx *a, fsv_modinfo *m)
{
	const fsvcore_config *conf = core->conf();

	lsnm = ffmem_tcalloc1(lisnmod);
	if (lsnm == NULL)
		return NULL;

	fflist_init(&lsnm->ctxs);
	fflist_init(&lsnm->cons);
	lsnm->max_cons = 10000;
	lsnm->core = core;
	lsnm->logctx = conf->logctx;

	ffpars_setargs(a, lsnm, lsnm_conf_args, FFCNT(lsnm_conf_args));
	return lsnm;
}

static void lsn_fincon(fsv_lsncon *c)
{
	ffstr_free(&c->saddr_local);
	ffstr_free(&c->saddr_peer);
	ffmem_free(c);
}

static void lsnx_fin(lisnctx *lx)
{
	if (lx->acc_init)
		ffaio_acceptfin(&lx->acc);
	FF_SAFECLOSE(lx->lsk, FF_BADSKT, ffskt_close);
	ffstr_free(&lx->saddr);
	ffmem_free(lx);
}

static void lsnm_destroy(void)
{
	FFLIST_ENUMSAFE(&lsnm->ctxs, lsnx_fin, lisnctx, sib);

	fsv_lsncon *c;
	while (NULL != (c = (void*)fflist1_pop(&lsnm->recycled_cons))) {
		lsn_fincon(FF_GETPTR(fsv_lsncon, recycled, c));
	}

	ffmem_free(lsnm);
	lsnm = NULL;
}

static int lsnm_sig(int signo)
{
	switch (signo) {
	case FSVCORE_SIGSTART:
		return lsnm_start();

	case FSVCORE_SIGSTOP:
		return lsnm_stop();
	}

	return 0;
}

static const void * lsnm_iface(const char *name)
{
	if (0 == ffsz_cmp(name, "listen"))
		return &fsv_lsn_iface;
	else if (0 == ffsz_cmp(name, "json-status"))
		return &lisn_stat_iface;
	return NULL;
}

/** Create socket and start listening. */
static int lsnx_start(lisnctx *lx)
{
	int er = 0;

	lx->lsk = ffskt_create(ffaddr_family(&lx->addr), SOCK_STREAM | SOCK_NONBLOCK, IPPROTO_TCP);
	if (lx->lsk == FF_BADSKT) {
		er = FFERR_SKTCREAT;
		goto fail;
	}

	if (lx->ip6dual
		&& 0 != ffskt_setopt(lx->lsk, IPPROTO_IPV6, IPV6_V6ONLY, 0)) {
		er = FFERR_SKTOPT;
		goto fail;
	}

	if (0 != ffskt_bind(lx->lsk, &lx->addr.a, lx->addr.len)) {
		er = FFERR_SKTBIND;
		goto fail;
	}

	if (0 != ffskt_listen(lx->lsk, lx->backlog)) {
		er = FFERR_SKTLISTEN;
		goto fail;
	}

	if (lx->defer_accept
		&& 0 != ffskt_deferaccept(lx->lsk, 1))
		lx_syserrlog(lx, FSV_LOG_WARN, "%e: defer accept", FFERR_SKTOPT);

	if (0 != ffaio_acceptinit(&lx->acc, lsnm->kq, lx->lsk, lx, ffaddr_family(&lx->addr), SOCK_STREAM)) {
		er = FFERR_KQUATT;
		goto fail;
	}
	lx->acc_init = 1;

	lx_dbglog(lx, FSV_LOG_DBGFLOW, "started listener, socket %L", (size_t)lx->lsk);
	fsv_taskpost(lsnm->core, &lx->task_accept, &lsn_onaccept, lx);
	return 0;

fail:
	lx_syserrlog(lx, FSV_LOG_ERR, "starting listener: %e", er);
	return 1;
}

static int lsnm_start(void)
{
	lisnctx *lx;
	lsnm->kq = lsnm->core->conf()->queue;

	_FFLIST_WALK(&lsnm->ctxs, lx, sib) {
		if (0 != lsnx_start(lx))
			return 1;
	}

	return 0;
}

/** Close the listening sockets.
UNIX: if a connection is still active, then a higher level module has a memory leak.
Windows: a connection may be still active while we're waiting for asynchronous cancel callback. */
static int lsnm_stop(void)
{
	lisnctx *lx;
	fflist_item *next;
	fsv_lsncon *c;

	lsnm->core->fsv_timerstop(&lsnm->queued_cons_timer);

	_FFLIST_WALK(&lsnm->ctxs, lx, sib) {
		lx_dbglog(lx, FSV_LOG_DBGFLOW, "stopping listener");
		FF_SAFECLOSE(lx->lsk, FF_BADSKT, ffskt_close);
	}

	FFLIST_WALKSAFE(&lsnm->cons, c, sib, next) {

#ifdef FF_WIN
		if (!ffaio_active(&c->aiotask))
#endif
			lx_errlog(c->lx, FSV_LOG_ERR, "module stop: connection with %S is still active"
				, &c->saddr_peer);

		c->aiotask.whandler = c->aiotask.rhandler = NULL;
		lsn_closecon(c, 0);
	}

	FF_ASSERT(lsnm->cons.len == 0);
	return 0;
}

static const int lsn_status_jsonmeta[] = {
	FFJSON_TOBJ
	, FFJSON_FKEYNAME, FFJSON_TSTR
	, FFJSON_FKEYNAME, FFJSON_FINTVAL
	, FFJSON_FKEYNAME, FFJSON_FINTVAL
	, FFJSON_TOBJ
};

static void lisn_status(const fsv_status *statusmod)
{
	lisnctx *lx;
	ffjson_cook status_json;
	char buf[4096];
	ffjson_cookinit(&status_json, buf, sizeof(buf));

	_FFLIST_WALK(&lsnm->ctxs, lx, sib) {
		ffjson_addv(&status_json, lsn_status_jsonmeta, FFCNT(lsn_status_jsonmeta)
			, FFJSON_CTXOPEN
			, "listener", &lx->saddr
			, "connected", (int64)lx->connected
			, "max-connected", (int64)lx->max_connected
			, FFJSON_CTXCLOSE
			, NULL);
	}

	statusmod->setdata(status_json.buf.ptr, status_json.buf.len, 0);
	ffjson_cookfin(&status_json);
}


static fsv_lsnctx * lsn_newctx(ffpars_ctx *a, const fsv_listen_cb *cb, void *userctx)
{
	lisnctx *lx = ffmem_tcalloc1(lisnctx);
	if (lx == NULL)
		return NULL;
	fflist_ins(&lsnm->ctxs, &lx->sib);

	ffaddr_init(&lx->addr);
	lx->max_cons = lsnm->max_cons;
	lx->backlog = SOMAXCONN;
	lx->logctx = lsnm->logctx;
	lx->tmout_linger = 30;
	lx->cb = cb;
	lx->userctx = userctx;

#ifdef FF_LINUX
	lx->defer_accept = 1;
#endif

	ffpars_setargs(a, lx, lsnx_conf_args, FFCNT(lsnx_conf_args));
	return (fsv_lsnctx*)lx;
}

static fsv_lsnctx * lsn_findctx(const char *name, size_t len)
{
	lisnctx *lx;
	_FFLIST_WALK(&lsnm->ctxs, lx, sib) {
		if (ffstr_eq(&lx->saddr, name, len))
			return (fsv_lsnctx*)lx;
	}
	return NULL;
}

/** Read and discard data. */
static void lsn_linger(void *udata)
{
	fsv_lsncon *c = udata;
	char buf[4096];
	ssize_t r;

	for (;;) {
		r = ffaio_recv(&c->aiotask, &lsn_linger, buf, sizeof(buf));
		if (r == FFAIO_ASYNC) {
			c->aiotask.udata = c;
			return;
		} else if (r == 0 || r == -1) {
			lsn_closecon(c, 0);
			return;
		}
	}
}

static void lsn_onexpire(void *param)
{
	fsv_lsncon *c = param;
	lx_dbglog(c->lx, FSV_LOG_DBGNET, "%S: timer expired", &c->saddr_peer);
	ffaio_cancelasync(&c->aiotask, FFAIO_RW, NULL);
}

static void lsn_oncancel(void *udata)
{
	lsn_closecon(udata, 0);
}

/** Close connection. */
static void lsn_closecon(fsv_lsncon *c, int flags)
{
	lisnctx *lx = c->lx;

	if (c->userptr != NULL) {
		c->userptr = NULL;
		lsn_setopt(c, FSV_LISN_OPT_LOG, lx->logctx);
	}

	if (FSV_IO_ASYNC == lsn_cancel(c, FFAIO_RW, &lsn_oncancel, c))
		return; //wait until async operations on both channels are completed

	if (flags & FSV_LISN_LINGER) {

		if (lx->modssl != NULL) {
			lsn_resettimer(c, lx->tmout_linger);
			lsn_ssl_shut(c);
			return;
		}

		if (0 == ffskt_fin(c->sk)) {
			lx_dbglog(lx, FSV_LOG_DBGNET, "%S: linger", &c->saddr_peer);
			lsn_resettimer(c, lx->tmout_linger);
			lsn_linger(c);
			return;
		}

		lx_syserrlog(lx, FSV_LOG_WARN, "%S: %e", &c->saddr_peer, FFERR_SKTSHUT);
	}

	lx->connected--;
	lx_dbglog(lx, FSV_LOG_DBGNET, "closing connection with %S, socket %L  [%u]"
		, &c->saddr_peer, (ssize_t)c->sk, lx->connected);
	fflist_rm(&lsnm->cons, &c->sib);
	lsnm->core->fsv_timerstop(&c->tmr);

	if (c->sslcon != NULL) {
		lx->modssl->fin(c->sslcon);
		c->sslcon = NULL;
	}

	lsn_recycle(c);

	if (lx->queued) {
		lx->queued = 0;
		fsv_taskpost(lsnm->core, &lx->task_accept, &lsn_onaccept, lx);
	}
}

/** Get recycled connection or allocate new. */
static fsv_lsncon * lsn_getconn(lisnctx *lx)
{
	fsv_lsncon *c;

	if (lx->connected == lx->max_cons) {
		lx_errlog(lx, FSV_LOG_ERR, "reached max_clients limit");
		return NULL;
	}

	if (NULL != (c = (void*)fflist1_pop(&lsnm->recycled_cons))) {
		return FF_GETPTR(fsv_lsncon, recycled, c);
	}

	if (lsnm->cons.len == lsnm->max_cons) {
		lx_errlog(lx, FSV_LOG_ERR, "reached total max_clients limit");
		return NULL;
	}

	c = ffmem_tcalloc1(fsv_lsncon);
	if (c == NULL) {
		lx_syserrlog(lx, FSV_LOG_ERR, "%e", FFERR_BUFALOC);
		return NULL;
	}

	return c;
}

static void lsn_resettimer(fsv_lsncon *c, uint t)
{
	lsnm->core->timer(&c->tmr, -(int64)t * 1000, &lsn_onexpire, c);
}

/** Convert address into string. */
static int lsn_addrstr(fsv_lsncon *c, ffaddr *a, ffstr *dst, int flags)
{
	char sa[FF_MAXIP6];
	size_t salen;

	if (ffaddr_family(a) == AF_INET6 && ffip6_isv4mapped(a))
		ffip_v4mapped_tov4(a);

	salen = ffaddr_tostr(a, sa, FFCNT(sa), flags);

	//perform allocation only if the buffer is not large enough
	if (salen > dst->len) {
		char *p = ffmem_realloc(dst->ptr, salen);
		if (p == NULL)
			return 1;
		dst->ptr = p;
	}

	ffmemcpy(dst->ptr, sa, salen);
	dst->len = salen;
	return 0;
}

/** Put connection in cache. */
static void lsn_recycle(fsv_lsncon *c)
{
	FF_SAFECLOSE(c->sk, FF_BADSKT, ffskt_close);
	ffaio_fin(&c->aiotask);
	c->lx = NULL;
	fflist1_push(&lsnm->recycled_cons, &c->recycled);
}

/** Notify parent module. */
static void lsn_callmod(fsv_lsncon *c)
{
	c->lx->cb->onaccept(c->lx->userctx, c);
}

/** Process queued inbound connections. */
static void lsnm_process_queued_cons(void *param)
{
	lisnctx *lx;
	_FFLIST_WALK(&lsnm->ctxs, lx, sib) {
		if (lx->queued) {
			lx->queued = 0;
			lsn_onaccept(lx);
		}
	}
}

static void lsn_onaccept(void *udata)
{
	lisnctx *lx = udata;
	for (;;) {
		if (0 != lsn_accept1(lx))
			return;
	}
}

/** Accept one connection. */
static int lsn_accept1(lisnctx *lx)
{
	ffaddr local, peer;
	fsv_lsncon *c;

	c = lsn_getconn(lx);
	if (c == NULL) {
		lx->queued = 1;
		if (lsnm->cons.len != lsnm->max_cons)
			lsnm->core->timer(&lsnm->queued_cons_timer, -NOMEM_TIMER_INTERVAL, &lsnm_process_queued_cons, NULL);
		return 1;
	}

	c->sk = ffaio_accept(&lx->acc, &local, &peer, SOCK_NONBLOCK, &lsn_onaccept);
	if (c->sk == FF_BADSKT) {
		int er = fferr_last();
		lsn_recycle(c);

		if (fferr_fdlim(er)) {
			if (!lsnm->fd_limit) {
				lsnm->fd_limit = 1;
				fsv_errlog(lsnm->logctx, FSV_LOG_ERR, LSN_MODNAME, NULL, "accept: %E", er);
			}

			lx->queued = 1;
			lsnm->core->timer(&lsnm->queued_cons_timer, -FDLIM_TIMER_INTERVAL, &lsnm_process_queued_cons, NULL);
			return 1;
		}

		if (fferr_again(er)) {
			return 1;
		}

		lx_errlog(lx, FSV_LOG_WARN, "%E", er);
		return 0;
	}

	if (lsnm->fd_limit)
		lsnm->fd_limit = 0;

	ffaio_init(&c->aiotask);
	c->aiotask.sk = c->sk;
	c->lx = lx;

	if (0 != lsn_addrstr(c, &local, &c->saddr_local, 0)
		|| 0 != lsn_addrstr(c, &peer, &c->saddr_peer, FFADDR_USEPORT)) {
		lx_syserrlog(lx, FSV_LOG_ERR, "accept: %e", FFERR_BUFALOC);
		lsn_recycle(c);
		lx->queued = 1;
		lsnm->core->timer(&lsnm->queued_cons_timer, -NOMEM_TIMER_INTERVAL, &lsnm_process_queued_cons, NULL);
		return 1;
	}

	if (0 != ffaio_attach(&c->aiotask, lsnm->kq, FFKQU_READ | FFKQU_WRITE)) {
		lx_syserrlog(c->lx, FSV_LOG_ERR, "%S: %e", &c->saddr_peer, FFERR_KQUATT);
		lsn_recycle(c);
		return 0;
	}

	fflist_ins(&lsnm->cons, &c->sib);
	lx->connected++;
	if (lx->connected > lx->max_connected)
		lx->max_connected = lx->connected;

	lx_dbglog(c->lx, FSV_LOG_DBGNET, "accepted connection from %S, socket %L  [%u]"
		, &c->saddr_peer, (size_t)c->sk, lx->connected);

	if (lx->modssl != NULL) {
		lsn_ssl_finaccept(c);
		return 0;
	}

	lsn_callmod(c);
	return 0;
}

static ssize_t lsn_recv(fsv_lsncon *c, void *buf, size_t size, ffaio_handler handler, void *udata)
{
	if (c->aiotask.ev == NULL && c->aiotask.rpending) {
		/* mod http relies on this behaviour: async recv operation is still active,
		but despite this another call to recv() is made, because mod http doesn't keep track of active operations. */
		c->aiotask.rhandler = handler;
		c->aiotask.udata = udata;
		return FSV_IO_ASYNC;
	}

	if (buf == (void*)-1 && size == 0) {
		ssize_t r = ffaio_recv(&c->aiotask, handler, NULL, 0);
		if (r == FFAIO_ASYNC) {
			c->aiotask.udata = udata;
			return FSV_IO_ASYNC;
		} else if (r == FFAIO_ERROR)
			return FSV_IO_ERR;

#ifdef FF_WIN
		// data is available on the socket
		return 0;
#endif

		//socket HUP watch for UNIX
		c->aiotask.rhandler = handler;
		c->aiotask.udata = udata;
		c->aiotask.rpending = 1;
		return FSV_IO_ASYNC;
	}

	if (c->lx->modssl != NULL)
		return lsn_ssl_recv(c, buf, size, handler, udata);

	ssize_t r = ffaio_recv(&c->aiotask, handler, buf, size);
	if (r == FFAIO_ASYNC) {
		c->aiotask.udata = udata;
		return FSV_IO_ASYNC;
	}

	return r;
}

static ssize_t lsn_send(fsv_lsncon *c, const void *buf, size_t len, ffaio_handler handler, void *udata)
{
	ffsf sf;
	ffiovec iov;
	ffiov_set(&iov, buf, len);
	ffsf_init(&sf);
	ffsf_sethdtr(&sf.ht, &iov, 1, NULL, 0);
	return lsn_sendfile(c, &sf, handler, udata);
}

static ssize_t lsn_sendfile(fsv_lsncon *c, ffsf *sf, ffaio_handler handler, void *udata)
{
	if (c->lx->modssl != NULL)
		return lsn_ssl_sendfile(c, sf, handler, udata);

	ssize_t r = ffsf_sendasync(sf, &c->aiotask, handler);
	if (r == FFAIO_ASYNC) {
		c->aiotask.udata = udata;
		return FSV_IO_ASYNC;
	}

	return r;
}

static int lsn_cancel(fsv_lsncon *c, int op, ffaio_handler handler, void *udata)
{
	if (ffaio_active(&c->aiotask)) {
		c->aiotask.udata = udata;
		ffaio_cancelasync(&c->aiotask, op, handler);
		return FSV_IO_ASYNC;
	}

	return FSV_IO_ERR;
}

static int lsn_setopt(fsv_lsncon *c, int opt, void *data)
{
	switch (opt) {
	case FSV_LISN_OPT_USERPTR:
		c->userptr = data;
		break;

	case FSV_LISN_OPT_LOG:
		c->logctx = data;

		if (c->sslcon != NULL)
			c->lx->modssl->setopt(c->sslcon, FSV_SSL_OPT_LOG, c->logctx);
		break;

	case FSV_LISN_OPT_SSLCTX:
		if (c->ssl_init) {
			c->ssl_init = 0;
			lsn_ssl_newcon(c, data);
			break;
		}

		if (0 != c->lx->modssl->setopt(c->sslcon, FSV_SSL_OPT_SSLCTX, data))
			lsn_closecon(c, 0);
		break;

	default:
		return 1;
	}

	return 0;
}

static const ffstr lsn_vars[] = {
	FFSTR_INIT("context_ptr") //void*
	, FFSTR_INIT("socket_fd") //ffskt

	//char*:
	, FFSTR_INIT("server_addr")
	, FFSTR_INIT("server_port")
	, FFSTR_INIT("remote_addr")
	, FFSTR_INIT("client_id") //peer_addr:peer_port
};
enum {
	VAR_CONTEXT_PTR
	, VAR_SOCKET_FD

	, VAR_SERVER_ADDR
	, VAR_SERVER_PORT
	, VAR_REMOTE_ADDR
	, VAR_CLIENT_ID
};

static ssize_t lsn_getvar(fsv_lsncon *c, const char *name, size_t namelen, void *dst, size_t cap)
{
	void *p = NULL;
	size_t n = 0;
	ssize_t v = ffstr_findarr(lsn_vars, FFCNT(lsn_vars), name, namelen);
	if (v == -1) {
		if (c->lx->modssl != NULL) {
			n = c->lx->modssl->getvar(c->sslcon, name, namelen, dst, cap);
			if (n != -1)
				return n;
		}

		return lsnm->core->getvar(name, namelen, dst, cap);
	}

	switch (v) {

	case VAR_CONTEXT_PTR:
		if (cap != sizeof(void*))
			return -1;
		*(void**)dst = c->lx;
		return sizeof(void*);

	case VAR_SOCKET_FD:
		if (cap != sizeof(ffskt))
			return -1;
		*(ffskt*)dst = c->sk;
		return sizeof(ffskt);

	case VAR_SERVER_ADDR:
		p = c->saddr_local.ptr;
		n = c->saddr_local.len;
		break;

	case VAR_SERVER_PORT:
		p = c->lx->saddr.ptr + c->lx->saddr.len - c->lx->saddr_portlen;
		n = c->lx->saddr_portlen;
		break;

	case VAR_REMOTE_ADDR: {
		const char *colon = ffs_rfind(c->saddr_peer.ptr, c->saddr_peer.len, ':');
		p = c->saddr_peer.ptr;
		n = colon - c->saddr_peer.ptr;
		break;
		}

	case VAR_CLIENT_ID:
		p = c->saddr_peer.ptr;
		n = c->saddr_peer.len;
		break;
	}

	*(char**)dst = p;
	return n;
}


static void lsn_ssl_newcon(fsv_lsncon *c, void *sslctx)
{
	fsv_ssl_newcon opts = {0};
	opts.srvname_cb = &lsn_ssl_srvname;
	opts.srvname_param = c;
	opts.logctx = c->logctx;
	c->sslcon = c->lx->modssl->newcon(sslctx, &opts, FSV_SSL_ACCEPT);
	if (c->sslcon == NULL) {
		lsn_closecon(c, 0);
		return;
	}

	lsn_ssl_handshake(c);
}

static void lsn_ssl_finaccept(fsv_lsncon *c)
{
	c->ssl_init = 1;
	if (0 != c->lx->cb->onsig(c, NULL, FSV_LISN_SSL_INIT)) {
		lsn_closecon(c, 0);
		return;
	}
}

static int lsn_ssl_srvname(void *udata)
{
	fsv_lsncon *c = udata;
	return c->lx->cb->onsig(c, NULL, FSV_LISN_SSL_SNI);
}

static void lsn_ssl_handshake(void *udata)
{
	fsv_lsncon *c = udata;
	int r;
	void *sslbuf_ptr;
	ssize_t sslbuf_len = -1;

	lsnm->core->fsv_timerstop(&c->tmr);

	for (;;) {
		r = c->lx->modssl->handshake(c->sslcon, &sslbuf_ptr, &sslbuf_len);
		switch (r) {
		case FSV_SSL_WANTREAD:
			r = ffaio_recv(&c->aiotask, &lsn_ssl_handshake, sslbuf_ptr, sslbuf_len);
			if (r == FFAIO_ASYNC) {
				c->aiotask.udata = udata;
				lsn_resettimer(c, LISN_SSL_RECV_TM);
				return;
			}
			break;

		case FSV_SSL_WANTWRITE:
			r = ffaio_send(&c->aiotask, &lsn_ssl_handshake, sslbuf_ptr, sslbuf_len);
			if (r == FFAIO_ASYNC) {
				c->aiotask.udata = udata;
				lsn_resettimer(c, LISN_SSL_SEND_TM);
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
	//handshake done
	lsn_callmod(c);
	return;

fail:
	lx_syserrlog(c->lx, FSV_LOG_ERR, "%s", "SSL handshake");
	lsn_closecon(c, 0);
}

static ssize_t lsn_ssl_recv(fsv_lsncon *c, void *buf, size_t size, ffaio_handler handler, void *udata)
{
	void *sslbuf_ptr;
	ssize_t r, sslbuf_len = -1;

	for (;;) {
		r = c->lx->modssl->recv(c->sslcon, buf, size, &sslbuf_ptr, &sslbuf_len);
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

static ssize_t lsn_ssl_sendfile(fsv_lsncon *c, ffsf *sf, ffaio_handler handler, void *udata)
{
	void *sslbuf_ptr;
	ssize_t r, sslbuf_len = -1;

	for (;;) {
		r = c->lx->modssl->sendfile(c->sslcon, sf, &sslbuf_ptr, &sslbuf_len);
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

static void lsn_ssl_shut(void *udata)
{
	fsv_lsncon *c = udata;
	int er = 0;
	void *sslbuf_ptr;
	ssize_t r, sslbuf_len = -1;

	for (;;) {
		r = c->lx->modssl->shut(c->sslcon, &sslbuf_ptr, &sslbuf_len);
		switch (r) {
		case FSV_SSL_WANTREAD:
			r = ffaio_recv(&c->aiotask, &lsn_ssl_shut, sslbuf_ptr, sslbuf_len);
			if (r == FFAIO_ASYNC) {
				c->aiotask.udata = c;
				return;
			} else if (r == -1) {
				er = FFERR_READ;
				goto err;
			}
			break;

		case FSV_SSL_WANTWRITE:
			r = ffaio_send(&c->aiotask, &lsn_ssl_shut, sslbuf_ptr, sslbuf_len);
			if (r == FFAIO_ASYNC) {
				c->aiotask.udata = c;
				return;
			} else if (r == -1) {
				er = FFERR_WRITE;
				goto err;
			}
			break;

		case FSV_SSL_ERR:
			//error is reported by mod-ssl
			goto done;

		default:
			goto done;
		}

		sslbuf_len = r;
	}
	//unreachable

err:
	lx_syserrlog(c->lx, FSV_LOG_ERR, "shutdown SSL connection with %S: %e", &c->saddr_peer, er);

done:
	lsn_closecon(c, 0);
}

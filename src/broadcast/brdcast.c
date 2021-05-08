/**
Copyright 2014 Simon Zolin.
*/

/*
                iovec[]      iovec[]            data[]
(client) <- http <- broadcast <- icy-client <- http-proxy <- (remote media server)
                                           \-> mp3-store -> (filesystem)

                            iovec[] data[]
(client) <- http <- broadcast <- icy-mp3 <- (filesystem)
*/

#include <broadcast/brdcast.h>

#include <FF/time.h>
#include <FF/data/json.h>
#include <FFOS/error.h>


bcastmodule *bcastm;

typedef struct bcast_client {
	bcastctx *bx;

	const fsv_http *Htp;
	fsv_httpcon *httpcon;
	fsv_httpfilter *hf;
	fsv_logctx *logctx;
	ffhttp_cook *cook;

	fflist_item sib;
	fflist_item sib_bufUsg;

	ffiovec iovs[5]; //meta + buffer
	uint niovs;
	int metaInt; //-1 = no meta. otherwise = the bytes until next meta (0 = meta must be sent now)
	uint lastMetaChange;

	ffiovec buf;
	int ibuf;
	unsigned usingbuf :1
		, metasent :1
		, inited :1
		, hdrsSent :1
		;
} bcast_client;


// FSERV MODULE
static void * bcastm_create(const fsv_core *core, ffpars_ctx *c, fsv_modinfo *mi);
static void bcastm_destroy(void);
static int bcastm_start(void);
static void bcastm_stop(void);
static int bcastm_sig(int signo);
static const void * bcastm_iface(const char *name);
static const fsv_mod bcastm_funcs = {
	&bcastm_create, &bcastm_destroy, &bcastm_sig, &bcastm_iface
};

// STATUS
static void bcastm_status(const fsv_status *statusmod);
static const fsv_status_handler bcastm_stat_iface = {
	&bcastm_status
};

// HTTP CTX
static int bcast_newctx(fsv_http_hdlctx *hc);
static const fsv_httphandler_iface bcast_htpf = {
	&bcast_newctx
};

// HTTP HANDLER
static void bcast_onsending(fsv_httphandler *h);
static void bcast_ondone(fsv_httphandler *h);
static const fsv_http_cb bcast_htph = {
	&bcast_onsending, &bcast_ondone
};

// CONFIG
static int bcastx_conf_log(ffparser_schem *ps, bcastctx *bx, ffpars_ctx *confctx);
static int bcast_conf_log(ffparser_schem *ps, bcastmodule *t, ffpars_ctx *confctx);
static int bcast_conf_provider(ffparser_schem *ps, bcastctx *bx, ffpars_ctx *confctx);

// LOG
static int bcast_logadd(fsv_logctx *lx, int lev, const char *modname, const ffstr *trid, const char *fmt, ...);
static int bcast_logaddv(fsv_logctx *lx, int lev, const char *modname, const ffstr *trid, const char *fmt, va_list va);
static const fsv_log bcast_log = {
	NULL, &bcast_logadd, &bcast_logaddv
};

static void bcastx_start(bcastctx *bx);
static void bcastx_starttimer(void *param);
static void bcastx_stoptimer(void *param);
static void bcast_statustimer(void *param);
static void bcastx_free(bcastctx *bx);
static void bcast_played(void *param);
static void bcast_clearBuf(bcastctx *bx, uint i);
static void bcast_resumeClients(bcastctx *bx);

static void bcast_sendNext(bcast_client *c);
static bcast_client* bcast_newclient(fsv_httphandler *h);
static int bcast_initclient(bcast_client *c);
static void bcast_decusg(bcast_client *c);


FF_EXTN FF_EXP const fsv_mod * fsv_getmod(const char *name)
{
	ffmem_init();
	if (!ffsz_cmp(name, "icy"))
		return &bcastm_funcs;
	return NULL;
}


static const ffpars_arg mod_args[] = {
	{ "log",  FFPARS_TOBJ | FFPARS_FOBJ1,  FFPARS_DST(&bcast_conf_log) }
};

static const ffpars_arg ctx_args[] = {
	{ "log",  FFPARS_TOBJ,  FFPARS_DST(&bcastx_conf_log) }
	, { "name",  FFPARS_TSTR | FFPARS_FCOPY,  FFPARS_DSTOFF(bcastctx, name) }
	, { "genre",  FFPARS_TSTR | FFPARS_FCOPY,  FFPARS_DSTOFF(bcastctx, genre) }
	, { "url",  FFPARS_TSTR | FFPARS_FCOPY,  FFPARS_DSTOFF(bcastctx, url) }
	, { "buffer_size",  FFPARS_TSIZE,  FFPARS_DSTOFF(bcastctx, buf_size_conf) }
	, { "buffer_ms",  FFPARS_TINT | FFPARS_F16BIT,  FFPARS_DSTOFF(bcastctx, buf_ms) }
	, { "always_on",  FFPARS_TBOOL | FFPARS_F8BIT,  FFPARS_DSTOFF(bcastctx, always_on) }
	, { "stop_delay",  FFPARS_TINT | FFPARS_F16BIT,  FFPARS_DSTOFF(bcastctx, stop_delay) }
	, { "reconnect_timeout",  FFPARS_TINT | FFPARS_F16BIT,  FFPARS_DSTOFF(bcastctx, reconnect_timeout) }

	, { "icy_meta_int",  FFPARS_TSIZE,  FFPARS_DSTOFF(bcastctx, icy_meta_int) }
	, { "provider",  FFPARS_TOBJ | FFPARS_FOBJ1 | FFPARS_FREQUIRED,  FFPARS_DST(bcast_conf_provider) }
};


static int bcast_conf_log(ffparser_schem *ps, bcastmodule *t, ffpars_ctx *confctx)
{
	const fsv_log *log_iface;
	const ffstr *modname = &ps->vals[0];
	const fsv_modinfo *mi = bcastm->core->findmod(modname->ptr, modname->len);
	if (mi == NULL)
		return FFPARS_EBADVAL;

	log_iface = mi->f->iface("log");
	if (log_iface == NULL)
		return FFPARS_EBADVAL;

	bcastm->logctx = log_iface->newctx(confctx, bcastm->logctx);
	if (bcastm->logctx == NULL)
		return FFPARS_EBADVAL;

	return 0;
}

static int bcastx_conf_log(ffparser_schem *ps, bcastctx *bx, ffpars_ctx *confctx)
{
	bx->logctx = fsv_logctx_get(bcastm->logctx)->mlog->newctx(confctx, bx->logctx);
	if (bx->logctx == NULL)
		return FFPARS_EBADVAL;
	return 0;
}

static int bcast_conf_provider(ffparser_schem *ps, bcastctx *bx, ffpars_ctx *confctx)
{
	const ffstr *modname = &ps->vals[0];
	if (ffstr_eqcz(modname, "broadcast.icy-mp3"))
		return icy3_conf_init(bx, confctx);

	else if (ffstr_eqcz(modname, "broadcast.icy-client"))
		return icyx_conf_init(bx, confctx);

	else
		return FFPARS_EBADVAL;
	return 0;
}


static void * bcastm_create(const fsv_core *core, ffpars_ctx *c, fsv_modinfo *mi)
{
	bcastm = ffmem_tcalloc1(bcastmodule);
	if (bcastm == NULL)
		return NULL;

	fflist_init(&bcastm->ctxs);
	bcastm->core = core;
	bcastm->pagesize = core->conf()->pagesize;
	bcastm->logctx = core->conf()->logctx;

	ffpars_setargs(c, bcastm, mod_args, FFCNT(mod_args));
	return bcastm;
}

static void bcastm_destroy(void)
{
	FFLIST_ENUMSAFE(&bcastm->ctxs, bcastx_free, bcastctx, sib);
	ffmem_free(bcastm);
	bcastm = NULL;
}

static int bcastm_start(void)
{
	bcastctx *bx;

	bcastm->core->timer(&bcastm->status_tmr, 1000, &bcast_statustimer, NULL);

	_FFLIST_WALK(&bcastm->ctxs, bx, sib) {
		if (bx->always_on)
			bcastx_start(bx);
	}
	return 0;
}

static void bcastm_stop(void)
{
	bcastctx *bx;

	_FFLIST_WALK(&bcastm->ctxs, bx, sib) {
		bx->iface->stop(bx->prov);
	}
}

static int bcastm_sig(int signo)
{
	switch (signo) {
	case FSVCORE_SIGSTART:
		return bcastm_start();

	case FSVCORE_SIGSTOP:
		bcastm_stop();
		break;
	}

	return 0;
}

static const int bcast_json[] = {
	FFJSON_TOBJ
	, FFJSON_FKEYNAME, FFJSON_TSTR
	, FFJSON_FKEYNAME, FFJSON_FINTVAL
	, FFJSON_FKEYNAME, FFJSON_FINTVAL | FFJSON_F32BIT
	, FFJSON_FKEYNAME, FFJSON_FINTVAL
	, FFJSON_FKEYNAME, FFJSON_TSTR
	, FFJSON_FKEYNAME, FFJSON_TSTR
	, FFJSON_TOBJ
};

static const ffstr statuses[] = {
	FFSTR_INIT("stopped")
	, FFSTR_INIT("starting...")
	, FFSTR_INIT("buffering...")
	, FFSTR_INIT("ready")
};

static void bcastm_status(const fsv_status *statusmod)
{
	char duration[FFINT_MAXCHARS + FFSLEN(":00")];
	bcastctx *bx;
	ffstr title;
	ffstr sduration;
	ffjson_cook status_json;
	ffjson_cookinit(&status_json, NULL, 0);

	_FFLIST_WALK(&bcastm->ctxs, bx, sib) {

		sduration.len = 0;
		if (bx->status == ST_READY && bx->lastMetaChange != 0) {
			uint secs = bcast_now().sec - bx->lastMetaChange;
			ssize_t r = ffs_fmt(duration, duration + sizeof(duration) - 1, "%02u:%02u"
				, (int)secs / 60, (int)secs % 60);
			ffstr_set(&sduration, duration, r);
			title = bx->title;
		}
		else
			title = statuses[bx->status];

		ffjson_bufaddv(&status_json, bcast_json, FFCNT(bcast_json)
			, FFJSON_CTXOPEN
			, "name", &bx->name
			, "listeners", (int64)bx->nclients
			, "bitrate", (int)mm_tokbps(bx->byterate)
			, "output/sec", (int64)bx->outputBPS
			, "time", &sduration
			, "playing", &title
			, FFJSON_CTXCLOSE
			, NULL);
	}

	statusmod->setdata(status_json.buf.ptr, status_json.buf.len, 0);
	ffjson_cookfinbuf(&status_json);
}

static const void * bcastm_iface(const char *name)
{
	if (!ffsz_cmp(name, "http-handler"))
		return &bcast_htpf;
	else if (!ffsz_cmp(name, "json-status"))
		return &bcastm_stat_iface;
	return NULL;
}

static int bcast_newctx(fsv_http_hdlctx *hc)
{
	uint i;
	bcastctx *bx = ffmem_tcalloc1(bcastctx);
	if (bx == NULL)
		return 1;

	bx->logctx = bcastm->logctx;
	bx->lctx = *fsv_logctx_get(bx->logctx);
	bx->lctx.mlog = &bcast_log;
	bx->lx = (fsv_logctx*)&bx->lctx;

	bx->buf_size = bx->buf_size_conf = 2 * 1024;
	bx->buf_ms = 5000;
	bx->icy_meta_int = 32 * 1024;
	bx->always_on = 0;
	bx->stop_delay = 5;
	bx->reconnect_timeout = 5;

	fflist_init(&bx->suspendedClients);

	for (i = 0;  i < FFCNT(bx->users);  i++) {
		fflist_init(&bx->users[i]);
	}

	fflist_ins(&bcastm->ctxs, &bx->sib);
	hc->handler = &bcast_htph;
	hc->hctx = bx;

	ffpars_setargs(hc->args, bx, ctx_args, FFCNT(ctx_args));
	return 0;
}


static int bcast_logadd(fsv_logctx *lx, int lev, const char *modname, const ffstr *trid, const char *fmt, ...)
{
	int r;
	va_list va;
	va_start(va, fmt);
	r = bcast_logaddv(lx,  lev, modname, trid, fmt, va);
	va_end(va);
	return r;
}

static int bcast_logaddv(fsv_logctx *lx, int lev, const char *modname, const ffstr *trid, const char *fmt, va_list va)
{
	bcastctx *bx = FF_GETPTR(bcastctx, lctx, lx);
	return fsv_logctx_get(bx->logctx)->mlog->addv(bx->logctx, lev, modname, (trid != NULL) ? trid : &bx->name, fmt, va);
}


static void bcastx_start(bcastctx *bx)
{
	bx->status = ST_STARTING;
	dbglog(bx->lx, FSV_LOG_DBGFLOW, "initializing stream");
	bx->iface->start(bx->prov);
}

/** Close a stream without clients after a timeout. */
static void bcastx_stoptimer(void *param)
{
	bcastctx *bx = param;
	bx->stopping = 0;
	bx->iface->stop(bx->prov);
}

static void bcastx_starttimer(void *param)
{
	bcastx_start(param);
}

static void bcast_statustimer(void *param)
{
	bcastctx *bx;

	fftime now = bcastm->core->fsv_gettime();
	bcastm->lastUpdOutputBPS = fftime_mcs(&now);

	_FFLIST_WALK(&bcastm->ctxs, bx, sib) {
		bx->outputBPS = bx->outTraffic - bx->outTrafficLastSec;
		bx->outTrafficLastSec = bx->outTraffic;
	}
}

/// resume suspended clients
static void bcast_resumeClients(bcastctx *bx)
{
	bcast_client *c
		, *last = FF_GETPTR(bcast_client, sib, fflist_last(&bx->suspendedClients));
		//we don't resume the clients that will be added to this queue in this iteration
	fflist_item *next;

	FFLIST_WALKSAFE(&bx->suspendedClients, c, sib, next) {
		fflist_rm(&bx->suspendedClients, &c->sib);
		bcast_sendNext(c); //bcast_sendNext() never leads to another call to bcast_resumeClients()
		if (c == last)
			break;
	}
}

enum F {
	ERLOG = 1
	, DBGLOGLEV = 2
};

static void bcast_closeUsers(bcastctx *bx, uint i, int flags)
{
	bcast_client *c;
	fflist_item *next;

	FFLIST_WALKSAFE(&bx->users[i], c, sib_bufUsg, next) {
		if (flags & ERLOG) {
			errlog(c->logctx, FSV_LOG_ERR, "disconnecting client");

		} else if (flags & DBGLOGLEV) {
			dbglog(c->logctx, FSV_LOG_DBGNET, "disconnecting client");
		}

		bcast_decusg(c);
		c->Htp->send(c->hf, NULL, 0, FSV_HTTP_ERROR);
	}
}

void bcast_update(bcastctx *bx)
{
	if (bx->tmStartPlay == 0) {
		fftime now = bcast_now();
		bx->tmStartPlay = fftime_ms(&now);
		bx->status = ST_READY;
	}

	if (!bx->updatetime_set) {
		uint64 next_upd;
		int64 interval;
		fftime now = bcast_now();
		ffstr sbuf;
		bx->iface->getbuf(bx->prov, bx->curBuf, &sbuf);
		next_upd = bx->tmStartPlay + mm_duration(bx->byterate, bx->bytesPlayed + sbuf.len);
		interval = (next_upd > fftime_ms(&now)) ? (next_upd - fftime_ms(&now)) : 1;
		bcastm->core->timer(&bx->update_tmr, -interval, &bcast_played, bx);
		bx->updatetime_set = 1;
	}

	bcast_resumeClients(bx);
}

static void bcast_played(void *param)
{
	bcastctx *bx = param;
	ffstr sbuf;
	int e;
	uint iplayed;

	bx->updatetime_set = 0;
	e = bx->iface->getbuf(bx->prov, bx->curBuf, &sbuf);
	FF_ASSERT(e >= 0); //the buffer we've played was 100% filled
	(void)e;
	bx->bytesPlayed += sbuf.len;
	bcast_clearBuf(bx, bx->curBuf);
	//bx->bytesPlayed += 20000;//slow down

	iplayed = bx->curBuf;
	bx->curBuf = int_cycleinc(bx->curBuf, bx->nbufs);
	bx->iface->played(bx->prov, iplayed);
}

static void bcast_clearBuf(bcastctx *bx, uint i)
{
	fftime now = bcast_now();
	uint secs = now.sec - (uint)(bx->tmStartPlay / 1000);
	dbglog(bx->lx, FSV_LOG_DBGFLOW, "played buffer #%d [%02u:%02u] [%U]"
		, (int)i, (int)secs / 60, (int)secs % 60, (int64)bx->bytesPlayed);

	{
		uint64 tm_buf
			, ms_cur;
		int64 diff;
		uint64 udiff;
		tm_buf = mm_duration(bx->byterate, bx->bytesPlayed);
		ms_cur = fftime_ms(&now) - bx->tmStartPlay;
		diff = ms_cur - tm_buf;
		udiff = diff;
		if (diff < 0)
			udiff = -diff;
		if (udiff > mm_duration(bx->byterate, bx->buf_size) + 250 /*timer_interval*/) {
			errlog(bx->lx, FSV_LOG_WARN, "time resync.  diff: %Dms", (int64)diff);
			bx->tmStartPlay += diff;
		}
	}

	if (bx->usage[i] != 0) {
		// clients still use this buffer
		bcast_closeUsers(bx, i, ERLOG);
	}
}

void bcast_metaupdate(bcastctx *bx, const char *title, size_t len)
{
	ffarr a;
	fficy_initmeta(&a, bx->meta, sizeof(bx->meta));
	size_t imeta = fficy_addmeta(&a, FFSTR("StreamTitle"), title, len);
	bx->szmeta = fficy_finmeta(&a);
	bx->lastMetaChange = bcast_now().sec;
	bx->metaChangeIdx = bx->curBuf;

	dbglog(bx->lx, FSV_LOG_DBGFLOW, "prepared meta: [%L] %s"
		, (size_t)bx->szmeta-1, bx->meta+1);

	{
	char *begin = bx->meta + 1 + FFSLEN("StreamTitle='");
	char *end = bx->meta + 1 + imeta - FFSLEN("';");
	ffstr_set(&bx->title, begin, end - begin);
	}
}

/** get next chunk of data to be sent to the client
`ibuf' is which buffer was used the last time.  -1 if none */
static int bcast_getdata(bcastctx *bx, ffiovec *dst1, bcast_client *c)
{
	uint i = c->ibuf;
	char *buf;
	size_t sz, off = 0;
	ffstr sbuf;

	if (bx->tmStartPlay == 0)
		return 0; //nothing to send, we are preloading the buffers now

	if (i == (uint)-1) {
		//the first chunk of data for this client
		//find the first mp3 frame in the buffer
		const char *fr;
		i = bx->curBuf;
		if (0 > bx->iface->getbuf(bx->prov, i, &sbuf))
			return -1; //buffer is not filled

		for (;;) {
			buf = sbuf.ptr;
			sz = sbuf.len;
			fr = (char*)ffmpg_findframe(buf, sz, 2);

			if (fr != NULL)
				break;

			dbglog(bx->lx, FSV_LOG_DBGFLOW, "frame not found in buffer #%d from offset %L", (int)i, (size_t)off);
			i = int_cycleinc(i, bx->nbufs);
			if (i == bx->curBuf)
				return 0; //nothing to send

			if (0 > bx->iface->getbuf(bx->prov, i, &sbuf))
				return 0; //nothing to send
		}

		off = fr - buf;
		dbglog(bx->lx, FSV_LOG_DBGFLOW, "mpeg header is found in buffer #%d at %L"
			, (int)i, (size_t)off);
		buf += off;
		sz -= off;

	} else {
		int r;
		i = int_cycleinc(i, bx->nbufs);
		r = bx->iface->getbuf(bx->prov, i, &sbuf);
		if (r != 0)
			return 0; //nothing to send
		buf = sbuf.ptr;
		sz = sbuf.len;
	}
	c->ibuf = i;

	ffiov_set(dst1, buf, sz);
	bx->usage[i]++;
	c->usingbuf = 1;
	fflist_ins(&bx->users[i], &c->sib_bufUsg);
	dbglog(c->logctx, FSV_LOG_DBGFLOW, "buffer #%d usage +1 [%d]"
		, (int)i, (int)bx->usage[i]);

	return 1;
}

void bcast_sendNext(bcast_client *c)
{
	bcastctx *bx = c->bx;
	ffiovec *h;
	int i;
	int n;

	h = c->iovs;
	i = 0;

	if (c->buf.iov_len == 0) {
		ffiovec tel;

		if (bx->status == ST_STOPPED) {
			// error in provider
			c->Htp->send(c->hf, NULL, 0, FSV_HTTP_ERROR);
			return ;
		}

		else if (bx->status == ST_STARTING)
			goto suspend;

		else if (bx->status == ST_BUFFERING) {
			if (c->hdrsSent)
				goto suspend;

			if (!c->inited) {
				c->inited = 1;
				if (FFHTTP_200_OK != bcast_initclient(c)) {
					c->Htp->send(c->hf, NULL, 0, FSV_HTTP_ERROR);
					return ;
				}
			}

			// send just headers
			c->hdrsSent = 1;
			c->Htp->send(c->hf, NULL, 0, FSV_HTTP_ASIS | FSV_HTTP_MORE | FSV_HTTP_PUSH);
			return ;
		}

		n = bcast_getdata(bx, &tel, c); // we don't call it until we have sent all data within the buffer
		if (n == -1) {
			errlog(c->logctx, FSV_LOG_ERR, "no data");
			ffhttp_cookreset(c->cook);
			ffhttp_setstatus(c->cook, FFHTTP_500_INTERNAL_SERVER_ERROR);
			c->Htp->send(c->hf, NULL, 0, FSV_HTTP_ERROR);
			return ;
		}

		if (n == 0) {
suspend:
			//nothing to send yet. we must suspend the client until we have some more data to send
			fsv_dbglog(c->logctx, FSV_LOG_DBGFLOW, BCAST_MODNAME, NULL, "suspended");
			fflist_ins(&c->bx->suspendedClients, &c->sib);
			return ;
		}

		if (!c->inited) {
			c->inited = 1;
			if (FFHTTP_200_OK != bcast_initclient(c)) {
				c->Htp->send(c->hf, NULL, 0, FSV_HTTP_ERROR);
				return ;
			}
		}

		c->buf = tel;
		if (c->lastMetaChange != bx->lastMetaChange
			&& (c->ibuf == bx->metaChangeIdx || bx->metaChangeIdx == -1)) {
			// for the first block of data we always send meta
			// for next blocks, we check whether the current buffer is the meta changer
			c->metasent = 0;
			c->lastMetaChange = bx->lastMetaChange;
		}
	}

	while (i != FFCNT(c->iovs) - 1) {
		if (c->metaInt == -1) {
			//transfer all in one piece when no meta data is needed
			ffiov_set(&h[i++], c->buf.iov_base, c->buf.iov_len);
			ffiov_set(&c->buf, NULL, 0);

		} else {
			uint len = (int)ffmin(c->buf.iov_len, (size_t)c->metaInt);
			c->metaInt -= len;
			ffiov_set(&h[i++], c->buf.iov_base, len);
			ffiov_shift(&c->buf, len);

			if (c->metaInt == 0) {
				if (c->metasent || bx->szmeta == 0) {
					// empty meta
					ffiov_set(&h[i++], "\0", 1);

				} else {
					ffiov_set(&h[i++], bx->meta, bx->szmeta);
					c->metasent = 1;
					fsv_dbglog(c->logctx, FSV_LOG_DBGNET, BCAST_MODNAME, NULL, "sending meta: %u bytes"
						, (int)bx->szmeta);
				}
				c->metaInt = bx->icy_meta_int;
			}
		}
	}

	c->niovs = i;
	c->Htp->sendv(c->hf, c->iovs, i, FSV_HTTP_ASIS | FSV_HTTP_PUSH | FSV_HTTP_MORE);
}

static bcast_client* bcast_newclient(fsv_httphandler *h)
{
	bcastctx *bx = h->hctx;
	bcast_client *c = NULL;
	enum FFHTTP_STATUS er = FFHTTP_500_INTERNAL_SERVER_ERROR;

	if (bx->status != ST_READY && bx->always_on) {
		er = FFHTTP_504_GATEWAY_TIMEOUT;
		fsv_errlog(h->logctx, FSV_LOG_ERR, BCAST_MODNAME, NULL, "provider is not ready");
		goto fail;
	}

	if (bx->nclients == 0 && bx->stopping) {
		// the client has connected while we are waiting in the stoppage time
		bx->stopping = 0;
		bcastm->core->fsv_timerstop(&bx->startstop_tmr);
	}

	c = ffmem_tcalloc1(bcast_client);
	if (c == NULL) {
		fsv_syserrlog(h->logctx, FSV_LOG_ERR, BCAST_MODNAME, NULL, "%e", FFERR_BUFALOC);
		goto fail;
	}
	c->bx = bx;

	c->hf = h->id;
	c->Htp = h->http;
	c->logctx = h->logctx;
	c->httpcon = h->httpcon;
	c->cook = h->resp;

	c->ibuf = -1;

	c->metaInt = -1;
	if (bx->icy_meta_int != 0) {
		ffstr val;

		if (0 != ffhttp_findhdr(&h->req->h, FFSTR2(fficy_shdr[FFICY_HMETADATA]), &val)
			&& ffstr_eqcz(&val, "1")) {

			c->metaInt = bx->icy_meta_int;
		}

		fsv_dbglog(c->logctx, FSV_LOG_DBGFLOW, BCAST_MODNAME, NULL, "using meta: %s"
			, (c->metaInt == -1) ? "no" : "yes");
	}

	if (bx->status == ST_STOPPED) {
		// connect to the provider on demand, the first client
		bcastx_start(bx);
	}
	/*else if (bx->status == ST_BUFFERING || bx->status == ST_READY) {
		er = bcast_initclient(c);
		ffhttp_setstatus(cook, er);
		if (er != FFHTTP_200_OK)
			goto fail;
	}*/

	bx->nclients++;
	return c;

fail:
	if (c != NULL)
		ffmem_free(c);
	ffhttp_setstatus(h->resp, er);
	return NULL;
}

static int bcast_initclient(bcast_client *c)
{
	bcastctx *bx = c->bx;

	if (c->metaInt != -1 && bx->icy_meta_int == 0) {
		//meta is enabled by configuration, but the data provider didn't set it
		c->metaInt = -1;
	}

	if (bx->name.len != 0)
		ffhttp_addhdr_str(c->cook, &fficy_shdr[FFICY_HNAME], &bx->name);
	if (bx->genre.len != 0)
		ffhttp_addhdr_str(c->cook, &fficy_shdr[FFICY_HGENRE], &bx->genre);
	if (bx->url.len != 0)
		ffhttp_addhdr_str(c->cook, &fficy_shdr[FFICY_HURL], &bx->url);

	bx->iface->addhdrs(bx->prov, c->cook);

	if (c->metaInt != -1) {
		char s[64];
		uint i = ffs_fromint(bx->icy_meta_int, s, sizeof(s), 0);
		ffhttp_addhdr(c->cook, FFSTR2(fficy_shdr[FFICY_HMETAINT]), s, i);
	}

	ffstr_setcz(&c->cook->cont_type, "audio/mpeg");
	ffstr_setcz(&c->cook->proto, "ICY");
	c->cook->conn_close = 1;
	ffhttp_setstatus(c->cook, FFHTTP_200_OK);
	return FFHTTP_200_OK;
}

static void bcast_onsending(fsv_httphandler *h)
{
	bcast_client *c = h->id->udata;

	if (h->id->udata == NULL) {
		c = bcast_newclient(h);
		if (c == NULL) {
			h->http->send(h->id, NULL, 0, FSV_HTTP_ERROR);
			return;
		}

		h->id->udata = c;

	} else {
		if (c->usingbuf && c->buf.iov_len == 0)
			bcast_decusg(c);

		c->bx->outTraffic += ffiov_size(c->iovs, c->niovs);
	}

	bcast_sendNext(c);
}

static void bcast_decusg(bcast_client *c)
{
	FF_ASSERT(c->bx->usage[c->ibuf] != 0);
	c->bx->usage[c->ibuf]--;
	c->usingbuf = 0;
	fflist_rm(&c->bx->users[c->ibuf], &c->sib_bufUsg);
	dbglog(c->logctx, FSV_LOG_DBGFLOW, "buffer #%d usage -1 [%d]"
		, (int)c->ibuf, (int)c->bx->usage[c->ibuf]);
}

static void bcast_ondone(fsv_httphandler *h)
{
	bcast_client *c = h->id->udata;
	bcastctx *bx = c->bx;

	if (fflist_exists(&bx->suspendedClients, &c->sib))
		fflist_rm(&bx->suspendedClients, &c->sib);

	if (c->usingbuf)
		bcast_decusg(c);

	bx->nclients--;

	if (bx->nclients == 0 && !bx->always_on) {
		//This was the last client.  Wait for stop_delay and then stop the stream.
		bcastm->core->timer(&bx->startstop_tmr, -(int)bx->stop_delay * 1000, &bcastx_stoptimer, bx);
		bx->stopping = 1;
	}

	ffmem_free(c);
}

static void bcastx_free(bcastctx *bx)
{
	if (bx->prov != NULL)
		bx->iface->fin(bx->prov);

	ffstr_free(&bx->name);
	ffstr_free(&bx->genre);
	ffstr_free(&bx->url);

	ffmem_free(bx);
}

/** Provider has stopped.  Disconnect all clients. */
void bcastx_reset(bcastctx *bx)
{
	uint i;
	fflist_item *next;
	bcast_client *c;

	uint64 played = 0;
	if (bx->tmStartPlay != 0)
		played = bcast_now().sec - bx->tmStartPlay / 1000;
	errlog(bx->lx, FSV_LOG_INFO, "closing the stream [%U:%02u]"
		, played / 60, (int)(played % 60));

	bcastm->core->fsv_timerstop(&bx->update_tmr);
	bx->updatetime_set = 0;

	for (i = 0;  i < bx->nbufs;  i++) {
		if (bx->usage[i] != 0)
			bcast_closeUsers(bx, i, DBGLOGLEV);
	}

	FFLIST_WALKSAFE(&bx->suspendedClients, c, sib, next) {
		fsv_dbglog(c->logctx, FSV_LOG_DBGNET, BCAST_MODNAME, NULL, "disconnecting client");
		fflist_rm(&bx->suspendedClients, &c->sib);

		if (c->cook->code == 0)
			ffhttp_setstatus(c->cook, FFHTTP_500_INTERNAL_SERVER_ERROR);
		c->Htp->send(c->hf, NULL, 0, FSV_HTTP_ERROR);
	}

	bx->curBuf = 0;
	bx->byterate = 0;
	bx->tmStartPlay = 0;
	bx->bytesPlayed = 0;
	bx->lastMetaChange = 0;
	bx->szmeta = 0;
	bx->metaChangeIdx = -1;
	bx->status = ST_STOPPED;
	bx->err = 0;

	if (bx->always_on)
		bcastm->core->timer(&bx->startstop_tmr, -(int)bx->reconnect_timeout * 1000, &bcastx_starttimer, bx);
}


ffmpg_hdr* ffmpg_findframe(const void *_d, size_t sz, uint flags)
{
	const ffmpg_hdr *h;
	uint lev;
	const char *d = _d;
	const char *begin;
	const char *end = d + sz;
	uint nCheckFrames = flags & 0x07;
	uint sample_rate, lyr, ver; //these values stay the same across frames

	if (nCheckFrames == 0)
		nCheckFrames = 1;

	for (begin = d;  begin != end;) {

		if ((byte)begin[0] != 0xff) {
			d = ffs_findc(begin, end - begin, 0xff);
			if (d == NULL)
				break; //0xff not found, no header
		}

		if (d + sizeof(ffmpg_hdr) > end)
			break;

		h = (ffmpg_hdr *)d;
		lev = 0;
		sample_rate = h->sample_rate;
		ver = h->ver;
		lyr = h->layer;
		begin = d;

		while (ffmpg_hdr_valid(h)
			&& ver == h->ver && lyr == h->layer && sample_rate == h->sample_rate)
		{
			lev++;
			if (lev == nCheckFrames)
				return (ffmpg_hdr*)d; //the last frame is also valid

			//if (!h->noprotect)
			//	begin += 2; //skip crc16

			begin += ffmpg_hdr_framelen(h);
			if (begin + sizeof(ffmpg_hdr) > end)
				break; //frame data is too large for the specified input data chunk

			h = (ffmpg_hdr*)begin;
		}

		d++;
		begin = d;
	}

	return NULL; //mpeg frame is not found
}

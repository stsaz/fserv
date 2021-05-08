/**
Copyright (c) 2014 Simon Zolin
*/

#include "log.h"
#include <http/iface.h>

enum {
	bufSize = 8 * 1024
	, firstSendSpace = 1024
};

typedef struct htlog_mod {
	fsv_timer iTmr;
	const fsv_core *srv;
	fflist htlogs;
} htlog_mod;

static htlog_mod *mod;

typedef struct htlog {
	fflist_item sib;
	fflist clients;
	ffstr name;
} htlog;

typedef struct LogClient {
	htlog *hl;

	fsv_httpfilter *hf;
	const fsv_http *http;

	ffstr filter;
	ffstr buf;
	ffstr buf2;
	ffstr *curBuf;
	fflist_item sib;
	unsigned suspended :1;
} LogClient;

typedef struct htlog_usr {
	htlog *hl;
} htlog_usr;


// FSERV MODULE
static void * htlog_creat(const fsv_core *srv, ffpars_ctx *ctx, fsv_modinfo *m);
static void htlog_destroy(void);
static int htlog_start(void);
static int htlog_sig(int signo);
static const void * htlog_iface(const char *name);
const fsv_mod fsv_htplog = {
	&htlog_creat, &htlog_destroy, &htlog_sig, &htlog_iface
};

// FSERV LOG OUTPUT
static fsv_log_outptr * htp_create(ffpars_ctx *a);
static void htp_free(fsv_log_outptr *instance);
static int htp_open(fsv_log_outptr *instance, int flags);
static int htp_write(fsv_log_outptr *instance, int lev, const char *buf, size_t len);
const fsv_log_output loghttp_output = {
	&htp_create, &htp_free, &htp_open, &htp_write
};

// FSERV HTTP
static int logh_newctx(fsv_http_hdlctx *hc);
static void * logh_onstartsend(fsv_httphandler *h);
static void logh_onsending(fsv_httphandler *h);
static void logh_ondone(fsv_httphandler *h);

static const fsv_httphandler_iface log_htpm = {
	&logh_newctx
};

static const fsv_http_cb log_htph = {
	&logh_onsending, &logh_ondone
};

static void swapAndSend(LogClient *c);
static void log_http_onTimer(void *param);

static int htlogusr_conf_usename(ffparser_schem *ps, htlog_usr *hu, ffstr *v);


static const ffpars_arg htlog_args[] = {
	{ "Name", FFPARS_TSTR | FFPARS_FNOTEMPTY | FFPARS_FREQUIRED | FFPARS_FCOPY,  FFPARS_DSTOFF(htlog, name) }
};

static int htlogusr_conf_usename(ffparser_schem *ps, htlog_usr *hu, ffstr *v)
{
	htlog *hl;
	_FFLIST_WALK(&mod->htlogs, hl, sib) {
		if (ffstr_eq2(&hl->name, v)) {
			hu->hl = hl;
			return 0;
		}
	}

	return FFPARS_EBADVAL;
}

static const ffpars_arg htlog_usr_args[] = {
	{ "UseName", FFPARS_TSTR | FFPARS_FNOTEMPTY | FFPARS_FREQUIRED,  FFPARS_DST(&htlogusr_conf_usename) }
};

static void * htlog_creat(const fsv_core *srv, ffpars_ctx *ctx, fsv_modinfo *m)
{
	mod = ffmem_tcalloc1(htlog_mod);
	if (mod == NULL)
		return NULL;
	ffhttp_initheaders();
	fflist_init(&mod->htlogs);
	mod->srv = srv;
	return mod;
}

static void htlog_destroy(void)
{
	ffmem_free(mod);
	mod = NULL;
}

static int htlog_start(void)
{
	mod->srv->timer(&mod->iTmr, 50, &log_http_onTimer, mod);
	return 0;
}

static int htlog_sig(int signo)
{
	switch (signo) {
	case FSVCORE_SIGSTART:
		return htlog_start();
	}

	if (signo == FSVCORE_SIGSTOP) {
		mod->srv->timer(&mod->iTmr, 0, NULL, NULL);
	}
	return 0;
}

static const void * htlog_iface(const char *name)
{
	if (!ffsz_cmp(name, "http-handler"))
		return &log_htpm;
	return NULL;
}

static fsv_log_outptr * htp_create(ffpars_ctx *a)
{
	htlog *hl = ffmem_tcalloc1(htlog);
	if (hl == NULL)
		return NULL;
	fflist_ins(&mod->htlogs, &hl->sib);
	fflist_init(&hl->clients);
	ffpars_setargs(a, hl, htlog_args, FFCNT(htlog_args));
	return (fsv_log_outptr*)hl;
}

static void htp_free(fsv_log_outptr *instance)
{
	htlog *hl = (htlog*)instance;
	fflist_rm(&mod->htlogs, &hl->sib);
	ffstr_free(&hl->name);
	ffmem_free(hl);
}

static int htp_open(fsv_log_outptr *instance, int flags)
{
	return 0;
}

static int htp_write(fsv_log_outptr *instance, int lev, const char *msg, size_t len)
{
	htlog *hl = (htlog*)instance;
	LogClient *c;
	_FFLIST_WALK(&hl->clients, c, sib) {
		if (msg + len == ffs_finds(msg, len, FFSTR2(c->filter)))
			continue;
		if (bufSize - c->curBuf->len < len)
			continue;
		memcpy(ffarr_end(c->curBuf), msg, len);
		c->curBuf->len += len;
	}
	return 0;
}


static int logh_newctx(fsv_http_hdlctx *hc)
{
	htlog_usr *hu = ffmem_tcalloc1(htlog_usr);//%free the pointer on mod destroy!
	if (hu == NULL)
		return 1;

	hc->handler = &log_htph;
	hc->hctx = hu;
	ffpars_setargs(hc->args, hu, htlog_usr_args, FFCNT(htlog_usr_args));
	return 0;
}


static void * logh_onstartsend(fsv_httphandler *h)
{
	htlog_usr *hu = h->hctx;
	htlog *hl = hu->hl;
	LogClient *c;
	ffstr qs = ffhttp_requrl(h->req, FFURL_QS);
	ffhttp_setstatus(h->resp, FFHTTP_500_INTERNAL_SERVER_ERROR);

	if (h->req->method != FFHTTP_GET) {
		ffhttp_setstatus(h->resp, FFHTTP_405_METHOD_NOT_ALLOWED);
		return NULL;
	}

	c = ffmem_tcalloc1(LogClient);
	if (c == NULL)
		return NULL;

	while (qs.len != 0) {
		ffstr par;
		size_t by = ffstr_nextval(FFSTR2(qs), &par, '&');
		ffstr_shift(&qs, by);
		if (ffstr_match(&par, FFSTR("filter="))) {
			ffstr_shift(&par, FFSLEN("filter="));
			c->filter = par;
		}
	}

	if (NULL == ffstr_alloc(&c->buf, bufSize)) {
		ffmem_free(c);
		return NULL;
	}
	if (NULL == ffstr_alloc(&c->buf2, bufSize)) {
		ffstr_free(&c->buf);
		ffmem_free(c);
		return NULL;
	}
	c->hl = hl;
	c->hf = h->id;
	c->curBuf = &c->buf;
	fflist_ins(&hl->clients, &c->sib);
	c->suspended = 1;
	memset(c->curBuf->ptr, ' ', firstSendSpace);
	c->curBuf->ptr[firstSendSpace] = '\n';
	c->curBuf->len = firstSendSpace + 1;

	ffhttp_setstatus(h->resp, FFHTTP_200_OK);
	ffstr_setcz(&h->resp->cont_type, "text/plain");
	return c;
}

static void logh_onsending(fsv_httphandler *h)
{
	LogClient *c = h->id->udata;

	if (h->id->udata == NULL) {
		c = logh_onstartsend(h);
		if (c == NULL) {
			h->http->send(h->id, NULL, 0, FSV_HTTP_ERROR);
			return;
		}

		h->id->udata = c;
		c->http = h->http;
	}

	if (c->curBuf == &c->buf2)
		c->buf.len = 0;
	else
		c->buf2.len = 0;

	if (c->curBuf->len != bufSize) {
		//% we dont currently fill the buffer completely, so we'll get here almost always
		c->suspended = 1;
		return ;
	}
	swapAndSend(c);
}

static void swapAndSend(LogClient *c)
{
	ffstr *b;
	b = c->curBuf;
	if (c->curBuf == &c->buf2)
		c->curBuf = &c->buf;
	else
		c->curBuf = &c->buf2;
	if (b->len == 0)
		return ;

	c->suspended = 0;
	c->http->send(c->hf, b->ptr, b->len, FSV_HTTP_NOINPUT | FSV_HTTP_MORE | FSV_HTTP_PUSH);
}

static void logh_ondone(fsv_httphandler *h)
{
	LogClient *c = h->id->udata;
	fflist_rm(&c->hl->clients, &c->sib);
	ffstr_free(&c->buf);
	ffstr_free(&c->buf2);
	ffmem_free(c);
}

static void log_http_onTimer(void *param)
{
	htlog *hl;
	LogClient *c;
	_FFLIST_WALK(&mod->htlogs, hl, sib) {
		_FFLIST_WALK(&hl->clients, c, sib) {
			if (!c->suspended)
				continue;

			swapAndSend(c);
		}
	}
}

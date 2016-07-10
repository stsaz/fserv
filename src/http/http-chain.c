/** The processor of HTTP filter chain.
Copyright 2014 Simon Zolin.
*/

#include <http/http.h>


static int http_init_reqchain(httpcon *c);
static void http_callmod(httpcon *c, httpfilter *hf);
static void http_initfilter(httpcon *c, httpfilter *hf, const http_submod *sm);
static void http_chain_error(httpcon *c, httpfilter *hf);
static int http_mainhandler_process(httpcon *c, httpfilter **phf, uint flags);
static int http_chain_process(httpcon *c, httpfilter **phf, uint flags);
static void http_finfilter(httpcon *c, httpfilter *hf);
static void http_fin(httpcon *c);

static const char *const filt_type_str[] = { "response", "request" };
#define FILT_TYPE(t)  filt_type_str[t]

#define HF_SENTL(hf)  ((hf)->reqfilt ? ffchain_sentl(&c->filters) : ffchain_sentl(&c->respfilters))


void http_start(httpcon *c)
{
	if (0 != http_init_reqchain(c)) {
		http_close(c);
		return;
	}
	http_callmod(c, c->reqchain.ptr);
}

enum {
	CHAIN_NOP = 1
	, CHAIN_NEXT = 2
};

void http_send(fsv_httpfilter *_hf, const void *buf, size_t len, int flags)
{
	httpfilter *hf = (httpfilter*)_hf;
	httpcon *c = (httpcon*)hf->con;
	int r = http_mainhandler_process(c, &hf, flags);
	if (r == CHAIN_NOP)
		return;

	else if (r == CHAIN_NEXT && !(flags & FSV_HTTP_PASS)) {
		if (len != 0) {
			ffiov_set(&hf->iov, buf, len);
			ffsf_sethdtr(&hf->input.ht, &hf->iov, 1, NULL, 0);
		}
		if (!(flags & FSV_HTTP_MORE))
			ffsf_init(&((httpfilter*)_hf)->input);
	}

	http_callmod(c, hf);
}

void http_sendv(fsv_httpfilter *_hf, ffiovec *iovs, size_t n, int flags)
{
	httpfilter *hf = (httpfilter*)_hf;
	httpcon *c = (httpcon*)hf->con;
	int r = http_mainhandler_process(c, &hf, flags);
	if (r == CHAIN_NOP)
		return;

	else if (r == CHAIN_NEXT && !(flags & FSV_HTTP_PASS)) {
		//note: there must be no empty iovec items, or ffsf_empty() won't work
		ffsf_sethdtr(&hf->input.ht, iovs, n, NULL, 0);
		if (!(flags & FSV_HTTP_MORE))
			ffsf_init(&((httpfilter*)_hf)->input);
	}

	http_callmod(c, hf);
}

void http_sendfile(fsv_httpfilter *_hf, fffd fd, uint64 fsize, uint64 foffset, sf_hdtr *hdtr, int flags)
{
	httpfilter *hf = (httpfilter*)_hf;
	httpcon *c = (httpcon*)hf->con;
	int r = http_mainhandler_process(c, &hf, flags);
	if (r == CHAIN_NOP)
		return;

	else if (r == CHAIN_NEXT && !(flags & FSV_HTTP_PASS)) {
		fffile_mapset(&hf->input.fm, httpm->pagesize, fd, foffset, fsize);
		if (hdtr != NULL)
			hf->input.ht = *hdtr;
		if (!(flags & FSV_HTTP_MORE))
			ffsf_init(&((httpfilter*)_hf)->input);
	}

	http_callmod(c, hf);
}


static void http_initfilter(httpcon *c, httpfilter *hf, const http_submod *sm)
{
	ffsf_init(&hf->input);
	hf->con = c;
	hf->sm = sm;
}

void http_resptask(void *param)
{
	httpcon *c = param;
	http_callmod(c, c->respchain.ptr);
}

static void http_respchain_continue(void *param)
{
	httpfilter *hf = param;
	httpcon *c = hf->con;
	if (CHAIN_NOP == http_chain_process(c, &hf, hf->flags))
		return;
	http_callmod(c, hf);
}

/** Handle error reported from a filter. */
static void http_chain_error(httpcon *c, httpfilter *hf)
{
	dbglog(c->logctx, FSV_LOG_HTTPFILT, "%s: '%s' reported an error"
		, FILT_TYPE(hf->reqfilt), hf->sm->modname);

	if (hf->reqfilt)
		c->req_fin = 1;

	/* We can send error response if:
	. we haven't sent anything yet
	. we aren't sending anything right now. */
	if (c->nwrite == 0 && (hf->reqfilt || !(c->tmr_flags & TMR_WRITE)) && !c->err) {
		c->err = 1;

		httpm->core->utask(&c->rtask, FSVCORE_TASKDEL);

		FFARR_WALK(&c->respchain, hf) {
			http_finfilter(c, hf);
		}
		c->respchain.len = 0;
		c->respmain_fin = 0;
		c->resp_fin = 0;
		ffchain_init(&c->respfilters);

		{
		uint code = c->resp.code;
		ffstr status = c->resp.status;
		unsigned conn_close = c->resp.conn_close;
		ffhttp_cookreset(&c->resp);
		ffhttp_setstatus4(&c->resp, code, status.ptr, status.len);
		c->resp.conn_close = conn_close;
		}

		if (0 == http_init_respchain(c, &httpm->err_hdler)) {
			http_callmod(c, c->respchain.ptr);
			return;
		}
	}

	http_close(c);
}

static int http_mainhandler_process(httpcon *c, httpfilter **phf, uint flags)
{
	httpfilter *hf = *phf;

	hf->flags = flags | (hf->flags & (FSV_HTTP_ASIS | FSV_HTTP_PUSH));

	if (hf->ismain
		&& ((hf->flags & (FSV_HTTP_NOINPUT | FSV_HTTP_DONE | FSV_HTTP_ERROR))
			|| !(hf->flags & (FSV_HTTP_MORE | FSV_HTTP_BACK)))) {

		//main-handler doesn't want request body or it has no more output
		c->respmain_fin = 1;

		if ((hf->flags & (FSV_HTTP_NOINPUT | FSV_HTTP_DONE | FSV_HTTP_ERROR))
			&& hf->sib.prev != HF_SENTL(hf)) {

			fsv_taskpost(httpm->core, &c->rtask, &http_respchain_continue, hf);
			hf = FF_GETPTR(httpfilter, sib, hf->sib.prev);
			hf->fin = 1;
			http_callmod(c, hf);
			return 1;
		}
	}

	return http_chain_process(c, phf, flags);
}

/** Process the results of the previous call to a filter.
Get the next filter in chain. */
static int http_chain_process(httpcon *c, httpfilter **phf, uint flags)
{
	httpfilter *hf = *phf;
	fflist_cursor cur;
	uint r;

	if (hf->flags & FSV_HTTP_ERROR) {
		http_chain_error(c, hf);
		return 1;
	}

	dbglog(c->logctx, FSV_LOG_HTTPFILT, "%s: '%s' returned. back:%u, more:%u, done:%u"
		, FILT_TYPE(hf->reqfilt), hf->sm->modname
		, (hf->flags & FSV_HTTP_BACK) != 0, (hf->flags & FSV_HTTP_MORE) != 0, (hf->flags & FSV_HTTP_DONE) != 0);

	if (flags & FSV_HTTP_BACK)
		r = FFLIST_CUR_PREV;
	else
		r = FFLIST_CUR_NEXT | FFLIST_CUR_BOUNCE
			| ((flags & FSV_HTTP_MORE) ? FFLIST_CUR_SAMEIFBOUNCE : 0);

	if (flags & FSV_HTTP_NOINPUT)
		r |= FFLIST_CUR_RMPREV;
	if (flags & FSV_HTTP_NONEXT)
		r |= FFLIST_CUR_RMNEXT;
	if (flags & FSV_HTTP_DONE)
		r |= FFLIST_CUR_RM;
	else if (!(flags & FSV_HTTP_MORE))
		r |= FFLIST_CUR_RMFIRST;

	cur = &hf->sib;
	r = fflist_curshift(&cur, r, HF_SENTL(hf));

	switch (r) {
	case FFLIST_CUR_NONEXT:
		goto done;

	case FFLIST_CUR_NOPREV:
		errlog(c->logctx, FSV_LOG_ERR, "%s: no more input data for '%s'"
			, FILT_TYPE(hf->reqfilt), hf->sm->modname);
		http_chain_error(c, hf);
		return CHAIN_NOP;

	case FFLIST_CUR_NEXT:
		*phf = FF_GETPTR(httpfilter, sib, cur);
		(*phf)->flags |= (hf->flags & (FSV_HTTP_PUSH | FSV_HTTP_ASIS));

		FF_ASSERT(ffsf_empty(&(*phf)->input));
		if (flags & FSV_HTTP_PASS) {
			(*phf)->input = hf->input;
			ffsf_init(&hf->input);
		}

		return CHAIN_NEXT;
	}

	ffsf_init(&hf->input);

	// find the filter to the left that has more output data
	for (;;) {
		hf = FF_GETPTR(httpfilter, sib, cur);
		if (hf->flags & FSV_HTTP_MORE) {
			*phf = hf;
			break;
		}
		r = fflist_curshift(&cur, FFLIST_CUR_PREV, HF_SENTL(hf));
	}
	hf->sentdata = 1;
	return 0;

done:
	dbglog(c->logctx, FSV_LOG_HTTPFILT, "%s: done", FILT_TYPE(hf->reqfilt));

	if (hf->reqfilt) {
		c->req_fin = 1;
		if (!c->resp_fin)
			return 1;

	} else {
		c->resp_fin = 1;
		if (!c->req_fin) {
			http_bodyprovide_continue(c);
			return 1;
		}
	}

	http_fin(c);
	return 1;
}

/** Pass control to a filter. */
static void http_callmod(httpcon *c, httpfilter *hf)
{
	fsv_httphandler p;

	p.id = (fsv_httpfilter*)hf;
	p.data = &hf->input;
	p.flags = (hf->sib.prev == HF_SENTL(hf)) ? FSV_HTTP_LAST : 0;
	p.flags |= (hf->flags & (FSV_HTTP_PUSH | FSV_HTTP_ASIS));

	if (hf->fin)
		p.flags |= FSV_HTTP_FIN;

	if (hf->sentdata) {
		hf->sentdata = 0;
		p.flags |= FSV_HTTP_SENT;
	}

	p.hctx = hf->sm->hctx;
	p.http = &fsv_http_iface;
	p.httpcon = (fsv_httpcon*)c;
	p.logctx = c->logctx;
	p.req = &c->req;
	p.resp = &c->resp;

	dbglog(c->logctx, FSV_LOG_HTTPFILT, "%s: calling '%s'. data: %U. last:%u"
		, FILT_TYPE(hf->reqfilt), hf->sm->modname, ffsf_len(p.data)
		, (p.flags & FSV_HTTP_LAST) != 0);

	hf->sm->handler->onevent(&p);
}

static void http_finfilter(httpcon *c, httpfilter *hf)
{
	if (hf->hf.udata != NULL) {
		fsv_httphandler p = {0};
		p.id = (fsv_httpfilter*)hf;
		p.data = &hf->input;
		p.hctx = hf->sm->hctx;
		p.http = &fsv_http_iface;
		p.httpcon = (fsv_httpcon*)c;
		p.logctx = c->logctx;
		p.req = &c->req;
		p.resp = &c->resp;

		dbglog(c->logctx, FSV_LOG_HTTPFILT, "%s: closing '%s'"
			, FILT_TYPE(hf->reqfilt), hf->sm->modname);

		hf->sm->handler->ondone(&p);
		hf->hf.udata = NULL;
	}

	ffsf_close(&hf->input);
}

static int http_init_reqchain(httpcon *c)
{
	const http_submod *reqfilts;
	size_t i, n;
	httpfilter *hf;

	http_get_def_reqfilts(&reqfilts, &n);

	if (NULL == ffarr_realloc(&c->reqchain, n)) {
		syserrlog(c->logctx, FSV_LOG_ERR, "%e", FFERR_BUFALOC);
		return 1;
	}
	ffmem_zero(c->reqchain.ptr, c->reqchain.cap * sizeof(httpfilter));
	c->reqchain.len = n;

	hf = c->reqchain.ptr;
	for (i = 0;  i != n;  i++) {
		http_initfilter(c, hf, &reqfilts[i]);
		hf->reqfilt = 1;
		ffchain_add(&c->filters, &hf->sib);
		hf++;
	}
	return 0;
}

int http_init_respchain(httpcon *c, const http_submod *mainhandler)
{
	const http_submod *sm, *respfilts;
	httpfilter *hf;
	size_t n, i, nfilts;

	http_get_def_respfilts(&respfilts, &nfilts);

	n = 1 + c->host->resp_filters.len + nfilts;
	if (NULL == ffarr_realloc(&c->respchain, n)) {
		syserrlog(c->logctx, FSV_LOG_ERR, "%e", FFERR_BUFALOC);
		return 1;
	}
	ffmem_zero(c->respchain.ptr, c->respchain.cap * sizeof(httpfilter));
	c->respchain.len = n;
	hf = c->respchain.ptr;

	http_initfilter(c, hf, &respfilts[0]);
	ffchain_add(&c->respfilters, &hf->sib);
	hf++;

	http_initfilter(c, hf, mainhandler);
	ffchain_add(&c->respfilters, &hf->sib);
	hf->ismain = 1;
	hf++;

	FFARR_WALK(&c->host->resp_filters, sm) {
		http_initfilter(c, hf, sm);
		ffchain_add(&c->respfilters, &hf->sib);
		hf++;
	}

	for (i = 1;  i != nfilts;  i++) {
		http_initfilter(c, hf, &respfilts[i]);
		ffchain_add(&c->respfilters, &hf->sib);
		hf++;
	}
	return 0;
}

static void http_karequest(void *param)
{
	httpcon *c = param;
	http_callmod(c, c->reqchain.ptr);
}

/** Finalize the current session and start processing a new keep-alive request. */
static void http_fin(httpcon *c)
{
	if (c->resp.conn_close) {
		http_close(c);
		return;
	}

	http_chain_fin(c);
	http_reset(c);
	(void)http_init_reqchain(c); //doesn't return with an error
	fsv_taskpost(httpm->core, &c->rtask, http_karequest, c); //clear call stack
}

void http_chain_fin(httpcon *c)
{
	httpfilter *hf;
	FFARR_WALK(&c->reqchain, hf) {
		http_finfilter(c, hf);
	}
	c->reqchain.len = 0;

	FFARR_WALK(&c->respchain, hf) {
		http_finfilter(c, hf);
	}
	c->respchain.len = 0;

	ffhttp_reqfree(&c->req);
}

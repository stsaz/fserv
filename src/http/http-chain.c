/** The processor of HTTP filter chain.
Copyright 2014 Simon Zolin.
*/

#include <http/http.h>


static int http_init_reqchain(httpcon *c);
static void http_callmod(httpcon *c, httpfilter *hf);
static void http_initfilter(httpcon *c, httpfilter *hf, const http_submod *sm);
static void http_chain_error(httpcon *c, httpfilter *hf);
static int http_mainhandler_process(httpcon *c, httpfilter **phf);
static int http_chain_process(httpcon *c, httpfilter **phf);
static void http_finfilter(httpcon *c, httpfilter *hf);
static void http_fin(httpcon *c);

static const char *const filt_type_str[] = { "response", "request" };
#define FILT_TYPE(t)  filt_type_str[t]


void http_start(httpcon *c)
{
	if (0 != http_init_reqchain(c)) {
		http_close(c);
		return;
	}
	http_callmod(c, c->reqchain.ptr);
}

void http_send(fsv_httpfilter *_hf, const void *buf, size_t len, int flags)
{
	httpfilter *hf = (httpfilter*)_hf, *next;
	httpcon *c = (httpcon*)hf->con;

	if (!(flags & FSV_HTTP_BACK) && hf->sib.next != NULL) {
		next = FF_GETPTR(httpfilter, sib, hf->sib.next);

		ffsf_init(&next->input);
		if (flags & FSV_HTTP_PASS) {
			next->input = hf->input;
		} else {
			if (len != 0) {
				ffiov_set(&next->iov, buf, len);
				ffsf_sethdtr(&next->input.ht, &next->iov, 1, NULL, 0);
			}
		}
	}

	hf->flags = flags | (hf->flags & (FSV_HTTP_ASIS | FSV_HTTP_PUSH));

	if (0 != http_mainhandler_process(c, &hf))
		return;
	http_callmod(c, hf);
}

void http_sendv(fsv_httpfilter *_hf, ffiovec *iovs, size_t n, int flags)
{
	httpfilter *hf = (httpfilter*)_hf, *next;
	httpcon *c = (httpcon*)hf->con;

	if (!(flags & FSV_HTTP_BACK) && hf->sib.next != NULL) {
		next = FF_GETPTR(httpfilter, sib, hf->sib.next);

		ffsf_init(&next->input);
		if (flags & FSV_HTTP_PASS) {
			next->input = hf->input;
		} else {
			//note: there must be no empty iovec items, or ffsf_empty() won't work
			ffsf_sethdtr(&next->input.ht, iovs, n, NULL, 0);
		}
	}

	hf->flags = flags | (hf->flags & (FSV_HTTP_ASIS | FSV_HTTP_PUSH));

	if (0 != http_mainhandler_process(c, &hf))
		return;
	http_callmod(c, hf);
}

void http_sendfile(fsv_httpfilter *_hf, fffd fd, uint64 fsize, uint64 foffset, sf_hdtr *hdtr, int flags)
{
	httpfilter *hf = (httpfilter*)_hf, *next;
	httpcon *c = (httpcon*)hf->con;

	if (!(flags & FSV_HTTP_BACK) && hf->sib.next != NULL) {
		next = FF_GETPTR(httpfilter, sib, hf->sib.next);

		ffsf_init(&next->input);
		if (flags & FSV_HTTP_PASS) {
			next->input = hf->input;
		} else {
			fffile_mapset(&next->input.fm, httpm->pagesize, fd, foffset, fsize);
			if (hdtr != NULL)
				next->input.ht = *hdtr;
		}
	}

	hf->flags = flags | (hf->flags & (FSV_HTTP_ASIS | FSV_HTTP_PUSH));

	if (0 != http_mainhandler_process(c, &hf))
		return;
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
	if (0 != http_chain_process(c, &hf))
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

static int http_mainhandler_process(httpcon *c, httpfilter **phf)
{
	httpfilter *hf = *phf;

	if (hf->ismain
		&& ((hf->flags & (FSV_HTTP_NOINPUT | FSV_HTTP_DONE | FSV_HTTP_ERROR))
			|| !(hf->flags & (FSV_HTTP_MORE | FSV_HTTP_BACK)))) {

		//main-handler doesn't want request body or it has no more output
		c->respmain_fin = 1;

		if ((hf->flags & (FSV_HTTP_NOINPUT | FSV_HTTP_DONE | FSV_HTTP_ERROR))
			&& hf->sib.prev != NULL) {

			fsv_taskpost(httpm->core, &c->rtask, &http_respchain_continue, hf);
			hf = FF_GETPTR(httpfilter, sib, hf->sib.prev);
			hf->fin = 1;
			http_callmod(c, hf);
			return 1;
		}
	}

	return http_chain_process(c, phf);
}

/** Process the results of the previous call to a filter.
Get the next filter in chain. */
static int http_chain_process(httpcon *c, httpfilter **phf)
{
	httpfilter *hf = *phf;
	fflist_item sib;

	if (hf->flags & FSV_HTTP_ERROR) {
		http_chain_error(c, hf);
		return 1;
	}

	dbglog(c->logctx, FSV_LOG_HTTPFILT, "%s: '%s' returned. back:%u, more:%u, done:%u"
		, FILT_TYPE(hf->reqfilt), hf->sm->modname
		, (hf->flags & FSV_HTTP_BACK) != 0, (hf->flags & FSV_HTTP_MORE) != 0, (hf->flags & FSV_HTTP_DONE) != 0);

	if (!(hf->flags & FSV_HTTP_MORE) || (hf->flags & FSV_HTTP_PASS))
		ffsf_init(&hf->input);

	if (hf->flags & FSV_HTTP_NOINPUT)
		hf->sib.prev = NULL;

	sib = hf->sib;

	if ((hf->flags & FSV_HTTP_DONE)
		|| (sib.prev == NULL && !(hf->flags & FSV_HTTP_MORE)))
		fflist_unlink(&hf->sib);

	if (hf->flags & FSV_HTTP_BACK) {
		if (sib.prev == NULL) {
			errlog(c->logctx, FSV_LOG_ERR, "%s: no more input data for '%s'"
				, FILT_TYPE(hf->reqfilt), hf->sm->modname);
			http_chain_error(c, hf);
			return 1;
		}
		goto prev;

	} else if (sib.next == NULL) {
		if (sib.prev == NULL)
			goto done; //the chain completed successfully
		goto prev;
	}

	*phf = FF_GETPTR(httpfilter, sib, sib.next);
	(*phf)->flags |= (hf->flags & (FSV_HTTP_PUSH | FSV_HTTP_ASIS));
	return 0;

prev:
	// find the filter to the left that has more output data
	hf = FF_GETPTR(httpfilter, sib, sib.prev);
	for (;;) {
		if (hf->flags & FSV_HTTP_MORE) {
			*phf = hf;
			break;
		}
		hf = FF_GETPTR(httpfilter, sib, hf->sib.prev);
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
	p.flags = (hf->sib.prev == NULL) ? FSV_HTTP_LAST : 0;
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
		if (hf != c->reqchain.ptr)
			fflist_link(&hf->sib, &(hf-1)->sib);
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
	hf++;

	http_initfilter(c, hf, mainhandler);
	hf->ismain = 1;
	fflist_link(&hf->sib, &(hf-1)->sib);
	hf++;

	FFARR_WALK(&c->host->resp_filters, sm) {
		http_initfilter(c, hf, sm);
		fflist_link(&hf->sib, &(hf-1)->sib);
		hf++;
	}

	for (i = 1;  i != nfilts;  i++) {
		http_initfilter(c, hf, &respfilts[i]);
		fflist_link(&hf->sib, &(hf-1)->sib);
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

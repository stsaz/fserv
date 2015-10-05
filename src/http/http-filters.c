/** Default HTTP request-response filters.
Copyright 2014 Simon Zolin.
*/

/*
req-filters... <-> main-handler <-> resp-filters...

recv-req <-> parse-req <-> process-req -> recv-body <-> cont-len|chunked <-> pre-buf <->
req-body <-> (main-handler)|errdoc <-> gz <-> cont-len|chunked <-> make-resp <-> send-resp
*/

#include <http/http.h>


static void http_resettimer(httpcon *c, int t);
static void http_stoptimer(httpcon *c, int t);
static void http_onexpire(const fftime *now, void *udata);

static void http_reqrecv(fsv_httphandler *h);
static void http_reqrecv_ondone(fsv_httphandler *h);
static void http_readrequest(void *udata);
static const fsv_http_cb http_recv_hdrs_filter = {
	&http_reqrecv, &http_reqrecv_ondone
};

static void http_reqparse(fsv_httphandler *h);
static void http_reqparse_ondone(fsv_httphandler *h);
static void http_printreq(httpcon *c);
static int http_sethost(httpcon *c, const ffstr *shost);
static int http_ssl_checkservname(httpcon *c, const ffstr *host);
static const fsv_http_cb http_reqhdrs_filter = {
	&http_reqparse, &http_reqparse_ondone
};

static void http_reqhandler(fsv_httphandler *h);
static httptarget* http_findroute(httpcon *c);
static const fsv_http_cb http_reqproc_filter = {
	&http_reqhandler, NULL
};

static void http_bodyrecv(fsv_httphandler *h);
static void http_bodyrecv_ondone(fsv_httphandler *h);
static void http_readbody(void *udata);
static const fsv_http_cb http_recvbody_filter = {
	&http_bodyrecv, &http_bodyrecv_ondone
};

static void http_bodyprovide(fsv_httphandler *h);
static void http_hangupwatch(void *udata);
static const fsv_http_cb http_prebuf_filter = {
	&http_bodyprovide, NULL
};
static void http_bodyconsume(fsv_httphandler *h);
static void http_bodyconsume_ondone(fsv_httphandler *h);
static const fsv_http_cb http_reqbody_filter = {
	&http_bodyconsume, &http_bodyconsume_ondone
};

static void http_chunked_req(fsv_httphandler *h);
static void http_chunked_req_ondone(fsv_httphandler *h);
static const fsv_http_cb http_chunked_req_filter = {
	&http_chunked_req, &http_chunked_req_ondone
};
static void http_chunked_resp(fsv_httphandler *h);
static void http_chunked_resp_ondone(fsv_httphandler *h);
static const fsv_http_cb http_chunked_resp_filter = {
	&http_chunked_resp, &http_chunked_resp_ondone
};

static void http_contlen_req(fsv_httphandler *h);
static void http_contlen_req_ondone(fsv_httphandler *h);
static const fsv_http_cb http_contlen_recv_filter = {
	&http_contlen_req, &http_contlen_req_ondone
};
static void http_contlen_resp(fsv_httphandler *h);
static const fsv_http_cb http_contlen_resp_filter = {
	&http_contlen_resp, NULL
};

static void http_resphdrs(fsv_httphandler *h);
static void http_resphdrs_ondone(fsv_httphandler *h);
static void http_addhdrs(httpcon *c, const char *phdrs, size_t len, ffhttp_cook *resp);
static int http_addhdrs_fromconf(httpcon *c, ffhttp_cook *resp);
static const fsv_http_cb http_resphdrs_filter = {
	&http_resphdrs, &http_resphdrs_ondone
};

static void http_respsend(fsv_httphandler *h);
static void http_respsend_ondone(fsv_httphandler *h);
static void http_sendresponse(void *udata);
static const fsv_http_cb http_sender_filter = {
	&http_respsend, &http_respsend_ondone
};

static const http_submod def_reqfilts[] = {
	{ "recv-req", NULL, &http_recv_hdrs_filter }
	, { "parse-req", NULL, &http_reqhdrs_filter }
	, { "process-req", NULL, &http_reqproc_filter }

	, { "recv-body", NULL, &http_recvbody_filter }
	, { "cont-len", NULL, &http_contlen_recv_filter }
	, { "chunked", NULL, &http_chunked_req_filter }
	, { "pre-buf", NULL, &http_prebuf_filter }
};

static const http_submod def_respfilts[] = {
	{ "req-body", NULL, &http_reqbody_filter }
	, { "cont-len", NULL, &http_contlen_resp_filter }
	, { "chunked", NULL, &http_chunked_resp_filter }
	, { "make-resp", NULL, &http_resphdrs_filter }
	, { "send-resp", NULL, &http_sender_filter }
};

void http_get_def_reqfilts(const http_submod **sm, size_t *n)
{
	*sm = def_reqfilts;
	*n = FFCNT(def_reqfilts);
}
void http_get_def_respfilts(const http_submod **sm, size_t *n)
{
	*sm = def_respfilts;
	*n = FFCNT(def_respfilts);
}


static void http_resettimer(httpcon *c, int t)
{
	int val = 0;
	uint tmr_when;

	if (c->tmr_flags & t)
		return;

	if (t & TMR_READHDR)
		val = (c->notstarted) ? httpm->keepalive_tmout : httpm->read_header_tmout;
	else if (t & TMR_READBODY)
		val = c->host->read_body_tmout;
	else if (t & TMR_WRITE)
		val = c->host->write_tmout;

	tmr_when = httpm->core->fsv_gettime().s + val;
	if (tmr_when <= c->tmr_when)
		return;

	dbglog(c->logctx, FSV_LOG_DBGNET, "timer set: %us", val);

	c->tmr_flags = t;
	c->tmr_when = tmr_when;
	httpm->core->timer(&c->tmr, -val * 1000, &http_onexpire, c);
}

static void http_stoptimer(httpcon *c, int t)
{
	if (!(c->tmr_flags & t))
		return;

	c->tmr_when = 0;
	if (c->tmr_flags & ~t) {
		t = (c->tmr_flags & ~t);
		c->tmr_flags = 0;
		http_resettimer(c, t);
		return;
	}

	c->tmr_flags = 0;
	dbglog(c->logctx, FSV_LOG_DBGNET, "timer stop");
	httpm->core->fsv_timerstop(&c->tmr);
}

static void http_onexpire(const fftime *now, void *udata)
{
	httpcon *c = udata;
	c->tmr_when = 0;
	c->tmr_flags = 0;
	httpm->lisn->cancelio(c->conn, FFAIO_RW, NULL, c);
}


static void http_reqrecv(fsv_httphandler *h)
{
	httpcon *c = (httpcon*)h->httpcon;

	if (h->id->udata == NULL) {
		h->id->udata = (void*)1;

		if (c->pipelined) {
			c->pipelined = 0;
			dbglog(c->logctx, FSV_LOG_DBGFLOW, "have %L bytes of pipelined data"
				, c->reqhdrbuf.len);
			h->http->send(h->id, c->reqhdrbuf.ptr, c->reqhdrbuf.len, FSV_HTTP_MORE);
			return;
		}
	}

	c->hfrecv = h->id;
	http_readrequest(c);
}

static void http_reqrecv_ondone(fsv_httphandler *h)
{
	httpcon *c = (httpcon*)h->httpcon;
	http_stoptimer(c, TMR_READHDR);
}

/** Receive request.*/
static void http_readrequest(void *udata)
{
	httpcon *c = udata;
	ssize_t r;

	// note: max_header_size must be a multiple of read_header_growby
	if (ffarr_isfull(&c->reqhdrbuf)
		&& NULL == ffarr_grow(&c->reqhdrbuf, httpm->read_header_growby, 0)) {

		syserrlog(c->logctx, FSV_LOG_ERR, "receive request: %e", FFERR_BUFGROW);
		ffhttp_setstatus(&c->resp, FFHTTP_500_INTERNAL_SERVER_ERROR);
		goto fail;
	}

	r = httpm->lisn->recv(c->conn, ffarr_end(&c->reqhdrbuf), ffarr_unused(&c->reqhdrbuf), NULL, NULL);

	if (r == FSV_IO_EAGAIN) {
		r = httpm->lisn->recv(c->conn, NULL, 0, &http_readrequest, c);

		if (r == FSV_IO_ASYNC) {
			http_resettimer(c, TMR_READHDR);
			return;
		}
	}

	http_stoptimer(c, TMR_READHDR);

	if (c->notstarted) {
		c->notstarted = 0;
		c->start_time = httpm->core->fsv_gettime();

		if (r == FSV_IO_ESHUT || r == FSV_IO_ERR) {
			http_close(c);
			return;
		}
	}

	if (r == FSV_IO_ESHUT) {
		errlog(c->logctx, FSV_LOG_ERR, "receive request: client closed the connection unexpectedly");
		ffhttp_setstatus(&c->resp, FFHTTP_400_BAD_REQUEST);
		goto fail;

	} else if (r == FSV_IO_ERR) {
		if (fferr_last() == ECANCELED)
			errlog(c->logctx, FSV_LOG_ERR, "receive request: time out");
		else
			syserrlog(c->logctx, FSV_LOG_ERR, "%s", "receive request");
		http_close(c);
		return;
	}

	c->reqhdrbuf.len += r;
	c->nread += r;
	ffatom_add(&httpm->allread, r);

	dbglog(c->logctx, FSV_LOG_DBGNET, "received data +%L [%U]  \"%*s\""
		, r, c->nread
		, ffmin(r, HTTP_LOG_READ_DATAWND), ffarr_end(&c->reqhdrbuf) - r);

	fsv_http_iface.send(c->hfrecv, c->reqhdrbuf.ptr, c->reqhdrbuf.len, FSV_HTTP_MORE);
	return;

fail:
	fsv_http_iface.send(c->hfrecv, NULL, 0, FSV_HTTP_ERROR);
}


/** Parse request.
All data received beyond the end of request (if any) is passed to the next filter. */
static void http_reqparse(fsv_httphandler *h)
{
	httpcon *c = (httpcon*)h->httpcon;
	int r = FFHTTP_OK, f;
	ffstr reqdata, nextdata;

	FF_ASSERT(h->data->ht.hdr_cnt == 1);
	ffstr_setiovec(&reqdata, &h->data->ht.headers[0]);

	if (h->id->udata == NULL) {
		h->id->udata = c;
		ffhttp_reqinit(h->req);
		ffatom_inc(&httpm->req_count);
	}

	if (h->req->h.firstline_len == 0)
		r = ffhttp_reqparse(h->req, reqdata.ptr, reqdata.len);

	while (r == FFHTTP_OK) {
		r = ffhttp_reqparsehdr(h->req, reqdata.ptr, reqdata.len);
	}

	if (r == FFHTTP_MORE) {
		if (reqdata.len == httpm->max_header_size) {
			errlog(h->logctx, FSV_LOG_ERR, "parse request: reached max_header_size limit");
			ffhttp_setstatus(h->resp, FFHTTP_413_REQUEST_ENTITY_TOO_LARGE);
			f = FSV_HTTP_ERROR;
			goto done;
		}

		f = FSV_HTTP_BACK;
		goto done;

	} else if (r != FFHTTP_DONE) {
		errlog(h->logctx, FSV_LOG_ERR, "parse request: at byte #%u: %s"
			, (int)h->req->h.len, ffhttp_errstr(r));
		ffhttp_setstatus(h->resp, FFHTTP_400_BAD_REQUEST);
		f = FSV_HTTP_ERROR;
		goto done;
	}

	c->keep_alive = !h->req->h.has_body;

	{
	ffstr shost = ffhttp_reqhost(h->req);
	if (0 != http_sethost(c, &shost)) {
		f = FSV_HTTP_ERROR;
		goto done;
	}
	}

	if (fsv_log_checkdbglevel(h->logctx, FSV_LOG_DBGNET))
		http_printreq(c);

	ffstr_set(&nextdata, reqdata.ptr + h->req->h.len, reqdata.len - h->req->h.len);
	h->http->send(h->id, nextdata.ptr, nextdata.len, FSV_HTTP_NOINPUT);
	return;

done:
	h->http->send(h->id, NULL, 0, f);
}

static void http_reqparse_ondone(fsv_httphandler *h)
{
	httpcon *c = h->id->udata;

	http_accesslog(c);
}

/** Set HTTP host from request. */
static int http_sethost(httpcon *c, const ffstr *shost)
{
	httphost *host;

	if (c->host->sslctx != NULL
		&& 0 != http_ssl_checkservname(c, shost)) {
		ffhttp_setstatus(&c->resp, FFHTTP_400_BAD_REQUEST);
		return 1;
	}

	host = http_gethost(c->conn, shost);
	if (host != NULL) {
		c->host = host;
		http_setlog(c, host->logctx);
	} else
		dbglog(c->logctx, FSV_LOG_DBGFLOW, "requested host not found: '%S'", shost);

	return 0;
}

/** Write the received request to log. */
static void http_printreq(httpcon *c)
{
	ffstr req_line = ffhttp_firstline(&c->req.h);
	ffstr hdrs = ffhttp_hdrs(&c->req.h);
	const char *n;

	dbglog(c->logctx, FSV_LOG_DBGNET, "received request on host '%S': [%L] %S"
		, &c->host->name, (size_t)c->req.h.len, &req_line);

	for (;;) {
		n = ffs_findof(hdrs.ptr, hdrs.len, FFSTR("\r\n"));
		if (n == hdrs.ptr)
			break;

		dbglog(c->logctx, FSV_LOG_DBGNET, "request header: %*s"
			, n - hdrs.ptr, hdrs.ptr);

		n += (*n == '\r') ? FFSLEN("\r\n") : FFSLEN("\n");
		ffstr_shift(&hdrs, n - hdrs.ptr);
	}
}

/** Ensure that HTTP host from request matches TLS server name. */
static int http_ssl_checkservname(httpcon *c, const ffstr *host)
{
	ffstr srvname;

	srvname.len = httpm->lisn->getvar(c->conn, FFSTR("ssl_servername"), &srvname.ptr, 0);
	if (srvname.len == -1)
		return 0;

	if (!ffstr_eq2(host, &srvname)) {
		errlog(c->logctx, FSV_LOG_ERR, "HTTP host '%S' does not match TLS server name '%S'"
			, host, &srvname);
		return 1;
	}
	return 0;
}


/** Find an appropriate handler for request. */
static void http_reqhandler(fsv_httphandler *h)
{
	httpcon *c = (httpcon*)h->httpcon;
	const http_submod *sm;
	httptarget *tgt;
	int f = FSV_HTTP_PASS;

	tgt = http_findroute(c);
	if (tgt == NULL) {
		ffhttp_setstatus(h->resp, FFHTTP_404_NOT_FOUND);
		sm = &httpm->err_hdler;
		goto done;
	}

	c->tgt = tgt;
	http_setlog(c, tgt->logctx);
	sm = &tgt->file_hdler;

	{
	ffstr path;
	path = ffhttp_reqpath(&c->req);
	if (ffarr_back(&path) == '/')
		sm = &tgt->dir_hdler;
	}

	if (sm->handler == NULL) {
		c->tgt = NULL;
		errlog(c->logctx, FSV_LOG_ERR, "route '%S': no handler configured", &tgt->path);
		ffhttp_setstatus(&c->resp, FFHTTP_404_NOT_FOUND);
		sm = &httpm->err_hdler;
		goto done;
	}

	if (c->req.method == FFHTTP_CONNECT)
		f |= FSV_HTTP_ASIS;

done:
	if (0 != http_init_respchain(c, sm)) {
		http_close(c);
		return;
	}
	fsv_taskpost(httpm->core, &c->rtask, &http_resptask, c);
	h->http->send(h->id, NULL, 0, f);
}

/** Test regexps one by one. */
static FFINL httptarget* http_findrxroute(const ffstr *path, httptarget *tgt)
{
	httptarget *rxtgt;
	FFLIST_WALK(&tgt->rxroutes, rxtgt, sib) {
		if (0 == ffs_regex(rxtgt->path.ptr, rxtgt->path.len, path->ptr, path->len, 0))
			return rxtgt;
	}
	return tgt;
}

/** Look up the path in routing hash table.
Note: in the worst-case scenario, we perform count('/')+1 attempts. */
static httptarget* http_findroute(httpcon *c)
{
	ffstr path = ffhttp_reqpath(&c->req), reqpath = path;
	httptarget *tgt;
	uint hash;
	char *slash;

	for (;;) {
		hash = ffcrc32_get(path.ptr, path.len, FFCRC_ICASE);
		tgt = ffhst_find(&c->host->hstroute, hash, path.ptr, path.len, NULL);
		if (tgt != NULL) {

			if (tgt->ispath) {
				ffstr_shift(&reqpath, path.len);
				tgt = http_findrxroute(&reqpath, tgt);
				break; //"path=/" or its "target_regex=.bc" matches URI "/abc"

			} else if (path.len == reqpath.len)
				break; //target "/abc" matches URI "/abc"
		}

		slash = ffs_rfind(path.ptr, path.len, '/');

		if (path.len == FFSLEN("/") || slash == path.ptr + path.len) {
			if (c->host->anytarget == NULL) {
				errlog(c->logctx, FSV_LOG_ERR, "unknown route in request URL");
				return NULL;
			}

			tgt = c->host->anytarget;
			break;
		}

		if (slash == path.ptr)
			path.len = FFSLEN("/");
		else
			path.len = slash - path.ptr;
	}

	//note: for "target_regex" only regexp is printed here (without the full path)
	dbglog(c->logctx, FSV_LOG_DBGFLOW, "using route '%S'", &tgt->path);
	return tgt;
}


/** Receive request body. */
static void http_bodyrecv(fsv_httphandler *h)
{
	httpcon *c = (httpcon*)h->httpcon;
	int f;
	size_t cap;

	if (h->id->udata == NULL) {
		h->id->udata = (void*)1;

		if (!h->req->h.has_body && !(h->flags & FSV_HTTP_ASIS)) {
			f = FSV_HTTP_DONE;
			goto done;
		}

		if (!ffsf_empty(h->data)) {
			f = FSV_HTTP_PASS | FSV_HTTP_MORE;
			goto done;
		}
	}

	if (c->reqbodybuf.cap == 0) {
		cap = c->host->reqbody_buf_size;
		if (c->req.h.cont_len != -1 && !c->req.h.chunked) {
			//don't allocate more memory than content-length
			cap = (size_t)ffmin64(c->req.h.cont_len, c->host->reqbody_buf_size);
		}
		if (NULL == ffarr_alloc(&c->reqbodybuf, cap)) {
			syserrlog(c->logctx, FSV_LOG_ERR, "%e", FFERR_BUFALOC);
			f = FSV_HTTP_ERROR;
			goto done;
		}
	}

	c->hfrecv = h->id;
	http_readbody(h->httpcon);
	return;

done:
	h->http->send(h->id, NULL, 0, f);
}

static void http_bodyrecv_ondone(fsv_httphandler *h)
{
	httpcon *c = (httpcon*)h->httpcon;

	if (!h->resp->conn_close) {

		if (c->reqhdrbuf.len == h->req->h.len || h->req->h.has_body) {
			ffmem_zero(c->reqhdrbuf.ptr, c->reqhdrbuf.len);
			c->reqhdrbuf.len = 0;

		} else {
			// shift pipelined data
			char *d = c->reqhdrbuf.ptr + h->req->h.len;
			size_t n = c->reqhdrbuf.len - h->req->h.len;
			ffmemcpy(c->reqhdrbuf.ptr, d, n);
			ffmem_zero(c->reqhdrbuf.ptr + n, c->reqhdrbuf.len - n);
			c->reqhdrbuf.len = n;
			c->pipelined = 1;
		}
	}

	http_stoptimer(c, TMR_READBODY);
	ffarr_free(&c->reqbodybuf);
}

static void http_readbody(void *udata)
{
	httpcon *c = udata;
	ssize_t r;
	int f;

	r = httpm->lisn->recv(c->conn, c->reqbodybuf.ptr, c->reqbodybuf.cap, NULL, NULL);

	if (r == FSV_IO_EAGAIN) {
		r = httpm->lisn->recv(c->conn, NULL, 0, &http_readbody, c);

		if (r == FSV_IO_ASYNC) {
			http_resettimer(c, TMR_READBODY);
			return;
		}
	}

	http_stoptimer(c, TMR_READBODY);

	if (r == FSV_IO_ESHUT) {

		if (((httpfilter*)c->hfrecv)->flags & FSV_HTTP_ASIS) {
			dbglog(c->logctx, FSV_LOG_DBGNET, "receive data: TCP FIN");
			f = 0;
			goto fail;
		}

		f = FSV_HTTP_ERROR;
		errlog(c->logctx, FSV_LOG_ERR, "receive request body: client closed connection");
		goto fail;

	} else if (r == FSV_IO_ERR) {

		if (fferr_last() == ECANCELED) {
			errlog(c->logctx, FSV_LOG_ERR, "receive request body: time out");
			http_close(c);
			return;

		} else
			syserrlog(c->logctx, FSV_LOG_ERR, "%s", "receive request body");

		f = FSV_HTTP_ERROR;
		goto fail;
	}

	c->reqbodybuf.len = r;
	c->nread += r;
	ffatom_add(&httpm->allread, r);

	dbglog(c->logctx, FSV_LOG_DBGNET, "received data +%L [%U]  \"%*s\""
		, r, c->nread - c->reqbodybuf.len
		, ffmin(r, HTTP_LOG_READ_DATAWND), ffarr_end(&c->reqbodybuf) - r);

	fsv_http_iface.send(c->hfrecv, c->reqbodybuf.ptr, c->reqbodybuf.len, FSV_HTTP_MORE);
	return;

fail:
	fsv_http_iface.send(c->hfrecv, NULL, 0, f);
}


/** Detect the situation when a client closes connection while his request is still being processed. */
static void http_hangupwatch(void *udata)
{
	httpcon *c = udata;
	ssize_t r = 0;

	if (c->hupwatch) {
		c->hupwatch = 0;
		r = httpm->lisn->recv(c->conn, NULL, 0, NULL, NULL);

#ifdef FF_WIN
		if (r == 0) {
			dbglog(c->logctx, FSV_LOG_DBGNET, "hangup watch: data pending");
			return;
		}
#endif
	}

	if (r == 0 || r == FSV_IO_EAGAIN) {
		r = httpm->lisn->recv(c->conn, NULL, 0, &http_hangupwatch, c);

		if (r == FSV_IO_ASYNC) {
			c->hupwatch = 1;
			dbglog(c->logctx, FSV_LOG_DBGNET, "hangup watch: started");
			return;
		}
	}

	// if (r == FSV_IO_ERR)
	syserrlog(c->logctx, FSV_LOG_ERR, "%s", "hangup watch");
	http_close(c);
}

/** Pass request body to the filters in response chain.
Watch for hangup signal from the client until this data chunk is processed. */
static void http_bodyprovide(fsv_httphandler *h)
{
	httpcon *c = (httpcon*)h->httpcon;

	if (h->flags & FSV_HTTP_LAST)
		c->body_fin = 1;

	if (c->body_skip) {

		if (!c->body_fin) {
			h->http->send(h->id, NULL, 0, FSV_HTTP_BACK);
			return;

		} else if (c->respmain_fin) {
			h->http->send(h->id, NULL, 0, 0);
			return;
		}

	} else {

		c->body_ready = 1;

		if (c->want_readbody) {
			c->want_readbody = 0;
			fsv_taskpost(httpm->core, &c->rtask, &http_resptask, c);
		}
	}

	http_hangupwatch(c);
}

/** Continue reading request body or finish the request chain. */
void http_bodyprovide_continue(httpcon *c)
{
	httpfilter *prebuf = &ffarr_back(&c->reqchain);

	if (c->body_fin && c->respmain_fin) {
		fsv_http_iface.send((fsv_httpfilter*)prebuf, NULL, 0, 0);
		return; //request is done
	}

	if (!c->body_ready)
		return; //we're reading the body
	c->body_ready = 0;

	if (c->body_fin)
		return; //body is complete, just watch for hangup

	fsv_http_iface.send((fsv_httpfilter*)prebuf, NULL, 0, FSV_HTTP_BACK);
}


/** Get request body from the filters in request chain. */
static void http_bodyconsume(fsv_httphandler *h)
{
	httpcon *c = (httpcon*)h->httpcon;

	if (h->id->udata == NULL)
		h->id->udata = (void*)1;

	if (h->flags & FSV_HTTP_FIN) {
		// main handler doesn't want more body
		c->body_skip = 1;
		http_bodyprovide_continue(c);
		return;
	}

	if (h->flags & FSV_HTTP_SENT) {
		// a chunk of request body is processed
		c->want_readbody = 1;
		http_bodyprovide_continue(c);
		return;
	}

	if (c->body_skip) {
		h->http->send(h->id, NULL, 0, 0);
		return;
	}

	if (!c->body_ready) {
		// body hasn't been received yet
		int f = (c->body_fin) ? 0 : FSV_HTTP_MORE;
		h->http->send(h->id, NULL, 0, f);
		return;
	}

	{
	httpfilter *prebuf = &ffarr_back(&c->reqchain);
	ffsf *data = &prebuf->input;
	int f = (c->body_fin) ? 0 : FSV_HTTP_MORE;
	h->http->sendfile(h->id, data->fm.fd, data->fm.fsize, data->fm.foff, &data->ht, f);
	}
}

static void http_bodyconsume_ondone(fsv_httphandler *h)
{
	httpcon *c = (httpcon*)h->httpcon;
	c->want_readbody = 0;
	c->body_skip = 1; //in case when we're sending error response, noone asks for request body
}


/** Determine the end of request body by Content-Length in request. */
static void http_contlen_req(fsv_httphandler *h)
{
	httpcon *c = (httpcon*)h->httpcon;
	ffstr body = {0};
	uint64 body_recvd = c->nread - h->req->h.len;
	uint64 cont_len = h->req->h.cont_len;
	int f;

	if (h->id->udata == NULL) {
		if (h->req->h.cont_len == -1 || h->req->h.chunked) {
			f = FSV_HTTP_PASS | FSV_HTTP_DONE;
			goto done;
		}

		if (cont_len > c->host->max_reqbody) {
			errlog(c->logctx, FSV_LOG_ERR, "cont-len: Content-Length in request is larger than max_request_body limit");
			if (h->resp->code == 0)
				ffhttp_setstatus(h->resp, FFHTTP_413_REQUEST_ENTITY_TOO_LARGE);
			f = FSV_HTTP_ERROR;
			goto done;
		}

		h->id->udata = (void*)1;
	}

	if (h->data->ht.hdr_cnt != 0) {
		ffstr_setiovec(&body, &h->data->ht.headers[0]);
		if (body_recvd > cont_len)
			body.len -= body_recvd - cont_len;
	}
	FF_ASSERT(h->data->fm.fsize == 0 && h->data->ht.trl_cnt == 0);

	f = 0;
	if (body_recvd == cont_len) {
		f = FSV_HTTP_NOINPUT;
		c->keep_alive = 1;

	} else if (body_recvd > cont_len) {
		errlog(h->logctx, FSV_LOG_INFO, "cont-len: pipelined request with body is not supported");
		f = FSV_HTTP_NOINPUT;

	} else if (h->flags & FSV_HTTP_LAST) {
		errlog(h->logctx, FSV_LOG_ERR, "cont-len: incomplete input data");
		f = FSV_HTTP_ERROR;
		goto done;
	}

	h->http->send(h->id, body.ptr, body.len, f);
	return;

done:
	h->http->send(h->id, NULL, 0, f);
}

static void http_contlen_req_ondone(fsv_httphandler *h)
{
}

/** Set Content-Length in response, if appropriate. */
static void http_contlen_resp(fsv_httphandler *h)
{
	if ((h->flags & FSV_HTTP_LAST) && !(h->flags & FSV_HTTP_ASIS)
		&& h->resp->cont_len == -1 && h->resp->trans_enc.len == 0
		&& !ffhttp_respnobody(h->resp->code)) {

		h->resp->cont_len = ffsf_len(h->data);
	}

	h->http->send(h->id, NULL, 0, FSV_HTTP_PASS | FSV_HTTP_DONE);
}


/** Process request body with Transfer-Encoding:chunked. */
static void http_chunked_req(fsv_httphandler *h)
{
	httpcon *c = (httpcon*)h->httpcon;
	ffstr chunk = {0};
	int r, f, havemore;
	size_t datalen;

	if (h->id->udata == NULL) {
		if (!h->req->h.chunked) {
			f = FSV_HTTP_PASS | FSV_HTTP_DONE;
			goto done;
		}

		ffhttp_chunkinit(&c->chunked);
		h->id->udata = (void*)1;
	}

	FF_ASSERT(h->data->ht.hdr_cnt == 1);
	datalen = h->data->ht.headers[0].iov_len;
	r = ffhttp_chunkparse(&c->chunked, h->data->ht.headers[0].iov_base, &datalen, &chunk);
	havemore = ffsf_shift(h->data, datalen);

	switch (r) {
	case FFHTTP_OK:
		h->http->send(h->id, chunk.ptr, chunk.len, (havemore) ? FSV_HTTP_MORE : 0);
		return;

	case FFHTTP_MORE:
		f = 0;
		if (h->flags & FSV_HTTP_LAST) {
			errlog(h->logctx, FSV_LOG_ERR, "chunked: incomplete input data");
			f = FSV_HTTP_ERROR;
		}
		break;

	case FFHTTP_DONE:
		if (havemore)
			errlog(h->logctx, FSV_LOG_INFO, "chunked: pipelined request with body is not supported");
		else
			c->keep_alive = 1;

		f = FSV_HTTP_NOINPUT;
		break;

	default:
		errlog(h->logctx, FSV_LOG_ERR, "chunked: parse: %s", ffhttp_errstr(r));
		f = FSV_HTTP_ERROR;
		break;
	}

done:
	h->http->send(h->id, NULL, 0, f);
}

static void http_chunked_req_ondone(fsv_httphandler *h)
{
}


/** Use Transfer-Encoding:chunked when sending data. */
static void http_chunked_resp(fsv_httphandler *h)
{
	sf_hdtr *ht;
	sf_hdtr ht_out;
	httpcon *c = (httpcon*)h->httpcon;
	int r, f;
	const char *pchunk_ftr;
	uint64 all_size;

	if (h->id->udata == NULL) {
		if (h->resp->cont_len != -1
			|| h->resp->trans_enc.len != 0 || !h->req->accept_chunked
			|| ffhttp_respnobody(h->resp->code)
			|| (h->flags & FSV_HTTP_ASIS)) {

			f = FSV_HTTP_PASS | FSV_HTTP_DONE;
			goto done;
		}

		h->id->udata = c;
		ffstr_setcz(&h->resp->trans_enc, "chunked");
	}

	all_size = ffsf_len(h->data);
	if (all_size == 0) {
		if (h->flags & FSV_HTTP_LAST) {
			r = ffhttp_chunkfin(&pchunk_ftr, FFHTTP_CHUNKZERO);
			h->http->send(h->id, pchunk_ftr, r, 0);
			return;
		}

		f = FSV_HTTP_BACK;
		goto done;
	}

	ht = &h->data->ht;

	if (NULL == ffarr_realloc(&c->chunked_iovs, 1 + ht->hdr_cnt + ht->trl_cnt + 1)) {
		syserrlog(c->logctx, FSV_LOG_ERR, "%e", FFERR_BUFALOC);
		f = FSV_HTTP_ERROR;
		goto done;
	}

	r = ffhttp_chunkbegin(c->chunk_hdr, sizeof(c->chunk_hdr), all_size);
	ffiov_set(c->chunked_iovs.ptr, c->chunk_hdr, r);

	c->chunked_iovs.len = 2 + ffiov_copyhdtr(c->chunked_iovs.ptr + 1, c->chunked_iovs.cap - 2, ht);

	r = ffhttp_chunkfin(&pchunk_ftr, (h->flags & FSV_HTTP_LAST) ? FFHTTP_CHUNKLAST : 0);
	ffiov_set(c->chunked_iovs.ptr + 1 + ht->hdr_cnt + ht->trl_cnt, pchunk_ftr, r);

	if (h->data->fm.fsize != 0 || ht->trl_cnt != 0)
		ffsf_sethdtr(&ht_out, c->chunked_iovs.ptr, 1 + ht->hdr_cnt, c->chunked_iovs.ptr + 1 + ht->hdr_cnt, ht->trl_cnt + 1);
	else {
		// if there's no file then don't use trailers
		ffsf_sethdtr(&ht_out, c->chunked_iovs.ptr, 1 + ht->hdr_cnt + 1, NULL, 0);
	}
	h->http->sendfile(h->id, h->data->fm.fd, h->data->fm.fsize, h->data->fm.foff, &ht_out, 0);
	return;

done:
	h->http->send(h->id, NULL, 0, f);
}

static void http_chunked_resp_ondone(fsv_httphandler *h)
{
	httpcon *c = h->id->udata;
	ffarr_free(&c->chunked_iovs);
}


/** Prepare to send HTTP headers. */
static void http_resphdrs(fsv_httphandler *h)
{
	httpcon *c = (httpcon*)h->httpcon;
	ffhttp_cook *resp = h->resp;
	char dt[64];
	ffstr hdrs = {0};
	size_t i;
	ffiovec *iov;

	ffstr_acqstr3(&hdrs, &resp->buf);

	if (resp->code == 0)
		ffhttp_setstatus(resp, FFHTTP_500_INTERNAL_SERVER_ERROR);
	ffhttp_addstatus(resp);

	if (resp->date.len == 0) {
		httpm->core->gettime4(NULL, dt, FFCNT(dt), FSV_TIME_WDMY);
		ffstr_setz(&resp->date, dt);
	}

	if (resp->cont_type.len == 0 && !ffsf_empty(h->data))
		resp->cont_type = c->host->def_mime_type;

	/* use "Connection: close":
	if set by a filter
	or client doesn't support keep-alive
	or reached max keep-alive requests limit
	or the response is without both Content-Length and Transfer-Encoding. */
	if (!resp->conn_close
		&& (!c->keep_alive || h->req->h.conn_close
			|| c->keepalive_cnt++ == httpm->max_keepalive_requests
			|| (!ffhttp_respnobody(resp->code) && resp->cont_len == -1 && resp->trans_enc.len == 0)))
		resp->conn_close = 1;

	ffhttp_addihdr(resp, FFHTTP_SERVER, FFSTR("fserv/" FSV_VER));
	ffhttp_cookflush(resp);

	http_addhdrs(c, hdrs.ptr, hdrs.len, resp);
	ffstr_free(&hdrs);
	if (0 != http_addhdrs_fromconf(c, resp))
		goto fail;

	if (0 != ffhttp_cookfin(resp)) {
		syserrlog(h->logctx, FSV_LOG_ERR, "%e", FFERR_BUFALOC);
		goto fail;
	}
	c->resplen = c->resp.buf.len;

	dbglog(c->logctx, FSV_LOG_DBGFLOW, "response headers: [%L] %S", c->resp.buf.len, &c->resp.buf);

	if (h->req->method == FFHTTP_HEAD) {
		h->http->send(h->id, c->resp.buf.ptr, c->resp.buf.len, FSV_HTTP_NOINPUT);
		return;
	}

	//insert HTTP headers buffer into the chain of 'ffiovec' headers
	c->hdr_iovs = ffmem_tcalloc(ffiovec, 1 + h->data->ht.hdr_cnt);
	if (c->hdr_iovs == NULL) {
		syserrlog(h->logctx, FSV_LOG_ERR, "%e", FFERR_BUFALOC);
		goto fail;
	}
	h->id->udata = (void*)1;

	iov = c->hdr_iovs;
	ffiov_set(iov, c->resp.buf.ptr, c->resp.buf.len);
	iov++;
	for (i = 0;  i < h->data->ht.hdr_cnt;  i++) {
		*iov++ = h->data->ht.headers[i];
	}
	h->data->ht.headers = c->hdr_iovs;
	h->data->ht.hdr_cnt = (uint)(iov - c->hdr_iovs);

	h->http->sendfile(h->id, h->data->fm.fd, h->data->fm.fsize, h->data->fm.foff, &h->data->ht, FSV_HTTP_DONE);
	return;

fail:
	ffstr_free(&hdrs);
	h->http->send(h->id, NULL, 0, FSV_HTTP_ERROR);
}

static void http_resphdrs_ondone(fsv_httphandler *h)
{
	httpcon *c = (httpcon*)h->httpcon;
	ffmem_free(c->hdr_iovs);
}

/** Add response headers set by filters. */
static void http_addhdrs(httpcon *c, const char *phdrs, size_t len, ffhttp_cook *resp)
{
	ffstr hdrs;
	ffhttp_hdr state;

	ffstr_set(&hdrs, phdrs, len);
	ffhttp_inithdr(&state);

	while (FFHTTP_OK == ffhttp_nexthdr(&state, hdrs.ptr, hdrs.len)) {
		ffstr key = ffrang_get(&state.key, hdrs.ptr);
		ffstr hvalue = ffrang_get(&state.val, hdrs.ptr);

		if (state.ihdr != FFHTTP_SERVER) {
			ffhttp_addhdr(resp, key.ptr, key.len, hvalue.ptr, hvalue.len);
		}
	}
}

/** Add response headers specified in configuration. */
static int http_addhdrs_fromconf(httpcon *c, ffhttp_cook *resp)
{
	ffstr name, val;
	ffstr3 tmp = {0};
	int res = 0;
	size_t off = 0;

	for (;;) {

		if (0 == ffbstr_next(c->host->resp_hdrs.ptr, c->host->resp_hdrs.len, &off, &name)
			|| 0 == ffbstr_next(c->host->resp_hdrs.ptr, c->host->resp_hdrs.len, &off, &val))
			break;

		if (0 != httpm->core->process_vars(&tmp, &val, fsv_http_iface.getvar, c, c->logctx)) {
			res = 1;
			goto done;
		}

		ffhttp_addhdr(resp, name.ptr, name.len, tmp.ptr, tmp.len);
	}

done:
	ffarr_free(&tmp);
	return res;
}


/** Send response (headers + body) to client. */
static void http_respsend(fsv_httphandler *h)
{
	httpcon *c = (httpcon*)h->httpcon;

	if (h->id->udata == NULL)
		h->id->udata = (void*)1;

	if (ffsf_empty(h->data)) {
		ffskt sk;

		dbglog(h->logctx, FSV_LOG_DBGNET, "socket shutdown");
		httpm->lisn->getvar(c->conn, FFSTR("socket_fd"), &sk, sizeof(ffskt));
		ffskt_fin(sk);
		c->skshut = 1;

		fsv_http_iface.send(h->id, NULL, 0, FSV_HTTP_DONE);
		return;
	}

	c->hfsend = h->id;
	http_sendresponse(c);
}

static void http_respsend_ondone(fsv_httphandler *h)
{
	httpcon *c = (httpcon*)h->httpcon;
	http_stoptimer(c, TMR_WRITE);
}

static void http_sendresponse(void *udata)
{
	httpcon *c = udata;
	ffsf *sf = &((httpfilter*)c->hfsend)->input;
	ssize_t r;

	for (;;) {
		r = httpm->lisn->sendfile(c->conn, sf, NULL, NULL);

		if (r == FSV_IO_EAGAIN) {
			r = httpm->lisn->sendfile(c->conn, sf, &http_sendresponse, c);

			if (r == FSV_IO_ASYNC) {
				http_resettimer(c, TMR_WRITE);
				return;
			}
		}

		http_stoptimer(c, TMR_WRITE);

		if (r == FSV_IO_ERR) {

			if (fferr_last() == ECANCELED)
				errlog(c->logctx, FSV_LOG_ERR, "sending response: time out");
			else
				syserrlog(c->logctx, FSV_LOG_ERR, "%s", "sending response");

			http_close(c);
			return;
		}

		c->nwrite += r;
		ffatom_add(&httpm->allwritten, r);

		dbglog(c->logctx, FSV_LOG_DBGNET, "sent data: +%L [%U]"
			, r, c->nwrite);

		if (0 == ffsf_shift(sf, r))
			break;
	}

	fsv_http_iface.send(c->hfsend, NULL, 0, 0);
}

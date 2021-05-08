/**
Copyright 2014 Simon Zolin
*/

#include <test/tests.h>
#include <FFOS/test.h>
#include <FFOS/thread.h>
#include <FFOS/process.h>
#include <FF/list.h>
#include <FF/net/url.h>
#include <FF/net/http.h>

#define x  FFTEST_BOOL

typedef struct test_http_s {
	tester *t;
	ffstr addr;
	fflist reqs; //test_http_req[]
	fsv_task task;
} test_http_s;

typedef struct test_http_req {
	fflist_item li;
	ffstr req;
	unsigned fin :1;
} test_http_req;

static test_http_s *ht;

static int test_http_conf_req(ffparser_schem *ps, test_http_s *h, const ffstr *val);
static void test_http_fin(void *param);


static void test_http_req_destroy(test_http_req *rq)
{
	ffstr_free(&rq->req);
	ffmem_free(rq);
}

static void test_http_fin(void *param)
{
	tester *t = ht->t;
	FFLIST_ENUMSAFE(&ht->reqs, test_http_req_destroy, test_http_req, li);
	ffstr_free(&ht->addr);
	ffmem_free(ht);
	ht = NULL;

	testm_runnext(t);
}

static size_t test_http_recvhdrs(ffskt sk, ffhttp_response *resp)
{
	char buf[4096];
	ssize_t r, nresp;
	int n;

	nresp = 0;

	for (;;) {
		r = ffskt_recv(sk, buf, sizeof(buf), 0);
		x(r > 0);
		nresp += r;

		if (resp->code == 0) {
			n = ffhttp_respparse(resp, buf, nresp, 0);
			if (n == FFHTTP_MORE)
				continue;
			x(n == FFHTTP_OK);
		}

		n = ffhttp_respparsehdrs(resp, buf, nresp);
		if (n == FFHTTP_MORE)
			continue;
		if (n == FFHTTP_DONE)
			break;
		x(n == FFHTTP_OK);
	}

	fsv_dbglog(ht->t->logctx, FSV_LOG_DBGNET, "HTST", NULL, "received response: [%u] %*s"
		, resp->h.len, (size_t)resp->h.len, buf);

	return r;
}

static int test_http_recvbody(ffskt sk, ffhttp_response *resp, size_t rresp)
{
	ffhttp_chunked chunked;
	char body[16 * 1024];
	ffstr sbody;
	ssize_t r;
	int n;

	ffhttp_chunkinit(&chunked);
	ffstr_set(&sbody, resp->h.base + resp->h.len, rresp - resp->h.len);

	for (;;) {

		if (!resp->h.has_body)
			break;

		if (sbody.len == 0) {
			r = ffskt_recv(sk, body, sizeof(body), 0);

			if (r == 0)
				return 1;

			x(r > 0);
			ffstr_set(&sbody, body, r);
		}

		fsv_dbglog(ht->t->logctx, FSV_LOG_DBGNET, "HTST", NULL, "received body: [%L] %S"
			, sbody.len, &sbody);

		if (resp->h.cont_len != -1) {
			x((uint64)resp->h.cont_len >= sbody.len);
			resp->h.cont_len -= sbody.len;
			if (resp->h.cont_len == 0)
				break;

		} else if (resp->h.chunked) {
			size_t t;
			char *start = sbody.ptr, *end = ffarr_end(&sbody);

			for (;;) {
				t = end - start;
				n = ffhttp_chunkparse(&chunked, start, &t, &sbody);
				if (n == FFHTTP_DONE || n == FFHTTP_MORE)
					break;
				x(n == FFHTTP_OK);
				start += t;
			}

			if (n == FFHTTP_DONE)
				break;
		}

		sbody.len = 0;
	}

	return 0;
}

static int FFTHDCALL test_http_run(void *udata)
{
	ffaddr a;
	ffskt sk = FF_BADSKT;
	test_http_req *rq;
	ssize_t r;
	ffurl u;
	ffstr host, port;
	ffhttp_response resp;
	uint ireq = 0;

	FFTEST_FUNC;

	ffhttp_initheaders();

	ffurl_init(&u);
	x(0 == ffurl_parse(&u, ht->addr.ptr, ht->addr.len));
	host = ffurl_get(&u, ht->addr.ptr, FFURL_HOST);
	port = ffurl_get(&u, ht->addr.ptr, FFURL_PORT);
	x(0 == ffaddr_set(&a, host.ptr, host.len, port.ptr, port.len));

	_FFLIST_WALK(&ht->reqs, rq, li) {

		if (sk == FF_BADSKT) {
			sk = ffskt_create(AF_INET, SOCK_STREAM, IPPROTO_TCP);
			x(sk != FF_BADSKT);
			x(0 == ffskt_connect(sk, &a.a, a.len));
		}

		r = ffskt_send(sk, rq->req.ptr, rq->req.len, 0);

		x(rq->req.len == r);
		ireq++;

		fsv_dbglog(ht->t->logctx, FSV_LOG_DBGNET, "HTST", NULL, "#%u: sent data: [%L] %*s"
			, ireq, r, r, rq->req.ptr);

		if (rq->fin)
			ffskt_fin(sk);

		ffhttp_respinit(&resp);
		r = test_http_recvhdrs(sk, &resp);
		r = test_http_recvbody(sk, &resp, r);

		if (resp.h.conn_close || r != 0) {
			ffskt_close(sk);
			sk = FF_BADSKT;
		}

		ffhttp_respfree(&resp);
	}

	FF_SAFECLOSE(sk, FF_BADSKT, ffskt_close);

	ffhttp_freeheaders();

	FF_SAFECLOSE(sk, FF_BADSKT, ffskt_close);

	fsv_taskpost(ht->t->srv, &ht->task, &test_http_fin, NULL);
	return 0;
}

int test_http(tester *t)
{
	ffthd th;

	if (ht == NULL) {
		testm_runnext(t);
		return 0;
	}

	FFTEST_FUNC;

	ht->t = t;
	th = ffthd_create(&test_http_run, NULL, 0);
	ffthd_detach(th);
	return 0;
}


const ffpars_arg test_http_conf_args[] = {
	{ "addr",  FFPARS_TSTR | FFPARS_FCOPY,  FFPARS_DSTOFF(test_http_s, addr) }
	, { "req",  FFPARS_TSTR | FFPARS_FMULTI | FFPARS_FCOPY,  FFPARS_DST(&test_http_conf_req) }
	, { "req_fin",  FFPARS_TSTR | FFPARS_FMULTI | FFPARS_FCOPY,  FFPARS_DST(&test_http_conf_req) }
};

int testm_conf_http(ffparser_schem *ps, tester *t, ffpars_ctx *ctx)
{
	ht = ffmem_tcalloc1(test_http_s);
	fflist_init(&ht->reqs);

	ffpars_setargs(ctx, ht, test_http_conf_args, FFCNT(test_http_conf_args));
	return 0;
}

static int test_http_conf_req(ffparser_schem *ps, test_http_s *h, const ffstr *val)
{
	test_http_req *rq = ffmem_tcalloc1(test_http_req);
	if (rq == NULL)
		return FFPARS_ESYS;
	fflist_ins(&ht->reqs, &rq->li);
	rq->req = *val;
	rq->fin = !ffsz_cmp(ps->curarg->name, "req_fin");
	return 0;
}

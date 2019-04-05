/**
Copyright 2014 Simon Zolin
*/

#include <test/tests.h>
#include <FFOS/test.h>
#include <FF/net/dns.h>
#include <FF/net/url.h>

#define x  FFTEST_BOOL
static int state;

static void test_resolv_cb_nx(void *udata, int status, const ffaddrinfo *ai[2]);
static void test_resolv_cb(void *udata, int status, const ffaddrinfo *ai[2]);


enum {
	RESV_Q1
	, RESV_Q1_2
	, RESV_CACHED
};

static void test_resolv_cb(void *udata, int status, const ffaddrinfo *ai[2])
{
	tester *t = udata;
	const ffaddrinfo *a;
	ffaddr adr;
	char s[255];
	size_t n;

	FFTEST_FUNC;

	if ((size_t)udata & 1)
		t = (void*)((size_t)t & ~1);

	x(status == 0);
	x(ai[0] != NULL);
	x(ai[1] != NULL);

	for (a = ai[0];  a != NULL;  a = a->ai_next) {
		ffaddr_copy(&adr, a->ai_addr, a->ai_addrlen);
		n = ffaddr_tostr(&adr, s, FFCNT(s), 0);
		fsv_dbglog(t->logctx, FSV_LOG_DBGFLOW, "TEST", NULL, "addr %d: %*s"
			, a->ai_family, n, s);
	}

	for (a = ai[1];  a != NULL;  a = a->ai_next) {
		ffaddr_copy(&adr, a->ai_addr, a->ai_addrlen);
		n = ffaddr_tostr(&adr, s, FFCNT(s), 0);
		fsv_dbglog(t->logctx, FSV_LOG_DBGFLOW, "TEST", NULL, "addr %d: %*s"
			, a->ai_family, n, s);
	}

	t->resolve->unref(ai[0]);
	t->resolve->unref(ai[1]);

	switch (state++) {
	case RESV_Q1:
		x(0 == ((size_t)udata & 1));
		break;

	case RESV_Q1_2:
		x((size_t)udata & 1);
		// now get the same results from cache
		x(0 == t->resolve->resolve(t->resolve_ctx, FFSTR("www.google.com"), &test_resolv_cb, t, 0));
		break;

	case RESV_CACHED:
		//try to resolve non-existing domain
		x(0 == t->resolve->resolve(t->resolve_ctx, FFSTR("nx-label.google.com"), &test_resolv_cb_nx, t, 0));
		break;
	}
}

static void test_resolv_cb_nx(void *udata, int status, const ffaddrinfo *ai[2])
{
	tester *t = udata;
	x(status == FFDNS_NXDOMAIN);
	testm_runnext(t);
}

int test_resolve(tester *t)
{
	ffstr host;

	if (t->resolve == NULL) {
		testm_runnext(t);
		return 0;
	}

	FFTEST_FUNC;

	ffstr_setcz(&host, "www.google.com");
	x(0 == t->resolve->resolve(t->resolve_ctx, host.ptr, host.len, &test_resolv_cb, t, 0));
	x(0 == t->resolve->resolve(t->resolve_ctx, host.ptr, host.len, &test_resolv_cb, (void*)((size_t)t | 1), 0)); //add ref to the same query

	//add dummy ref to the same query and then unref it
	x(0 == t->resolve->resolve(t->resolve_ctx, host.ptr, host.len, &test_resolv_cb, (void*)0x1234, 0));
	x(1 == t->resolve->resolve(t->resolve_ctx, host.ptr, host.len, &test_resolv_cb, (void*)0x12345, FFDNSCL_CANCEL));
	x(0 == t->resolve->resolve(t->resolve_ctx, host.ptr, host.len, &test_resolv_cb, (void*)0x1234, FFDNSCL_CANCEL));
	return 0;
}

int testm_conf_resolve(ffparser_schem *ps, tester *t, ffpars_ctx *a)
{
	const ffstr *name = &ps->vals[0];
	const fsv_modinfo *m = t->srv->findmod(name->ptr, name->len);
	if (m == NULL)
		return FFPARS_EBADVAL;

	t->resolve = m->f->iface("resolve");
	if (t->resolve == NULL)
		return FFPARS_EBADVAL;

	t->resolve_ctx = t->resolve->newctx(a);
	if (t->resolve_ctx == NULL)
		return FFPARS_EBADVAL;
	return 0;
}

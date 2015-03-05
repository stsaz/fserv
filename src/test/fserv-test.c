/**
Copyright 2014 Simon Zolin
*/

#include <test/tests.h>
#include <FFOS/test.h>
#include <FFOS/thread.h>
#include <FFOS/process.h>


static tester *testm;

// FSERV MODULE
static void * testm_create(const fsv_core *srv, ffpars_ctx *c, fsv_modinfo *m);
static void testm_destroy(void);
static int testm_sig(int sig);
static const fsv_mod fsv_test_mod = {
	&testm_create, &testm_destroy, &testm_sig, NULL
};


static void oninit(void)
{
	ffos_init();
	ffskt_init(FFSKT_WSAFUNCS);
}
FFDL_ONINIT(oninit, NULL)

FF_EXTN FF_EXP const fsv_mod * fsv_getmod(const char *name)
{
	if (!ffsz_cmp(name, "test"))
		return &fsv_test_mod;
	return NULL;
}

const ffpars_arg testm_args[] = {
	{ "cache",  FFPARS_TOBJ | FFPARS_FOBJ1,  FFPARS_DST(&testm_conf_cache) }
	, { "cache_multi",  FFPARS_TOBJ | FFPARS_FOBJ1,  FFPARS_DST(&testm_conf_cache_multi) }
	, { "fcache",  FFPARS_TOBJ | FFPARS_FOBJ1,  FFPARS_DST(&testm_conf_fcache) }
	, { "resolve",  FFPARS_TOBJ | FFPARS_FOBJ1,  FFPARS_DST(&testm_conf_resolve) }
	, { "connect",  FFPARS_TOBJ | FFPARS_FOBJ1,  FFPARS_DST(&testm_conf_connect) }
	, { "server",  FFPARS_TOBJ | FFPARS_FOBJ1,  FFPARS_DST(&testm_conf_server) }
	, { "client",  FFPARS_TOBJ | FFPARS_FOBJ1,  FFPARS_DST(&testm_conf_client) }
	, { "http",  FFPARS_TOBJ,  FFPARS_DST(&testm_conf_http) }
	, { "server_stop",  FFPARS_TBOOL,  FFPARS_DSTOFF(tester, server_stop) }
};

static const test_func_t funcs[] = {
	&test_cache, &test_fcache, &test_listen, &test_http, &test_resolve, &test_connect, NULL
};

static void * testm_create(const fsv_core *srv, ffpars_ctx *c, fsv_modinfo *m)
{
	const fsvcore_config *conf = srv->conf();

	testm = ffmem_tcalloc1(tester);
	if (testm == NULL)
		return NULL;

	testm->srv = srv;
	testm->logctx = conf->logctx;
	testm->curfunc = funcs;

	ffpars_setargs(c, testm, testm_args, FFCNT(testm_args));
	return testm;
}

static void testm_destroy(void)
{
	ffmem_free(testm);
	testm = NULL;
}

static int testm_sig(int sig)
{
	switch (sig) {
	case FSVCORE_SIGSTART:
		fftestobj.flags |= FFTEST_TRACE | FFTEST_FATALERR;
		(*testm->curfunc)(testm);
		break;

	case FSVCORE_SIGSTOP:
		break;
	}

	return 0;
}

#ifdef FF_MSVC
enum {
	SIGINT = 1
};
#endif

void testm_runnext(tester *t)
{
	testm->curfunc++;
	if (*testm->curfunc != NULL) {
		(*testm->curfunc)(testm);
		return;
	}

	fsv_errlog(testm->logctx, FSV_LOG_INFO, "TEST", NULL, "%u tests were run, %u failed."
		, fftestobj.nrun, fftestobj.nfail);

	if (t->server_stop) {
		ffthd_sleep(1000);
		ffps_sig(ffps_curid(), SIGINT);
	}
}

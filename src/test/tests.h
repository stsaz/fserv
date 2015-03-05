/**
Copyright 2014 Simon Zolin
*/

#include <core/fserv.h>
#include <FF/sendfile.h>

typedef struct tester tester;
typedef int (*test_func_t)(tester *t);

struct tester {
	const fsv_core *srv;
	fsv_logctx *logctx;
	const test_func_t *curfunc;
	uint server_stop;

	const fsv_cache *cachmod;
	fsv_cachectx *cachctx;
	fsv_cachectx *cachctx_multi;

	const fsv_fcache *fcachmod;
	fsv_cachectx *fcachctx;

	const fsv_connect *conn;
	fsv_conctx *conctx;
	fsv_conn *conn_id;

	const fsv_resolver *resolve;
	fsv_resolv_ctx *resolve_ctx;

	const fsv_listen *lsn;
	fsv_lsnctx *lsnctx;
	fsv_lsncon *lsncon;

	const fsv_connect *lsn_conn;
	fsv_conctx *lsn_conctx;
	fsv_conn *lsn_conn_id
		, *lsn_conn_id2;

	fsv_timer tmr;
	ffstr3 inbuf;
	ffstr3 inbuf2;
	ffsf sf;
	fffd fd;
	ffiovec iov[2];
	char *iov_bufs[2];
};

extern void testm_runnext(tester *t);

extern int test_cache(tester *t);
extern int testm_conf_cache(ffparser_schem *ps, tester *t, ffpars_ctx *a);
extern int testm_conf_cache_multi(ffparser_schem *ps, tester *t, ffpars_ctx *a);

extern int test_fcache(tester *t);
extern int testm_conf_fcache(ffparser_schem *ps, tester *t, ffpars_ctx *a);

extern int test_connect(tester *t);
extern int testm_conf_connect(ffparser_schem *ps, tester *t, ffpars_ctx *a);

extern int test_resolve(tester *t);
extern int testm_conf_resolve(ffparser_schem *ps, tester *t, ffpars_ctx *a);

extern int test_listen(tester *t);
extern int testm_conf_server(ffparser_schem *ps, tester *t, ffpars_ctx *a);
extern int testm_conf_client(ffparser_schem *ps, tester *t, ffpars_ctx *a);

extern int test_http(tester *t);
extern int testm_conf_http(ffparser_schem *ps, tester *t, ffpars_ctx *ctx);

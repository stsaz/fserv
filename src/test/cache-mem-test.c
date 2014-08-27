/**
Copyright 2014 Simon Zolin
*/

#include <test/tests.h>
#include <FFOS/test.h>

#define x  FFTEST_BOOL

static int state;

enum {
	CACH_K1
	, CACH_K
	, CACH_K2
	, CACH_MAX_ITEMS = CACH_K2 + 3
	, CACH_MEM_LIMIT = CACH_MAX_ITEMS + 2
	, CACH_K3
	, CACH_K3_1
};

static int test_cach_onchange(fsv_cachectx *ctx, fsv_cacheitem *ca, int flags)
{
	FFTEST_FUNC;

	switch (state++) {
	case CACH_K1:
		x(!ffs_cmpz(ca->key, ca->keylen, "k1"));
		x(!ffs_cmpz(ca->data, ca->datalen, "mydata"));
		break;
	}

	return 0;
}

static int test_cach_onchange_multi(fsv_cachectx *ctx, fsv_cacheitem *ca, int flags)
{
	FFTEST_FUNC;
	state++;
	return 0;
}

static const fsv_cach_cb test_cach_cb = {
	&test_cach_onchange
};

static const fsv_cach_cb test_cach_cb_multi = {
	&test_cach_onchange_multi
};

#define cach_initscz(pca, scz) \
do { \
	fsv_cache_init(pca); \
	(pca)->key = scz; \
	(pca)->keylen = FFSLEN(scz); \
} while (0)

static void test_cach_multi(tester *t)
{
	fsv_cacheitem ca, ca2;
	const fsv_cache *cach = t->cachmod;
	fsv_cachectx *cx = t->cachctx_multi;

	FFTEST_FUNC;

	cach_initscz(&ca, "k3");
	ca.data = "mydata1";
	ca.datalen = FFSLEN("mydata1");
	x(0 == cach->store(cx, &ca, 0));
	x(0 == cach->unref(&ca, 0));

	cach_initscz(&ca, "k3");
	ca.data = "mydata2";
	ca.datalen = FFSLEN("mydata2");
	ca.refs = 0;
	x(0 == cach->store(cx, &ca, 0));
	x(ca.id != NULL);

	cach_initscz(&ca, "k3");
	x(0 == cach->fetch(cx, &ca, 0));

	fsv_cache_init(&ca2);
	ca2.id = ca.id;
	x(0 == cach->fetch(cx, &ca2, FSV_CACH_NEXT));
	x(ca.id != ca2.id);
	x(!ffs_cmpz(ca2.data, ca2.datalen, "mydata2"));
	x(state == CACH_K3);
	x(0 == cach->unref(&ca2, FSV_CACH_UNLINK));
	x(state == CACH_K3 + 1);

	x(!ffs_cmpz(ca.data, ca.datalen, "mydata1"));
	x(state == CACH_K3_1);
	x(0 == cach->unref(&ca, FSV_CACH_UNLINK));
	x(state == CACH_K3_1 + 1);
}

static void test_cach_single(tester *t)
{
	fsv_cacheitem ca, ca2;
	const fsv_cache *cach = t->cachmod;
	fsv_cachectx *cx = t->cachctx;

	FFTEST_FUNC;

	cach_initscz(&ca, "k1");
	x(FSV_CACH_ENOTFOUND == cach->fetch(cx, &ca, 0));

	ca.data = "mydata";
	ca.datalen = FFSLEN("mydata");
	ca.refs = 2;
	x(0 == cach->store(cx, &ca, 0));
	x(ca.expire == 2); //"expiry" config option worked
	x(0 == cach->unref(&ca, 0));

	x(FSV_CACH_ESYS == cach->fetch(cx, &ca, FSV_CACH_NEXT));

	cach_initscz(&ca, "K1"); //check FSV_CACH_KEYICASE
	x(0 == cach->fetch(cx, &ca, 0));
	x(!ffs_cmpz(ca.data, ca.datalen, "mydata"));

	x(FSV_CACH_ELOCKED == cach->update(&ca, 0));

	cach_initscz(&ca2, "K1");
	x(FSV_CACH_EEXISTS == cach->store(cx, &ca2, 0));

	x(0 == cach->unref(&ca, FSV_CACH_UNLINK));
	cach_initscz(&ca2, "K1");
	x(FSV_CACH_ENOTFOUND == cach->fetch(cx, &ca2, 0));

	x(state == CACH_K1);
	x(0 == cach->unref(&ca, 0));
	x(state == CACH_K1 + 1); //the item was deleted

// update
	cach_initscz(&ca, "k");
	ca.data = "mydata1";
	ca.datalen = FFSLEN("mydata1");
	x(0 == cach->store(cx, &ca, 0));

	ca.data = "mynewdata";
	ca.datalen = FFSLEN("mynewdata");
	x(0 == cach->update(&ca, 0));
	x(!ffs_cmpz(ca.data, ca.datalen, "mynewdata"));

	x(state == CACH_K);
	x(0 == cach->unref(&ca, FSV_CACH_UNLINK));
	x(state == CACH_K + 1);

// FSV_CACH_ACQUIRE
	cach_initscz(&ca, "k2");
	ca.data = "mydata";
	ca.datalen = FFSLEN("mydata");
	ca.expire = 5;
	x(0 == cach->store(cx, &ca, 0));
	x(ca.expire == 3); //"max_age" config option worked

	cach_initscz(&ca2, "k2");
	x(FSV_CACH_ELOCKED == cach->fetch(cx, &ca2, FSV_CACH_ACQUIRE));
	x(0 == cach->unref(&ca, 0));

	cach_initscz(&ca, "k2");
	x(0 == cach->fetch(cx, &ca, FSV_CACH_ACQUIRE));
	x(!ffs_cmpz(ca.data, ca.datalen, "mydata"));
	x(state == CACH_K2);
	x(0 == cach->unref(&ca, 0));
	x(state == CACH_K2 + 1); //the item was deleted
}

static void test_cach_limits(tester *t)
{
	fsv_cacheitem ca, ca2, ca3;
	const fsv_cache *cach = t->cachmod;
	fsv_cachectx *cx = t->cachctx;

	FFTEST_FUNC;

// "max_data"
	cach_initscz(&ca, "k1");
	ca.data = "1234567890z";
	ca.datalen = FFSLEN("1234567890z");
	x(FSV_CACH_ESZLIMIT == cach->store(cx, &ca, 0)); //"max_data" config option worked

// "max_items"
	cach_initscz(&ca, "k1");
	x(0 == cach->store(cx, &ca, 0));

	cach_initscz(&ca2, "k2");
	x(0 == cach->store(cx, &ca2, 0));

	cach_initscz(&ca3, "k3");
	x(FSV_CACH_ENUMLIMIT == cach->store(cx, &ca3, 0)); //"max_items" config option worked

	x(0 == cach->unref(&ca, 0));
	x(0 == cach->store(cx, &ca3, 0)); //"k1" was deleted automatically
	x(0 == cach->unref(&ca2, FSV_CACH_UNLINK));
	x(0 == cach->unref(&ca3, FSV_CACH_UNLINK));
	x(state == CACH_MAX_ITEMS + 1);

// "mem_limit"
	cach_initscz(&ca, "k1");
	ca.data = "1";
	ca.datalen = FFSLEN("1");
	x(0 == cach->store(cx, &ca, 0));

	cach_initscz(&ca2, "k2");
	ca2.data = "123456";
	ca2.datalen = FFSLEN("123456");
	x(FSV_CACH_EMEMLIMIT == cach->store(cx, &ca2, 0)); //"mem_limit" config option worked

	x(0 == cach->unref(&ca, 0));
	x(0 == cach->store(cx, &ca2, 0));
	cach_initscz(&ca, "k1");
	x(FSV_CACH_ENOTFOUND == cach->fetch(cx, &ca, 0)); //"k1" was deleted automatically
	x(0 == cach->unref(&ca2, FSV_CACH_UNLINK));
	x(state == CACH_MEM_LIMIT + 1);
}

int test_cache(tester *t)
{
	if (t->cachmod == NULL) {
		testm_runnext(t);
		return 0;
	}

	test_cach_single(t);
	test_cach_limits(t);
	test_cach_multi(t);

	testm_runnext(t);
	return 0;
}


int testm_conf_cache(ffparser_schem *ps, tester *t, ffpars_ctx *a)
{
	const ffstr *name = &ps->vals[0];
	const fsv_modinfo *m = t->srv->findmod(name->ptr, name->len);
	if (m == NULL)
		return FFPARS_EBADVAL;

	t->cachmod = m->f->iface("cache");
	if (t->cachmod == NULL)
		return FFPARS_EINTL;

	t->cachctx = t->cachmod->newctx(a, &test_cach_cb, FSV_CACH_KEYICASE);
	if (t->cachctx == NULL)
		return FFPARS_EINTL;

	return 0;
}

int testm_conf_cache_multi(ffparser_schem *ps, tester *t, ffpars_ctx *a)
{
	const ffstr *name = &ps->vals[0];
	const fsv_modinfo *m = t->srv->findmod(name->ptr, name->len);
	if (m == NULL)
		return FFPARS_EBADVAL;

	t->cachmod = m->f->iface("cache");
	if (t->cachmod == NULL)
		return FFPARS_EINTL;

	t->cachctx_multi = t->cachmod->newctx(a, &test_cach_cb_multi, FSV_CACH_MULTI | FSV_CACH_KEYICASE);
	if (t->cachctx_multi == NULL)
		return FFPARS_EINTL;

	return 0;
}

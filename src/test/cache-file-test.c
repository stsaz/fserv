/**
Copyright 2015 Simon Zolin
*/

#include <test/tests.h>
#include <FFOS/test.h>
#include <FFOS/file.h>

#define x  FFTEST_BOOL


#define fcach_initscz(pca, scz) \
do { \
	fsv_fcache_init(pca); \
	(pca)->key = scz; \
	(pca)->keylen = FFSLEN(scz); \
} while (0)

static fsv_cacheitem_id *fcach_id;

static void test_fcache_onwrite(void *userptr, fsv_fcacheitem *ca, int result)
{
	fcach_id = ca->id;
}

static const fsv_fcach_cb test_fcach_cb = {
	&test_fcache_onwrite
};

static void test_fcache1(tester *t)
{
	char buf[8];
	fsv_fcacheitem ca, ca2;
	const fsv_fcache *cach = t->fcachmod;
	fsv_cachectx *cx = t->fcachctx;

	FFTEST_FUNC;

//store and fetch
	fcach_initscz(&ca, "key1");
	x(FSV_CACH_ENOTFOUND == cach->fetch(cx, &ca, 0));
	ca.hdr = "hdr"; ca.hdrlen = 3;
	ca.data = "data"; ca.len = 4;
	ca.total_size = 5;
	x(0 == cach->store(cx, &ca, 0));
	ca.id = fcach_id;
	x(0 == cach->unref(&ca, 0));

	fcach_initscz(&ca, "key1");
	x(0 == cach->fetch(cx, &ca, 0));
	x(ca.cretm != 0);
	x(ca.expire != 0);
	x(ffs_eqcz(ca.hdr, ca.hdrlen, "hdr"));
	x(ca.len == 4);
	fffile_seek(ca.fd, ca.fdoff, SEEK_SET);
	x(ca.len == fffile_read(ca.fd, buf, 4));
	x(ffs_eqcz(buf, ca.len, "data"));
	x(0 == cach->unref(&ca, 0));

//overwrite
	fcach_initscz(&ca, "key1");
	x(0 == cach->fetch(cx, &ca, 0));
	ca.hdr = "hdr3"; ca.hdrlen = 4;
	ca.data = "dat3"; ca.len = 4;
	x(0 == cach->update(&ca, 0));
	ca.id = fcach_id;
	x(0 == cach->unref(&ca, 0));

	fcach_initscz(&ca, "key1");
	x(0 == cach->fetch(cx, &ca, 0));
	x(ffs_eqcz(ca.hdr, ca.hdrlen, "hdr3"));
	x(ca.len == 4);
	fffile_seek(ca.fd, ca.fdoff, SEEK_SET);
	x(ca.len == fffile_read(ca.fd, buf, 4));
	x(ffs_eqcz(buf, ca.len, "dat3"));
	x(0 == cach->unref(&ca, 0));

//unlink
	fcach_initscz(&ca, "key1");
	x(0 == cach->fetch(cx, &ca, 0));
	fcach_initscz(&ca2, "key1");
	x(0 == cach->fetch(cx, &ca2, 0));
	x(0 == cach->unref(&ca2, FSV_CACH_UNLINK));

	fcach_initscz(&ca2, "key1");
	x(FSV_CACH_ENOTFOUND == cach->fetch(cx, &ca2, 0));
	x(0 == cach->unref(&ca, 0));

//append data
	fcach_initscz(&ca, "key1");
	ca.data = "dat4"; ca.len = 4;
	x(0 == cach->store(cx, &ca, FSV_FCACH_LOCK));
	ca.id = fcach_id;

	fcach_initscz(&ca2, "key1");
	x(FSV_CACH_ENOTFOUND == cach->fetch(cx, &ca2, 0));

	ca.data = "dat5"; ca.len = 4;
	x(0 == cach->update(&ca, FSV_FCACH_APPEND | FSV_FCACH_UNLOCK));
	x(0 == cach->unref(&ca, 0));

	fcach_initscz(&ca, "key1");
	x(0 == cach->fetch(cx, &ca, 0));
	x(ca.len == 8);
	fffile_seek(ca.fd, ca.fdoff, SEEK_SET);
	x(ca.len == fffile_read(ca.fd, buf, 8));
	x(ffs_eqcz(buf, ca.len, "dat4dat5"));
	x(0 == cach->unref(&ca, FSV_CACH_UNLINK));

	fcach_initscz(&ca, "key1");
	x(FSV_CACH_ENOTFOUND == cach->fetch(cx, &ca, 0));
}

int test_fcache(tester *t)
{
	if (t->fcachmod != NULL) {
		test_fcache1(t);
	}

	testm_runnext(t);
	return 0;
}

int testm_conf_fcache(ffparser_schem *ps, tester *t, ffpars_ctx *a)
{
	const ffstr *name = &ps->vals[0];
	const fsv_modinfo *m = t->srv->findmod(name->ptr, name->len);
	if (m == NULL)
		return FFPARS_EBADVAL;

	t->fcachmod = m->f->iface("file-cache");
	if (t->fcachmod == NULL)
		return FFPARS_EINTL;

	t->fcachctx = t->fcachmod->newctx(a, &test_fcach_cb, 0);
	if (t->fcachctx == NULL)
		return FFPARS_EINTL;

	return 0;
}

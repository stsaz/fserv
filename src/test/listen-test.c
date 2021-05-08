/**
Copyright 2014 Simon Zolin
*/

#include <test/tests.h>
#include <FFOS/test.h>
#include <FFOS/process.h>

#define x  FFTEST_BOOL
enum {
	M = 1024 * 1024
	, BUFSIZE = 2 * M
};
static int sstate;
static int cstate;

enum {
	LSN_ACC1
	, LSN_IO1
	, LSN_ACC2
};

enum {
	LSN_CONN1
	, LSN_CONN2
};

static void test_lsn_onaccept(void *userctx, fsv_lsncon *conn);
static void test_lsn_srv_onrecv(void *udata);
static void test_lsn_srv_onsend(void *udata);
static int test_lsn_onsig(fsv_lsncon *conn, void *userptr, int sig);
static const fsv_listen_cb test_lsn_cb = {
	&test_lsn_onaccept, &test_lsn_onsig
};

static void test_lsn_conn_onconnect(void *userptr, int result);
static void test_lsn_client_onsend(void *udata);
static void test_lsn_client_onrecv(void *udata);
static void test_lsn_client_onrecv2(void *udata);
static ssize_t test_lsn_conn_getvar(void *obj, const char *name, size_t namelen, void *dst, size_t cap);
static const fsv_connect_cb test_lsn_conn_cb = {
	&test_lsn_conn_onconnect, &test_lsn_conn_getvar
};

static void prep_sf(tester *t);
static void test_lsn_fin(tester *t);


static void test_lsn_onaccept(void *userctx, fsv_lsncon *conn)
{
	tester *t = userctx;
	size_t r;

	FFTEST_FUNC;

	switch (sstate) {
	case LSN_ACC1:
		t->lsncon = conn;
		test_lsn_srv_onrecv(t);
		sstate = LSN_IO1;
		t->lsn->setopt(t->lsncon, FSV_LISN_OPT_USERPTR, t);
		break;

	case LSN_ACC2:
		x(t->lsncon == NULL); //previous connection was finished
		t->lsncon = conn;
		r = t->lsn->send(t->lsncon, FFSTR("listener"), NULL, NULL);
		x(r == FFSLEN("listener"));
		t->lsn->setopt(t->lsncon, FSV_LISN_OPT_USERPTR, t);
		break;
	}
}

static void test_lsn_srv_onrecv(void *udata)
{
	tester *t = udata;
	ssize_t r;
	FFTEST_FUNC;

	for (;;) {
		r = t->lsn->recv(t->lsncon, ffarr_end(&t->inbuf), ffarr_unused(&t->inbuf), NULL, NULL);

		if (r == FSV_IO_EAGAIN) {
			x(FSV_IO_ASYNC == t->lsn->recv(t->lsncon, ffarr_end(&t->inbuf), ffarr_unused(&t->inbuf), &test_lsn_srv_onrecv, t));
			return;
		}

		fsv_dbglog(t->logctx, FSV_LOG_DBGNET, "TEST", NULL, "srv recvd +%L [%L]", r, r + t->inbuf.len);
		x(r > 0);
		t->inbuf.len += r;
		if (0 == ffarr_unused(&t->inbuf))
			break;
	}

	prep_sf(t);
	test_lsn_srv_onsend(t);
}

static void test_lsn_srv_onsend(void *udata)
{
	tester *t = udata;
	ssize_t r;
	FFTEST_FUNC;

	for (;;) {
		r = t->lsn->sendfile(t->lsncon, &t->sf, NULL, NULL);

		if (r == FSV_IO_EAGAIN) {
			x(FSV_IO_ASYNC == t->lsn->sendfile(t->lsncon, &t->sf, &test_lsn_srv_onsend, t));
			return;
		}

		x(r > 0);
		if (0 == ffsf_shift(&t->sf, r))
			break;
	}

	ffsf_close(&t->sf);
	t->lsn->fin(t->lsncon, FSV_LISN_LINGER);
	t->lsncon = NULL;
	sstate = LSN_ACC2;
}

static int test_lsn_onsig(fsv_lsncon *conn, void *userptr, int sig)
{
	FFTEST_FUNC;
	return 0;
}


static void test_lsn_conn_onconnect(void *userptr, int result)
{
	tester *t = userptr;
	char buf[16];
	FFTEST_FUNC;

	switch (cstate) {

	case LSN_CONN1:
		x(result == FSV_CONN_OK);
		prep_sf(t);
		test_lsn_client_onsend(t);
		cstate = LSN_CONN2;
		break;

	case LSN_CONN2:
		// test listen.max_clients
		x(FSV_IO_EAGAIN == t->lsn_conn->recv(t->lsn_conn_id2, buf, sizeof(buf), NULL, NULL));
		x(FSV_IO_ASYNC == t->lsn_conn->recv(t->lsn_conn_id2, NULL, 0, &test_lsn_client_onrecv2, t));
		break;
	}
}

static void test_lsn_client_onsend(void *udata)
{
	tester *t = udata;
	ssize_t r;
	FFTEST_FUNC;

	for (;;) {
		r = t->lsn_conn->sendfile(t->lsn_conn_id, &t->sf, NULL, NULL);

		if (r == FSV_IO_EAGAIN) {
			x(FSV_IO_ASYNC == t->lsn_conn->sendfile(t->lsn_conn_id, &t->sf, &test_lsn_client_onsend, t));
			return;
		}

		x(r > 0);
		if (0 == ffsf_shift(&t->sf, r))
			break;
	}

	ffsf_close(&t->sf);
	test_lsn_client_onrecv(t);
}

static void test_lsn_client_onrecv(void *udata)
{
	tester *t = udata;
	ssize_t r;
	FFTEST_FUNC;

	for (;;) {
		r = t->lsn_conn->recv(t->lsn_conn_id, ffarr_end(&t->inbuf2), ffarr_unused(&t->inbuf2), NULL, NULL);

		if (r == FSV_IO_EAGAIN) {
			x(FSV_IO_ASYNC == t->lsn_conn->recv(t->lsn_conn_id, ffarr_end(&t->inbuf2), ffarr_unused(&t->inbuf2), &test_lsn_client_onrecv, t));
			return;
		}

		fsv_dbglog(t->logctx, FSV_LOG_DBGNET, "TEST", NULL, "client recvd +%L [%L]", r, r + t->inbuf2.len);
		x(r > 0);
		t->inbuf2.len += r;
		if (0 == ffarr_unused(&t->inbuf2))
			break;
	}

	//test socket lingering
	r = t->lsn_conn->send(t->lsn_conn_id, t->iov_bufs, 16 * 1024, NULL, NULL);
	x(r > 0);

	t->lsn_conn->fin(t->lsn_conn_id, 0);
	t->lsn_conn_id = NULL;
	test_lsn_fin(t);
}

static void test_lsn_client_onrecv2(void *udata)
{
	tester *t = udata;
	char buf[16];
	FFTEST_FUNC;

	x(FFSLEN("listener") == t->lsn_conn->recv(t->lsn_conn_id2, buf, sizeof(buf), NULL, NULL));
	t->lsn_conn->fin(t->lsn_conn_id2, FSV_CONN_KEEPALIVE);
	t->lsn_conn_id2 = NULL;

	//drop server-side connection, so we can test how keep-alive connection is signalled in mod-connect
	t->lsn->fin(t->lsncon, 0);
	t->lsncon = NULL;

	testm_runnext(t);
}

static ssize_t test_lsn_conn_getvar(void *obj, const char *name, size_t namelen, void *dst, size_t cap)
{
	FFTEST_FUNC;
	return 0;
}

static void prep_sf(tester *t)
{
	size_t i;
	// prepare hdtr
	for (i = 0;  i < FFCNT(t->iov_bufs);  i++) {
		ffiov_set(&t->iov[i], t->iov_bufs[i], BUFSIZE);
	}

	ffsf_init(&t->sf);
	fffile_mapset(&t->sf.fm, 64 * 1024, t->fd, 0, BUFSIZE);
	ffsf_sethdtr(&t->sf.ht, &t->iov[0], 1, &t->iov[1], 1);
}

static void test_lsn_fin(tester *t)
{
	size_t i;
	ffarr_free(&t->inbuf);
	ffarr_free(&t->inbuf2);
	fffile_close(t->sf.fm.fd);
	ffsf_close(&t->sf);
	for (i = 0;  i < FFCNT(t->iov_bufs);  i++)
		ffmem_free(t->iov_bufs[i]);
}

int test_listen(tester *t)
{
	fsv_conn_new nc = {0};
	char fne[FF_MAXPATH];
	const char *fn;
	fffd f;
	size_t i;

	if (t->lsnctx == NULL) {
		testm_runnext(t);
		return 0;
	}

	FFTEST_FUNC;

	x(NULL != ffarr_alloc(&t->inbuf, BUFSIZE * 3));
	x(NULL != ffarr_alloc(&t->inbuf2, BUFSIZE * 3));

	// prepare file
#ifdef FF_UNIX
	#define TMPDIR "/tmp"
#else
	#define TMPDIR "%TMP%"
#endif
	fn = TMPDIR "/tmp-ff";
	fn = ffenv_expand(fne, sizeof(fne), fn);
	f = fffile_createtemp(fn, O_RDWR);
	x(f != FF_BADFD);
	x(0 == fffile_trunc(f, BUFSIZE));
	t->fd = f;

	for (i = 0;  i < FFCNT(t->iov_bufs);  i++) {
		t->iov_bufs[i] = ffmem_alloc(BUFSIZE);
		x(t->iov_bufs[i] != NULL);
	}

	nc.userptr = t;
	x(0 == t->lsn_conn->getserv(t->lsn_conctx, &nc, 0));
	t->lsn_conn_id = nc.con;
	t->lsn_conn->connect(t->lsn_conn_id, 0);

	ffmem_tzero(&nc);
	nc.userptr = t;
	x(0 == t->lsn_conn->getserv(t->lsn_conctx, &nc, 0));
	t->lsn_conn_id2 = nc.con;
	t->lsn_conn->connect(t->lsn_conn_id2, 0);
	return 0;
}


int testm_conf_server(ffparser_schem *ps, tester *t, ffpars_ctx *a)
{
	const ffstr *name = &ps->vals[0];
	const fsv_modinfo *m = t->srv->findmod(name->ptr, name->len);
	if (m == NULL)
		return FFPARS_EBADVAL;

	t->lsn = m->f->iface("listen");
	if (t->lsn == NULL)
		return FFPARS_EBADVAL;

	t->lsnctx = t->lsn->newctx(a, &test_lsn_cb, t);
	if (t->lsnctx == NULL)
		return FFPARS_EBADVAL;
	return 0;
}

int testm_conf_client(ffparser_schem *ps, tester *t, ffpars_ctx *a)
{
	const ffstr *name = &ps->vals[0];
	const fsv_modinfo *m = t->srv->findmod(name->ptr, name->len);
	if (m == NULL)
		return FFPARS_EBADVAL;

	t->lsn_conn = m->f->iface("connect");
	if (t->lsn_conn == NULL)
		return FFPARS_EBADVAL;

	t->lsn_conctx = t->lsn_conn->newctx(a, &test_lsn_conn_cb);
	if (t->lsn_conctx == NULL)
		return FFPARS_EBADVAL;
	return 0;
}

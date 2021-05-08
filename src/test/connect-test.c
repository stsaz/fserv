/**
Copyright 2014 Simon Zolin
*/

#include <test/tests.h>
#include <FFOS/test.h>

#define x  FFTEST_BOOL
static int state;


static void test_conn_onconnect(void *userptr, int result);
static ssize_t test_conn_getvar(void *obj, const char *name, size_t namelen, void *dst, size_t cap);
static const fsv_connect_cb test_conn_cb = {
	&test_conn_onconnect, &test_conn_getvar
};

static void test_conn_connectok(tester *t)
{
	ffskt sk;

	t->conn->getvar(t->conn_id, FFSTR("socket_fd"), &sk, sizeof(ffskt));
	fsv_dbglog(t->logctx, FSV_LOG_DBGNET, "TEST", NULL, "socket: %L", sk);

	t->conn->fin(t->conn_id, FSV_CONN_KEEPALIVE);
	t->conn_id = NULL;
}

static void test_conn_connectnext(tester *t)
{
	fsv_conn_new cn = {0};
	cn.userptr = t;
	t->conn->getserv(t->conctx, &cn, 0);
	t->conn_id = cn.con;
	t->conn->connect(t->conn_id, 0);
}

enum {
	CONN_OK
	, CONN_DNS
	, CONN_ADDR
	, CONN_KA_OK
	, CONN_KA_EXPIRED
};

static void test_conn_katimer(void *param)
{
	tester *t = param;
	FFTEST_FUNC;

	test_conn_connectnext(t);
}

static void test_conn_onconnect(void *userptr, int result)
{
	tester *t = userptr;

	FFTEST_FUNC;

	switch (state++) {
	case CONN_OK:
		x(result == FSV_CONN_OK);
		test_conn_connectok(t);
		test_conn_connectnext(t);
		break;

	case CONN_DNS:
		//failed to connect to a server.  The server is now marked as down.
		x(result == FSV_CONN_EDNS);
		t->conn->fin(t->conn_id, 0);
		t->conn_id = NULL;

		test_conn_connectnext(t);
		break;

	case CONN_ADDR:
		x(result == FSV_CONN_ENOADDR);
		t->conn->fin(t->conn_id, 0);
		t->conn_id = NULL;

		test_conn_connectnext(t);
		//getting connection with www.google.com from keep-alive cache...
		break;

	case CONN_KA_OK:
		//keep-alive connection is ok
		x(result == FSV_CONN_OK);
		test_conn_connectok(t);

		{
			fsv_conn_new cn = {0};
			cn.userptr = t;
			cn.con = t->conn_id;
			t->conn->getserv(t->conctx, &cn, 0);
			// we have google.com again, because both srv1 and srv2 are down.
			x(ffstr_eqcz(&cn.url, "http://www.google.com/some/path"));
			t->conn->fin(cn.con, FSV_CONN_KEEPALIVE);
		}

		t->srv->timer(&t->tmr, -2 * 1000, &test_conn_katimer, t); //wait 2 seconds to test keepalive_cache.expiry
		break;

	case CONN_KA_EXPIRED:
		//keep-alive connection expired, we established a new connection
		x(result == FSV_CONN_OK);
		testm_runnext(t);
		break;
	}
}

static ssize_t test_conn_getvar(void *obj, const char *name, size_t namelen, void *dst, size_t cap)
{
	FFTEST_FUNC;

	if (ffs_eqcz(name, namelen, "my_var")) {
		ffstr s;
		if (obj == NULL)
			ffstr_setcz(&s, "server3");
		else
			ffstr_setcz(&s, "www.google.com");
		*(char**)dst = s.ptr;
		return s.len;
	}
	return 0;
}

static void test_round_robin_balancer(tester *t)
{
	const fsv_connect *conn = t->conn;
	fsv_conn_new cn = {0};

	conn->getserv(t->conctx, &cn, 0);
	x(ffstr_eqcz(&cn.url, "http://server1"));
	conn->fin(cn.con, 0);
	cn.con = NULL;

	conn->getserv(t->conctx, &cn, 0);
	x(ffstr_eqcz(&cn.url, "http://127.0.0.1:64000"));
	conn->fin(cn.con, 0);
	cn.con = NULL;

	conn->getserv(t->conctx, &cn, 0);
	x(ffstr_eqcz(&cn.url, "http://127.0.0.1:64000")); //"weight" worked
	conn->fin(cn.con, 0);
	cn.con = NULL;

	conn->getserv(t->conctx, &cn, 0);
	x(ffstr_eqcz(&cn.url, "http://server3/some/path"));
	conn->fin(cn.con, 0);
	cn.con = NULL;

// iterate through servers
	conn->getserv(t->conctx, &cn, 0);
	x(ffstr_eqcz(&cn.url, "http://server1"));
	conn->getserv(t->conctx, &cn, 0);
	x(ffstr_eqcz(&cn.url, "http://127.0.0.1:64000"));
	conn->getserv(t->conctx, &cn, 0);
	x(ffstr_eqcz(&cn.url, "http://server3/some/path"));
	x(FSV_CONN_ENOSERV == conn->getserv(t->conctx, &cn, 0));
	x(cn.con == NULL);
}

int test_connect(tester *t)
{
	const fsv_connect *conn = t->conn;
	fsv_conn_new cn = {0};

	if (t->conn == NULL) {
		testm_runnext(t);
		return 0;
	}

	FFTEST_FUNC;

	test_round_robin_balancer(t);

	//rotate to the 3rd server
	conn->getserv(t->conctx, &cn, 0); //srv2 weight 1
	conn->fin(cn.con, 0);
	cn.con = NULL;
	conn->getserv(t->conctx, &cn, 0); //srv2 weight 2
	conn->fin(cn.con, 0);
	cn.con = NULL;

// connect
	cn.userptr = t;
	conn->getserv(t->conctx, &cn, 0); //get www.google.com
	t->conn_id = cn.con;
	conn->connect(t->conn_id, 0);

	return 0;
}

int testm_conf_connect(ffparser_schem *ps, tester *t, ffpars_ctx *a)
{
	const ffstr *name = &ps->vals[0];
	const fsv_modinfo *m = t->srv->findmod(name->ptr, name->len);
	if (m == NULL)
		return FFPARS_EBADVAL;

	t->conn = m->f->iface("connect");
	if (t->conn == NULL)
		return FFPARS_EBADVAL;

	t->conctx = t->conn->newctx(a, &test_conn_cb);
	if (t->conctx == NULL)
		return FFPARS_EBADVAL;
	return 0;
}

/**
Copyright (c) 2014 Simon Zolin
*/

/*
... <-> mod-listen | mod-connect   <->     mod-ssl
           (socket recv/send)         (SSL crypto only)
*/

#include <core/fserv.h>

#include <FF/net/ssl.h>
#include <FF/list.h>
#include <FFOS/file.h>


#define MOD_SHORT_NAME "SSL "

#define dbglog1(p, level, ...) \
	fsv_dbglog((p)->logctx, level, MOD_SHORT_NAME, NULL, __VA_ARGS__)

#define errlog1(p, level, ...) \
	fsv_errlog((p)->logctx, level, MOD_SHORT_NAME, NULL, __VA_ARGS__)

#define syserrlog1(p, level, fmt, ...) \
	fsv_syserrlog((p)->logctx, level, MOD_SHORT_NAME, NULL, fmt, __VA_ARGS__)

#define SSL_DEF_VERIFY 9


typedef struct fsv_sslm {
	fflist ctxs;
	const fsv_core *srv;
	fsv_logctx *logctx;
} fsv_sslm;

static fsv_sslm *sslm;

typedef struct fsv_sslx {
	fflist_item sib;
	SSL_CTX *sslctx;
	int verify;
	uint verify_depth;

	ffstr ciphers;
	ffstr pkey_fn
		, cert_fn
		, ca_certs_fn;
	char *hostname;
	uint protos;
	uint use_server_cipher;
	uint sess_cache;
	uint sess_cache_size;

	int (*onsrvname)(void *);
} fsv_sslx;

struct fsv_sslcon {
	fsv_sslx *sx;
	SSL *sslcon;
	fsv_logctx *logctx;

	void *param;
	uint64 allin
		, allout;
	int wantop;

	unsigned hshake_logged :1
		, shut_actv :1;
};


// FSERV MODULE
static void * sslm_create(const fsv_core *srv, ffpars_ctx *ctx, fsv_modinfo *mod);
static void sslm_destroy(void);
static int sslm_sig(int signo);
static const void * sslm_iface(const char *name);
const fsv_mod sslm_funcs = {
	&sslm_create, &sslm_destroy, &sslm_sig, &sslm_iface
};

// FSERV SSL
static void* ssl_newctx(ffpars_ctx *args);
static fsv_sslcon* ssl_newcon(void *ctx, fsv_ssl_newcon *opts, int flags);
static int ssl_handshake(fsv_sslcon *c, void **sslbuf, ssize_t *sslbuf_len);
static ssize_t ssl_recv(fsv_sslcon *c, void *buf, size_t size, void **sslbuf, ssize_t *sslbuf_len);
static ssize_t ssl_sendfile(fsv_sslcon *c, ffsf *sf, void **sslbuf, ssize_t *sslbuf_len);
static int ssl_shut(fsv_sslcon *c, void **sslbuf, ssize_t *sslbuf_len);
static int ssl_fin(fsv_sslcon *c);
static ssize_t ssl_getvar(fsv_sslcon *c, const char *name, size_t namelen, void *dst, size_t cap);
static int ssl_setopt(fsv_sslcon *c, int opt, void *data);
static const fsv_ssl ssl_funcs = {
	&ssl_newctx, &ssl_newcon, &ssl_fin,
	&ssl_handshake, &ssl_recv, &ssl_sendfile, &ssl_shut,
	&ssl_getvar, &ssl_setopt,
};

// CONFIG
static int ssl_conf_protos(ffparser_schem *ps, fsv_sslx *sx, ffstr *v);
static int ssl_conf_verify(ffparser_schem *ps, fsv_sslx *sx, const ffstr *s);
static int ssl_conf_sesscache(ffparser_schem *ps, fsv_sslx *sx, ffstr *v);
static int ssl_conf_hostname(ffparser_schem *ps, fsv_sslx *sx, const ffstr *v);
static int ssl_conf_end(ffparser_schem *ps, fsv_sslx *sx);

static void ssl_iolog(fsv_sslcon *c, size_t len);
static void ssl_aio(fsv_sslcon *c, void **sslbuf, ssize_t *sslbuf_len, int r);

FF_EXTN FF_EXP const fsv_mod * fsv_getmod(const char *name);

const fsv_mod * fsv_getmod(const char *name)
{
	if (!ffsz_cmp(name, "ssl"))
		return &sslm_funcs;
	return NULL;
}

static int load_ca(fsv_sslx *sx);
static int ssl_verify_cb(int preverify_ok, X509_STORE_CTX *x509ctx, void *udata);
static int tls_srvname(SSL *ssl, int *ad, void *arg, void *udata);


static const ffpars_arg ssl_args[] = {
	{ "certificate",	FFPARS_TSTR | FFPARS_FREQUIRED | FFPARS_FCOPY,  FFPARS_DSTOFF(fsv_sslx, cert_fn) },
	{ "private_key",	FFPARS_TSTR | FFPARS_FREQUIRED | FFPARS_FCOPY,  FFPARS_DSTOFF(fsv_sslx, pkey_fn) },
	{ "protocols",	FFPARS_TSTR | FFPARS_FLIST,  FFPARS_DST(&ssl_conf_protos) },

	{ "ca_certificate",	FFPARS_TSTR | FFPARS_FCOPY,  FFPARS_DSTOFF(fsv_sslx, ca_certs_fn) },
	{ "verify",	FFPARS_TSTR,  FFPARS_DST(&ssl_conf_verify) },
	{ "verify_depth",	FFPARS_TINT,  FFPARS_DSTOFF(fsv_sslx, verify_depth) },

	{ "ciphers",	FFPARS_TSTR | FFPARS_FSTRZ | FFPARS_FCOPY,  FFPARS_DSTOFF(fsv_sslx, ciphers) },
	{ "use_server_cipher",	FFPARS_TBOOL,  FFPARS_DSTOFF(fsv_sslx, use_server_cipher) },

	{ "session_cache",	FFPARS_TSTR,  FFPARS_DST(ssl_conf_sesscache) },
	{ "session_cache_size",	FFPARS_TINT,  FFPARS_DSTOFF(fsv_sslx, sess_cache_size) },

	{ "tls_hostname",	FFPARS_TSTR,  FFPARS_DST(&ssl_conf_hostname) },
	{ NULL,	FFPARS_TCLOSE,  FFPARS_DST(&ssl_conf_end) },
};

static void ssl_err(int lev, int e)
{
	char buf[1024];
	size_t n = ffssl_errstr(e, buf, sizeof(buf));
	errlog1(sslm, lev, "%*s", n, buf);
}

static void sslcon_err(int lev, int e)
{
	char buf[1024];
	size_t n = ffssl_errstr(e, buf, sizeof(buf));
	errlog1(sslm, lev, "%*s", n, buf);
}

static FFINL void sslx_fin(fsv_sslx *sx)
{
	ffstr_free(&sx->cert_fn);
	ffstr_free(&sx->pkey_fn);
	ffstr_free(&sx->ciphers);
	ffstr_free(&sx->ca_certs_fn);

	ffmem_safefree(sx->hostname);

	if (sx->sslctx != NULL)
		ffssl_ctx_free(sx->sslctx);
	ffmem_free(sx);
}

static void * sslm_create(const fsv_core *srv, ffpars_ctx *ctx, fsv_modinfo *mod)
{
	int e;

	ffmem_init();

	sslm = ffmem_tcalloc1(fsv_sslm);
	if (sslm == NULL) {
		syserrlog1(sslm, FSV_LOG_ERR, "%e", FFERR_BUFALOC);
		return NULL;
	}

	fflist_init(&sslm->ctxs);
	if (0 != (e = ffssl_init())) {
		ssl_err(FSV_LOG_ERR, e);
		goto err;
	}

	{
		const fsvcore_config *conf = srv->conf();
		sslm->logctx = conf->logctx;
	}

	sslm->srv = srv;
	return sslm;

err:
	ffmem_free(sslm);
	return NULL;
}

static int sslm_sig(int signo)
{
	return 0;
}

static void sslm_destroy(void)
{
	FFLIST_ENUMSAFE(&sslm->ctxs, sslx_fin, fsv_sslx, sib);
	ffssl_uninit();
	ffmem_free(sslm);
}


static const void * sslm_iface(const char *name)
{
	if (0 == strcmp(name, "ssl"))
		return &ssl_funcs;
	return NULL;
}

static int tls_srvname(SSL *ssl, int *ad, void *arg, void *udata)
{
	const char *name;
	fsv_sslcon *c = udata;

	if (NULL == (name = ffssl_getptr(ssl, FFSSL_HOSTNAME)))
		return FFSSL_SRVNAME_NOACK;

	dbglog1(c, FSV_LOG_DBGNET, "TLS server name: %s", name);

	if (c->sx->onsrvname != NULL && 0 != c->sx->onsrvname(c->param))
		return FFSSL_SRVNAME_NOACK;

	return FFSSL_SRVNAME_OK;
}

static int ssl_verify_cb(int preverify_ok, X509_STORE_CTX *x509ctx, void *udata)
{
	fsv_sslcon *c = udata;
	X509 *cert;
	int er, depth;
	struct ffssl_cert_info ci;

	er = X509_STORE_CTX_get_error(x509ctx);
	cert = X509_STORE_CTX_get_current_cert(x509ctx);
	depth = X509_STORE_CTX_get_error_depth(x509ctx);

	ffssl_cert_info(cert, &ci);

	dbglog1(c, FSV_LOG_DBGFLOW, "verify: %d, depth: %d.  error: (%d) %s.  Subject: %s.  Issuer: %s."
		, preverify_ok, depth
		, er, ffssl_cert_verify_errstr(er)
		, ci.subject, ci.issuer);

	return preverify_ok;
}

enum {
	FSV_SSL_VERF_OFF
	, FSV_SSL_VERF_ON
	//, FSV_SSL_VERF_OPT
};

static int ssl_conf_verify(ffparser_schem *ps, fsv_sslx *sx, const ffstr *s)
{
	if (ffstr_eqcz(s, "off"))
		return 0;

	if (ffstr_eqcz(s, "on"))
		sx->verify = FSV_SSL_VERF_ON;
	//else if (ffstr_eqcz(s, "optional"))
	//	sx->verify = FSV_SSL_VERF_OPT;
	else
		return FFPARS_EBADVAL;

	return 0;
}

enum {
	FSV_SSL_SESSCACHE_DEF
	, FSV_SSL_SESSCACHE_OFF
};

static const char *const sesscach_str[] = {
	"default", "off"
};

static int ssl_conf_sesscache(ffparser_schem *ps, fsv_sslx *sx, ffstr *v)
{
	ssize_t i = ffs_findarrz(sesscach_str, FFCNT(sesscach_str), v->ptr, v->len);
	if (i == -1)
		return FFPARS_EBADVAL;
	sx->sess_cache = i;
	return 0;
}

// enum FFSSL_PROTO
static const char * const ssl_proto_str[] = {
	"ssl3", "tls1", "tls1_1", "tls1_2"
};

static int ssl_conf_protos(ffparser_schem *ps, fsv_sslx *sx, ffstr *v)
{
	ssize_t i = ffs_findarrz(ssl_proto_str, FFCNT(ssl_proto_str), v->ptr, v->len);
	if (i == -1)
		return FFPARS_EBADVAL;
	sx->protos |= (1 << i);
	return 0;
}

static int load_ca(fsv_sslx *sx)
{
	char *fn;
	int e;

	if (sx->ca_certs_fn.len == 0) {
		errlog1(sslm, FSV_LOG_ERR, "verify is enabled, but ca_certificate is not specified");
		return FFPARS_EBADVAL;
	}

	if (NULL == (fn = sslm->srv->getpath(NULL, NULL, sx->ca_certs_fn.ptr, sx->ca_certs_fn.len)))
		return FFPARS_EBADVAL;

	if (0 != (e = ffssl_ctx_ca(sx->sslctx, &ssl_verify_cb, sx->verify_depth, fn))) {
		ssl_err(FSV_LOG_ERR, e);
		e = FFPARS_EINTL;
		goto done;
	}

	e = 0;

done:
	ffmem_free(fn);
	ffstr_free(&sx->ca_certs_fn);
	return e;
}

static int ssl_conf_end(ffparser_schem *ps, fsv_sslx *sx)
{
	int r, e;
	struct ffssl_ctx_conf sslconf = {};

	if (NULL == (sslconf.certfile = sslm->srv->getpath(NULL, NULL, sx->cert_fn.ptr, sx->cert_fn.len))
		|| NULL == (sslconf.pkeyfile = sslm->srv->getpath(NULL, NULL, sx->pkey_fn.ptr, sx->pkey_fn.len))) {
		e = FFPARS_EBADVAL;
		goto done;
	}

	sslconf.ciphers = (sx->ciphers.ptr != NULL) ? sx->ciphers.ptr : "";
	sslconf.use_server_cipher = sx->use_server_cipher;
	sslconf.tls_srvname_func = &tls_srvname;
	sslconf.allowed_protocols = sx->protos;

	if (0 != (e = ffssl_ctx_conf(sx->sslctx, &sslconf))) {
		ssl_err(FSV_LOG_ERR, e);
		e = FFPARS_EINTL;
		goto done;
	}

	if (sx->verify != FSV_SSL_VERF_OFF) {
		if (0 != (r = load_ca(sx))) {
			e = r;
			goto done;
		}
	}

	if (sx->sess_cache == FSV_SSL_SESSCACHE_OFF)
		ffssl_ctx_cache(sx->sslctx, -1);
	else
		ffssl_ctx_cache(sx->sslctx, sx->sess_cache_size);

	e = 0;

done:
	ffmem_safefree(sslconf.certfile);
	ffmem_safefree(sslconf.pkeyfile);
	ffstr_free(&sx->pkey_fn);
	ffstr_free(&sx->cert_fn);
	return e;
}

static int ssl_conf_hostname(ffparser_schem *ps, fsv_sslx *sx, const ffstr *v)
{
	sx->hostname = ffmem_alloc(v->len + 1);
	if (sx->hostname == NULL)
		return FFPARS_ESYS;
	ffsz_copy(sx->hostname, v->len + 1, v->ptr, v->len);
	return 0;
}

static void* ssl_newctx(ffpars_ctx *args)
{
	int e;
	fsv_sslx *sx = ffmem_tcalloc1(fsv_sslx);
	if (sx == NULL) {
		syserrlog1(sslm, FSV_LOG_ERR, "%e", FFERR_BUFALOC);
		return NULL;
	}

	if (0 != (e = ffssl_ctx_create(&sx->sslctx))) {
		ssl_err(FSV_LOG_ERR, e);
		goto err;
	}

	sx->verify_depth = SSL_DEF_VERIFY;

	ffpars_setargs(args, sx, ssl_args, FFCNT(ssl_args));
	return sx;

err:
	ffmem_free(sx);
	return NULL;
}

static fsv_sslcon * ssl_newcon(void *ctx, fsv_ssl_newcon *opts, int flags)
{
	fsv_sslx *sx = ctx;
	fsv_sslcon *c;
	int e, f = 0;
	ffssl_opt sslopt = {0};

	c = ffmem_tcalloc1(fsv_sslcon);
	if (c == NULL) {
		syserrlog1(sslm, FSV_LOG_ERR, "%e", FFERR_BUFALOC);
		return NULL;
	}

	c->sx = sx;
	c->sx->onsrvname = opts->srvname_cb;
	c->param = opts->srvname_param;
	c->logctx = (opts->logctx != NULL) ? opts->logctx : sslm->logctx;

	if (flags == FSV_SSL_ACCEPT)
		f = FFSSL_ACCEPT;
	else
		sslopt.tls_hostname = c->sx->hostname;
	sslopt.udata = c;
	if (0 != (e = ffssl_create(&c->sslcon, sx->sslctx, f | FFSSL_IOBUF, &sslopt))) {
		ssl_err(FSV_LOG_ERR, e);
		goto fail;
	}

	return c;

fail:
	if (c->sslcon != NULL)
		ffssl_free(c->sslcon);
	ffmem_free(c);
	return NULL;
}

static int ssl_shut(fsv_sslcon *c, void **sslbuf, ssize_t *sslbuf_len)
{
	int e;

	if (!c->shut_actv) {
		c->shut_actv = 1;
		dbglog1(c, FSV_LOG_DBGNET, "performing shutdown...");

		ffssl_input(c->sslcon, (size_t)-1);
		c->wantop = 0;
	}

	if (*sslbuf_len != -1) {
		ffssl_input(c->sslcon, *sslbuf_len);
		ssl_iolog(c, *sslbuf_len);

	} else if (c->wantop != 0) {
		ffstr s;
		ffssl_iobuf(c->sslcon, &s);
		*sslbuf = s.ptr;
		*sslbuf_len = s.len;
		return c->wantop;
	}

	if (0 != (e = ffssl_shut(c->sslcon))) {
		if (e == FFSSL_WANTREAD) {
			ssl_aio(c, sslbuf, sslbuf_len, e);
			return FSV_SSL_WANTREAD;

		} else if (e == FFSSL_WANTWRITE) {
			ssl_aio(c, sslbuf, sslbuf_len, e);
			return FSV_SSL_WANTWRITE;
		}

		sslcon_err(FSV_LOG_ERR, e);
		return FSV_SSL_ERR;
	}

	return 0;
}

static int ssl_fin(fsv_sslcon *c)
{
	dbglog1(c, FSV_LOG_DBGFLOW
		, "finish SSL connection: read:%U, written:%U, renegotiations:%u"
		, c->allin, c->allout, (int)ffssl_get(c->sslcon, FFSSL_NUM_RENEGOTIATIONS));

	ffssl_free(c->sslcon);
	ffmem_free(c);
	return 0;
}

static void ssl_iolog(fsv_sslcon *c, size_t len)
{
	if (c->wantop == FSV_SSL_WANTWRITE) {
		c->allout += len;
		dbglog1(c, FSV_LOG_DBGNET, "SSL send +%L [%U]"
			, len, c->allout);

	} else {
		c->allin += len;
		dbglog1(c, FSV_LOG_DBGNET, "SSL recv +%L [%U]"
			, len, c->allin);
	}

	c->wantop = 0;
}

static void ssl_aio(fsv_sslcon *c, void **sslbuf, ssize_t *sslbuf_len, int r)
{
	ffstr s;
	ffssl_iobuf(c->sslcon, &s);
	*sslbuf = s.ptr;
	*sslbuf_len = s.len;
	c->wantop = (r == FFSSL_WANTREAD) ? FSV_SSL_WANTREAD : FSV_SSL_WANTWRITE;
}

static int ssl_handshake(fsv_sslcon *c, void **sslbuf, ssize_t *sslbuf_len)
{
	int e;

	if (*sslbuf_len != -1) {
		ffssl_input(c->sslcon, *sslbuf_len);
		ssl_iolog(c, *sslbuf_len);

	} else if (c->wantop != 0) {
		ffstr s;
		ffssl_iobuf(c->sslcon, &s);
		*sslbuf = s.ptr;
		*sslbuf_len = s.len;
		return c->wantop;
	}

	if (!c->hshake_logged) {
		c->hshake_logged = 1;
		dbglog1(c, FSV_LOG_DBGNET, "performing handshake...");
	}

	if (0 != (e = ffssl_handshake(c->sslcon))) {
		if (e == FFSSL_WANTREAD) {
			ssl_aio(c, sslbuf, sslbuf_len, e);
			return FSV_SSL_WANTREAD;

		} else if (e == FFSSL_WANTWRITE) {
			ssl_aio(c, sslbuf, sslbuf_len, e);
			return FSV_SSL_WANTWRITE;
		}

		sslcon_err(FSV_LOG_ERR, e);
		return -1;
	}

	dbglog1(c, FSV_LOG_DBGNET, "handshake done.  proto: %s, cipher: %s, reused session: %d."
		, ffssl_getptr(c->sslcon, FFSSL_VERSION)
		, ffssl_getptr(c->sslcon, FFSSL_CIPHER_NAME)
		, (int)ffssl_get(c->sslcon, FFSSL_SESS_REUSED));

	if (c->sx->verify == FSV_SSL_VERF_ON) {
		if (X509_V_OK != ffssl_get(c->sslcon, FFSSL_CERT_VERIFY_RESULT)) {
			errlog1(sslm, FSV_LOG_ERR, "failed to verify peer certificate");
			ffssl_ctx_sess_del(c->sx->sslctx, c->sslcon);
			return -1;
		}
	}

	return 0;
}

/**
1. (sslbuf_len == -1).  Set sslbuf and sslbuf_len.  Return I/O operation.
2. (sslbuf_len != -1).  Process received data.  Return the number of decoded bytes received.
*/
static ssize_t ssl_recv(fsv_sslcon *c, void *buf, size_t size, void **sslbuf, ssize_t *sslbuf_len)
{
	int r;

	if (*sslbuf_len != -1) {
		ffssl_input(c->sslcon, *sslbuf_len);
		ssl_iolog(c, *sslbuf_len);

	} else if (c->wantop != 0) {
		ffstr s;
		ffssl_iobuf(c->sslcon, &s);
		*sslbuf = s.ptr;
		*sslbuf_len = s.len;
		return c->wantop;
	}

	r = ffssl_read(c->sslcon, buf, size);
	if (r < 0) {
		r = -r;
		if (r == FFSSL_WANTREAD) {
			ssl_aio(c, sslbuf, sslbuf_len, r);
			return FSV_SSL_WANTREAD;

		} else if (r == FFSSL_WANTWRITE) {
			errlog1(sslm, FSV_LOG_INFO, "SSL renegotiation");
			ssl_aio(c, sslbuf, sslbuf_len, r);
			return FSV_SSL_WANTWRITE;
		}

		sslcon_err(FSV_LOG_ERR, r);
		return FSV_SSL_ERR;
	}
	return r;
}

static ssize_t ssl_sendfile(fsv_sslcon *c, ffsf *sf, void **sslbuf, ssize_t *sslbuf_len)
{
	int r;
	ffstr dat;

	if (*sslbuf_len != -1) {
		ffssl_input(c->sslcon, *sslbuf_len);
		ssl_iolog(c, *sslbuf_len);

	} else if (c->wantop != 0) {
		ffstr s;
		ffssl_iobuf(c->sslcon, &s);
		*sslbuf = s.ptr;
		*sslbuf_len = s.len;
		return c->wantop;
	}

	if (-1 == ffsf_nextchunk(sf, &dat))
		return FSV_SSL_ERR;

	r = ffssl_write(c->sslcon, dat.ptr, dat.len);
	if (r < 0) {
		r = -r;
		if (r == FFSSL_WANTWRITE) {
			ssl_aio(c, sslbuf, sslbuf_len, r);
			return FSV_SSL_WANTWRITE;

		} else if (r == FFSSL_WANTREAD) {
			errlog1(sslm, FSV_LOG_INFO, "SSL renegotiation");
			ssl_aio(c, sslbuf, sslbuf_len, r);
			return FSV_SSL_WANTREAD;
		}

		sslcon_err(FSV_LOG_ERR, r);
		return FSV_SSL_ERR;
	}

	return r;
}

static ssize_t ssl_getvar(fsv_sslcon *c, const char *name, size_t namelen, void *dst, size_t cap)
{
	if (ffs_eqcz(name, namelen, "https")) {
		*(char**)dst = "1";
		return 1;

	} else if (ffs_eqcz(name, namelen, "ssl_servername")) {
		const char *name = ffssl_getptr(c->sslcon, FFSSL_HOSTNAME);
		if (name == NULL)
			return -1;

		*(const char**)dst = name;
		return ffsz_len(name);

	} else
		return -1;
	return 0;
}

static int ssl_setopt(fsv_sslcon *c, int opt, void *data)
{
	switch (opt) {
	case FSV_SSL_OPT_LOG:
		c->logctx = data;
		break;

	case FSV_SSL_OPT_SSLCTX: {
		fsv_sslx *sx = data;
		ffssl_setctx(c->sslcon, sx->sslctx);
		}
		break;
	}
	return 0;
}

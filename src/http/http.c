/** Handle HTTP connections.
Copyright 2014 Simon Zolin.
*/

#include <http/http.h>
#include <FFOS/process.h>
#include <FF/path.h>
#include <FF/json.h>


httpmodule *httpm;

// FSERV MODULE
static void * httpm_create(const fsv_core *core, ffpars_ctx *c, fsv_modinfo *m);
static void httpm_destroy(void);
static int httpm_sig(int sig);
static const void * httpm_iface(const char *name);
static const fsv_mod fsv_http_mod = {
	&httpm_create, &httpm_destroy, &httpm_sig, &httpm_iface
};

// HTTP MODULE
static ssize_t http_getvar(void *con, const char *name, size_t namelen, void *dst, size_t cap);
extern void http_send(fsv_httpfilter *_hf, const void *buf, size_t len, int flags);
extern void http_sendv(fsv_httpfilter *_hf, ffiovec *iovs, size_t n, int flags);
extern void http_sendfile(fsv_httpfilter *_hf, fffd fd, uint64 fsize, uint64 foffset, sf_hdtr *hdtr, int flags);
const fsv_http fsv_http_iface = {
	&http_getvar, &http_send, &http_sendv, &http_sendfile
};

// MOD-LISTEN CALLBACKS
static void http_onaccept(void *userctx, fsv_lsncon *conn);
static int http_onsig(fsv_lsncon *conn, void *userptr, int sig);
static const fsv_listen_cb http_lisn_cb = {
	&http_onaccept, &http_onsig
};

// STATUS
static void http_status(const fsv_status *statusmod);
static const fsv_status_handler http_stat_iface = {
	&http_status
};

// CONFIG
static const char * http_conf_err(int cod);
static int httpm_conf_log(ffparser_schem *ps, httpmodule *hm, ffpars_ctx *args);
static int httpm_conf_host(ffparser_schem *ps, httpmodule *hm, ffpars_ctx *args);
static int httpm_conf_server(ffparser_schem *ps, httpmodule *hm, ffpars_ctx *args);
static int httpm_conf_errorhandler(ffparser_schem *ps, httpmodule *hm, ffpars_ctx *args);
static int httpm_conf_sktopt(ffparser_schem *ps, httpmodule *hm, ffpars_ctx *args);
static int httpm_conf_end(ffparser_schem *ps, httpmodule *hm);

static int hthost_conf_log(ffparser_schem *ps, httphost *h, ffpars_ctx *args);
static int hthost_conf_use_listener(ffparser_schem *ps, httphost *h, const ffstr *val);
static int hthost_conf_alias(ffparser_schem *ps, httphost *h, const ffstr *val);
static int hthost_conf_errorhandler(ffparser_schem *ps, httphost *h, ffpars_ctx *args);
static int hthost_conf_target_ex(ffparser_schem *ps, httphost *h, ffpars_ctx *args, httptarget *parent);
static int hthost_conf_target(ffparser_schem *ps, httphost *h, ffpars_ctx *args);
static int hthost_conf_targetany(ffparser_schem *ps, httphost *h, ffpars_ctx *args);
static int hthost_conf_respfilter(ffparser_schem *ps, httphost *h, ffpars_ctx *args);
static int hthost_conf_end(ffparser_schem *ps, httphost *h);

static int httgt_conf_index(ffparser_schem *ps, httptarget *tgt, const ffstr *val);
static int httgt_conf_log(ffparser_schem *ps, httptarget *tgt, ffpars_ctx *args);
static int httgt_conf_target(ffparser_schem *ps, httptarget *tgt, ffpars_ctx *args);
static int httgt_conf_handler(ffparser_schem *ps, httptarget *tgt, ffpars_ctx *args);

static int http_conf_resphdrs(ffparser_schem *ps, httphost *h, ffpars_ctx *args);
static int http_conf_resphdr_item(ffparser_schem *ps, httphost *h, const ffstr *val);
static int http_conf_handler(ffparser_schem *ps, ffpars_ctx *args, http_submod *sm);

// VHOSTS
static httphost * http_defhost(fsv_lsncon *conn);
static void hthost_destroy(httphost *h);
static int hthost_hbn_init(void);
static int hthost_hbn_cmpkey(void *val, const char *key, size_t keylen, void *param);

static int hthost_hstroute_init(httphost *h);
static int hthost_hstroute_cmpkey(void *val, const char *key, size_t keylen, void *param);
static void hstroute_free(httptarget *tgt);

// LOG
static int http_logadd(fsv_logctx *lx, int lev, const char *modname, const ffstr *trid, const char *fmt, ...);
static int http_logaddv(fsv_logctx *lx, int lev, const char *modname, const ffstr *trid, const char *fmt, va_list va);
static const fsv_log http_log = {
	NULL, &http_logadd, &http_logaddv
};

static void http_prepare(httpcon *c);
static void http_statustimer(const fftime *now, void *param);
static int http_hstvar_init(void);
static ssize_t http_getvar_hdr(httpcon *c, const ffstr *nm, void *dst);


static void oninit(void)
{
	ffos_init();
	if (0 != ffskt_init(FFSKT_WSAFUNCS)
		|| 0 != ffhttp_initheaders())
		ffps_exit(1);
	//ffhttp_freeheaders()
}

FFDL_ONINIT(oninit, NULL)


typedef struct httpmod_t {
	const char *name;
	const fsv_mod *f;
} httpmod_t;

extern const fsv_mod fsv_http_errdoc;
extern const fsv_mod fsv_http_stfl;
extern const fsv_mod fsv_http_drix;
extern const fsv_mod fsv_http_stat;
extern const fsv_mod fsv_http_gzip;

static const httpmod_t http_mods[] = {
	{ "http", &fsv_http_mod }
	, { "errdoc", &fsv_http_errdoc }
	, { "static-file", &fsv_http_stfl }
	, { "dir-index", &fsv_http_drix }
	, { "status", &fsv_http_stat }
	, { "gzip", &fsv_http_gzip }
};

FF_EXTN FF_EXP const fsv_mod * fsv_getmod(const char *name)
{
	int i;
	for (i = 0; i != FFCNT(http_mods); ++i) {
		const httpmod_t *mc = &http_mods[i];
		if (0 == ffsz_cmp(name, mc->name))
			return mc->f;
	}
	return NULL;
}


static const ffpars_arg httpm_conf_args[] = {
	{ "log",  FFPARS_TOBJ | FFPARS_FOBJ1,  FFPARS_DST(&httpm_conf_log) }
	, { "host",  FFPARS_TOBJ | FFPARS_FOBJ1 | FFPARS_FMULTI | FFPARS_FREQUIRED,  FFPARS_DST(&httpm_conf_host) }
	, { "server",  FFPARS_TOBJ | FFPARS_FOBJ1 | FFPARS_FMULTI,  FFPARS_DST(&httpm_conf_server) }
	, { "error_handler",  FFPARS_TOBJ | FFPARS_FOBJ1 | FFPARS_FREQUIRED,  FFPARS_DST(&httpm_conf_errorhandler) }
	, { "socket_option",  FFPARS_TOBJ,  FFPARS_DST(&httpm_conf_sktopt) }

	, { "read_header_timeout",  FFPARS_TINT | FFPARS_F16BIT | FFPARS_FNOTZERO,  FFPARS_DSTOFF(httpmodule, read_header_tmout) }
	, { "keepalive_timeout",  FFPARS_TINT | FFPARS_F16BIT | FFPARS_FNOTZERO,  FFPARS_DSTOFF(httpmodule, keepalive_tmout) }

	, { "read_header_growby",  FFPARS_TSIZE | FFPARS_FNOTZERO,  FFPARS_DSTOFF(httpmodule, read_header_growby) }
	, { "max_header_size",  FFPARS_TSIZE | FFPARS_FNOTZERO,  FFPARS_DSTOFF(httpmodule, max_header_size) }
	, { "max_keepalive_requests",  FFPARS_TINT,  FFPARS_DSTOFF(httpmodule, max_keepalive_requests) }

	, { NULL,  FFPARS_TCLOSE,  FFPARS_DST(&httpm_conf_end) }
};

static const ffpars_arg hthost_conf_args[] = {
	{ "log",  FFPARS_TOBJ,  FFPARS_DST(&hthost_conf_log) }
	, { "use_listener",  FFPARS_TSTR | FFPARS_FLIST,  FFPARS_DST(&hthost_conf_use_listener) }
	, { "alias",  FFPARS_TSTR | FFPARS_FLIST,  FFPARS_DST(&hthost_conf_alias) }
	, { "linger",  FFPARS_TBOOL,  FFPARS_DSTOFF(httphost, linger) }
	, { "error_handler",  FFPARS_TOBJ | FFPARS_FOBJ1,  FFPARS_DST(&hthost_conf_errorhandler) }
	, { "default_mime_type",  FFPARS_TSTR | FFPARS_FCOPY,  FFPARS_DSTOFF(httphost, def_mime_type) }
	, { "request_body_buffer",  FFPARS_TSIZE,  FFPARS_DSTOFF(httphost, reqbody_buf_size) }
	, { "max_request_body",  FFPARS_TSIZE | FFPARS_F64BIT,  FFPARS_DSTOFF(httphost, max_reqbody) }
	, { "response_headers",  FFPARS_TOBJ,  FFPARS_DST(&http_conf_resphdrs) }
	, { "accesslog_info",  FFPARS_TSTR | FFPARS_FCOPY,  FFPARS_DSTOFF(httphost, accesslog_info) }

	, { "read_body_timeout",  FFPARS_TINT | FFPARS_F16BIT | FFPARS_FNOTZERO,  FFPARS_DSTOFF(httphost, read_body_tmout) }
	, { "write_timeout",  FFPARS_TINT | FFPARS_F16BIT | FFPARS_FNOTZERO,  FFPARS_DSTOFF(httphost, write_tmout) }

	, { "resp_filter",  FFPARS_TOBJ | FFPARS_FOBJ1 | FFPARS_FMULTI,  FFPARS_DST(&hthost_conf_respfilter) }
	, { "target",  FFPARS_TOBJ | FFPARS_FOBJ1 | FFPARS_FMULTI | FFPARS_FNOTEMPTY,  FFPARS_DST(&hthost_conf_target) }
	, { "path",  FFPARS_TOBJ | FFPARS_FOBJ1 | FFPARS_FMULTI | FFPARS_FNOTEMPTY,  FFPARS_DST(&hthost_conf_target) }
	, { "target_any",  FFPARS_TOBJ,  FFPARS_DST(&hthost_conf_targetany) }

	, { NULL,  FFPARS_TCLOSE,  FFPARS_DST(&hthost_conf_end) }
};

#define HTTP_LOG_DEF_ACCESSINFO  "\"$host\" \"$remote_addr\" \"$http_user_agent\""

static const ffpars_arg httgt_conf_args[] = {
	{ "log",  FFPARS_TOBJ,  FFPARS_DST(&httgt_conf_log) }
	, { "index",  FFPARS_TSTR | FFPARS_FLIST,  FFPARS_DST(&httgt_conf_index) }
	, { "target",  FFPARS_TOBJ | FFPARS_FOBJ1 | FFPARS_FMULTI,  FFPARS_DST(httgt_conf_target) }
	, { "path",  FFPARS_TOBJ | FFPARS_FOBJ1 | FFPARS_FMULTI,  FFPARS_DST(httgt_conf_target) }

	, { "handler",  FFPARS_TOBJ | FFPARS_FOBJ1,  FFPARS_DST(&httgt_conf_handler) }
	, { "file_handler",  FFPARS_TOBJ | FFPARS_FOBJ1,  FFPARS_DST(&httgt_conf_handler) }
	, { "dir_handler",  FFPARS_TOBJ | FFPARS_FOBJ1,  FFPARS_DST(&httgt_conf_handler) }
};

static const ffpars_arg http_conf_resphdrs_args[] = {
	{ "*",  FFPARS_TSTR,  FFPARS_DST(&http_conf_resphdr_item) }
};


static const char *const http_conf_serr[] = {
	"specified module was not found"
	, "module doesn't implement required interface"
	, "can't create module context"
};

/** fserv.core calls this function to print configuration-time error. */
static const char * http_conf_err(int cod)
{
	cod -= HTTP_CONF_ENOMOD;
	FF_ASSERT(cod < FFCNT(http_conf_serr));
	return http_conf_serr[cod];
}

static int httpm_conf_log(ffparser_schem *ps, httpmodule *hm, ffpars_ctx *args)
{
	const ffstr *name = &ps->vals[0];
	const fsv_log *log_iface;
	const fsv_modinfo *m = httpm->core->findmod(name->ptr, name->len);
	if (m == NULL)
		return HTTP_CONF_ENOMOD;

	log_iface = m->f->iface("log");
	if (log_iface == NULL)
		return HTTP_CONF_ENOIFACE;

	httpm->logctx = log_iface->newctx(args, httpm->logctx);
	if (httpm->logctx == NULL)
		return HTTP_CONF_EMODCTX;

	return 0;
}

static int httpm_conf_server(ffparser_schem *ps, httpmodule *hm, ffpars_ctx *args)
{
	fsv_lsnctx *lsnr;
	const ffstr *mod = &ps->vals[0];
	const fsv_modinfo *m = httpm->core->findmod(mod->ptr, mod->len);
	if (m == NULL)
		return HTTP_CONF_ENOMOD;

	httpm->lisn = m->f->iface("listen");
	if (httpm->lisn == NULL)
		return HTTP_CONF_ENOIFACE;

	lsnr = httpm->lisn->newctx(args, &http_lisn_cb, NULL);
	if (lsnr == NULL)
		return HTTP_CONF_EMODCTX;

	return 0;
}

static int httpm_conf_errorhandler(ffparser_schem *ps, httpmodule *hm, ffpars_ctx *args)
{
	return http_conf_handler(ps, args, &httpm->err_hdler);
}

static int httpm_conf_sktopt(ffparser_schem *ps, httpmodule *hm, ffpars_ctx *args)
{
	ffpars_setargs(args, &hm->sktopt, fsv_sktopt_conf, FFCNT(fsv_sktopt_conf));
	return 0;
}

static int httpm_conf_end(ffparser_schem *ps, httpmodule *hm)
{
	if (0 != hthost_hbn_init())
		return FFPARS_ESYS;
	return 0;
}

static int httpm_conf_host(ffparser_schem *ps, httpmodule *hm, ffpars_ctx *args)
{
	int rc;
	const ffstr *hostname = &ps->vals[0];
	httphost *h = ffmem_tcalloc1(httphost);
	if (h == NULL)
		return FFPARS_ESYS;
	fflist_ins(&httpm->hosts, &h->sib);

	h->logctx = httpm->logctx;
	h->err_hdler = httpm->err_hdler;
	h->reqbody_buf_size = 8 * 1024;
	h->max_reqbody = (uint64)-1;
	h->read_body_tmout = 65;
	h->write_tmout = 65;
	h->linger = 1;

	rc = hthost_conf_alias(NULL, h, hostname);
	if (rc != 0) {
		ffmem_free(h);
		return rc;
	}

	ffpars_setargs(args, h, hthost_conf_args, FFCNT(hthost_conf_args));
	return 0;
}

static void hthost_destroy(httphost *h)
{
	ffstr_free(&h->resp_hdrs);
	ffarr_free(&h->names);
	ffhst_free(&h->hstroute);
	ffmem_free(h->anytarget);
	FFLIST_ENUMSAFE(&h->routes, hstroute_free, httptarget, sib);
	ffarr_free(&h->listeners);

	if (!h->def_mime_type_static)
		ffstr_free(&h->def_mime_type);

	if (!h->accesslog_info_static)
		ffstr_free(&h->accesslog_info);

	ffmem_free(h);
}

static int hthost_conf_log(ffparser_schem *ps, httphost *h, ffpars_ctx *args)
{
	h->logctx = fsv_logctx_get(httpm->logctx)->mlog->newctx(args, h->logctx);
	if (h->logctx == NULL)
		return FFPARS_EINTL;
	return 0;
}

static int hthost_conf_use_listener(ffparser_schem *ps, httphost *h, const ffstr *val)
{
	fsv_lsnctx **lx = ffarr_push(&h->listeners, fsv_lsnctx*);
	if (lx == NULL)
		return FFPARS_ESYS;
	*lx = httpm->lisn->findctx(val->ptr, val->len);
	if (*lx == NULL)
		return FFPARS_EBADVAL;
	return 0;
}

static int hthost_conf_alias(ffparser_schem *ps, httphost *h, const ffstr *val)
{
	if (NULL == ffarr_grow(&h->names, val->len + 1, 0))
		return FFPARS_ESYS;
	ffsz_copy(ffarr_end(&h->names), ffarr_unused(&h->names), val->ptr, val->len);
	h->names.len += val->len + 1;
	return 0;
}

static int hthost_conf_errorhandler(ffparser_schem *ps, httphost *h, ffpars_ctx *args)
{
	return http_conf_handler(ps, args, &h->err_hdler);
}

static int httgt_conf_index(ffparser_schem *ps, httptarget *tgt, const ffstr *val)
{
	if (!ffpath_isvalidfn(val->ptr, val->len))
		return FFPARS_EBADVAL;

	if (NULL == ffarr_grow(&tgt->index, val->len + 1, 0))
		return FFPARS_ESYS;
	ffsz_copy(ffarr_end(&tgt->index), ffarr_unused(&tgt->index), val->ptr, val->len);
	tgt->index.len += val->len + 1;
	return 0;
}

static int hthost_hbn_cmpkey(void *val, const char *key, size_t keylen, void *param)
{
	hostbyname *hbn = val;
	fsv_lsnctx **lx;

	if (!ffstr_eq(&hbn->name, key, keylen))
		return -1;

	if (hbn->host->listeners.len == 0)
		return 0; //the host is for all listeners

	FFARR_WALK(&hbn->host->listeners, lx) {
		if (*lx == param)
			return 0;
	}

	return -1;
}

/** Initialize name => host hash table. */
static int hthost_hbn_init(void)
{
	size_t names_size = 0, names_count = 0;
	httphost *h;
	hostbyname *hbn;

	FFLIST_WALK(&httpm->hosts, h, sib) {
		names_size += h->names.len;
		names_count += ffs_nfindc(h->names.ptr, h->names.len, '\0');
	}

	if (0 != ffhst_init(&httpm->ht_hbn, names_count))
		return 1;
	httpm->ht_hbn.cmpkey = &hthost_hbn_cmpkey;

	if (NULL == ffarr_alloc(&httpm->hbn_arr, names_size))
		return 1;
	httpm->hbn_arr.len = names_size;
	hbn = httpm->hbn_arr.ptr;

	FFLIST_WALK(&httpm->hosts, h, sib) {
		char *nm;
		size_t len;
		uint hash;
		for (nm = h->names.ptr;  nm != ffarr_end(&h->names);  nm += len + 1) {
			len = ffsz_len(nm);

			ffstr_set(&hbn->name, nm, len);
			hbn->host = h;

			hash = ffcrc32_get(nm, len, FFCRC_ICASE);
			if (ffhst_ins(&httpm->ht_hbn, hash, hbn++) < 0)
				return 1;
		}
	}

	return 0;
}

static int hthost_conf_respfilter(ffparser_schem *ps, httphost *h, ffpars_ctx *args)
{
	http_submod *sm = ffarr_push(&h->resp_filters, http_submod);
	if (sm == NULL)
		return FFPARS_ESYS;

	return http_conf_handler(ps, args, sm);
}

static int hthost_conf_target_ex(ffparser_schem *ps, httphost *h, ffpars_ctx *args, httptarget *parent)
{
	const ffstr *path = &ps->vals[0];
	char *p;
	size_t npath = path->len + ((parent != NULL) ? parent->path.len : 0);
	httptarget *tgt;

	tgt = ffmem_calloc(1, sizeof(httptarget) + npath);
	if (tgt == NULL)
		return FFPARS_ESYS;
	fflist_ins(&h->routes, &tgt->sib);

	p = tgt->path_s;
	if (parent != NULL)
		p = ffmem_copy(tgt->path_s, parent->path.ptr, parent->path.len);
	ffmemcpy(p, path->ptr, path->len);
	ffstr_set(&tgt->path, tgt->path_s, npath);

	tgt->host = h;
	tgt->logctx = h->logctx;
	tgt->ispath = !ffsz_cmp(ps->curarg->name, "path");

	ffpars_setargs(args, tgt, httgt_conf_args, FFCNT(httgt_conf_args));
	return 0;
}

static int hthost_conf_target(ffparser_schem *ps, httphost *h, ffpars_ctx *args)
{
	return hthost_conf_target_ex(ps, h, args, NULL);
}

static int hthost_conf_targetany(ffparser_schem *ps, httphost *h, ffpars_ctx *args)
{
	httptarget *tgt = ffmem_calloc(1, sizeof(httptarget) + 0);
	if (tgt == NULL)
		return FFPARS_ESYS;
	tgt->host = h;
	tgt->logctx = h->logctx;
	h->anytarget = tgt;
	ffpars_setargs(args, tgt, httgt_conf_args, FFCNT(httgt_conf_args));
	return 0;
}

static int hthost_conf_end(ffparser_schem *ps, httphost *h)
{
	ffstr_setz(&h->name, h->names.ptr);

	if (h->accesslog_info.ptr == NULL) {
		ffstr_setcz(&h->accesslog_info, HTTP_LOG_DEF_ACCESSINFO);
		h->accesslog_info_static = 1;
	}

	if (h->def_mime_type.ptr == NULL) {
		ffstr_setcz(&h->def_mime_type, "application/octet-stream");
		h->def_mime_type_static = 1;
	}

	return hthost_hstroute_init(h);
}

static int httgt_conf_log(ffparser_schem *ps, httptarget *tgt, ffpars_ctx *args)
{
	tgt->logctx = fsv_logctx_get(tgt->host->logctx)->mlog->newctx(args, tgt->logctx);
	if (tgt->logctx == NULL)
		return FFPARS_EINTL;
	return 0;
}

static int httgt_conf_target(ffparser_schem *ps, httptarget *tgt, ffpars_ctx *args)
{
	if (tgt->path.len == 0)
		return FFPARS_EBADVAL; //no sub-paths for target_any

	return hthost_conf_target_ex(ps, tgt->host, args, tgt);
}

static int httgt_conf_handler(ffparser_schem *ps, httptarget *tgt, ffpars_ctx *args)
{
	http_submod *sm;
	int r;

	sm = &tgt->file_hdler;
	if (!ffsz_cmp(ps->curarg->name, "dir_handler"))
		sm = &tgt->dir_hdler;

	r = http_conf_handler(ps, args, sm);
	if (r != 0)
		return r;

	if (!ffsz_cmp(ps->curarg->name, "handler"))
		tgt->dir_hdler = *sm;
	return 0;
}

/** Get context pointer of HTTP handler module. */
static int http_conf_handler(ffparser_schem *ps, ffpars_ctx *args, http_submod *sm)
{
	fsv_http_hdlctx ctx = {0};
	const fsv_httphandler_iface *hi;
	const ffstr *modname = &ps->vals[0];
	const fsv_modinfo *m = httpm->core->findmod(modname->ptr, modname->len);
	if (m == NULL)
		return HTTP_CONF_ENOMOD;

	hi = m->f->iface("http-handler");
	if (hi == NULL)
		return HTTP_CONF_ENOIFACE;

	ctx.http = &fsv_http_iface;
	ctx.args = args;
	if (0 != hi->newctx(&ctx))
		return HTTP_CONF_EMODCTX;

	sm->hctx = ctx.hctx;
	sm->handler = ctx.handler;
	sm->modname = m->name;
	return 0;
}

static int http_conf_resphdrs(ffparser_schem *ps, httphost *h, ffpars_ctx *args)
{
	ffpars_setargs(args, h, http_conf_resphdrs_args, FFCNT(http_conf_resphdrs_args));
	return 0;
}

static int http_conf_resphdr_item(ffparser_schem *ps, httphost *h, const ffstr *val)
{
	char *p;
	http_resphdr *rh;

	p = ffmem_realloc(h->resp_hdrs.ptr, h->resp_hdrs.len + sizeof(http_resphdr) + val->len);
	if (p == NULL)
		return FFPARS_ESYS;

	h->resp_hdrs.ptr = p;
	rh = (http_resphdr*)(p + h->resp_hdrs.len);
	h->resp_hdrs.len += sizeof(http_resphdr) + val->len;

	if (val->len > 0xffff)
		return FFPARS_EBIGVAL;
	rh->len = (ushort)val->len;
	ffmemcpy(rh->data, val->ptr, val->len);
	return 0;
}


static void * httpm_create(const fsv_core *core, ffpars_ctx *args, fsv_modinfo *m)
{
	httpm = ffmem_tcalloc1(httpmodule);
	if (httpm == NULL)
		return NULL;

	fflist_init(&httpm->hosts);
	httpm->core = core;
	httpm->logctx = core->conf()->logctx;

	httpm->read_header_tmout = 65;
	httpm->keepalive_tmout = 65;
	httpm->read_header_growby = 1024;
	httpm->max_header_size = 4 * 1024;
	httpm->max_keepalive_requests = 64;
	httpm->pagesize = core->conf()->pagesize;

	if (0 != http_hstvar_init())
		return NULL;

	ffpars_setargs(args, httpm, httpm_conf_args, FFCNT(httpm_conf_args));
	args->errfunc = &http_conf_err;
	return httpm;
}

static void httpm_destroy(void)
{
	FFLIST_ENUMSAFE(&httpm->hosts, hthost_destroy, httphost, sib);

	ffarr_free(&httpm->hbn_arr);
	ffhst_free(&httpm->ht_hbn);
	ffhst_free(&httpm->hstvars);

	ffmem_free(httpm);
	httpm = NULL;
}

static int httpm_sig(int sig)
{
	switch (sig) {
	case FSVCORE_SIGSTART:
		httpm->core->timer(&httpm->status_tmr, 1000, &http_statustimer, httpm);
		break;

	case FSVCORE_SIGSTOP:
		httpm->core->fsv_timerstop(&httpm->status_tmr);
		break;
	}

	return 0;
}

static const void * httpm_iface(const char *name)
{
	if (!ffsz_cmp(name, "json-status"))
		return &http_stat_iface;
	return NULL;
}


static const int http_status_jsonmeta[] = {
	FFJSON_TOBJ
	, FFJSON_FKEYNAME, FFJSON_FINTVAL
	, FFJSON_FKEYNAME, FFJSON_FINTVAL
	, FFJSON_FKEYNAME, FFJSON_FINTVAL
	, FFJSON_TOBJ
};

static void http_status(const fsv_status *statusmod)
{
	ffjson_cook status_json;
	char buf[4096];
	ffjson_cookinit(&status_json, buf, sizeof(buf));

	ffjson_addv(&status_json, http_status_jsonmeta, FFCNT(http_status_jsonmeta)
		, FFJSON_CTXOPEN
		, "hits", (int64)ffatom_get(&httpm->req_count)
		, "input/sec", (int64)httpm->read_bps
		, "output/sec", (int64)httpm->write_bps
		, FFJSON_CTXCLOSE
		, NULL);

	statusmod->setdata(status_json.buf.ptr, status_json.buf.len, 0);
	ffjson_cookfin(&status_json);
}

static void http_statustimer(const fftime *now, void *param)
{
	httpm->write_bps = ffatom_xchg(&httpm->allwritten, 0);
	httpm->read_bps = ffatom_xchg(&httpm->allread, 0);
}


static void http_onaccept(void *userctx, fsv_lsncon *conn)
{
	httpcon *c = ffmem_tcalloc1(httpcon);
	if (c == NULL) {
		syserrlog(httpm->logctx, FSV_LOG_ERR, "%e", FFERR_BUFALOC);
		goto fail;
	}

	c->conn = conn;
	httpm->lisn->setopt(conn, FSV_LISN_OPT_USERPTR, c);
	httpm->lisn->setopt(conn, FSV_LISN_OPT_LOG, &c->lctx);

	c->defhost = http_defhost(c->conn);
	if (c->defhost == NULL) {
		//note: this should be a configuration time error
		errlog(httpm->logctx, FSV_LOG_ERR, "no hosts configured for this listener");
		goto fail;
	}

	if (NULL == ffarr_alloc(&c->respbuf, HTTP_MAX_RESPHDR)) {
		syserrlog(httpm->logctx, FSV_LOG_ERR, "%e", FFERR_BUFALOC);
		goto fail;
	}

	http_prepare(c);
	http_start(c);
	return;

fail:
	httpm->lisn->fin(c->conn, 0);
}

static int http_onsig(fsv_lsncon *conn, void *userptr, int sig)
{
	return 0;
}


/** Get default host for this server address. */
static httphost * http_defhost(fsv_lsncon *conn)
{
	httphost *h;
	fsv_lsnctx *curlx, **lx;

	httpm->lisn->getvar(conn, FFSTR("context_ptr"), &curlx, sizeof(void*));

	FFLIST_WALK(&httpm->hosts, h, sib) {

		if (h->listeners.len == 0)
			return h;

		FFARR_WALK(&h->listeners, lx) {
			if (curlx == *lx)
				return h;
		}
	}
	return NULL;
}

/** Find host by name. */
httphost * http_gethost(fsv_lsncon *conn, const ffstr *name)
{
	uint hs;
	fsv_lsnctx *curlx;
	hostbyname *hbn;

	httpm->lisn->getvar(conn, FFSTR("context_ptr"), &curlx, sizeof(void*));

	hs = ffcrc32_get(name->ptr, name->len, FFCRC_ICASE);
	hbn = ffhst_find(&httpm->ht_hbn, hs, name->ptr, name->len, curlx);

	if (hbn == NULL)
		return NULL;
	return hbn->host;
}

void http_setlog(httpcon *c, fsv_logctx *logctx)
{
	c->lctx = *fsv_logctx_get(logctx);
	c->lctx.mlog = &http_log;
}

static void http_prepare(httpcon *c)
{
	c->host = c->defhost;
	http_setlog(c, c->defhost->logctx);
	c->logctx = (fsv_logctx*)&c->lctx;
	c->notstarted = 1;

	ffhttp_cookinit(&c->resp, c->respbuf.ptr, c->respbuf.cap);

	{
	size_t nreq = ffatom_incret(&httpm->nrequests);
	size_t n = ffs_fmt(c->id, c->id + sizeof(c->id), "*%L", nreq);
	ffstr_set(&c->sid, c->id, n);
	}

	if (fsv_log_checkdbglevel(c->logctx, FSV_LOG_DBGNET)) {
		ffstr saddr;
		saddr.len = httpm->lisn->getvar(c->conn, FFSTR("client_id"), &saddr.ptr, 0);
		dbglog(c->logctx, FSV_LOG_DBGNET, "reading request from client %S, ka:%u"
			, &saddr, (int)c->keepalive_cnt);
	}
}

/** Prepare for the next request. */
void http_reset(httpcon *c)
{
	httpcon c2;

	c->respbuf.len = 0;
	c2 = *c;

	ffmem_tzero(c);
	c->start_time = c2.start_time;
	c->conn = c2.conn;
	c->defhost = c2.defhost;
	c->keepalive_cnt = c2.keepalive_cnt;
	c->notstarted = !c2.pipelined;
	c->pipelined = c2.pipelined;
	c->respbuf = c2.respbuf;
	c->reqhdrbuf = c2.reqhdrbuf;
	c->reqchain = c2.reqchain;
	c->respchain = c2.respchain;

	http_prepare(c);
}

/** Close the connection and free httpcon object. */
void http_close(httpcon *c)
{
	http_chain_fin(c);

	{
	int f = 0;
	if (c->host->linger)
		f = FSV_LISN_LINGER;
	httpm->lisn->fin(c->conn, f);
	}

	httpm->core->utask(&c->rtask, FSVCORE_TASKDEL);

	ffarr_free(&c->reqhdrbuf);
	ffarr_free(&c->respbuf);
	ffarr_free(&c->reqchain);
	ffarr_free(&c->respchain);
	ffmem_free(c);
}


static void hstroute_free(httptarget *tgt)
{
	ffarr_free(&tgt->index);
	ffmem_free(tgt);
}

static int hthost_hstroute_init(httphost *h)
{
	httptarget *tgt;

	if (0 != ffhst_init(&h->hstroute, h->routes.len))
		return FFPARS_ESYS;
	h->hstroute.cmpkey = &hthost_hstroute_cmpkey;

	FFLIST_WALK(&h->routes, tgt, sib) {
		uint hash = ffcrc32_get(tgt->path.ptr, tgt->path.len, FFCRC_ICASE);
		if (ffhst_ins(&h->hstroute, hash, tgt) < 0)
			return -1;
	}

	return 0;
}

static int hthost_hstroute_cmpkey(void *val, const char *key, size_t keylen, void *param)
{
	httptarget *tgt = val;
	if (!ffstr_eq(&tgt->path, key, keylen))
		return -1;
	return 0;
}


void http_accesslog(httpcon *c)
{
	ffstr3 addinfo = {0};
	ffstr req_line = {0};
	fftime stop;
	uint64 sent_body = 0, recvd_body = 0;

	if (c->req.h.firstline_len != 0)
		req_line = ffhttp_firstline(&c->req.h);

	stop = httpm->core->fsv_gettime();
	fftime_diff(&c->start_time, &stop);

	if (c->nwrite > c->respbuf.len)
		sent_body = c->nwrite - c->respbuf.len;

	if (c->req.h.has_body && c->nread > c->req.h.len)
		recvd_body = c->nread - c->req.h.len; //note: may be larger than the actual request body

	(void)httpm->core->process_vars(&addinfo, &c->host->accesslog_info, &http_getvar, c, c->logctx);

	errlog(c->logctx, FSV_LOG_INFO
		, "[%u+%U] \"%S\"" //request
		" [%u+%U] \"%S\"" //response
		" %S" //additional info
		"  %Ums" //response time
		, (int)c->req.h.len, recvd_body, &req_line
		, (int)c->respbuf.len, sent_body, &c->resp.status
		, &addinfo
		, fftime_ms(&stop));

	ffarr_free(&addinfo);
}

static int http_logadd(fsv_logctx *lx, int lev, const char *modname, const ffstr *trid, const char *fmt, ...)
{
	int r;
	va_list va;
	va_start(va, fmt);
	r = http_logaddv(lx, lev, modname, trid, fmt, va);
	va_end(va);
	return r;
}

/** Override default logger to set transaction ID = current HTTP request.
For error-level message provide additional info about the request. */
static int http_logaddv(fsv_logctx *lx, int lev, const char *modname, const ffstr *trid, const char *fmt, va_list va)
{
	httpcon *c = FF_GETPTR(httpcon, lctx, lx);
	char buf[4 * 1024];
	ffstr omsg, host, req_line, saddr;
	fsv_logctx *logctx = (c->tgt != NULL) ? c->tgt->logctx : c->host->logctx;

	if ((lev & FSV_LOG_MASK) != FSV_LOG_ERR) {
		fsv_logctx_get(logctx)->mlog->addv(logctx, lev, modname, &c->sid, fmt, va);
		return 0;
	}

	omsg.ptr = buf;
	omsg.len = ffs_fmtv(buf, buf + sizeof(buf), fmt, va);

	host = ffhttp_requrl(&c->req, FFURL_FULLHOST);
	req_line = ffhttp_firstline(&c->req.h);

	saddr.len = httpm->lisn->getvar(c->conn, FFSTR("client_id"), &saddr.ptr, 0);

	fsv_logctx_get(logctx)->mlog->add(logctx, lev, modname, &c->sid
		, "%S.  Client \"%S\", request \"%S\", host \"%S\"."
		, &omsg, &saddr, &req_line, &host);
	return 0;
}


static const ffstr http_vars[] = {
	FFSTR_INIT("host")
	, FFSTR_INIT("http_host")
	, FFSTR_INIT("server_protocol")
	, FFSTR_INIT("server_software")
	, FFSTR_INIT("request_method")
	, FFSTR_INIT("request_uri")
	, FFSTR_INIT("document_uri")
	, FFSTR_INIT("query_string")
	, FFSTR_INIT("response_status")
};

enum HTTP_VARS {
	VAR_HOST
	, VAR_HTTP_HOST
	, VAR_SERVER_PROTOCOL
	, VAR_SERVER_SOFTWARE
	, VAR_REQUEST_METHOD
	, VAR_REQUEST_URI
	, VAR_DOCUMENT_URI
	, VAR_QUERY_STRING
	, VAR_RESPONSE_STATUS
	, VAR_LAST
};

static int http_hstvar_cmpkey(void *udata, const char *key, size_t klen, void *param)
{
	size_t i = (size_t)udata - 1;
	return !ffstr_eq(&http_vars[i], key, klen);
}

static int http_hstvar_init(void)
{
	size_t i;
	if (0 != ffhst_init(&httpm->hstvars, VAR_LAST))
		return -1;
	httpm->hstvars.cmpkey = &http_hstvar_cmpkey;

	for (i = 0;  i < FFCNT(http_vars);  i++) {
		const ffstr *name = &http_vars[i];
		uint hash = ffcrc32_get(name->ptr, name->len, 0);
		if (ffhst_ins(&httpm->hstvars, hash, (void*)(i + 1)) < 0)
			return -1;
	}

	return 0;
}

/** Get value of request header. */
static ssize_t http_getvar_hdr(httpcon *c, const ffstr *nm, void *dst)
{
	ffstr val;
	char shdr[255];
	size_t nhdr;

	if (nm->len > sizeof(shdr))
		return -1;

	if (NULL != ffs_findc(nm->ptr, nm->len, '-'))
		return -1; //input name can't contain '-'

	nhdr = ffs_replacechar(nm->ptr, nm->len, shdr, sizeof(shdr), '_', '-', NULL);
	if (0 == ffhttp_findhdr(&c->req.h, shdr, nhdr, &val))
		return -1; //header not found

	*(char**)dst = val.ptr;
	return val.len;

}

static ssize_t http_getvar(void *con, const char *name, size_t namelen, void *dst, size_t cap)
{
	httpcon *c = con;
	ffstr val;
	uint hash = ffcrc32_get(name, namelen, 0);
	size_t v = (size_t)ffhst_find(&httpm->hstvars, hash, name, namelen, NULL);

	if (v == 0) {
		ffstr nm;
		ffstr_set(&nm, name, namelen);

		if (ffstr_matchcz(&nm, "http_")) {
			ffstr_shift(&nm, FFSLEN("http_"));
			return http_getvar_hdr(c, &nm, dst);
		}

		return httpm->lisn->getvar(c->conn, name, namelen, dst, cap);
	}

	switch (v - 1) {

	case VAR_HOST:
		if (c->req.url.hostlen != 0)
			val = ffhttp_requrl(&c->req, FFURL_FULLHOST);
		else
			val = c->host->name;
		break;

	case VAR_HTTP_HOST:
		val = ffhttp_requrl(&c->req, FFURL_FULLHOST);
		break;

	case VAR_SERVER_PROTOCOL:
		ffstr_setcz(&val, "HTTP/1.1");
		break;

	case VAR_SERVER_SOFTWARE:
		ffstr_setcz(&val, "fserv");
		break;

	case VAR_REQUEST_METHOD:
		val = ffhttp_reqmethod(&c->req);
		break;

	case VAR_REQUEST_URI:
		val = ffhttp_requrl(&c->req, FFURL_PATHQS);
		break;

	case VAR_DOCUMENT_URI:
		val = ffhttp_reqpath(&c->req);
		break;

	case VAR_QUERY_STRING:
		val = ffhttp_requrl(&c->req, FFURL_QS);
		break;

	case VAR_RESPONSE_STATUS:
		val = c->resp.status;
		break;

	default:
		FF_ASSERT(0);
	}

	*(char**)dst = val.ptr;
	return val.len;
}

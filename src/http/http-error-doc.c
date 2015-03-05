/** Error document.
Copyright 2014 Simon Zolin.
*/

#include <core/fserv.h>
#include <http/iface.h>
#include <FFOS/file.h>


typedef struct edoc_module {
	const fsv_core *core;
	fflist ctxs; //edoc_ctx[]
	ffstr template;
} edoc_module;

static edoc_module *edocm;

typedef struct edoc_ctx {
	fflist_item sib;
	ffstr template;
} edoc_ctx;

typedef struct edoc_con {
	fsv_httphandler ht;
	ffstr3 data;
} edoc_con;


// FSERV MODULE
static void* edocm_create(const fsv_core *core, ffpars_ctx *args, fsv_modinfo *m);
static void edocm_destroy(void);
static int edocm_sig(int sig);
static const void* edocm_iface(const char *name);
const fsv_mod fsv_http_errdoc = {
	&edocm_create, &edocm_destroy, &edocm_sig, &edocm_iface
};

// HTTP
static int edoc_newctx(fsv_http_hdlctx *ctx);
static const fsv_httphandler_iface edoc_httpiface = {
	&edoc_newctx
};

// HTTP HANDLER
static void edoc_onevent(fsv_httphandler *h);
static void edoc_ondone(fsv_httphandler *h);
static const fsv_http_cb edoc_httphandler = {
	&edoc_onevent, &edoc_ondone
};

// CONFIG
static int edocm_conf_template(ffparser_schem *ps, edoc_module *em, const ffstr *fn);
static int edocx_conf_template(ffparser_schem *ps, edoc_ctx *ex, const ffstr *fn);

static void edocx_destroy(edoc_ctx *ex);


static const ffpars_arg edocm_conf_args[] = {
	{ "template",  FFPARS_TSTR | FFPARS_FREQUIRED,  FFPARS_DST(&edocm_conf_template) }
};

static const ffpars_arg edocx_conf_args[] = {
	{ "template",  FFPARS_TSTR,  FFPARS_DST(&edocx_conf_template) }
};

extern void* http_loadfile(const char *fn, size_t *size);

static int edocm_conf_template(ffparser_schem *ps, edoc_module *em, const ffstr *fn)
{
	char *path = edocm->core->getpath(NULL, NULL, fn->ptr, fn->len);
	if (path == NULL)
		return FFPARS_EBADVAL;
	edocm->template.ptr = (char*)http_loadfile(path, &edocm->template.len);
	ffmem_free(path);
	if (edocm->template.ptr == NULL)
		return FFPARS_ESYS;
	return 0;
}

static int edocx_conf_template(ffparser_schem *ps, edoc_ctx *ex, const ffstr *fn)
{
	char *path = edocm->core->getpath(NULL, NULL, fn->ptr, fn->len);
	if (path == NULL)
		return FFPARS_EBADVAL;
	ex->template.ptr = (char*)http_loadfile(path, &ex->template.len);
	ffmem_free(path);
	if (ex->template.ptr == NULL)
		return FFPARS_ESYS;
	return 0;
}


static void* edocm_create(const fsv_core *core, ffpars_ctx *args, fsv_modinfo *m)
{
	edocm = ffmem_tcalloc1(edoc_module);
	if (edocm == NULL)
		return NULL;

	edocm->core = core;
	fflist_init(&edocm->ctxs);
	ffpars_setargs(args, edocm, edocm_conf_args, FFCNT(edocm_conf_args));
	return edocm;
}

static void edocx_destroy(edoc_ctx *ex)
{
	if (ex->template.ptr != edocm->template.ptr)
		ffstr_free(&ex->template);
	ffmem_free(ex);
}

static void edocm_destroy(void)
{
	FFLIST_ENUMSAFE(&edocm->ctxs, edocx_destroy, edoc_ctx, sib);
	ffstr_free(&edocm->template);
	ffmem_free(edocm);
}

static int edocm_sig(int sig)
{
	return 0;
}

static const void* edocm_iface(const char *name)
{
	if (!ffsz_cmp(name, "http-handler"))
		return &edoc_httpiface;
	return NULL;
}


static int edoc_newctx(fsv_http_hdlctx *ctx)
{
	edoc_ctx *ex = ffmem_tcalloc1(edoc_ctx);
	if (ex == NULL)
		return 1;
	fflist_ins(&edocm->ctxs, &ex->sib);
	ex->template = edocm->template;

	ffpars_setargs(ctx->args, ex, edocx_conf_args, FFCNT(edocx_conf_args));
	ctx->hctx = ex;
	ctx->handler = &edoc_httphandler;
	return 0;
}


static void edoc_onevent(fsv_httphandler *h)
{
	edoc_ctx *ex = h->hctx;
	edoc_con *c = ffmem_tcalloc1(edoc_con);
	if (c == NULL) {
		fsv_syserrlog(h->logctx, FSV_LOG_ERR, "EDOC", NULL, "%e", FFERR_BUFALOC);
		goto fail;
	}

	if (0 != edocm->core->process_vars(&c->data, &ex->template, h->http->getvar, h->httpcon, h->logctx))
		goto fail;

	ffstr_setcz(&h->resp->cont_type, "text/html; charset=UTF-8");

	h->id->udata = c;
	h->http->send(h->id, c->data.ptr, c->data.len, FSV_HTTP_NOINPUT);
	return;

fail:
	if (c != NULL)
		ffmem_free(c);
	h->http->fsv_http_err(h->id);
}

static void edoc_ondone(fsv_httphandler *h)
{
	edoc_con *c = h->id->udata;
	ffarr_free(&c->data);
	ffmem_free(c);
}

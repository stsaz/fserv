/** Get status of other modules and send this data to a client.
Copyright 2014 Simon Zolin.
*/

#include <core/fserv.h>
#include <http/iface.h>
#include <FF/json.h>
#include <FF/list.h>


typedef struct stat_item {
	const char *modname;
	const fsv_status_handler *htstat;
} stat_item;

typedef struct stat_module {
	const fsv_core *core;
	struct { FFARR(stat_item) } mods;

	// conf:
	ffstr3 mod_names;
	ushort interval;

	ffjson_cook jscook;
	int curmod;
	fftime expire;
	fflist waiting_clients;
} stat_module;

static stat_module *statm;

typedef struct stat_con {
	fflist_item waiting_sib;
	ffstr3 data;
	uint updates_left;

	fsv_httpfilter *hfid;
	const fsv_http *http;
	fsv_logctx *logctx;
} stat_con;


// FSERV MODULE
static void* statm_create(const fsv_core *core, ffpars_ctx *pctx, fsv_modinfo *mi);
static void statm_destroy(void);
static int statm_sig(int sig);
static const void* statm_iface(const char *name);
static int statm_start(void);
const fsv_mod fsv_http_stat = {
	&statm_create, &statm_destroy, &statm_sig, &statm_iface
};

// STATUS
static int stat_add(const char *s, size_t len, int flags);
static const fsv_status fsv_stat = {
	&stat_add
};

// HTTP
static int stat_newctx(fsv_http_hdlctx *ctx);
static const fsv_httphandler_iface stat_httpiface = {
	&stat_newctx
};

// HTTP HANDLER
static void stat_onevent(fsv_httphandler *h);
static void stat_ondone(fsv_httphandler *h);
static const fsv_http_cb stat_httphandler = {
	&stat_onevent, &stat_ondone
};

// CONFIG
static int stat_conf_module(ffparser_schem *ps, stat_module *mod, const ffstr *modname);

static void stat_update(void);
static void stat_finish(void);
static void stat_getdata(void);
static void stat_senddata(stat_con *c);


#define STAT_MODNAME "STAT"
#define errlog(logctx, lev, ...) \
	fsv_errlog(logctx, lev, STAT_MODNAME, NULL, __VA_ARGS__)


static const ffpars_arg statm_conf_args[] = {
	{ "update_interval",  FFPARS_TINT | FFPARS_F16BIT | FFPARS_FNOTZERO,  FFPARS_DSTOFF(stat_module, interval) }
	, { "modules",  FFPARS_TSTR | FFPARS_FLIST | FFPARS_FNONULL,  FFPARS_DST(&stat_conf_module) }
};

static int stat_conf_module(ffparser_schem *ps, stat_module *mod, const ffstr *modname)
{
	if (NULL == ffarr_grow(&mod->mod_names, modname->len + 1, 0))
		return FFPARS_ESYS;
	ffsz_copy(ffarr_end(&mod->mod_names), ffarr_unused(&mod->mod_names), modname->ptr, modname->len);
	mod->mod_names.len += modname->len + 1;
	return 0;
}


static void* statm_create(const fsv_core *core, ffpars_ctx *pctx, fsv_modinfo *mi)
{
	statm = ffmem_tcalloc1(stat_module);
	if (statm == NULL)
		return NULL;

	fflist_init(&statm->waiting_clients);
	statm->interval = 500;
	statm->core = core;
	ffjson_cookinit(&statm->jscook, NULL, 0);

	ffpars_setargs(pctx, statm, statm_conf_args, FFCNT(statm_conf_args));
	return statm;
}

static void statm_destroy(void)
{
	ffarr_free(&statm->mods);
	ffarr_free(&statm->mod_names);
	ffjson_cookfinbuf(&statm->jscook);
	ffmem_free(statm);
	statm = NULL;
}

/** Find needed modules and start the timer. */
static int statm_start(void)
{
	const char *nm;
	size_t len;
	const fsv_modinfo *mi;
	stat_item *item;

	len = ffs_nfindc(statm->mod_names.ptr, statm->mod_names.len, '\0');
	if (len == 0)
		return 0; //no modules specified
	if (NULL == ffarr_alloc(&statm->mods, len))
		return 1;
	statm->mods.len = len;
	item = statm->mods.ptr;

	for (nm = statm->mod_names.ptr;  nm != ffarr_end(&statm->mod_names);  nm += len + 1) {
		len = ffsz_len(nm);

		mi = statm->core->findmod(nm, len);
		if (mi == NULL) {
			errlog(statm->core->conf()->logctx, FSV_LOG_ERR, "%s: module not found", nm);
			return 1;
		}

		item->modname = mi->name;
		item->htstat = mi->f->iface("json-status");
		if (item->htstat == NULL) {
			errlog(statm->core->conf()->logctx, FSV_LOG_ERR, "%s: the module doesn't implement 'json-status' interface"
				, nm);
			return 1;
		}
		item++;
	}
	ffarr_free(&statm->mod_names);
	return 0;
}

static int statm_sig(int sig)
{
	switch (sig) {
	case FSVCORE_SIGSTART:
		return statm_start();
	}
	return 0;
}

static const void* statm_iface(const char *name)
{
	if (!ffsz_cmp(name, "http-handler"))
		return &stat_httpiface;
	return NULL;
}


static int stat_newctx(fsv_http_hdlctx *ctx)
{
	ctx->hctx = NULL;
	ctx->handler = &stat_httphandler;
	return 0;
}

static const int json_top[] = {
	FFJSON_TOBJ
		, FFJSON_FKEYNAME, FFJSON_FINTVAL | FFJSON_F32BIT
		, FFJSON_FKEYNAME
			, FFJSON_TARR
};
static const int json_item_top[] = {
	FFJSON_TOBJ
		, FFJSON_FKEYNAME, FFJSON_FSTRZ
		, FFJSON_FKEYNAME
			, FFJSON_TARR
};
//...module data...
static const int json_item_btm[] = {
			FFJSON_TARR
	, FFJSON_TOBJ
};
static const int json_btm[] = {
			FFJSON_TARR
	, FFJSON_TOBJ
};

/** Ask a module to refresh its data. */
static void stat_getdata(void)
{
	stat_item *it = &statm->mods.ptr[statm->curmod];
	it->htstat->get(&fsv_stat);
}

/** Finish JSON and notify all waiting clients. */
static void stat_finish(void)
{
	stat_con *c;
	fflist_item *next;

	ffjson_bufaddv(&statm->jscook, json_btm, FFCNT(json_btm)
			, FFJSON_CTXCLOSE
		, FFJSON_CTXCLOSE
		, NULL);

	FFLIST_WALKSAFE(&statm->waiting_clients, c, waiting_sib, next) {

		fflist_rm(&statm->waiting_clients, &c->waiting_sib);
		stat_senddata(c);
	}
}

/** Add JSON generated by module. */
static int stat_add(const char *s, size_t len, int flags)
{
	ffjson_cook *ck = &statm->jscook;
	stat_item *it = &statm->mods.ptr[statm->curmod];

	ffjson_bufaddv(ck, json_item_top, FFCNT(json_item_top)
		, FFJSON_CTXOPEN
		, "mod", it->modname
		, "data"
		, FFJSON_CTXOPEN
		, NULL);

	ffarr_append(&ck->buf, s, len);

	ffjson_bufaddv(ck, json_item_btm, FFCNT(json_item_btm)
		, FFJSON_CTXCLOSE
		, FFJSON_CTXCLOSE
		, NULL);

	if (++statm->curmod == statm->mods.len) {
		statm->curmod = 0;
		stat_finish();
		return 0;
	}

	stat_getdata();
	return 0;
}

static void stat_update(void)
{
	fftime now = statm->core->fsv_gettime();
	statm->expire = now;
	fftime_addms(&statm->expire, statm->interval);

	ffjson_cookreset(&statm->jscook);
	ffjson_bufaddv(&statm->jscook, json_top, FFCNT(json_top)
		, FFJSON_CTXOPEN
		, "time", now.s
		, "data"
			, FFJSON_CTXOPEN
			, NULL);

	stat_getdata();
}


/** Send currently available data or put the connection on hold until the data is updated. */
static void stat_onevent(fsv_httphandler *h)
{
	stat_con *c = h->id->udata;
	fftime now;

	if (h->id->udata == NULL) {
		c = ffmem_tcalloc1(stat_con);
		if (c == NULL) {
			h->http->fsv_http_err(h->id);
			return;
		}

		h->id->udata = c;
		ffhttp_setstatus(h->resp, FFHTTP_200_OK);
		ffstr_setcz(&h->resp->cont_type, "application/json");
		ffhttp_addihdr(h->resp, FFHTTP_CACHE_CONTROL, FFSTR("max-age=1"));
	}

	c->hfid = h->id;
	c->http = h->http;
	c->logctx = h->logctx;

	now = statm->core->fsv_gettime();
	if (fftime_cmp(&statm->expire, &now) <= 0) {
		ffbool first = fflist_empty(&statm->waiting_clients);
		fflist_ins(&statm->waiting_clients, &c->waiting_sib);
		if (first)
			stat_update();
		return;
	}

	stat_senddata(c);
}

static void stat_ondone(fsv_httphandler *h)
{
	stat_con *c = h->id->udata;

	if (fflist_exists(&statm->waiting_clients, &c->waiting_sib))
		fflist_rm(&statm->waiting_clients, &c->waiting_sib);

	ffarr_free(&c->data);
	ffmem_free(c);
}

static void stat_senddata(stat_con *c)
{
	c->data.len = 0;
	if (NULL == ffarr_append(&c->data, statm->jscook.buf.ptr, statm->jscook.buf.len)) {
		fsv_syserrlog(c->logctx, FSV_LOG_ERR, STAT_MODNAME, NULL, "%e", FFERR_BUFALOC);
		c->http->fsv_http_err(c->hfid);
		return;
	}

	c->http->send(c->hfid, c->data.ptr, c->data.len, FSV_HTTP_NOINPUT);
}

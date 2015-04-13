/**
Copyright (c) 2014 Simon Zolin
*/

#include "log.h"
#include <FFOS/error.h>
#include <FFOS/process.h>
#include <FF/data/json.h>


// FSERV MODULE
static void * logm_create(const fsv_core *srv, ffpars_ctx *c, fsv_modinfo *m);
static void logm_fin(void);
static int logm_sig(int sig);
static const void * logm_iface(const char *name);
static const fsv_mod fsv_log_mod = {
	&logm_create, &logm_fin, &logm_sig, &logm_iface
};

// FSERV LOG
static fsv_logctx * logm_newctx(ffpars_ctx *a, fsv_logctx *parent);
static int logx_add(fsv_logctx *lx, int level, const char *modname, const ffstr *trid, const char *fmt, ...);
static int logx_addv(fsv_logctx *lx, int level, const char *modname, const ffstr *trid, const char *fmt, va_list va);
static fsv_log fsv_log_iface = {
	&logm_newctx, &logx_add, &logx_addv
};

// MOD
static int logm_start();
static void logm_flush();
static void logm_flushtimer(const fftime *now, void *param) {
	logm_flush();
}

// STATUS
static void log_status(const fsv_status *statusmod);
static const fsv_status_handler log_stat_iface = {
	&log_status
};

// CTX CONFIG
static int logx_conf_setlevel(ffparser_schem *ps, fsv_logctx *lx, const ffstr *s);
static int logx_conf_addleveldbg(ffparser_schem *ps, fsv_logctx *lx, const ffstr *s);
static int logx_conf_output(ffparser_schem *ps, fsv_logctx *lx, ffpars_ctx *a);
static int logx_conf_validate(ffparser_schem *ps, fsv_logctx *lx);

// CTX
static int logx_start(fsv_logctx *lx);
static void logx_free(fsv_logctx *lx);
static void logx_output(fsv_logctx *lx, uint lev, const char *msg, size_t len);


static void oninit(void)
{
	ffos_init();
}
FFDL_ONINIT(oninit, NULL)

FF_EXTN FF_EXP	const fsv_mod * fsv_getmod(const char *name)
{
	if (!ffsz_cmp(name, "log"))
		return &fsv_log_mod;
	return NULL;
}


void logm_err(const char *fmt, ...)
{
	char buf[4096];
	char *s = buf;
	va_list va;

	s += ffs_fmt(buf, buf + FFCNT(buf), "fserv: %s: error: log: "
		, logm->pid);

	va_start(va, fmt);
	s += ffs_fmtv(s, buf + FFCNT(buf), fmt, va);
	va_end(va);

	s = ffs_copyc(s, buf + FFCNT(buf), '\n');

	fffile_write(ffstderr, buf, s - buf);
}


logmodule *logm;

enum TIME_E {
	LOGTM_HIDE
	, LOGTM_LOCAL
	, LOGTM_UTC
};
static const char *const logm_time_enumstr[] = {
	"hide", "local", "utc"
};
static const ffpars_enumlist logm_time_enum = {
	logm_time_enumstr, FFCNT(logm_time_enumstr), FFPARS_DSTOFF(logmodule, use_time)
};

static const ffpars_arg logm_args[] = {
	{ "flush_delay",  FFPARS_TINT,  FFPARS_DSTOFF(logmodule, flush_delay) }
	, { "time", FFPARS_TENUM,  FFPARS_DST(&logm_time_enum) }
};


static const ffpars_arg logx_args[] = {
	{ "error", FFPARS_TOBJ | FFPARS_FOBJ1 | FFPARS_FMULTI,  FFPARS_DST(&logx_conf_output) }
	, { "error_warn", FFPARS_TOBJ | FFPARS_FOBJ1 | FFPARS_FMULTI,  FFPARS_DST(&logx_conf_output) }
	, { "error_info", FFPARS_TOBJ | FFPARS_FOBJ1 | FFPARS_FMULTI,  FFPARS_DST(&logx_conf_output) }
	, { "debug", FFPARS_TOBJ | FFPARS_FOBJ1 | FFPARS_FMULTI,  FFPARS_DST(&logx_conf_output) }
	, { "access", FFPARS_TOBJ | FFPARS_FOBJ1 | FFPARS_FMULTI,  FFPARS_DST(&logx_conf_output) }

	, { "pass_to_std", FFPARS_TBOOL | FFPARS_F8BIT,  FFPARS_DSTOFF(fsv_logctx, pass_to_std) }
	, { "level", FFPARS_TSTR | FFPARS_FNOTEMPTY,  FFPARS_DST(&logx_conf_setlevel) }
	, { "debug_levels", FFPARS_TSTR | FFPARS_FLIST,  FFPARS_DST(&logx_conf_addleveldbg) }

	, { NULL,  FFPARS_TCLOSE,  FFPARS_DST(&logx_conf_validate) }
};

static const char *const log_levelstr[] = {
	"", "ERR", "WRN", "INF", "DBG"
};
static const char * const log_conf_levelstr[] = {
	"none", "error", "warn", "info", "debug"
};

static const char *const log_conf_dbglevelstr[] = {
	"flow", "net", "http-filters", "all"
};

static int logx_conf_setlevel(ffparser_schem *ps, fsv_logctx *lx, const ffstr *s)
{
	ssize_t i = ffs_findarrz(log_conf_levelstr, FFCNT(log_conf_levelstr), s->ptr, s->len);
	if (i == -1)
		return FFPARS_EBADVAL;

	lx->level = (lx->level & ~FSV_LOG_MASK) | (uint)i;
	return 0;
}

static int logx_conf_addleveldbg(ffparser_schem *ps, fsv_logctx *lx, const ffstr *s)
{
	ssize_t i = ffs_findarrz(log_conf_dbglevelstr, FFCNT(log_conf_dbglevelstr), s->ptr, s->len);
	if (i == -1)
		return FFPARS_EBADVAL;

	if (i == FFCNT(log_conf_dbglevelstr) - 1)
		lx->level |= FSV_LOG_DBGMASK;
	else
		lx->level |= (FSV_LOG_DBGFLOW << (uint)i);
	return 0;
}

static const char * const log_outnames[] = {
	"file", "gzip"
};
static const fsv_log_output *const log_outs[] = {
	&logf_output, &logz_output
};

static const char * const log_slevels[] = {
	"error", "error_warn", "error_info", "debug", "access"
};
static const uint log_levels[] = {
	FSV_LOG_ERR, FSV_LOG_WARN, FSV_LOG_INFO, FSV_LOG_DBG, FSV_LOG_ACCESS
};

static int logx_conf_output(ffparser_schem *ps, fsv_logctx *lx, ffpars_ctx *a)
{
	const ffstr *name;
	logoutput *out;
	ssize_t i;
	int outlev;

	// get log level
	i = ffs_findarrz(log_slevels, FFCNT(log_slevels), ps->curarg->name, strlen(ps->curarg->name));
	if (i == -1)
		return FFPARS_EBADVAL;
	outlev = log_levels[i];
	if (outlev == FSV_LOG_ACCESS)
		lx->level |= FSV_LOG_ACCESS;

	out = ffarr_push(&lx->outs, logoutput);
	if (out == NULL)
		return FFPARS_ESYS;

	// get output interface
	name = &ps->vals[0];
	i = ffs_findarrz(log_outnames, FFCNT(log_outnames), name->ptr, name->len);
	if (i == -1)
		return FFPARS_EBADVAL;
	out->iface = log_outs[i];

	out->instance = out->iface->create(a);
	if (out->instance == NULL)
		return FFPARS_EINTL;
	out->level = outlev;
	return 0;
}

static int logx_conf_validate(ffparser_schem *ps, fsv_logctx *lx)
{
	uint *lev = &lx->level;
	if ((*lev & FSV_LOG_MASK) >= FSV_LOG_DBG) {
		if ((*lev & FSV_LOG_DBGMASK) == 0) //no debug events were specified in config
			*lev |= FSV_LOG_DBGMASK;

	} else
		*lev &= ~FSV_LOG_DBGMASK; //no debug events if no debug level

	if (0 != logx_start(lx))
		return FFPARS_EINTL;
	return 0;
}


static void * logm_create(const fsv_core *srv, ffpars_ctx *c, fsv_modinfo *m)
{
	logm = ffmem_tcalloc1(logmodule);
	if (logm == NULL)
		return NULL;

	logm->srv = srv;
	logm->flush_delay = 2000;
	logm->use_time = LOGTM_LOCAL;
	fflist_init(&logm->ctxs);

	// get PID as a string
	{
	int i = ffs_fromint(ffps_curid(), logm->pid, FFCNT(logm->pid), 0);
	logm->pid[i] = '\0';
	}

	ffpars_setargs(c, logm, logm_args, FFCNT(logm_args));
	return logm;
}

static void logm_fin(void)
{
	FFLIST_ENUMSAFE(&logm->ctxs, logx_free, fsv_logctx, sib);
	ffmem_free(logm);
	logm = NULL;
}

static int logm_sig(int sig)
{
	switch (sig) {
	case FSVCORE_SIGSTART:
		return logm_start();

	case FSVCORE_SIGSTOP:
		logm->srv->fsv_timerstop(&logm->flush_timer);
		logm_flush();
		break;

	case FSVCORE_SIGREOPEN: {
		fsv_logctx *lx;
		logoutput *out;
		FFLIST_WALK(&logm->ctxs, lx, sib) {
			FFARR_WALK(&lx->outs, out) {
				out->iface->open(out->instance, LOG_REOPEN);
			}
		}
		}
		break;
	}

	return 0;
}

static const void * logm_iface(const char *name)
{
	if (0 == strcmp(name, "log"))
		return &fsv_log_iface;
	else if (!ffsz_cmp(name, "json-status"))
		return &log_stat_iface;
	return NULL;
}


static int logm_start()
{
	// get PID as a string
	uint i = ffs_fromint(ffps_curid(), logm->pid, sizeof(logm->pid), 0);
	logm->pid[i] = '\0';

	if (logm->flush_delay != 0)
		logm->srv->timer(&logm->flush_timer, logm->flush_delay, &logm_flushtimer, logm);

	return 0;
}

static void logm_flush()
{
	fsv_logctx *lx;
	logoutput *out;
	FFLIST_WALK(&logm->ctxs, lx, sib) {
		FFARR_WALK(&lx->outs, out) {
			out->iface->open(out->instance, LOG_FLUSH);
		}
	}
}

static const int log_status_json[] = {
	FFJSON_TOBJ
	, FFJSON_FKEYNAME, FFJSON_FINTVAL
	, FFJSON_FKEYNAME, FFJSON_FINTVAL
	, FFJSON_TOBJ
};

static void log_status(const fsv_status *statusmod)
{
	ffjson_cook status_json;
	char buf[4096];
	ffjson_cookinit(&status_json, buf, sizeof(buf));

	ffjson_addv(&status_json, log_status_json, FFCNT(log_status_json)
		, FFJSON_CTXOPEN
		, "messages", (int64)ffatom_get(&logm->stat_messages)
		, "size", (int64)ffatom_get(&logm->stat_written)
		, FFJSON_CTXCLOSE
		, NULL);

	statusmod->setdata(status_json.buf.ptr, status_json.buf.len, 0);
	ffjson_cookfin(&status_json);
}


static fsv_logctx * logm_newctx(ffpars_ctx *a, fsv_logctx *parent)
{
	fsv_logctx *lx = ffmem_tcalloc1(fsv_logctx);
	if (lx == NULL)
		return NULL;
	fflist_ins(&logm->ctxs, &lx->sib);

	lx->level = FSV_LOG_INFO;
	lx->parent = parent;
	lx->mlog = &fsv_log_iface;

	if (parent != NULL) {
		lx->level = parent->level;
		lx->pass_to_std = parent->pass_to_std;
	}

	ffpars_setargs(a, lx, logx_args, FFCNT(logx_args));
	return lx;
}

static int logx_start(fsv_logctx *lx)
{
	logoutput *out;
	FFARR_WALK(&lx->outs, out) {
		if (0 != out->iface->open(out->instance, LOG_OPEN))
			return 1;
	}
	return 0;
}

static void logx_free(fsv_logctx *lx)
{
	logoutput *out;
	FFARR_WALK(&lx->outs, out) {
		out->iface->free(out->instance);
	}
	ffarr_free(&lx->outs);

	ffmem_free(lx);
}

static void logx_output(fsv_logctx *lx, uint lev, const char *msg, size_t len)
{
	fsv_logctx *clx;
	logoutput *out;

	for (clx = lx;  clx != NULL;  clx = clx->parent) {

		FFARR_WALK(&clx->outs, out) {

			if ((out->level & FSV_LOG_MASK) >= (lev & FSV_LOG_MASK)
				&& (out->level & FSV_LOG_ACCESS) == (lev & FSV_LOG_ACCESS))
			{
				out->iface->write(out->instance, lev, msg, len);
			}
		}
	}

	if (lx->pass_to_std) {
		fffd f = ffstdout;
		if (lev == FSV_LOG_ERR || lev == FSV_LOG_WARN)
			f = ffstderr;
		fffile_write(f, msg, len);
	}
}

static int logx_add(fsv_logctx *lx, int level, const char *modname, const ffstr *trid, const char *fmt, ...)
{
	int r;
	va_list va;
	va_start(va, fmt);
	r = logx_addv(lx, level, modname, trid, fmt, va);
	va_end(va);
	return r;
}

// [DATE TIME.MS ] LEV PID: [MOD ] [TRID:\t] MSG
static int logx_addv(fsv_logctx *lx, int level, const char *modname, const ffstr *trid, const char *fmt, va_list va)
{
	char ss[4096];
	char ss_encoded[4096 * 3];
	char *s = ss;
	const char *end = ss + sizeof(ss) - FFSLEN(FF_NEWLN);
	char *msg = ss;
	size_t msgsz;

	if (logm->use_time != LOGTM_HIDE) {
		uint f = FSV_TIME_YMD; //LOGTM_UTC
		char ts[64];
		if (logm->use_time == LOGTM_LOCAL)
			f = FSV_TIME_YMD_LOCAL;
		logm->srv->gettime4(NULL, ts, FFCNT(ts), f | FSV_TIME_ADDMS);
		s = ffs_copyz(s, end, ts);
		*s++ = ' ';
	}

	//level
	if (!(level & FSV_LOG_ACCESS)) {
		int lev = level & FSV_LOG_MASK;
		FF_ASSERT(lev <= FSV_LOG_DBG);
		s = ffs_copyz(s, end, log_levelstr[lev]);
		*s++ = ' ';
	}

	//pid
	s = ffs_copyz(s, end, logm->pid);
	s = ffs_copycz(s, end, ": ");

	//short mod name
	if (modname != NULL) {
		s = ffs_copyz(s, end, modname);
		s = ffs_copyc(s, end, ' ');
	}

	//transaction id
	if (trid != NULL)
		s += ffs_fmt(s, end, "%*s:\t", trid->len, trid->ptr);

	s += ffs_fmtv(s, end, fmt, va);

	s = ffs_copyz(s, ss + sizeof(ss), FF_NEWLN);

	msgsz = s - ss;

	{
		size_t nenc = ffs_escape(NULL, 0, ss, msgsz, FFS_ESC_NONPRINT);
		if (nenc != msgsz) {
			// the message contains characters that need to be encoded
			msgsz = ffs_escape(ss_encoded, FFCNT(ss_encoded), ss, msgsz, FFS_ESC_NONPRINT);
			msg = ss_encoded;
		}
	}

	logx_output(lx, level, msg, msgsz);

	ffatom_add(&logm->stat_written, msgsz);
	ffatom_inc(&logm->stat_messages);

	return 0;
}

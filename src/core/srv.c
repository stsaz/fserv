/**
Copyright 2014 Simon Zolin
*/

#include <core/fserv.h>
#include <FF/timer-queue.h>
#include <FF/time.h>
#include <FF/path.h>
#include <FF/filemap.h>
#include <FF/data/conf.h>
#include <FF/dir.h>
#include <FFOS/process.h>
#include <FFOS/sig.h>
#include <FFOS/atomic.h>
#include <FFOS/dir.h>

#ifdef FF_UNIX
#include <sys/resource.h> //setrlimit
#endif


enum TM_E {
	TM_YMD = 1
	, TM_WDMY = 2
	, TM_YMD_LOCAL = 4
	, TM_MSEC = 1 << 31
};

typedef struct curtime_t {
	fftime time;
	ffdtm dt
		, dt_lo;
	char ymd[32]; // yyyy-MM-dd...
	char wdmy[32]; // Wed, 07 Sep...
	char ymd_lo[32]; // yyyy-MM-dd...
	uint flags; //enum TM_E
} curtime_t;


typedef struct fmodule {
	fsv_modinfo mod;
	fflist_item sib;
	char name[1];
} fmodule;

/** Manages configuration, modules, timer, signals and event loop. */
typedef struct fserver {
	fffd kq;
	ffkqu_time quTm;
	const ffkqu_time *pquTm;

	fsv_timer tmr;
	fftimer_queue tmrqu;
	curtime_t time;

	fftaskmgr taskmgr;
	ffsignal sigs_task;

	int state;
	fflist mods;
	ffstr3 errstk;

	fsv_logctx *logctx;
	struct _fsv_logctx logctx_empty;

	fsvcore_config cfg;
	union {
		ffstr pid_fn;
		ffstr pid_fn_conf;
	};
	ffstr rootdir; ///< e.g. "/path/path2/"
	ushort events_count;
	ushort timer_resol; //in ms
	uint page_size;
	uint include_depth;
} fserver;


#define dbglog(level, ...) \
	fsv_dbglog(serv->logctx, level, "FSRV", NULL, __VA_ARGS__)

#define errlog(level, ...) \
	fsv_errlog(serv->logctx, level, "FSRV", NULL, __VA_ARGS__)

#define syserrlog(level, fmt, ...) \
	fsv_syserrlog(serv->logctx, level, "FSRV", NULL, fmt, __VA_ARGS__)

#define dbglog2(logctx, level, ...) \
	fsv_dbglog(logctx, level, "FSRV", NULL, __VA_ARGS__)

#define errlog2(logctx, level, ...) \
	fsv_errlog(logctx, level, "FSRV", NULL, __VA_ARGS__)

static fserver *serv;


// FSERV MAIN
static void * srv_create(void);
static void srv_destroy(void);
static int srv_setroot(const char *dir, size_t len);
static int srv_readconf(const char *fn);
static int srv_sig(int signo);
static const char * srv_errstr(void);
static const fsv_main fsv_mainiface = {
	&srv_create, &srv_destroy, &srv_setroot, &srv_readconf, &srv_sig, &srv_errstr
};
FF_EXTN FF_EXP const fsv_main * fsv_getmain()
{
	return &fsv_mainiface;
}

// FSERV CORE
static const fsvcore_config * srv_getconf(void);
static char* srv_getpath(char *dst, size_t *dstlen, const char *path, size_t len);
static fftime srv_gettime4(ffdtm *dt, char *dst, size_t cap, uint flags);
static const fsv_modinfo * srv_findmod(const char *name, size_t namelen);
static ssize_t srv_getvar(const char *name, size_t namelen, void *dst, size_t cap);
static int srv_process_vars(ffstr3 *dst, const ffstr *src, fsv_getvar_t getvar, void *udata, fsv_logctx *logctx);
static void srv_timer(fsv_timer *tmr, int64 interval_ms, fftmrq_handler func, void *param);
static int srv_usertask(fsv_task *task, int op);
static const fsv_core srvcore = {
	&srv_getconf
	, &srv_getpath
	, &srv_findmod
	, &srv_getvar, &srv_process_vars
	, &srv_gettime4
	, &srv_timer
	, &srv_usertask
};

// CONFIG
static int srv_conf_mod(ffparser_schem *ps, fserver *srv, ffpars_ctx *a);
static int srv_conf_rootdir(ffparser_schem *ps, fserver *srv, const ffstr *s);
static int srv_conf_log(ffparser_schem *ps, fserver *srv, ffpars_ctx *a);
static int srv_conf_maxfd(ffparser_schem *ps, fserver *srv, const int64 *val);
static int srv_conf_getpidfn(ffparser_schem *ps, fserver *srv);
static int srv_conf_validate(ffparser_schem *ps, fserver *srv);

static int srv_getmod(const ffstr *binfn, ffdl *pdl, fsv_getmod_t *getmod);
static int srv_confinclude_wild(ffparser_schem *ps, const ffstr *val);
static int srv_confinclude(ffparser_schem *ps, const char *fn);
static int srv_conf(const char *filename, ffparser_schem *ps);
static int srv_start(void);
static int srv_stop(int sig, fmodule *last);
static int srv_evloop(void);
static void srv_destroymods(void);
static int srv_startmods(void);

static int srv_initsigs(void);
static void srv_handlesig(void *t);
static int srv_sendsig(int sig);

static int srv_savepid(uint pid);
static int srv_readpid(void);

static FFINL void srv_errclear(void) {
	serv->errstk.len = 0;
}
static void srv_errsave(int syser, const char *fmt, ...);

static void curtime_update(const fftime *now, void *param);
static uint curtime_get(curtime_t *tt, fftime *t, ffdtm *dt, char *dst, size_t cap, uint flags);


static void * srv_create(void)
{
	if (0 != ffskt_init(FFSKT_WSA))
		return NULL;

	serv = ffmem_tcalloc1(fserver);
	if (serv == NULL)
		return NULL;

	fftask_init(&serv->taskmgr);
	fflist_init(&serv->mods);
	serv->kq = FF_BADFD;
	fftmrq_init(&serv->tmrqu);
	serv->events_count = 64;
	serv->timer_resol = 250;
	fftime_now(&serv->time.time);

	{
		ffsysconf sc;
		ffsc_init(&sc);
		serv->cfg.pagesize = ffsc_get(&sc, _SC_PAGESIZE);
		_ffsc_ncpu = ffsc_get(&sc, _SC_NPROCESSORS_ONLN);
	}

	serv->logctx_empty.level = 0; //no log levels
	serv->logctx = (fsv_logctx*)&serv->logctx_empty;
	serv->cfg.logctx = (fsv_logctx*)&serv->logctx_empty;

	return serv;
}

static void mod_destroy(fmodule *m)
{
	if (m->mod.binary != NULL)
		(void)ffdl_close((ffdl)m->mod.binary);
	ffmem_free(m);
}

static const int sigs[] = { SIGINT, SIGHUP, SIGUSR1 };

static void srv_destroy(void)
{
	FFLIST_ENUMSAFE(&serv->mods, mod_destroy, fmodule, sib);
	serv->mods.len = 0;

	ffsig_ctl(&serv->sigs_task, serv->kq, sigs, FFCNT(sigs), NULL);
	ffsig_mask(SIG_UNBLOCK, sigs, FFCNT(sigs));

	fftmrq_destroy(&serv->tmrqu, serv->kq);
	FF_SAFECLOSE(serv->kq, FF_BADFD, (void)ffkqu_close);

	ffstr_free(&serv->pid_fn);
	ffstr_free(&serv->rootdir);
	ffarr_free(&serv->errstk);
	ffmem_free(serv);
	serv = NULL;
}

static int srv_sendsig(int sig)
{
	int pid;
	srv_errclear();

	pid = srv_readpid();
	if (pid == 0)
		return -1;

	if (0 != ffps_sig(pid, sig)) {
		srv_errsave(fferr_last(), "send signal to process %u", pid);
		return -1;
	}

	return 0;
}

static int srv_sig(int signo)
{
	srv_errclear();

	switch (signo) {
	case FSVMAIN_RUN:
		return (0 == srv_start() ? serv->state : -1);

	case FSVMAIN_STOP:
		return srv_sendsig(SIGINT);

	case FSVMAIN_REOPEN:
		return srv_sendsig(SIGUSR1);

	case FSVMAIN_RECONFIG:
		return srv_sendsig(SIGHUP);
	}

	srv_errsave(-1, "invalid signal");
	return -1;
}

static const char * srv_errstr(void)
{
	char *s = ffarr_push(&serv->errstk, char);
	if (s == NULL)
		return "";
	*s = '\0';
	return serv->errstk.ptr;
}


static const ffpars_arg srv_args[] = {
	{ "mod",  FFPARS_TOBJ | FFPARS_FOBJ1 | FFPARS_FMULTI,  FFPARS_DST(&srv_conf_mod) }
	, { "root",  FFPARS_TSTR | FFPARS_FNOTEMPTY,  FFPARS_DST(&srv_conf_rootdir) }
	, { "event_pool",  FFPARS_TINT | FFPARS_F16BIT | FFPARS_FNOTZERO,  FFPARS_DSTOFF(fserver, events_count) }
	, { "timer_resolution",  FFPARS_TINT | FFPARS_F16BIT | FFPARS_FNOTZERO,  FFPARS_DSTOFF(fserver, timer_resol) }
	, { "max_fd_number",  FFPARS_TINT | FFPARS_FNOTZERO,  FFPARS_DST(&srv_conf_maxfd) }
	, { "log",  FFPARS_TOBJ | FFPARS_FOBJ1,  FFPARS_DST(&srv_conf_log) }
	, { "pidfile",  FFPARS_TSTR | FFPARS_FCOPY | FFPARS_FNOTEMPTY,  FFPARS_DSTOFF(fserver, pid_fn_conf) }
	, { NULL,  FFPARS_TCLOSE,  FFPARS_DST(&srv_conf_validate) }
};

static int srv_readconf(const char *fn)
{
	int r;
	ffparser pconf;
	ffparser_schem ps;
	const ffpars_ctx ctx = { serv, srv_args, FFCNT(srv_args), NULL, {0} };

	srv_errclear();

	ffconf_scheminit(&ps, &pconf, &ctx);
	ps.flags = FFPARS_KEYICASE;

	r = srv_conf(fn, &ps);

	ffpars_free(&pconf);
	ffpars_schemfree(&ps);
	return r;
}

static int srv_conf_rootdir(ffparser_schem *ps, fserver *srv, const ffstr *s)
{
	return srv_setroot(s->ptr, s->len);
}

static int srv_setroot(const char *dir, size_t len)
{
	fffileinfo fi;
	ffstr *root = &serv->rootdir;
	if (NULL == ffstr_alloc(root, len + FFSLEN("/0")))
		return FFPARS_ESYS;

	root->len = ffpath_norm(root->ptr, len, dir, len, 0);
	if (root->len == 0)
		return FFPARS_EBADVAL;

	if (!ffpath_slash(root->ptr[root->len - 1]))
		root->ptr[root->len++] = FFPATH_SLASH;
	root->ptr[root->len] = '\0';

	if (0 != fffile_infofn(root->ptr, &fi))
		return FFPARS_ESYS;

	serv->cfg.root = root->ptr;
	return 0;
}

static int srv_conf_log(ffparser_schem *ps, fserver *srv, ffpars_ctx *a)
{
	const ffstr *name = &ps->vals[0];
	const fsv_log *log_iface;
	const fsv_modinfo *m = srv_findmod(name->ptr, name->len);
	if (m == NULL)
		return FFPARS_EBADVAL;

	log_iface = m->f->iface("log");
	if (log_iface == NULL)
		return FFPARS_EBADVAL;

	serv->logctx = log_iface->newctx(a, NULL);
	if (serv->logctx == NULL)
		return FFPARS_EBADVAL;

	serv->cfg.logctx = serv->logctx;
	return 0;
}

#ifdef FF_UNIX
static FFINL int os_setrlimit(int type, int val) {
	struct rlimit rl;
	rl.rlim_cur = val;
	rl.rlim_max = val;
	return setrlimit(type, &rl);
}

#else

enum {
	RLIMIT_NOFILE
};

#define os_setrlimit(type, val)  (0)

#endif

static int srv_conf_maxfd(ffparser_schem *ps, fserver *srv, const int64 *val) {
	if (0 != os_setrlimit(RLIMIT_NOFILE, (uint)*val))
		return FFPARS_ESYS;
	return 0;
}

static int srv_getmod(const ffstr *binfn, ffdl *pdl, fsv_getmod_t *getmod)
{
	ffdl dl;
	char fn[FF_MAXPATH];
	size_t len;

	if (!ffpath_isvalidfn(binfn->ptr, binfn->len))
		return FFPARS_EBADVAL;

	len = ffs_fmt(fn, fn + FFCNT(fn), "%Smod/%S." FFDL_EXT "%Z"
		, &serv->rootdir, binfn);
	if (len == FFCNT(fn))
		return FFPARS_EBIGVAL;

	dl = ffdl_open(fn, 0);
	if (dl == NULL) {
		srv_errsave(-1, "open module file: %s: %s", fn, ffdl_errstr());
		return FFPARS_ESYS;
	}

	*getmod = (fsv_getmod_t)ffdl_addr(dl, "fsv_getmod");
	if (*getmod == NULL) {
		srv_errsave(-1, "resolve function: fsv_getmod: %s", ffdl_errstr());
		ffdl_close(dl);
		return FFPARS_ESYS;
	}

	*pdl = dl;
	return 0;
}

static int srv_conf_mod(ffparser_schem *ps, fserver *srv, ffpars_ctx *a)
{
	ffdl dl = NULL;
	fmodule *m;
	const fsv_mod *miface;
	ffstr binfn = {0}
		, modname;
	const ffstr *name = &ps->vals[0];
	enum { MAX_MOD_NAME = 255 };
	char namez[MAX_MOD_NAME + 1];
	char *end;
	fsv_getmod_t getmod;
	int r;

	ffs_split2by(name->ptr, name->len, '.', &binfn, &modname);

	if (name->len > MAX_MOD_NAME)
		return FFPARS_EBIGVAL;

	if (modname.len == 0) {
		srv_errsave(-1, "module name is not specified: %S", name);
		return FFPARS_EBADVAL;
	}

	r = srv_getmod(&binfn, &dl, &getmod);
	if (r != 0)
		return r;

	end = ffs_copystr(namez, namez + FFCNT(namez), &modname);
	*end = '\0';
	miface = getmod(namez);
	if (miface == NULL) {
		srv_errsave(-1, "can't find module name: %s", namez);
		return FFPARS_ESYS;
	}

	m = (fmodule*)ffmem_calloc(1, sizeof(fmodule) + name->len /*+1*/);
	if (m == NULL) {
		srv_errsave(-1, "%e", FFERR_BUFALOC);
		return FFPARS_ESYS;
	}

	m->mod.instance = miface->create(&srvcore, a, &m->mod);
	if (m->mod.instance == NULL) {
		ffmem_free(m);
		srv_errsave(-1, "create module: %s", namez);
		return FFPARS_ESYS;
	}

	fflist_ins(&serv->mods, &m->sib);
	ffsz_copy(m->name, name->len + 1, name->ptr, name->len);
	m->mod.f = miface;
	m->mod.binary = dl;
	m->mod.name = m->name;
	return 0;
}

static int srv_conf_getpidfn(ffparser_schem *ps, fserver *srv)
{
	ffstr pid_fn_conf = serv->pid_fn_conf;
	ffstr pid = serv->pid_fn_conf;
	if (pid.len == 0)
		ffstr_setcz(&pid, "log/fserv.pid");

	serv->pid_fn.ptr = srv_getpath(NULL, &serv->pid_fn.len, pid.ptr, pid.len);
	ffstr_free(&pid_fn_conf);
	if (serv->pid_fn.ptr == NULL)
		return FFPARS_EBADVAL;
	return 0;
}

static int srv_conf_validate(ffparser_schem *ps, fserver *srv)
{
	return srv_conf_getpidfn(ps, srv);
}

static const fsvcore_config * srv_getconf(void)
{
	return &serv->cfg;
}

/** Get full path using value of "root" specified in configuration.
The path is normalized.  The last slash is removed. */
static char* srv_getpath(char *dst, size_t *dstlen, const char *fn, size_t len)
{
	ffbool isabs = 0, aloc = 0;
	size_t cap = serv->rootdir.len + len + 1;

	if (ffpath_abs(fn, len)) {
		isabs = 1;
		cap = len + 1;
	}

	if (dst == NULL || *dstlen < cap) {
		dst = ffmem_alloc(cap);
		if (dst == NULL)
			return NULL;
		aloc = 1;
	}

	len = ffs_fmt(dst, dst + cap, "%*s%*s"
		, (!isabs) ? serv->rootdir.len : (size_t)0, serv->rootdir.ptr, len, fn);

	len = ffpath_norm(dst, cap, dst, len, FFPATH_STRICT_BOUNDS);
	if (len == 0) {
		if (aloc)
			ffmem_free(dst);
		return NULL; //invalid path
	}

	if (len != 1 && dst[len - 1] == '/')
		len--;

	dst[len] = '\0';
	if (dstlen != NULL)
		*dstlen = len;
	return dst;
}

static const fsv_modinfo * srv_findmod(const char *name, size_t namelen)
{
	fmodule *m;
	FFLIST_WALK(&serv->mods, m, sib) {
		if (0 == ffs_icmpz(name, namelen, m->name))
			return &m->mod;
	}
	return NULL;
}

static void srv_timer(fsv_timer *t, int64 interval_ms, fftmrq_handler func, void *param)
{
	if (fftmrq_active(&serv->tmrqu, t)) {
		dbglog(FSV_LOG_DBGFLOW, "remove timer: %p", t);
		fftmrq_rm(&serv->tmrqu, t);
	}

	if (interval_ms == 0)
		return;

	t->handler = func;
	t->param = param;
	fftmrq_add(&serv->tmrqu, t, interval_ms);
	dbglog(FSV_LOG_DBGFLOW, "add timer: %p, interval: %D, handler: %p, param: %p"
		, t, interval_ms, func, param);
}

static fftime srv_gettime4(ffdtm *dt, char *dst, size_t cap, uint flags)
{
	fftime t;
	int f = 0;

	if (flags & FSV_TIME_ADDMS)
		f |= TM_MSEC;

	switch (flags & 0x0f) {
	case FSV_TIME_YMD:
		f |= TM_YMD;
		break;

	case FSV_TIME_YMD_LOCAL:
		f |= TM_YMD_LOCAL;
		break;

	case FSV_TIME_WDMY:
		f |= TM_WDMY;
		break;
	}

	curtime_get(&serv->time, &t, dt, dst, cap, f);
	return t;
}

static ssize_t srv_getvar(const char *name, size_t namelen, void *dst, size_t cap)
{
	if (ffs_ieqcz(name, namelen, "server_name")) {
		*(char**)dst = "fserv/" FSV_VER;
		return FFSLEN("fserv/" FSV_VER);

	} else
		return -1;
	return 0;
}

static int srv_process_vars(ffstr3 *dst, const ffstr *src, fsv_getvar_t getvar, void *udata, fsv_logctx *logctx)
{
	ffstr sname, sval;
	const char *p = src->ptr
		, *end = src->ptr + src->len;
	ffsvar v;
	int r;

	dst->len = 0;

	while (p != end) {
		size_t n = end - p;
		r = ffsvar_parse(&v, p, &n);
		p += n;

		switch (r) {
		case FFSVAR_TEXT:
			sval = v.val;
			if (sval.len == src->len) {
				ffarr_free(dst);
				ffstr_set2(dst, src);
				return 0;
			}
			break;

		case FFSVAR_S:
			sname = v.val;
			sval.len = getvar(udata, sname.ptr, sname.len, &sval.ptr, 0);
			if (sval.len == -1) {
				dbglog2(logctx, FSV_LOG_DBGFLOW, "srv_process_vars(): unknown variable: $%S", &sname);
				continue;
			}
		}

		if (NULL == ffarr_grow(dst, sval.len, FFARR_GROWQUARTER)) {
			errlog2(logctx, FSV_LOG_ERR, "srv_process_vars(): %e: by %L bytes"
				, FFERR_BUFGROW, sval.len);
			return 1;
		}
		ffstr3_cat(dst, sval.ptr, sval.len);
	}

	return 0;
}

static int srv_usertask(fsv_task *task, int op)
{
	switch (op) {
	case FSVCORE_TASKADD:
		fftask_post(&serv->taskmgr, task);
		break;

	case FSVCORE_TASKDEL:
		if (fftask_active(&serv->taskmgr, task))
			fftask_del(&serv->taskmgr, task);
		break;

	case FSVCORE_TASKQUEUED:
		return fftask_active(&serv->taskmgr, task);
	}
	return 0;
}


static int srv_savepid(uint pid)
{
	int ret = 0;
	char spid[FFINT_MAXCHARS];
	fffd f;
	int r;

	f = fffile_open(serv->pid_fn.ptr, O_CREAT | O_TRUNC | O_WRONLY);
	if (f == FF_BADFD)
		return 1;

	r = ffs_fromint(pid, spid, FFCNT(spid), 0);

	if (r != fffile_write(f, spid, r))
		ret = 1;

	if (0 != fffile_close(f))
		ret = 1;

	return ret;
}

static int srv_readpid(void)
{
	char s[FFINT_MAXCHARS];
	size_t r;
	fffd f;
	int pid;

	f = fffile_open(serv->pid_fn.ptr, O_RDONLY);
	if (f == FF_BADFD) {
		srv_errsave(fferr_last(), "open PID file: %s", serv->pid_fn.ptr);
		return 0;
	}

	r = fffile_read(f, s, sizeof(s));
	if (r == 0 || r == -1) {
		srv_errsave(fferr_last(), "read PID file: %s", serv->pid_fn.ptr);
		(void)fffile_close(f);
		return 0;
	}
	(void)fffile_close(f);

	if (r != ffs_toint(s, r, &pid, FFS_INT32)) {
		srv_errsave(fferr_last(), "invalid PID in file: %s", serv->pid_fn.ptr);
		return 0;
	}

	return pid;
}

static int srv_initsigs(void)
{
	if (0 != ffsig_mask(SIG_BLOCK, sigs, FFCNT(sigs)))
		return FFERR_SYSTEM;

	ffsig_init(&serv->sigs_task);
	if (0 != ffsig_ctl(&serv->sigs_task, serv->kq, sigs, FFCNT(sigs), &srv_handlesig))
		return FFERR_SYSTEM;

	return FFERR_OK;
}

static const char *const ssigs[] = {
	"", "fast-stop", "reopen", "reconfigure"
};

static void srv_handlesig(void *t)
{
	int sig = -1;
	int r;

	for (;;) {
		r = ffsig_read(&serv->sigs_task, NULL);

		if (r == -1) {
			if (!fferr_again(fferr_last()))
				syserrlog(FSV_LOG_ERR, "%s", "processing signals");
			break;
		}

		if (sig != -1)
			continue;

		switch (r) {
		case SIGINT:
			sig = FSVMAIN_STOP;
			break;
		case SIGHUP:
			sig = FSVMAIN_RECONFIG;
			break;
		case SIGUSR1:
			sig = FSVMAIN_REOPEN;
			break;

		default:
			dbglog(FSV_LOG_DBGFLOW, "skipping unknown signal %u", r);
			break;
		}
	}

	if (sig == -1)
		return;

	dbglog(FSV_LOG_DBGFLOW, "received signal %s", ssigs[sig]);
	if (serv->state == FSVMAIN_RUN)
		serv->state = sig;
}

static void srv_errsave(int syser, const char *fmt, ...)
{
	va_list va;

	va_start(va, fmt);
	ffstr_catfmtv(&serv->errstk, fmt, va);
	va_end(va);

	if (syser != -1)
		ffstr_catfmt(&serv->errstk, ": %E", syser);

	ffstr_catfmt(&serv->errstk, ". ");
}

static int srv_confinclude_wild(ffparser_schem *ps, const ffstr *val)
{
	int rc = 0;
	size_t pathlen;
	char *path;
	const char *fn;
	ffdirexp dex;

	path = srv_getpath(NULL, &pathlen, val->ptr, val->len);
	if (path == NULL) {
		srv_errsave(-1, "invalid file name");
		return FFPARS_ESYS;
	}

	if (path + pathlen == ffs_findof(path, pathlen, "?*", 2)) {
		rc = srv_confinclude(ps, path);
		ffmem_free(path);
		return rc;
	}

	rc = ffdir_expopen(&dex, path, 0);
	ffmem_free(path);
	if (rc != 0) {
		srv_errsave(-1, "could not expand files by a wildcard pattern");
		return FFPARS_ESYS;
	}

	for (;;) {
		fn = ffdir_expread(&dex);
		if (fn == NULL)
			break;

		rc = srv_confinclude(ps, fn);
		if (rc != 0)
			break;
	}

	ffdir_expclose(&dex);
	return rc;
}

static int srv_confinclude(ffparser_schem *ps, const char *fn)
{
	ffparser conf;
	ffparser *old;
	int rc;
	ffconf_parseinit(&conf);
	old = ps->p;
	ps->p = &conf;
	rc = srv_conf(fn, ps);
	ps->p = old;

	ffpars_free(&conf);
	return rc;
}

static int srv_conf(const char *filename, ffparser_schem *ps)
{
	fffd fd;
	fffilemap fm;
	int r = FFPARS_ENOVAL;
	size_t nn;
	size_t maplen;
	ffbool include = 0;
	ffstr mp;

	serv->include_depth++;

	fd = fffile_open(filename, O_RDONLY);
	if (fd == FF_BADFD) {
		srv_errsave(fferr_last(), "%e: %s", FFERR_FOPEN, filename);
		return FFPARS_ESYS;
	}

	fffile_mapinit(&fm);
	fffile_mapset(&fm, serv->cfg.pagesize, fd, 0, fffile_size(fd));

	for (;;) {
		if (0 != fffile_mapbuf(&fm, &mp)) {
			srv_errsave(fferr_last(), "%e: %s", FFERR_FMAP, filename);
			goto fail;
		}
		maplen = mp.len;

		while (mp.len != 0) {
			nn = mp.len;
			r = ffconf_parse(ps->p, mp.ptr, &nn);
			ffstr_shift(&mp, nn);

			if (r == FFPARS_MORE) {
				break;
			}

			if (ffpars_iserr(r))
				goto err;

			if (include) {
				include = 0;
				if (r != FFPARS_VAL) {
					r = FFPARS_EBADVAL;
					goto err;
				}

				r = srv_confinclude_wild(ps, &ps->p->val);
				if (r != 0)
					goto err;

				continue;
			}

			if (r == FFPARS_KEY && ffstr_ieqcz(&ps->p->val, "include")) {
				include = 1;
				continue;
			}

			r = ffconf_schemrun(ps);
			if (ffpars_iserr(r))
				goto err;
		}

		if (0 == fffile_mapshift(&fm, maplen))
			break;
	}

	if (include)
		r = FFPARS_ENOVAL;

	if (serv->include_depth == 1 && !ffpars_iserr(r))
		r = ffconf_schemfin(ps);

err:
	if (ffpars_iserr(r)) {
		const char *ser = ffpars_schemerrstr(ps, r, NULL, 0);
		srv_errsave(r == FFPARS_ESYS ? fferr_last() : -1
			, "parse config: %s: %u:%u: near \"%S\": \"%s\": %s"
			, filename
			, (int)ps->p->line, (int)ps->p->ch
			, &ps->p->val, (ps->curarg != NULL) ? ps->curarg->name : ""
			, ser);
		goto fail;
	}

	r = 0;

fail:
	fffile_mapclose(&fm);
	fffile_close(fd);
	serv->include_depth--;
	return r;
}

static int srv_startmods(void)
{
	size_t r;
	fmodule *m;

	FFLIST_WALK(&serv->mods, m, sib) {
		dbglog(FSV_LOG_DBGFLOW, "starting module %s", m->name);

		r = m->mod.f->sig(FSVCORE_SIGSTART);
		if (r != 0) {
			srv_errsave(fferr_last(), "module start: %s.  last error"
				, m->name);

			if (m->sib.prev != fflist_sentl(&serv->mods))
				srv_stop(FSVCORE_SIGSTOP, FF_GETPTR(fmodule, sib, m->sib.prev));
			return 1;
		}
	}

	return 0;
}

static int srv_start(void)
{
	int wh;

	serv->kq = ffkqu_create();
	if (serv->kq == FF_BADFD) {
		srv_errsave(fferr_last(), "%e", FFERR_KQUCREAT);
		return 1;
	}
	serv->cfg.queue = serv->kq;

	wh = srv_initsigs();
	if (wh != FFERR_OK) {
		srv_errsave(fferr_last(), "%e", wh);
		return 1;
	}

	if (0 != srv_savepid(ffps_curid())) {
		srv_errsave(fferr_last(), "save PID to the file: %s", serv->pid_fn.ptr);
		return 1;
	}

	srv_timer(&serv->tmr, 1, &curtime_update, &serv->time);
	fftime_now(&serv->time.time);

	serv->pquTm = ffkqu_settm(&serv->quTm, (uint)-1);

	serv->state = FSVMAIN_RUN;
	if (0 != srv_startmods()) {
		wh = 1;
		goto done;
	}

	if (0 != fftmrq_start(&serv->tmrqu, serv->kq, serv->timer_resol)) {
		srv_errsave(fferr_last(), "%e", FFERR_TMRINIT);
		wh = 1;
		goto done;
	}

	errlog(FSV_LOG_INFO, "server started");

	srv_evloop();
	fftmr_stop(serv->tmrqu.tmr, serv->kq);

	wh = 0;

done:
	srv_destroymods();
	(void)fffile_rm(serv->pid_fn.ptr);
	return wh;
}

static void srv_reopen()
{
	fmodule *m;
	FFLIST_WALK(&serv->mods, m, sib) {
		if (m->mod.f->sig == NULL)
			continue;
		m->mod.f->sig(FSVCORE_SIGREOPEN);
	}
}

static int srv_evloop(void)
{
	struct { FFARR(ffkqu_entry) } events;

	dbglog(FSV_LOG_DBGFLOW, "entering event loop");

	if (NULL == ffarr_alloc(&events, serv->events_count)) {
		srv_errsave(fferr_last(), "%e", FFERR_BUFALOC);
		return 1;
	}

	for (;;) {
		while (serv->state == FSVMAIN_RUN) {
			int i;
			int nevents = ffkqu_wait(serv->kq, events.ptr, events.cap, serv->pquTm);

#ifdef FSV_DBGTASKS
			if (nevents > 0 && nevents != 1) {
				dbglog(FSV_LOG_DBGFLOW, "kernel events: %L", (size_t)nevents);
			}
#endif

			for (i = 0;  i < nevents;  i++) {
				ffkqu_entry *ev = &events.ptr[i];
				ffkev_call(ev);

				fftask_run(&serv->taskmgr);
			}

			if (nevents == -1 && fferr_last() != EINTR) {
				syserrlog(FSV_LOG_ERR, "%e", FFERR_KQUWAIT);
				serv->state = FSVMAIN_STOP;
				break;
			}
		}

		switch (serv->state) {
		case FSVMAIN_STOP:
			srv_stop(FSVCORE_SIGSTOP, NULL);
			goto end;

		case FSVMAIN_RECONFIG:
			srv_stop(FSVCORE_SIGSTOP, NULL);
			goto end;

		case FSVMAIN_REOPEN:
			srv_reopen();
			serv->state = FSVMAIN_RUN;
			break;
		}
	}

end:
	dbglog(FSV_LOG_DBGFLOW, "leaving event loop");
	ffarr_free(&events);
	return 0;
}

static int srv_stop(int sig, fmodule *last)
{
	fflist_item *li = serv->mods.last;

	if (last != NULL)
		li = &last->sib;

	for (;  li != fflist_sentl(&serv->mods);  li = li->prev) {
		fmodule *m = FF_GETPTR(fmodule, sib, li);

		dbglog(FSV_LOG_DBGFLOW, "stopping module %s", m->name);

		if (m->mod.f->sig != NULL)
			m->mod.f->sig(sig);
	}

	return 0;
}

static void srv_destroymods(void)
{
	fmodule *m;
	FFLIST_WALK(&serv->mods, m, sib) {
		m->mod.f->destroy();
	}
}

static void curtime_update(const fftime *now, void *param)
{
	curtime_t *ct = (curtime_t*)param;

	if (0 != fftime_cmp(now, &ct->time)) {
		ct->time = *now;
		ct->flags = 0;
	}
}

static uint curtime_get(curtime_t *tt, fftime *t, ffdtm *dt, char *dst, size_t cap, uint flags)
{
	size_t r;

	if (flags & TM_YMD) {
		if (!(tt->flags & TM_YMD)) {
			if ((tt->flags & (TM_YMD | TM_WDMY)) == 0)
				fftime_split(&tt->dt, &tt->time, FFTIME_TZUTC);

			r = fftime_tostr(&tt->dt, tt->ymd, FFCNT(tt->ymd), FFTIME_DATE_YMD | FFTIME_HMS_MSEC);
			tt->ymd[r] = '\0';
			tt->flags |= TM_YMD;

		} else
			r = strlen(tt->ymd);

		if (dt != NULL)
			*dt = tt->dt;

		if (!(flags & TM_MSEC))
			r -= FFSLEN(".000");
		ffsz_copy(dst, cap, tt->ymd, r);
	}

	if (flags & TM_YMD_LOCAL) {
		if (!(tt->flags & TM_YMD_LOCAL)) {
			fftime_split(&tt->dt_lo, &tt->time, FFTIME_TZLOCAL);

			r = fftime_tostr(&tt->dt_lo, tt->ymd_lo, FFCNT(tt->ymd_lo), FFTIME_DATE_YMD | FFTIME_HMS_MSEC);
			tt->ymd_lo[r] = '\0';
			tt->flags |= TM_YMD_LOCAL;

		} else
			r = strlen(tt->ymd_lo);

		if (dt != NULL)
			*dt = tt->dt_lo;

		if (!(flags & TM_MSEC))
			r -= FFSLEN(".000");
		ffsz_copy(dst, cap, tt->ymd_lo, r);
	}

	if (flags & TM_WDMY) {
		if (!(tt->flags & TM_WDMY)) {
			if ((tt->flags & (TM_YMD | TM_WDMY)) == 0)
				fftime_split(&tt->dt, &tt->time, FFTIME_TZUTC);

			r = fftime_tostr(&tt->dt, tt->wdmy, FFCNT(tt->wdmy), FFTIME_WDMY);
			tt->wdmy[r] = '\0';
			tt->flags |= TM_WDMY;
		} else
			r = strlen(tt->wdmy);

		if (dt != NULL)
			*dt = tt->dt;

		ffsz_copy(dst, cap, tt->wdmy, r);
	}

	if (t != NULL)
		*t = tt->time;
	return 0;
}

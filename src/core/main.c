/**
Copyright (c) 2014 Simon Zolin
*/

#include <core/fserv.h>
#include <FFOS/file.h>
#include <FFOS/process.h>
#include <FF/path.h>
#include <FF/data/psarg.h>


#define FSV_FULLNAME "fserv " FSV_VER " beta"

typedef struct cmdline {
	ffstr conf_fn;
	int sig;
	byte daemon;
#ifdef FF_WIN
	byte bground;
#endif
} cmdline;

// CONFIG
static int conf_ver(ffparser_schem *ps, void *obj);
static int conf_help(ffparser_schem *ps, void *obj);
static const ffpars_enumlist conf_sigenum;

static int setroot(const fsv_main *fsv, const char *argv0);
static int args_parse(cmdline *opts, const char **argv, int argc);
static fffd bgrun(const cmdline *opts);


static void flog(fffd fd, const char *level, const char *fmt, ...)
{
	char buf[4096];
	char *s = buf;
	const char *end = buf + FFCNT(buf);
	va_list va;

	s += ffs_fmt(s, end, "fserv: %u: %s: ", ffps_curid(), level);

	va_start(va, fmt);
	s += ffs_fmtv(s, end, fmt, va);
	va_end(va);

	s = ffs_copyc(s, end, '\n');

	fffile_write(fd, buf, s - buf);
}

#define flog_out(level, ...) \
	flog(ffstdout, level, __VA_ARGS__)

#define flog_err(level, ...) \
	flog(ffstderr, level, __VA_ARGS__)

#define flog_errsys(level, fmt, ...) \
	flog(ffstderr, level, fmt ": %E", __VA_ARGS__, fferr_last())


static const ffpars_arg args[] = {
	{ "help", FFPARS_SETVAL('h') | FFPARS_TBOOL | FFPARS_FALONE,  FFPARS_DST(&conf_help) }
	, { "version", FFPARS_SETVAL('v') | FFPARS_TBOOL | FFPARS_FALONE,  FFPARS_DST(&conf_ver) }
	, { "conf", FFPARS_SETVAL('c') | FFPARS_TSTR,  FFPARS_DSTOFF(cmdline, conf_fn) }
	, { "sig", FFPARS_SETVAL('s') | FFPARS_TENUM,  FFPARS_DST(&conf_sigenum) }
	, { "daemon", FFPARS_SETVAL('d') | FFPARS_TBOOL | FFPARS_F8BIT | FFPARS_FALONE,  FFPARS_DSTOFF(cmdline, daemon) }

#ifdef FF_WIN
	, { "bg", FFPARS_TBOOL | FFPARS_F8BIT | FFPARS_FALONE,  FFPARS_DSTOFF(cmdline, bground) }
#endif
};

static int conf_ver(ffparser_schem *ps, void *obj)
{
	fffile_write(ffstdout, FFSTR(FSV_FULLNAME FF_NEWLN));
	return FFPARS_ELAST;
}

#define N FF_NEWLN
static int conf_help(ffparser_schem *ps, void *obj)
{
	fffile_write(ffstdout, FFSTR(
FSV_FULLNAME N
"Usage: fserv [-hvd] [-c CONF] [-s CMD]" N
N
"Options:" N
"  -h, --help       show this help" N
"  -v, --version    show version" N
"  -c, --conf=FILE  set configuration file (=conf/fserv.conf)" N
"  -d, --daemon     run in background" N
"  -s, --sig=CMD    send signal:" N
"      stop         stop the server" N
"      reconfig     re-read configuration file" N
"      reopen       reopen log files; clear cache" N
	));
	return FFPARS_ELAST;
}
#undef N

static const char *const conf_ssigs[] = {
	"stop", "reconfig", "reopen"
};
static const byte conf_sigs[] = {
	FSVMAIN_STOP, FSVMAIN_RECONFIG, FSVMAIN_REOPEN
};
static const ffpars_enumlist conf_sigenum = {
	conf_ssigs, FFCNT(conf_ssigs), FFPARS_DSTOFF(cmdline, sig)
};

static int setroot(const fsv_main *fsv, const char *argv0)
{
	const char *fn;
	ffstr path;
	char fnu[FF_MAXPATH];

	fn = ffps_filename(fnu, FFCNT(fnu), argv0);
	if (fn == NULL) {
		return -1;
	}
	ffpath_split2(fn, strlen(fn), &path, NULL);

	return fsv->setroot(path.ptr, path.len);
}

static int args_parse(cmdline *opts, const char **argv, int argc)
{
	int r, i;
	ffpsarg_parser p;
	ffparser_schem ps;
	const ffpars_ctx ctx = { opts, args, FFCNT(args), NULL };

	ffpsarg_scheminit(&ps, &p, &ctx);

	for (i = 1;  i < argc; ) {
		int n = 0;
		r = ffpsarg_parse(&p, argv[i], &n);
		i += n;

		r = ffpsarg_schemrun(&ps);
		if (ffpars_iserr(r))
			goto end;
	}

	r = ffpsarg_schemfin(&ps);

end:
	if (ffpars_iserr(r) && r != FFPARS_ELAST) {
		const char *fmt = (r == FFPARS_ESYS
			? "argument #%u '%S': %s: %E"
			: "argument #%u '%S': %s");
		flog(ffstderr, "error", fmt
			, (int)p.line, &p.val, ffpars_schemerrstr(&ps, r, NULL, 0), fferr_last());
	}

	ffpsarg_parseclose(&p);
	ffpars_schemfree(&ps);
	return r;
}

static fffd bgrun(const cmdline *opts)
{
#ifdef FF_WIN
	if (opts->bground)
		ffterm_detach();
	else
#endif
	if (opts->daemon) {
		fffd ps = ffps_createself_bg("--bg");
		return ps;
	}
	return 0;
}

FF_EXTN const fsv_main * fsv_getmain(void);

int main(int argc, const char **argv)
{
	cmdline opts;
	int ret = 1, st;
	const fsv_main *fsv = NULL;
	char *conf;
	fffd ps;

	ffmem_tzero(&opts);
	opts.sig = -1;
	ffmem_init();

	{
		int r = args_parse(&opts, argv, argc);
		if (r == FFPARS_ELAST)
			return 0;
		if (ffpars_iserr(r))
			return 1;
	}

	if (opts.conf_fn.len != 0)
		conf = opts.conf_fn.ptr;
	else {
		conf = "conf/fserv.conf";
	}

serve:
	fsv = fsv_getmain();
	if (NULL == fsv->create()) {
		flog_errsys("error", "%s", "create server");
		goto fin;
	}

	if (0 != setroot(fsv, argv[0])) {
		flog_err("error", "set root directory");
		goto fin;
	}

	if (0 != fsv->readconf(conf)) {
		flog_err("error", "%s", fsv->errstr());
		goto fin;
	}

	if (opts.sig != -1) {
		if (0 != fsv->sig(conf_sigs[opts.sig])) {
			flog_err("error", "%s", fsv->errstr());
			goto fin;
		}

		ret = 0;
		goto fin;
	}

	ps = bgrun(&opts);
	if (ps == FF_BADFD) {
		flog_errsys("error", "%e", FFERR_PSFORK);
		goto fin;

	} else if (ps != 0) {
		flog_out("info", "forked process: %u", ffps_id(ps));
		(void)ffps_close(ps);
		ret = 0;
		goto fin;
	}

	st = fsv->sig(FSVMAIN_RUN);
	switch (st) {
	case FSVMAIN_RECONFIG:
		fsv->destroy();
		goto serve;

	case -1:
		flog_err("error", "%s", fsv->errstr());
		goto fin;

	default:
		ret = 0;
	}

fin:
	if (fsv != NULL)
		fsv->destroy();
	return ret;
}

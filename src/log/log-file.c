/**
Copyright (c) 2014 Simon Zolin
*/

#include "log.h"


typedef struct logfile {
	fffd fd;
	ffstr3 buf;
	fsv_timer rotate_timer;
	unsigned have_output :1; //data was written since the last rotation

	//conf:
	ffstr fn;
	uint buf_size;
	uint rotate_every; //sec
} logfile;


// FSERV LOG OUTPUT
static fsv_log_outptr * logf_create(ffpars_ctx *a);
static void logf_free(fsv_log_outptr *out);
static int logf_open(fsv_log_outptr *out, int flags);
static int logf_write(fsv_log_outptr *out, int lev, const char *buf, size_t len);
const fsv_log_output logf_output = {
	&logf_create, &logf_free, &logf_open, &logf_write
};

// CONFIG
static int logf_conf_filename(ffparser_schem *ps, logfile *lf, const ffstr *s);

static int logf_openfile(logfile *lf);
static int logf_close(logfile *lf);
static int logf_fwrite(logfile *lf, const char *src, size_t len);
static void logf_flush(logfile *lf);
static void logf_rotate(const fftime *now, void *param);


static const ffpars_arg logf_args[] = {
	{ "file", FFPARS_TSTR | FFPARS_FREQUIRED | FFPARS_FNOTEMPTY,  FFPARS_DST(logf_conf_filename) }
	, { "buffer_size", FFPARS_TSIZE,  FFPARS_DSTOFF(logfile, buf_size) }
	, { "rotate_every",  FFPARS_TINT,  FFPARS_DSTOFF(logfile, rotate_every) }
};

static int logf_conf_filename(ffparser_schem *ps, logfile *lf, const ffstr *s)
{
	ssize_t r = logm->srv->getpath(NULL, 0, s->ptr, s->len);
	if (r == -1)
		return FFPARS_EBADVAL;
	if (NULL == ffstr_alloc(&lf->fn, r))
		return FFPARS_ESYS;
	lf->fn.len = logm->srv->getpath(lf->fn.ptr, r, s->ptr, s->len);
	return 0;
}


static fsv_log_outptr * logf_create(ffpars_ctx *a)
{
	logfile *lf = ffmem_tcalloc1(logfile);
	if (lf == NULL)
		return NULL;

	lf->fd = FF_BADFD;
	lf->buf_size = 4 * 1024;
	lf->rotate_every = 0;

	ffpars_setargs(a, lf, logf_args, FFCNT(logf_args));
	return (fsv_log_outptr*)lf;
}

static void logf_free(fsv_log_outptr *out)
{
	logfile *lf = (logfile*)out;
	logm->srv->fsv_timerstop(&lf->rotate_timer);
	logf_close(lf);
	ffstr_free(&lf->fn);
	ffarr_free(&lf->buf);

	ffmem_free(lf);
}

static int logf_open(fsv_log_outptr *out, int flags)
{
	logfile *lf = (logfile*)out;

	switch (flags) {
	case LOG_OPEN:
		if (lf->rotate_every != 0)
			logm->srv->timer(&lf->rotate_timer, lf->rotate_every * 1000, &logf_rotate, lf);

		if (lf->buf_size != 0
			&& NULL == ffarr_alloc(&lf->buf, lf->buf_size))
		{
			logm_errsys("%e", FFERR_BUFALOC);
			return 1;
		}

		return logf_openfile(lf);

	case LOG_FLUSH:
		logf_flush(lf);
		return 0;

	case LOG_REOPEN:
		logf_flush(lf);
		logf_close(lf);
		return logf_openfile(lf);
	}

	return 0;
}

static int logf_write(fsv_log_outptr *out, int lev, const char *buf, size_t len)
{
	logfile *lf = (logfile*)out;
	ffstr dst;
	const char *bufend = buf + len;

	if (!lf->have_output)
		lf->have_output = 1;

	if (lf->buf.cap == 0) {
		logf_fwrite(lf, buf, len);
		return 0;
	}

	for (;;) {
		buf += ffbuf_add(&lf->buf, buf, bufend - buf, &dst);
		if (dst.len == 0)
			break;
		logf_fwrite(lf, dst.ptr, dst.len);
	}

	return 0;
}


static int logf_openfile(logfile *lf)
{
	lf->fd = fffile_open(lf->fn.ptr, FFO_APPEND | O_WRONLY);
	if (lf->fd == FF_BADFD) {
		logm_errsys("%e: %S", FFERR_FOPEN, &lf->fn);
		return 1;
	}
	return 0;
}

static int logf_close(logfile *lf)
{
	int r = 0;
	if (lf->fd != FF_BADFD) {
		r = fffile_close(lf->fd);
		if (r != 0)
			logm_errsys("%e: %S", FFERR_FCLOSE, &lf->fn);
		lf->fd = FF_BADFD;
	}
	return r;
}

static int logf_fwrite(logfile *lf, const char *src, size_t len)
{
	if (len != fffile_write(lf->fd, src, len)) {
		logm_errsys("%e: %S", FFERR_WRITE, &lf->fn);
		return 1;
	}

#if 0
	fffile_fmt(ffstdout, NULL, "written %L bytes into %S\n"
		, len, &lf->fn);
#endif
	return 0;
}

static void logf_flush(logfile *lf)
{
	if (lf->buf.len == 0)
		return;

	logf_fwrite(lf, lf->buf.ptr, lf->buf.len);
	lf->buf.len = 0;
}

// /logdir/filename.log -> /logdir/filename.log.20010101-234537
static void logf_rotate(const fftime *now, void *param)
{
	logfile *lf = (logfile*)param;
	char fn[FF_MAXPATH];
	ssize_t n;
	ffdtm dt;

	if (!lf->have_output)
		return; //don't create a file with size 0

	logf_flush(lf);

	logm->srv->gettime4(&dt, NULL, 0, FSV_TIME_YMD_LOCAL);

	n = ffs_fmt(fn, fn + FFCNT(fn), "%S.%04u%02u%02u-%02u%02u%02u%Z"
		, &lf->fn
		, dt.year, dt.month, dt.day
		, dt.hour, dt.min, dt.sec);
	if (n == FFCNT(fn)) {
		logm_err("log rotate: too large filename: %S", &lf->fn);
		return;
	}

	logf_close(lf);

	if (0 != fffile_rename(lf->fn.ptr, fn))
		logm_errsys("log rotate: %e", FFERR_FRENAME);

	logf_openfile(lf);

	lf->have_output = 0;
}

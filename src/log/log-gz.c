/**
Copyright (c) 2014 Simon Zolin
*/

#include "log.h"
#include <FF/gz.h>


typedef struct loggzip {
	ffgz gz;
	fffd fd;
	ffstr3 buf;

	//conf:
	ffstr fn;
	uint bufsize;
	byte gzlev;
	byte gzmemlev;
	byte gzwbits;
} loggzip;


// FSERV LOG OUTPUT
static fsv_log_outptr * logz_create(ffpars_ctx *a);
static void logz_free(fsv_log_outptr *out);
static int logz_open(fsv_log_outptr *out, int flags);
static int logz_write(fsv_log_outptr *out, int lev, const char *buf, size_t len);
const fsv_log_output logz_output = {
	&logz_create, &logz_free, &logz_open, &logz_write
};

// CONFIG
static int logz_conf_file(ffparser_schem *ps, loggzip *lz, const ffstr *v);
static int logz_conf_gzipbufsize(ffparser_schem *ps, loggzip *lz, const int64 *n);
static int logz_conf_end(ffparser_schem *ps, loggzip *lz);

static int logz_openfile(loggzip *lz);
static void logz_close(loggzip *lz);
static int logz_flush(loggzip *lz, const char *d, size_t len, int flush);


static const ffpars_arg logz_conf_args[] = {
	{ "file", FFPARS_TSTR | FFPARS_FREQUIRED | FFPARS_FNOTEMPTY,  FFPARS_DST(logz_conf_file) }
	, { "buffer_size", FFPARS_TSIZE | FFPARS_FNOTZERO,  FFPARS_DSTOFF(loggzip, bufsize) }
	, { "gzip_level",  FFPARS_TINT | FFPARS_F8BIT,  FFPARS_DSTOFF(loggzip, gzlev) }
	, { "gzip_buffer_size",  FFPARS_TSIZE | FFPARS_FNOTZERO,  FFPARS_DST(&logz_conf_gzipbufsize) }
	, { NULL,  FFPARS_TCLOSE,  FFPARS_DST(&logz_conf_end) }
};

static int logz_conf_gzipbufsize(ffparser_schem *ps, loggzip *lz, const int64 *n)
{
	int half = (int)*n / 2;
	int i;

	i = ffgz_wbits(half);
	if (i == -1)
		return FFPARS_EBADVAL;
	lz->gzwbits = i;

	i = ffgz_memlevel(half);
	if (i == -1)
		return FFPARS_EBADVAL;
	lz->gzmemlev = i;

	return 0;
}

static int logz_conf_file(ffparser_schem *ps, loggzip *lz, const ffstr *s)
{
	ssize_t r = logm->srv->getpath(NULL, 0, s->ptr, s->len);
	if (r == -1)
		return FFPARS_EBADVAL;
	if (NULL == ffstr_alloc(&lz->fn, r))
		return FFPARS_ESYS;
	lz->fn.len = logm->srv->getpath(lz->fn.ptr, r, s->ptr, s->len);
	return 0;
}

static int logz_conf_end(ffparser_schem *ps, loggzip *lz)
{
	lz->gzlev = (uint)ffmin(lz->gzlev, 9);
	return 0;
}


static fsv_log_outptr * logz_create(ffpars_ctx *a)
{
	loggzip *lz = ffmem_tcalloc1(loggzip);
	if (lz == NULL)
		return NULL;

	lz->gzlev = 6;
	lz->gzwbits = ffgz_wbits(0);
	lz->gzmemlev = ffgz_memlevel(0);
	lz->fd = FF_BADFD;
	lz->bufsize = 4 * 1024;

	ffpars_setargs(a, lz, logz_conf_args, FFCNT(logz_conf_args));
	return (fsv_log_outptr*)lz;
}

static void logz_free(fsv_log_outptr *out)
{
	loggzip *lz = (loggzip*)out;
	logz_close(lz);
	ffstr_free(&lz->fn);
	ffarr_free(&lz->buf);

	ffmem_free(lz);
}

static int logz_open(fsv_log_outptr *out, int flags)
{
	loggzip *lz = (loggzip*)out;

	switch (flags) {
	case LOG_OPEN:
		if (NULL == ffarr_alloc(&lz->buf, lz->bufsize)) {
			logm_errsys("%e", FFERR_BUFALOC);
			return 1;
		}

		return logz_openfile(lz);

	case LOG_FLUSH:
		if (lz->buf.len == 0)
			break; //nothing to flush

		logz_flush(lz, lz->buf.ptr, lz->buf.len, 0);
		lz->buf.len = 0;
		break;

	case LOG_REOPEN:
		logz_close(lz);
		return logz_openfile(lz);
	}

	return 0;
}

static int logz_write(fsv_log_outptr *out, int lev, const char *buf, size_t len)
{
	loggzip *lz = (loggzip*)out;
	ffstr dst;
	const char *bufend = buf + len;

	for (;;) {
		buf += ffbuf_add(&lz->buf, buf, bufend - buf, &dst);
		if (dst.len == 0)
			break;
		logz_flush(lz, dst.ptr, dst.len, 0);
	}
	return 0;
}


static int logz_openfile(loggzip *lz)
{
	lz->fd = fffile_open(lz->fn.ptr, FFO_APPEND | O_WRONLY);
	if (lz->fd == FF_BADFD) {
		logm_errsys("%e: %S", FFERR_FOPEN, &lz->fn);
		return 1;
	}
	return 0;
}

static void logz_close(loggzip *lz)
{
	if (lz->fd != FF_BADFD) {
		if (0 != fffile_close(lz->fd))
			logm_errsys("%e: %S", FFERR_FCLOSE, &lz->fn);
	}
}

static int logz_flush(loggzip *lz, const char *d, size_t len, int flush)
{
	int rc = 1;
	int r;
	char buf[16 * 1024];
	ffgz *gz = &lz->gz;

	if (0 != ffgz_deflateinit(gz, lz->gzlev, lz->gzwbits + 16, lz->gzmemlev)) {
		logm_err("init deflate: %S: %s", &lz->fn, ffgz_errstr(gz));
		return 1;
	}
	ffgz_setin(gz, d, len);

	for (;;) {
		ffgz_setout(gz, buf, FFCNT(buf));

		r = ffgz_deflate(gz, Z_FINISH, NULL, &len);
		if (r != Z_OK && r != Z_STREAM_END) {
			logm_err("deflate: %S: %s", &lz->fn, ffgz_errstr(gz));
			goto end;
		}

		if (len != fffile_write(lz->fd, buf, len)) {
			logm_errsys("%e: %S", FFERR_WRITE, &lz->fn);
			goto end;
		}

#if 0
		fffile_fmt(ffstdout, NULL, "written %L bytes into file %S\n"
			, (size_t)len, &lz->fn);
#endif

		if (r == Z_STREAM_END)
			break;
	}

	rc = 0;

end:
	if (0 != ffgz_deflatefin(gz))
		logm_err("fin deflate: %S: %s", &lz->fn, ffgz_errstr(gz));
	return rc;
}

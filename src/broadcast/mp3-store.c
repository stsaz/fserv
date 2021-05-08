/**
Copyright 2014 Simon Zolin.
*/

#include <broadcast/brdcast.h>

#include <FF/mtags/id3.h>
#include <FF/path.h>
#include <FF/time.h>
#include <FFOS/file.h>
#include <FFOS/dir.h>
#include <FFOS/error.h>


struct mp3store {
	//conf:
	ffstr dir;
	uint prealoc;
	uint min_size;
	byte use_spaces;
	byte use_time;
	byte use_meta;
	byte change_case;

	fsv_logctx *logctx;
	char buf[4096];
	uint nbuf;
	char fn[FF_MAXPATH];
	fffd fd;
	uint64 fsize;
	uint64 prealoc_size;
	ffstr title;
	unsigned tags_written :1
		, freopen :1;
};

enum MP3STOR_CHANGE_CASE {
	ccaseOff
	, ccaseLower
	, ccaseUpper
	, ccaseWordUpper
};


// CONFIG
static int mp3stor_conf_dir(ffparser_schem *ps, mp3store *stor, const ffstr *val);
static const ffpars_enumlist mp3stor_conf_storechgcaseenum;

static void mp3stor_writetofile(mp3store *stor, const void *data, size_t sz, ffbool freopen);
static void mp3stor_writetags(mp3store *stor, ffstr3 *buf);
static int mp3stor_prepfn(mp3store *stor, char *fn, size_t cnt);
static void mp3stor_closefile(mp3store *stor);


static const ffpars_arg mp3stor_store_conf_args[] = {
	{ "directory",  FFPARS_TSTR | FFPARS_FNOTEMPTY | FFPARS_FREQUIRED,  FFPARS_DST(&mp3stor_conf_dir) }
	, { "preallocate",  FFPARS_TSIZE,  FFPARS_DSTOFF(mp3store, prealoc) }
	, { "min_size",  FFPARS_TSIZE,  FFPARS_DSTOFF(mp3store, min_size) }
	, { "use_spaces",  FFPARS_TBOOL | FFPARS_F8BIT,  FFPARS_DSTOFF(mp3store, use_spaces) }
	, { "use_time",  FFPARS_TBOOL | FFPARS_F8BIT,  FFPARS_DSTOFF(mp3store, use_time) }
	, { "use_meta",  FFPARS_TBOOL | FFPARS_F8BIT,  FFPARS_DSTOFF(mp3store, use_meta) }
	, { "change_case",  FFPARS_TENUM | FFPARS_F8BIT,  FFPARS_DST(&mp3stor_conf_storechgcaseenum) }
};

mp3store * mp3stor_init(ffpars_ctx *ctx, fsv_logctx *lx)
{
	mp3store *stor = ffmem_tcalloc1(mp3store);
	if (stor == NULL)
		return NULL;

	stor->logctx = lx;
	stor->fd = FF_BADFD;
	stor->prealoc = 5 * 1024 * 1024;
	stor->min_size = 200 * 1024;
	stor->use_spaces = 0;
	stor->use_time = 1;
	stor->use_meta = 1;

	ffpars_setargs(ctx, stor, mp3stor_store_conf_args, FFCNT(mp3stor_store_conf_args));
	return stor;
}

void mp3stor_free(mp3store *stor)
{
	ffstr_free(&stor->dir);
	ffmem_free(stor);
}

void mp3stor_name(mp3store *stor, const char *name, size_t namelen)
{
	ffstr_set(&stor->title, name, namelen);
	stor->freopen = 1;
}

void mp3stor_write(mp3store *stor, const char *data, size_t len)
{
	const char *d = data;
	size_t dlen = len;

	if (stor->freopen) {
		// we continue writing to the current file until we find a valid frame
		d = (char*)ffmpg_findframe(data, len, 1); //^ 1 is not robust, but better than nothing
		if (d != NULL)
			dlen = len - (d - data);
		else
			dlen = 0;

		if (stor->fd != FF_BADFD) {
			if (dlen != len)
				mp3stor_writetofile(stor, data, len - dlen, 0);
			mp3stor_closefile(stor);
		}
	}

	if (dlen != 0) {
		mp3stor_writetofile(stor, d, dlen, stor->freopen);
		stor->freopen = 0;
	}
}

void mp3stor_stop(mp3store *stor)
{
	if (stor->fd != FF_BADFD)
		mp3stor_closefile(stor);
}

static const char *const mp3stor_conf_storechgcase[] = {
	"off", "lower", "upper", "wordupper"
};
static const ffpars_enumlist mp3stor_conf_storechgcaseenum = {
	mp3stor_conf_storechgcase, FFCNT(mp3stor_conf_storechgcase), FFPARS_DSTOFF(mp3store, change_case)
};

static int mp3stor_conf_dir(ffparser_schem *ps, mp3store *stor, const ffstr *val)
{
	stor->dir.ptr = bcastm->core->getpath(NULL, &stor->dir.len, val->ptr, val->len);
	if (stor->dir.ptr == NULL)
		return FFPARS_EBADVAL;
	return 0;
}

typedef size_t (*chcase_func_t)(char *dst, ffsize cap, const char *src, ffsize len);
static const chcase_func_t chcase[] = { &ffs_lower, &ffs_upper, &ffs_titlecase };

/** Prepare filename.
Create directory with current date.
Optionally, use current time, meta data.
Optionally, replace ' ' with '.'.
Add .mp3 extension. */
static int mp3stor_prepfn(mp3store *stor, char *fn, size_t cnt)
{
	char *pfn = fn;
	const char *fnend = fn + cnt - FFSLEN("\0");
	ffdtm dt;
	size_t ntitl;
	ffbool usemeta = (stor->use_meta && stor->title.len != 0);

	pfn += ffs_fmt(pfn, fnend, "%S/", &stor->dir);
	bcastm->core->gettime4(&dt, NULL, 0, FSV_TIME_YMD_LOCAL);
	pfn += fftime_tostr(&dt, pfn, fnend - pfn, FFTIME_DATE_YMD);
	if (pfn == fnend)
		return 1;

	*pfn = '\0';
	if (0 != ffdir_make(fn) && fferr_last() != EEXIST)
		return -1;

	*pfn++ = '/';

	if (!usemeta || stor->use_time)
		pfn += ffs_fmt(pfn, fnend, "%02u%02u%02u", dt.hour, dt.min, dt.sec);

	if (usemeta) {
		if (stor->use_time)
			pfn = ffs_copy(pfn, fnend, (stor->use_spaces ? " - " : ".-."), 3);

		ntitl = ffpath_makefn(pfn, fnend - pfn, stor->title.ptr, stor->title.len, '_');

		if (stor->change_case != ccaseOff)
			chcase[stor->change_case - 1](pfn, fnend - pfn, pfn, ntitl);

		if (!stor->use_spaces)
			ffs_replacechar(pfn, ntitl, pfn, fnend - pfn, ' ', '.', NULL);

		pfn += ntitl;
	}

	pfn = ffs_copycz(pfn, fnend, ".mp3");
	if (pfn == fnend)
		return 1;
	*pfn = '\0';

	return 0;
}

static void mp3stor_writetags(mp3store *stor, ffstr3 *buf)
{
	ffstr sartist = {0}, stitle = {0};
	char tmp[4 * 1024];
	ffid3_cook id3;

	ffmem_tzero(&id3);
	id3.buf = *buf;
	fficy_streamtitle(stor->title.ptr, stor->title.len, &sartist, &stitle);

	if (stor->change_case != ccaseOff) {
		stitle.len = chcase[stor->change_case - 1](tmp, sizeof(tmp), stitle.ptr, stitle.len);
		stitle.ptr = tmp;
	}
	ffid3_add(&id3, FFMMTAG_TITLE, stitle.ptr, stitle.len);

	if (sartist.len != 0) {
		if (stor->change_case != ccaseOff) {
			sartist.len = chcase[stor->change_case - 1](tmp, sizeof(tmp), sartist.ptr, sartist.len);
			sartist.ptr = tmp;
		}
		ffid3_add(&id3, FFMMTAG_ARTIST, sartist.ptr, sartist.len);
	}

	ffid3_fin(&id3);
	*buf = id3.buf;
	dbglog(stor->logctx, FSV_LOG_DBGFLOW, "prepared file tags: %u bytes", (int)buf->len);
}

static void mp3stor_writetofile(mp3store *stor, const void *data, size_t sz, ffbool freopen)
{
	int e = 0;
	fffd f = stor->fd;
	ffstr3 buf;
	ffstr dst;
	const char *d = data, *dataend = d + sz;

	if (freopen && stor->fd == FF_BADFD) {
		int er = mp3stor_prepfn(stor, stor->fn, sizeof(stor->fn));
		if (er != 0) {
			if (er == 1)
				errlog(stor->logctx, FSV_LOG_ERR, "filename is too large");
			else
				syserrlog(stor->logctx, FSV_LOG_ERR, "%s", "create path");
			return ;
		}

		f = fffile_open(stor->fn, FFO_CREATENEW | O_WRONLY);
		if (f == FF_BADFD) {
			syserrlog(stor->logctx, FSV_LOG_ERR, "%e: %s", FFERR_FOPEN, stor->fn);
			return ;
		}
		stor->fd = f;
		if (stor->prealoc != 0) {
			if (0 != fffile_trunc(f, stor->prealoc)) {
				e = FFERR_FSEEK;
				goto fail;
			}
			stor->prealoc_size = stor->prealoc;
		}
		stor->fsize = 0;
		dbglog(stor->logctx, FSV_LOG_DBGFLOW, "created file %s", stor->fn);
	}

	if (stor->fd == FF_BADFD)
		return ;

	if (stor->prealoc != 0 && stor->fsize + sz > stor->prealoc_size) {
		// if file size is about to become larger than we preallocated, extend the file
		if (0 != fffile_trunc(f, stor->prealoc_size + stor->prealoc / 2)) {
			e = FFERR_FSEEK;
			goto fail;
		}
		stor->prealoc_size += stor->prealoc / 2;
	}

	ffarr_set3(&buf, stor->buf, stor->nbuf, sizeof(stor->buf));

	if (!stor->tags_written && stor->fsize == 0 && stor->title.len != 0) {
		mp3stor_writetags(stor, &buf);
		stor->tags_written = 1;
	}

	for (;;) {
		d += ffbuf_add(&buf, d, dataend - d, &dst);
		stor->fsize += dst.len;
		stor->nbuf = (int)buf.len;
		if (dst.len == 0)
			break;

		if (dst.len != fffile_write(stor->fd, dst.ptr, dst.len)) {
			e = FFERR_WRITE;
			goto fail;
		}

		dbglog(stor->logctx, FSV_LOG_DBGFLOW, "written %L to file [%U]"
			, (size_t)dst.len, stor->fsize);
	}

	return;

fail:
	syserrlog(stor->logctx, FSV_LOG_ERR, "%e", (int)e);
	mp3stor_closefile(stor);
}

static void mp3stor_closefile(mp3store *stor)
{
	int e = 0;
	FF_ASSERT(stor->fd != FF_BADFD);

	if (stor->nbuf != 0) {
		if (stor->nbuf != fffile_write(stor->fd, stor->buf, stor->nbuf))
			e = FFERR_WRITE;
		else {
			stor->fsize += stor->nbuf;
			dbglog(stor->logctx, FSV_LOG_DBGFLOW, "written %L to file [%U], %L buffered"
				, (size_t)stor->nbuf, stor->fsize, (size_t)0);
		}
		stor->nbuf = 0;
	}

	if (0 != fffile_trunc(stor->fd, stor->fsize))
		e = FFERR_WRITE;

	if (0 != fffile_close(stor->fd))
		e = FFERR_FCLOSE;
	stor->fd = FF_BADFD;

	if (e != 0)
		syserrlog(stor->logctx, FSV_LOG_ERR, "%e", (int)e);

	if (stor->fsize < stor->min_size) {
		if (0 != fffile_rm(stor->fn))
			syserrlog(stor->logctx, FSV_LOG_ERR, "%e", FFERR_FDEL);
		else
			dbglog(stor->logctx, FSV_LOG_DBGFLOW, "deleted the stored file with size %U", (int64)stor->fsize);
	}
	else
		dbglog(stor->logctx, FSV_LOG_DBGFLOW, "stored the file with size %U", (int64)stor->fsize);

	stor->prealoc_size = 0;
	stor->fsize = 0;
	stor->tags_written = 0;
}

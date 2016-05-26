/** Persistent file cache.
Copyright 2015 Simon Zolin.
*/

#include <core/fserv.h>
#include <FF/list.h>
#include <FF/crc.h>
#include <FF/path.h>
#include <FFOS/dir.h>
#include <FFOS/file.h>


enum {
	MAX_KEYLEN = 64*1024
};

typedef struct fcachemodule {
	const fsv_core *core;
	fsv_logctx *logctx;
	fflist ctxs; //fcachectx[]
} fcachemodule;

static fcachemodule *fcachm;

typedef struct fcachectx {
	fflist_item sib;
	const fsv_fcach_cb *cb;
	ffstr dir;
	ushort max_hdr;
	uint64 max_data;
	uint def_expiry;
	size_t read_ahead;
	size_t bufsize;

	const fsv_cache *mca;
	fsv_cachectx *mcx;
} fcachectx;

enum HDR_F {
	HDR_INCOMPLETE = 0 //incomplete data marker
	, HDR_1 = 1
	, HDR_UNLINKED = 0x100
};

typedef struct fcache_hdr {
	uint flags; //enum HDR_F

	ushort keylen;
	ushort uhdr_len;
	uint fdoff;

	uint expire_tm //when a file is considered stale
		, creat_tm; //when a file was created

	char key[0];
} fcache_hdr;

typedef struct fcache {
	fcachectx *cx;
	fffd fd;
	uint64 size; //data size
	ffstr hdr; //mapped header file
	fcache_hdr *h;
	uint hash[1];

	ffstr3 buf;
	void *userptr;

	fsv_cacheitem_id *memid;

	unsigned locked :1 //locked for update
		, created :1
#ifdef FF_WIN
		, no_remove :1
#endif
		;
} fcache;

#define FCACH_MODNAME "FCAC"

#define dbglog(lx, ...) \
	fsv_dbglog(lx, FSV_LOG_DBGFLOW, FCACH_MODNAME, NULL, __VA_ARGS__)

#define errlog(lx, ...) \
	fsv_errlog(lx, FSV_LOG_ERR, FCACH_MODNAME, NULL, __VA_ARGS__)

#define syserrlog(lx, fmt, ...) \
	fsv_syserrlog(lx, FSV_LOG_ERR, FCACH_MODNAME, NULL, fmt, __VA_ARGS__)

// FSERV MODULE
static void * fcachm_create(const fsv_core *core, ffpars_ctx *confctx, fsv_modinfo *m);
static void fcachm_destroy(void);
static int fcachm_sig(int sig);
static const void * fcachm_iface(const char *name);
const fsv_mod fsv_cach_file = {
	&fcachm_create, &fcachm_destroy, &fcachm_sig, &fcachm_iface
};

// FSERV CACHE
static fsv_cachectx * fcach_newctx(ffpars_ctx *a, const fsv_fcach_cb *cb, int flags);
static int fcach_fetch(fsv_cachectx *cx, fsv_fcacheitem *ca, int flags);
static int fcach_store(fsv_cachectx *cx, fsv_fcacheitem *ca, int flags);
static int fcach_update(fsv_fcacheitem *ca, int flags);
static int fcach_unref(fsv_fcacheitem *ca, int flags);
static const fsv_fcache fsv_cach_iface = {
	&fcach_newctx, &fcach_fetch, &fcach_store, &fcach_update, &fcach_unref
};

// MEMORY CACHE
static int fcach_mem_fetch(fcachectx *cx, fsv_fcacheitem *ca, fcache **c, fsv_logctx *logctx);
static int fcach_mem_store(fcache *c, fsv_logctx *logctx);
static int fcach_mem_unref(fcache *c, uint f, fsv_logctx *logctx);
static int fcach_mem_cb(fsv_cachectx *ctx, fsv_cacheitem *ca, int flags);
static const fsv_cach_cb fsv_fcach_mem_cb = {
	&fcach_mem_cb
};

// CONFIG
static int fcachx_conf_dir(ffparser_schem *ps, fcachectx *cx, const ffstr *v);
static int fcach_conf_mem(ffparser_schem *ps, fcachectx *cx, ffpars_ctx *confctx);

static void fcach_init(fcache *c, fcachectx *cx);
static void fcach_fill(fcache *c, fsv_fcacheitem *ca);
static int fcach_write(fcache *c, const char *data, size_t len, fsv_logctx *logctx, int fin);
static int fcach_finstore(fcache *c, fsv_logctx *logctx);
static void fcach_finfile(fcache *c, fsv_logctx *logctx);
static void fcach_rm(fcache *c);
static void fcach_unlink(fcache *c);
static void fcach_free(fcache *c);
static int fcach_getfn(fcache *c, uint *hash, ffstr *fn);
static int fcach_parsehdr(fcache *c, fffd fhdr, fsv_logctx *logctx);
static int fcach_writehdr(fcache *c, fffd fhdr, fsv_fcacheitem *ca);

static FFINL void fcach_setexpire(fcache *c, uint expire) {
	c->h->expire_tm = (expire != 0) ? expire : fcachm->core->fsv_gettime().s + c->cx->def_expiry;
}

/** Return TRUE if hash is not set. */
#define KEYHASH_EMPTY(hash)  ((hash)[0] == 0)

#define KEYHASH_SET(hash, key, len, key_icase) \
	*(hash) = ffcrc32_get(key, len, key_icase)


static const ffpars_arg fcachx_conf_args[] = {
	{ "directory",  FFPARS_TSTR | FFPARS_FREQUIRED,  FFPARS_DST(&fcachx_conf_dir) }
	, { "expiry",  FFPARS_TINT,  FFPARS_DSTOFF(fcachectx, def_expiry) }
	, { "max_data",  FFPARS_TSIZE | FFPARS_F64BIT | FFPARS_FNOTZERO,  FFPARS_DSTOFF(fcachectx, max_data) }
	, { "max_header",  FFPARS_TSIZE | FFPARS_F16BIT | FFPARS_FNOTZERO,  FFPARS_DSTOFF(fcachectx, max_hdr) }
	, { "read_ahead",  FFPARS_TSIZE | FFPARS_FNOTZERO,  FFPARS_DSTOFF(fcachectx, read_ahead) }
	, { "buffer_size",  FFPARS_TSIZE,  FFPARS_DSTOFF(fcachectx, bufsize) }
	, { "mem",  FFPARS_TOBJ,  FFPARS_DST(&fcach_conf_mem) }
};


/** Error strings for enum FSV_CACH_E. */
static const char *const cach_serr[] = {
	""
	, "system"
	, "already exists"
	, "not found"
	, "key hash collision"
	, "items number limit"
	, "memory limit"
	, "size limit"
	, "locked"
};

static const char * fcach_errstr(int code)
{
	FF_ASSERT(code < FFCNT(cach_serr));
	return cach_serr[code];
}


static int fcachx_conf_dir(ffparser_schem *ps, fcachectx *cx, const ffstr *v)
{
	cx->dir.ptr = fcachm->core->getpath(NULL, &cx->dir.len, v->ptr, v->len);
	if (cx->dir.ptr == NULL)
		return FFPARS_EBADVAL;
	return 0;
}

static int fcach_conf_mem(ffparser_schem *ps, fcachectx *cx, ffpars_ctx *confctx)
{
	const fsv_modinfo *m = fcachm->core->findmod(FFSTR("cache.mem"));
	if (m == NULL)
		return FFPARS_EBADVAL;

	cx->mca = m->f->iface("cache");
	if (cx->mca == NULL)
		return FFPARS_EBADVAL;

	cx->mcx = cx->mca->newctx(confctx, &fsv_fcach_mem_cb, 0);
	if (cx->mcx == NULL)
		return FFPARS_EBADVAL;
	return 0;
}


static void * fcachm_create(const fsv_core *core, ffpars_ctx *confctx, fsv_modinfo *m)
{
	const fsvcore_config *conf = core->conf();

	fcachm = ffmem_tcalloc1(fcachemodule);
	if (fcachm == NULL)
		return NULL;

	fflist_init(&fcachm->ctxs);
	fcachm->core = core;
	fcachm->logctx = conf->logctx;

	ffpars_setargs(confctx, fcachm, NULL, 0);
	return fcachm;
}

static void fcachx_fin(fcachectx *cx)
{
	ffmem_free(cx);
}

static void fcachm_destroy(void)
{
	FFLIST_ENUMSAFE(&fcachm->ctxs, fcachx_fin, fcachectx, sib);
	ffmem_free(fcachm);
	fcachm = NULL;
}

static int fcachm_sig(int sig)
{
	return 0;
}

static const void * fcachm_iface(const char *name)
{
	if (0 == ffsz_cmp(name, "file-cache"))
		return &fsv_cach_iface;
	return NULL;
}


static void fcach_init(fcache *c, fcachectx *cx)
{
	c->fd = FF_BADFD;
	c->cx = cx;
}

// cache-dir/12/12345678
static int fcach_getfn(fcache *c, uint *hash, ffstr *fn)
{
	size_t len = c->cx->dir.len + FFSLEN("/00/00000000") + 1;
	fn->ptr = ffmem_alloc(len);
	if (fn->ptr == NULL)
		return -1;

	fn->len = ffs_fmt(fn->ptr, fn->ptr + len, "%S/%02xu/%08xu%Z"
		, &c->cx->dir, (hash[0] >> 8*3), hash[0]) - 1;
	return 0;
}

static int fcach_parsehdr(fcache *c, fffd fd, fsv_logctx *logctx)
{
	fcache_hdr tmphdr;
	fffd hmap;

	if (sizeof(fcache_hdr) != fffile_read(fd, &tmphdr, sizeof(fcache_hdr))) {
		syserrlog(logctx, "%e", FFERR_READ);
		return -1;
	}

	hmap = ffmap_create(fd, 0, FFMAP_PAGERW);
	if (hmap == 0) {
		syserrlog(logctx, "%e", FFERR_FMAP);
		return -1;
	}

	c->hdr.len = tmphdr.fdoff;
	c->hdr.ptr = ffmap_open(hmap, 0, c->hdr.len, PROT_READ | PROT_WRITE, MAP_SHARED);
	if (c->hdr.ptr == NULL) {
		syserrlog(logctx, "%e", FFERR_FMAP);
		ffmap_close(hmap);
		return -1;
	}
	ffmap_close(hmap);

	c->h = (fcache_hdr*)c->hdr.ptr;

	if (c->h->flags != HDR_1) {
		errlog(logctx, "invalid file");
		return -1;
	}

	if (sizeof(fcache_hdr) + c->h->keylen + c->h->uhdr_len > c->hdr.len) {
		errlog(logctx, "corrupted file");
		return -1;
	}

	return 0;
}

static int fcach_writehdr(fcache *c, fffd fd, fsv_fcacheitem *ca)
{
	fffd hmap;

	c->hdr.len = sizeof(fcache_hdr) + ca->keylen + ca->hdrlen;
	hmap = ffmap_create(fd, 0, FFMAP_PAGERW);
	if (hmap == 0) {
		return 1;
	}

	c->hdr.ptr = ffmap_open(hmap, 0, c->hdr.len, PROT_READ | PROT_WRITE, MAP_SHARED);
	ffmap_close(hmap);
	if (c->hdr.ptr == NULL) {
		return 1;
	}

	c->h = (fcache_hdr*)c->hdr.ptr;
	c->h->flags = HDR_INCOMPLETE;
	fcach_setexpire(c, ca->expire);
	c->h->creat_tm = fcachm->core->fsv_gettime().s;

	ffmemcpy(c->h->key, ca->key, ca->keylen);
	c->h->keylen = (ushort)ca->keylen;

	c->h->uhdr_len = (ushort)ca->hdrlen;
	c->h->fdoff = sizeof(fcache_hdr) + (ushort)ca->keylen + (ushort)ca->hdrlen;
	ffmemcpy(c->hdr.ptr + sizeof(fcache_hdr) + ca->keylen, ca->hdr, ca->hdrlen);
	return 0;
}

static void fcach_fill(fcache *c, fsv_fcacheitem *ca)
{
	ca->id = (fsv_cacheitem_id*)c;
	ca->hdr = c->hdr.ptr + sizeof(fcache_hdr) + c->h->keylen;
	ca->hdrlen = c->h->uhdr_len;
	ca->expire = c->h->expire_tm;
	ca->cretm = c->h->creat_tm;

	ca->len = c->size;
	ca->data = NULL;
	ca->fdoff = c->h->fdoff;
	ca->fd = c->fd;
}

/* Note: there are up to 3 calls to fffile_write(). */
static int fcach_write(fcache *c, const char *data, size_t len, fsv_logctx *logctx, int fin)
{
	ffstr s;
	const char *end = data + len;

	for (;;) {
		data += ffbuf_add(&c->buf, data, end - data, &s);
		if (s.len == 0)
			break; //some data is buffered

		if (s.len != fffile_write(c->fd, s.ptr, s.len))
			return 1;

		dbglog(logctx, "written +%L bytes", s.len);
	}

	c->size += len;

	if (fin && 0 != fcach_finstore(c, logctx))
		return 1;

	{
	fsv_fcacheitem ca;
	fsv_fcache_init(&ca);
	fcach_fill(c, &ca);
	c->cx->cb->onwrite(c->userptr, &ca, 0);
	}

	return 0;
}

/** Finalize a stored file.
Note: the file is NOT re-opened in read-only mode. */
static int fcach_finstore(fcache *c, fsv_logctx *logctx)
{
	if (c->buf.len != 0) {
		if (c->buf.len != fffile_write(c->fd, c->buf.ptr, c->buf.len))
			return 1;
		dbglog(logctx, "written +%L bytes", c->buf.len);
	}
	ffarr_free(&c->buf);

	fffile_seek(c->fd, c->h->fdoff, SEEK_SET);
	c->h->flags = HDR_1;
	c->created = 0;

	fcach_finfile(c, logctx);
	return 0;
}

static void fcach_finfile(fcache *c, fsv_logctx *logctx)
{
	if (c->cx->read_ahead != 0) {
		if (0 != fffile_readahead(c->fd, c->cx->read_ahead))
			syserrlog(logctx, "%s", "file readahead");
	}

	if (c->cx->mcx != NULL)
		fcach_mem_store(c, logctx);
}

static void fcach_rm(fcache *c)
{
	ffstr fn = {0};
	if (0 != fcach_getfn(c, c->hash, &fn)) {
		syserrlog(fcachm->logctx, "%e", FFERR_BUFALOC);
		return;
	}

	if (0 != fffile_rm(fn.ptr))
		syserrlog(fcachm->logctx, "%e: %s", FFERR_FDEL, fn.ptr); //note: the file might be already deleted
	else
		dbglog(fcachm->logctx, "deleted file %s", fn.ptr);

	ffstr_free(&fn);
}

static void fcach_unlink(fcache *c)
{
#ifdef FF_UNIX
	fcach_rm(c);

#else
	c->h->flags |= HDR_UNLINKED;
#endif
}

static void fcach_free(fcache *c)
{
#ifdef FF_WIN
	ffbool del_files = 0;
#endif

	if (c->fd != FF_BADFD && 0 != fffile_close(c->fd))
		syserrlog(fcachm->logctx, "%e", FFERR_FCLOSE);

	if (c->hdr.ptr != NULL) {
#ifdef FF_WIN
		if (c->h->flags & HDR_UNLINKED)
			del_files = 1;
#endif
		ffmap_unmap(c->hdr.ptr, c->hdr.len);
	}

#ifdef FF_WIN
	if (del_files && !c->no_remove)
		fcach_rm(c);
#endif

	ffarr_free(&c->buf);
	ffmem_free(c);
}


static int fcach_mem_fetch(fcachectx *cx, fsv_fcacheitem *fca, fcache **c, fsv_logctx *logctx)
{
	int e;
	fsv_cacheitem ca;
	fsv_cache_init(&ca);
	ca.logctx = logctx;
	ca.key = fca->key;
	ca.keylen = fca->keylen;

	e = cx->mca->fetch(cx->mcx, &ca, 0);
	if (e == 0) {
		*c = *(fcache**)ca.data;
	}

	return e;
}

static int fcach_mem_store(fcache *c, fsv_logctx *logctx)
{
	fsv_cacheitem ca;
	fsv_cache_init(&ca);
	ca.logctx = logctx;
	ca.key = c->h->key;
	ca.keylen = c->h->keylen;
	ca.data = (void*)&c;
	ca.datalen = sizeof(fcache*);
	if (0 == c->cx->mca->store(c->cx->mcx, &ca, 0))
		c->memid = ca.id;
	return 0;
}

static int fcach_mem_unref(fcache *c, uint f, fsv_logctx *logctx)
{
	fsv_cacheitem ca;

	if (c->memid == NULL)
		return 1;

	fsv_cache_init(&ca);
	ca.logctx = logctx;
	ca.id = c->memid;
	c->cx->mca->unref(&ca, f);
	return 0;
}

/** Notification from cache.mem. */
static int fcach_mem_cb(fsv_cachectx *ctx, fsv_cacheitem *ca, int flags)
{
	fcache *c = *(fcache**)ca->data;

	if (flags == FSV_CACH_ONDELETE) {
		fcach_free(c);
	}

	return 0;
}


static fsv_cachectx * fcach_newctx(ffpars_ctx *a, const fsv_fcach_cb *cb, int flags)
{
	fcachectx *cx = ffmem_tcalloc1(fcachectx);
	if (cx == NULL)
		return NULL;

	fflist_ins(&fcachm->ctxs, &cx->sib);
	cx->cb = cb;
	cx->max_hdr = 64 * 1024 - 1;
	cx->max_data = 2 * 1024 * 1024 * 1024ULL;
	cx->def_expiry = 1 * 60 * 60;
	cx->bufsize = 4 * 1024;

	ffpars_setargs(a, cx, fcachx_conf_args, FFCNT(fcachx_conf_args));
	return (fsv_cachectx*)cx;
}

static int fcach_fetch(fsv_cachectx *_cx, fsv_fcacheitem *ca, int flags)
{
	fcache *c = NULL;
	fffd fd = FF_BADFD;
	ffstr fn = {0};
	int er, esys = 0;
	fsv_logctx *logctx = (ca->logctx != NULL) ? ca->logctx : fcachm->logctx;
	fcachectx *cx = (fcachectx*)_cx;

	if (cx->mcx != NULL) {
		er = fcach_mem_fetch(cx, ca, &c, logctx);
		if (er == 0)
			goto done;
		else if (er != FSV_CACH_ENOTFOUND)
			goto fail;
	}

	er = FSV_CACH_ESYS;

	if (KEYHASH_EMPTY(ca->hash))
		KEYHASH_SET(ca->hash, ca->key, ca->keylen, 0);

	c = ffmem_tcalloc1(fcache);
	if (c == NULL)
		return FSV_CACH_ESYS;
	fcach_init(c, cx);

	if (0 != fcach_getfn(c, ca->hash, &fn)) {
		esys = FFERR_BUFALOC;
		goto fail;
	}

	fd = fffile_open(fn.ptr, O_RDWR);
	if (fd == FF_BADFD) {
		if (fferr_nofile(fferr_last())) {
			er = FSV_CACH_ENOTFOUND;
			goto fail;
		}

		esys = FFERR_FOPEN;
		goto fail;
	}
	c->hash[0] = ca->hash[0];
	c->fd = fd;

	if (0 != fcach_parsehdr(c, fd, logctx)) {
		er = FSV_CACH_ENOTFOUND;
		goto fail;
	}

	if (c->h->keylen != ca->keylen
		|| 0 != ffs_cmp(c->h->key, ca->key, ca->keylen)) {
		er = FSV_CACH_ECOLL;
		goto fail;
	}

	c->size = fffile_size(fd) - c->h->fdoff;

	fcach_finfile(c, logctx);

done:
	dbglog(logctx, "fetch: \"%*s\"; age: %us; data size: %U; filename: %S"
		, (size_t)c->h->keylen, c->h->key, fcachm->core->fsv_gettime().s - c->h->creat_tm, c->size, &fn);

	fcach_fill(c, ca);
	ffstr_free(&fn);
	return FSV_CACH_OK;

fail:
	if (er == FSV_CACH_ENOTFOUND) {
		dbglog(logctx, "fetch: \"%*s\": %s"
			, ca->keylen, ca->key, fcach_errstr(er));

	} else {
		fsv_errlog(logctx, FSV_LOG_ERR, FCACH_MODNAME, NULL
			, ((er == FSV_CACH_ESYS) ? "fetch: \"%*s\": %s: %e: %E" : "fetch: \"%*s\": %s")
			, ca->keylen, ca->key, fcach_errstr(er), esys, fferr_last());
	}

	if (fd != FF_BADFD && 0 != fffile_close(fd))
		syserrlog(logctx, "%e", FFERR_FCLOSE);

	ffstr_free(&fn);
#ifdef FF_WIN
	c->no_remove = 1;
#endif
	fcach_free(c);
	return er;
}

static int fcach_store(fsv_cachectx *_cx, fsv_fcacheitem *ca, int flags)
{
	fcache *c = NULL;
	fffd fd = FF_BADFD;
	ffstr fn = {0};
	int er = FSV_CACH_ESYS, esys = 0;
	fsv_logctx *logctx = (ca->logctx != NULL) ? ca->logctx : fcachm->logctx;
	fcachectx *cx = (fcachectx*)_cx;

	if (ca->keylen > MAX_KEYLEN
		|| ca->hdrlen > cx->max_hdr
		|| ca->len > cx->max_data || ca->total_size > cx->max_data) {
		er = FSV_CACH_ESZLIMIT;
		goto fail;
	}

	if (KEYHASH_EMPTY(ca->hash))
		KEYHASH_SET(ca->hash, ca->key, ca->keylen, 0);

	c = ffmem_tcalloc1(fcache);
	if (c == NULL) {
		esys = FFERR_BUFALOC;
		goto fail;
	}
	fcach_init(c, (fcachectx*)cx);

	if (0 != fcach_getfn(c, ca->hash, &fn)) {
		esys = FFERR_BUFALOC;
		goto fail;
	}

	fd = fffile_open(fn.ptr, FFO_CREATENEW | O_RDWR);
	if (fd == FF_BADFD) {

		if (fferr_nofile(fferr_last())) {
			size_t last_slash = fn.len - sizeof(uint)*2 - FFSLEN("/");
			fn.ptr[last_slash] = '\0';
			if (0 != ffdir_rmake(fn.ptr, cx->dir.len + 1)) {
				esys = FFERR_FOPEN;
				goto fail;
			}
			fn.ptr[last_slash] = '/';

			fd = fffile_open(fn.ptr, FFO_CREATENEW | O_RDWR);
		}

		if (fd == FF_BADFD) {
			if (fferr_last() == EEXIST)
				er = FSV_CACH_EEXISTS;
			else
				esys = FFERR_FOPEN;
			goto fail;
		}
	}
	c->created = 1;
	c->hash[0] = ca->hash[0];
	c->fd = fd;
	c->userptr = ca->userptr;

	if (0 != fffile_trunc(fd, ca->total_size + sizeof(fcache_hdr) + ca->keylen + ca->hdrlen)) {
		esys = FFERR_FSEEK;
		goto fail;
	}

	if (0 != fcach_writehdr(c, fd, ca)) {
		esys = FFERR_FMAP;
		goto fail;
	}

	if (c->h->fdoff != fffile_seek(fd, c->h->fdoff, SEEK_SET)) {
		esys = FFERR_FSEEK;
		goto fail;
	}

	if (flags & FSV_FCACH_LOCK)
		c->locked = 1;

	dbglog(logctx, "store: \"%*s\"; max-age: %ds; data size: %U; filename: %S"
		, (size_t)c->h->keylen, c->h->key, c->h->expire_tm - fcachm->core->fsv_gettime().s, ca->len, &fn);
	ffstr_free(&fn);

	if (cx->bufsize != 0 && NULL == ffarr_alloc(&c->buf, cx->bufsize)) {
		esys = FFERR_BUFALOC;
		goto fail;
	}

	if (0 != fcach_write(c, ca->data, ca->len, logctx, (flags & FSV_FCACH_LOCK) ? 0 : 1)) {
		esys = FFERR_WRITE;
		goto fail;
	}

	return FSV_CACH_OK;

fail:
	fsv_errlog(logctx, FSV_LOG_ERR, FCACH_MODNAME, NULL
		, ((er != FSV_CACH_ESYS) ? "store: \"%*s\": %s" : "store: \"%*s\": %s: %e: %E")
		, ca->keylen, ca->key, fcach_errstr(er), esys, fferr_last());

	if (fd != FF_BADFD && 0 != fffile_close(fd))
		syserrlog(fcachm->logctx, "%e", FFERR_FCLOSE);

	ffstr_free(&fn);
	if (c != NULL) {
		if (c->created)
			fcach_unlink(c);
		fcach_free(c);
	}
	return er;
}

static int fcach_update(fsv_fcacheitem *ca, int flags)
{
	fcache *c = (fcache*)ca->id;
	int er = FSV_CACH_ESYS, esys = 0;
	fsv_logctx *logctx = (ca->logctx != NULL) ? ca->logctx : fcachm->logctx;

	if (!(flags & (FSV_FCACH_APPEND | FSV_FCACH_REFRESH | FSV_FCACH_UNLOCK))) {
		//overwrite existing data

		fcachectx *cx = c->cx;
		fcach_unref(ca, FSV_FCACH_UNLINK);
		return fcach_store((fsv_cachectx*)cx, ca, flags);
	}

	if (flags & (FSV_FCACH_APPEND | FSV_FCACH_UNLOCK)) {

		if (!c->locked) {
			er = FSV_CACH_ELOCKED; //the item must be exclusively owned by the caller
			goto fail;
		}

		if ((flags & FSV_FCACH_APPEND)
			&& (ca->len > c->cx->max_data || c->size + ca->len > c->cx->max_data)) {
			er = FSV_CACH_ESZLIMIT;
			goto fail;
		}

		if (flags & FSV_FCACH_UNLOCK)
			c->locked = 0;

		dbglog(logctx, "update: \"%*s\"; data size: %U"
			, (size_t)c->h->keylen, c->h->key, c->size + ca->len);

		if (0 != fcach_write(c, ca->data, ca->len, logctx, (flags & FSV_FCACH_UNLOCK) ? 1 : 0)) {
			esys = FFERR_WRITE;
			goto fail;
		}
		return FSV_CACH_OK;
	}

	if (flags & FSV_FCACH_REFRESH)
		fcach_setexpire(c, ca->expire);

	dbglog(logctx, "update: \"%*s\"; data size: %U"
		, (size_t)c->h->keylen, c->h->key, c->size);

	fcach_fill(c, ca);
	return FSV_CACH_OK;

fail:
	fsv_errlog(logctx, FSV_LOG_ERR, FCACH_MODNAME, NULL
		, ((er != FSV_CACH_ESYS) ? "update: \"%*s\": %s" : "update: \"%*s\": %s: %e: %E")
		, ca->keylen, ca->key, fcach_errstr(er), esys, fferr_last());

	return er;
}

static int fcach_unref(fsv_fcacheitem *ca, int flags)
{
	fcache *c = (fcache*)ca->id;
	fsv_logctx *logctx = (ca->logctx != NULL) ? ca->logctx : fcachm->logctx;

	if (c->locked) {
		if (0 != fcach_finstore(c, logctx))
			flags |= FSV_FCACH_UNLINK;
	}

	if (flags & FSV_FCACH_UNLINK)
		fcach_unlink(c);

	if (c->cx->mcx != NULL
		&& 0 == fcach_mem_unref(c, (flags & FSV_FCACH_UNLINK) ? FSV_CACH_UNLINK : 0, logctx))
		return FSV_CACH_OK;

	dbglog(logctx, "unref: \"%*s\"", (size_t)c->h->keylen, c->h->key);

	fcach_free(c);
	return FSV_CACH_OK;
}

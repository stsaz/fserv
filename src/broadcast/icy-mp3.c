/** Generate continuous stream from local mp3 files.
Copyright 2014 Simon Zolin.
*/

#include <broadcast/brdcast.h>

#include <FF/audio/mpeg.h>
#include <FF/mtags/id3.h>
#include <FF/data/m3u.h>
#include <FF/sys/filemap.h>
#include <FFOS/file.h>
#include <FFOS/error.h>


typedef struct icymp3 {
	bcastctx *bx;
	fsv_logctx *lx;

	//conf:
	ffstr loadList;
	uint64 first_track;

	uint64 curTrackNo;
	char curfn[FF_MAXPATH];
	fffd listfd;
	fftime listTime;
	uint64 listSize;
	fffilemap listSf;

	fffd mediaFd;
	uint64 mediaSz;
	uint64 mediaOff;
	fffilemap mediaSf[4];
	uint iwbuf;
	// ffstr bufs[10];
} icymp3;

enum {
	eBadFile = -1
	, eInvMp3 = -2
	, eNoSpace = -3
	, eInvList = -4
	, eInvBr = -5
};

static const char *const serrs[] = {
	""
	, "bad file"
	, "invalid mp3"
	, "no space"
	, "invalid listing"
	, "invalid bitrate"
};

static const char * geterr(int e)
{
	FF_ASSERT(e <= 0 && -e < FFCNT(serrs));
	return serrs[-e];
}

static void printErr(icymp3 *mp, int e)
{
	FF_ASSERT(e != 0);
	if (e > 0)
		syserrlog(mp->lx, FSV_LOG_ERR, "%e", (int)e);
	else
		errlog(mp->lx, FSV_LOG_ERR, "%s", geterr(e));
}


// CONFIG
static int icy3_conf_load(ffparser_schem *ps, icymp3 *mp, const ffstr *val);

// BROADCAST IFACE
static ffbool icy3_start(void *prov);
static void icy3_stop(void *prov);
static void icy3_addhdrs(void *prov, ffhttp_cook *cook);
static int icy3_getbuf(void *prov, size_t ibuf, ffstr *buf);
static void icy3_played(void *prov, uint iplayed);
static void icy3_fin(void *prov);
static const bcast_prov_iface icy3_iface = {
	&icy3_start, &icy3_stop, &icy3_addhdrs, &icy3_getbuf, &icy3_played, &icy3_fin
};

static int icy3_loadNextFile(icymp3 *mp);
static int icy3_loadNextFiles(icymp3 *mp);

static ffbool icy3_isFilled(void *prov, size_t ibuf) {
	const icymp3 *mp = prov;
	return mp->mediaSf[ibuf].fd != FF_BADFD;
}

static int icy3_getbuf(void *prov, size_t ibuf, ffstr *buf)
{
	icymp3 *mp = prov;
	if (!icy3_isFilled(prov, ibuf))
		return -1;

	fffile_mapbuf(&mp->mediaSf[ibuf], buf);
	return (ibuf == mp->iwbuf) ? 1 : 0;
}


static const ffpars_arg icy3_conf_args[] = {
	{ "load_list",  FFPARS_TSTR,  FFPARS_DST(&icy3_conf_load) }
	, { "first_track",  FFPARS_TINT | FFPARS_F64BIT | FFPARS_FNOTZERO,  FFPARS_DSTOFF(icymp3, first_track) }
};

static int icy3_conf_load(ffparser_schem *ps, icymp3 *mp, const ffstr *val)
{
	mp->loadList.ptr = bcastm->core->getpath(NULL, &mp->loadList.len, val->ptr, val->len);
	if (mp->loadList.ptr == NULL)
		return FFPARS_EBADVAL;
	return 0;
}


int icy3_conf_init(bcastctx *bx, ffpars_ctx *ctx)
{
	icymp3 *mp = ffmem_tcalloc1(icymp3);
	if (mp == NULL)
		return FFPARS_ESYS;

	mp->bx = bx;
	mp->lx = bx->lx;
	mp->first_track = 1;

	bx->prov = mp;
	bx->nbufs = FFCNT(mp->mediaSf);
	bx->iface = &icy3_iface;

	ffpars_setargs(ctx, mp, icy3_conf_args, FFCNT(icy3_conf_args));
	return 0;
}

static void icy3_fin(void *prov)
{
	icymp3 *mp = prov;
	ffstr_free(&mp->loadList);
	ffmem_free(mp);
}


static void icy3_addhdrs(void *prov, ffhttp_cook *cook)
{
}

/** map new file blocks
*/
static int icy3_moreData(icymp3 *mp)
{
	bcastctx *bx = mp->bx;
	int e = 0;

	for (;;) {
		if (icy3_isFilled(mp, mp->iwbuf))
			break;
		if (mp->mediaSz == 0) {
			FF_SAFECLOSE(mp->mediaFd, FF_BADFD, (void)fffile_close);
			e = icy3_loadNextFiles(mp);
			if (e != 0)
				goto fail;

		} else {
			ffstr buf;
			fffilemap *sf = &mp->mediaSf[mp->iwbuf];
			fffile_mapset(sf, bx->buf_size, mp->mediaFd, mp->mediaOff, mp->mediaSz);
			if (0 != fffile_mapbuf(sf, &buf)) {
				e = FFERR_FMAP;
				goto fail;
			}
			mp->mediaOff += sf->mapsz;
			mp->mediaSz -= sf->mapsz;

			dbglog(mp->lx, FSV_LOG_DBGFLOW, "opened buffer #%u at %xU [%LK]"
				, mp->iwbuf, (int64)sf->foff, (size_t)buf.len / 1024);

			if (mp->mediaSz < sizeof(ffid31)) {
				const ffid31 *tag = (ffid31*)(buf.ptr + buf.len - (sizeof(ffid31) - mp->mediaSz));
				if (ffid31_valid(tag)) {
					mp->mediaSz = 0;
					sf->fsize = (char*)tag - buf.ptr;
				}
			}

			mp->iwbuf = int_cycleinc(mp->iwbuf, bx->nbufs);
		}
	}

	bcast_update(mp->bx);
	return 0;

fail:
	return e;
}

static void icy3_played(void *prov, uint iplayed)
{
	icymp3 *mp = prov;
	int e;

	fffile_mapclose(&mp->mediaSf[iplayed]);

	e = icy3_moreData(mp);
	if (e != 0) {
		printErr(mp, e);
		icy3_stop(mp);
		return;
	}
}

static int icy3_parseFile(icymp3 *mp, fffilemap *sf)
{
	bcastctx *bx = mp->bx;
	ffmpg_hdr *fr;
	ffstr buf = {0};
	ffmpg_hdr h;
	ffid3 id3;
	size_t nnmap = 0;
	ffstr3 val = {0}, artist = {0}, title = {0};
	fffile_mapset(sf, bx->buf_size, mp->mediaFd, 0, mp->mediaSz);
	ffid3_parseinit(&id3);

	for (;;) {
		size_t len = buf.len;
		int r = ffid3_parse(&id3, buf.ptr, &len);
		ffstr_shift(&buf, len);

		switch (r) {
		case FFID3_RNO:
		case FFID3_RDONE:
			ffid3_parsefin(&id3);
			goto tagdone;
			// break;

		case FFID3_RHDR:
			continue;

		case FFID3_RERR:
			ffarr_free(&artist);
			ffarr_free(&title);
			ffid3_parsefin(&id3);
			return eInvMp3;

		case FFID3_RMORE:
			fffile_mapshift(sf, nnmap);
			if (0 != fffile_mapbuf(sf, &buf)) {
				ffarr_free(&artist);
				ffarr_free(&title);
				ffid3_parsefin(&id3);
				return FFERR_FMAP;
			}
			nnmap = buf.len;

			mp->mediaOff += sf->mapsz;
			mp->mediaSz -= sf->mapsz;
			dbglog(mp->lx, FSV_LOG_DBGFLOW, "opened buffer #%d at %xU", (int)mp->iwbuf, (int64)sf->foff);
			break;

		case FFID3_RFRAME:
			if (bx->icy_meta_int == 0)
				break;

			switch (id3.frame) {
			case FFMMTAG_TITLE:
			case FFMMTAG_ARTIST:
				id3.flags |= FFID3_FWHOLE;
				break;

			default:
				id3.flags &= ~FFID3_FWHOLE;
			}
			break;

		case FFID3_RDATA:
			if (!(id3.flags & FFID3_FWHOLE))
				break;

			if (-1 == ffid3_getdata(id3.frame, id3.data.ptr, id3.data.len, id3.txtenc, 0, &val))
				break;

			switch (id3.frame) {

			case FFMMTAG_TITLE:
				ffarr_copy(&title, val.ptr, val.len);
				break;

			case FFMMTAG_ARTIST:
				ffarr_copy(&artist, val.ptr, val.len);
				break;
			}
			ffarr_free(&val);
			break;

		default:
			FF_ASSERT(0);
		}
	}

	// skip ID3v2 tag
	/*if (0 == fffile_mapshift(sf, ffmin(buf.len, tag2size)))
		return FFERR_FMAP;
	if ((uint)tag2size < buf.len) {
		// shift the buffer pointer and size to the potential mpeg header
		buf.len -= tag2size;
		buf.ptr += tag2size;
		break;
	}*/

tagdone:
	{
	char s_both[4096];
	size_t nboth = ffs_fmt(s_both, s_both + sizeof(s_both), "%S - %S", &artist, &title);
	bcast_metaupdate(bx, s_both, nboth);
	ffarr_free(&artist);
	ffarr_free(&title);
	}

	if (buf.len >= sizeof(ffmpg_hdr))
		h = *(ffmpg_hdr*)buf.ptr;
	else {
		// handle situation, when the mpeg header is split between two file mappings

		//memcpy(&h, buf.ptr, buf.len);
		fffile_mapshift(sf, nnmap);
		if (0 != fffile_mapbuf(sf, &buf))
			return FFERR_FMAP;

		mp->mediaOff += sf->mapsz;
		mp->mediaSz -= sf->mapsz;
		dbglog(mp->lx, FSV_LOG_DBGFLOW, "opened buffer #%d at %xU", (int)mp->iwbuf, (int64)sf->foff);
		//memcpy((char*)&h + buf.len, m2, sizeof(ffmpg_hdr) - buf.len);
	}

	fr = ffmpg_findframe(buf.ptr, buf.len, 2);

	if (fr == NULL) {
		errlog(mp->lx, FSV_LOG_ERR, "mpeg frame not found");
		return eInvMp3; //invalid mp3
	}
	h = *fr;
	if (h.ver != FFMPG_1 || h.layer != FFMPG_L3) {
		errlog(mp->lx, FSV_LOG_ERR, "the file is not mpeg1 layer3");
		return eInvMp3;
	}

	dbglog(mp->lx, FSV_LOG_DBGFLOW, "the first mpeg header is found in buffer #%u at pos %U"
		, (int)mp->iwbuf, (int64)sf->foff);

	{
		uint br;
		br = ffmpg_hdr_bitrate(&h);
		if (br / 8 != bx->byterate && bx->byterate != 0) {
			errlog(mp->lx, FSV_LOG_ERR, "the file's bitrate %d doesn't match the stream bitrate %d"
				, (int)br / 1000, (int)mm_tokbps(bx->byterate));
			return eInvBr;
		}
		if (bx->byterate == 0)
			bx->byterate = br / 8;
	}

	mp->iwbuf = int_cycleinc(mp->iwbuf, bx->nbufs);
	return 0;
}


/// extract the next file name from the file list.  move to the beginning when the end is reached
static int icy3_getNextFile(icymp3 *mp, char *dst, size_t *dstsz)
{
	fffilemap *sf = &mp->listSf;
	ffm3u p;
	ffbool spin = 0;
	int r;

	ffm3u_init(&p);

	for (;;) {
		ffstr buf;
		size_t n;
		ffbool fin = 0;

		if (0 != fffile_mapbuf(sf, &buf)) {
			r = FFERR_FMAP;
			goto fail;
		}
		if (sf->foff == 0)
			mp->curTrackNo = 0; //reopened the file from the beginning

		// n = ffm3u_parse(&p, buf.ptr, buf.len, (const char**)&s.ptr, &s.len);
		n = buf.len;
		r = ffm3u_parse(&p, &buf);
		n -= buf.len;

		if (r == FFPARS_MORE)
		{}
		else if (ffpars_iserr(r)) {
			r = eInvList;
			goto fail;

		} else {

			switch (r) {
			case FFM3U_URL:
				if (p.val.len > *dstsz)
					break;
				ffmemcpy(dst, p.val.ptr, p.val.len);
				*dstsz = p.val.len;
				fin = 1;
				break;
			}
		}

		if (0 == fffile_mapshift(sf, n)) {
			if (spin) {
				r = eInvList; // no useful lines in the file
				goto fail;
			}
			spin = 1;
			fffile_mapset(sf, bcastm->pagesize, mp->listfd, 0, mp->listSize);
		}

		if (fin)
			break;
	}

	mp->curTrackNo++;
	return 0;//ok

fail:
	ffm3u_close(&p);
	return r;
}

/** Map into memory next file in the list
Return 0 on success */
int icy3_loadNextFile(icymp3 *mp)
{
	int e;
	fffd fd;
	char *dst;
	size_t dstsz;
	dst = mp->curfn;
	dstsz = FFCNT(mp->curfn) - 1;

	e = icy3_getNextFile(mp, dst, &dstsz);
	if (e != 0)
		return e; //fatal error

	mp->curfn[dstsz] = '\0';

	fd = fffile_open(mp->curfn, FFO_NONBLOCK | FFO_RDONLY);
	if (fd == FF_BADFD) {
		syserrlog(mp->lx, FSV_LOG_WARN, "%e: %s", FFERR_FOPEN, mp->curfn);
		return eBadFile; // bad file in the list
	}
	mp->mediaFd = fd;
	mp->mediaSz = fffile_size(fd);
	mp->mediaOff = 0;
	fffile_mapinit(&mp->mediaSf[mp->iwbuf]);
	e = icy3_parseFile(mp, &mp->mediaSf[mp->iwbuf]);
	if (e != 0) {
		if (e > 0)
			syserrlog(mp->lx, FSV_LOG_WARN, "%e: %s", (int)e, mp->curfn);
		else
			errlog(mp->lx, FSV_LOG_WARN, "%s: %s", geterr(e), mp->curfn);
		mp->mediaFd = FF_BADFD;
		mp->mediaSz = 0;
		fffile_mapclose(&mp->mediaSf[mp->iwbuf]);
		(void)fffile_close(fd);
		return eBadFile;
	}

	return 0;
}

int icy3_loadNextFiles(icymp3 *mp)
{
	bcastctx *bx = mp->bx;
	int e = 0;
	int64 curTrk = mp->curTrackNo;
	for (;;) {
		e = icy3_loadNextFile(mp);
		if (e != eBadFile)
			break;
		if (curTrk == mp->curTrackNo) {
			// stop looping when no valid files are found within the whole listing
			return eInvList;
		}
	}

	if (e == 0) {
		uint64 len = mp->mediaSf[mp->iwbuf].fsize / bx->byterate;
		errlog(mp->lx, FSV_LOG_INFO, "opened file #%U: \"%s\".  %U KBytes.  [%02u:%02u]"
			, (int64)mp->curTrackNo, mp->curfn, (int64)mp->mediaSz / 1024, (int)len / 60, (int)len % 60);
	}

	return e;
}

/// Start iterating on local files specified in the list
ffbool icy3_start(void *prov)
{
	icymp3 *mp = prov;
	fffd fd;
	int e = 0;
	uint i;
	bcastctx *bx = mp->bx;

	mp->mediaFd = mp->listfd = FF_BADFD;
	fffile_mapinit(&mp->listSf);
	for (i = 0;  i < FFCNT(mp->mediaSf);  ++i) {
		fffile_mapinit(&mp->mediaSf[i]);
	}

	bx->buf_size = ff_align_ceil2(bx->buf_size_conf, bcastm->pagesize);
	bx->buf_size = ffmax(bx->buf_size, bcastm->pagesize);

	for (i = 0; i < FFCNT(mp->mediaSf); ++i) {
		fffile_mapinit(&mp->mediaSf[i]);
	}

	fd = fffile_open(mp->loadList.ptr, O_RDONLY);
	if (fd == FF_BADFD) {
		syserrlog(mp->lx, FSV_LOG_ERR, "%e: %s", FFERR_FOPEN, mp->loadList.ptr);
		goto fail;
	}
	mp->listfd = fd;
	{
		fffileinfo fi;
		if (0 != fffile_info(fd, &fi))
			goto fail;
		mp->listSize = fffile_infosize(&fi);
		mp->listTime = fffile_infomtime(&fi);
	}
	fffile_mapset(&mp->listSf, bcastm->pagesize, fd, 0, mp->listSize);

	{
		uint64 i;
		char fnu[1024];
		char *dst = fnu;
		for (i = 1; i < mp->first_track; ++i) {
			size_t dstsz = sizeof(fnu);
			e = icy3_getNextFile(mp, dst, &dstsz);
			if (e != 0)
				goto fail;
		}
	}

	bx->status = ST_BUFFERING;
	e = icy3_loadNextFiles(mp);
	if (e != 0)
		goto fail;

	e = icy3_moreData(mp); //preload data in buffers
	if (e != 0)
		goto fail;
	return 1;

fail:
	if (e != 0)
		printErr(mp, e);
	icy3_stop(mp);
	return 0;
}

static void icy3_stop(void *prov)
{
	icymp3 *mp = prov;
	uint i;

	mp->first_track = mp->curTrackNo;

	mp->curfn[0] = '\0';
	fffile_mapclose(&mp->listSf);
	FF_SAFECLOSE(mp->listfd, FF_BADFD, (void)fffile_close);
	for (i = 0; i < FFCNT(mp->mediaSf); ++i) {
		fffile_mapclose(&mp->mediaSf[i]);
	}
	FF_SAFECLOSE(mp->mediaFd, FF_BADFD, (void)fffile_close);

	bcastx_reset(mp->bx);

	{
	icymp3 mp2 = *mp;
	ffmem_tzero(mp);
	mp->bx = mp2.bx;
	mp->lx = mp2.lx;
	mp->loadList = mp2.loadList;
	mp->first_track = mp2.first_track;
	}
}

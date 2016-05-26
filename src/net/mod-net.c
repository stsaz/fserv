/**
Copyright 2014 Simon Zolin.
*/

#include <core/fserv.h>
#include <FFOS/process.h>


static void oninit(void)
{
	ffmem_init();
	if (0 != ffskt_init(FFSKT_WSAFUNCS))
		ffps_exit(1);
}
FFDL_ONINIT(oninit, NULL)


FF_EXTN const fsv_mod fsv_lsn_mod;
FF_EXTN const fsv_mod fsv_conn_mod;
FF_EXTN const fsv_mod fsv_reslv_mod;

FF_EXTN FF_EXP const fsv_mod * fsv_getmod(const char *name)
{
	if (0 == ffsz_cmp(name, "listen"))
		return &fsv_lsn_mod;
	else if (0 == ffsz_cmp(name, "connect"))
		return &fsv_conn_mod;
	else if (0 == ffsz_cmp(name, "resolve"))
		return &fsv_reslv_mod;
	return NULL;
}

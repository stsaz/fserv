/** Configure socket options.
Copyright 2014 Simon Zolin.
*/

#include <FFOS/socket.h>

enum FSV_SO_OPT {
	FSV_SO_TCPNODELAY = 1
};

typedef struct fsv_sktopt {
	uint flags;
	uint recvbuf
		, sendbuf;
	uint recvlowat;
} fsv_sktopt;

static FFINL void fsv_sktopt_init(fsv_sktopt *so)
{
	ffmem_tzero(so);
	so->flags = FSV_SO_TCPNODELAY;
}


static const ffpars_arg fsv_sktopt_conf[] = {
	{ "tcp_nodelay",  FFPARS_TBOOL | FFPARS_SETBIT(0),  FFPARS_DSTOFF(fsv_sktopt, flags) }
	, { "recv_buffer",  FFPARS_TSIZE,  FFPARS_DSTOFF(fsv_sktopt, recvbuf) }
	, { "send_buffer",  FFPARS_TSIZE,  FFPARS_DSTOFF(fsv_sktopt, sendbuf) }
	, { "recv_lowat",  FFPARS_TSIZE,  FFPARS_DSTOFF(fsv_sktopt, recvlowat) }
};

static const uint opts[] = { SO_RCVBUF, SO_SNDBUF, SO_RCVLOWAT };

#define OFF(member) FFOFF(fsv_sktopt, member)
static const uint offs[] = { OFF(recvbuf), OFF(sendbuf), OFF(recvlowat) };
#undef OFF

static FFINL ffbool fsv_sktopt_set(fsv_sktopt *so, ffskt sk)
{
	int i, er = 0;

	if (so->flags & FSV_SO_TCPNODELAY)
		er |= ffskt_setopt(sk, IPPROTO_TCP, TCP_NODELAY, 1);

	for (i = 0;  i != FFCNT(opts);  i++) {
		uint *u = (uint*) ((char*)so + offs[i]);
		if (*u != 0)
			er |= ffskt_setopt(sk, SOL_SOCKET, opts[i], *u);
	}

	return er == 0;
}

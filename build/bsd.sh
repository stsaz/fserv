gmake -j2  OS=bsd  ARCH=64  CFLAGS='-fpic'  LDFLAGS=''  FSV_LDFLAGS='' \
	CP='cp -v'  PACK='tar --uid=0 --gid=0 --numeric-owner -cJv' \
	$@

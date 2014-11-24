make -j4 -k  OS=win  OSTYPE=wint  LDFLAGS=-lws2_32  VISIBILITY=  PTHREAD= \
	SO=dll \
	LIBZSO=zlib1.dll  ZLIB='$(FF)/3pt/z/zlib1-win32.dll' \
	$1

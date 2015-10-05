# fserv v0.24 makefile

OS = linux

FSV_BIN = fserv
FSV_SRCDIR = ../src
RUNDIR := ../fserv
VER =

FFOS = ../../ffos
FFOS_OBJ_DIR = ./ff-obj

FF = ../../ff
FF_OBJ_DIR = $(FFOS_OBJ_DIR)


OSTYPE := unix
ifeq ($(OS),win)
OSTYPE := wint
endif

# set initial values for:
# . linux/bsd/windows
# . gcc
# . packaging: tar.xz/zip
ifeq ($(OSTYPE),unix)

TARGET := amd64
override CFLAGS += -fpic -DFF_OLDLIBC
override LDFLAGS += -lrt
SO := so
PACK_EXT := tar.xz

ifeq ($(OS),linux)

LD_LDL := -ldl
CP := cp -u -v -p
PACK := tar --owner=0 --group=0 --numeric-owner -cJv -f

else #bsd:

CP := cp -v
PACK := tar --uid=0 --gid=0 --numeric-owner -cJv -f

endif

else #windows:

TARGET := x64
LDFLAGS := -lws2_32 -L$(FF)/3pt/win-x64
SO := dll
CP := cp -u -v -p
PACK := zip -9 -r -v
PACK_EXT := zip

endif


C = gcc
LD = gcc
OPT = -O2
# -D_DEBUG

override CFLAGS += -c $(OPT) -g -Wall -Werror -pthread \
	-I$(FSV_SRCDIR) -I$(FF) -I$(FFOS) -I$(FF)/3pt \
	-ffunction-sections -fdata-sections  -fvisibility=hidden -fno-exceptions

override LDFLAGS += -pthread \
	-fvisibility=hidden \
	-Wl,-gc-sections

# 3-party libraries
ifeq ($(OSTYPE),unix)
ZLIB := -lz
SSL_LIBS := -lcrypto -lssl

else
SSL_LIBS := -lssleay32 -leay32
ZLIB := -lzlib1
endif

include ./makerules

strip-debug: all
	sh strip-debug.sh $(FSV_BIN) $(MOD_ALL)

install: all preinstall
ifeq ($(OSTYPE),unix)
	$(CP) fserv-exec-unix $(RUNDIR)/sbin/fserv
	$(CP) $(FSV_BIN) $(RUNDIR)/sbin/$(FSV_BIN)-bin

	chmod 755 $(RUNDIR)/sbin/fserv $(RUNDIR)/sbin/$(FSV_BIN)-bin
	chmod 644 $(RUNDIR)/mod/*.$(SO)

else #windows:
	$(CP) fserv-exec-win.cmd $(RUNDIR)/sbin/fserv.cmd
	$(CP) $(FSV_BIN) $(RUNDIR)/sbin/fserv-bin.exe
	$(CP) ./*_fserv.cmd $(RUNDIR)/

endif

package: all install
	cd .. \
		&&  rm -f fserv-$(VER)-$(OS)-$(TARGET).$(PACK_EXT) \
		&&  $(PACK) fserv-$(VER)-$(OS)-$(TARGET).$(PACK_EXT) ./fserv

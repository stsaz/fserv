# fserv v0.17 makefile

OSTYPE = unix
OS = linux
FSV_BIN = fserv
SO = so
FSV_SRCDIR = ../src
ARCH = 64
TARGET = amd64
RUNDIR=../run
VER =

FFOS = ../../ffos
FFOS_OBJ_DIR = ./ff-obj

FF = ../../ff
FF_OBJ_DIR = $(FFOS_OBJ_DIR)
ZLIB = $(FF)/3pt/z/libz-$(OS)$(ARCH).so.1.2.8
ZDLL = $(ZLIB)
LIBZSO = libz.so.1

CP = cp -u -v -p
PACK = tar --owner=0 --group=0 --numeric-owner -cJv

C = gcc
O = -o
LD = gcc
O_LD = -o
SHARED = -shared
OPT = -O2
DBG = -g
# -D_DEBUG

override CFLAGS += -c $(OPT) $(DBG) -Wall -Werror -pthread \
	-I$(FSV_SRCDIR) -I$(FF) -I$(FFOS) \
	-ffunction-sections -fdata-sections  -fvisibility=hidden -fno-exceptions \
	-DFF_OLDLIBC

override LDFLAGS += -lrt -pthread \
	-fvisibility=hidden \
	-Wl,-gc-sections

FSV_LDFLAGS = -ldl

FSV_EXOBJS = *.debug

include ./makerules

strip-debug: all
	sh strip-debug.sh $(FSV_BIN) $(MOD_ALL)

install: all preinstall
	$(CP) fserv-exec-unix $(RUNDIR)/sbin/fserv
	$(CP) $(FSV_BIN) $(RUNDIR)/sbin/$(FSV_BIN)-bin
	$(CP) $(FSV_SRCDIR)/../README.txt $(RUNDIR)/README

	chmod 755 $(RUNDIR)/sbin/fserv $(RUNDIR)/sbin/$(FSV_BIN)-bin
	chmod 644 $(RUNDIR)/mod/*.$(SO)

package: all install
	mv $(RUNDIR) ../fserv
	cd ..  &&  rm -f fserv-$(VER)-$(OS)-$(TARGET).tar.xz \
		&& $(PACK) -f fserv-$(VER)-$(OS)-$(TARGET).tar.xz ./fserv
	mv ../fserv $(RUNDIR)

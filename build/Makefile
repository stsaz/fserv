# fserv v0.16 makefile

OSTYPE = unix
OS = linux
FSV_BIN = fserv
SO = so
FSV_SRCDIR = ../src
ARCH = 64
RUNDIR=../run

FSRV = ../../firmsrv

FFOS = ../../ffos
FFOS_OBJ_DIR = ./ff-obj

FF = ../../ff
FF_OBJ_DIR = $(FFOS_OBJ_DIR)
ZLIB = $(FF)/3pt/z/libz-$(OS)$(ARCH).so.1.2.8

C = gcc
O = -o
LD = gcc
O_LD = -o
SHARED = -shared

DBG = -g
# -D_DEBUG

override CFLAGS += -c $(DBG) -Wall -Werror -pthread \
	-I$(FSV_SRCDIR) -I$(FF) -I$(FFOS) \
	-ffunction-sections -fdata-sections  -fvisibility=hidden -fno-exceptions -fpic \
	-DFF_OLDLIBC

override LDFLAGS += -lrt -pthread \
	-fvisibility=hidden \
	-Wl,-gc-sections

FSV_LDFLAGS = -ldl

FSV_EXOBJS = *.debug

include ./makerules

install: all
	cp -n fserv-exec-unix $(RUNDIR)/sbin/fserv && chmod ug+x $(RUNDIR)/sbin/fserv
	cp -f $(FSV_BIN) $(RUNDIR)/sbin/$(FSV_BIN).bin
	cp -f *.$(SO) $(RUNDIR)/mod/
	cp -n $(ZLIB) $(RUNDIR)/mod/libz.so.1

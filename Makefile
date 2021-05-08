# fserv v0.26 makefile

ROOT := ..
PROJDIR := $(ROOT)/fserv
FSV_SRCDIR := $(PROJDIR)/src
RUNDIR := ./fserv-0
VER =
OS :=
OPT := LTO3

FFBASE := $(ROOT)/ffbase
FFPACK := $(ROOT)/ffpack
FFOS := $(ROOT)/ffos
FF := $(ROOT)/ff
FF3PT := $(ROOT)/ff-3pt

include $(FFOS)/makeconf

ifeq ($(OS),win)
BIN := fserv.exe
else
BIN := fserv
endif

FF_OBJ_DIR := ./ff-obj
FFOS_CFLAGS := $(CFLAGS) -pthread
FF_CFLAGS := $(CFLAGS)
FF3PTLIB := $(FF3PT)-bin/$(OS)-$(ARCH)
FF3PT_CFLAGS := $(CFLAGS)

override CFLAGS += -Wall -Werror -Wno-stringop-overflow \
	-I$(FSV_SRCDIR) -I$(FF) -I$(FFPACK) -I$(FFOS) -I$(FFBASE) -I$(FF3PT)

override LDFLAGS += \
	-L$(FF3PTLIB) $(LD_LWS2_32)

# 3-party libraries
SSL_LIBS := -lcrypto -lssl

include $(PROJDIR)/makerules


package: install
	rm -f fserv-$(VER)-$(OS)-$(ARCH).$(PACK_EXT)
	$(PACK) fserv-$(VER)-$(OS)-$(ARCH).$(PACK_EXT) $(RUNDIR)
	$(PACK) fserv-$(VER)-$(OS)-$(ARCH)-debug.$(PACK_EXT) ./*.debug

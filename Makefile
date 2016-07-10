# fserv v0.26 makefile

BIN := fserv-bin
ROOT := ..
PROJDIR := $(ROOT)/fserv
FSV_SRCDIR := $(PROJDIR)/src
RUNDIR := ./fserv-0
VER =
OS :=
OPT := LTO

FFOS := $(ROOT)/ffos
FF := $(ROOT)/ff
FF3PT := $(ROOT)/ff-3pt

include $(FFOS)/makeconf

FF_OBJ_DIR := ./ff-obj
FF_CFLAGS := $(CFLAGS)
FF3PTLIB := $(FF3PT)/$(OS)-$(ARCH)
FF3PT_CFLAGS := $(CFLAGS)

override CFLAGS += -Wall -Werror \
	-I$(FSV_SRCDIR) -I$(FF) -I$(FFOS) -I$(FF3PT)

override LDFLAGS += \
	-L$(FF3PTLIB) $(LD_LWS2_32)

# 3-party libraries
ifneq ($(OS),win)
SSL_LIBS := -lcrypto -lssl

else
SSL_LIBS := -lssleay32 -leay32
endif

include $(PROJDIR)/makerules


package: install
	rm -f fserv-$(VER)-$(OS)-$(ARCH).$(PACK_EXT)
	$(PACK) fserv-$(VER)-$(OS)-$(ARCH).$(PACK_EXT) $(RUNDIR)
	$(PACK) fserv-$(VER)-$(OS)-$(ARCH)-debug.$(PACK_EXT) ./*.debug

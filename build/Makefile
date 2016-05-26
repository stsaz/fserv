# fserv v0.26 makefile

OS = linux

BIN := fserv-bin
PROJDIR := ..
FSV_SRCDIR := $(PROJDIR)/src
RUNDIR := ./fserv-0
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
override ALL_CFLAGS += -fpic
override LDFLAGS += -lrt
SO := so
PACK_EXT := tar.xz

ifeq ($(OS),linux)

override ALL_CFLAGS += -DFF_OLDLIBC
LD_LDL := -ldl
CP := cp -u -v --no-preserve=mode,ownership
PACK := tar --owner=0 --group=0 --numeric-owner -cJv -f

else #bsd:

CP := cp -v
PACK := tar --uid=0 --gid=0 --numeric-owner -cJv -f

endif

else #windows:

TARGET := x64
LDFLAGS := -lws2_32
SO := dll
CP := cp -u -v -p
PACK := zip -9 -r -v
PACK_EXT := zip

endif

FF3PTLIB := $(FF)-3pt/$(OS)-$(TARGET)


C = gcc
LD = gcc
OPT = -O2
# -D_DEBUG

override CFLAGS += $(ALL_CFLAGS) -c $(OPT) -g -Wall -Werror -pthread \
	-I$(FSV_SRCDIR) -I$(FF) -I$(FFOS) -I$(FF)-3pt \
	-ffunction-sections -fdata-sections  -fvisibility=hidden

override FF_CFLAGS += $(ALL_CFLAGS) $(OPT) -g \
	-ffunction-sections -fdata-sections  -fvisibility=hidden

override LDFLAGS += -pthread \
	-L$(FF3PTLIB) \
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

include $(PROJDIR)/build/makerules


%.debug: %
	objcopy --only-keep-debug $< $@
	strip $<
	objcopy --add-gnu-debuglink=$@ $<
	touch $@


package: install
	rm -f fserv-$(VER)-$(OS)-$(TARGET).$(PACK_EXT) \
		&&  $(PACK) fserv-$(VER)-$(OS)-$(TARGET).$(PACK_EXT) $(RUNDIR)
	$(PACK) fserv-$(VER)-$(OS)-$(TARGET)-debug.$(PACK_EXT) ./*.debug

PS5_HOST ?= ps5
PS5_PORT ?= 9021

ifdef PS5_PAYLOAD_SDK
    include $(PS5_PAYLOAD_SDK)/toolchain/prospero.mk
else
    $(error PS5_PAYLOAD_SDK is undefined)
endif

LOADER_OPT ?= -O2
CFLAGS     += -Wall -Werror
CPPFLAGS   += -Iinclude -I.

LDFLAGS    += -Wl,-s

SRC := $(wildcard source/*.c) $(wildcard src/*.c)

all: decrypt_rnps.elf

decrypt_rnps.elf: $(SRC)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LOADER_OPT) $(SRC) -o $@ $(LDFLAGS)

clean:
	rm -f *.o *.elf $(TARGET)

test: decrypt_rnps.elf
	$(PS5_DEPLOY) -h $(PS5_HOST) -p $(PS5_PORT) $^

.PHONY: all clean test
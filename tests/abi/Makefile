# The PKCS#11 ABI tests (Phase 6 slice 5c, user: "Keep as tests/abi/ (Recommended)"): C programs
# that dlopen the module and use nothing of pqHSM's but the PKCS#11 interface, so they test the
# all-Rust libpqhsm.so as any consumer would. DIV-057 and DIV-059 are in their sources.
#   make -C tests/abi check MODULE=/abs/path/libpqhsm.so    (signed: scripts/sign_module.sh)
OUT            ?= ../../.obj/abi
OPENSSL_PREFIX ?= /usr/local/ssl

# The legacy Makefile's warnings and hardening, which these always built under.
WARN := -Wall -Wextra -Wpedantic -Werror -Wstrict-prototypes -Wshadow -Wpointer-arith -Wcast-align \
        -Wwrite-strings -Wnested-externs -Wmissing-prototypes -Wmissing-declarations \
        -Wredundant-decls -Wstrict-aliasing=2 -Wformat=2 -Wformat-security -Wno-format-nonliteral \
        -Wnull-dereference -Wdouble-promotion -Wconversion -Wno-sign-conversion -Wno-unused-parameter
CFLAGS ?= -g -O2
CFLAGS += $(WARN) -fstack-protector-strong -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=2 -fno-strict-aliasing \
          -DOPENSSL_API_COMPAT=0x30000000L -std=c11 -D_GNU_SOURCE -I. -I../../modernized/pqHSM/gui/include -I$(OPENSSL_PREFIX)/include
# libcrypto for the eleven that check the module's output with OpenSSL; --as-needed drops it elsewhere.
LDLIBS := -L$(OPENSSL_PREFIX)/lib64 -L$(OPENSSL_PREFIX)/lib -Wl,--push-state,--as-needed -lcrypto \
          -Wl,--pop-state -ldl -lpthread

BINS := $(patsubst %.c,$(OUT)/%,$(wildcard *.c))

all: $(BINS)
$(OUT)/%: %.c $(wildcard *.h) Makefile
	@mkdir -p $(OUT)
	$(CC) $(CFLAGS) -o $@ $< $(LDLIBS)

check: all
	@[ -n "$(MODULE)" ] || { echo "check needs MODULE=<signed libpqhsm.so>" >&2; exit 2; }
	OPENSSL_PREFIX=$(OPENSSL_PREFIX) sh check.sh $(OUT) $(abspath $(MODULE))

clean:
	rm -rf $(OUT)
.PHONY: all check clean

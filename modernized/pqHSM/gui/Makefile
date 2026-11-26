# fhsm-gui, the GTK 4 window (Phase 6 slice 5b, user: "Move it unchanged (Recommended)"): the C
# of the legacy tools/fhsm_gui.c, unchanged, linked to pqhsm-pkiops alone, so every operation it
# runs is Rust; PQHSM_REV_LOCK gives its database jobs DIV-074's lock. include/ holds copies of
# the legacy headers it needs, frozen; pkiops.h must match pkiops/src by hand, as before.
#   make -C modernized/pqHSM/gui [smoke]       (needs GTK 4: libgtk-4-dev)
CARGO_TARGET   ?= ../target
OPENSSL_PREFIX ?= /usr/local/ssl
PKIOPS := $(CARGO_TARGET)/release/libpqhsm_pkiops.a
GTK_CFLAGS = $(shell pkg-config --cflags gtk4 2>/dev/null | sed 's/-I/-isystem /g')
GTK_LIBS   = $(shell pkg-config --libs gtk4 2>/dev/null)

# The legacy Makefile's warnings and hardening, which the window always built under.
WARN := -Wall -Wextra -Wpedantic -Werror -Wstrict-prototypes -Wshadow -Wpointer-arith -Wcast-align \
        -Wwrite-strings -Wnested-externs -Wmissing-prototypes -Wmissing-declarations \
        -Wredundant-decls -Wstrict-aliasing=2 -Wformat=2 -Wformat-security -Wno-format-nonliteral \
        -Wnull-dereference -Wdouble-promotion -Wconversion -Wno-sign-conversion -Wno-unused-parameter
CF_PROTECTION := $(shell $(CC) -Werror -fcf-protection=full -x c -c /dev/null -o /dev/null >/dev/null 2>&1 && echo -fcf-protection=full)
CFLAGS ?= -g -O2
CFLAGS += $(WARN) -fstack-protector-strong -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=2 -fstack-clash-protection $(CF_PROTECTION) \
          -fno-strict-aliasing -fno-omit-frame-pointer -DOPENSSL_API_COMPAT=0x30000000L \
          -std=c11 -D_GNU_SOURCE -DPQHSM_REV_LOCK -Iinclude -I$(OPENSSL_PREFIX)/include
# The staticlib's `rustc --print native-static-libs`, less -lgcc_s (-static-libgcc), as hybrid.mk.
LDLIBS := -static-libgcc $(PKIOPS) -L$(OPENSSL_PREFIX)/lib64 -L$(OPENSSL_PREFIX)/lib \
          -Wl,--push-state,--as-needed -lssl -lcrypto -lutil -lrt -lpthread -lm -ldl -lc -Wl,--pop-state

fhsm-gui: fhsm_gui.c $(wildcard include/*.h) Makefile $(PKIOPS)
	@pkg-config --exists gtk4 || { echo "fhsm-gui needs GTK 4: sudo apt install libgtk-4-dev" >&2; exit 2; }
	$(CC) $(CFLAGS) $(GTK_CFLAGS) -o $@ $< -Wl,-z,relro,-z,now,-z,noexecstack $(LDLIBS) $(GTK_LIBS)

# Cargo decides whether anything is stale.
$(PKIOPS): FORCE
	+cargo build --release --locked -p pqhsm-pkiops --target-dir $(CARGO_TARGET) --manifest-path ../Cargo.toml

# The window under a virtual display, closed over the session bus (gui_smoke.sh).
smoke: fhsm-gui
	sh gui_smoke.sh

# The pkiops interface's tests (tests/, since slice 5c): pkiops.h and the Rust library, no GTK.
# Each runs in its own directory against MODULE, a dev-bypass module copied in as ./libfreehsm.so.
GT    := $(CARGO_TARGET)/gui-tests
TESTS := $(patsubst tests/%.c,$(GT)/%,$(wildcard tests/*.c))
tests: $(TESTS)
$(GT)/%: tests/%.c include/pkiops.h Makefile $(PKIOPS)
	@mkdir -p $(GT)
	$(CC) $(CFLAGS) -o $@ $< $(LDLIBS)
check: tests
	@[ -n "$(MODULE)" ] || { echo "check needs MODULE=<a dev-bypass libpqhsm_module.so>" >&2; exit 2; }
	@failed=; for t in $(notdir $(TESTS)); do d=$(abspath $(GT))/run-$$t; mkdir -p $$d; \
	    cp $(abspath $(MODULE)) $$d/libfreehsm.so; \
	    (cd $$d && FHSM_INTEGRITY_ALLOW_UNSIGNED=1 FHSM_TOKENS_DIR=$$(mktemp -d) OPENSSL_CONF=/dev/null \
	     LD_LIBRARY_PATH=$(OPENSSL_PREFIX)/lib64:$(OPENSSL_PREFIX)/lib ../$$t) < /dev/null > $$d/log 2>&1 || \
	    { failed="$$failed $$t"; tail -5 $$d/log; }; done; \
	[ -z "$$failed" ] || { echo "gui tests failed:$$failed (logs in $(GT)/run-*)"; exit 1; }; \
	echo "gui tests: $(words $(TESTS)) run, all passed"

clean:
	rm -f fhsm-gui $(TESTS)
.PHONY: smoke tests check clean FORCE

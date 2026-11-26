# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 mor-sec <192092408+mor-sec@users.noreply.github.com>
#
# pqHSM's build. Cargo builds everything (the workspace is modernized/pqHSM); this file signs,
# tests and installs what it builds. The C it replaced, and the hybrid build that retired it, are
# in legacy/ (make -C legacy builds the C oracle).
#
#   make [PROFILE=all-mechanisms] [AUDIT=optional]   build and sign: out/libpqhsm.so, out/pqhsm-*
#   make test                                        the Rust suites, then tests/abi and the GUI's
#                                                    tests on a dev-bypass build of the module
#   sudo make install | uninstall                    what out/ holds, under PREFIX (as root)

WS             := modernized/pqHSM
PROFILE        ?= nist-approved-only
AUDIT          ?= mandatory
OPENSSL_PREFIX ?= /usr/local/ssl
PREFIX         ?= /opt/freehsm
LIBDIR         ?= $(PREFIX)/lib
# The module reads /etc/freehsm/freehsm.conf (crypto/src/conf.rs DEFAULT_PATH), not $(PREFIX)/etc
ETCDIR         ?= /etc/freehsm
STATEDIR       ?= /var/lib/freehsm
SYSUSER        ?= freehsm
UNITDIR        ?= /etc/systemd/system

ifeq ($(filter $(PROFILE),nist-approved-only all-mechanisms),)
$(error PROFILE is nist-approved-only or all-mechanisms, not "$(PROFILE)")
endif
ifeq ($(filter $(AUDIT),mandatory optional),)
$(error AUDIT is mandatory or optional, not "$(AUDIT)")
endif
# override: a command-line FEATURES=dev-bypass would sign and install a bypassable module (DIV-034)
override FEATURES := $(if $(filter all-mechanisms,$(PROFILE)),all-mechanisms) $(if $(filter optional,$(AUDIT)),audit-optional)
CARGO    := cargo build --release --locked --manifest-path $(WS)/Cargo.toml
MODFEAT   = $(foreach f,$(1),--features pqhsm-module/$(f))
REL      := $(WS)/target-release/release
DEV      := $(WS)/target/release
TOOLS    := csr token crypt sign ca
# replaced in one rename, so a running process never finds the name missing
RELINK    = ln -sfn $(2) $(dir $(1)).$(notdir $(1)).tmp && mv -Tf $(dir $(1)).$(notdir $(1)).tmp $(1)

.PHONY: all build sign test test-tools install uninstall clean
all: sign

# Cargo knows what changed; make asks it every time.
build:
	+$(CARGO) --target-dir $(WS)/target-release -p pqhsm-module -p pqhsm-service $(call MODFEAT,$(FEATURES))
	+$(CARGO) --target-dir $(WS)/target-release -p pqhsm-cli -p pqhsm-audit-verify

# Fresh copies each time: scripts/sign_module.sh refuses a module already signed.
sign: build
	@mkdir -p out && rm -f out/profile
	cp $(REL)/libpqhsm_module.so out/libpqhsm.so
	cp $(REL)/pqhsm-service $(REL)/pqhsm-audit out/
	for t in $(TOOLS); do cp $(REL)/fhsm-$$t out/pqhsm-$$t || exit 1; done
	scripts/sign_module.sh out/libpqhsm.so
	scripts/sign_module.sh out/pqhsm-service
	echo '$(PROFILE) $(AUDIT)' > out/profile

# A dev-bypass module, in its own target dir: the tests run with no FIPS provider and unsigned.
test:
	+cargo test --locked --workspace --manifest-path $(WS)/Cargo.toml
	+cargo test --locked -p pqhsm-selftest --features ffi --manifest-path $(WS)/Cargo.toml
	+cargo test --locked -p pqhsm-token --features ffi --manifest-path $(WS)/Cargo.toml
	+$(CARGO) --target-dir $(WS)/target -p pqhsm-module $(call MODFEAT,dev-bypass $(FEATURES))
	$(MAKE) -C tests/abi check MODULE=$(abspath $(DEV)/libpqhsm_module.so) OPENSSL_PREFIX=$(OPENSSL_PREFIX)
	$(MAKE) -C $(WS)/gui check MODULE=$(abspath $(DEV)/libpqhsm_module.so) OPENSSL_PREFIX=$(OPENSSL_PREFIX)
	$(MAKE) test-tools

# The suites that drive the tools and the service (tests/*.sh), as the hybrid ran them on the Rust
# (legacy/hybrid/harness/inner.sh): all-mechanisms, which the service needs (DIV-081) and so do
# the composite keys, dev-bypass, in a directory laid out as they expect. The audit switch's
# optional side needs a second build: slice 5e's.
ST    := out/stage
STDEV := $(WS)/target-tools/release
SUITES := fhsm_crypt_cli pki_tools_algs audit_switch service_guards service_budget service_public revocation_db ocsp_delegated
test-tools:
	+$(CARGO) --target-dir $(WS)/target-tools -p pqhsm-module -p pqhsm-service $(call MODFEAT,dev-bypass all-mechanisms)
	+$(CARGO) --target-dir $(WS)/target-tools -p pqhsm-cli
	@mkdir -p $(ST)/tools $(ST)/service
	cp $(STDEV)/libpqhsm_module.so $(ST)/libfreehsm.so
	cp $(STDEV)/pqhsm-service $(ST)/service/fhsm-service
	for t in $(TOOLS); do cp $(STDEV)/fhsm-$$t $(ST)/tools/fhsm-$$t || exit 1; done
	ln -sfn ../../tests $(ST)/tests
	@cd $(ST) && failed=; for s in $(SUITES); do a=; [ $$s = audit_switch ] && a=mandatory; \
	    LD_LIBRARY_PATH=.:$(OPENSSL_PREFIX)/lib64:$(OPENSSL_PREFIX)/lib sh tests/$$s.sh $$a < /dev/null > $$s.log 2>&1 || \
	    { failed="$$failed $$s"; tail -5 $$s.log; }; done; \
	[ -z "$$failed" ] || { echo "tool suites failed:$$failed (logs in $(ST))"; exit 1; }; \
	echo "tool suites: $(words $(SUITES)) run, all passed"

# Installs what `make` signed; it builds nothing, so root needs no Rust toolchain.
install:
	@[ -f out/profile ] || { echo "install: out/ is empty: run make first, as yourself" >&2; exit 2; }
	install -d -o root -g root -m 755 $(LIBDIR) $(ETCDIR) $(PREFIX)/bin $(PREFIX)/share/kat $(PREFIX)/share/doc/pqhsm/LICENSES
	install -o root -g root -m 0755 out/libpqhsm.so $(LIBDIR)/libpqhsm.so
	$(call RELINK,$(LIBDIR)/libfreehsm.so,libpqhsm.so)
	-setcap 'cap_ipc_lock=+ep' $(LIBDIR)/libpqhsm.so
	id -u $(SYSUSER) >/dev/null 2>&1 || useradd -r -s /usr/sbin/nologin -d $(STATEDIR) $(SYSUSER)
	install -d -o $(SYSUSER) -g $(SYSUSER) -m 700 $(STATEDIR)/tokens $(STATEDIR)/audit $(STATEDIR)/kek
	test -f $(ETCDIR)/freehsm.conf || printf '# freehsm.conf --- runtime configuration.\n#\n# Every key below is read by the module. Nothing else is: the rest of the\n# module is configured at compile time (FHSM_PIN_MAX_FAILED, the PBKDF2\n# iteration count, the throttle curve) or through the environment\n# (FHSM_TOKENS_DIR, FHSM_MODE). Until v1.6.0 this file listed nine keys and\n# no code read any of them -- a file that promises controls nothing enforces.\n\n# Runtime mode: strict | permissive. Overridden by the FHSM_MODE environment\n# variable. `strict` refuses the thirteen mechanisms NIST has not approved;\n# `permissive` runs them. The former spellings `fips` and `legacy` are still\n# accepted and print a note naming the replacement.\n#\n# NOTE its narrow scope. This is one of two axes, and it is the second one:\n# which mechanisms the PKCS#11 API advertises at all is fixed when the module\n# is built (make PROFILE=nist-approved-only|all-mechanisms) and\n# cannot be changed here. A mechanism the build left out cannot be turned on\n# by this key; this key only decides whether a compiled-in but unapproved\n# mechanism is allowed to run.\nmode = permissive\n\n# Size of the mlock(2)-ed secure heap holding key material, in KiB.\n# Range 64..65536, rounded UP to a power of two (the arena allocator requires\n# one). Out-of-range or unparseable values fall back to the compiled default.\n# Raise this if the module reports CKR_DEVICE_MEMORY when loading a token with\n# many private keys.\nsecure_heap_kb = 8192\n' > $(ETCDIR)/freehsm.conf
	chmod 0644 $(ETCDIR)/freehsm.conf
	install -o root -g root -m 0644 kat/cavp/*.rsp $(PREFIX)/share/kat/
	for t in $(TOOLS); do \
	    install -o root -g root -m 0755 out/pqhsm-$$t $(PREFIX)/bin/pqhsm-$$t && \
	    ln -sfn pqhsm-$$t $(PREFIX)/bin/.fhsm-$$t.tmp && mv -Tf $(PREFIX)/bin/.fhsm-$$t.tmp $(PREFIX)/bin/fhsm-$$t || exit 1; \
	done
	install -o root -g root -m 0755 out/pqhsm-audit $(PREFIX)/bin/pqhsm-audit
	$(call RELINK,$(PREFIX)/bin/freehsm-audit,pqhsm-audit)
	@case "$$(cat out/profile)" in all-mechanisms*) \
	    set -e; install -d -o root -g root -m 755 $(PREFIX)/libexec $(UNITDIR); \
	    install -o root -g root -m 0755 out/pqhsm-service $(PREFIX)/libexec/pqhsm-service; \
	    sed -e 's|^ExecStart=/usr/libexec/fhsm-service|ExecStart=$(PREFIX)/libexec/pqhsm-service|' \
	        -e 's|^Environment=FHSM_|Environment=PQHSM_|' \
	        -e 's|^#   install -m 0644 systemd/fhsm-service.service /etc/systemd/system/|#   installed by: make install|' \
	        systemd/fhsm-service.service > $(UNITDIR)/pqhsm-service.service; \
	    grep -q '^ExecStart=$(PREFIX)/libexec/pqhsm-service ' $(UNITDIR)/pqhsm-service.service; \
	    echo "[install] $(PREFIX)/libexec/pqhsm-service, $(UNITDIR)/pqhsm-service.service";; \
	*) echo "[install] the service is not installed: a nist-approved-only build's refuses to start (DIV-081)";; esac
	install -o root -g root -m 0644 LICENSE NOTICE $(PREFIX)/share/doc/pqhsm/
	install -o root -g root -m 0644 LICENSES/Apache-2.0.txt LICENSES/MIT.txt $(PREFIX)/share/doc/pqhsm/LICENSES/
	@echo "[install] $(LIBDIR)/libpqhsm.so ($$(cat out/profile)), $(PREFIX)/bin/pqhsm-*"

uninstall:
	@echo "[uninstall] WARNING: this DESTROYS every token, audit log and KEK under $(STATEDIR),"
	@echo "[uninstall] and removes $(ETCDIR)/freehsm.conf and the pqhsm-service unit (system-wide)."
	@echo "[uninstall] Ctrl-C now to abort, or wait 5 s..."
	@sleep 5
	-systemctl disable --now pqhsm-service 2>/dev/null || true
	-systemctl stop freehsm-bound-service 2>/dev/null || true
	-shred -uz $(STATEDIR)/tokens/*.tok $(STATEDIR)/audit/*.audit.log $(STATEDIR)/kek/*.kek 2>/dev/null || true
	rm -f $(LIBDIR)/libpqhsm.so $(LIBDIR)/libfreehsm.so $(ETCDIR)/freehsm.conf \
	    $(UNITDIR)/pqhsm-service.service $(PREFIX)/libexec/pqhsm-service \
	    $(PREFIX)/bin/pqhsm-audit $(PREFIX)/bin/freehsm-audit $(foreach t,$(TOOLS),$(PREFIX)/bin/pqhsm-$(t) $(PREFIX)/bin/fhsm-$(t))
	rm -rf $(STATEDIR) $(PREFIX)/share/doc/pqhsm $(PREFIX)/share/kat
	-systemctl daemon-reload 2>/dev/null || true
	-userdel $(SYSUSER) 2>/dev/null || true
	@echo "[uninstall] done"

clean:
	rm -rf out .obj
	$(MAKE) -C $(WS)/gui clean

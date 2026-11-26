# Hybrid build: the legacy Makefile, unchanged, with the ported C objects replaced by the one
# Rust staticlib, pqhsm-module. Phase 1: src/fhsm_audit.c (plus the C shim for the variadic
# entry point). Phase 2 slice 1: src/fhsm_tpm.c and src/fhsm_token_tpm.c. Slice 2:
# src/fhsm_revocation.c, which is not in the module but in every $(REVOCATION_OBJ) link (the
# tools, the service, test_pki_classic, test_pkiops*); those links take $(LDFLAGS) too. Slice 3:
# src/fhsm_token.c. The Rust store's cap is fixed at 1024 objects: -DFHSM_MAX_OBJECTS= no longer
# reaches it. Phase 3 slice 1: src/fhsm_memory.c and src/fhsm_conf.c (the arena size and minimum
# block are fixed too: -DFHSM_SECURE_HEAP_BYTES= and -DFHSM_SECURE_HEAP_MINSIZE= no longer reach them).
# Slice 2: src/fhsm_drbg.c. Slice 3: src/fhsm_crypto.c; the staticlib is built with dev-bypass,
# because every `make tests` recipe sets FHSM_INTEGRITY_ALLOW_UNSIGNED (DIV-034). Slice 4:
# src/fhsm_integrity.c; its digest array stays C, where scripts/sign_module.sh patches it.
# Slice 5: src/fhsm_composite.c, in the module and in every PKI tool and test_pkiops* link.
# Phase 4 slice 0: the function tables and C_GetFunctionList, C_GetInterfaceList, C_GetInterface.
# Slice 1a: src/fhsm_session.c (the session table; its cap is fixed at 128, as the store's).
# Slice 1b: src/fhsm_state.c. Slice 1c: src/fhsm_apilock.c. Slice 1d: C_Initialize to C_SetPIN
# (fifteen entry points of src/fhsm_pkcs11.c) and the slot registry. Slice 2: the object
# entry points but C_CreateObject. Slice 3: the five digest entry points and their table.
# Slices 4 to 6c: encrypt and decrypt, sign and verify, key generation, C_CreateObject, wrap.
# Slices 6d to 8b: the rest of src/fhsm_pkcs11.c. Slice 8c: no part of it, nor of
# src/fhsm_ecdsa_raw.c, src/fhsm_pq_params.c, src/fhsm_mode.c, src/gen/ or src/dispatch/, is in
# the module (tests/test_conf alone links fhsm_mode.c). Phase 5 slice 0: the PKI tools' module
# loader and pkiops_load, _open, _close, _unload and _set_call_log (pqhsm-pkiops, below).
# Slice 1: tools/fhsm-csr is pqhsm-cli's binary, and fhsm-csr's twelve pkiops_* are Rust.
# Slice 2: tools/fhsm-token likewise, with pkiops_token_info and pkiops_token_init.
# Slice 3: tools/fhsm-crypt likewise, with the objects, secret keys and CMS envelopes.
# Slice 4: tools/fhsm-sign likewise. Slice 5: tools/fhsm-ca likewise, and the rest of pkiops.h:
# test_pkiops* link no C of tools/pkiops.c or tools/cms_env.c.
# Phase 6 slice 5a: $(LIB) is pqhsm-module's cdylib, copied. Of the module's C shims only
# audit_event.c is left: the variadic fhsm_audit_event the C callers use, until slice 5d.
#
#   make -f modernized/pqHSM/hybrid.mk <any legacy target>     (from the repository root)
#
# It builds in place like the legacy Makefile, so run it on a copy of the tree: the C tree is
# the oracle until Phase 6 and is never built over (brief Q4). tests-support/hybrid/run.sh does.
#
# Every legacy link that uses $(LIB_OBJ) appends $(LDFLAGS) after it, so adding the staticlib
# there reaches the module and the internal-linking tests alike. --exclude-libs keeps every
# Rust symbol out of the module's dynamic symbol table: fhsm_audit_* stay hidden, as in C.
include Makefile

PQHSM_DIR  := modernized/pqHSM
# The harness builds with dev-bypass (DIV-034's environment seams); `PQHSM_FEATURES=` is the
# release build install-pqhsm requires, in its own target dir so neither is taken for the other.
PQHSM_FEATURES ?= dev-bypass
PQHSM_TARGET := $(PQHSM_DIR)/target$(if $(PQHSM_FEATURES),,-release)
# Slice 5a: the profile and the audit switch are Cargo features of the module (and the service).
PQHSM_CFG    := $(if $(filter all-mechanisms,$(PROFILE_CANON)),all-mechanisms) \
                $(if $(findstring -DFHSM_AUDIT_MANDATORY=0,$(EXTRA_CFLAGS)),audit-optional)
PQHSM_FEAT   := $(foreach f,$(PQHSM_FEATURES) $(PQHSM_CFG),--features $(f)) --target-dir $(PQHSM_TARGET)
PQHSM_LIB  := $(PQHSM_TARGET)/release/libpqhsm_module.a
PQHSM_SO   := $(PQHSM_TARGET)/release/libpqhsm_module.so
# tests/test_tpm only: the same staticlib with the FHSM_TPM_CMD seam, built into its own
# target dir so the shipped one is never the hooks build (review H6).
PQHSM_HOOKS_LIB := $(PQHSM_DIR)/target-hooks/release/libpqhsm_module.a
PQHSM_SHIM := $(PQHSM_DIR)/audit/shim/audit_event.c
PQHSM_EMPTY := $(PQHSM_DIR)/module/empty.c
# Cargo is incremental, so depending on every source is cheap and never misses one (review L2).
PQHSM_SRC  := $(shell find $(PQHSM_DIR) -path $(PQHSM_DIR)/target -prune -o -path $(PQHSM_DIR)/target-hooks -prune -o -path $(PQHSM_DIR)/target-release -prune \
                -o \( -name '*.rs' -o -name Cargo.toml \) -print) $(PQHSM_DIR)/Cargo.lock
# From `rustc --print native-static-libs`, less -lgcc_s: -static-libgcc links the unwinder
# from libgcc_eh.a instead, and --as-needed drops the rest, so the module's NEEDED list stays
# exactly C's (no libgcc_s.so.1, no libssl.so).
PQHSM_NATIVE := -lssl -lcrypto -lutil -lrt -lpthread -lm -ldl -lc

LDFLAGS += -static-libgcc -Wl,--exclude-libs,ALL $(PQHSM_LIB) \
           -Wl,--push-state,--as-needed $(PQHSM_NATIVE) -Wl,--pop-state

# Cargo runs every time and decides (review L1): a change of features (profile, audit switch)
# rebuilds, and a no-op leaves the outputs' mtimes alone, so nothing downstream relinks. `+` runs
# it under `make -n` too, so a dry run (the harness lists `make -n tests`) sees the same. One run
# builds both the staticlib the C tests link and the cdylib that is $(LIB).
$(PQHSM_LIB): FORCE
	+cargo build --release --locked -p pqhsm-module $(PQHSM_FEAT) --manifest-path $(PQHSM_DIR)/Cargo.toml

$(PQHSM_SO): $(PQHSM_LIB) ;

# With the build's profile and audit switch too, which are the staticlib's since slice 5a (review M2).
$(PQHSM_HOOKS_LIB): FORCE
	+cargo build --release --locked -p pqhsm-module --features tpm-test-hooks,dev-bypass $(foreach f,$(PQHSM_CFG),--features $(f)) \
	    --target-dir $(PQHSM_DIR)/target-hooks --manifest-path $(PQHSM_DIR)/Cargo.toml

# An explicit recipe outranks the legacy pattern rule: the object named fhsm_audit.o is now the
# shim, and every rule that lists $(LIB_OBJ) picks it up unchanged.
$(OBJDIR)/src/fhsm_audit.o: $(PQHSM_SHIM) $(PQHSM_LIB)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c -o $@ $<

# Objects whose code is now in the staticlib: an empty object keeps every $(LIB_OBJ) rule as is.
$(OBJDIR)/src/fhsm_tpm.o $(OBJDIR)/src/fhsm_token_tpm.o $(OBJDIR)/src/fhsm_token.o \
$(OBJDIR)/src/fhsm_memory.o $(OBJDIR)/src/fhsm_conf.o $(OBJDIR)/src/fhsm_drbg.o \
$(OBJDIR)/kat/fhsm_kat_vectors.o $(OBJDIR)/kat/cavp_extended.o $(OBJDIR)/src/fhsm_pairwise.o \
$(OBJDIR)/src/fhsm_composite.o $(OBJDIR)/src/fhsm_session.o $(OBJDIR)/src/fhsm_state.o \
$(OBJDIR)/src/fhsm_apilock.o $(OBJDIR)/src/fhsm_create_attrs.o $(OBJDIR)/src/fhsm_crypto.o \
$(OBJDIR)/src/fhsm_integrity.o $(OBJDIR)/src/fhsm_pkcs11.o \
$(OBJDIR)/src/fhsm_ecdsa_raw.o $(OBJDIR)/src/fhsm_pq_params.o $(OBJDIR)/src/fhsm_mode.o \
$(OBJDIR)/src/gen/fhsm_dispatch.o $(patsubst %.c,$(OBJDIR)/%.o,$(wildcard src/dispatch/*.c)): \
		$(PQHSM_EMPTY) $(PQHSM_LIB)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c -o $@ $<

# Slice 5a: the C_* exports, fhsm_kat_results, the .fhsm_digest array and the two build settings
# are all the staticlib's, so fhsm_crypto.o, fhsm_integrity.o and fhsm_pkcs11.o are empty (above).
# fhsm_pkcs11.o keeps the generated source as a prerequisite: it is what regenerates src/gen on a
# change of profile (the legacy chain ran through gen/fhsm_dispatch.o), so check-profile holds.
$(OBJDIR)/src/fhsm_pkcs11.o: src/gen/fhsm_dispatch.c

# The module is the cargo cdylib (slice 5a), soname libpqhsm.so; the legacy prerequisites stay,
# and make warns "overriding recipe".
$(LIB): $(PQHSM_SO)
	cp $(PQHSM_SO) $@

# tests/test_conf unit-tests src/fhsm_mode.c, which the module no longer links (Q16: not
# ported; the profile is the build's only mode switch). Its link alone takes the C object.
$(OBJDIR)/src/fhsm_mode_unit.o: src/fhsm_mode.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c -o $@ $<
tests/test_conf: LDFLAGS := $(OBJDIR)/src/fhsm_mode_unit.o $(LDFLAGS)
tests/test_conf: $(OBJDIR)/src/fhsm_mode_unit.o

# test_tpm linked fhsm_tpm.c rebuilt with -DFHSM_TPM_TEST_HOOKS. That seam is now the Rust
# feature, so the object is empty and test_tpm links the hooks staticlib instead. LDFLAGS is
# recursive, so the target-specific PQHSM_LIB reaches its link line.
$(OBJDIR)/tests/fhsm_tpm_testhooks.o: $(PQHSM_EMPTY) $(PQHSM_HOOKS_LIB)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c -o $@ $<
tests/test_tpm: PQHSM_LIB := $(PQHSM_HOOKS_LIB)
tests/test_tpm: $(PQHSM_HOOKS_LIB)

# Phase 5 slice 0: the PKI tools and test_pkiops* link pqhsm-pkiops in place of pqhsm-module.
# Its staticlib bundles pqhsm-pki, the composite and revocation code those links took from the
# module's (their $(OBJDIR) objects are the empty ones above). Slice 5: it holds all of
# pkiops.h, so they compile no tools/pkiops.c or tools/cms_env.c. The legacy recipes name
# tools/pkiops.c literally, so each is overridden here: make warns "overriding recipe" once per
# target. Not a target-specific PQHSM_LIB, as test_tpm's: it would reach $(LIB), a prerequisite
# of test_pkiops*, if make built the module for them. The GUI: modernized/pqHSM/gui (slice 5b).
# From slice 1 a ported tool is pqhsm-cli's binary instead (PQHSM_CLI_BINS, below).
PQHSM_PKIOPS_LIB  := $(PQHSM_TARGET)/release/libpqhsm_pkiops.a
PQHSM_CLI_BINS    := tools/fhsm-csr tools/fhsm-token tools/fhsm-crypt tools/fhsm-sign tools/fhsm-ca
PQHSM_PKIOPS_BINS := $(filter-out $(PQHSM_CLI_BINS),$(TOOLS)) tests/test_pkiops tests/test_pkiops_algs \
                     tests/test_pkiops_objects tests/test_pkiops_secret tests/test_pkiops_envelope \
                     tests/test_pkiops_envelope_rsa

$(PQHSM_PKIOPS_LIB): $(PQHSM_SRC)
	cargo build --release --locked -p pqhsm-pkiops --target-dir $(PQHSM_TARGET) --manifest-path $(PQHSM_DIR)/Cargo.toml

# The Rust tools, built by cargo and copied to the C names; they keep the legacy prerequisites.
$(PQHSM_CLI_BINS): $(PQHSM_SRC)
	cargo build --release --locked -p pqhsm-cli --bin $(notdir $@) --target-dir $(PQHSM_TARGET) --manifest-path $(PQHSM_DIR)/Cargo.toml
	cp $(PQHSM_TARGET)/release/$(notdir $@) $@

# The main source is the legacy rule's .c prerequisite (slice 5c: the tests are in gui/tests). Not
# $<: with this rule's recipe, its own prerequisite (the library) comes first (5c review H1).
$(PQHSM_PKIOPS_BINS): $(PQHSM_PKIOPS_LIB)
	$(CC) $(CFLAGS) -Itools -o $@ $(firstword $(filter %.c,$^)) \
	    $(OBJDIR)/src/fhsm_composite.o $(REVOCATION_OBJ) $(subst $(PQHSM_LIB),$(PQHSM_PKIOPS_LIB),$(LDFLAGS)) -ldl

# The GUI (slice 6: C on pqhsm-pkiops) has its own build since slice 5b: modernized/pqHSM/gui.

# Phase 6 slice 0: pqhsm-service, built beside the C service (which ships until slice 3). Slice 5b:
# a Cargo binary with no C (service/src/main.rs is its C `main`); service/build.rs exports
# C_GetFunctionList, which pqhsm-pkiops reaches with dlopen(NULL), and nothing else.
PQHSM_SERVICE_BIN := $(PQHSM_TARGET)/release/pqhsm-service
$(PQHSM_SERVICE_BIN): FORCE
	+cargo build --release --locked -p pqhsm-service --bin pqhsm-service $(PQHSM_FEAT) --manifest-path $(PQHSM_DIR)/Cargo.toml

# Copied every time (review M1): after a feature switch Cargo can put back an older build with
# its old mtime, which make would take for up to date.
service/pqhsm-service: $(PQHSM_SERVICE_BIN) FORCE
	cp $(PQHSM_SERVICE_BIN) $@

# Slice 3: the hybrid build ships the Rust service under the C name, so `service-guards`,
# `service-budget` and `service-public` run it (the install rule is slice 4's, Q21). Copied
# every time: the Makefile's prerequisites stay on the target, so a C binary built since by
# plain make would otherwise look up to date.
service/fhsm-service: service/pqhsm-service FORCE
	cp $< $@
.PHONY: FORCE
FORCE:

# REVOCATION_OBJ cannot be reassigned here: the legacy prerequisite lists are already expanded
# (review H5). So the object it names is emptied, and the code comes from the staticlib.
$(OBJDIR)/src/fhsm_revocation.o: $(PQHSM_EMPTY) $(PQHSM_LIB)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c -o $@ $<

# Phase 6 slice 4 (Q18, Q21): the pqHSM layout over the legacy install, which installs the module
# under its C name and freehsm-audit. The module becomes libpqhsm.so with libfreehsm.so a link
# (soname libpqhsm.so, below); the tools pqhsm-* with
# fhsm-* links for one release; the service $(PREFIX)/libexec/pqhsm-service and its unit, with
# ExecStart to match, when the build's service can start (all-mechanisms: DIV-081). A release
# build only, signed (review H1, M3), from a clean checkout:
#   make -f modernized/pqHSM/hybrid.mk PQHSM_FEATURES= PROFILE=... install-pqhsm
# Each old name is replaced by its link in one rename, so it is never missing (review L5).
# shortcut: a target of its own beside `install`, whose recipe hybrid.mk cannot extend; it
# becomes `install` at the cutover (slice 5).
UNITDIR ?= /etc/systemd/system
# The library's soname is libpqhsm.so (user, 2026-11-12), so programs linked from now on need only
# the new name and the libfreehsm.so link can go, as Q18 intends. Since slice 5a (module/build.rs)
# the harness build's is too: its tests load the module by path.
# Slice 5b (user: "The Rust one (Recommended)"): the installed verifier is audit-verify's pqhsm-audit,
# with freehsm-audit its link for one release. tools/freehsm-audit stays the C oracle's, which the
# harness cross-checks it against (the legacy install still puts it in place first).
PQHSM_AUDIT_BIN := $(PQHSM_TARGET)/release/pqhsm-audit
$(PQHSM_AUDIT_BIN): FORCE
	+cargo build --release --locked -p pqhsm-audit-verify --bin pqhsm-audit --target-dir $(PQHSM_TARGET) --manifest-path $(PQHSM_DIR)/Cargo.toml
PQHSM_RELINK = ln -sfn $(2) $(dir $(1)).$(notdir $(1)).tmp && mv -Tf $(dir $(1)).$(notdir $(1)).tmp $(1)
.PHONY: install-pqhsm
install-pqhsm: $(LIB) $(PQHSM_CLI_BINS) $(PQHSM_AUDIT_BIN) service/pqhsm-service
	@[ -z "$(PQHSM_FEATURES)" ] || { echo "install-pqhsm: refused: built with $(PQHSM_FEATURES), the harness's seams (DIV-034). From a clean checkout: make -f $(PQHSM_DIR)/hybrid.mk PQHSM_FEATURES= install-pqhsm" >&2; exit 1; }
	@# the cargo outputs themselves, not a copy make took for current (slice 5b review M1)
	cp $(PQHSM_SO) $(LIB) && cp $(PQHSM_SERVICE_BIN) service/pqhsm-service
	scripts/sign_module.sh $(LIB) || [ $$? = 3 ]
	@# -o: the signed file is never remade. A regenerated header (the profile stamp lands a second
	@# after it; a tar copy keeps whole seconds) made the legacy objects newer, and the inner make
	@# copied the unsigned cargo output over it (harness run 36)
	$(MAKE) -f $(PQHSM_DIR)/hybrid.mk -o $(LIB) install
	ln -f $(LIBDIR)/$(LIB) $(LIBDIR)/libpqhsm.so
	$(call PQHSM_RELINK,$(LIBDIR)/$(LIB),libpqhsm.so)
	for t in $(notdir $(PQHSM_CLI_BINS)); do \
	    install -o root -g root -m 0755 tools/$$t $(PREFIX)/bin/pq$${t#f} && \
	    ln -sfn pq$${t#f} $(PREFIX)/bin/.$$t.tmp && mv -Tf $(PREFIX)/bin/.$$t.tmp $(PREFIX)/bin/$$t || exit 1; \
	done
	install -o root -g root -m 0755 $(PQHSM_AUDIT_BIN) $(PREFIX)/bin/pqhsm-audit
	$(call PQHSM_RELINK,$(PREFIX)/bin/freehsm-audit,pqhsm-audit)
	@if [ "$(PROFILE_CANON)" = all-mechanisms ]; then \
	    set -e; scripts/sign_module.sh service/pqhsm-service || [ $$? = 3 ]; \
	    install -d -o root -g root -m 755 $(PREFIX)/libexec $(UNITDIR); \
	    install -o root -g root -m 0755 service/pqhsm-service $(PREFIX)/libexec/pqhsm-service; \
	    sed -e 's|^ExecStart=/usr/libexec/fhsm-service|ExecStart=$(PREFIX)/libexec/pqhsm-service|' \
	        -e 's|^Environment=FHSM_|Environment=PQHSM_|' \
	        -e 's|^#   install -m 0644 systemd/fhsm-service.service /etc/systemd/system/|#   installed by: make -f $(PQHSM_DIR)/hybrid.mk install-pqhsm|' \
	        systemd/fhsm-service.service > $(UNITDIR)/pqhsm-service.service; \
	    grep -q '^ExecStart=$(PREFIX)/libexec/pqhsm-service ' $(UNITDIR)/pqhsm-service.service; \
	    echo "[install] $(PREFIX)/libexec/pqhsm-service, $(UNITDIR)/pqhsm-service.service"; \
	else echo "[install] the service is not installed: a $(PROFILE_CANON) build's refuses to start (DIV-081)"; fi
	install -d -o root -g root -m 755 $(PREFIX)/share/doc/pqhsm/LICENSES
	install -o root -g root -m 0644 LICENSE NOTICE $(PREFIX)/share/doc/pqhsm/
	install -o root -g root -m 0644 LICENSES/Apache-2.0.txt LICENSES/MIT.txt $(PREFIX)/share/doc/pqhsm/LICENSES/
	@echo "[install] pqHSM layout: $(LIBDIR)/libpqhsm.so, $(PREFIX)/bin/pqhsm-*"

# The legacy uninstall (its warning and 5 s pause, then tokens, audit logs and KEK shredded),
# then the pqHSM layout. The service is stopped first, so nothing writes while it runs.
PQHSM_TOOL_NAMES := $(notdir $(PQHSM_CLI_BINS)) $(patsubst fhsm-%,pqhsm-%,$(notdir $(PQHSM_CLI_BINS)))
.PHONY: uninstall-pqhsm
uninstall-pqhsm:
	-systemctl disable --now pqhsm-service 2>/dev/null || true
	$(MAKE) -f $(PQHSM_DIR)/hybrid.mk uninstall
	rm -f $(UNITDIR)/pqhsm-service.service $(PREFIX)/libexec/pqhsm-service $(LIBDIR)/libpqhsm.so \
	    $(PREFIX)/bin/pqhsm-audit $(PREFIX)/bin/freehsm-audit $(addprefix $(PREFIX)/bin/,$(PQHSM_TOOL_NAMES))
	rm -rf $(PREFIX)/share/doc/pqhsm $(PREFIX)/share/kat
	@echo "[uninstall] pqHSM layout removed"

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
PQHSM_LIB  := $(PQHSM_DIR)/target/release/libpqhsm_module.a
# tests/test_tpm only: the same staticlib with the FHSM_TPM_CMD seam, built into its own
# target dir so the shipped one is never the hooks build (review H6).
PQHSM_HOOKS_LIB := $(PQHSM_DIR)/target-hooks/release/libpqhsm_module.a
PQHSM_SHIM := $(PQHSM_DIR)/audit/shim/audit_event.c
PQHSM_EMPTY := $(PQHSM_DIR)/module/empty.c
PQHSM_KAT_SHIM := $(PQHSM_DIR)/crypto/shim/kat_results.c
PQHSM_DIGEST_SHIM := $(PQHSM_DIR)/selftest/shim/integrity_digest.c
# Cargo is incremental, so depending on every source is cheap and never misses one (review L2).
PQHSM_SRC  := $(shell find $(PQHSM_DIR) -path $(PQHSM_DIR)/target -prune -o -path $(PQHSM_DIR)/target-hooks -prune \
                -o \( -name '*.rs' -o -name Cargo.toml \) -print) $(PQHSM_DIR)/Cargo.lock
# From `rustc --print native-static-libs`, less -lgcc_s: -static-libgcc links the unwinder
# from libgcc_eh.a instead, and --as-needed drops the rest, so the module's NEEDED list stays
# exactly C's (no libgcc_s.so.1, no libssl.so).
PQHSM_NATIVE := -lssl -lcrypto -lutil -lrt -lpthread -lm -ldl -lc

LDFLAGS += -static-libgcc -Wl,--exclude-libs,ALL $(PQHSM_LIB) \
           -Wl,--push-state,--as-needed $(PQHSM_NATIVE) -Wl,--pop-state

$(PQHSM_LIB): $(PQHSM_SRC)
	cargo build --release --locked -p pqhsm-module --features dev-bypass --manifest-path $(PQHSM_DIR)/Cargo.toml

$(PQHSM_HOOKS_LIB): $(PQHSM_SRC)
	cargo build --release --locked -p pqhsm-module --features tpm-test-hooks,dev-bypass \
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
$(OBJDIR)/src/fhsm_apilock.o $(OBJDIR)/src/fhsm_create_attrs.o \
$(OBJDIR)/src/fhsm_ecdsa_raw.o $(OBJDIR)/src/fhsm_pq_params.o $(OBJDIR)/src/fhsm_mode.o \
$(OBJDIR)/src/gen/fhsm_dispatch.o $(patsubst %.c,$(OBJDIR)/%.o,$(wildcard src/dispatch/*.c)): \
		$(PQHSM_EMPTY) $(PQHSM_LIB)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c -o $@ $<

# fhsm_crypto.o keeps the module's one non-PKCS#11 export, which --exclude-libs would hide.
$(OBJDIR)/src/fhsm_crypto.o: $(PQHSM_KAT_SHIM) $(PQHSM_LIB)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c -o $@ $<

# fhsm_integrity.o keeps the .fhsm_digest section the signing script patches.
$(OBJDIR)/src/fhsm_integrity.o: $(PQHSM_DIGEST_SHIM) $(PQHSM_LIB)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c -o $@ $<

# fhsm_pkcs11.o: every C_* is Rust's (slice 8a), so the object is the shim exporting them and
# the two build-time settings the Rust reads (slice 8c); src/fhsm_pkcs11.c is not compiled.
PQHSM_P11_SHIM   := $(PQHSM_DIR)/p11/shim/interface.c
PQHSM_P11_CONFIG := $(PQHSM_DIR)/p11/shim/build_config.c
# The Makefile's check-profile formula: all-mechanisms is the one profile that is not strict.
PQHSM_FIPS_STRICT := $(if $(filter all-mechanisms,$(PROFILE_CANON)),0,1)
# On the generated source, not the stamp: it is what regenerates src/gen on a change of profile
# (the legacy chain ran through gen/fhsm_dispatch.o), so check-profile still holds.
$(OBJDIR)/src/fhsm_pkcs11.o: $(PQHSM_P11_SHIM) $(PQHSM_P11_CONFIG) $(PQHSM_LIB) src/gen/fhsm_dispatch.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c -o $@.shim.o $(PQHSM_P11_SHIM)
	$(CC) $(CFLAGS) -DPQHSM_FIPS_STRICT=$(PQHSM_FIPS_STRICT) -c -o $@.config.o $(PQHSM_P11_CONFIG)
	$(LD) -r -o $@ $@.shim.o $@.config.o

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
# module's (their $(OBJDIR) objects are the empty ones above). They compile
# pkiops/shim/pkiops_tu.c in place of tools/pkiops.c, which it includes. The legacy recipes name
# tools/pkiops.c literally, so each is overridden here: make warns "overriding recipe" once per
# target. Not a target-specific PQHSM_LIB, as test_tpm's: it would reach $(LIB), a prerequisite
# of test_pkiops*, if make built the module for them. tools/fhsm-gui stays pure C (slice 6).
# From slice 1 a ported tool is pqhsm-cli's binary instead (PQHSM_CLI_BINS, below).
PQHSM_PKIOPS_LIB  := $(PQHSM_DIR)/target/release/libpqhsm_pkiops.a
PQHSM_PKIOPS_TU   := $(PQHSM_DIR)/pkiops/shim/pkiops_tu.c
PQHSM_CLI_BINS    := tools/fhsm-csr
PQHSM_PKIOPS_BINS := $(filter-out $(PQHSM_CLI_BINS),$(TOOLS)) tests/test_pkiops tests/test_pkiops_algs \
                     tests/test_pkiops_objects tests/test_pkiops_secret tests/test_pkiops_envelope \
                     tests/test_pkiops_envelope_rsa

$(PQHSM_PKIOPS_LIB): $(PQHSM_SRC)
	cargo build --release --locked -p pqhsm-pkiops --features shim --manifest-path $(PQHSM_DIR)/Cargo.toml

# The Rust tools, built by cargo and copied to the C names; they keep the legacy prerequisites.
$(PQHSM_CLI_BINS): $(PQHSM_SRC)
	cargo build --release --locked -p pqhsm-cli --bin $(notdir $@) --manifest-path $(PQHSM_DIR)/Cargo.toml
	cp $(PQHSM_DIR)/target/release/$(notdir $@) $@

# The main source is the target's name with _ for -: tools/fhsm-csr is tools/fhsm_csr.c.
$(PQHSM_PKIOPS_BINS): $(PQHSM_PKIOPS_TU) $(PQHSM_PKIOPS_LIB)
	$(CC) $(CFLAGS) -Itools -o $@ $(subst -,_,$@).c $(PQHSM_PKIOPS_TU) tools/cms_env.c \
	    $(OBJDIR)/src/fhsm_composite.o $(REVOCATION_OBJ) $(subst $(PQHSM_LIB),$(PQHSM_PKIOPS_LIB),$(LDFLAGS)) -ldl

# REVOCATION_OBJ cannot be reassigned here: the legacy prerequisite lists are already expanded
# (review H5). So the object it names is emptied, and the code comes from the staticlib.
$(OBJDIR)/src/fhsm_revocation.o: $(PQHSM_EMPTY) $(PQHSM_LIB)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c -o $@ $<

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
# Slice 1b: src/fhsm_state.c. Slice 1c: src/fhsm_apilock.c.
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
$(OBJDIR)/src/fhsm_apilock.o: $(PQHSM_EMPTY) $(PQHSM_LIB)
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

# fhsm_pkcs11.o: C's three table calls are made local, and the shim exporting Rust's is linked
# into the same object, so every $(LIB_OBJ) link picks it up unchanged. The other C_* stay C's
# and the Rust tables point at them.
PQHSM_P11_SHIM := $(PQHSM_DIR)/p11/shim/interface.c
$(OBJDIR)/src/fhsm_pkcs11.o: src/fhsm_pkcs11.c $(PQHSM_P11_SHIM) $(PQHSM_LIB)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c -o $@.c.o $<
	objcopy --localize-symbol=C_GetFunctionList --localize-symbol=C_GetInterfaceList \
	    --localize-symbol=C_GetInterface $@.c.o
	$(CC) $(CFLAGS) -c -o $@.shim.o $(PQHSM_P11_SHIM)
	$(LD) -r -o $@ $@.c.o $@.shim.o

# test_tpm linked fhsm_tpm.c rebuilt with -DFHSM_TPM_TEST_HOOKS. That seam is now the Rust
# feature, so the object is empty and test_tpm links the hooks staticlib instead. LDFLAGS is
# recursive, so the target-specific PQHSM_LIB reaches its link line.
$(OBJDIR)/tests/fhsm_tpm_testhooks.o: $(PQHSM_EMPTY) $(PQHSM_HOOKS_LIB)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c -o $@ $<
tests/test_tpm: PQHSM_LIB := $(PQHSM_HOOKS_LIB)
tests/test_tpm: $(PQHSM_HOOKS_LIB)

# REVOCATION_OBJ cannot be reassigned here: the legacy prerequisite lists are already expanded
# (review H5). So the object it names is emptied, and the code comes from the staticlib.
$(OBJDIR)/src/fhsm_revocation.o: $(PQHSM_EMPTY) $(PQHSM_LIB)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c -o $@ $<

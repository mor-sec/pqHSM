# Builds gen_token against the unchanged legacy Makefile's objects and flags,
# with fhsm_tpm.c recompiled through the FHSM_TPM_TEST_HOOKS seam exactly as
# tests/test_tpm is. Used only by regen_token.sh, inside a throwaway copy.
# GEN_BASE=modernized/pqHSM/hybrid.mk builds gen_token over the Rust token store instead (the
# hybrid harness, PHASE2_PLAN.md §5.1), with the TPM seam from the hooks staticlib as test_tpm.
GEN_BASE ?= Makefile
include $(GEN_BASE)
GEN_DIR ?= modernized/pqHSM/tests-support/golden
ifdef PQHSM_HOOKS_LIB
gen_token: PQHSM_LIB := $(PQHSM_HOOKS_LIB)
gen_token: $(PQHSM_HOOKS_LIB)
endif

gen_token: $(GEN_DIR)/gen_token.c $(OBJDIR)/tests/fhsm_tpm_testhooks.o $(LIB_OBJ) $(REVOCATION_OBJ)
	$(CC) $(CFLAGS) -o $@ $< $(OBJDIR)/tests/fhsm_tpm_testhooks.o \
	    $(filter-out $(OBJDIR)/src/fhsm_tpm.o,$(LIB_OBJ)) $(REVOCATION_OBJ) $(LDFLAGS) -lpthread

# Phase 2 slice 1 (TPM) goldens: the same seam and link line as tests/test_tpm. Used only by
# regen_tpm.sh.
gen_tpm: $(GEN_DIR)/gen_tpm.c $(OBJDIR)/tests/fhsm_tpm_testhooks.o $(LIB_OBJ)
	$(CC) $(CFLAGS) -o $@ $< $(OBJDIR)/tests/fhsm_tpm_testhooks.o \
	    $(filter-out $(OBJDIR)/src/fhsm_tpm.o,$(LIB_OBJ)) $(LDFLAGS) -lpthread

# Phase 2 slice 2 (revocation) goldens. The two --wrap seams are on this link line only: they
# record the arguments the legacy fhsm_ocsp_answer_ex hands fhsm_pki_ocsp, and pin time() so the
# answers are byte-stable. Used only by regen_rev.sh.
gen_rev: $(GEN_DIR)/gen_rev.c $(LIB_OBJ) $(REVOCATION_OBJ)
	$(CC) $(CFLAGS) -o $@ $< $(LIB_OBJ) $(REVOCATION_OBJ) $(LDFLAGS) \
	    -Wl,--wrap=fhsm_pki_ocsp -Wl,--wrap=time -lpthread

# Phase 2 slice 3 (token store) goldens: the TPM seam of gen_token, plus a deterministic
# fhsm_rng_bytes through --wrap so every salt, nonce and serial repeats run to run, and a
# fhsm_audit_event wrap that defines the TPM sites' key-without-value calls (see gen_store.c).
# Used only by regen_store.sh.
gen_store: $(GEN_DIR)/gen_store.c $(OBJDIR)/tests/fhsm_tpm_testhooks.o $(LIB_OBJ)
	$(CC) $(CFLAGS) -Wno-format-truncation -o $@ $< $(OBJDIR)/tests/fhsm_tpm_testhooks.o \
	    $(filter-out $(OBJDIR)/src/fhsm_tpm.o,$(LIB_OBJ)) $(LDFLAGS) \
	    -Wl,--wrap=fhsm_rng_bytes -Wl,--wrap=fhsm_audit_event -lpthread

# Phase 3 slice 1 (conf + secure heap) goldens: the two legacy objects and libcrypto, nothing
# else. Used only by regen_crypto.sh.
gen_crypto: $(GEN_DIR)/gen_crypto.c $(OBJDIR)/src/fhsm_memory.o $(OBJDIR)/src/fhsm_conf.o
	$(CC) $(CFLAGS) -o $@ $< $(OBJDIR)/src/fhsm_memory.o $(OBJDIR)/src/fhsm_conf.o $(LDFLAGS) -lpthread

# Phase 3 slice 2 (DRBG) goldens: fhsm_drbg.o alone, its generator, reseed counter, clock and
# conditioner replaced by the --wrap seams in gen_drbg.c. Used only by regen_crypto.sh.
gen_drbg: $(GEN_DIR)/gen_drbg.c $(OBJDIR)/src/fhsm_drbg.o
	$(CC) $(CFLAGS) -o $@ $< $(OBJDIR)/src/fhsm_drbg.o $(LDFLAGS) -lpthread \
	    -Wl,--wrap=RAND_bytes -Wl,--wrap=RAND_add -Wl,--wrap=time -Wl,--wrap=EVP_MD_fetch

# Phase 3 slice 3: the legacy crypto core, its lifecycle collaborators stubbed in gen_core.c and
# the provider and RAND calls replaced by --wrap seams. Used only by regen_crypto.sh.
gen_core: $(GEN_DIR)/gen_core.c $(OBJDIR)/src/fhsm_crypto.o $(OBJDIR)/src/fhsm_memory.o $(OBJDIR)/src/fhsm_conf.o
	$(CC) $(CFLAGS) -o $@ $< $(OBJDIR)/src/fhsm_crypto.o $(OBJDIR)/src/fhsm_memory.o $(OBJDIR)/src/fhsm_conf.o \
	    $(LDFLAGS) -lpthread -Wl,--wrap=OSSL_PROVIDER_load -Wl,--wrap=OSSL_PROVIDER_unload \
	    -Wl,--wrap=EVP_default_properties_enable_fips -Wl,--wrap=RAND_status -Wl,--wrap=RAND_add

# Phase 3 slice 4: the legacy integrity check on the ELF files make_integrity_elf.py lays out;
# the self-locate is the --wrap seam in gen_integrity.c. Used only by regen_selftest.sh.
gen_integrity: $(GEN_DIR)/gen_integrity.c $(OBJDIR)/src/fhsm_integrity.o $(OBJDIR)/src/fhsm_memory.o $(OBJDIR)/src/fhsm_conf.o
	$(CC) $(CFLAGS) -o $@ $< $(OBJDIR)/src/fhsm_integrity.o $(OBJDIR)/src/fhsm_memory.o $(OBJDIR)/src/fhsm_conf.o \
	    $(LDFLAGS) -lpthread -Wl,--wrap=dl_iterate_phdr -Wl,--wrap=EVP_MD_fetch

# Phase 3 slice 4: the legacy KAT sources, #included by gen_kat.c (so -I.), with the crypto-core
# primitives they call defined there. Used only by regen_selftest.sh.
gen_kat: $(GEN_DIR)/gen_kat.c kat/fhsm_kat_vectors.c kat/cavp_extended.c $(OBJDIR)/src/fhsm_memory.o $(OBJDIR)/src/fhsm_conf.o
	$(CC) $(CFLAGS) -I. -o $@ $< $(OBJDIR)/src/fhsm_memory.o $(OBJDIR)/src/fhsm_conf.o \
	    $(LDFLAGS) -lpthread -Wl,--wrap=fopen -Wl,--wrap=EVP_DigestUpdate -Wl,--wrap=EVP_DigestSign \
	    -Wl,--wrap=EVP_PKEY_encrypt

# Phase 3 slice 4: the legacy pair-wise check, on keys gen_pairwise.c builds. Used only by
# regen_selftest.sh.
gen_pairwise: $(GEN_DIR)/gen_pairwise.c $(OBJDIR)/src/fhsm_pairwise.o
	$(CC) $(CFLAGS) -o $@ $< $(OBJDIR)/src/fhsm_pairwise.o $(LDFLAGS)

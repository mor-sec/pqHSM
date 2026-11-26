/* PHASE3_PLAN.md §4.3, the PKI step: a root, a request, an issued certificate, a CRL, an OCSP
 * response (and its BasicOCSPResponse) and a detached CMS from fhsm_pki_*, for three real classic signers, written as DER
 * for inner.sh to compare between the C and the hybrid build and to check with the openssl CLI.
 * The signers are deterministic (Ed25519, RSA PKCS#1 v1.5, ECDSA with RFC 6979 nonces), the
 * serial RNG is a counter and the clock is pinned, so both builds must write the same bytes.
 *
 *   pki_artifacts <key dir> <out dir> <data file>     keys: ed25519.pem p256.pem rsa.pem */
#include "fhsm_pki.h"

#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/ocsp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#define NOW ((time_t)1798761600) /* as tests-support/golden/gen_x509.c */

/* Interposes libc's time() for libcrypto too (see gen_x509.c). */
__attribute__((visibility("default"))) time_t time(time_t *t) {
    if (t) *t = NOW;
    return NOW;
}

struct key { EVP_PKEY *k; const char *md; int rfc6979; };

static fhsm_rv_t sign(void *c, const uint8_t *tbs, size_t n, uint8_t *sig, size_t *sl) {
    const struct key *k = c;
    EVP_MD_CTX *m = EVP_MD_CTX_new();
    EVP_PKEY_CTX *pc = NULL;
    unsigned int one = 1;
    OSSL_PARAM p[] = { OSSL_PARAM_construct_uint(OSSL_SIGNATURE_PARAM_NONCE_TYPE, &one), OSSL_PARAM_END };
    int ok = m && EVP_DigestSignInit_ex(m, &pc, k->md, NULL, NULL, k->k, NULL) == 1
             && (!k->rfc6979 || EVP_PKEY_CTX_set_params(pc, p) == 1)
             && EVP_DigestSign(m, sig, sl, tbs, n) == 1;
    EVP_MD_CTX_free(m);
    return ok ? FHSM_RV_OK : FHSM_RV_FUNCTION_FAILED;
}

static fhsm_rv_t counter(void *c, uint8_t *out, size_t n) {
    unsigned *i = c;
    for (size_t j = 0; j < n; j++) out[j] = (uint8_t)(++*i * 37u);
    return FHSM_RV_OK;
}

static int put(const char *dir, const char *alg, const char *what, fhsm_rv_t rv,
               const uint8_t *der, size_t n) {
    char path[512];
    snprintf(path, sizeof path, "%s/%s_%s.der", dir, alg, what);
    FILE *f = rv == FHSM_RV_OK ? fopen(path, "wb") : NULL;
    int ok = f && fwrite(der, 1, n, f) == n;
    if (f) fclose(f);
    printf("%s %s rv=0x%x len=%zu%s\n", alg, what, (unsigned)rv, rv == FHSM_RV_OK ? n : 0, ok ? "" : " FAIL");
    return ok;
}

int main(int argc, char **argv) {
    static const struct { const char *name; fhsm_pki_sigalg_t sig; const char *md, *cms_md; int rfc6979; } algs[] = {
        { "ed25519", FHSM_PKI_SIG_ED25519,          NULL,     "SHA512", 0 },
        { "p256",    FHSM_PKI_SIG_ECDSA_SHA256,     "SHA256", "SHA256", 1 },
        { "rsa",     FHSM_PKI_SIG_RSA_PKCS1_SHA256, "SHA256", "SHA256", 0 },
    };
    static uint8_t ca[16384], csr[16384], leaf[16384], crl[16384], basic[16384], cms[32768], data[65536];
    static const uint8_t GT[] = "\x18\x0f" "20270101000000Z";
    static const uint8_t SER[] = { 0x01, 0x23 };
    if (argc != 4) return 2;
    FILE *df = fopen(argv[3], "rb");
    size_t dl = df ? fread(data, 1, sizeof data, df) : 0;
    if (df) fclose(df);
    int fails = !df;
    for (size_t i = 0; i < sizeof algs / sizeof algs[0]; i++) {
        const char *a = algs[i].name;
        char path[512];
        snprintf(path, sizeof path, "%s/%s.pem", argv[1], a);
        FILE *kf = fopen(path, "r");
        struct key k = { kf ? PEM_read_PrivateKey(kf, NULL, NULL, NULL) : NULL, algs[i].md, algs[i].rfc6979 };
        if (kf) fclose(kf);
        uint8_t *spki = NULL;
        int spl = k.k ? i2d_PUBKEY(k.k, &spki) : -1;
        const uint8_t *algid = NULL;
        size_t al = 0;
        if (spl <= 0 || fhsm_pki_algid(algs[i].sig, &algid, &al) != FHSM_RV_OK) {
            printf("%s key FAIL\n", a);
            fails++;
            continue;
        }
        fhsm_pki_signer_t s = { algid, al, spki, (size_t)spl, sign, &k };
        unsigned ctr = 0;
        size_t cal = sizeof ca, csl = sizeof csr, ll = sizeof leaf, crll = sizeof crl, bl = sizeof basic, cmsl = sizeof cms;
        fhsm_rv_t rv = fhsm_pki_selfsigned(&s, "/C=FR/O=pqHSM harness/CN=Root", 1, 30, ca, &cal);
        fails += !put(argv[2], a, "ca", rv, ca, cal);
        rv = fhsm_pki_csr(&s, "/C=FR/O=pqHSM harness/CN=leaf", csr, &csl);
        fails += !put(argv[2], a, "csr", rv, csr, csl);
        rv = fhsm_pki_issue(&s, ca, cal, csr, csl, NULL, "DNS:leaf.example", NULL, 0,
                            FHSM_CERT_END_ENTITY, 30, counter, &ctr, leaf, &ll);
        fails += !put(argv[2], a, "leaf", rv, leaf, ll);
        fhsm_composite_revoked_t r = { SER, sizeof SER, NOW - 86400, 1 };
        rv = fhsm_pki_crl(&s, ca, cal, &r, 1, 7, 7, crl, &crll);
        fails += !put(argv[2], a, "crl", rv, crl, crll);

        /* OCSP: the leaf reported good, signed by the root itself; the CLI reads a whole
         * OCSPResponse, so OpenSSL wraps the BasicOCSPResponse. */
        const uint8_t *q = ca, *q2 = leaf;
        X509 *cx = d2i_X509(NULL, &q, (long)cal), *lx = d2i_X509(NULL, &q2, (long)ll);
        OCSP_CERTID *id = cx && lx ? OCSP_cert_to_id(NULL, lx, cx) : NULL;
        uint8_t *idd = NULL, *resp = NULL;
        int idl = id ? i2d_OCSP_CERTID(id, &idd) : -1, rl = -1;
        fhsm_composite_ocsp_single_t one = { idd, idl > 0 ? (size_t)idl : 0, 0, NULL, 0, -1, GT, sizeof GT - 1, NULL, 0 };
        rv = idl > 0 ? fhsm_pki_ocsp(&s, ca, cal, GT, sizeof GT - 1, &one, 1, NULL, 0, basic, &bl)
                     : FHSM_RV_FUNCTION_FAILED;
        fails += !put(argv[2], a, "basic", rv, basic, bl);   /* fhsm_pki_ocsp's own bytes, for cmp */
        if (rv == FHSM_RV_OK) {
            const uint8_t *b = basic;
            OCSP_BASICRESP *bs = d2i_OCSP_BASICRESP(NULL, &b, (long)bl);
            OCSP_RESPONSE *o = bs ? OCSP_response_create(OCSP_RESPONSE_STATUS_SUCCESSFUL, bs) : NULL;
            rl = o ? i2d_OCSP_RESPONSE(o, &resp) : -1;
            OCSP_RESPONSE_free(o);
            OCSP_BASICRESP_free(bs);
        }
        fails += !put(argv[2], a, "ocsp", rl > 0 ? rv : FHSM_RV_FUNCTION_FAILED, resp, rl > 0 ? (size_t)rl : 0);

        uint8_t d[EVP_MAX_MD_SIZE];
        unsigned int dn = 0;
        rv = EVP_Digest(data, dl, d, &dn, EVP_get_digestbyname(algs[i].cms_md), NULL) == 1
             ? fhsm_pki_cms(&s, algs[i].cms_md, leaf, ll, d, dn, cms, &cmsl) : FHSM_RV_FUNCTION_FAILED;
        fails += !put(argv[2], a, "cms", rv, cms, cmsl);

        OPENSSL_free(resp);
        OPENSSL_free(idd);
        OCSP_CERTID_free(id);
        X509_free(lx);
        X509_free(cx);
        OPENSSL_free(spki);
        EVP_PKEY_free(k.k);
    }
    printf("fails=%d\n", fails);
    return fails != 0;
}

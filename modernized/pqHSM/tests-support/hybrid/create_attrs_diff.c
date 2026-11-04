/* Harness step 4j: fhsm_parse_create_attrs, C against Rust. Built twice: once with
 * src/fhsm_create_attrs.c, once with the Rust staticlib's export. Each input is a template in
 * fuzz/fuzz_create_attrs.c's encoding (count byte, then per row an 8-byte type, a 1-byte
 * length, the value), taken from the files named on the command line and then from a seeded
 * generator biased to the types, classes, key types and OIDs the parser reads. Prints one
 * line per input: the rv and every field, pointers as offsets into the input. The two runs'
 * outputs must be identical.
 *
 *   create_attrs_diff N_GENERATED FILE...
 */
#include "fhsm_create_attrs.h"
#include "fhsm_attr_utils.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_ATTRS 12u

/* fuzz_create_attrs.c's build_template, unchanged. */
static unsigned long build_template(const uint8_t *data, size_t size, fhsm_attr_t *out,
                                    unsigned long max) {
    if (size < 1) return 0;
    unsigned long want = (unsigned long)data[0] % (max + 1u);
    if (want == 0) return 0;
    size_t cursor = 1;
    unsigned long built = 0;
    for (unsigned long i = 0; i < want; ++i) {
        if (cursor + 9u > size) break;
        unsigned long t = 0;
        memcpy(&t, data + cursor, sizeof(t));
        cursor += sizeof(t);
        size_t plen = (size_t)data[cursor];
        cursor += 1u;
        if (cursor + plen > size) break;
        out[i].type = t;
        out[i].pValue = (void *)(uintptr_t)(data + cursor);
        out[i].ulValueLen = (unsigned long)plen;
        cursor += plen;
        built++;
    }
    return built;
}

static void span(const char *name, const uint8_t *base, const uint8_t *p, size_t n) {
    if (p) printf(" %s=+%ld:%zu", name, (long)(p - base), n);
    else printf(" %s=NULL:%zu", name, n);
}

static void one(const uint8_t *data, size_t size) {
    fhsm_attr_t t[MAX_ATTRS];
    memset(t, 0, sizeof t);
    unsigned long n = build_template(data, size, t, MAX_ATTRS);
    fhsm_create_attrs_t a;
    memset(&a, 0xA5, sizeof a);
    fhsm_parse_rv_t rv = fhsm_parse_create_attrs(n ? t : NULL, n, &a);
    printf("rv=%d path=%d cko=%lx ckk=%lx ct=%lx label=", (int)rv, (int)a.path, a.cko, a.ckk,
           a.cert_type);
    for (size_t i = 0; i < sizeof a.label; ++i) printf("%02x", (unsigned char)a.label[i]);
    span("id", data, a.id_data, a.id_len);
    span("value", data, a.value_data, a.value_len);
    printf(" pqc=%s group=%s", a.pqc_alg ? a.pqc_alg : "NULL", a.ec_group ? a.ec_group : "NULL");
    span("point", data, a.ec_point, a.ec_point_len);
    span("n", data, a.rsa_modulus, a.rsa_modulus_len);
    span("e", data, a.rsa_exponent, a.rsa_exponent_len);
    span("d", data, a.rsa_d, a.rsa_d_len);
    span("p", data, a.rsa_p, a.rsa_p_len);
    span("q", data, a.rsa_q, a.rsa_q_len);
    span("dp", data, a.rsa_dmp1, a.rsa_dmp1_len);
    span("dq", data, a.rsa_dmq1, a.rsa_dmq1_len);
    span("qi", data, a.rsa_iqmp, a.rsa_iqmp_len);
    printf("\n");
}

static uint64_t s = 0x9E3779B97F4A7C15ull;
static uint64_t rnd(void) { s ^= s << 13; s ^= s >> 7; s ^= s << 17; return s; }

/* A value the parser has a branch for, or noise. */
static size_t gen_value(uint8_t *out, unsigned long kind) {
    static const uint8_t oids[][10] = {
        { 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07 },
        { 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22 }, { 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x23 },
        { 0x06, 0x03, 0x2b, 0x65, 0x70 }, { 0x06, 0x03, 0x2b, 0x65, 0x71 },
    };
    static const size_t oid_len[] = { 10, 7, 7, 5, 5 };
    static const unsigned long ulongs[] = { 0, 1, 2, 3, 4, 5, 0x3, 0x40, 0x49, 0x4A, 0x4B, 0x1F };
    unsigned long pick = rnd() % 7;
    if (kind == 0x180 && rnd() % 5) pick = 2;   /* CKA_EC_PARAMS: usually an OID */
    if (kind == 0x181 && rnd() % 5) pick = 3;   /* CKA_EC_POINT: usually a point */
    switch (pick) {
    case 0: case 1: {
        unsigned long v = ulongs[rnd() % 12];
        size_t n = rnd() % 4 ? sizeof v : rnd() % 12;
        memset(out, 0, n);
        memcpy(out, &v, n < sizeof v ? n : sizeof v);
        return n;
    }
    case 2: { size_t k = rnd() % 5; memcpy(out, oids[k], oid_len[k]); return oid_len[k]; }
    case 3: {   /* an OCTET STRING of 32, 57 or 65 bytes, sometimes bare */
        static const size_t ls[] = { 32, 57, 65 };
        size_t l = ls[rnd() % 3];
        if (rnd() % 3 == 0) { memset(out, 0x04, l); return l; }
        out[0] = 0x04; out[1] = (uint8_t)l; memset(out + 2, 0x04, l);
        if (rnd() % 5 == 0) out[1]++;   /* a wrong length */
        return l + 2;
    }
    default: { size_t n = rnd() % 70; for (size_t i = 0; i < n; ++i) out[i] = (uint8_t)rnd(); return n; }
    }
}

static void generated(unsigned long count) {
    static const unsigned long kinds[] = { 0x0, 0x3, 0x11, 0x80, 0x100, 0x102, 0x120, 0x122,
                                           0x123, 0x124, 0x125, 0x126, 0x127, 0x128, 0x180,
                                           0x181, 0x1, 0xdead };
    uint8_t buf[2048];
    for (unsigned long c = 0; c < count; ++c) {
        size_t rows = rnd() % 9, cur = 1;
        buf[0] = (uint8_t)rows;
        for (size_t r = 0; r < rows; ++r) {
            unsigned long k = kinds[rnd() % (sizeof kinds / sizeof kinds[0])];
            /* Most templates open with a well-formed class and key type, so the paths
             * behind them are reached, not only the early refusals. */
            int lead = r < 2 && rnd() % 5 != 0;
            if (lead) k = r == 0 ? 0x0 : 0x100;
            memcpy(buf + cur, &k, sizeof k);
            cur += sizeof k;
            size_t l;
            if (lead) {
                static const unsigned long cls[] = { 0, 1, 2, 2, 2, 3, 3, 4 };
                static const unsigned long kts[] = { 0x0, 0x3, 0x40, 0x49, 0x4A, 0x4B, 0x1F };
                unsigned long v = r == 0 ? cls[rnd() % 8] : kts[rnd() % 7];
                memcpy(buf + cur + 1, &v, sizeof v);
                l = sizeof v;
            } else {
                l = gen_value(buf + cur + 1, k);
            }
            buf[cur] = (uint8_t)l;
            cur += 1 + l;
        }
        one(buf, cur);
    }
}

int main(int argc, char **argv) {
    if (argc < 2) return 2;
    for (int i = 2; i < argc; ++i) {
        FILE *f = fopen(argv[i], "rb");
        if (!f) return 1;
        static uint8_t d[1 << 16];
        size_t n = fread(d, 1, sizeof d, f);
        fclose(f);
        one(d, n);
    }
    generated(strtoul(argv[1], NULL, 10));
    return 0;
}

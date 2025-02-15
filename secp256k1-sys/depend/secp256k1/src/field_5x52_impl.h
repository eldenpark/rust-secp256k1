/***********************************************************************
 * Copyright (c) 2013, 2014 Pieter Wuille                              *
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

#ifndef SECP256K1_FIELD_REPR_IMPL_H
#define SECP256K1_FIELD_REPR_IMPL_H

#if defined HAVE_CONFIG_H
#include "libsecp256k1-config.h"
#endif

#include "util.h"
#include "field.h"
#include "modinv64_impl.h"

#if defined(USE_ASM_X86_64)
#include "field_5x52_asm_impl.h"
#else
#include "field_5x52_int128_impl.h"
#endif

/** Implements arithmetic modulo FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE FFFFFC2F,
 *  represented as 5 uint64_t's in base 2^52, least significant first. Note that the limbs are allowed to
 *  contain >52 bits each.
 *
 *  Each field element has a 'magnitude' associated with it. Internally, a magnitude M means:
 *  - 2*M*(2^48-1) is the max (inclusive) of the most significant limb
 *  - 2*M*(2^52-1) is the max (inclusive) of the remaining limbs
 *
 *  Operations have different rules for propagating magnitude to their outputs. If an operation takes a
 *  magnitude M as a parameter, that means the magnitude of input field elements can be at most M (inclusive).
 *
 *  Each field element also has a 'normalized' flag. A field element is normalized if its magnitude is either
 *  0 or 1, and its value is already reduced modulo the order of the field.
 */

#ifdef VERIFY
static void rustsecp256k1_v0_8_0_fe_verify(const rustsecp256k1_v0_8_0_fe *a) {
    const uint64_t *d = a->n;
    int m = a->normalized ? 1 : 2 * a->magnitude, r = 1;
   /* secp256k1 'p' value defined in "Standards for Efficient Cryptography" (SEC2) 2.7.1. */
    r &= (d[0] <= 0xFFFFFFFFFFFFFULL * m);
    r &= (d[1] <= 0xFFFFFFFFFFFFFULL * m);
    r &= (d[2] <= 0xFFFFFFFFFFFFFULL * m);
    r &= (d[3] <= 0xFFFFFFFFFFFFFULL * m);
    r &= (d[4] <= 0x0FFFFFFFFFFFFULL * m);
    r &= (a->magnitude >= 0);
    r &= (a->magnitude <= 2048);
    if (a->normalized) {
        r &= (a->magnitude <= 1);
        if (r && (d[4] == 0x0FFFFFFFFFFFFULL) && ((d[3] & d[2] & d[1]) == 0xFFFFFFFFFFFFFULL)) {
            r &= (d[0] < 0xFFFFEFFFFFC2FULL);
        }
    }
    VERIFY_CHECK(r == 1);
}
#endif

static void rustsecp256k1_v0_8_0_fe_get_bounds(rustsecp256k1_v0_8_0_fe *r, int m) {
    VERIFY_CHECK(m >= 0);
    VERIFY_CHECK(m <= 2048);
    r->n[0] = 0xFFFFFFFFFFFFFULL * 2 * m;
    r->n[1] = 0xFFFFFFFFFFFFFULL * 2 * m;
    r->n[2] = 0xFFFFFFFFFFFFFULL * 2 * m;
    r->n[3] = 0xFFFFFFFFFFFFFULL * 2 * m;
    r->n[4] = 0x0FFFFFFFFFFFFULL * 2 * m;
#ifdef VERIFY
    r->magnitude = m;
    r->normalized = (m == 0);
    rustsecp256k1_v0_8_0_fe_verify(r);
#endif
}

static void rustsecp256k1_v0_8_0_fe_normalize(rustsecp256k1_v0_8_0_fe *r) {
    uint64_t t0 = r->n[0], t1 = r->n[1], t2 = r->n[2], t3 = r->n[3], t4 = r->n[4];

    /* Reduce t4 at the start so there will be at most a single carry from the first pass */
    uint64_t m;
    uint64_t x = t4 >> 48; t4 &= 0x0FFFFFFFFFFFFULL;

    /* The first pass ensures the magnitude is 1, ... */
    t0 += x * 0x1000003D1ULL;
    t1 += (t0 >> 52); t0 &= 0xFFFFFFFFFFFFFULL;
    t2 += (t1 >> 52); t1 &= 0xFFFFFFFFFFFFFULL; m = t1;
    t3 += (t2 >> 52); t2 &= 0xFFFFFFFFFFFFFULL; m &= t2;
    t4 += (t3 >> 52); t3 &= 0xFFFFFFFFFFFFFULL; m &= t3;

    /* ... except for a possible carry at bit 48 of t4 (i.e. bit 256 of the field element) */
    VERIFY_CHECK(t4 >> 49 == 0);

    /* At most a single final reduction is needed; check if the value is >= the field characteristic */
    x = (t4 >> 48) | ((t4 == 0x0FFFFFFFFFFFFULL) & (m == 0xFFFFFFFFFFFFFULL)
        & (t0 >= 0xFFFFEFFFFFC2FULL));

    /* Apply the final reduction (for constant-time behaviour, we do it always) */
    t0 += x * 0x1000003D1ULL;
    t1 += (t0 >> 52); t0 &= 0xFFFFFFFFFFFFFULL;
    t2 += (t1 >> 52); t1 &= 0xFFFFFFFFFFFFFULL;
    t3 += (t2 >> 52); t2 &= 0xFFFFFFFFFFFFFULL;
    t4 += (t3 >> 52); t3 &= 0xFFFFFFFFFFFFFULL;

    /* If t4 didn't carry to bit 48 already, then it should have after any final reduction */
    VERIFY_CHECK(t4 >> 48 == x);

    /* Mask off the possible multiple of 2^256 from the final reduction */
    t4 &= 0x0FFFFFFFFFFFFULL;

    r->n[0] = t0; r->n[1] = t1; r->n[2] = t2; r->n[3] = t3; r->n[4] = t4;

#ifdef VERIFY
    r->magnitude = 1;
    r->normalized = 1;
    rustsecp256k1_v0_8_0_fe_verify(r);
#endif
}

static void rustsecp256k1_v0_8_0_fe_normalize_weak(rustsecp256k1_v0_8_0_fe *r) {
    uint64_t t0 = r->n[0], t1 = r->n[1], t2 = r->n[2], t3 = r->n[3], t4 = r->n[4];

    /* Reduce t4 at the start so there will be at most a single carry from the first pass */
    uint64_t x = t4 >> 48; t4 &= 0x0FFFFFFFFFFFFULL;

    /* The first pass ensures the magnitude is 1, ... */
    t0 += x * 0x1000003D1ULL;
    t1 += (t0 >> 52); t0 &= 0xFFFFFFFFFFFFFULL;
    t2 += (t1 >> 52); t1 &= 0xFFFFFFFFFFFFFULL;
    t3 += (t2 >> 52); t2 &= 0xFFFFFFFFFFFFFULL;
    t4 += (t3 >> 52); t3 &= 0xFFFFFFFFFFFFFULL;

    /* ... except for a possible carry at bit 48 of t4 (i.e. bit 256 of the field element) */
    VERIFY_CHECK(t4 >> 49 == 0);

    r->n[0] = t0; r->n[1] = t1; r->n[2] = t2; r->n[3] = t3; r->n[4] = t4;

#ifdef VERIFY
    r->magnitude = 1;
    rustsecp256k1_v0_8_0_fe_verify(r);
#endif
}

static void rustsecp256k1_v0_8_0_fe_normalize_var(rustsecp256k1_v0_8_0_fe *r) {
    uint64_t t0 = r->n[0], t1 = r->n[1], t2 = r->n[2], t3 = r->n[3], t4 = r->n[4];

    /* Reduce t4 at the start so there will be at most a single carry from the first pass */
    uint64_t m;
    uint64_t x = t4 >> 48; t4 &= 0x0FFFFFFFFFFFFULL;

    /* The first pass ensures the magnitude is 1, ... */
    t0 += x * 0x1000003D1ULL;
    t1 += (t0 >> 52); t0 &= 0xFFFFFFFFFFFFFULL;
    t2 += (t1 >> 52); t1 &= 0xFFFFFFFFFFFFFULL; m = t1;
    t3 += (t2 >> 52); t2 &= 0xFFFFFFFFFFFFFULL; m &= t2;
    t4 += (t3 >> 52); t3 &= 0xFFFFFFFFFFFFFULL; m &= t3;

    /* ... except for a possible carry at bit 48 of t4 (i.e. bit 256 of the field element) */
    VERIFY_CHECK(t4 >> 49 == 0);

    /* At most a single final reduction is needed; check if the value is >= the field characteristic */
    x = (t4 >> 48) | ((t4 == 0x0FFFFFFFFFFFFULL) & (m == 0xFFFFFFFFFFFFFULL)
        & (t0 >= 0xFFFFEFFFFFC2FULL));

    if (x) {
        t0 += 0x1000003D1ULL;
        t1 += (t0 >> 52); t0 &= 0xFFFFFFFFFFFFFULL;
        t2 += (t1 >> 52); t1 &= 0xFFFFFFFFFFFFFULL;
        t3 += (t2 >> 52); t2 &= 0xFFFFFFFFFFFFFULL;
        t4 += (t3 >> 52); t3 &= 0xFFFFFFFFFFFFFULL;

        /* If t4 didn't carry to bit 48 already, then it should have after any final reduction */
        VERIFY_CHECK(t4 >> 48 == x);

        /* Mask off the possible multiple of 2^256 from the final reduction */
        t4 &= 0x0FFFFFFFFFFFFULL;
    }

    r->n[0] = t0; r->n[1] = t1; r->n[2] = t2; r->n[3] = t3; r->n[4] = t4;

#ifdef VERIFY
    r->magnitude = 1;
    r->normalized = 1;
    rustsecp256k1_v0_8_0_fe_verify(r);
#endif
}

static int rustsecp256k1_v0_8_0_fe_normalizes_to_zero(const rustsecp256k1_v0_8_0_fe *r) {
    uint64_t t0 = r->n[0], t1 = r->n[1], t2 = r->n[2], t3 = r->n[3], t4 = r->n[4];

    /* z0 tracks a possible raw value of 0, z1 tracks a possible raw value of P */
    uint64_t z0, z1;

    /* Reduce t4 at the start so there will be at most a single carry from the first pass */
    uint64_t x = t4 >> 48; t4 &= 0x0FFFFFFFFFFFFULL;

    /* The first pass ensures the magnitude is 1, ... */
    t0 += x * 0x1000003D1ULL;
    t1 += (t0 >> 52); t0 &= 0xFFFFFFFFFFFFFULL; z0  = t0; z1  = t0 ^ 0x1000003D0ULL;
    t2 += (t1 >> 52); t1 &= 0xFFFFFFFFFFFFFULL; z0 |= t1; z1 &= t1;
    t3 += (t2 >> 52); t2 &= 0xFFFFFFFFFFFFFULL; z0 |= t2; z1 &= t2;
    t4 += (t3 >> 52); t3 &= 0xFFFFFFFFFFFFFULL; z0 |= t3; z1 &= t3;
                                                z0 |= t4; z1 &= t4 ^ 0xF000000000000ULL;

    /* ... except for a possible carry at bit 48 of t4 (i.e. bit 256 of the field element) */
    VERIFY_CHECK(t4 >> 49 == 0);

    return (z0 == 0) | (z1 == 0xFFFFFFFFFFFFFULL);
}

static int rustsecp256k1_v0_8_0_fe_normalizes_to_zero_var(const rustsecp256k1_v0_8_0_fe *r) {
    uint64_t t0, t1, t2, t3, t4;
    uint64_t z0, z1;
    uint64_t x;

    t0 = r->n[0];
    t4 = r->n[4];

    /* Reduce t4 at the start so there will be at most a single carry from the first pass */
    x = t4 >> 48;

    /* The first pass ensures the magnitude is 1, ... */
    t0 += x * 0x1000003D1ULL;

    /* z0 tracks a possible raw value of 0, z1 tracks a possible raw value of P */
    z0 = t0 & 0xFFFFFFFFFFFFFULL;
    z1 = z0 ^ 0x1000003D0ULL;

    /* Fast return path should catch the majority of cases */
    if ((z0 != 0ULL) & (z1 != 0xFFFFFFFFFFFFFULL)) {
        return 0;
    }

    t1 = r->n[1];
    t2 = r->n[2];
    t3 = r->n[3];

    t4 &= 0x0FFFFFFFFFFFFULL;

    t1 += (t0 >> 52);
    t2 += (t1 >> 52); t1 &= 0xFFFFFFFFFFFFFULL; z0 |= t1; z1 &= t1;
    t3 += (t2 >> 52); t2 &= 0xFFFFFFFFFFFFFULL; z0 |= t2; z1 &= t2;
    t4 += (t3 >> 52); t3 &= 0xFFFFFFFFFFFFFULL; z0 |= t3; z1 &= t3;
                                                z0 |= t4; z1 &= t4 ^ 0xF000000000000ULL;

    /* ... except for a possible carry at bit 48 of t4 (i.e. bit 256 of the field element) */
    VERIFY_CHECK(t4 >> 49 == 0);

    return (z0 == 0) | (z1 == 0xFFFFFFFFFFFFFULL);
}

SECP256K1_INLINE static void rustsecp256k1_v0_8_0_fe_set_int(rustsecp256k1_v0_8_0_fe *r, int a) {
    VERIFY_CHECK(0 <= a && a <= 0x7FFF);
    r->n[0] = a;
    r->n[1] = r->n[2] = r->n[3] = r->n[4] = 0;
#ifdef VERIFY
    r->magnitude = (a != 0);
    r->normalized = 1;
    rustsecp256k1_v0_8_0_fe_verify(r);
#endif
}

SECP256K1_INLINE static int rustsecp256k1_v0_8_0_fe_is_zero(const rustsecp256k1_v0_8_0_fe *a) {
    const uint64_t *t = a->n;
#ifdef VERIFY
    VERIFY_CHECK(a->normalized);
    rustsecp256k1_v0_8_0_fe_verify(a);
#endif
    return (t[0] | t[1] | t[2] | t[3] | t[4]) == 0;
}

SECP256K1_INLINE static int rustsecp256k1_v0_8_0_fe_is_odd(const rustsecp256k1_v0_8_0_fe *a) {
#ifdef VERIFY
    VERIFY_CHECK(a->normalized);
    rustsecp256k1_v0_8_0_fe_verify(a);
#endif
    return a->n[0] & 1;
}

SECP256K1_INLINE static void rustsecp256k1_v0_8_0_fe_clear(rustsecp256k1_v0_8_0_fe *a) {
    int i;
#ifdef VERIFY
    a->magnitude = 0;
    a->normalized = 1;
#endif
    for (i=0; i<5; i++) {
        a->n[i] = 0;
    }
}

static int rustsecp256k1_v0_8_0_fe_cmp_var(const rustsecp256k1_v0_8_0_fe *a, const rustsecp256k1_v0_8_0_fe *b) {
    int i;
#ifdef VERIFY
    VERIFY_CHECK(a->normalized);
    VERIFY_CHECK(b->normalized);
    rustsecp256k1_v0_8_0_fe_verify(a);
    rustsecp256k1_v0_8_0_fe_verify(b);
#endif
    for (i = 4; i >= 0; i--) {
        if (a->n[i] > b->n[i]) {
            return 1;
        }
        if (a->n[i] < b->n[i]) {
            return -1;
        }
    }
    return 0;
}

static int rustsecp256k1_v0_8_0_fe_set_b32(rustsecp256k1_v0_8_0_fe *r, const unsigned char *a) {
    int ret;
    r->n[0] = (uint64_t)a[31]
            | ((uint64_t)a[30] << 8)
            | ((uint64_t)a[29] << 16)
            | ((uint64_t)a[28] << 24)
            | ((uint64_t)a[27] << 32)
            | ((uint64_t)a[26] << 40)
            | ((uint64_t)(a[25] & 0xF)  << 48);
    r->n[1] = (uint64_t)((a[25] >> 4) & 0xF)
            | ((uint64_t)a[24] << 4)
            | ((uint64_t)a[23] << 12)
            | ((uint64_t)a[22] << 20)
            | ((uint64_t)a[21] << 28)
            | ((uint64_t)a[20] << 36)
            | ((uint64_t)a[19] << 44);
    r->n[2] = (uint64_t)a[18]
            | ((uint64_t)a[17] << 8)
            | ((uint64_t)a[16] << 16)
            | ((uint64_t)a[15] << 24)
            | ((uint64_t)a[14] << 32)
            | ((uint64_t)a[13] << 40)
            | ((uint64_t)(a[12] & 0xF) << 48);
    r->n[3] = (uint64_t)((a[12] >> 4) & 0xF)
            | ((uint64_t)a[11] << 4)
            | ((uint64_t)a[10] << 12)
            | ((uint64_t)a[9]  << 20)
            | ((uint64_t)a[8]  << 28)
            | ((uint64_t)a[7]  << 36)
            | ((uint64_t)a[6]  << 44);
    r->n[4] = (uint64_t)a[5]
            | ((uint64_t)a[4] << 8)
            | ((uint64_t)a[3] << 16)
            | ((uint64_t)a[2] << 24)
            | ((uint64_t)a[1] << 32)
            | ((uint64_t)a[0] << 40);
    ret = !((r->n[4] == 0x0FFFFFFFFFFFFULL) & ((r->n[3] & r->n[2] & r->n[1]) == 0xFFFFFFFFFFFFFULL) & (r->n[0] >= 0xFFFFEFFFFFC2FULL));
#ifdef VERIFY
    r->magnitude = 1;
    if (ret) {
        r->normalized = 1;
        rustsecp256k1_v0_8_0_fe_verify(r);
    } else {
        r->normalized = 0;
    }
#endif
    return ret;
}

/** Convert a field element to a 32-byte big endian value. Requires the input to be normalized */
static void rustsecp256k1_v0_8_0_fe_get_b32(unsigned char *r, const rustsecp256k1_v0_8_0_fe *a) {
#ifdef VERIFY
    VERIFY_CHECK(a->normalized);
    rustsecp256k1_v0_8_0_fe_verify(a);
#endif
    r[0] = (a->n[4] >> 40) & 0xFF;
    r[1] = (a->n[4] >> 32) & 0xFF;
    r[2] = (a->n[4] >> 24) & 0xFF;
    r[3] = (a->n[4] >> 16) & 0xFF;
    r[4] = (a->n[4] >> 8) & 0xFF;
    r[5] = a->n[4] & 0xFF;
    r[6] = (a->n[3] >> 44) & 0xFF;
    r[7] = (a->n[3] >> 36) & 0xFF;
    r[8] = (a->n[3] >> 28) & 0xFF;
    r[9] = (a->n[3] >> 20) & 0xFF;
    r[10] = (a->n[3] >> 12) & 0xFF;
    r[11] = (a->n[3] >> 4) & 0xFF;
    r[12] = ((a->n[2] >> 48) & 0xF) | ((a->n[3] & 0xF) << 4);
    r[13] = (a->n[2] >> 40) & 0xFF;
    r[14] = (a->n[2] >> 32) & 0xFF;
    r[15] = (a->n[2] >> 24) & 0xFF;
    r[16] = (a->n[2] >> 16) & 0xFF;
    r[17] = (a->n[2] >> 8) & 0xFF;
    r[18] = a->n[2] & 0xFF;
    r[19] = (a->n[1] >> 44) & 0xFF;
    r[20] = (a->n[1] >> 36) & 0xFF;
    r[21] = (a->n[1] >> 28) & 0xFF;
    r[22] = (a->n[1] >> 20) & 0xFF;
    r[23] = (a->n[1] >> 12) & 0xFF;
    r[24] = (a->n[1] >> 4) & 0xFF;
    r[25] = ((a->n[0] >> 48) & 0xF) | ((a->n[1] & 0xF) << 4);
    r[26] = (a->n[0] >> 40) & 0xFF;
    r[27] = (a->n[0] >> 32) & 0xFF;
    r[28] = (a->n[0] >> 24) & 0xFF;
    r[29] = (a->n[0] >> 16) & 0xFF;
    r[30] = (a->n[0] >> 8) & 0xFF;
    r[31] = a->n[0] & 0xFF;
}

SECP256K1_INLINE static void rustsecp256k1_v0_8_0_fe_negate(rustsecp256k1_v0_8_0_fe *r, const rustsecp256k1_v0_8_0_fe *a, int m) {
#ifdef VERIFY
    VERIFY_CHECK(a->magnitude <= m);
    rustsecp256k1_v0_8_0_fe_verify(a);
    VERIFY_CHECK(0xFFFFEFFFFFC2FULL * 2 * (m + 1) >= 0xFFFFFFFFFFFFFULL * 2 * m);
    VERIFY_CHECK(0xFFFFFFFFFFFFFULL * 2 * (m + 1) >= 0xFFFFFFFFFFFFFULL * 2 * m);
    VERIFY_CHECK(0x0FFFFFFFFFFFFULL * 2 * (m + 1) >= 0x0FFFFFFFFFFFFULL * 2 * m);
#endif
    r->n[0] = 0xFFFFEFFFFFC2FULL * 2 * (m + 1) - a->n[0];
    r->n[1] = 0xFFFFFFFFFFFFFULL * 2 * (m + 1) - a->n[1];
    r->n[2] = 0xFFFFFFFFFFFFFULL * 2 * (m + 1) - a->n[2];
    r->n[3] = 0xFFFFFFFFFFFFFULL * 2 * (m + 1) - a->n[3];
    r->n[4] = 0x0FFFFFFFFFFFFULL * 2 * (m + 1) - a->n[4];
#ifdef VERIFY
    r->magnitude = m + 1;
    r->normalized = 0;
    rustsecp256k1_v0_8_0_fe_verify(r);
#endif
}

SECP256K1_INLINE static void rustsecp256k1_v0_8_0_fe_mul_int(rustsecp256k1_v0_8_0_fe *r, int a) {
    r->n[0] *= a;
    r->n[1] *= a;
    r->n[2] *= a;
    r->n[3] *= a;
    r->n[4] *= a;
#ifdef VERIFY
    r->magnitude *= a;
    r->normalized = 0;
    rustsecp256k1_v0_8_0_fe_verify(r);
#endif
}

SECP256K1_INLINE static void rustsecp256k1_v0_8_0_fe_add(rustsecp256k1_v0_8_0_fe *r, const rustsecp256k1_v0_8_0_fe *a) {
#ifdef VERIFY
    rustsecp256k1_v0_8_0_fe_verify(a);
#endif
    r->n[0] += a->n[0];
    r->n[1] += a->n[1];
    r->n[2] += a->n[2];
    r->n[3] += a->n[3];
    r->n[4] += a->n[4];
#ifdef VERIFY
    r->magnitude += a->magnitude;
    r->normalized = 0;
    rustsecp256k1_v0_8_0_fe_verify(r);
#endif
}

static void rustsecp256k1_v0_8_0_fe_mul(rustsecp256k1_v0_8_0_fe *r, const rustsecp256k1_v0_8_0_fe *a, const rustsecp256k1_v0_8_0_fe * SECP256K1_RESTRICT b) {
#ifdef VERIFY
    VERIFY_CHECK(a->magnitude <= 8);
    VERIFY_CHECK(b->magnitude <= 8);
    rustsecp256k1_v0_8_0_fe_verify(a);
    rustsecp256k1_v0_8_0_fe_verify(b);
    VERIFY_CHECK(r != b);
    VERIFY_CHECK(a != b);
#endif
    rustsecp256k1_v0_8_0_fe_mul_inner(r->n, a->n, b->n);
#ifdef VERIFY
    r->magnitude = 1;
    r->normalized = 0;
    rustsecp256k1_v0_8_0_fe_verify(r);
#endif
}

static void rustsecp256k1_v0_8_0_fe_sqr(rustsecp256k1_v0_8_0_fe *r, const rustsecp256k1_v0_8_0_fe *a) {
#ifdef VERIFY
    VERIFY_CHECK(a->magnitude <= 8);
    rustsecp256k1_v0_8_0_fe_verify(a);
#endif
    rustsecp256k1_v0_8_0_fe_sqr_inner(r->n, a->n);
#ifdef VERIFY
    r->magnitude = 1;
    r->normalized = 0;
    rustsecp256k1_v0_8_0_fe_verify(r);
#endif
}

static SECP256K1_INLINE void rustsecp256k1_v0_8_0_fe_cmov(rustsecp256k1_v0_8_0_fe *r, const rustsecp256k1_v0_8_0_fe *a, int flag) {
    uint64_t mask0, mask1;
    VG_CHECK_VERIFY(r->n, sizeof(r->n));
    mask0 = flag + ~((uint64_t)0);
    mask1 = ~mask0;
    r->n[0] = (r->n[0] & mask0) | (a->n[0] & mask1);
    r->n[1] = (r->n[1] & mask0) | (a->n[1] & mask1);
    r->n[2] = (r->n[2] & mask0) | (a->n[2] & mask1);
    r->n[3] = (r->n[3] & mask0) | (a->n[3] & mask1);
    r->n[4] = (r->n[4] & mask0) | (a->n[4] & mask1);
#ifdef VERIFY
    if (flag) {
        r->magnitude = a->magnitude;
        r->normalized = a->normalized;
    }
#endif
}

static SECP256K1_INLINE void rustsecp256k1_v0_8_0_fe_half(rustsecp256k1_v0_8_0_fe *r) {
    uint64_t t0 = r->n[0], t1 = r->n[1], t2 = r->n[2], t3 = r->n[3], t4 = r->n[4];
    uint64_t one = (uint64_t)1;
    uint64_t mask = -(t0 & one) >> 12;

#ifdef VERIFY
    rustsecp256k1_v0_8_0_fe_verify(r);
    VERIFY_CHECK(r->magnitude < 32);
#endif

    /* Bounds analysis (over the rationals).
     *
     * Let m = r->magnitude
     *     C = 0xFFFFFFFFFFFFFULL * 2
     *     D = 0x0FFFFFFFFFFFFULL * 2
     *
     * Initial bounds: t0..t3 <= C * m
     *                     t4 <= D * m
     */

    t0 += 0xFFFFEFFFFFC2FULL & mask;
    t1 += mask;
    t2 += mask;
    t3 += mask;
    t4 += mask >> 4;

    VERIFY_CHECK((t0 & one) == 0);

    /* t0..t3: added <= C/2
     *     t4: added <= D/2
     *
     * Current bounds: t0..t3 <= C * (m + 1/2)
     *                     t4 <= D * (m + 1/2)
     */

    r->n[0] = (t0 >> 1) + ((t1 & one) << 51);
    r->n[1] = (t1 >> 1) + ((t2 & one) << 51);
    r->n[2] = (t2 >> 1) + ((t3 & one) << 51);
    r->n[3] = (t3 >> 1) + ((t4 & one) << 51);
    r->n[4] = (t4 >> 1);

    /* t0..t3: shifted right and added <= C/4 + 1/2
     *     t4: shifted right
     *
     * Current bounds: t0..t3 <= C * (m/2 + 1/2)
     *                     t4 <= D * (m/2 + 1/4)
     */

#ifdef VERIFY
    /* Therefore the output magnitude (M) has to be set such that:
     *     t0..t3: C * M >= C * (m/2 + 1/2)
     *         t4: D * M >= D * (m/2 + 1/4)
     *
     * It suffices for all limbs that, for any input magnitude m:
     *     M >= m/2 + 1/2
     *
     * and since we want the smallest such integer value for M:
     *     M == floor(m/2) + 1
     */
    r->magnitude = (r->magnitude >> 1) + 1;
    r->normalized = 0;
    rustsecp256k1_v0_8_0_fe_verify(r);
#endif
}

static SECP256K1_INLINE void rustsecp256k1_v0_8_0_fe_storage_cmov(rustsecp256k1_v0_8_0_fe_storage *r, const rustsecp256k1_v0_8_0_fe_storage *a, int flag) {
    uint64_t mask0, mask1;
    VG_CHECK_VERIFY(r->n, sizeof(r->n));
    mask0 = flag + ~((uint64_t)0);
    mask1 = ~mask0;
    r->n[0] = (r->n[0] & mask0) | (a->n[0] & mask1);
    r->n[1] = (r->n[1] & mask0) | (a->n[1] & mask1);
    r->n[2] = (r->n[2] & mask0) | (a->n[2] & mask1);
    r->n[3] = (r->n[3] & mask0) | (a->n[3] & mask1);
}

static void rustsecp256k1_v0_8_0_fe_to_storage(rustsecp256k1_v0_8_0_fe_storage *r, const rustsecp256k1_v0_8_0_fe *a) {
#ifdef VERIFY
    VERIFY_CHECK(a->normalized);
#endif
    r->n[0] = a->n[0] | a->n[1] << 52;
    r->n[1] = a->n[1] >> 12 | a->n[2] << 40;
    r->n[2] = a->n[2] >> 24 | a->n[3] << 28;
    r->n[3] = a->n[3] >> 36 | a->n[4] << 16;
}

static SECP256K1_INLINE void rustsecp256k1_v0_8_0_fe_from_storage(rustsecp256k1_v0_8_0_fe *r, const rustsecp256k1_v0_8_0_fe_storage *a) {
    r->n[0] = a->n[0] & 0xFFFFFFFFFFFFFULL;
    r->n[1] = a->n[0] >> 52 | ((a->n[1] << 12) & 0xFFFFFFFFFFFFFULL);
    r->n[2] = a->n[1] >> 40 | ((a->n[2] << 24) & 0xFFFFFFFFFFFFFULL);
    r->n[3] = a->n[2] >> 28 | ((a->n[3] << 36) & 0xFFFFFFFFFFFFFULL);
    r->n[4] = a->n[3] >> 16;
#ifdef VERIFY
    r->magnitude = 1;
    r->normalized = 1;
    rustsecp256k1_v0_8_0_fe_verify(r);
#endif
}

static void rustsecp256k1_v0_8_0_fe_from_signed62(rustsecp256k1_v0_8_0_fe *r, const rustsecp256k1_v0_8_0_modinv64_signed62 *a) {
    const uint64_t M52 = UINT64_MAX >> 12;
    const uint64_t a0 = a->v[0], a1 = a->v[1], a2 = a->v[2], a3 = a->v[3], a4 = a->v[4];

    /* The output from rustsecp256k1_v0_8_0_modinv64{_var} should be normalized to range [0,modulus), and
     * have limbs in [0,2^62). The modulus is < 2^256, so the top limb must be below 2^(256-62*4).
     */
    VERIFY_CHECK(a0 >> 62 == 0);
    VERIFY_CHECK(a1 >> 62 == 0);
    VERIFY_CHECK(a2 >> 62 == 0);
    VERIFY_CHECK(a3 >> 62 == 0);
    VERIFY_CHECK(a4 >> 8 == 0);

    r->n[0] =  a0                   & M52;
    r->n[1] = (a0 >> 52 | a1 << 10) & M52;
    r->n[2] = (a1 >> 42 | a2 << 20) & M52;
    r->n[3] = (a2 >> 32 | a3 << 30) & M52;
    r->n[4] = (a3 >> 22 | a4 << 40);

#ifdef VERIFY
    r->magnitude = 1;
    r->normalized = 1;
    rustsecp256k1_v0_8_0_fe_verify(r);
#endif
}

static void rustsecp256k1_v0_8_0_fe_to_signed62(rustsecp256k1_v0_8_0_modinv64_signed62 *r, const rustsecp256k1_v0_8_0_fe *a) {
    const uint64_t M62 = UINT64_MAX >> 2;
    const uint64_t a0 = a->n[0], a1 = a->n[1], a2 = a->n[2], a3 = a->n[3], a4 = a->n[4];

#ifdef VERIFY
    VERIFY_CHECK(a->normalized);
#endif

    r->v[0] = (a0       | a1 << 52) & M62;
    r->v[1] = (a1 >> 10 | a2 << 42) & M62;
    r->v[2] = (a2 >> 20 | a3 << 32) & M62;
    r->v[3] = (a3 >> 30 | a4 << 22) & M62;
    r->v[4] =  a4 >> 40;
}

static const rustsecp256k1_v0_8_0_modinv64_modinfo rustsecp256k1_v0_8_0_const_modinfo_fe = {
    {{-0x1000003D1LL, 0, 0, 0, 256}},
    0x27C7F6E22DDACACFLL
};

static void rustsecp256k1_v0_8_0_fe_inv(rustsecp256k1_v0_8_0_fe *r, const rustsecp256k1_v0_8_0_fe *x) {
    rustsecp256k1_v0_8_0_fe tmp;
    rustsecp256k1_v0_8_0_modinv64_signed62 s;

    tmp = *x;
    rustsecp256k1_v0_8_0_fe_normalize(&tmp);
    rustsecp256k1_v0_8_0_fe_to_signed62(&s, &tmp);
    rustsecp256k1_v0_8_0_modinv64(&s, &rustsecp256k1_v0_8_0_const_modinfo_fe);
    rustsecp256k1_v0_8_0_fe_from_signed62(r, &s);

#ifdef VERIFY
    VERIFY_CHECK(rustsecp256k1_v0_8_0_fe_normalizes_to_zero(r) == rustsecp256k1_v0_8_0_fe_normalizes_to_zero(&tmp));
#endif
}

static void rustsecp256k1_v0_8_0_fe_inv_var(rustsecp256k1_v0_8_0_fe *r, const rustsecp256k1_v0_8_0_fe *x) {
    rustsecp256k1_v0_8_0_fe tmp;
    rustsecp256k1_v0_8_0_modinv64_signed62 s;

    tmp = *x;
    rustsecp256k1_v0_8_0_fe_normalize_var(&tmp);
    rustsecp256k1_v0_8_0_fe_to_signed62(&s, &tmp);
    rustsecp256k1_v0_8_0_modinv64_var(&s, &rustsecp256k1_v0_8_0_const_modinfo_fe);
    rustsecp256k1_v0_8_0_fe_from_signed62(r, &s);

#ifdef VERIFY
    VERIFY_CHECK(rustsecp256k1_v0_8_0_fe_normalizes_to_zero(r) == rustsecp256k1_v0_8_0_fe_normalizes_to_zero(&tmp));
#endif
}

#endif /* SECP256K1_FIELD_REPR_IMPL_H */

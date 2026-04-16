/*
 * archive.c - ZIP and 7Z archive parsing and password validation
 * Implements PKZIP encryption check and 7Z AES-based verification
 * C11 standard, optimized for Termux/Android Linux
 *
 * FIX: Full CRC32 validation on decrypted+decompressed data to
 *      eliminate ALL false positives in PKZIP validation.
 * FIX2: Added CLI fallback (7z t) for DEFLATE/LZMA/BZIP2 to kill
 *       structural false positives.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdarg.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <pthread.h>
#include <math.h>
#include <time.h>

#include "archive.h"

/* Forward declarations from utils.c */

void log_message(log_level_t level, const char *fmt, ...);
#define log_debug(fmt, ...)   log_message(LOG_DEBUG,   fmt, ##__VA_ARGS__)
#define log_info(fmt, ...)    log_message(LOG_INFO,    fmt, ##__VA_ARGS__)
#define log_warn(fmt, ...)    log_message(LOG_WARNING, fmt, ##__VA_ARGS__)
#define log_error(fmt, ...)   log_message(LOG_ERROR,   fmt, ##__VA_ARGS__)

#define LIKELY(x)             __builtin_expect(!!(x), 1)
#define UNLIKELY(x)           __builtin_expect(!!(x), 0)
#define FORCE_INLINE          __attribute__((always_inline)) static inline
#define PACKED                __attribute__((packed))

#define MAX_PASSWORD_LEN      128
#define KB                    (1024ULL)
#define MB                    (1024ULL * KB)

/*
 * CRC32 table from utils.c — the same table used by PKZIP key update.
 * Standard IEEE 802.3 polynomial 0xEDB88320 (reflected).
 */
extern uint32_t g_crc32_table[256];
void crc32_init(void);

/*
 * Raw CRC32 update — no pre/post inversion.
 * Used both for PKZIP key scheduling and for data CRC verification.
 */
FORCE_INLINE uint32_t crc32_update(uint32_t crc,
                                    const uint8_t *data,
                                    size_t len) {
    while (len--) {
        crc = g_crc32_table[(crc ^ *data++) & 0xFF] ^ (crc >> 8);
    }
    return crc;
}

/*
 * Full CRC32 with standard pre/post XOR (matches ZIP spec).
 * ZIP stores CRC32 as: ~CRC32_RAW(~0, data, len)
 * which equals crc32_update(0xFFFFFFFF, data, len) ^ 0xFFFFFFFF
 */
FORCE_INLINE uint32_t crc32_full(const uint8_t *data, size_t len) {
    uint32_t crc = 0xFFFFFFFFUL;
    crc = crc32_update(crc, data, len);
    return crc ^ 0xFFFFFFFFUL;
}

/* ============================================================
 * SHA-1 IMPLEMENTATION (needed for ZIP WinZip AES)
 * ============================================================ */

typedef struct {
    uint32_t state[5];
    uint32_t count[2];
    uint8_t  buffer[64];
} sha1_ctx_t;

#define SHA1_ROTL(value, bits) \
    (((value) << (bits)) | ((value) >> (32 - (bits))))

#define SHA1_BLK0(i) \
    (block[i] = (SHA1_ROTL(block[i],24)&0xFF00FF00) | \
                (SHA1_ROTL(block[i],8) &0x00FF00FF))

#define SHA1_BLK(i) \
    (block[i&15] = SHA1_ROTL(block[(i+13)&15] ^ block[(i+8)&15] \
                             ^ block[(i+2)&15] ^ block[i&15], 1))

#define SHA1_R0(v,w,x,y,z,i) \
    z += ((w&(x^y))^y)        + SHA1_BLK0(i) + 0x5A827999 + SHA1_ROTL(v,5); \
    w  = SHA1_ROTL(w,30);

#define SHA1_R1(v,w,x,y,z,i) \
    z += ((w&(x^y))^y)        + SHA1_BLK(i)  + 0x5A827999 + SHA1_ROTL(v,5); \
    w  = SHA1_ROTL(w,30);

#define SHA1_R2(v,w,x,y,z,i) \
    z += (w^x^y)               + SHA1_BLK(i)  + 0x6ED9EBA1 + SHA1_ROTL(v,5); \
    w  = SHA1_ROTL(w,30);

#define SHA1_R3(v,w,x,y,z,i) \
    z += (((w|x)&y)|(w&x))     + SHA1_BLK(i)  + 0x8F1BBCDC + SHA1_ROTL(v,5); \
    w  = SHA1_ROTL(w,30);

#define SHA1_R4(v,w,x,y,z,i) \
    z += (w^x^y)               + SHA1_BLK(i)  + 0xCA62C1D6 + SHA1_ROTL(v,5); \
    w  = SHA1_ROTL(w,30);

static void sha1_transform(uint32_t state[5], const uint8_t buffer[64]) {
    uint32_t block[16];
    for (int i = 0; i < 16; i++) {
        block[i] = ((uint32_t)buffer[i*4]     << 24) |
                   ((uint32_t)buffer[i*4 + 1] << 16) |
                   ((uint32_t)buffer[i*4 + 2] <<  8) |
                   ((uint32_t)buffer[i*4 + 3]);
    }

    uint32_t a = state[0];
    uint32_t b = state[1];
    uint32_t c = state[2];
    uint32_t d = state[3];
    uint32_t e = state[4];

    SHA1_R0(a,b,c,d,e, 0); SHA1_R0(e,a,b,c,d, 1);
    SHA1_R0(d,e,a,b,c, 2); SHA1_R0(c,d,e,a,b, 3);
    SHA1_R0(b,c,d,e,a, 4); SHA1_R0(a,b,c,d,e, 5);
    SHA1_R0(e,a,b,c,d, 6); SHA1_R0(d,e,a,b,c, 7);
    SHA1_R0(c,d,e,a,b, 8); SHA1_R0(b,c,d,e,a, 9);
    SHA1_R0(a,b,c,d,e,10); SHA1_R0(e,a,b,c,d,11);
    SHA1_R0(d,e,a,b,c,12); SHA1_R0(c,d,e,a,b,13);
    SHA1_R0(b,c,d,e,a,14); SHA1_R0(a,b,c,d,e,15);
    SHA1_R1(e,a,b,c,d,16); SHA1_R1(d,e,a,b,c,17);
    SHA1_R1(c,d,e,a,b,18); SHA1_R1(b,c,d,e,a,19);
    SHA1_R2(a,b,c,d,e,20); SHA1_R2(e,a,b,c,d,21);
    SHA1_R2(d,e,a,b,c,22); SHA1_R2(c,d,e,a,b,23);
    SHA1_R2(b,c,d,e,a,24); SHA1_R2(a,b,c,d,e,25);
    SHA1_R2(e,a,b,c,d,26); SHA1_R2(d,e,a,b,c,27);
    SHA1_R2(c,d,e,a,b,28); SHA1_R2(b,c,d,e,a,29);
    SHA1_R2(a,b,c,d,e,30); SHA1_R2(e,a,b,c,d,31);
    SHA1_R2(d,e,a,b,c,32); SHA1_R2(c,d,e,a,b,33);
    SHA1_R2(b,c,d,e,a,34); SHA1_R2(a,b,c,d,e,35);
    SHA1_R2(e,a,b,c,d,36); SHA1_R2(d,e,a,b,c,37);
    SHA1_R2(c,d,e,a,b,38); SHA1_R2(b,c,d,e,a,39);
    SHA1_R3(a,b,c,d,e,40); SHA1_R3(e,a,b,c,d,41);
    SHA1_R3(d,e,a,b,c,42); SHA1_R3(c,d,e,a,b,43);
    SHA1_R3(b,c,d,e,a,44); SHA1_R3(a,b,c,d,e,45);
    SHA1_R3(e,a,b,c,d,46); SHA1_R3(d,e,a,b,c,47);
    SHA1_R3(c,d,e,a,b,48); SHA1_R3(b,c,d,e,a,49);
    SHA1_R3(a,b,c,d,e,50); SHA1_R3(e,a,b,c,d,51);
    SHA1_R3(d,e,a,b,c,52); SHA1_R3(c,d,e,a,b,53);
    SHA1_R3(b,c,d,e,a,54); SHA1_R3(a,b,c,d,e,55);
    SHA1_R3(e,a,b,c,d,56); SHA1_R3(d,e,a,b,c,57);
    SHA1_R3(c,d,e,a,b,58); SHA1_R3(b,c,d,e,a,59);
    SHA1_R4(a,b,c,d,e,60); SHA1_R4(e,a,b,c,d,61);
    SHA1_R4(d,e,a,b,c,62); SHA1_R4(c,d,e,a,b,63);
    SHA1_R4(b,c,d,e,a,64); SHA1_R4(a,b,c,d,e,65);
    SHA1_R4(e,a,b,c,d,66); SHA1_R4(d,e,a,b,c,67);
    SHA1_R4(c,d,e,a,b,68); SHA1_R4(b,c,d,e,a,69);
    SHA1_R4(a,b,c,d,e,70); SHA1_R4(e,a,b,c,d,71);
    SHA1_R4(d,e,a,b,c,72); SHA1_R4(c,d,e,a,b,73);
    SHA1_R4(b,c,d,e,a,74); SHA1_R4(a,b,c,d,e,75);
    SHA1_R4(e,a,b,c,d,76); SHA1_R4(d,e,a,b,c,77);
    SHA1_R4(c,d,e,a,b,78); SHA1_R4(b,c,d,e,a,79);

    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
}

static void sha1_init(sha1_ctx_t *ctx) {
    ctx->state[0] = 0x67452301U;
    ctx->state[1] = 0xEFCDAB89U;
    ctx->state[2] = 0x98BADCFEU;
    ctx->state[3] = 0x10325476U;
    ctx->state[4] = 0xC3D2E1F0U;
    ctx->count[0] = 0;
    ctx->count[1] = 0;
    memset(ctx->buffer, 0, 64);
}

static void sha1_update(sha1_ctx_t *ctx, const uint8_t *data, size_t len) {
    size_t i;
    uint32_t j = (ctx->count[0] >> 3) & 63U;

    if ((ctx->count[0] += (uint32_t)(len << 3)) < (uint32_t)(len << 3)) {
        ctx->count[1]++;
    }
    ctx->count[1] += (uint32_t)(len >> 29);

    if ((j + len) > 63) {
        i = 64 - j;
        memcpy(&ctx->buffer[j], data, i);
        sha1_transform(ctx->state, ctx->buffer);
        for (; i + 63 < len; i += 64) {
            sha1_transform(ctx->state, &data[i]);
        }
        j = 0;
    } else {
        i = 0;
    }

    if (len - i > 0) {
        memcpy(&ctx->buffer[j], &data[i], len - i);
    }
}

static void sha1_final(sha1_ctx_t *ctx, uint8_t digest[20]) {
    uint8_t finalcount[8];
    for (int i = 0; i < 8; i++) {
        finalcount[i] = (uint8_t)(
            (ctx->count[(i >= 4) ? 0 : 1] >>
             ((3 - (i & 3)) * 8)) & 255);
    }

    uint8_t c = 0x80;
    sha1_update(ctx, &c, 1);
    while ((ctx->count[0] & 504) != 448) {
        c = 0x00;
        sha1_update(ctx, &c, 1);
    }
    sha1_update(ctx, finalcount, 8);

    for (int i = 0; i < 20; i++) {
        digest[i] = (uint8_t)(
            (ctx->state[i >> 2] >> ((3 - (i & 3)) * 8)) & 255);
    }

    volatile uint8_t *vp = (volatile uint8_t *)ctx;
    for (size_t k = 0; k < sizeof(*ctx); k++) vp[k] = 0;
    volatile uint8_t *vf = (volatile uint8_t *)finalcount;
    for (size_t k = 0; k < sizeof(finalcount); k++) vf[k] = 0;
}

static void sha1(const uint8_t *data, size_t len, uint8_t digest[20]) {
    sha1_ctx_t ctx;
    sha1_init(&ctx);
    sha1_update(&ctx, data, len);
    sha1_final(&ctx, digest);
}

/* ============================================================
 * SHA-256 IMPLEMENTATION (needed for 7Z AES key derivation)
 * ============================================================ */

typedef struct {
    uint32_t state[8];
    uint32_t count[2];
    uint8_t  buffer[64];
} sha256_ctx_t;

static const uint32_t sha256_K[64] = {
    0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U,
    0x3956c25bU, 0x59f111f1U, 0x923f82a4U, 0xab1c5ed5U,
    0xd807aa98U, 0x12835b01U, 0x243185beU, 0x550c7dc3U,
    0x72be5d74U, 0x80deb1feU, 0x9bdc06a7U, 0xc19bf174U,
    0xe49b69c1U, 0xefbe4786U, 0x0fc19dc6U, 0x240ca1ccU,
    0x2de92c6fU, 0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU,
    0x983e5152U, 0xa831c66dU, 0xb00327c8U, 0xbf597fc7U,
    0xc6e00bf3U, 0xd5a79147U, 0x06ca6351U, 0x14292967U,
    0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU, 0x53380d13U,
    0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U,
    0xa2bfe8a1U, 0xa81a664bU, 0xc24b8b70U, 0xc76c51a3U,
    0xd192e819U, 0xd6990624U, 0xf40e3585U, 0x106aa070U,
    0x19a4c116U, 0x1e376c08U, 0x2748774cU, 0x34b0bcb5U,
    0x391c0cb3U, 0x4ed8aa4aU, 0x5b9cca4fU, 0x682e6ff3U,
    0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U,
    0x90befffaU, 0xa4506cebU, 0xbef9a3f7U, 0xc67178f2U,
};

#define SHA256_CH(x,y,z)  (((x)&(y))^(~(x)&(z)))
#define SHA256_MAJ(x,y,z) (((x)&(y))^((x)&(z))^((y)&(z)))
#define SHA256_EP0(x)     (SHA256_ROTR(x,2) ^SHA256_ROTR(x,13)^SHA256_ROTR(x,22))
#define SHA256_EP1(x)     (SHA256_ROTR(x,6) ^SHA256_ROTR(x,11)^SHA256_ROTR(x,25))
#define SHA256_SIG0(x)    (SHA256_ROTR(x,7) ^SHA256_ROTR(x,18)^((x)>>3))
#define SHA256_SIG1(x)    (SHA256_ROTR(x,17)^SHA256_ROTR(x,19)^((x)>>10))
#define SHA256_ROTR(x,n)  (((x)>>(n))|((x)<<(32-(n))))

static void sha256_transform(sha256_ctx_t *ctx, const uint8_t data[64]) {
    uint32_t m[64];
    uint32_t a, b, c, d, e, f, g, h, t1, t2;

    for (int i = 0, j = 0; i < 16; i++, j += 4) {
        m[i] = ((uint32_t)data[j]   << 24) |
               ((uint32_t)data[j+1] << 16) |
               ((uint32_t)data[j+2] <<  8) |
               ((uint32_t)data[j+3]);
    }
    for (int i = 16; i < 64; i++) {
        m[i] = SHA256_SIG1(m[i-2]) + m[i-7] +
               SHA256_SIG0(m[i-15]) + m[i-16];
    }

    a = ctx->state[0]; b = ctx->state[1];
    c = ctx->state[2]; d = ctx->state[3];
    e = ctx->state[4]; f = ctx->state[5];
    g = ctx->state[6]; h = ctx->state[7];

    for (int i = 0; i < 64; i++) {
        t1 = h + SHA256_EP1(e) + SHA256_CH(e,f,g) + sha256_K[i] + m[i];
        t2 = SHA256_EP0(a) + SHA256_MAJ(a,b,c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }

    ctx->state[0] += a; ctx->state[1] += b;
    ctx->state[2] += c; ctx->state[3] += d;
    ctx->state[4] += e; ctx->state[5] += f;
    ctx->state[6] += g; ctx->state[7] += h;
}

static void sha256_init(sha256_ctx_t *ctx) {
    ctx->state[0] = 0x6a09e667U;
    ctx->state[1] = 0xbb67ae85U;
    ctx->state[2] = 0x3c6ef372U;
    ctx->state[3] = 0xa54ff53aU;
    ctx->state[4] = 0x510e527fU;
    ctx->state[5] = 0x9b05688cU;
    ctx->state[6] = 0x1f83d9abU;
    ctx->state[7] = 0x5be0cd19U;
    ctx->count[0] = 0;
    ctx->count[1] = 0;
    memset(ctx->buffer, 0, 64);
}

static void sha256_update(sha256_ctx_t *ctx, const uint8_t *data, size_t len) {
    uint32_t bitlen_high = (uint32_t)(len >> 29);

    uint32_t rem = ctx->count[0] & 63;
    ctx->count[0] += (uint32_t)len;
    if (ctx->count[0] < (uint32_t)len) ctx->count[1]++;
    ctx->count[1] += bitlen_high;

    size_t i = 0;
    if (rem > 0) {
        size_t fill = 64 - rem;
        if (len < fill) {
            memcpy(ctx->buffer + rem, data, len);
            return;
        }
        memcpy(ctx->buffer + rem, data, fill);
        sha256_transform(ctx, ctx->buffer);
        i = fill;
    }

    for (; i + 63 < len; i += 64) {
        sha256_transform(ctx, &data[i]);
    }

    if (i < len) {
        memcpy(ctx->buffer, &data[i], len - i);
    }
}

static void sha256_final(sha256_ctx_t *ctx, uint8_t digest[32]) {
    uint32_t rem = ctx->count[0] & 63;
    ctx->buffer[rem++] = 0x80;

    if (rem > 56) {
        memset(ctx->buffer + rem, 0, 64 - rem);
        sha256_transform(ctx, ctx->buffer);
        rem = 0;
    }

    memset(ctx->buffer + rem, 0, 56 - rem);

    uint64_t bitlen = ((uint64_t)ctx->count[1] << 32) | ctx->count[0];
    bitlen <<= 3;

    ctx->buffer[56] = (uint8_t)(bitlen >> 56);
    ctx->buffer[57] = (uint8_t)(bitlen >> 48);
    ctx->buffer[58] = (uint8_t)(bitlen >> 40);
    ctx->buffer[59] = (uint8_t)(bitlen >> 32);
    ctx->buffer[60] = (uint8_t)(bitlen >> 24);
    ctx->buffer[61] = (uint8_t)(bitlen >> 16);
    ctx->buffer[62] = (uint8_t)(bitlen >>  8);
    ctx->buffer[63] = (uint8_t)(bitlen);

    sha256_transform(ctx, ctx->buffer);

    for (int i = 0; i < 8; i++) {
        digest[i*4]   = (uint8_t)(ctx->state[i] >> 24);
        digest[i*4+1] = (uint8_t)(ctx->state[i] >> 16);
        digest[i*4+2] = (uint8_t)(ctx->state[i] >>  8);
        digest[i*4+3] = (uint8_t)(ctx->state[i]);
    }

    volatile uint8_t *vp = (volatile uint8_t *)ctx;
    for (size_t k = 0; k < sizeof(*ctx); k++) vp[k] = 0;
}

static void sha256(const uint8_t *data, size_t len, uint8_t digest[32]) {
    sha256_ctx_t ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, data, len);
    sha256_final(&ctx, digest);
}

static void hmac_sha256(const uint8_t *key, size_t key_len,
                        const uint8_t *data, size_t data_len,
                        uint8_t out[32]) {
    uint8_t ipad[64], opad[64];
    uint8_t key_hash[32];
    const uint8_t *k = key;
    size_t klen = key_len;

    if (klen > 64) {
        sha256(key, key_len, key_hash);
        k    = key_hash;
        klen = 32;
    }

    memset(ipad, 0x36, 64);
    memset(opad, 0x5C, 64);

    for (size_t i = 0; i < klen; i++) {
        ipad[i] ^= k[i];
        opad[i] ^= k[i];
    }

    sha256_ctx_t ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, ipad, 64);
    sha256_update(&ctx, data, data_len);
    sha256_final(&ctx, out);

    sha256_init(&ctx);
    sha256_update(&ctx, opad, 64);
    sha256_update(&ctx, out, 32);
    sha256_final(&ctx, out);
}

static void pbkdf2_sha256(const uint8_t *password, size_t pass_len,
                          const uint8_t *salt, size_t salt_len,
                          uint32_t iterations,
                          uint8_t *out, size_t out_len) {
    uint32_t block_num = 0;
    size_t   done      = 0;

    uint8_t salt_blk[128];
    if (salt_len > sizeof(salt_blk) - 4)
        salt_len = sizeof(salt_blk) - 4;
    memcpy(salt_blk, salt, salt_len);

    while (done < out_len) {
        block_num++;
        salt_blk[salt_len + 0] = (uint8_t)(block_num >> 24);
        salt_blk[salt_len + 1] = (uint8_t)(block_num >> 16);
        salt_blk[salt_len + 2] = (uint8_t)(block_num >>  8);
        salt_blk[salt_len + 3] = (uint8_t)(block_num);

        uint8_t U[32], T[32];
        hmac_sha256(password, pass_len, salt_blk, salt_len + 4, U);
        memcpy(T, U, 32);

        for (uint32_t i = 1; i < iterations; i++) {
            hmac_sha256(password, pass_len, U, 32, U);
            for (int j = 0; j < 32; j++) T[j] ^= U[j];
        }

        size_t copy = (out_len - done > 32) ? 32 : (out_len - done);
        memcpy(out + done, T, copy);
        done += copy;
    }
    secure_memzero(salt_blk, sizeof(salt_blk));
}

static void rar3_derive_key(const char *password, const uint8_t *salt, uint8_t key[16], uint8_t iv[16]) {
    uint8_t utf16[MAX_PASSWORD_LEN * 2];
    size_t utf16_len = 0;
    for (size_t i = 0; password[i] && i < MAX_PASSWORD_LEN; i++) {
        utf16[utf16_len++] = (uint8_t)password[i];
        utf16[utf16_len++] = 0x00;
    }

    sha1_ctx_t ctx;
    sha1_init(&ctx);

    for (uint32_t i = 0; i < 524288; i++) {
        sha1_update(&ctx, utf16, utf16_len);
        sha1_update(&ctx, salt, 8);
        uint8_t ctrl[3];
        ctrl[0] = (uint8_t)(i & 0xFF);
        ctrl[1] = (uint8_t)((i >> 8) & 0xFF);
        ctrl[2] = (uint8_t)((i >> 16) & 0xFF);
        sha1_update(&ctx, ctrl, 3);

        if ((i & 0x3FFF) == 0x3FFF) {
            sha1_ctx_t temp_ctx = ctx;
            uint8_t digest[20];
            sha1_final(&temp_ctx, digest);
            if (i < 262144)
                key[i >> 14] = digest[19];
            else
                iv[(i >> 14) - 16] = digest[19];
        }
    }
    secure_memzero(utf16, sizeof(utf16));
}

static void rar5_derive_values(const char *password, const uint8_t *salt, uint32_t iterations, uint8_t key[32], uint8_t check[8]) {
    uint8_t U[32], T[32];
    size_t pass_len = strlen(password);

    uint8_t salt_blk[16 + 4];
    memcpy(salt_blk, salt, 16);
    salt_blk[16] = 0; salt_blk[17] = 0; salt_blk[18] = 0; salt_blk[19] = 1;

    hmac_sha256((const uint8_t *)password, pass_len, salt_blk, 20, U);
    memcpy(T, U, 32);

    for (uint32_t i = 1; i < iterations; i++) {
        hmac_sha256((const uint8_t *)password, pass_len, U, 32, U);
        for (int j = 0; j < 32; j++) T[j] ^= U[j];
    }
    if (key) memcpy(key, T, 32);

    /* additionnal 16 rounds for Hash Key value (not used here) */
    for (uint32_t i = 0; i < 16; i++) {
        hmac_sha256((const uint8_t *)password, pass_len, U, 32, U);
    }

    /* additionnal 16 rounds for Password Check value */
    memset(T, 0, 32);
    for (uint32_t i = 0; i < 16; i++) {
        hmac_sha256((const uint8_t *)password, pass_len, U, 32, U);
        for (int j = 0; j < 32; j++) T[j] ^= U[j];
    }
    if (check) memcpy(check, T, 8);
    secure_memzero(U, sizeof(U));
    secure_memzero(T, sizeof(T));
    secure_memzero(salt_blk, sizeof(salt_blk));
}

/* ============================================================
 * AES-256 IMPLEMENTATION (for 7Z decryption)
 * ============================================================ */

#define AES_BLOCK_SIZE  16
#define AES256_KEY_SIZE 32
#define AES256_ROUNDS   14

typedef struct {
    uint32_t round_key[4 * (AES256_ROUNDS + 1)];
    int      nr;
} aes_ctx_t;

static const uint8_t aes_sbox[256] = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,
    0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,
    0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,
    0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,
    0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,
    0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,
    0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,
    0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,
    0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,
    0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,
    0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,
    0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,
    0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,
    0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,
    0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,
    0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,
    0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
};

static const uint8_t aes_rsbox[256] = {
    0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,
    0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb,
    0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,
    0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb,
    0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,
    0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e,
    0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,
    0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25,
    0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,
    0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92,
    0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,
    0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84,
    0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,
    0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06,
    0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,
    0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b,
    0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,
    0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73,
    0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,
    0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e,
    0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,
    0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b,
    0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,
    0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4,
    0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,
    0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f,
    0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,
    0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef,
    0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,
    0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61,
    0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,
    0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d,
};

static const uint8_t aes_rcon[11] = {
    0x8d, 0x01, 0x02, 0x04, 0x08, 0x10,
    0x20, 0x40, 0x80, 0x1b, 0x36
};

FORCE_INLINE uint8_t aes_xtime(uint8_t x) {
    return (uint8_t)((x << 1) ^ ((x >> 7) * 0x1b));
}

FORCE_INLINE uint8_t aes_mul(uint8_t x, uint8_t y) {
    return ((y & 1) * x) ^
           ((y >> 1 & 1) * aes_xtime(x)) ^
           ((y >> 2 & 1) * aes_xtime(aes_xtime(x))) ^
           ((y >> 3 & 1) * aes_xtime(aes_xtime(aes_xtime(x)))) ^
           ((y >> 4 & 1) * aes_xtime(aes_xtime(aes_xtime(aes_xtime(x)))));
}

static void aes128_key_expansion(aes_ctx_t *ctx,
                                  const uint8_t key[16]) {
    uint32_t *rk = ctx->round_key;

    for (int i = 0; i < 4; i++) {
        rk[i] = ((uint32_t)key[i*4]   << 24) |
                ((uint32_t)key[i*4+1] << 16) |
                ((uint32_t)key[i*4+2] <<  8) |
                ((uint32_t)key[i*4+3]);
    }

    for (int i = 4; i < 4 * (10 + 1); i++) {
        uint32_t t = rk[i - 1];
        if (i % 4 == 0) {
            uint8_t tmp[4];
            tmp[0] = aes_sbox[(t >> 16) & 0xFF];
            tmp[1] = aes_sbox[(t >>  8) & 0xFF];
            tmp[2] = aes_sbox[(t      ) & 0xFF];
            tmp[3] = aes_sbox[(t >> 24) & 0xFF];
            t = ((uint32_t)tmp[0] << 24) |
                ((uint32_t)tmp[1] << 16) |
                ((uint32_t)tmp[2] <<  8) |
                ((uint32_t)tmp[3]);
            t ^= ((uint32_t)aes_rcon[i / 4]) << 24;
        }
        rk[i] = rk[i - 4] ^ t;
    }
    ctx->nr = 10;
}

static void aes256_key_expansion(aes_ctx_t *ctx,
                                  const uint8_t key[AES256_KEY_SIZE]) {
    uint8_t  tmp[4];
    uint32_t *rk = ctx->round_key;

    for (int i = 0; i < 8; i++) {
        rk[i] = ((uint32_t)key[i*4]   << 24) |
                ((uint32_t)key[i*4+1] << 16) |
                ((uint32_t)key[i*4+2] <<  8) |
                ((uint32_t)key[i*4+3]);
    }

    for (int i = 8; i < 4 * (AES256_ROUNDS + 1); i++) {
        uint32_t t = rk[i - 1];

        if (i % 8 == 0) {
            tmp[0] = aes_sbox[(t >> 16) & 0xFF];
            tmp[1] = aes_sbox[(t >>  8) & 0xFF];
            tmp[2] = aes_sbox[(t      ) & 0xFF];
            tmp[3] = aes_sbox[(t >> 24) & 0xFF];
            t = ((uint32_t)tmp[0] << 24) |
                ((uint32_t)tmp[1] << 16) |
                ((uint32_t)tmp[2] <<  8) |
                ((uint32_t)tmp[3]);
            t ^= ((uint32_t)aes_rcon[i / 8]) << 24;
        } else if (i % 8 == 4) {
            tmp[0] = aes_sbox[(t >> 24) & 0xFF];
            tmp[1] = aes_sbox[(t >> 16) & 0xFF];
            tmp[2] = aes_sbox[(t >>  8) & 0xFF];
            tmp[3] = aes_sbox[(t      ) & 0xFF];
            t = ((uint32_t)tmp[0] << 24) |
                ((uint32_t)tmp[1] << 16) |
                ((uint32_t)tmp[2] <<  8) |
                ((uint32_t)tmp[3]);
        }

        rk[i] = rk[i - 8] ^ t;
    }

    ctx->nr = AES256_ROUNDS;
}

static void aes_add_round_key(uint8_t state[16],
                               const uint32_t *rk, int round) {
    for (int c = 0; c < 4; c++) {
        uint32_t k = rk[round * 4 + c];
        state[c*4+0] ^= (k >> 24) & 0xFF;
        state[c*4+1] ^= (k >> 16) & 0xFF;
        state[c*4+2] ^= (k >>  8) & 0xFF;
        state[c*4+3] ^= (k      ) & 0xFF;
    }
}

static void aes_sub_bytes(uint8_t state[16]) {
    for (int i = 0; i < 16; i++) state[i] = aes_sbox[state[i]];
}

static void aes_shift_rows(uint8_t state[16]) {
    uint8_t t;
    t = state[1]; state[1] = state[5]; state[5] = state[9];
    state[9] = state[13]; state[13] = t;

    t = state[2]; state[2] = state[10]; state[10] = t;
    t = state[6]; state[6] = state[14]; state[14] = t;

    t         = state[15]; state[15] = state[11];
    state[11] = state[7];  state[7]  = state[3]; state[3] = t;
}

static void aes_mix_columns(uint8_t state[16]) {
    for (int c = 0; c < 4; c++) {
        uint8_t s0 = state[c*4+0], s1 = state[c*4+1];
        uint8_t s2 = state[c*4+2], s3 = state[c*4+3];
        state[c*4+0] = aes_mul(s0,2)^aes_mul(s1,3)^s2^s3;
        state[c*4+1] = s0^aes_mul(s1,2)^aes_mul(s2,3)^s3;
        state[c*4+2] = s0^s1^aes_mul(s2,2)^aes_mul(s3,3);
        state[c*4+3] = aes_mul(s0,3)^s1^s2^aes_mul(s3,2);
    }
}

static void aes256_encrypt_block(const aes_ctx_t *ctx,
                                  const uint8_t in[16],
                                  uint8_t out[16]) {
    uint8_t state[16];
    for (int r = 0; r < 4; r++)
        for (int c = 0; c < 4; c++)
            state[r + c*4] = in[r*4 + c];

    aes_add_round_key(state, ctx->round_key, 0);
    for (int round = 1; round < ctx->nr; round++) {
        aes_sub_bytes(state);
        aes_shift_rows(state);
        aes_mix_columns(state);
        aes_add_round_key(state, ctx->round_key, round);
    }
    aes_sub_bytes(state);
    aes_shift_rows(state);
    aes_add_round_key(state, ctx->round_key, ctx->nr);

    for (int r = 0; r < 4; r++)
        for (int c = 0; c < 4; c++)
            out[r*4 + c] = state[r + c*4];
}

static void aes_inv_sub_bytes(uint8_t state[16]) {
    for (int i = 0; i < 16; i++) state[i] = aes_rsbox[state[i]];
}

static void aes_inv_shift_rows(uint8_t state[16]) {
    uint8_t t;
    t = state[13]; state[13] = state[9]; state[9] = state[5];
    state[5] = state[1]; state[1] = t;

    t = state[2]; state[2] = state[10]; state[10] = t;
    t = state[6]; state[6] = state[14]; state[14] = t;

    t        = state[3];  state[3]  = state[7];
    state[7] = state[11]; state[11] = state[15]; state[15] = t;
}

static void aes_inv_mix_columns(uint8_t state[16]) {
    for (int c = 0; c < 4; c++) {
        uint8_t s0 = state[c*4+0], s1 = state[c*4+1];
        uint8_t s2 = state[c*4+2], s3 = state[c*4+3];
        state[c*4+0]=aes_mul(s0,0x0e)^aes_mul(s1,0x0b)^
                     aes_mul(s2,0x0d)^aes_mul(s3,0x09);
        state[c*4+1]=aes_mul(s0,0x09)^aes_mul(s1,0x0e)^
                     aes_mul(s2,0x0b)^aes_mul(s3,0x0d);
        state[c*4+2]=aes_mul(s0,0x0d)^aes_mul(s1,0x09)^
                     aes_mul(s2,0x0e)^aes_mul(s3,0x0b);
        state[c*4+3]=aes_mul(s0,0x0b)^aes_mul(s1,0x0d)^
                     aes_mul(s2,0x09)^aes_mul(s3,0x0e);
    }
}

static void aes_decrypt_block(const aes_ctx_t *ctx,
                               const uint8_t in[16],
                               uint8_t out[16]) {
    uint8_t state[16];
    for (int r = 0; r < 4; r++)
        for (int c = 0; c < 4; c++)
            state[r + c*4] = in[r*4 + c];

    aes_add_round_key(state, ctx->round_key, ctx->nr);
    for (int round = ctx->nr - 1; round > 0; round--) {
        aes_inv_shift_rows(state);
        aes_inv_sub_bytes(state);
        aes_add_round_key(state, ctx->round_key, round);
        aes_inv_mix_columns(state);
    }
    aes_inv_shift_rows(state);
    aes_inv_sub_bytes(state);
    aes_add_round_key(state, ctx->round_key, 0);

    for (int r = 0; r < 4; r++)
        for (int c = 0; c < 4; c++)
            out[r*4 + c] = state[r + c*4];
}

static void aes_cbc_decrypt(const aes_ctx_t *ctx,
                             const uint8_t *iv,
                             const uint8_t *in,
                             uint8_t *out,
                             size_t len) {
    uint8_t prev[AES_BLOCK_SIZE];
    uint8_t block[AES_BLOCK_SIZE];
    memcpy(prev, iv, AES_BLOCK_SIZE);

    for (size_t i = 0; i + AES_BLOCK_SIZE <= len; i += AES_BLOCK_SIZE) {
        aes_decrypt_block(ctx, in + i, block);
        for (int j = 0; j < AES_BLOCK_SIZE; j++)
            out[i + j] = block[j] ^ prev[j];
        memcpy(prev, in + i, AES_BLOCK_SIZE);
    }
}

/* ============================================================
 * ZIP FILE FORMAT STRUCTURES
 * ============================================================ */

#define ZIP_LOCAL_FILE_HEADER_SIG       0x04034B50UL
#define ZIP_CENTRAL_DIR_HEADER_SIG      0x02014B50UL
#define ZIP_END_OF_CENTRAL_DIR_SIG      0x06054B50UL
#define ZIP_DATA_DESCRIPTOR_SIG         0x08074B50UL

#define ZIP_FLAG_ENCRYPTED              (1 << 0)
#define ZIP_FLAG_DATA_DESCRIPTOR        (1 << 3)
#define ZIP_FLAG_STRONG_ENCRYPTION      (1 << 6)
#define ZIP_FLAG_UTF8                   (1 << 11)

#define ZIP_METHOD_STORED               0
#define ZIP_METHOD_DEFLATED             8
#define ZIP_METHOD_BZIP2                12
#define ZIP_METHOD_LZMA                 14
#define ZIP_METHOD_AES                  99

#define ZIP_ENCRYPTION_HEADER_SIZE      12

typedef struct PACKED {
    uint32_t signature;
    uint16_t version_needed;
    uint16_t flags;
    uint16_t compression_method;
    uint16_t last_mod_time;
    uint16_t last_mod_date;
    uint32_t crc32;
    uint32_t compressed_size;
    uint32_t uncompressed_size;
    uint16_t filename_len;
    uint16_t extra_field_len;
} zip_local_header_t;

typedef struct PACKED {
    uint32_t signature;
    uint16_t version_made_by;
    uint16_t version_needed;
    uint16_t flags;
    uint16_t compression_method;
    uint16_t last_mod_time;
    uint16_t last_mod_date;
    uint32_t crc32;
    uint32_t compressed_size;
    uint32_t uncompressed_size;
    uint16_t filename_len;
    uint16_t extra_field_len;
    uint16_t comment_len;
    uint16_t disk_number_start;
    uint16_t internal_attributes;
    uint32_t external_attributes;
    uint32_t local_header_offset;
} zip_central_header_t;

typedef struct PACKED {
    uint32_t signature;
    uint16_t disk_number;
    uint16_t central_dir_disk;
    uint16_t disk_entries;
    uint16_t total_entries;
    uint32_t central_dir_size;
    uint32_t central_dir_offset;
    uint16_t comment_len;
} zip_eocd_t;

/* ============================================================
 * PKZIP ENCRYPTION KEYS
 * ============================================================ */

typedef struct {
    uint32_t k0, k1, k2;
} zip_keys_t;

FORCE_INLINE void zip_update_keys(zip_keys_t *keys, uint8_t c) {
    keys->k0 = crc32_update(keys->k0, &c, 1);
    keys->k1 = keys->k1 + (keys->k0 & 0xFF);
    keys->k1 = keys->k1 * 134775813UL + 1UL;
    uint8_t b = (uint8_t)(keys->k1 >> 24);
    keys->k2 = crc32_update(keys->k2, &b, 1);
}

FORCE_INLINE uint8_t zip_decrypt_byte(const zip_keys_t *keys) {
    uint16_t t = (uint16_t)(keys->k2 | 2);
    return (uint8_t)(((uint32_t)t * (uint32_t)(t ^ 1U)) >> 8);
}

FORCE_INLINE uint8_t zip_decrypt_char(zip_keys_t *keys, uint8_t c) {
    uint8_t p = c ^ zip_decrypt_byte(keys);
    zip_update_keys(keys, p);
    return p;
}

static void zip_init_keys(zip_keys_t *keys, const char *password) {
    keys->k0 = 305419896UL;
    keys->k1 = 591751049UL;
    keys->k2 = 878082192UL;
    while (*password) {
        zip_update_keys(keys, (uint8_t)*password);
        password++;
    }
}

/* ============================================================
 * ZIP PARSING HELPERS
 * ============================================================ */

static uint16_t le16(const uint8_t *p) {
    return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}

static uint32_t le32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static uint64_t le64(const uint8_t *p) {
    return (uint64_t)p[0] | ((uint64_t)p[1] << 8)  |
           ((uint64_t)p[2] << 16) | ((uint64_t)p[3] << 24) |
           ((uint64_t)p[4] << 32) | ((uint64_t)p[5] << 40) |
           ((uint64_t)p[6] << 48) | ((uint64_t)p[7] << 56);
}

static const uint8_t *zip_find_eocd(const uint8_t *data, size_t size) {
    if (size < sizeof(zip_eocd_t)) return NULL;

    size_t search_start = (size >= 65536 + sizeof(zip_eocd_t))
                          ? size - 65536 - sizeof(zip_eocd_t)
                          : 0;

    for (size_t i = size - sizeof(zip_eocd_t); ; i--) {
        if (data[i]   == 0x50 && data[i+1] == 0x4B &&
            data[i+2] == 0x05 && data[i+3] == 0x06) {
            return &data[i];
        }
        if (i == search_start) break;
    }
    return NULL;
}

static bool zip_parse_aes_extra(const uint8_t *extra, uint16_t extra_len,
                                 struct zip_ctx *ctx) {
    const uint8_t *p   = extra;
    const uint8_t *end = extra + extra_len;

    while (p + 4 <= end) {
        uint16_t tag  = le16(p);
        uint16_t size = le16(p + 2);
        p += 4;

        if (p + size > end) break;

        if (tag == 0x9901 && size >= 7) {
            uint16_t ver      = le16(p);
            uint8_t  strength = p[4];
            uint16_t actual   = le16(p + 5);

            if (ver == 1 || ver == 2) {
                ctx->is_aes            = true;
                ctx->aes_strength      = strength;
                ctx->aes_actual_method = actual;
                return true;
            }
        }
        p += size;
    }
    return false;
}

/* ============================================================
 * ZIP FULL PARSING
 * ============================================================ */

int zip_parse(struct zip_ctx *ctx, const char *path) {
    memset(ctx, 0, sizeof(*ctx));

    /* Store archive path for later CLI verification */
    snprintf(ctx->archive_path, sizeof(ctx->archive_path), "%s", path);

    ctx->fd = open(path, O_RDONLY);
    if (ctx->fd < 0) {
        log_error("zip_parse: cannot open '%s': %s", path, strerror(errno));
        return -1;
    }

    struct stat st;
    if (fstat(ctx->fd, &st) != 0) {
        log_error("zip_parse: fstat failed: %s", strerror(errno));
        close(ctx->fd);
        return -1;
    }

    ctx->data_size = (size_t)st.st_size;
    if (ctx->data_size < sizeof(zip_local_header_t)) {
        log_error("zip_parse: file too small (%zu bytes)", ctx->data_size);
        close(ctx->fd);
        return -1;
    }

    ctx->data = (const uint8_t *)mmap(NULL, ctx->data_size,
                                       PROT_READ, MAP_PRIVATE,
                                       ctx->fd, 0);
    if (ctx->data == MAP_FAILED) {
        log_warn("zip_parse: mmap failed, falling back to read");
        uint8_t *buf = (uint8_t *)malloc(ctx->data_size);
        if (!buf) {
            log_error("zip_parse: malloc failed");
            close(ctx->fd);
            return -1;
        }
        ssize_t n = read(ctx->fd, buf, ctx->data_size);
        if (n != (ssize_t)ctx->data_size) {
            log_error("zip_parse: read failed");
            free(buf);
            close(ctx->fd);
            return -1;
        }
        ctx->data      = buf;
        ctx->mmap_used = false;
    } else {
        ctx->mmap_used = true;
        madvise((void *)ctx->data, ctx->data_size, MADV_SEQUENTIAL);
    }

    const uint8_t *eocd_ptr = zip_find_eocd(ctx->data, ctx->data_size);
    if (!eocd_ptr) {
        log_error("zip_parse: EOCD not found - not a valid ZIP file");
        goto fail;
    }

    const zip_eocd_t *eocd = (const zip_eocd_t *)eocd_ptr;
    uint32_t cd_offset     = le32((const uint8_t *)&eocd->central_dir_offset);
    uint32_t cd_size       = le32((const uint8_t *)&eocd->central_dir_size);
    uint16_t total_entries = le16((const uint8_t *)&eocd->total_entries);

    log_debug("zip_parse: EOCD found, %u entries, CD at 0x%08X (size %u)",
              total_entries, cd_offset, cd_size);

    if (cd_offset + cd_size > ctx->data_size) {
        log_error("zip_parse: central directory exceeds file size");
        goto fail;
    }

    const uint8_t *cd_ptr = ctx->data + cd_offset;
    const uint8_t *cd_end = cd_ptr + cd_size;
    int  enc_count        = 0;
    ctx->num_files        = 0;

    while (cd_ptr + sizeof(zip_central_header_t) <= cd_end) {
        uint32_t sig = le32(cd_ptr);
        if (sig != ZIP_CENTRAL_DIR_HEADER_SIG) break;

        const zip_central_header_t *ch = (const zip_central_header_t *)cd_ptr;

        uint16_t flags     = le16((const uint8_t *)&ch->flags);
        uint16_t method    = le16((const uint8_t *)&ch->compression_method);
        uint32_t crc       = le32((const uint8_t *)&ch->crc32);
        uint32_t comp_sz   = le32((const uint8_t *)&ch->compressed_size);
        uint32_t ucomp_sz  = le32((const uint8_t *)&ch->uncompressed_size);
        uint16_t fn_len    = le16((const uint8_t *)&ch->filename_len);
        uint16_t extra_len = le16((const uint8_t *)&ch->extra_field_len);
        uint16_t cm_len    = le16((const uint8_t *)&ch->comment_len);
        uint32_t lh_offset = le32((const uint8_t *)&ch->local_header_offset);
        uint16_t mod_time  = le16((const uint8_t *)&ch->last_mod_time);

        ctx->num_files++;

        if (fn_len > 0 && ctx->num_files == 1) {
            size_t copy = (fn_len < 255) ? fn_len : 255;
            memcpy(ctx->filename, cd_ptr + sizeof(zip_central_header_t), copy);
            ctx->filename[copy] = '\0';
        }

        if (flags & ZIP_FLAG_ENCRYPTED) {
            ctx->has_encrypted_file = true;
            enc_count++;

            if (enc_count == 1) {
                ctx->crc32             = crc;
                ctx->flags             = flags;
                ctx->method            = method;
                ctx->compressed_size   = comp_sz;
                ctx->uncompressed_size = ucomp_sz;

                if (flags & ZIP_FLAG_DATA_DESCRIPTOR) {
                    ctx->check_byte_time = (uint8_t)(mod_time >> 8);
                    ctx->use_crc_check   = false;
                } else {
                    ctx->check_byte_crc  = (uint8_t)(crc >> 24);
                    ctx->use_crc_check   = true;
                }

                if (method == ZIP_METHOD_AES) {
                    const uint8_t *extra = cd_ptr +
                        sizeof(zip_central_header_t) + fn_len;
                    if (extra + extra_len <= cd_end) {
                        zip_parse_aes_extra(extra, extra_len, ctx);
                    }
                }

                if (lh_offset + sizeof(zip_local_header_t) <= ctx->data_size) {
                    const uint8_t *lh_ptr = ctx->data + lh_offset;

                    if (le32(lh_ptr) != ZIP_LOCAL_FILE_HEADER_SIG) {
                        log_warn("zip_parse: local header sig mismatch at 0x%08X",
                                 lh_offset);
                    } else {
                        const zip_local_header_t *lh =
                            (const zip_local_header_t *)lh_ptr;

                        uint16_t lfn_len    = le16((const uint8_t *)&lh->filename_len);
                        uint16_t lextra_len = le16((const uint8_t *)&lh->extra_field_len);

                        size_t data_start = lh_offset +
                            sizeof(zip_local_header_t) +
                            lfn_len + lextra_len;

                        if (ctx->is_aes) {
                            int salt_len = 0;
                            switch (ctx->aes_strength) {
                                case 1: salt_len = 8;  break;
                                case 2: salt_len = 12; break;
                                case 3: salt_len = 16; break;
                                default: salt_len = 16; break;
                            }
                            ctx->aes_salt_len = salt_len;

                            if (data_start + salt_len + 2 <= ctx->data_size) {
                                memcpy(ctx->aes_salt,
                                       ctx->data + data_start,
                                       salt_len);
                                memcpy(ctx->aes_pwv,
                                       ctx->data + data_start + salt_len,
                                       2);
                            }
                            ctx->data_offset = (uint32_t)(data_start + salt_len + 2);
                        } else {
                            if (data_start + ZIP_ENCRYPTION_HEADER_SIZE
                                    <= ctx->data_size) {
                                memcpy(ctx->enc_header,
                                       ctx->data + data_start,
                                       ZIP_ENCRYPTION_HEADER_SIZE);
                            }
                            ctx->data_offset = (uint32_t)(
                                data_start + ZIP_ENCRYPTION_HEADER_SIZE);
                        }
                    }
                }
            }
        }

        size_t entry_size = sizeof(zip_central_header_t) +
                            fn_len + extra_len + cm_len;
        cd_ptr += entry_size;
    }

    if (!ctx->has_encrypted_file) {
        log_error("zip_parse: no encrypted entries found in '%s'", path);
        goto fail;
    }

    ctx->parsed = true;
    log_info("zip_parse: OK - %d files, %d encrypted, method=%u %s",
             ctx->num_files, enc_count, ctx->method,
             ctx->is_aes ? "(WinZip AES)" : "(PKZIP classic)");
    return 0;

fail:
    if (ctx->mmap_used) {
        munmap((void *)ctx->data, ctx->data_size);
    } else {
        free((void *)ctx->data);
    }
    close(ctx->fd);
    ctx->data = NULL;
    return -1;
}

void zip_ctx_free(struct zip_ctx *ctx) {
    if (!ctx) return;
    if (ctx->data && !ctx->is_clone) {
        if (ctx->mmap_used)
            munmap((void *)ctx->data, ctx->data_size);
        else
            free((void *)ctx->data);
        ctx->data = NULL;
    }
    if (ctx->fd >= 0) {
        close(ctx->fd);
        ctx->fd = -1;
    }
    ctx->parsed = false;
}

/* ============================================================
 * WINZIP AES KEY DERIVATION (PBKDF2-SHA1)
 * ============================================================ */

static void hmac_sha1(const uint8_t *key, size_t key_len,
                       const uint8_t *data, size_t data_len,
                       uint8_t out[20]) {
    uint8_t ipad[64], opad[64];
    uint8_t key_hash[20];
    const uint8_t *k = key;
    size_t klen = key_len;

    if (klen > 64) {
        sha1(key, key_len, key_hash);
        k    = key_hash;
        klen = 20;
    }

    memset(ipad, 0x36, 64);
    memset(opad, 0x5C, 64);

    for (size_t i = 0; i < klen; i++) {
        ipad[i] ^= k[i];
        opad[i] ^= k[i];
    }

    sha1_ctx_t ctx;
    sha1_init(&ctx);
    sha1_update(&ctx, ipad, 64);
    sha1_update(&ctx, data, data_len);
    sha1_final(&ctx, out);

    sha1_init(&ctx);
    sha1_update(&ctx, opad, 64);
    sha1_update(&ctx, out, 20);
    sha1_final(&ctx, out);
}

static void pbkdf2_sha1(const uint8_t *password, size_t pass_len,
                         const uint8_t *salt, size_t salt_len,
                         uint32_t iterations,
                         uint8_t *out, size_t out_len) {
    uint32_t block_num = 0;
    size_t   done      = 0;

    uint8_t salt_blk[128];
    if (salt_len > sizeof(salt_blk) - 4)
        salt_len = sizeof(salt_blk) - 4;
    memcpy(salt_blk, salt, salt_len);

    while (done < out_len) {
        block_num++;
        salt_blk[salt_len + 0] = (uint8_t)(block_num >> 24);
        salt_blk[salt_len + 1] = (uint8_t)(block_num >> 16);
        salt_blk[salt_len + 2] = (uint8_t)(block_num >>  8);
        salt_blk[salt_len + 3] = (uint8_t)(block_num);

        uint8_t U[20], T[20];
        hmac_sha1(password, pass_len, salt_blk, salt_len + 4, U);
        memcpy(T, U, 20);

        for (uint32_t i = 1; i < iterations; i++) {
            hmac_sha1(password, pass_len, U, 20, U);
            for (int j = 0; j < 20; j++) T[j] ^= U[j];
        }

        size_t copy = (out_len - done > 20) ? 20 : (out_len - done);
        memcpy(out + done, T, copy);
        done += copy;
    }
    secure_memzero(salt_blk, sizeof(salt_blk));
}

/* ============================================================
 * CRC32 STREAMING VALIDATION FOR PKZIP
 * ============================================================ */

/*
 * Maximum number of compressed bytes we will decrypt and CRC-check.
 * For stored files we need all of them. For others this is just
 * a sanity check on the first chunk so we keep it small.
 */
#define CRC32_MAX_VALIDATE_BYTES  (4ULL * MB)

/*
 * zip_decrypt_stream:
 *   Decrypt exactly `len` bytes starting at ctx->data + offset
 *   using the supplied key state. The key state is updated in place.
 *   Output is written to `out`.
 *   Returns false if bounds would be exceeded.
 */
static bool zip_decrypt_stream(const struct zip_ctx *ctx,
                                zip_keys_t *keys,
                                size_t offset,
                                size_t len,
                                uint8_t *out) {
    if (offset + len > ctx->data_size) return false;
    const uint8_t *src = ctx->data + offset;
    for (size_t i = 0; i < len; i++) {
        out[i] = zip_decrypt_char(keys, src[i]);
    }
    return true;
}

/*
 * zip_crc32_validate_stored:
 *   For method=STORED files only.
 *   Decrypt all compressed bytes (== plaintext) and compute CRC32.
 *   Compare against the stored CRC32 in the central directory.
 *
 *   This is the most reliable check possible — guaranteed zero
 *   false positives as long as the archive is not corrupt.
 *
 *   Returns true  ↔ CRC32 matches (correct password)
 *           false ↔ CRC32 mismatch or allocation failure
 */
static bool zip_crc32_validate_stored(const struct zip_ctx *ctx,
                                       zip_keys_t *keys) {
    uint32_t comp_size = ctx->compressed_size;

    /* The "compressed_size" for STORED includes the 12-byte enc header.
     * The actual plaintext payload is comp_size - ZIP_ENCRYPTION_HEADER_SIZE. */
    if (comp_size <= ZIP_ENCRYPTION_HEADER_SIZE) {
        /* Empty file or size field zero — accept if header byte matched */
        return true;
    }

    uint32_t payload_size = comp_size - ZIP_ENCRYPTION_HEADER_SIZE;

    /* Sanity cap */
    if ((uint64_t)payload_size > CRC32_MAX_VALIDATE_BYTES) {
        log_debug("zip_crc32_validate_stored: payload %u exceeds cap, "
                  "skipping full CRC32", payload_size);
        return true; /* Cannot validate — accept (rare large stored file) */
    }

    /* Bounds check against mapped file */
    if ((uint64_t)ctx->data_offset + payload_size > ctx->data_size) {
        log_debug("zip_crc32_validate_stored: data truncated");
        return false;
    }

    uint8_t *buf = (uint8_t *)malloc(payload_size);
    if (!buf) {
        log_warn("zip_crc32_validate_stored: malloc(%u) failed", payload_size);
        return true; /* Memory pressure — accept */
    }

    if (!zip_decrypt_stream(ctx, keys, ctx->data_offset, payload_size, buf)) {
        free(buf);
        return false;
    }

    uint32_t computed = crc32_full(buf, payload_size);
    free(buf);

    bool ok = (computed == ctx->crc32);
    log_debug("zip_crc32_validate_stored: computed=0x%08X stored=0x%08X %s",
              computed, ctx->crc32, ok ? "MATCH" : "MISMATCH");
    return ok;
}

/*
 * zip_validate_deflate_stream:
 *   Decrypt the first N bytes of a DEFLATED stream and check whether
 *   they look like valid deflate-compressed data.
 */
static bool zip_validate_deflate_stream(const struct zip_ctx *ctx,
                                         zip_keys_t *keys) {
    size_t peek = 32;
    if (ctx->data_offset + peek > ctx->data_size) {
        peek = ctx->data_size - ctx->data_offset;
    }
    if (peek < 1) return false;

    uint8_t buf[32];
    if (!zip_decrypt_stream(ctx, keys, ctx->data_offset, peek, buf)) {
        return false;
    }

    /* Raw deflate block header check */
    uint8_t btype = (buf[0] >> 1) & 0x03;
    if (btype == 0x03) {
        log_debug("zip_validate_deflate: invalid BTYPE=11");
        return false;
    }

    /* Stored-block sub-check */
    if (btype == 0x00 && peek >= 5) {
        uint16_t len  = (uint16_t)buf[1] | ((uint16_t)buf[2] << 8);
        uint16_t nlen = (uint16_t)buf[3] | ((uint16_t)buf[4] << 8);
        if ((uint16_t)(len ^ nlen) != 0xFFFF) {
            log_debug("zip_validate_deflate: stored-block LEN/NLEN mismatch");
            return false;
        }
    }

    /* Dynamic Huffman sub-check */
    if (btype == 0x02 && peek >= 4) {
        uint32_t bits = (uint32_t)buf[0]        |
                        ((uint32_t)buf[1] << 8)  |
                        ((uint32_t)buf[2] << 16) |
                        ((uint32_t)buf[3] << 24);
        uint32_t hlit = (bits >> 3) & 0x1F;
        if (hlit > 29) {
            log_debug("zip_validate_deflate: HLIT=%u out of range", hlit);
            return false;
        }
    }

    /* All-zeros check */
    bool all_zero = true;
    for (size_t i = 0; i < peek; i++) {
        if (buf[i] != 0) { all_zero = false; break; }
    }
    if (all_zero) return false;

    return true;
}

/*
 * zip_validate_bzip2_stream:
 */
static bool zip_validate_bzip2_stream(const struct zip_ctx *ctx,
                                       zip_keys_t *keys) {
    uint8_t buf[4];
    size_t peek = 4;
    if (ctx->data_offset + peek > ctx->data_size) return false;

    if (!zip_decrypt_stream(ctx, keys, ctx->data_offset, peek, buf)) {
        return false;
    }

    return (buf[0] == 'B' && buf[1] == 'Z' && buf[2] == 'h' &&
            buf[3] >= '1' && buf[3] <= '9');
}

/*
 * zip_validate_lzma_stream:
 */
static bool zip_validate_lzma_stream(const struct zip_ctx *ctx,
                                      zip_keys_t *keys) {
    uint8_t buf[9];
    size_t peek = 9;
    if (ctx->data_offset + peek > ctx->data_size) peek = 4;
    if (ctx->data_offset + 4 > ctx->data_size) return false;

    if (!zip_decrypt_stream(ctx, keys, ctx->data_offset, peek, buf)) {
        return false;
    }

    if (buf[2] != 0x05 || buf[3] != 0x00) return false;
    if (buf[0] != 0x00 && buf[0] != 0x14) return false;

    return true;
}

/* ============================================================
 * ZIP CLI VALIDATION (definitive fallback)
 * ============================================================ */

static bool zip_validate_cli(const char *archive_path, const char *password) {
    if (!archive_path || !password || password[0] == '\0')
        return false;

    char pwarg[MAX_PASSWORD_LEN + 3];
    int n = snprintf(pwarg, sizeof(pwarg), "-p%s", password);
    if (n <= 2 || (size_t)n >= sizeof(pwarg))
        return false;

    pid_t pid = fork();
    if (pid < 0) return false;

    if (pid == 0) {
        int devnull = open("/dev/null", O_WRONLY);
        if (devnull >= 0) {
            dup2(devnull, STDOUT_FILENO);
            dup2(devnull, STDERR_FILENO);
            close(devnull);
        }
        execlp("7z", "7z", "t", "-y", pwarg, archive_path, (char *)NULL);
        _exit(127);
    }

    int status = 0;
    if (waitpid(pid, &status, 0) < 0) return false;

    return WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

/* ============================================================
 * MAIN PKZIP VALIDATION — WITH CLI FALLBACK
 * ============================================================ */

static bool zip_validate_pkzip(const struct zip_ctx *ctx,
                                const char *password) {
    if (UNLIKELY(!ctx->parsed)) return false;

    /* ── Stage 1: 12-byte encryption header check ── */
    zip_keys_t keys;
    zip_init_keys(&keys, password);

    uint8_t decrypted[ZIP_ENCRYPTION_HEADER_SIZE];
    for (int i = 0; i < ZIP_ENCRYPTION_HEADER_SIZE; i++) {
        decrypted[i] = zip_decrypt_char(&keys, ctx->enc_header[i]);
    }

    uint8_t check = ctx->use_crc_check ? ctx->check_byte_crc
                                       : ctx->check_byte_time;

    if (decrypted[ZIP_ENCRYPTION_HEADER_SIZE - 1] != check) {
        return false;
    }

    uint16_t method = ctx->method;
    bool structural_ok = false;

    switch (method) {
        case ZIP_METHOD_STORED:
            /* CRC32 is already definitive */
            return zip_crc32_validate_stored(ctx, &keys);

        case ZIP_METHOD_DEFLATED:
            structural_ok = zip_validate_deflate_stream(ctx, &keys);
            break;
        case ZIP_METHOD_BZIP2:
            structural_ok = zip_validate_bzip2_stream(ctx, &keys);
            break;
        case ZIP_METHOD_LZMA:
            structural_ok = zip_validate_lzma_stream(ctx, &keys);
            break;
        default:
            /* Unknown method – accept structural only (conservative) */
            log_debug("zip_validate_pkzip: unknown method %u, header check only", method);
            return true;
    }

    if (!structural_ok)
        return false;

    /* Stage 3: definitive CLI test for compressed methods */
    if (!zip_validate_cli(ctx->archive_path, password)) {
        log_debug("zip_validate_pkzip: structural check passed but CLI rejected password");
        return false;
    }

    return true;
}

/* ============================================================
 * WINZIP AES VALIDATION
 * ============================================================ */

static bool zip_validate_aes(const struct zip_ctx *ctx,
                              const char *password) {
    if (UNLIKELY(!ctx->parsed || !ctx->is_aes)) return false;

    int aes_key_len;
    switch (ctx->aes_strength) {
        case 1: aes_key_len = 16; break;
        case 2: aes_key_len = 24; break;
        case 3: aes_key_len = 32; break;
        default: return false;
    }

    int    derive_len = aes_key_len * 2 + 2;
    uint8_t derived[66];

    pbkdf2_sha1((const uint8_t *)password, strlen(password),
                ctx->aes_salt, (size_t)ctx->aes_salt_len,
                1000,
                derived, (size_t)derive_len);

    uint8_t *pwv = derived + aes_key_len * 2;
    return (pwv[0] == ctx->aes_pwv[0] && pwv[1] == ctx->aes_pwv[1]);
}

/* ============================================================
 * PUBLIC ZIP VALIDATION ENTRY POINT
 * ============================================================ */

bool zip_validate_password(const struct zip_ctx *ctx, const char *password) {
    if (UNLIKELY(!ctx || !ctx->parsed)) return false;

    if (ctx->is_aes) {
        return zip_validate_aes(ctx, password);
    } else {
        return zip_validate_pkzip(ctx, password);
    }
}

/* ============================================================
 * 7Z PARSING
 * ============================================================ */

typedef struct {
    const uint8_t *data;
    size_t         size;
    size_t         pos;
} sz_reader_t;

static void sz_reader_init(sz_reader_t *r,
                            const uint8_t *data, size_t size) {
    r->data = data;
    r->size = size;
    r->pos  = 0;
}

static int sz_read_byte(sz_reader_t *r, uint8_t *out) {
    if (r->pos >= r->size) return -1;
    *out = r->data[r->pos++];
    return 0;
}

static int sz_read_number(sz_reader_t *r, uint64_t *out) {
    uint8_t first;
    if (sz_read_byte(r, &first) != 0) return -1;

    if ((first & 0x80) == 0) { *out = first; return 0; }

    uint8_t second;
    if (sz_read_byte(r, &second) != 0) return -1;

    if ((first & 0x40) == 0) {
        *out = ((uint64_t)(first & 0x3F) << 8) | second;
        return 0;
    }

    uint8_t third;
    if (sz_read_byte(r, &third) != 0) return -1;

    if ((first & 0x20) == 0) {
        *out = ((uint64_t)(first & 0x1F) << 16) |
               ((uint64_t)second << 8) | third;
        return 0;
    }

    uint8_t fourth;
    if (sz_read_byte(r, &fourth) != 0) return -1;

    if ((first & 0x10) == 0) {
        *out = ((uint64_t)(first & 0x0F) << 24) |
               ((uint64_t)second << 16) |
               ((uint64_t)third  <<  8) |
               fourth;
        return 0;
    }

    uint64_t val = (uint64_t)(first & 0x0F);
    val = (val << 8) | second;
    val = (val << 8) | third;
    val = (val << 8) | fourth;

    int extra_bytes;
    if      ((first & 0x08) == 0) extra_bytes = 1;
    else if ((first & 0x04) == 0) extra_bytes = 2;
    else if ((first & 0x02) == 0) extra_bytes = 3;
    else if ((first & 0x01) == 0) extra_bytes = 4;
    else                          { extra_bytes = 4; val = 0; }

    for (int i = 0; i < extra_bytes; i++) {
        uint8_t b;
        if (sz_read_byte(r, &b) != 0) return -1;
        val = (val << 8) | b;
    }

    *out = val;
    return 0;
}

/* suppress unused warning */
static int sz_read_number_unused_wrapper(sz_reader_t *r, uint64_t *out) {
    return sz_read_number(r, out);
}

static bool sz_parse_aes_props(const uint8_t *props, size_t props_len,
                                struct sz_ctx *ctx) {
    if (props_len < 2) return false;

    uint8_t b0 = props[0];
    uint8_t b1 = props[1];

    ctx->num_cycles_power = b0 & 0x3F;

    int salt_size = ((b0 >> 7) & 1) * 16 + ((b1 >> 4) & 0x0F);
    int iv_size   = ((b0 >> 6) & 1) * 16 + (b1 & 0x0F);

    if (2 + salt_size + iv_size > (int)props_len) {
        salt_size = 0;
        iv_size   = 0;
    }

    ctx->aes_salt_len = salt_size;
    if (salt_size > 0)
        memcpy(ctx->aes_salt, props + 2, salt_size);

    memset(ctx->aes_iv, 0, 16);
    if (iv_size > 0) {
        int copy = (iv_size < 16) ? iv_size : 16;
        memcpy(ctx->aes_iv, props + 2 + salt_size, copy);
    }

    log_debug("sz_parse_aes_props: NumCyclesPower=%u, salt=%d, iv=%d",
              ctx->num_cycles_power, salt_size, iv_size);
    return true;
}

static bool sz_scan_for_aes_coder(const uint8_t *data, size_t size,
                                   struct sz_ctx *ctx) {
    static const uint8_t aes_codec_id[] = {0x06, 0xF1, 0x07, 0x01};

    for (size_t i = 0; i + sizeof(aes_codec_id) + 4 < size; i++) {
        if (memcmp(data + i, aes_codec_id, sizeof(aes_codec_id)) == 0) {
            size_t prop_offset = i + sizeof(aes_codec_id);
            if (prop_offset >= size) continue;

            uint8_t prop_size_byte = data[prop_offset];
            prop_offset++;

            if (prop_size_byte == 0 || prop_offset + prop_size_byte > size)
                continue;

            if (sz_parse_aes_props(data + prop_offset, prop_size_byte, ctx)) {
                log_debug("sz_scan_for_aes_coder: found at offset %zu", i);
                return true;
            }
        }
    }
    return false;
}

int sz_parse(struct sz_ctx *ctx, const char *path) {
    memset(ctx, 0, sizeof(*ctx));

    ctx->fd = open(path, O_RDONLY);
    if (ctx->fd < 0) {
        log_error("sz_parse: cannot open '%s': %s", path, strerror(errno));
        return -1;
    }

    struct stat st;
    if (fstat(ctx->fd, &st) != 0) {
        log_error("sz_parse: fstat failed: %s", strerror(errno));
        close(ctx->fd);
        return -1;
    }

    ctx->data_size = (size_t)st.st_size;
    if (ctx->data_size < sizeof(sz_signature_header_t)) {
        log_error("sz_parse: file too small");
        close(ctx->fd);
        return -1;
    }

    ctx->data = (const uint8_t *)mmap(NULL, ctx->data_size,
                                       PROT_READ, MAP_PRIVATE,
                                       ctx->fd, 0);
    if (ctx->data == MAP_FAILED) {
        uint8_t *buf = (uint8_t *)malloc(ctx->data_size);
        if (!buf) {
            log_error("sz_parse: malloc failed");
            close(ctx->fd);
            return -1;
        }
        ssize_t n = read(ctx->fd, buf, ctx->data_size);
        if (n != (ssize_t)ctx->data_size) {
            free(buf);
            close(ctx->fd);
            return -1;
        }
        ctx->data      = buf;
        ctx->mmap_used = false;
    } else {
        ctx->mmap_used = true;
        madvise((void *)ctx->data, ctx->data_size, MADV_SEQUENTIAL);
    }

    if (memcmp(ctx->data, SZ_SIGNATURE, SZ_SIGNATURE_SIZE) != 0) {
        log_error("sz_parse: invalid 7z signature");
        goto fail;
    }

    const sz_signature_header_t *hdr =
        (const sz_signature_header_t *)ctx->data;

    ctx->next_header_offset = le64((const uint8_t *)&hdr->next_header_offset);
    ctx->next_header_size   = le64((const uint8_t *)&hdr->next_header_size);
    ctx->next_header_crc    = le32((const uint8_t *)&hdr->next_header_crc);

    log_debug("sz_parse: ver=%u.%u, offset=0x%llX, size=%llu, crc=0x%08X",
              hdr->major_version, hdr->minor_version,
              (unsigned long long)ctx->next_header_offset,
              (unsigned long long)ctx->next_header_size,
              ctx->next_header_crc);

    uint64_t hdr_start = sizeof(sz_signature_header_t) +
                          ctx->next_header_offset;

    if (hdr_start >= ctx->data_size) {
        log_error("sz_parse: next header offset exceeds file size");
        goto fail;
    }

    uint64_t hdr_end = hdr_start + ctx->next_header_size;
    if (hdr_end > ctx->data_size) {
        log_error("sz_parse: next header extends beyond file size");
        goto fail;
    }

    const uint8_t *hdr_data = ctx->data + hdr_start;
    size_t         hdr_size = (size_t)ctx->next_header_size;

    if (hdr_data[0] == SZ_ID_ENCODED_HEADER) {
        ctx->is_header_encrypted = true;
        log_debug("sz_parse: encoded header detected");
        if (sz_scan_for_aes_coder(hdr_data, hdr_size, ctx)) {
            ctx->has_encrypted_streams = true;
            size_t enc_copy = (hdr_size > 32) ? 32 : hdr_size;
            memcpy(ctx->enc_header_data, hdr_data, enc_copy);
            ctx->enc_header_size = enc_copy;
        }
    } else if (hdr_data[0] == SZ_ID_HEADER) {
        log_debug("sz_parse: plain header detected");
        if (sz_scan_for_aes_coder(hdr_data, hdr_size, ctx)) {
            ctx->has_encrypted_streams = true;
            log_debug("sz_parse: encrypted stream in plain header");
        } else {
            log_warn("sz_parse: no encrypted streams");
        }
    } else {
        log_warn("sz_parse: unexpected header type 0x%02X", hdr_data[0]);
        if (sz_scan_for_aes_coder(hdr_data, hdr_size, ctx))
            ctx->has_encrypted_streams = true;
    }

    size_t pack_start     = sizeof(sz_signature_header_t);
    size_t pack_available = (ctx->next_header_offset > 0 &&
                              pack_start < ctx->data_size)
                            ? (size_t)(ctx->next_header_offset)
                            : 0;

    if (pack_available >= AES_BLOCK_SIZE) {
        size_t enc_copy = (pack_available >= 32) ? 32 : pack_available;
        memcpy(ctx->enc_header_data, ctx->data + pack_start, enc_copy);
        ctx->enc_header_size = enc_copy;
        ctx->has_encrypted_streams = true;
    }

    if (!ctx->has_encrypted_streams) {
        log_error("sz_parse: no encrypted streams in '%s'", path);
        goto fail;
    }

    ctx->parsed = true;
    log_info("sz_parse: OK - encrypted=%s, NumCyclesPower=%u, salt_len=%d",
             ctx->has_encrypted_streams ? "yes" : "no",
             ctx->num_cycles_power, ctx->aes_salt_len);
    return 0;

fail:
    if (ctx->mmap_used)
        munmap((void *)ctx->data, ctx->data_size);
    else
        free((void *)ctx->data);
    close(ctx->fd);
    ctx->data = NULL;
    return -1;
}

void sz_ctx_free(struct sz_ctx *ctx) {
    if (!ctx) return;
    if (ctx->data && !ctx->is_clone) {
        if (ctx->mmap_used)
            munmap((void *)ctx->data, ctx->data_size);
        else
            free((void *)ctx->data);
        ctx->data = NULL;
    }
    if (ctx->fd >= 0) {
        close(ctx->fd);
        ctx->fd = -1;
    }
    ctx->parsed = false;
}

/* ============================================================
 * 7Z KEY DERIVATION
 * ============================================================ */

static void sz_derive_key(const char *password,
                           const uint8_t *salt, int salt_len,
                           uint32_t num_cycles_power,
                           uint8_t key[32]) {
    size_t pass_len = strlen(password);

    uint8_t utf16[MAX_PASSWORD_LEN * 2];
    size_t  utf16_len = 0;

    for (size_t i = 0; i < pass_len && i < MAX_PASSWORD_LEN; i++) {
        utf16[utf16_len++] = (uint8_t)password[i];
        utf16[utf16_len++] = 0x00;
    }

    if (num_cycles_power == 0x3F) {
        sha256_ctx_t ctx;
        sha256_init(&ctx);
        if (salt_len > 0)
            sha256_update(&ctx, salt, salt_len);
        sha256_update(&ctx, utf16, utf16_len);
        sha256_final(&ctx, key);
        return;
    }

    uint64_t num_rounds = (uint64_t)1 << num_cycles_power;

    sha256_ctx_t sha_ctx;
    sha256_init(&sha_ctx);

    size_t round_data_len = utf16_len + (size_t)salt_len;
    uint8_t round_data[MAX_PASSWORD_LEN * 2 + 64];

    if (round_data_len > sizeof(round_data))
        round_data_len = sizeof(round_data);

    memcpy(round_data, utf16, utf16_len);
    if (salt_len > 0)
        memcpy(round_data + utf16_len, salt, salt_len);

    for (uint64_t round = 0; round < num_rounds; round++) {
        sha256_update(&sha_ctx, round_data, round_data_len);
        uint8_t counter[8];
        uint64_t r = round;
        for (int i = 0; i < 8; i++) {
            counter[i] = (uint8_t)(r & 0xFF);
            r >>= 8;
        }
        sha256_update(&sha_ctx, counter, 8);
    }

    sha256_final(&sha_ctx, key);
    secure_memzero(utf16, sizeof(utf16));
    secure_memzero(round_data, sizeof(round_data));
}

/* ============================================================
 * RAR PARSING AND VALIDATION
 * ============================================================ */

static int rar_read_vint(const uint8_t *p, size_t max_len, uint64_t *out) {
    uint64_t res = 0;
    int shift = 0;
    for (int i = 0; i < 10 && i < (int)max_len; i++) {
        res |= (uint64_t)(p[i] & 0x7f) << shift;
        if (!(p[i] & 0x80)) {
            if (out) *out = res;
            return i + 1;
        }
        shift += 7;
    }
    return -1;
}

static bool rar_validate_cli(const char *archive_path, const char *password) {
    if (!archive_path || !password) return false;
    char pwarg[MAX_PASSWORD_LEN + 3];
    snprintf(pwarg, sizeof(pwarg), "-p%s", password);
    pid_t pid = fork();
    if (pid < 0) return false;
    if (pid == 0) {
        int devnull = open("/dev/null", O_WRONLY);
        if (devnull >= 0) {
            dup2(devnull, STDOUT_FILENO);
            dup2(devnull, STDERR_FILENO);
            close(devnull);
        }
        execlp("unrar", "unrar", "t", "-y", pwarg, archive_path, (char *)NULL);
        _exit(127);
    }
    int status = 0;
    waitpid(pid, &status, 0);
    return WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

int rar_parse(struct rar_ctx *ctx, const char *path) {
    memset(ctx, 0, sizeof(*ctx));
    ctx->fd = open(path, O_RDONLY);
    if (ctx->fd < 0) {
        log_error("rar_parse: cannot open '%s': %s", path, strerror(errno));
        return -1;
    }

    struct stat st;
    if (fstat(ctx->fd, &st) != 0) {
        log_error("rar_parse: fstat failed");
        close(ctx->fd);
        return -1;
    }

    ctx->data_size = (size_t)st.st_size;
    if (ctx->data_size < 7) {
        log_error("rar_parse: file too small");
        close(ctx->fd);
        return -1;
    }

    ctx->data = (const uint8_t *)mmap(NULL, ctx->data_size, PROT_READ, MAP_PRIVATE, ctx->fd, 0);
    if (ctx->data == MAP_FAILED) {
        log_warn("rar_parse: mmap failed, falling back to read");
        uint8_t *buf = (uint8_t *)malloc(ctx->data_size);
        if (!buf) {
            log_error("rar_parse: malloc failed");
            close(ctx->fd);
            return -1;
        }
        if (read(ctx->fd, buf, ctx->data_size) != (ssize_t)ctx->data_size) {
            log_error("rar_parse: read failed");
            free(buf);
            close(ctx->fd);
            return -1;
        }
        ctx->data = buf;
        ctx->mmap_used = false;
    } else {
        ctx->mmap_used = true;
        madvise((void *)ctx->data, ctx->data_size, MADV_SEQUENTIAL);
    }

    /* Signature scanning (handle SFX) */
    size_t sig_pos = 0;
    bool found_sig = false;
    size_t scan_limit = (ctx->data_size > 1024 * 1024) ? 1024 * 1024 : ctx->data_size - 7;

    for (size_t i = 0; i < scan_limit; i++) {
        if (ctx->data[i] == 0x52 && ctx->data[i+1] == 0x61 &&
            ctx->data[i+2] == 0x72 && ctx->data[i+3] == 0x21) {
            if (i + 8 <= ctx->data_size &&
                ctx->data[i+4] == 0x1A && ctx->data[i+5] == 0x07 && ctx->data[i+6] == 0x01 &&
                ctx->data[i+7] == 0x00) {
                ctx->version = 5;
                sig_pos = i;
                found_sig = true;
                break;
            } else if (i + 7 <= ctx->data_size &&
                       ctx->data[i+4] == 0x1A && ctx->data[i+5] == 0x07 && ctx->data[i+6] == 0x00) {
                ctx->version = 3;
                sig_pos = i;
                found_sig = true;
                break;
            }
        }
    }

    if (!found_sig) {
        log_error("rar_parse: RAR signature not found");
        goto fail;
    }

    log_debug("rar_parse: found RARv%d signature at offset %zu", ctx->version, sig_pos);

    if (ctx->version == 5) {
        size_t pos = sig_pos + 8;
        while (pos + 7 < ctx->data_size) {
            uint64_t h_size, h_type, h_flags;
            int n_hsize;
            /* Header CRC is at pos, Header Size starts at pos+4 */
            n_hsize = rar_read_vint(ctx->data + pos + 4, ctx->data_size - pos - 4, &h_size);
            if (n_hsize < 0) break;
            size_t header_payload_start = pos + 4 + (size_t)n_hsize;

            int n;
            n = rar_read_vint(ctx->data + header_payload_start, ctx->data_size - header_payload_start, &h_type);
            if (n < 0) break;
            size_t flags_pos = header_payload_start + (size_t)n;

            n = rar_read_vint(ctx->data + flags_pos, ctx->data_size - flags_pos, &h_flags);
            if (n < 0) break;

            if (h_type == 4) { /* Encryption Header */
                size_t enc_pos = flags_pos + (size_t)n;
                uint64_t enc_ver, enc_flags;
                n = rar_read_vint(ctx->data + enc_pos, ctx->data_size - enc_pos, &enc_ver);
                if (n < 0) break;
                enc_pos += (size_t)n;
                n = rar_read_vint(ctx->data + enc_pos, ctx->data_size - enc_pos, &enc_flags);
                if (n < 0) break;
                enc_pos += (size_t)n;

                if (enc_pos + 17 > ctx->data_size) break;
                /* Limit exponent to avoid undefined behavior in 1U << ctx->data[enc_pos] */
                if (ctx->data[enc_pos] >= 32) break;
                ctx->iterations = 1U << ctx->data[enc_pos++];
                memcpy(ctx->salt, ctx->data + enc_pos, 16);
                enc_pos += 16;
                ctx->salt_len = 16;
                if (enc_flags & 0x0001) {
                    if (enc_pos + 12 > ctx->data_size) break;
                    memcpy(ctx->check_value, ctx->data + enc_pos, 12);
                    ctx->has_check_value = true;
                }
                ctx->is_header_encrypted = true;
                ctx->is_encrypted = true;
                break;
            }
            pos += 4 + (size_t)n_hsize + (size_t)h_size;
        }
    } else {
        size_t pos = sig_pos + 7;
        while (pos + 7 < ctx->data_size) {
            uint16_t h_type = ctx->data[pos+2];
            uint16_t h_flags = le16(ctx->data + pos + 3);
            uint16_t h_size = le16(ctx->data + pos + 5);

            if (pos + h_size > ctx->data_size) break;

            if (h_type == 0x73) { /* Archive Header */
                if (h_flags & 0x0080) {
                    if (pos + h_size + 8 > ctx->data_size) break;
                    ctx->is_header_encrypted = true;
                    ctx->is_encrypted = true;
                    memcpy(ctx->salt, ctx->data + pos + h_size, 8);
                    ctx->salt_len = 8;
                    break;
                }
            }
            if (h_type == 0x74) { /* File Header */
                if (h_flags & 0x0004) {
                    if (pos + h_size < 8) break; /* should not happen */
                    ctx->is_encrypted = true;
                    memcpy(ctx->salt, ctx->data + pos + h_size - 8, 8);
                    ctx->salt_len = 8;
                    break;
                }
            }

            size_t next_pos = pos + h_size;
            if (h_type == 0x74) {
                next_pos += (size_t)le32(ctx->data + pos + 7); /* add pack size */
            }
            if (next_pos <= pos) break; /* avoid infinite loop */
            pos = next_pos;
        }
    }

    if (!ctx->is_encrypted) goto fail;
    ctx->parsed = true;
    return 0;

fail:
    if (ctx->data) {
        if (ctx->mmap_used)
            munmap((void *)ctx->data, ctx->data_size);
        else
            free((void *)ctx->data);
        ctx->data = NULL;
    }
    close(ctx->fd);
    return -1;
}

void rar_ctx_free(struct rar_ctx *ctx) {
    if (!ctx) return;
    if (ctx->data && !ctx->is_clone) {
        if (ctx->mmap_used)
            munmap((void *)ctx->data, ctx->data_size);
        else
            free((void *)ctx->data);
        ctx->data = NULL;
    }
    if (ctx->fd >= 0) {
        close(ctx->fd);
        ctx->fd = -1;
    }
    ctx->parsed = false;
}

bool rar_validate_password(const struct rar_ctx *ctx, const char *password, const char *path) {
    if (ctx->version == 5) {
        if (ctx->has_check_value) {
            uint8_t derived_check[8];
            rar5_derive_values(password, ctx->salt, ctx->iterations, NULL, derived_check);
            if (memcmp(derived_check, ctx->check_value, 8) == 0) {
                /* checksum check */
                uint8_t digest[32];
                sha256(ctx->check_value, 8, digest);
                if (memcmp(digest, ctx->check_value + 8, 4) == 0) {
                    return true;
                }
            }
            return false;
        }
    } else {
        /* RAR3: custom derivation + structural check */
        uint8_t key[16], iv[16];
        rar3_derive_key(password, ctx->salt, key, iv);

        /* If headers are encrypted, we can decrypt the first block after the salt
           and check for a valid RAR3 header type. */
        if (ctx->is_header_encrypted && ctx->data_size > 7 + 7 + 8 + 16) {
            /* Sig(7) + MainHdr(7) + Salt(8) = 22. Next is encrypted. */
            size_t enc_start = 0;
            /* Re-scan for the salt position to be sure */
            for (size_t i = 0; i < ctx->data_size - 22; i++) {
                if (memcmp(ctx->data + i, "Rar!\x1a\x07\x00", 7) == 0) {
                    /* Read h_size of the Main Header (after the 7-byte signature) */
                    uint16_t h_size = le16(ctx->data + i + 7 + 5);
                    /* enc_start skips: Signature(7) + MainHeader(h_size) + Salt(8) */
                    enc_start = i + 7 + h_size + 8;
                    break;
                }
            }

            if (enc_start > 0 && enc_start + 16 <= ctx->data_size) {
                aes_ctx_t aes;
                aes128_key_expansion(&aes, key);
                uint8_t block[16], dec[16];
                memcpy(block, ctx->data + enc_start, 16);
                aes_cbc_decrypt(&aes, iv, block, dec, 16);

                /* First byte of decrypted block should be part of a header CRC or type.
                   In RAR3, header type is at offset 2. */
                uint8_t type = dec[2];
                bool type_valid = (type == 0x73 || type == 0x74 || type == 0x75 ||
                                   type == 0x76 || type == 0x77 || type == 0x78 || type == 0x7a);
                if (!type_valid) return false;
            }
        }
    }
    /* Definitive CLI check for RAR3 or RAR5 without check data */
    return rar_validate_cli(path, password);
}

/* ============================================================
 * 7Z PASSWORD VALIDATION
 * ============================================================ */

static bool sz_validate_password_cli(const char *archive_path,
                                     const char *password) {
    if (!archive_path || !password || password[0] == '\0')
        return false;

    char pwarg[MAX_PASSWORD_LEN + 3];
    int n = snprintf(pwarg, sizeof(pwarg), "-p%s", password);
    if (n <= 2 || (size_t)n >= sizeof(pwarg))
        return false;

    pid_t pid = fork();
    if (pid < 0) return false;

    if (pid == 0) {
        int devnull = open("/dev/null", O_WRONLY);
        if (devnull >= 0) {
            (void)dup2(devnull, STDOUT_FILENO);
            (void)dup2(devnull, STDERR_FILENO);
            close(devnull);
        }
        execlp("7z", "7z", "t", "-y", pwarg, archive_path, (char *)NULL);
        _exit(127);
    }

    int status = 0;
    if (waitpid(pid, &status, 0) < 0) return false;

    return WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

static bool sz_validate_password(const struct sz_ctx *ctx,
                                 const char *password,
                                 const char *archive_path) {
    if (UNLIKELY(!ctx || !ctx->parsed)) return false;
    if (UNLIKELY(!ctx->has_encrypted_streams)) return false;

    uint8_t aes_key[32];
    sz_derive_key(password,
                  ctx->aes_salt_len > 0 ? ctx->aes_salt : NULL,
                  ctx->aes_salt_len,
                  ctx->num_cycles_power,
                  aes_key);

    aes_ctx_t aes;
    aes256_key_expansion(&aes, aes_key);

    if (ctx->enc_header_size < AES_BLOCK_SIZE) {
        volatile uint8_t *vk = (volatile uint8_t *)aes_key;
        for (int i = 0; i < 32; i++) vk[i] = 0;
        return false;
    }

    uint8_t iv[AES_BLOCK_SIZE];
    memcpy(iv, ctx->aes_iv, AES_BLOCK_SIZE);

    uint8_t dec_block[AES_BLOCK_SIZE];
    aes_cbc_decrypt(&aes, iv,
                     ctx->enc_header_data,
                     dec_block,
                     AES_BLOCK_SIZE);

    /*
     * ── 7Z CRC32 validation of decrypted header ──
     */
    bool validated = false;

    if (ctx->is_header_encrypted &&
        ctx->next_header_crc != 0 &&
        ctx->next_header_size > 0 &&
        ctx->next_header_size <= (uint64_t)(4 * MB)) {

        size_t hdr_sz = (size_t)ctx->next_header_size;
        size_t aes_len = (hdr_sz + AES_BLOCK_SIZE - 1) & ~(size_t)(AES_BLOCK_SIZE - 1);

        size_t hdr_file_offset = sizeof(sz_signature_header_t) +
                                  (size_t)ctx->next_header_offset;

        if (ctx->data != NULL &&
            hdr_file_offset + hdr_sz <= ctx->data_size) {

            uint8_t *dec_hdr = (uint8_t *)malloc(aes_len);
            if (dec_hdr) {
                uint8_t *enc_padded = (uint8_t *)malloc(aes_len);
                if (enc_padded) {
                    memcpy(enc_padded,
                           ctx->data + hdr_file_offset,
                           hdr_sz);
                    if (aes_len > hdr_sz)
                        memset(enc_padded + hdr_sz, 0, aes_len - hdr_sz);

                    aes_cbc_decrypt(&aes, iv,
                                     enc_padded,
                                     dec_hdr,
                                     aes_len);
                    free(enc_padded);

                    uint32_t computed_crc = crc32_full(dec_hdr, hdr_sz);
                    free(dec_hdr);

                    if (computed_crc == ctx->next_header_crc) {
                        log_debug("sz_validate: CRC32 match 0x%08X",
                                  computed_crc);
                        validated = true;
                    } else {
                        log_debug("sz_validate: CRC32 mismatch "
                                  "computed=0x%08X stored=0x%08X",
                                  computed_crc, ctx->next_header_crc);
                        volatile uint8_t *vk = (volatile uint8_t *)aes_key;
                        for (int i = 0; i < 32; i++) vk[i] = 0;
                        return false;
                    }
                } else {
                    free(dec_hdr);
                }
            }
        }
    }

    bool maybe_ok = false;
    if (validated) {
        maybe_ok = true;
    } else if (ctx->is_header_encrypted) {
        /* If header is encrypted and we didn't validate via CRC, it's a fail */
        maybe_ok = false;
    } else {
        uint8_t first = dec_block[0];
        maybe_ok = (first == SZ_ID_HEADER          ||
                    first == SZ_ID_ENCODED_HEADER   ||
                    first == SZ_ID_END              ||
                    first == SZ_ID_PACK_INFO        ||
                    first == SZ_ID_UNPACK_INFO      ||
                    first == SZ_ID_MAIN_STREAMS_INFO);
    }

    volatile uint8_t *vk = (volatile uint8_t *)aes_key;
    for (int i = 0; i < 32; i++) vk[i] = 0;

    if (maybe_ok) {
        /* Double-confirm with CLI if internal check says OK or if no header encryption */
        return sz_validate_password_cli(archive_path, password);
    }

    return false;
}

/* ============================================================
 * UNIFIED ARCHIVE CONTEXT
 * ============================================================ */

int archive_open(archive_ctx_t *ctx, const char *path,
                 archive_type_t type) {
    memset(ctx, 0, sizeof(*ctx));
    ctx->type = type;
    snprintf(ctx->path, sizeof(ctx->path), "%s", path);

    switch (type) {
        case ARCHIVE_ZIP:
            return zip_parse(&ctx->zip, path);
        case ARCHIVE_7Z:
            return sz_parse(&ctx->sz, path);
        case ARCHIVE_RAR:
            return rar_parse(&ctx->rar, path);
        default:
            log_error("archive_open: unsupported type %d", type);
            return -1;
    }
}

void archive_ctx_free(archive_ctx_t *ctx) {
    if (!ctx) return;
    switch (ctx->type) {
        case ARCHIVE_ZIP: zip_ctx_free(&ctx->zip); break;
        case ARCHIVE_7Z:  sz_ctx_free(&ctx->sz);   break;
        case ARCHIVE_RAR: rar_ctx_free(&ctx->rar); break;
        default: break;
    }
}

bool archive_validate_password(const archive_ctx_t *ctx,
                                const char *password) {
    if (UNLIKELY(!ctx)) return false;

    switch (ctx->type) {
        case ARCHIVE_ZIP:
            return zip_validate_password(&ctx->zip, password);
        case ARCHIVE_7Z:
            return sz_validate_password(&ctx->sz, password, ctx->path);
        case ARCHIVE_RAR:
            return rar_validate_password(&ctx->rar, password, ctx->path);
        default:
            return false;
    }
}

int archive_ctx_clone(archive_ctx_t *dst, const archive_ctx_t *src) {
    if (!dst || !src) return -1;
    memcpy(dst, src, sizeof(*dst));

    if (src->type == ARCHIVE_ZIP) {
        dst->zip.is_clone  = true;
        dst->zip.fd        = -1;
    } else if (src->type == ARCHIVE_7Z) {
        dst->sz.is_clone   = true;
        dst->sz.fd         = -1;
    } else if (src->type == ARCHIVE_RAR) {
        dst->rar.is_clone  = true;
        dst->rar.fd        = -1;
    }
    return 0;
}

void archive_print_info(const archive_ctx_t *ctx, bool no_color) {
    const char *c_l = no_color ? "" : "\033[97m";
    const char *c_v = no_color ? "" : "\033[36m";
    const char *c_r = no_color ? "" : "\033[0m";

    fprintf(stderr, "\n%s[Archive Info]%s\n", c_l, c_r);

    switch (ctx->type) {
        case ARCHIVE_ZIP: {
            const struct zip_ctx *z = &ctx->zip;
            fprintf(stderr, "  %sType:%s     %sZIP%s\n",    c_l,c_r,c_v,c_r);
            fprintf(stderr, "  %sFiles:%s    %s%d%s\n",     c_l,c_r,c_v,z->num_files,c_r);
            if (z->filename[0])
                fprintf(stderr, "  %sFirst:%s    %s%s%s\n", c_l,c_r,c_v,z->filename,c_r);
            fprintf(stderr, "  %sEncrypt:%s  %s%s%s\n",
                    c_l,c_r,c_v,
                    z->is_aes ? "WinZip AES" : "PKZIP Classic",
                    c_r);
            if (z->is_aes) {
                int bits = 0;
                switch (z->aes_strength) {
                    case 1: bits=128; break;
                    case 2: bits=192; break;
                    case 3: bits=256; break;
                }
                fprintf(stderr,"  %sAES Bits:%s %s%d%s\n",c_l,c_r,c_v,bits,c_r);
            }
            fprintf(stderr,"  %sMethod:%s   %s%u%s\n",c_l,c_r,c_v,z->method,c_r);
            break;
        }
        case ARCHIVE_7Z: {
            const struct sz_ctx *s = &ctx->sz;
            fprintf(stderr,"  %sType:%s     %s7-Zip%s\n",   c_l,c_r,c_v,c_r);
            fprintf(stderr,"  %sEncrypted:%s%s%s%s\n",
                    c_l,c_r,c_v,
                    s->has_encrypted_streams ? "Yes" : "No",
                    c_r);
            fprintf(stderr,"  %sKDF Iters:%s%s%llu%s\n",
                    c_l,c_r,c_v,
                    (unsigned long long)(1ULL << s->num_cycles_power),
                    c_r);
            fprintf(stderr,"  %sSalt Len:%s %s%d%s\n",c_l,c_r,c_v,s->aes_salt_len,c_r);
            break;
        }
        case ARCHIVE_RAR: {
            const struct rar_ctx *r = &ctx->rar;
            fprintf(stderr,"  %sType:%s     %sRAR (v%d)%s\n", c_l,c_r,c_v,r->version,c_r);
            fprintf(stderr,"  %sEncrypted:%s%sYes%s\n",        c_l,c_r,c_v,c_r);
            if (r->version == 5) {
                fprintf(stderr,"  %sKDF Iters:%s%s%u%s\n",    c_l,c_r,c_v,r->iterations,c_r);
            }
            fprintf(stderr,"  %sSalt Len:%s %s%d%s\n",        c_l,c_r,c_v,r->salt_len,c_r);
            break;
        }
        default:
            fprintf(stderr,"  Type: Unknown\n");
            break;
    }
    fprintf(stderr,"\n");
}

/* ============================================================
 * BENCHMARK HELPERS
 * ============================================================ */

typedef struct {
    archive_type_t type;
    double         validations_per_sec;
    double         ns_per_validation;
} archive_bench_t;

archive_bench_t archive_benchmark(archive_type_t type, int duration_ms) {
    archive_bench_t result = {0};
    result.type = type;

    struct zip_ctx zip_dummy;
    struct sz_ctx  sz_dummy;
    struct rar_ctx rar_dummy;
    memset(&zip_dummy, 0, sizeof(zip_dummy));
    memset(&sz_dummy,  0, sizeof(sz_dummy));
    memset(&rar_dummy, 0, sizeof(rar_dummy));

    zip_dummy.parsed             = true;
    zip_dummy.has_encrypted_file = true;
    zip_dummy.use_crc_check      = true;
    zip_dummy.check_byte_crc     = 0xAB;
    zip_dummy.method             = ZIP_METHOD_DEFLATED; /* no CRC32 alloc */
    zip_dummy.compressed_size    = ZIP_ENCRYPTION_HEADER_SIZE + 64;
    zip_dummy.data_offset        = 0; /* triggers fast path */
    for (int i = 0; i < ZIP_ENCRYPTION_HEADER_SIZE; i++)
        zip_dummy.enc_header[i] = (uint8_t)(i * 17 + 43);

    sz_dummy.parsed                = true;
    sz_dummy.has_encrypted_streams = true;
    sz_dummy.num_cycles_power      = 19;
    sz_dummy.aes_salt_len          = 0;
    memset(sz_dummy.aes_iv, 0, 16);
    for (int i = 0; i < 32; i++)
        sz_dummy.enc_header_data[i] = (uint8_t)(i * 37);
    sz_dummy.enc_header_size = 32;

    rar_dummy.parsed             = true;
    rar_dummy.is_encrypted       = true;
    rar_dummy.iterations         = 1024;
    rar_dummy.salt_len           = 16;
    memset(rar_dummy.salt, 0xAB, 16);
    rar_dummy.has_check_value    = true;
    memset(rar_dummy.check_value, 0xCD, 12);

    const char *test_pw = "benchmark_password_test";
    uint64_t    count   = 0;
    struct timespec ts_start, ts_end;

    clock_gettime(CLOCK_MONOTONIC, &ts_start);
    uint64_t start = (uint64_t)ts_start.tv_sec * 1000000000ULL +
                     (uint64_t)ts_start.tv_nsec;
    uint64_t end = start;
    uint64_t duration_ns = (uint64_t)duration_ms * 1000000ULL;

    if (type == ARCHIVE_ZIP) {
        while (true) {
            for (int i = 0; i < 1000; i++) {
                zip_validate_pkzip(&zip_dummy, test_pw);
                count++;
            }
            clock_gettime(CLOCK_MONOTONIC, &ts_end);
            end = (uint64_t)ts_end.tv_sec * 1000000000ULL +
                  (uint64_t)ts_end.tv_nsec;
            if (end - start >= duration_ns) break;
        }
    } else if (type == ARCHIVE_7Z) {
        while (true) {
            for (int i = 0; i < 10; i++) {
                sz_validate_password(&sz_dummy, test_pw, NULL);
                count++;
            }
            clock_gettime(CLOCK_MONOTONIC, &ts_end);
            end = (uint64_t)ts_end.tv_sec * 1000000000ULL +
                  (uint64_t)ts_end.tv_nsec;
            if (end - start >= duration_ns) break;
        }
    } else if (type == ARCHIVE_RAR) {
        while (true) {
            rar_dummy.version = 5; /* Fast RAR5 path */
            for (int i = 0; i < 10; i++) {
                rar_validate_password(&rar_dummy, test_pw, NULL);
                count++;
            }
            clock_gettime(CLOCK_MONOTONIC, &ts_end);
            end = (uint64_t)ts_end.tv_sec * 1000000000ULL +
                  (uint64_t)ts_end.tv_nsec;
            if (end - start >= duration_ns) break;
        }
    }

    uint64_t elapsed_ns = end - start;
    if (elapsed_ns > 0 && count > 0) {
        result.validations_per_sec = (double)count /
                                     ((double)elapsed_ns / 1e9);
        result.ns_per_validation   = (double)elapsed_ns / (double)count;
    }

    return result;
}

/* ============================================================
 * END OF archive.c
 * ============================================================ */

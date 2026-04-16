#ifndef ARCHIVE_H
#define ARCHIVE_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#define MAX_PATH_LEN 4096
#define MAX_PASSWORD_LEN 128

/* -------------------------------------------------------------------------
 * Common archive type enumeration
 * ------------------------------------------------------------------------- */
typedef enum {
    ARCHIVE_UNKNOWN = 0,
    ARCHIVE_ZIP     = 1,
    ARCHIVE_7Z      = 2,
    ARCHIVE_RAR     = 3,
    ARCHIVE_MAX
} archive_type_t;

typedef enum {
    ATTACK_NONE         = 0,
    ATTACK_DICTIONARY   = 1,
    ATTACK_BRUTEFORCE   = 2,
    ATTACK_MASK         = 3,
    ATTACK_HYBRID       = 4,
    ATTACK_RULE         = 5,
    ATTACK_BENCHMARK    = 6,
    ATTACK_MAX
} attack_mode_t;

typedef enum {
    LOG_DEBUG   = 0,
    LOG_INFO    = 1,
    LOG_WARNING = 2,
    LOG_ERROR   = 3,
    LOG_SILENT  = 4,
} log_level_t;

typedef enum {
    ATTACK_RESULT_NOT_FOUND = 0,
    ATTACK_RESULT_FOUND     = 1,
    ATTACK_RESULT_EXHAUSTED = 2,
    ATTACK_RESULT_ERROR     = 3,
    ATTACK_RESULT_ABORTED   = 4,
} attack_result_t;

typedef enum {
    RULE_APPEND_DIGIT       = 0,
    RULE_PREPEND_DIGIT      = 1,
    RULE_UPPERCASE_ALL      = 2,
    RULE_LOWERCASE_ALL      = 3,
    RULE_CAPITALIZE         = 4,
    RULE_REVERSE            = 5,
    RULE_DUPLICATE          = 6,
    RULE_LEET_SPEAK         = 7,
    RULE_APPEND_YEAR        = 8,
    RULE_APPEND_SPECIAL     = 9,
    RULE_TOGGLE_CASE        = 10,
    RULE_ROTATE_LEFT        = 11,
    RULE_ROTATE_RIGHT       = 12,
    RULE_REFLECT            = 13,
    RULE_STRIP_VOWELS       = 14,
    RULE_MAX
} rule_type_t;

/* -------------------------------------------------------------------------
 * ZIP context structure – full definition
 * ------------------------------------------------------------------------- */
typedef struct zip_ctx {
    const uint8_t   *data;
    size_t           data_size;
    bool             mmap_used;
    bool             is_clone;
    int              fd;

    char             archive_path[MAX_PATH_LEN];   /* archive path for CLI verification */

    uint32_t         crc32;
    uint16_t         flags;
    uint16_t         method;
    uint32_t         compressed_size;
    uint32_t         uncompressed_size;

    uint8_t          enc_header[12];          /* PKZIP encryption header */
    uint8_t          check_byte_crc;
    uint8_t          check_byte_time;
    bool             use_crc_check;

    bool             is_aes;
    uint8_t          aes_strength;
    uint8_t          aes_salt[16];
    int              aes_salt_len;
    uint8_t          aes_pwv[2];
    uint16_t         aes_actual_method;

    bool             parsed;
    int              num_files;
    char             filename[256];
    bool             has_encrypted_file;
    uint32_t         data_offset;             /* offset of encrypted data (after header) */
} zip_ctx_t;

/* -------------------------------------------------------------------------
 * 7‑Zip constants, signature header, and context structure
 * ------------------------------------------------------------------------- */
#define SZ_SIGNATURE_SIZE           6
#define SZ_SIGNATURE                "\x37\x7A\xBC\xAF\x27\x1C"

/* 7z property IDs */
#define SZ_ID_END                   0x00
#define SZ_ID_HEADER                0x01
#define SZ_ID_ARCHIVE_PROPERTIES    0x02
#define SZ_ID_ADD_STREAMS_INFO      0x03
#define SZ_ID_MAIN_STREAMS_INFO     0x04
#define SZ_ID_FILES_INFO            0x05
#define SZ_ID_PACK_INFO             0x06
#define SZ_ID_UNPACK_INFO           0x07
#define SZ_ID_SUBSTREAMS_INFO       0x08
#define SZ_ID_SIZE                  0x09
#define SZ_ID_CRC                   0x0A
#define SZ_ID_FOLDER                0x0B
#define SZ_ID_CODERS_UNPACK_SIZE    0x0C
#define SZ_ID_NUM_UNPACK_STREAM     0x0D
#define SZ_ID_EMPTY_STREAM          0x0E
#define SZ_ID_EMPTY_FILE            0x0F
#define SZ_ID_ANTI                  0x10
#define SZ_ID_NAME                  0x11
#define SZ_ID_CREATION_TIME         0x12
#define SZ_ID_LAST_ACCESS_TIME      0x13
#define SZ_ID_LAST_WRITE_TIME       0x14
#define SZ_ID_WIN_ATTRIB            0x15
#define SZ_ID_COMMENT               0x16
#define SZ_ID_ENCODED_HEADER        0x17
#define SZ_ID_START_POS             0x18
#define SZ_ID_DUMMY                 0x19

/* 7z codec IDs */
#define SZ_CODEC_COPY               0x00
#define SZ_CODEC_DEFLATE            0x040108
#define SZ_CODEC_BZIP2              0x040202
#define SZ_CODEC_LZMA               0x030101
#define SZ_CODEC_LZMA2              0x21
#define SZ_CODEC_AES256_SHA256      0x06F10701

/* Packed attribute for binary structures */
#define PACKED __attribute__((packed))

/* 7‑Zip signature header (on‑disk layout) */
typedef struct PACKED {
    uint8_t  signature[SZ_SIGNATURE_SIZE];
    uint8_t  major_version;
    uint8_t  minor_version;
    uint32_t start_header_crc;
    uint64_t next_header_offset;
    uint64_t next_header_size;
    uint32_t next_header_crc;
} sz_signature_header_t;

/* 7‑Zip context structure – full definition */
typedef struct sz_ctx {
    const uint8_t   *data;
    size_t           data_size;
    bool             mmap_used;
    bool             is_clone;
    int              fd;

    bool             parsed;
    bool             has_encrypted_streams;
    bool             is_header_encrypted;

    uint8_t          aes_iv[16];
    uint8_t          aes_salt[64];
    uint32_t         num_cycles_power;
    int              aes_salt_len;

    uint8_t          enc_header_data[32];
    size_t           enc_header_size;

    uint32_t         next_header_crc;
    uint64_t         next_header_offset;
    uint64_t         next_header_size;
} sz_ctx_t;

/* -------------------------------------------------------------------------
 * RAR context structure
 * ------------------------------------------------------------------------- */
typedef struct rar_ctx {
    const uint8_t   *data;
    size_t           data_size;
    bool             mmap_used;
    bool             is_clone;
    int              fd;

    bool             parsed;
    int              version;               /* 3 or 5 */

    bool             is_encrypted;
    bool             is_header_encrypted;

    uint8_t          salt[16];
    int              salt_len;
    uint32_t         iterations;

    /* RAR5 specific */
    uint8_t          check_value[12];       /* for RAR5 password validation */
    bool             has_check_value;

    /* RAR3 specific */
    uint8_t          iv[16];
} rar_ctx_t;

/* -------------------------------------------------------------------------
 * Unified archive context (visible to engine.c and main.c)
 * ------------------------------------------------------------------------- */
struct archive_ctx {
    archive_type_t   type;
    char             path[MAX_PATH_LEN];
    union {
        zip_ctx_t    zip;
        sz_ctx_t     sz;
        rar_ctx_t    rar;
    };
    uint8_t          scratch[4096];
};

typedef struct archive_ctx archive_ctx_t;

/* -------------------------------------------------------------------------
 * Function prototypes (implemented in archive.c)
 * ------------------------------------------------------------------------- */
int  archive_open(archive_ctx_t *ctx, const char *path, archive_type_t type);
void archive_ctx_free(archive_ctx_t *ctx);
bool archive_validate_password(const archive_ctx_t *ctx, const char *password);
int  archive_ctx_clone(archive_ctx_t *dst, const archive_ctx_t *src);
void archive_print_info(const archive_ctx_t *ctx, bool no_color);
archive_type_t detect_archive_type(const char *path);
bool command_exists(const char *cmd);

static inline void secure_memzero(void *ptr, size_t len) {
    if (!ptr || len == 0) return;
    volatile uint8_t *p = (volatile uint8_t *)ptr;
    while (len--) *p++ = 0;
}

#endif /* ARCHIVE_H */

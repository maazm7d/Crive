#ifndef ARCHIVE_H
#define ARCHIVE_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#define MAX_PATH_LEN 4096
#define MAX_PASSWORD_LEN 128

typedef enum {
    ARCHIVE_UNKNOWN = 0,
    ARCHIVE_ZIP     = 1,
    ARCHIVE_7Z      = 2,
    ARCHIVE_MAX
} archive_type_t;

/* ZIP context structure – full definition */
typedef struct zip_ctx {
    const uint8_t   *data;
    size_t           data_size;
    bool             mmap_used;
    int              fd;

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
} zip_ctx_t;

/* 7Z context structure – full definition */
typedef struct sz_ctx {
    const uint8_t   *data;
    size_t           data_size;
    bool             mmap_used;
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

/* Unified archive context */
struct archive_ctx {
    archive_type_t   type;
    char             path[MAX_PATH_LEN];
    union {
        zip_ctx_t    zip;
        sz_ctx_t     sz;
    };
    uint8_t          scratch[4096];
};

typedef struct archive_ctx archive_ctx_t;

/* Function prototypes (implemented in archive.c) */
int  archive_open(archive_ctx_t *ctx, const char *path, archive_type_t type);
void archive_ctx_free(archive_ctx_t *ctx);
bool archive_validate_password(const archive_ctx_t *ctx, const char *password);
int  archive_ctx_clone(archive_ctx_t *dst, const archive_ctx_t *src);
void archive_print_info(const archive_ctx_t *ctx, bool no_color);
archive_type_t detect_archive_type(const char *path);

#endif /* ARCHIVE_H */

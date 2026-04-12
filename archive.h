#ifndef ARCHIVE_H
#define ARCHIVE_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#define MAX_PATH_LEN 4096

/* Archive type enumeration */
typedef enum {
    ARCHIVE_UNKNOWN = 0,
    ARCHIVE_ZIP     = 1,
    ARCHIVE_7Z      = 2,
    ARCHIVE_MAX
} archive_type_t;

/* Opaque forward declarations of internal structures */
typedef struct zip_ctx zip_ctx_t;
typedef struct sz_ctx  sz_ctx_t;

/*
 * Unified archive context – complete definition.
 * This must be visible to engine.c, main.c, and archive.c.
 */
struct archive_ctx {
    archive_type_t   type;
    char             path[MAX_PATH_LEN];
    union {
        zip_ctx_t    zip;
        sz_ctx_t     sz;
    };
    uint8_t          scratch[4096];   /* thread‑local scratch buffer */
};

typedef struct archive_ctx archive_ctx_t;

/* Function prototypes – all implemented in archive.c */
int  archive_open(archive_ctx_t *ctx, const char *path, archive_type_t type);
void archive_ctx_free(archive_ctx_t *ctx);
bool archive_validate_password(const archive_ctx_t *ctx, const char *password);
int  archive_ctx_clone(archive_ctx_t *dst, const archive_ctx_t *src);
void archive_print_info(const archive_ctx_t *ctx, bool no_color);
archive_type_t detect_archive_type(const char *path);

#endif /* ARCHIVE_H */

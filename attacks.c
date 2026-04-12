/*
 * attacks.c - All attack strategy implementations
 * Dictionary, Brute-Force, Mask, Hybrid, Rule-Based attacks
 * C11 standard, optimized for Termux/Android Linux
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
#include <pthread.h>
#include <ctype.h>
#include <limits.h>
#include <stdatomic.h>

/* ============================================================
 * FORWARD DECLARATIONS FROM utils.c
 * ============================================================ */

typedef enum {
    LOG_DEBUG   = 0,
    LOG_INFO    = 1,
    LOG_WARNING = 2,
    LOG_ERROR   = 3,
    LOG_SILENT  = 4,
} log_level_t;

void log_message(log_level_t level, const char *fmt, ...);
#define log_debug(fmt, ...)  log_message(LOG_DEBUG,   fmt, ##__VA_ARGS__)
#define log_info(fmt, ...)   log_message(LOG_INFO,    fmt, ##__VA_ARGS__)
#define log_warn(fmt, ...)   log_message(LOG_WARNING, fmt, ##__VA_ARGS__)
#define log_error(fmt, ...)  log_message(LOG_ERROR,   fmt, ##__VA_ARGS__)

#define LIKELY(x)            __builtin_expect(!!(x), 1)
#define UNLIKELY(x)          __builtin_expect(!!(x), 0)
#define FORCE_INLINE         __attribute__((always_inline)) static inline
#define PURE_FN              __attribute__((pure))
#define UNUSED               __attribute__((unused))

#define MAX_PASSWORD_LEN     128
#define MAX_PATH_LEN         4096
#define MAX_CHARSET_LEN      512
#define MAX_MASK_LEN         256
#define MAX_MASK_POSITIONS   32
#define MAX_RULES            4096
#define MAX_LINE_LEN         8192
#define KB                   (1024ULL)
#define MB                   (1024ULL * KB)
#define DEFAULT_BATCH_SIZE   1024

/* ============================================================
 * CHARSET AND MASK STRUCTS (mirrored from utils.c)
 * ============================================================ */

typedef struct {
    char    chars[MAX_CHARSET_LEN];
    int     len;
    bool    use_lower;
    bool    use_upper;
    bool    use_digits;
    bool    use_special;
    bool    use_custom;
    char    custom[MAX_CHARSET_LEN];
} charset_spec_t;

typedef struct {
    char    charset[MAX_CHARSET_LEN];
    int     charset_len;
} mask_position_t;

typedef struct {
    mask_position_t positions[MAX_MASK_POSITIONS];
    int             num_positions;
    char            raw_mask[MAX_MASK_LEN];
} mask_spec_t;

typedef struct {
    bool        append_digits;
    bool        append_special;
    bool        prepend_digits;
    bool        prepend_special;
    int         suffix_min_len;
    int         suffix_max_len;
    int         prefix_min_len;
    int         prefix_max_len;
    char        suffix_charset[MAX_CHARSET_LEN];
    char        prefix_charset[MAX_CHARSET_LEN];
} hybrid_config_t;

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

typedef struct {
    rule_type_t type;
    char        param[64];
    int         param_int;
} rule_t;

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

/* ============================================================
 * ATTACK RESULT CODES
 * ============================================================ */

typedef enum {
    ATTACK_RESULT_NOT_FOUND    = 0,
    ATTACK_RESULT_FOUND        = 1,
    ATTACK_RESULT_EXHAUSTED    = 2,
    ATTACK_RESULT_ERROR        = 3,
    ATTACK_RESULT_ABORTED      = 4,
} attack_result_t;

/* ============================================================
 * CANDIDATE BATCH
 * ============================================================ */

#define CANDIDATE_MAX_LEN   MAX_PASSWORD_LEN
#define BATCH_MAX_SIZE      4096

typedef struct {
    char     passwords[BATCH_MAX_SIZE][CANDIDATE_MAX_LEN];
    int      count;
    int      capacity;
} candidate_batch_t;

FORCE_INLINE void batch_init(candidate_batch_t *b, int capacity) {
    b->count    = 0;
    b->capacity = (capacity > BATCH_MAX_SIZE) ? BATCH_MAX_SIZE : capacity;
}

FORCE_INLINE void batch_reset(candidate_batch_t *b) {
    b->count = 0;
}

FORCE_INLINE bool batch_full(const candidate_batch_t *b) {
    return b->count >= b->capacity;
}

FORCE_INLINE bool batch_empty(const candidate_batch_t *b) {
    return b->count == 0;
}

FORCE_INLINE void batch_add(candidate_batch_t *b, const char *pw) {
    if (b->count < b->capacity) {
        size_t len = strlen(pw);
        if (len >= CANDIDATE_MAX_LEN) len = CANDIDATE_MAX_LEN - 1;
        memcpy(b->passwords[b->count], pw, len);
        b->passwords[b->count][len] = '\0';
        b->count++;
    }
}

/* ============================================================
 * BASE ATTACK INTERFACE
 * ============================================================ */

struct attack_ctx;
typedef struct attack_ctx attack_ctx_t;

typedef int  (*attack_init_fn)      (attack_ctx_t *ctx);
typedef int  (*attack_next_batch_fn)(attack_ctx_t *ctx,
                                      candidate_batch_t *batch);
typedef void (*attack_cleanup_fn)   (attack_ctx_t *ctx);
typedef void (*attack_get_state_fn) (const attack_ctx_t *ctx,
                                      char *buf, size_t buflen);
typedef uint64_t (*attack_keyspace_fn)(const attack_ctx_t *ctx);

typedef struct {
    attack_init_fn       init;
    attack_next_batch_fn next_batch;
    attack_cleanup_fn    cleanup;
    attack_get_state_fn  get_state;
    attack_keyspace_fn   keyspace;
} attack_ops_t;

/* ============================================================
 * THREAD PARTITION DESCRIPTOR
 * Used to split keyspace across threads
 * ============================================================ */

typedef struct {
    int         thread_id;
    int         num_threads;
    uint64_t    start_index;    /* absolute start in keyspace */
    uint64_t    end_index;      /* absolute end (exclusive) */
    uint64_t    local_index;    /* current position within partition */
    uint64_t    total_done;     /* total processed by this thread */
    uint64_t    skip;           /* global skip offset */
    uint64_t    limit;          /* global limit (0 = no limit) */
} thread_partition_t;

/* ============================================================
 * DICTIONARY ATTACK STATE
 * ============================================================ */

#define DICT_IO_BUFFER_SIZE     (4 * MB)
#define DICT_LINE_MAX           MAX_PASSWORD_LEN

typedef struct {
    /* Config */
    char            path[MAX_PATH_LEN];
    uint64_t        start_offset;       /* resume: file offset */
    uint64_t        skip_count;         /* resume: lines already processed */
    int             thread_id;
    int             num_threads;

    /* I/O */
    FILE           *fp;
    uint8_t        *io_buf;
    size_t          io_buf_size;
    size_t          buf_pos;
    size_t          buf_len;
    bool            eof;

    /* State */
    uint64_t        line_number;
    uint64_t        bytes_read;
    int64_t         file_size;

    /* Line buffer (stack allocated) */
    char            line_buf[DICT_LINE_MAX];

    /* Current batch offset for interleaving */
    uint64_t        batch_count;

} dict_state_t;

/*
 * Buffered line reader - reads into io_buf and extracts lines
 * without dynamic allocation. Returns length of line read,
 * 0 on EOF, -1 on error.
 */
static int dict_read_line(dict_state_t *st) {
    int out_len = 0;

    while (out_len < DICT_LINE_MAX - 1) {
        /* Refill buffer if needed */
        if (st->buf_pos >= st->buf_len) {
            if (st->eof) break;
            st->buf_len = fread(st->io_buf, 1, st->io_buf_size, st->fp);
            st->buf_pos = 0;
            if (st->buf_len == 0) {
                if (ferror(st->fp)) return -1;
                st->eof = true;
                break;
            }
            st->bytes_read += st->buf_len;
        }

        uint8_t c = st->io_buf[st->buf_pos++];

        if (c == '\n') {
            /* End of line */
            /* Strip trailing \r if present */
            if (out_len > 0 && st->line_buf[out_len - 1] == '\r') {
                out_len--;
            }
            st->line_number++;
            st->line_buf[out_len] = '\0';
            return out_len;
        }

        if (c == '\r') continue; /* skip CR */

        st->line_buf[out_len++] = (char)c;
    }

    /* Handle file without trailing newline */
    if (out_len > 0) {
        st->line_number++;
        st->line_buf[out_len] = '\0';
        return out_len;
    }

    return 0; /* EOF */
}

static int dict_init(dict_state_t *st,
                      const char *path,
                      uint64_t start_offset,
                      int thread_id,
                      int num_threads) {
    memset(st, 0, sizeof(*st));
    snprintf(st->path, sizeof(st->path), "%s", path);
    st->start_offset = start_offset;
    st->thread_id    = thread_id;
    st->num_threads  = num_threads;

    st->io_buf_size  = DICT_IO_BUFFER_SIZE;
    st->io_buf       = (uint8_t *)malloc(st->io_buf_size);
    if (!st->io_buf) {
        log_error("dict_init: malloc failed for IO buffer");
        return -1;
    }

    st->fp = fopen(path, "rb");
    if (!st->fp) {
        log_error("dict_init: cannot open '%s': %s", path, strerror(errno));
        free(st->io_buf);
        st->io_buf = NULL;
        return -1;
    }

    /* Seek to start offset for resume */
    if (start_offset > 0) {
        if (fseeko(st->fp, (off_t)start_offset, SEEK_SET) != 0) {
            log_warn("dict_init: fseeko failed, reading from start");
        } else {
            st->bytes_read = start_offset;
        }
    }

    /* Get file size */
    struct stat s;
    if (stat(path, &s) == 0) {
        st->file_size = (int64_t)s.st_size;
    } else {
        st->file_size = -1;
    }

    st->buf_pos     = 0;
    st->buf_len     = 0;
    st->eof         = false;
    st->line_number = 0;
    st->batch_count = 0;

    return 0;
}

static void dict_cleanup(dict_state_t *st) {
    if (st->fp)     { fclose(st->fp);     st->fp     = NULL; }
    if (st->io_buf) { free(st->io_buf);   st->io_buf = NULL; }
}

/*
 * Fill a batch from the dictionary.
 * For multi-threading: thread i processes lines where (line_num % num_threads == thread_id).
 * Returns number of candidates added, 0 on EOF.
 */
static int dict_next_batch(dict_state_t *st,
                            candidate_batch_t *batch,
                            uint64_t *total_skipped) {
    batch_reset(batch);
    *total_skipped = 0;

    while (!batch_full(batch)) {
        int len = dict_read_line(st);
        if (len < 0) return -1; /* error */
        if (len == 0 && st->eof) break;
        if (len == 0) continue; /* empty line */

        /* Thread interleaving: each thread processes its stripe */
        if (st->num_threads > 1) {
            uint64_t lnum = st->line_number - 1; /* 0-based */
            if ((lnum % (uint64_t)st->num_threads) !=
                (uint64_t)st->thread_id) {
                (*total_skipped)++;
                continue;
            }
        }

        batch_add(batch, st->line_buf);
    }

    st->batch_count++;
    return batch->count;
}

/* Get current file offset (for resume) */
static uint64_t dict_get_offset(const dict_state_t *st) {
    if (!st->fp) return 0;
    off_t pos = ftello(st->fp);
    if (pos < 0) return 0;
    /* Adjust back by buffered but unprocessed bytes */
    size_t buffered = st->buf_len - st->buf_pos;
    return (uint64_t)(pos - (off_t)buffered);
}

/* ============================================================
 * BRUTE-FORCE STATE
 * ============================================================ */

/*
 * Brute-force uses a base-N counter where N = charset length.
 * The counter array represents digits in the password, each
 * indexing into the charset.
 *
 * Example: charset="abc", length=2
 *   counter[0]=0, counter[1]=0 -> "aa"
 *   counter[0]=1, counter[1]=0 -> "ba"
 *   counter[0]=0, counter[1]=1 -> "ab"
 *   ...
 *
 * Thread partitioning: each thread gets a range of the keyspace.
 * Keyspace for length L with charset size N = N^L.
 * Total keyspace = sum(N^L) for L in [min_len, max_len].
 */

typedef struct {
    /* Config */
    charset_spec_t  charset;
    int             min_length;
    int             max_length;
    int             thread_id;
    int             num_threads;
    uint64_t        skip;
    uint64_t        limit;

    /* Current state */
    int             cur_length;
    int             counter[MAX_PASSWORD_LEN]; /* digit array, LSB first */
    uint64_t        cur_index;                  /* index within current length */
    uint64_t        length_keyspace;            /* total for current length */
    uint64_t        global_index;               /* position in total keyspace */
    uint64_t        global_end;                 /* end position for this thread */
    uint64_t        total_processed;

    /* Pre-built password buffer */
    char            password[MAX_PASSWORD_LEN];

    /* Done flag */
    bool            exhausted;

} brute_state_t;

/*
 * Compute N^exp safely, returning UINT64_MAX on overflow.
 */
static uint64_t safe_pow64(uint64_t base, int exp) {
    if (exp == 0) return 1;
    uint64_t result = 1;
    for (int i = 0; i < exp; i++) {
        if (result > UINT64_MAX / base) return UINT64_MAX;
        result *= base;
    }
    return result;
}

/*
 * Compute total keyspace for lengths [min, max] with charset size N.
 */
static uint64_t brute_total_keyspace(int min_len, int max_len, int N) {
    uint64_t total = 0;
    for (int l = min_len; l <= max_len; l++) {
        uint64_t ks = safe_pow64((uint64_t)N, l);
        if (total > UINT64_MAX - ks) return UINT64_MAX;
        total += ks;
    }
    return total;
}

/*
 * Given a global index, find which (length, local_index) it maps to.
 */
static void brute_index_to_length(int min_len, int max_len, int N,
                                   uint64_t global_idx,
                                   int *out_len,
                                   uint64_t *out_local_idx) {
    uint64_t cumulative = 0;
    for (int l = min_len; l <= max_len; l++) {
        uint64_t ks = safe_pow64((uint64_t)N, l);
        if (global_idx < cumulative + ks) {
            *out_len       = l;
            *out_local_idx = global_idx - cumulative;
            return;
        }
        cumulative += ks;
    }
    /* Past end */
    *out_len       = max_len + 1;
    *out_local_idx = 0;
}

/*
 * Set counter array from a local index (like converting a number
 * to base-N representation).
 */
static void brute_index_to_counter(int *counter, int length,
                                    uint64_t index, int N) {
    for (int i = 0; i < length; i++) {
        counter[i] = (int)(index % (uint64_t)N);
        index      /= (uint64_t)N;
    }
}

/*
 * Build password string from counter array.
 * counter[0] is the leftmost character (MSB of index layout).
 * Wait - actually counter[0] is LSB for standard brute, but we
 * want the most-varying position to be the rightmost character.
 * Let's use: counter[len-1] is MSB, counter[0] is LSB.
 * Password: charset[counter[len-1]] ... charset[counter[0]]
 * This gives "aaa", "baa", "caa" -> "aaa", "baa", "caa" if LSB=left
 * For "aaa", "aab", "aac" (LSB=right), we reverse:
 *   password[i] = charset[counter[len-1-i]]
 */
FORCE_INLINE void brute_build_password(const brute_state_t *st,
                                        char *out) {
    int L = st->cur_length;
    const char *cs = st->charset.chars;
    for (int i = 0; i < L; i++) {
        out[i] = cs[st->counter[L - 1 - i]];
    }
    out[L] = '\0';
}

/*
 * Increment the counter by 1. Returns false when length is exhausted.
 */
FORCE_INLINE bool brute_increment(brute_state_t *st) {
    int N = st->charset.len;
    int L = st->cur_length;

    for (int i = 0; i < L; i++) {
        st->counter[i]++;
        if (st->counter[i] < N) {
            return true; /* no carry */
        }
        st->counter[i] = 0; /* carry */
    }
    return false; /* overflow - length exhausted */
}

/*
 * Advance to next length group.
 */
static bool brute_next_length(brute_state_t *st) {
    if (st->cur_length >= st->max_length) {
        st->exhausted = true;
        return false;
    }
    st->cur_length++;
    memset(st->counter, 0, sizeof(int) * st->cur_length);
    st->cur_index         = 0;
    st->length_keyspace   = safe_pow64((uint64_t)st->charset.len,
                                        st->cur_length);

    /* Compute this thread's range for new length */
    uint64_t per_thread = st->length_keyspace / (uint64_t)st->num_threads;
    uint64_t remainder  = st->length_keyspace % (uint64_t)st->num_threads;

    uint64_t start = (uint64_t)st->thread_id * per_thread +
                     (((uint64_t)st->thread_id < remainder) ?
                      (uint64_t)st->thread_id : remainder);
    uint64_t count = per_thread +
                     (((uint64_t)st->thread_id < remainder) ? 1 : 0);

    if (count == 0) {
        /* This thread has no work for this length - skip */
        return brute_next_length(st);
    }

    brute_index_to_counter(st->counter, st->cur_length, start,
                            st->charset.len);
    st->cur_index   = start;
    st->global_end  = start + count;

    return true;
}

static int brute_init(brute_state_t *st,
                       const charset_spec_t *cs,
                       int min_len, int max_len,
                       int thread_id, int num_threads,
                       uint64_t global_skip,
                       uint64_t limit) {
    memset(st, 0, sizeof(*st));
    memcpy(&st->charset, cs, sizeof(*cs));
    st->min_length  = min_len;
    st->max_length  = max_len;
    st->thread_id   = thread_id;
    st->num_threads = num_threads;
    st->skip        = global_skip;
    st->limit       = limit;
    st->exhausted   = false;

    int N = cs->len;
    if (N == 0) {
        log_error("brute_init: empty charset");
        return -1;
    }

    /* Start at first length */
    st->cur_length      = min_len;
    st->length_keyspace = safe_pow64((uint64_t)N, min_len);

    /* Compute thread's range for first length */
    uint64_t per_thread = st->length_keyspace / (uint64_t)num_threads;
    uint64_t remainder  = st->length_keyspace % (uint64_t)num_threads;

    uint64_t t = (uint64_t)thread_id;
    uint64_t start = t * per_thread +
                     ((t < remainder) ? t : remainder);
    uint64_t count = per_thread + ((t < remainder) ? 1 : 0);

    if (count == 0 && min_len <= max_len) {
        /* No work at this length - advance to find work */
        bool found = false;
        for (int l = min_len + 1; l <= max_len; l++) {
            uint64_t ks = safe_pow64((uint64_t)N, l);
            uint64_t pt = ks / (uint64_t)num_threads;
            uint64_t rm = ks % (uint64_t)num_threads;
            uint64_t cnt = pt + ((t < rm) ? 1 : 0);
            if (cnt > 0) {
                st->cur_length      = l;
                st->length_keyspace = ks;
                uint64_t st_idx = t * pt + ((t < rm) ? t : rm);
                brute_index_to_counter(st->counter, l, st_idx, N);
                st->cur_index  = st_idx;
                st->global_end = st_idx + cnt;
                found = true;
                break;
            }
        }
        if (!found) {
            st->exhausted = true;
        }
    } else {
        brute_index_to_counter(st->counter, min_len, start, N);
        st->cur_index  = start;
        st->global_end = start + count;
    }

    st->total_processed = 0;
    return 0;
}

static int brute_next_batch(brute_state_t *st,
                              candidate_batch_t *batch) {
    batch_reset(batch);

    while (!batch_full(batch)) {
        if (UNLIKELY(st->exhausted)) break;

        /* Check if current length partition is done */
        if (st->cur_index >= st->global_end) {
            /* Move to next length group */
            if (!brute_next_length(st)) {
                st->exhausted = true;
                break;
            }
        }

        /* Build password from counter */
        brute_build_password(st, st->password);

        batch_add(batch, st->password);
        st->total_processed++;

        /* Check limit */
        if (st->limit > 0 && st->total_processed >= st->limit) {
            st->exhausted = true;
            break;
        }

        /* Advance counter */
        st->cur_index++;
        if (!brute_increment(st)) {
            /* Length exhausted - move to next length */
            if (!brute_next_length(st)) {
                st->exhausted = true;
            }
        }
    }

    return batch->count;
}

static void brute_get_state(const brute_state_t *st,
                              char *buf, size_t buflen) {
    char pw[MAX_PASSWORD_LEN];
    brute_build_password(st, pw);
    snprintf(buf, buflen, "len=%d idx=%llu pw=%.32s",
             st->cur_length,
             (unsigned long long)st->cur_index,
             pw);
}

static uint64_t brute_get_keyspace(const brute_state_t *st) {
    return brute_total_keyspace(st->min_length, st->max_length,
                                 st->charset.len);
}

/* ============================================================
 * MASK ATTACK STATE
 * ============================================================ */

/*
 * Mask attack uses the same counter-based approach as brute force,
 * but each position has its own charset from the mask specification.
 *
 * Example mask: ?l?l?d?d
 *   position 0: lowercase (26 chars)
 *   position 1: lowercase (26 chars)
 *   position 2: digits (10 chars)
 *   position 3: digits (10 chars)
 *   keyspace = 26 * 26 * 10 * 10 = 67600
 */

typedef struct {
    /* Config */
    mask_spec_t     mask;
    int             thread_id;
    int             num_threads;
    uint64_t        skip;
    uint64_t        limit;

    /* Counter per position */
    int             counter[MAX_MASK_POSITIONS];

    /* Precomputed keyspace per position and cumulative */
    uint64_t        pos_keyspace[MAX_MASK_POSITIONS]; /* charset len at pos i */
    uint64_t        total_keyspace;

    /* Thread partition */
    uint64_t        start_index;
    uint64_t        end_index;
    uint64_t        cur_index;

    /* Built password */
    char            password[MAX_PASSWORD_LEN];

    /* State */
    uint64_t        total_processed;
    bool            exhausted;

} mask_state_t;

/*
 * Convert linear index to counter array for mask attack.
 * Each position has its own radix (charset length).
 */
static void mask_index_to_counter(int *counter,
                                   const mask_spec_t *mask,
                                   uint64_t index) {
    int N = mask->num_positions;
    for (int i = N - 1; i >= 0; i--) {
        uint64_t radix = (uint64_t)mask->positions[i].charset_len;
        if (radix == 0) radix = 1;
        /* Counter is LSB-first (position 0 varies fastest) */
        /* We want rightmost position to vary fastest */
        int pi = N - 1 - i; /* map: pos 0 = rightmost in password */
        (void)pi;
        counter[i] = (int)(index % radix);
        index      /= radix;
    }
}

FORCE_INLINE void mask_build_password(const mask_state_t *st, char *out) {
    int N = st->mask.num_positions;
    for (int i = 0; i < N; i++) {
        out[i] = st->mask.positions[i].charset[st->counter[i]];
    }
    out[N] = '\0';
}

FORCE_INLINE bool mask_increment(mask_state_t *st) {
    int N = st->mask.num_positions;
    for (int i = N - 1; i >= 0; i--) {
        st->counter[i]++;
        if (st->counter[i] < st->mask.positions[i].charset_len) {
            return true;
        }
        st->counter[i] = 0;
    }
    return false; /* exhausted */
}

static int mask_init(mask_state_t *st,
                      const mask_spec_t *mask,
                      int thread_id, int num_threads,
                      uint64_t skip, uint64_t limit) {
    memset(st, 0, sizeof(*st));
    memcpy(&st->mask, mask, sizeof(*mask));
    st->thread_id   = thread_id;
    st->num_threads = num_threads;
    st->skip        = skip;
    st->limit       = limit;

    /* Compute total keyspace */
    uint64_t ks = 1;
    for (int i = 0; i < mask->num_positions; i++) {
        uint64_t n = (uint64_t)mask->positions[i].charset_len;
        if (n == 0) {
            log_error("mask_init: position %d has empty charset", i);
            return -1;
        }
        if (ks > UINT64_MAX / n) { ks = UINT64_MAX; break; }
        ks *= n;
    }
    st->total_keyspace = ks;

    /* Partition keyspace for this thread */
    uint64_t per_thread = ks / (uint64_t)num_threads;
    uint64_t remainder  = ks % (uint64_t)num_threads;
    uint64_t t          = (uint64_t)thread_id;

    st->start_index = t * per_thread + ((t < remainder) ? t : remainder);
    uint64_t count  = per_thread + ((t < remainder) ? 1 : 0);
    st->end_index   = st->start_index + count;

    /* Apply skip */
    if (skip > 0) {
        st->start_index += skip;
        if (st->start_index >= st->end_index) {
            st->exhausted = true;
            return 0;
        }
    }

    st->cur_index = st->start_index;
    mask_index_to_counter(st->counter, mask, st->cur_index);

    st->total_processed = 0;
    st->exhausted       = (count == 0);
    return 0;
}

static int mask_next_batch(mask_state_t *st, candidate_batch_t *batch) {
    batch_reset(batch);

    while (!batch_full(batch)) {
        if (UNLIKELY(st->exhausted)) break;
        if (UNLIKELY(st->cur_index >= st->end_index)) {
            st->exhausted = true;
            break;
        }

        mask_build_password(st, st->password);
        batch_add(batch, st->password);
        st->total_processed++;
        st->cur_index++;

        if (st->limit > 0 && st->total_processed >= st->limit) {
            st->exhausted = true;
            break;
        }

        if (!mask_increment(st)) {
            st->exhausted = true;
            break;
        }
    }

    return batch->count;
}

static void mask_get_state(const mask_state_t *st, char *buf, size_t buflen) {
    char pw[MAX_PASSWORD_LEN];
    mask_build_password(st, pw);
    snprintf(buf, buflen, "idx=%llu/%llu pw=%.32s",
             (unsigned long long)st->cur_index,
             (unsigned long long)st->total_keyspace,
             pw);
}

/* ============================================================
 * RULE ENGINE
 * ============================================================ */

/*
 * Apply a single rule to a word, producing output in 'out'.
 * Returns the output length, or 0 if rule produced empty string.
 * Returns -1 if output would exceed max_out_len.
 */
static int apply_rule(rule_type_t rule,
                       const char *param,
                       int param_int,
                       const char *in,
                       size_t in_len,
                       char *out,
                       size_t max_out_len) {
    (void)param; /* used by some rules */

    switch (rule) {

        case RULE_APPEND_DIGIT: {
            /* Append digits 0-9 */
            /* This generates multiple outputs - handled by rule batch */
            if (in_len + 2 > max_out_len) return -1;
            memcpy(out, in, in_len);
            out[in_len]     = (char)('0' + (param_int % 10));
            out[in_len + 1] = '\0';
            return (int)(in_len + 1);
        }

        case RULE_PREPEND_DIGIT: {
            if (in_len + 2 > max_out_len) return -1;
            out[0] = (char)('0' + (param_int % 10));
            memcpy(out + 1, in, in_len);
            out[in_len + 1] = '\0';
            return (int)(in_len + 1);
        }

        case RULE_UPPERCASE_ALL: {
            if (in_len + 1 > max_out_len) return -1;
            for (size_t i = 0; i < in_len; i++) {
                out[i] = (char)toupper((unsigned char)in[i]);
            }
            out[in_len] = '\0';
            return (int)in_len;
        }

        case RULE_LOWERCASE_ALL: {
            if (in_len + 1 > max_out_len) return -1;
            for (size_t i = 0; i < in_len; i++) {
                out[i] = (char)tolower((unsigned char)in[i]);
            }
            out[in_len] = '\0';
            return (int)in_len;
        }

        case RULE_CAPITALIZE: {
            if (in_len + 1 > max_out_len) return -1;
            memcpy(out, in, in_len);
            out[in_len] = '\0';
            if (in_len > 0) {
                out[0] = (char)toupper((unsigned char)out[0]);
                for (size_t i = 1; i < in_len; i++) {
                    out[i] = (char)tolower((unsigned char)out[i]);
                }
            }
            return (int)in_len;
        }

        case RULE_REVERSE: {
            if (in_len + 1 > max_out_len) return -1;
            for (size_t i = 0; i < in_len; i++) {
                out[i] = in[in_len - 1 - i];
            }
            out[in_len] = '\0';
            return (int)in_len;
        }

        case RULE_DUPLICATE: {
            if (in_len * 2 + 1 > max_out_len) return -1;
            memcpy(out, in, in_len);
            memcpy(out + in_len, in, in_len);
            out[in_len * 2] = '\0';
            return (int)(in_len * 2);
        }

        case RULE_LEET_SPEAK: {
            if (in_len + 1 > max_out_len) return -1;
            for (size_t i = 0; i < in_len; i++) {
                switch (tolower((unsigned char)in[i])) {
                    case 'a': out[i] = '@'; break;
                    case 'e': out[i] = '3'; break;
                    case 'i': out[i] = '1'; break;
                    case 'o': out[i] = '0'; break;
                    case 's': out[i] = '$'; break;
                    case 't': out[i] = '+'; break;
                    case 'l': out[i] = '!'; break;
                    case 'g': out[i] = '9'; break;
                    case 'b': out[i] = '8'; break;
                    case 'z': out[i] = '2'; break;
                    default:  out[i] = in[i]; break;
                }
            }
            out[in_len] = '\0';
            return (int)in_len;
        }

        case RULE_APPEND_YEAR: {
            /* Append years like 2020-2025 */
            int year = 2020 + (param_int % 6);
            if (in_len + 5 > max_out_len) return -1;
            memcpy(out, in, in_len);
            snprintf(out + in_len, max_out_len - in_len, "%d", year);
            return (int)(in_len + 4);
        }

        case RULE_APPEND_SPECIAL: {
            static const char specials[] = "!@#$%&*";
            int idx = param_int % (int)(sizeof(specials) - 1);
            if (in_len + 2 > max_out_len) return -1;
            memcpy(out, in, in_len);
            out[in_len]     = specials[idx];
            out[in_len + 1] = '\0';
            return (int)(in_len + 1);
        }

        case RULE_TOGGLE_CASE: {
            if (in_len + 1 > max_out_len) return -1;
            for (size_t i = 0; i < in_len; i++) {
                if (isupper((unsigned char)in[i])) {
                    out[i] = (char)tolower((unsigned char)in[i]);
                } else if (islower((unsigned char)in[i])) {
                    out[i] = (char)toupper((unsigned char)in[i]);
                } else {
                    out[i] = in[i];
                }
            }
            out[in_len] = '\0';
            return (int)in_len;
        }

        case RULE_ROTATE_LEFT: {
            if (in_len == 0) return 0;
            if (in_len + 1 > max_out_len) return -1;
            int n = (param_int == 0) ? 1 : param_int % (int)in_len;
            for (size_t i = 0; i < in_len; i++) {
                out[i] = in[(i + n) % in_len];
            }
            out[in_len] = '\0';
            return (int)in_len;
        }

        case RULE_ROTATE_RIGHT: {
            if (in_len == 0) return 0;
            if (in_len + 1 > max_out_len) return -1;
            int n = (param_int == 0) ? 1 : param_int % (int)in_len;
            for (size_t i = 0; i < in_len; i++) {
                out[i] = in[(i - n + (int)in_len) % (int)in_len];
            }
            out[in_len] = '\0';
            return (int)in_len;
        }

        case RULE_REFLECT: {
            /* word + reverse(word) */
            if (in_len * 2 + 1 > max_out_len) return -1;
            memcpy(out, in, in_len);
            for (size_t i = 0; i < in_len; i++) {
                out[in_len + i] = in[in_len - 1 - i];
            }
            out[in_len * 2] = '\0';
            return (int)(in_len * 2);
        }

        case RULE_STRIP_VOWELS: {
            size_t j = 0;
            for (size_t i = 0; i < in_len && j < max_out_len - 1; i++) {
                char c = (char)tolower((unsigned char)in[i]);
                if (c != 'a' && c != 'e' && c != 'i' &&
                    c != 'o' && c != 'u') {
                    out[j++] = in[i];
                }
            }
            out[j] = '\0';
            return (int)j;
        }

        default:
            /* Unknown rule - passthrough */
            if (in_len + 1 > max_out_len) return -1;
            memcpy(out, in, in_len);
            out[in_len] = '\0';
            return (int)in_len;
    }
}

/* ============================================================
 * RULE SET
 * ============================================================ */

/*
 * A rule_set_t defines all rules to apply to each base word.
 * For each base word, we generate one candidate per (rule, param_variant).
 * Plus the original word itself.
 */

#define MAX_RULE_VARIANTS   64  /* max param variants per rule type */

typedef struct {
    rule_type_t type;
    int         param_values[MAX_RULE_VARIANTS];
    int         num_variants;
    char        param[64];
} rule_entry_t;

typedef struct {
    rule_entry_t entries[MAX_RULES];
    int          num_entries;
} rule_set_t;

/*
 * Build default rule set (used when no rules file is specified).
 */
static void rule_set_default(rule_set_t *rs) {
    memset(rs, 0, sizeof(*rs));
    int idx = 0;

    /* Original (passthrough - no rule needed, handled in engine) */

    /* Capitalize */
    rs->entries[idx].type = RULE_CAPITALIZE;
    rs->entries[idx].num_variants = 1;
    rs->entries[idx].param_values[0] = 0;
    idx++;

    /* Uppercase all */
    rs->entries[idx].type = RULE_UPPERCASE_ALL;
    rs->entries[idx].num_variants = 1;
    rs->entries[idx].param_values[0] = 0;
    idx++;

    /* Lowercase all */
    rs->entries[idx].type = RULE_LOWERCASE_ALL;
    rs->entries[idx].num_variants = 1;
    rs->entries[idx].param_values[0] = 0;
    idx++;

    /* Leet speak */
    rs->entries[idx].type = RULE_LEET_SPEAK;
    rs->entries[idx].num_variants = 1;
    rs->entries[idx].param_values[0] = 0;
    idx++;

    /* Reverse */
    rs->entries[idx].type = RULE_REVERSE;
    rs->entries[idx].num_variants = 1;
    rs->entries[idx].param_values[0] = 0;
    idx++;

    /* Duplicate */
    rs->entries[idx].type = RULE_DUPLICATE;
    rs->entries[idx].num_variants = 1;
    rs->entries[idx].param_values[0] = 0;
    idx++;

    /* Toggle case */
    rs->entries[idx].type = RULE_TOGGLE_CASE;
    rs->entries[idx].num_variants = 1;
    rs->entries[idx].param_values[0] = 0;
    idx++;

    /* Append digits 0-9 */
    rs->entries[idx].type = RULE_APPEND_DIGIT;
    rs->entries[idx].num_variants = 10;
    for (int i = 0; i < 10; i++) rs->entries[idx].param_values[i] = i;
    idx++;

    /* Prepend digits 0-9 */
    rs->entries[idx].type = RULE_PREPEND_DIGIT;
    rs->entries[idx].num_variants = 10;
    for (int i = 0; i < 10; i++) rs->entries[idx].param_values[i] = i;
    idx++;

    /* Append years 2020-2025 */
    rs->entries[idx].type = RULE_APPEND_YEAR;
    rs->entries[idx].num_variants = 6;
    for (int i = 0; i < 6; i++) rs->entries[idx].param_values[i] = i;
    idx++;

    /* Append special chars */
    rs->entries[idx].type = RULE_APPEND_SPECIAL;
    rs->entries[idx].num_variants = 7;
    for (int i = 0; i < 7; i++) rs->entries[idx].param_values[i] = i;
    idx++;

    /* Reflect */
    rs->entries[idx].type = RULE_REFLECT;
    rs->entries[idx].num_variants = 1;
    rs->entries[idx].param_values[0] = 0;
    idx++;

    /* Strip vowels */
    rs->entries[idx].type = RULE_STRIP_VOWELS;
    rs->entries[idx].num_variants = 1;
    rs->entries[idx].param_values[0] = 0;
    idx++;

    rs->num_entries = idx;
}

/*
 * Load rules from file. Format: one rule per line.
 * Rule formats:
 *   capitalize
 *   uppercase
 *   lowercase
 *   leet
 *   reverse
 *   duplicate
 *   toggle
 *   append_digit
 *   prepend_digit
 *   append_year
 *   append_special
 *   reflect
 *   strip_vowels
 */
static int rule_set_load(rule_set_t *rs, const char *path) {
    memset(rs, 0, sizeof(*rs));

    FILE *f = fopen(path, "r");
    if (!f) {
        log_error("rule_set_load: cannot open '%s': %s",
                  path, strerror(errno));
        return -1;
    }

    char line[256];
    int  idx = 0;

    while (fgets(line, sizeof(line), f) && idx < MAX_RULES) {
        /* Trim */
        size_t len = strlen(line);
        while (len > 0 && (line[len-1] == '\n' || line[len-1] == '\r' ||
                            line[len-1] == ' ')) {
            line[--len] = '\0';
        }
        if (len == 0 || line[0] == '#') continue;

        rule_entry_t *e = &rs->entries[idx];
        memset(e, 0, sizeof(*e));
        snprintf(e->param, sizeof(e->param), "%s", line);

        if      (strcmp(line, "capitalize")    == 0) {
            e->type = RULE_CAPITALIZE;
            e->num_variants = 1;
            e->param_values[0] = 0;
        } else if (strcmp(line, "uppercase")   == 0) {
            e->type = RULE_UPPERCASE_ALL;
            e->num_variants = 1;
            e->param_values[0] = 0;
        } else if (strcmp(line, "lowercase")   == 0) {
            e->type = RULE_LOWERCASE_ALL;
            e->num_variants = 1;
            e->param_values[0] = 0;
        } else if (strcmp(line, "leet")        == 0) {
            e->type = RULE_LEET_SPEAK;
            e->num_variants = 1;
            e->param_values[0] = 0;
        } else if (strcmp(line, "reverse")     == 0) {
            e->type = RULE_REVERSE;
            e->num_variants = 1;
            e->param_values[0] = 0;
        } else if (strcmp(line, "duplicate")   == 0) {
            e->type = RULE_DUPLICATE;
            e->num_variants = 1;
            e->param_values[0] = 0;
        } else if (strcmp(line, "toggle")      == 0) {
            e->type = RULE_TOGGLE_CASE;
            e->num_variants = 1;
            e->param_values[0] = 0;
        } else if (strcmp(line, "append_digit") == 0) {
            e->type = RULE_APPEND_DIGIT;
            e->num_variants = 10;
            for (int i = 0; i < 10; i++) e->param_values[i] = i;
        } else if (strcmp(line, "prepend_digit") == 0) {
            e->type = RULE_PREPEND_DIGIT;
            e->num_variants = 10;
            for (int i = 0; i < 10; i++) e->param_values[i] = i;
        } else if (strcmp(line, "append_year") == 0) {
            e->type = RULE_APPEND_YEAR;
            e->num_variants = 6;
            for (int i = 0; i < 6; i++) e->param_values[i] = i;
        } else if (strcmp(line, "append_special") == 0) {
            e->type = RULE_APPEND_SPECIAL;
            e->num_variants = 7;
            for (int i = 0; i < 7; i++) e->param_values[i] = i;
        } else if (strcmp(line, "reflect")     == 0) {
            e->type = RULE_REFLECT;
            e->num_variants = 1;
            e->param_values[0] = 0;
        } else if (strcmp(line, "strip_vowels") == 0) {
            e->type = RULE_STRIP_VOWELS;
            e->num_variants = 1;
            e->param_values[0] = 0;
        } else if (strcmp(line, "rotate_left") == 0) {
            e->type = RULE_ROTATE_LEFT;
            e->num_variants = 3;
            e->param_values[0] = 1;
            e->param_values[1] = 2;
            e->param_values[2] = 3;
        } else if (strcmp(line, "rotate_right") == 0) {
            e->type = RULE_ROTATE_RIGHT;
            e->num_variants = 3;
            e->param_values[0] = 1;
            e->param_values[1] = 2;
            e->param_values[2] = 3;
        } else {
            log_warn("rule_set_load: unknown rule '%s', skipping", line);
            continue;
        }
        idx++;
    }

    fclose(f);
    rs->num_entries = idx;
    log_info("rule_set_load: loaded %d rules from '%s'", idx, path);
    return 0;
}

/* ============================================================
 * RULE-BASED ATTACK STATE
 * ============================================================ */

typedef struct {
    /* Dictionary reader */
    dict_state_t    dict;

    /* Rule set */
    rule_set_t      rules;

    /* State for applying rules to current word */
    char            base_word[MAX_PASSWORD_LEN];
    size_t          base_len;
    bool            base_valid;
    int             rule_idx;       /* current rule entry */
    int             variant_idx;    /* current variant within rule */
    bool            emitted_original; /* did we emit the base word? */

    /* Thread info */
    int             thread_id;
    int             num_threads;

    /* Stats */
    uint64_t        total_processed;
    bool            exhausted;

    /* Scratch buffer */
    char            scratch[MAX_PASSWORD_LEN];

} rule_state_t;

static int rule_state_init(rule_state_t *st,
                            const char *wordlist_path,
                            const char *rules_path,
                            int thread_id,
                            int num_threads,
                            uint64_t file_offset) {
    memset(st, 0, sizeof(*st));
    st->thread_id   = thread_id;
    st->num_threads = num_threads;

    if (dict_init(&st->dict, wordlist_path, file_offset,
                  thread_id, num_threads) != 0) {
        return -1;
    }

    if (rules_path && rules_path[0] != '\0') {
        if (rule_set_load(&st->rules, rules_path) != 0) {
            log_warn("rule_state_init: using default rules");
            rule_set_default(&st->rules);
        }
    } else {
        rule_set_default(&st->rules);
    }

    st->base_valid        = false;
    st->rule_idx          = 0;
    st->variant_idx       = 0;
    st->emitted_original  = false;
    st->exhausted         = false;
    st->total_processed   = 0;

    return 0;
}

static void rule_state_cleanup(rule_state_t *st) {
    dict_cleanup(&st->dict);
}

/*
 * Get next base word from dictionary.
 * Returns true if a new word was loaded, false on EOF.
 */
static bool rule_load_next_word(rule_state_t *st) {
    while (true) {
        int len = dict_read_line(&st->dict);
        if (len < 0) return false; /* error */
        if (len == 0 && st->dict.eof) return false;
        if (len == 0) continue;

        /* Thread interleaving */
        if (st->num_threads > 1) {
            uint64_t lnum = st->dict.line_number - 1;
            if ((lnum % (uint64_t)st->num_threads) !=
                (uint64_t)st->thread_id) {
                continue;
            }
        }

        memcpy(st->base_word, st->dict.line_buf, len);
        st->base_word[len] = '\0';
        st->base_len       = (size_t)len;
        st->base_valid     = true;
        st->rule_idx       = 0;
        st->variant_idx    = 0;
        st->emitted_original = false;
        return true;
    }
}

/*
 * Get next rule-generated candidate.
 * Returns true and fills 'out' with the next candidate.
 * Returns false when all rules for current word are exhausted.
 */
static bool rule_next_candidate(rule_state_t *st, char *out) {
    if (!st->base_valid) return false;

    /* First: emit original word */
    if (!st->emitted_original) {
        memcpy(out, st->base_word, st->base_len + 1);
        st->emitted_original = true;
        return true;
    }

    /* Then: iterate through rules and variants */
    while (st->rule_idx < st->rules.num_entries) {
        rule_entry_t *re = &st->rules.entries[st->rule_idx];

        if (st->variant_idx < re->num_variants) {
            int pv = re->param_values[st->variant_idx];
            st->variant_idx++;

            int rlen = apply_rule(re->type, re->param, pv,
                                   st->base_word, st->base_len,
                                   out, MAX_PASSWORD_LEN);

            if (rlen <= 0) continue; /* rule failed or empty */
            if (rlen >= MAX_PASSWORD_LEN) continue; /* too long */

            /* Skip if identical to base word (already emitted) */
            if (rlen == (int)st->base_len &&
                memcmp(out, st->base_word, st->base_len) == 0) {
                continue;
            }

            return true;
        }

        /* Move to next rule */
        st->rule_idx++;
        st->variant_idx = 0;
    }

    return false; /* all rules exhausted for this word */
}

static int rule_next_batch(rule_state_t *st, candidate_batch_t *batch) {
    batch_reset(batch);

    while (!batch_full(batch)) {
        if (UNLIKELY(st->exhausted)) break;

        /* Try to get next candidate from current word */
        if (st->base_valid) {
            char pw[MAX_PASSWORD_LEN];
            if (rule_next_candidate(st, pw)) {
                batch_add(batch, pw);
                st->total_processed++;
                continue;
            }
        }

        /* Load next base word */
        if (!rule_load_next_word(st)) {
            st->exhausted = true;
            break;
        }
    }

    return batch->count;
}

/* ============================================================
 * HYBRID ATTACK STATE
 * ============================================================ */

/*
 * Hybrid attack: takes base words from a dictionary and
 * appends/prepends generated suffixes/prefixes.
 *
 * For each base word, we generate:
 *   base + suffix   (suffix from charset, length suffix_min..suffix_max)
 *   prefix + base   (prefix from charset, length prefix_min..prefix_max)
 *
 * The suffix/prefix generation uses the same counter-based approach
 * as brute force, but with a configurable charset.
 */

typedef struct {
    /* Dictionary state */
    dict_state_t    dict;

    /* Hybrid config */
    hybrid_config_t config;

    /* Current base word */
    char            base_word[MAX_PASSWORD_LEN];
    size_t          base_len;
    bool            base_valid;

    /* Suffix/prefix generator state */
    charset_spec_t  suffix_cs;
    charset_spec_t  prefix_cs;

    /* Current suffix state */
    int             suffix_len;
    int             suffix_counter[MAX_PASSWORD_LEN];
    uint64_t        suffix_index;
    uint64_t        suffix_total;
    bool            suffix_done;

    /* Current prefix state */
    int             prefix_len;
    int             prefix_counter[MAX_PASSWORD_LEN];
    uint64_t        prefix_index;
    uint64_t        prefix_total;
    bool            prefix_done;

    /* Mode: 0=suffix, 1=prefix */
    int             mode;

    /* Thread info */
    int             thread_id;
    int             num_threads;

    /* Stats */
    uint64_t        total_processed;
    bool            exhausted;

    /* Output buffer */
    char            candidate[MAX_PASSWORD_LEN];

} hybrid_state_t;

static void hybrid_reset_suffix(hybrid_state_t *st) {
    if (st->config.suffix_min_len <= 0) {
        st->suffix_done = true;
        return;
    }
    st->suffix_len     = st->config.suffix_min_len;
    st->suffix_index   = 0;
    st->suffix_total   = safe_pow64((uint64_t)st->suffix_cs.len,
                                     st->suffix_len);
    memset(st->suffix_counter, 0,
           sizeof(int) * st->suffix_len);
    st->suffix_done    = false;
}

static void hybrid_reset_prefix(hybrid_state_t *st) {
    if (st->config.prefix_min_len <= 0) {
        st->prefix_done = true;
        return;
    }
    st->prefix_len     = st->config.prefix_min_len;
    st->prefix_index   = 0;
    st->prefix_total   = safe_pow64((uint64_t)st->prefix_cs.len,
                                     st->prefix_len);
    memset(st->prefix_counter, 0,
           sizeof(int) * st->prefix_len);
    st->prefix_done    = false;
}

static int hybrid_init(hybrid_state_t *st,
                        const char *wordlist_path,
                        const hybrid_config_t *cfg,
                        const charset_spec_t *suffix_cs,
                        const charset_spec_t *prefix_cs,
                        int thread_id, int num_threads,
                        uint64_t file_offset) {
    memset(st, 0, sizeof(*st));
    memcpy(&st->config, cfg, sizeof(*cfg));
    st->thread_id   = thread_id;
    st->num_threads = num_threads;

    if (dict_init(&st->dict, wordlist_path, file_offset,
                  thread_id, num_threads) != 0) {
        return -1;
    }

    /* Set up charsets */
    if (suffix_cs && suffix_cs->len > 0) {
        memcpy(&st->suffix_cs, suffix_cs, sizeof(*suffix_cs));
    } else {
        /* Default suffix charset: digits */
        memcpy(st->suffix_cs.chars, "0123456789", 10);
        st->suffix_cs.chars[10] = '\0';
        st->suffix_cs.len = 10;
    }

    if (prefix_cs && prefix_cs->len > 0) {
        memcpy(&st->prefix_cs, prefix_cs, sizeof(*prefix_cs));
    } else {
        memcpy(st->prefix_cs.chars, "0123456789", 10);
        st->prefix_cs.chars[10] = '\0';
        st->prefix_cs.len = 10;
    }

    st->base_valid      = false;
    st->exhausted       = false;
    st->total_processed = 0;
    st->mode            = 0; /* start with suffix */
    st->suffix_done     = true;
    st->prefix_done     = true;

    return 0;
}

static void hybrid_cleanup(hybrid_state_t *st) {
    dict_cleanup(&st->dict);
}

static bool hybrid_load_next_word(hybrid_state_t *st) {
    while (true) {
        int len = dict_read_line(&st->dict);
        if (len < 0 || (len == 0 && st->dict.eof)) return false;
        if (len == 0) continue;

        if (st->num_threads > 1) {
            uint64_t lnum = st->dict.line_number - 1;
            if ((lnum % (uint64_t)st->num_threads) !=
                (uint64_t)st->thread_id) {
                continue;
            }
        }

        memcpy(st->base_word, st->dict.line_buf, len);
        st->base_word[len] = '\0';
        st->base_len       = (size_t)len;
        st->base_valid     = true;
        st->mode           = 0;

        /* Reset generators */
        hybrid_reset_suffix(st);
        hybrid_reset_prefix(st);

        return true;
    }
}

static bool hybrid_increment_suffix(hybrid_state_t *st) {
    int N = st->suffix_cs.len;
    int L = st->suffix_len;

    /* Increment counter */
    for (int i = L - 1; i >= 0; i--) {
        st->suffix_counter[i]++;
        if (st->suffix_counter[i] < N) {
            st->suffix_index++;
            return true;
        }
        st->suffix_counter[i] = 0;
    }

    /* Counter overflowed - try next length */
    if (st->suffix_len < st->config.suffix_max_len) {
        st->suffix_len++;
        st->suffix_total = safe_pow64((uint64_t)N, st->suffix_len);
        st->suffix_index = 0;
        memset(st->suffix_counter, 0, sizeof(int) * st->suffix_len);
        return true;
    }

    return false; /* all suffix lengths exhausted */
}

static bool hybrid_increment_prefix(hybrid_state_t *st) {
    int N = st->prefix_cs.len;
    int L = st->prefix_len;

    for (int i = L - 1; i >= 0; i--) {
        st->prefix_counter[i]++;
        if (st->prefix_counter[i] < N) {
            st->prefix_index++;
            return true;
        }
        st->prefix_counter[i] = 0;
    }

    if (st->prefix_len < st->config.prefix_max_len) {
        st->prefix_len++;
        st->prefix_total = safe_pow64((uint64_t)N, st->prefix_len);
        st->prefix_index = 0;
        memset(st->prefix_counter, 0, sizeof(int) * st->prefix_len);
        return true;
    }

    return false;
}

/*
 * Build current suffix candidate into out.
 * Returns true if candidate was built successfully.
 */
static bool hybrid_build_suffix_candidate(hybrid_state_t *st, char *out) {
    if (st->suffix_done) return false;

    int L = st->suffix_len;
    if (st->base_len + (size_t)L >= MAX_PASSWORD_LEN) return false;

    /* Emit base word first (no suffix) on first iteration */
    memcpy(out, st->base_word, st->base_len);

    /* Append suffix */
    const char *cs = st->suffix_cs.chars;
    for (int i = 0; i < L; i++) {
        out[st->base_len + i] = cs[st->suffix_counter[i]];
    }
    out[st->base_len + L] = '\0';
    return true;
}

static bool hybrid_build_prefix_candidate(hybrid_state_t *st, char *out) {
    if (st->prefix_done) return false;

    int L = st->prefix_len;
    if (st->base_len + (size_t)L >= MAX_PASSWORD_LEN) return false;

    const char *cs = st->prefix_cs.chars;
    for (int i = 0; i < L; i++) {
        out[i] = cs[st->prefix_counter[i]];
    }
    memcpy(out + L, st->base_word, st->base_len);
    out[L + st->base_len] = '\0';
    return true;
}

static int hybrid_next_batch(hybrid_state_t *st, candidate_batch_t *batch) {
    batch_reset(batch);

    while (!batch_full(batch)) {
        if (UNLIKELY(st->exhausted)) break;

        if (!st->base_valid) {
            if (!hybrid_load_next_word(st)) {
                st->exhausted = true;
                break;
            }
            /* Emit base word without modifications */
            batch_add(batch, st->base_word);
            st->total_processed++;
            continue;
        }

        /* Emit suffix candidates */
        if (!st->suffix_done) {
            char pw[MAX_PASSWORD_LEN];
            if (hybrid_build_suffix_candidate(st, pw)) {
                batch_add(batch, pw);
                st->total_processed++;
            }
            if (!hybrid_increment_suffix(st)) {
                st->suffix_done = true;
            }
            continue;
        }

        /* Emit prefix candidates */
        if (!st->prefix_done) {
            char pw[MAX_PASSWORD_LEN];
            if (hybrid_build_prefix_candidate(st, pw)) {
                batch_add(batch, pw);
                st->total_processed++;
            }
            if (!hybrid_increment_prefix(st)) {
                st->prefix_done = true;
            }
            continue;
        }

        /* Both suffix and prefix done - load next word */
        st->base_valid = false;
    }

    return batch->count;
}

/* ============================================================
 * UNIFIED ATTACK CONTEXT
 * ============================================================ */

typedef struct attack_ctx {
    attack_mode_t   mode;
    attack_ops_t    ops;
    int             thread_id;
    int             num_threads;
    uint64_t        total_generated;
    bool            initialized;

    /* Union of attack-specific states */
    union {
        dict_state_t    dict;
        brute_state_t   brute;
        mask_state_t    mask;
        rule_state_t    rule;
        hybrid_state_t  hybrid;
    };

    /* Shared config (read-only) */
    const void *config_ref;

} attack_ctx_t;

/* ============================================================
 * ATTACK CONTEXT INIT/CLEANUP
 * ============================================================ */

int attack_ctx_init_dict(attack_ctx_t *ctx,
                          const char *wordlist_path,
                          uint64_t file_offset,
                          int thread_id,
                          int num_threads) {
    memset(ctx, 0, sizeof(*ctx));
    ctx->mode       = ATTACK_DICTIONARY;
    ctx->thread_id  = thread_id;
    ctx->num_threads = num_threads;

    int rc = dict_init(&ctx->dict, wordlist_path, file_offset,
                        thread_id, num_threads);
    if (rc != 0) return rc;

    ctx->initialized = true;
    return 0;
}

int attack_ctx_init_brute(attack_ctx_t *ctx,
                           const charset_spec_t *cs,
                           int min_len, int max_len,
                           int thread_id, int num_threads,
                           uint64_t skip, uint64_t limit) {
    memset(ctx, 0, sizeof(*ctx));
    ctx->mode        = ATTACK_BRUTEFORCE;
    ctx->thread_id   = thread_id;
    ctx->num_threads = num_threads;

    int rc = brute_init(&ctx->brute, cs, min_len, max_len,
                         thread_id, num_threads, skip, limit);
    if (rc != 0) return rc;

    ctx->initialized = true;
    return 0;
}

int attack_ctx_init_mask(attack_ctx_t *ctx,
                          const mask_spec_t *mask,
                          int thread_id, int num_threads,
                          uint64_t skip, uint64_t limit) {
    memset(ctx, 0, sizeof(*ctx));
    ctx->mode        = ATTACK_MASK;
    ctx->thread_id   = thread_id;
    ctx->num_threads = num_threads;

    int rc = mask_init(&ctx->mask, mask, thread_id, num_threads,
                        skip, limit);
    if (rc != 0) return rc;

    ctx->initialized = true;
    return 0;
}

int attack_ctx_init_rule(attack_ctx_t *ctx,
                          const char *wordlist_path,
                          const char *rules_path,
                          int thread_id, int num_threads,
                          uint64_t file_offset) {
    memset(ctx, 0, sizeof(*ctx));
    ctx->mode        = ATTACK_RULE;
    ctx->thread_id   = thread_id;
    ctx->num_threads = num_threads;

    int rc = rule_state_init(&ctx->rule, wordlist_path, rules_path,
                              thread_id, num_threads, file_offset);
    if (rc != 0) return rc;

    ctx->initialized = true;
    return 0;
}

int attack_ctx_init_hybrid(attack_ctx_t *ctx,
                            const char *wordlist_path,
                            const hybrid_config_t *cfg,
                            const charset_spec_t *suffix_cs,
                            const charset_spec_t *prefix_cs,
                            int thread_id, int num_threads,
                            uint64_t file_offset) {
    memset(ctx, 0, sizeof(*ctx));
    ctx->mode        = ATTACK_HYBRID;
    ctx->thread_id   = thread_id;
    ctx->num_threads = num_threads;

    int rc = hybrid_init(&ctx->hybrid, wordlist_path, cfg,
                          suffix_cs, prefix_cs,
                          thread_id, num_threads, file_offset);
    if (rc != 0) return rc;

    ctx->initialized = true;
    return 0;
}

void attack_ctx_cleanup(attack_ctx_t *ctx) {
    if (!ctx || !ctx->initialized) return;

    switch (ctx->mode) {
        case ATTACK_DICTIONARY:
            dict_cleanup(&ctx->dict);
            break;
        case ATTACK_RULE:
            rule_state_cleanup(&ctx->rule);
            break;
        case ATTACK_HYBRID:
            hybrid_cleanup(&ctx->hybrid);
            break;
        default:
            break;
    }
    ctx->initialized = false;
}

/*
 * Unified next_batch dispatcher.
 * Returns number of candidates generated, 0 if exhausted.
 */
int attack_ctx_next_batch(attack_ctx_t *ctx, candidate_batch_t *batch) {
    if (UNLIKELY(!ctx->initialized)) return 0;

    int count = 0;
    uint64_t skipped = 0;

    switch (ctx->mode) {
        case ATTACK_DICTIONARY:
            count = dict_next_batch(&ctx->dict, batch, &skipped);
            break;

        case ATTACK_BRUTEFORCE:
            count = brute_next_batch(&ctx->brute, batch);
            break;

        case ATTACK_MASK:
            count = mask_next_batch(&ctx->mask, batch);
            break;

        case ATTACK_RULE:
            count = rule_next_batch(&ctx->rule, batch);
            break;

        case ATTACK_HYBRID:
            count = hybrid_next_batch(&ctx->hybrid, batch);
            break;

        default:
            return 0;
    }

    if (count > 0) {
        ctx->total_generated += (uint64_t)count;
    }
    return count;
}

/*
 * Check if this attack context is exhausted.
 */
bool attack_ctx_exhausted(const attack_ctx_t *ctx) {
    if (!ctx->initialized) return true;

    switch (ctx->mode) {
        case ATTACK_DICTIONARY:
            return ctx->dict.eof && ctx->dict.buf_pos >= ctx->dict.buf_len;
        case ATTACK_BRUTEFORCE:
            return ctx->brute.exhausted;
        case ATTACK_MASK:
            return ctx->mask.exhausted;
        case ATTACK_RULE:
            return ctx->rule.exhausted;
        case ATTACK_HYBRID:
            return ctx->hybrid.exhausted;
        default:
            return true;
    }
}

/*
 * Get current state description for display.
 */
void attack_ctx_get_state(const attack_ctx_t *ctx,
                           char *buf, size_t buflen) {
    if (!ctx->initialized) {
        snprintf(buf, buflen, "(not initialized)");
        return;
    }

    switch (ctx->mode) {
        case ATTACK_DICTIONARY:
            snprintf(buf, buflen, "line=%llu offset=%llu",
                     (unsigned long long)ctx->dict.line_number,
                     (unsigned long long)dict_get_offset(&ctx->dict));
            break;

        case ATTACK_BRUTEFORCE:
            brute_get_state(&ctx->brute, buf, buflen);
            break;

        case ATTACK_MASK:
            mask_get_state(&ctx->mask, buf, buflen);
            break;

        case ATTACK_RULE:
            snprintf(buf, buflen, "word=%.32s rule=%d",
                     ctx->rule.base_word,
                     ctx->rule.rule_idx);
            break;

        case ATTACK_HYBRID:
            snprintf(buf, buflen, "word=%.32s sfx_len=%d pfx_len=%d",
                     ctx->hybrid.base_word,
                     ctx->hybrid.suffix_len,
                     ctx->hybrid.prefix_len);
            break;

        default:
            snprintf(buf, buflen, "unknown");
            break;
    }
}

/*
 * Get total keyspace estimate.
 */
uint64_t attack_ctx_keyspace(const attack_ctx_t *ctx) {
    if (!ctx->initialized) return 0;

    switch (ctx->mode) {
        case ATTACK_BRUTEFORCE:
            return brute_get_keyspace(&ctx->brute);

        case ATTACK_MASK:
            return ctx->mask.total_keyspace;

        case ATTACK_DICTIONARY:
            if (ctx->dict.file_size > 0) {
                /* Estimate based on average line length */
                return (uint64_t)(ctx->dict.file_size / 8);
            }
            return 0;

        case ATTACK_RULE:
        case ATTACK_HYBRID:
            /* Too complex to estimate accurately without reading file */
            return 0;

        default:
            return 0;
    }
}

/*
 * Get resume state for dictionary attacks.
 */
uint64_t attack_ctx_get_dict_offset(const attack_ctx_t *ctx) {
    if (ctx->mode == ATTACK_DICTIONARY) {
        return dict_get_offset(&ctx->dict);
    }
    if (ctx->mode == ATTACK_RULE) {
        return dict_get_offset(&ctx->rule.dict);
    }
    if (ctx->mode == ATTACK_HYBRID) {
        return dict_get_offset(&ctx->hybrid.dict);
    }
    return 0;
}

uint64_t attack_ctx_get_brute_index(const attack_ctx_t *ctx) {
    if (ctx->mode == ATTACK_BRUTEFORCE) {
        return ctx->brute.cur_index;
    }
    if (ctx->mode == ATTACK_MASK) {
        return ctx->mask.cur_index;
    }
    return 0;
}

/* ============================================================
 * CANDIDATE FILTERING
 * ============================================================ */

/*
 * Filter a candidate batch by password length constraints.
 * Removes passwords outside [min_len, max_len] in-place.
 */
void batch_filter_length(candidate_batch_t *batch,
                          int min_len, int max_len) {
    int out = 0;
    for (int i = 0; i < batch->count; i++) {
        int len = (int)strlen(batch->passwords[i]);
        if (len >= min_len && len <= max_len) {
            if (out != i) {
                memcpy(batch->passwords[out], batch->passwords[i],
                       (size_t)len + 1);
            }
            out++;
        }
    }
    batch->count = out;
}

/*
 * Filter batch: remove duplicates (in-place, O(n^2) but batches are small).
 */
void batch_dedup(candidate_batch_t *batch) {
    if (batch->count <= 1) return;

    int out = 1;
    for (int i = 1; i < batch->count; i++) {
        bool dup = false;
        for (int j = 0; j < out; j++) {
            if (strcmp(batch->passwords[i], batch->passwords[j]) == 0) {
                dup = true;
                break;
            }
        }
        if (!dup) {
            if (out != i) {
                size_t len = strlen(batch->passwords[i]);
                memcpy(batch->passwords[out], batch->passwords[i], len + 1);
            }
            out++;
        }
    }
    batch->count = out;
}

/* ============================================================
 * ATTACK UTILITY FUNCTIONS
 * ============================================================ */

/*
 * Print attack statistics summary.
 */
void attack_print_stats(attack_mode_t mode,
                         uint64_t total_tested,
                         uint64_t keyspace,
                         double elapsed_sec,
                         bool no_color) {
    const char *c_l = no_color ? "" : "\033[97m";
    const char *c_v = no_color ? "" : "\033[36m";
    const char *c_r = no_color ? "" : "\033[0m";

    double pct = (keyspace > 0)
                 ? (100.0 * (double)total_tested / (double)keyspace)
                 : 0.0;
    double speed = (elapsed_sec > 0.001)
                   ? ((double)total_tested / elapsed_sec)
                   : 0.0;

    fprintf(stderr,
            "\n%s[Attack Stats]%s\n"
            "  %sMode:%s      %s%s%s\n"
            "  %sTested:%s    %s%llu%s\n"
            "  %sKeyspace:%s  %s%llu%s\n"
            "  %sProgress:%s  %s%.2f%%%s\n"
            "  %sElapsed:%s   %s%.1fs%s\n"
            "  %sSpeed:%s     %s%.0f H/s%s\n\n",
            c_l, c_r,
            c_l, c_r, c_v,
            (mode < ATTACK_MAX) ? "N/A" : "N/A",
            c_r,
            c_l, c_r, c_v, (unsigned long long)total_tested, c_r,
            c_l, c_r, c_v, (unsigned long long)keyspace, c_r,
            c_l, c_r, c_v, pct, c_r,
            c_l, c_r, c_v, elapsed_sec, c_r,
            c_l, c_r, c_v, speed, c_r);
    (void)mode;
}

/*
 * Check if password is non-empty and within bounds.
 */
FORCE_INLINE bool candidate_valid(const char *pw, int min_len, int max_len) {
    if (!pw || pw[0] == '\0') return false;
    int len = 0;
    while (pw[len] && len <= max_len) len++;
    return (len >= min_len && len <= max_len);
}

/* ============================================================
 * SELF-TEST / UNIT TEST HELPERS
 * ============================================================ */

#ifdef CRIVE_SELFTEST

static void test_brute_small(void) {
    charset_spec_t cs;
    memset(&cs, 0, sizeof(cs));
    memcpy(cs.chars, "abc", 3);
    cs.chars[3] = '\0';
    cs.len = 3;

    brute_state_t st;
    brute_init(&st, &cs, 1, 2, 0, 1, 0, 0);

    candidate_batch_t batch;
    batch_init(&batch, 32);

    uint64_t count = 0;
    while (!st.exhausted) {
        brute_next_batch(&st, &batch);
        count += batch.count;
        batch_reset(&batch);
    }

    /* Expected: 3 (len=1) + 9 (len=2) = 12 */
    fprintf(stderr, "[selftest] brute abc 1-2: count=%llu (expected 12)\n",
            (unsigned long long)count);
}

static void test_mask_simple(void) {
    mask_spec_t mask;
    memset(&mask, 0, sizeof(mask));
    mask.num_positions = 2;
    memcpy(mask.positions[0].charset, "ab", 2);
    mask.positions[0].charset[2] = '\0';
    mask.positions[0].charset_len = 2;
    memcpy(mask.positions[1].charset, "12", 2);
    mask.positions[1].charset[2] = '\0';
    mask.positions[1].charset_len = 2;

    mask_state_t st;
    mask_init(&st, &mask, 0, 1, 0, 0);

    candidate_batch_t batch;
    batch_init(&batch, 32);

    uint64_t count = 0;
    while (!st.exhausted) {
        mask_next_batch(&st, &batch);
        count += batch.count;
        batch_reset(&batch);
    }

    /* Expected: 2 * 2 = 4 */
    fprintf(stderr, "[selftest] mask [ab][12]: count=%llu (expected 4)\n",
            (unsigned long long)count);
}

static void test_rule_apply(void) {
    char out[128];
    int len;

    len = apply_rule(RULE_CAPITALIZE,    NULL, 0, "hello", 5, out, 128);
    fprintf(stderr, "[selftest] capitalize hello -> '%s' len=%d\n", out, len);

    len = apply_rule(RULE_LEET_SPEAK,    NULL, 0, "password", 8, out, 128);
    fprintf(stderr, "[selftest] leet password -> '%s' len=%d\n", out, len);

    len = apply_rule(RULE_REVERSE,       NULL, 0, "hello", 5, out, 128);
    fprintf(stderr, "[selftest] reverse hello -> '%s' len=%d\n", out, len);

    len = apply_rule(RULE_DUPLICATE,     NULL, 0, "ab", 2, out, 128);
    fprintf(stderr, "[selftest] duplicate ab -> '%s' len=%d\n", out, len);

    len = apply_rule(RULE_APPEND_DIGIT,  NULL, 7, "pass", 4, out, 128);
    fprintf(stderr, "[selftest] append_digit pass 7 -> '%s' len=%d\n", out, len);

    len = apply_rule(RULE_APPEND_YEAR,   NULL, 2, "pass", 4, out, 128);
    fprintf(stderr, "[selftest] append_year pass 2 -> '%s' len=%d\n", out, len);

    len = apply_rule(RULE_REFLECT,       NULL, 0, "abc", 3, out, 128);
    fprintf(stderr, "[selftest] reflect abc -> '%s' len=%d\n", out, len);

    len = apply_rule(RULE_STRIP_VOWELS,  NULL, 0, "password", 8, out, 128);
    fprintf(stderr, "[selftest] strip_vowels password -> '%s' len=%d\n", out, len);
}

void attacks_run_selftest(void) {
    fprintf(stderr, "\n=== attacks.c self-test ===\n");
    test_brute_small();
    test_mask_simple();
    test_rule_apply();
    fprintf(stderr, "=== self-test done ===\n\n");
}

#endif /* CRIVE_SELFTEST */

/* ============================================================
 * END OF attacks.c
 * ============================================================ */

/*
 * engine.c - Thread pool, scheduler, and core cracking loop
 * pthread-based worker pool with lock-free design
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
#include <pthread.h>
#include <signal.h>
#include <time.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <stdatomic.h>
#include <ctype.h>
#include <math.h>
#include <limits.h>
#include "archive.h"

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
#define UNUSED               __attribute__((unused))

#define MAX_PASSWORD_LEN     128
#define MAX_PATH_LEN         4096
#define MAX_CHARSET_LEN      512
#define MAX_MASK_LEN         256
#define MAX_MASK_POSITIONS   32
#define MAX_THREADS          256
#define MAX_RULES            4096
#define BATCH_MAX_SIZE       4096
#define DEFAULT_BATCH_SIZE   1024
#define SPEED_SAMPLE_WINDOW  8
#define PROGRESS_UPDATE_MS   250
#define KB                   (1024ULL)
#define MB                   (1024ULL * KB)

/* ============================================================
 * STRUCT FORWARD DECLARATIONS
 * ============================================================ */

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
    RULE_APPEND_DIGIT   = 0,
    RULE_PREPEND_DIGIT  = 1,
    RULE_UPPERCASE_ALL  = 2,
    RULE_LOWERCASE_ALL  = 3,
    RULE_CAPITALIZE     = 4,
    RULE_REVERSE        = 5,
    RULE_DUPLICATE      = 6,
    RULE_LEET_SPEAK     = 7,
    RULE_APPEND_YEAR    = 8,
    RULE_APPEND_SPECIAL = 9,
    RULE_TOGGLE_CASE    = 10,
    RULE_ROTATE_LEFT    = 11,
    RULE_ROTATE_RIGHT   = 12,
    RULE_REFLECT        = 13,
    RULE_STRIP_VOWELS   = 14,
    RULE_MAX
} rule_type_t;

typedef struct {
    rule_type_t type;
    char        param[64];
    int         param_int;
} rule_t;

/* ============================================================
 * CONFIG STRUCT
 * ============================================================ */

typedef struct {
    char            archive_path[MAX_PATH_LEN];
    archive_type_t  archive_type;
    attack_mode_t   attack_mode;
    char            wordlist_path[MAX_PATH_LEN];
    size_t          dict_buffer_size;
    int             min_length;
    int             max_length;
    charset_spec_t  charset;
    mask_spec_t     mask;
    hybrid_config_t hybrid;
    char            rules_path[MAX_PATH_LEN];
    rule_t          rules[MAX_RULES];
    int             num_rules;
    int             num_threads;
    size_t          batch_size;
    char            output_path[MAX_PATH_LEN];
    char            log_path[MAX_PATH_LEN];
    bool            verbose;
    bool            quiet;
    log_level_t     log_level;
    bool            no_color;
    bool            show_progress;
    bool            resume;
    char            resume_path[MAX_PATH_LEN];
    bool            save_resume;
    int             benchmark_duration;
    uint64_t        limit;
    uint64_t        skip;
    int             progress_interval_ms;
    bool            force_archive_type;
    bool            interactive;
} config_t;

/* ============================================================
 * FORWARD DECLARATIONS FROM attacks.c
 * ============================================================ */

typedef struct {
    char     passwords[BATCH_MAX_SIZE][MAX_PASSWORD_LEN];
    int      count;
    int      capacity;
} candidate_batch_t;

typedef struct attack_ctx attack_ctx_t;

/* Declared in attacks.c */
extern int  attack_ctx_init_dict   (attack_ctx_t *ctx,
                                     const char *wordlist_path,
                                     uint64_t file_offset,
                                     int thread_id, int num_threads);
extern int  attack_ctx_init_brute  (attack_ctx_t *ctx,
                                     const charset_spec_t *cs,
                                     int min_len, int max_len,
                                     int thread_id, int num_threads,
                                     uint64_t skip, uint64_t limit);
extern int  attack_ctx_init_mask   (attack_ctx_t *ctx,
                                     const mask_spec_t *mask,
                                     int thread_id, int num_threads,
                                     uint64_t skip, uint64_t limit);
extern int  attack_ctx_init_rule   (attack_ctx_t *ctx,
                                     const char *wordlist_path,
                                     const char *rules_path,
                                     int thread_id, int num_threads,
                                     uint64_t file_offset);
extern int  attack_ctx_init_hybrid (attack_ctx_t *ctx,
                                     const char *wordlist_path,
                                     const hybrid_config_t *cfg,
                                     const charset_spec_t *suffix_cs,
                                     const charset_spec_t *prefix_cs,
                                     int thread_id, int num_threads,
                                     uint64_t file_offset);
extern void attack_ctx_cleanup     (attack_ctx_t *ctx);
extern int  attack_ctx_next_batch  (attack_ctx_t *ctx,
                                     candidate_batch_t *batch);
extern bool attack_ctx_exhausted   (const attack_ctx_t *ctx);
extern void attack_ctx_get_state   (const attack_ctx_t *ctx,
                                     char *buf, size_t buflen);
extern uint64_t attack_ctx_keyspace(const attack_ctx_t *ctx);
extern uint64_t attack_ctx_get_dict_offset  (const attack_ctx_t *ctx);
extern uint64_t attack_ctx_get_brute_index  (const attack_ctx_t *ctx);
extern size_t attack_ctx_size               (void);

#include "archive.h"

/* From utils.c */
extern void status_line_update     (const void *state, bool no_color);
extern void status_line_clear      (void);
extern void term_show_cursor       (void);
extern void term_hide_cursor       (void);
extern void print_found_password   (const char *password, const char *archive,
                                     bool no_color);
extern int  write_found_password   (const char *output_path,
                                     const char *archive_path,
                                     const char *password);
extern void format_speed           (char *buf, size_t buflen, double speed);
extern void format_number          (char *buf, size_t buflen, uint64_t n);
extern void format_elapsed         (char *buf, size_t buflen, double sec);
extern void format_eta             (char *buf, size_t buflen, int64_t eta_sec);
extern void sleep_ms               (long ms);
extern uint64_t get_time_ms        (void);
extern uint64_t get_time_ns        (void);
extern struct timespec get_timespec_now(void);
extern double elapsed_seconds_since(const struct timespec *start);
extern uint64_t elapsed_ms_since   (const struct timespec *start);

typedef struct {
    uint64_t    samples[SPEED_SAMPLE_WINDOW];
    uint64_t    timestamps[SPEED_SAMPLE_WINDOW];
    int         head;
    int         count;
    uint64_t    last_attempts;
    uint64_t    last_time_ns;
} speed_tracker_t;

extern void   speed_tracker_init       (speed_tracker_t *st);
extern void   speed_tracker_update     (speed_tracker_t *st,
                                         uint64_t total_attempts);
extern double speed_tracker_moving_avg (const speed_tracker_t *st);
extern uint64_t speed_tracker_current  (const speed_tracker_t *st);

/* Resume */
typedef struct {
    uint32_t        magic;
    uint32_t        version;
    attack_mode_t   attack_mode;
    archive_type_t  archive_type;
    char            archive_path[MAX_PATH_LEN];
    char            wordlist_path[MAX_PATH_LEN];
    uint64_t        total_attempts;
    uint64_t        wordlist_offset;
    uint64_t        bruteforce_index;
    int             current_length;
    char            brute_counter[MAX_PASSWORD_LEN];
    time_t          saved_at;
    uint32_t        checksum;
} resume_state_t;

extern int resume_save(const char *path, const resume_state_t *rs);
extern int resume_load(const char *path, resume_state_t *rs);

/* ============================================================
 * THREAD STATUS
 * ============================================================ */

typedef struct {
    int             thread_id;
    uint64_t        attempts;
    uint64_t        speed;
    bool            running;
    bool            found;
    char            current_password[MAX_PASSWORD_LEN];
    struct timespec last_update;
} thread_status_t;

/* ============================================================
 * ENGINE STATE
 * ============================================================ */

typedef struct {
    atomic_bool             found;
    atomic_bool             shutdown;
    atomic_bool             paused;
    char                    found_password[MAX_PASSWORD_LEN];
    pthread_mutex_t         found_mutex;
    atomic_uint_fast64_t    total_attempts;
    atomic_uint_fast64_t    total_skipped;
    struct timespec         start_time;
    struct timespec         last_display_time;
    thread_status_t         thread_status[MAX_THREADS];
    int                     num_threads;
    speed_tracker_t         speed;
    pthread_mutex_t         speed_mutex;
    volatile uint64_t       passwords_per_sec;
    volatile double         moving_avg_speed;
    volatile int64_t        eta_seconds;
    volatile uint64_t       keyspace_total;
    volatile uint64_t       keyspace_done;
    resume_state_t          resume;
    const config_t         *config;
} engine_state_t;

/* ============================================================
 * WORKER THREAD ARGUMENTS
 * ============================================================ */

typedef struct {
    int                 thread_id;
    engine_state_t     *engine;
    const config_t     *config;
    archive_ctx_t      *archive;      /* thread-local archive context */
    attack_ctx_t       *attack;       /* thread-local attack context */
    pthread_t           tid;
    bool                started;
} worker_args_t;

/* ============================================================
 * BENCHMARK WORKER ARGS
 * ============================================================ */

typedef struct {
    int             thread_id;
    engine_state_t *engine;
    archive_type_t  archive_type;
    int             duration_ms;
    uint64_t        count;
    double          speed;
    pthread_t       tid;
} bench_worker_args_t;

/* ============================================================
 * PROGRESS DISPLAY THREAD ARGS
 * ============================================================ */

typedef struct {
    engine_state_t *engine;
    const config_t *config;
    bool            running;
    pthread_t       tid;
} progress_args_t;

/* ============================================================
 * ENGINE STATE FUNCTIONS (local implementations)
 * ============================================================ */

static void engine_state_init_local(engine_state_t *state,
                                     const config_t *cfg) {
    memset(state, 0, sizeof(*state));

    atomic_init(&state->found,          false);
    atomic_init(&state->shutdown,       false);
    atomic_init(&state->paused,         false);
    atomic_init(&state->total_attempts, 0ULL);
    atomic_init(&state->total_skipped,  0ULL);

    pthread_mutex_init(&state->found_mutex, NULL);
    pthread_mutex_init(&state->speed_mutex, NULL);

    state->start_time        = get_timespec_now();
    state->last_display_time = state->start_time;
    state->num_threads       = cfg ? cfg->num_threads : 1;
    state->config            = cfg;
    state->eta_seconds       = -1;
    state->keyspace_total    = 0;
    state->keyspace_done     = 0;
    state->passwords_per_sec = 0;
    state->moving_avg_speed  = 0.0;

    for (int i = 0; i < MAX_THREADS; i++) {
        state->thread_status[i].thread_id = i;
        state->thread_status[i].running   = false;
        state->thread_status[i].attempts  = 0;
    }

    speed_tracker_init(&state->speed);
}

static void engine_state_cleanup_local(engine_state_t *state) {
    pthread_mutex_destroy(&state->found_mutex);
    pthread_mutex_destroy(&state->speed_mutex);

    volatile char *vp = (volatile char *)state->found_password;
    for (int i = 0; i < MAX_PASSWORD_LEN; i++) vp[i] = 0;
}

FORCE_INLINE void engine_set_found(engine_state_t *state,
                                    const char *password) {
    pthread_mutex_lock(&state->found_mutex);
    if (!atomic_load_explicit(&state->found, memory_order_acquire)) {
        size_t len = strlen(password);
        if (len >= MAX_PASSWORD_LEN) len = MAX_PASSWORD_LEN - 1;
        memcpy(state->found_password, password, len);
        state->found_password[len] = '\0';
        atomic_store_explicit(&state->found, true, memory_order_release);
    }
    pthread_mutex_unlock(&state->found_mutex);
}

FORCE_INLINE bool engine_is_found(const engine_state_t *state) {
    return atomic_load_explicit(&state->found, memory_order_acquire);
}

FORCE_INLINE bool engine_is_shutdown(const engine_state_t *state) {
    return atomic_load_explicit(&state->shutdown, memory_order_relaxed);
}

static void engine_update_speed(engine_state_t *state) {
    pthread_mutex_lock(&state->speed_mutex);

    uint64_t total = atomic_load_explicit(&state->total_attempts,
                                          memory_order_relaxed);
    speed_tracker_update(&state->speed, total);
    state->moving_avg_speed  = speed_tracker_moving_avg(&state->speed);
    state->passwords_per_sec = speed_tracker_current(&state->speed);

    uint64_t ks_total = state->keyspace_total;
    if (ks_total > 0 && state->moving_avg_speed > 0.0) {
        uint64_t remaining = (ks_total > total) ? (ks_total - total) : 0;
        state->eta_seconds = (int64_t)((double)remaining /
                                        state->moving_avg_speed);
    } else {
        state->eta_seconds = -1;
    }
    state->keyspace_done = total;

    pthread_mutex_unlock(&state->speed_mutex);
}

/* ============================================================
 * ARCHIVE CONTEXT POOL
 * For giving each thread its own archive context
 * ============================================================ */

typedef struct {
    archive_ctx_t  *contexts;
    int             count;
    bool            initialized;
} archive_pool_t;

static int archive_pool_init(archive_pool_t *pool,
                              const archive_ctx_t *master,
                              int num_threads) {
    pool->count  = num_threads;
    pool->contexts = (archive_ctx_t *)calloc((size_t)num_threads,
                                              sizeof(archive_ctx_t));
    if (!pool->contexts) {
        log_error("archive_pool_init: calloc failed");
        return -1;
    }

    for (int i = 0; i < num_threads; i++) {
        if (archive_ctx_clone(&pool->contexts[i], master) != 0) {
            log_error("archive_pool_init: clone failed for thread %d", i);
            /* Free already-cloned ones */
            free(pool->contexts);
            pool->contexts = NULL;
            return -1;
        }
    }

    pool->initialized = true;
    return 0;
}

static void archive_pool_free(archive_pool_t *pool) {
    if (!pool || !pool->initialized) return;
    /* Clones don't own the mmap - just free the struct */
    free(pool->contexts);
    pool->contexts    = NULL;
    pool->count       = 0;
    pool->initialized = false;
}

/* ============================================================
 * ATTACK CONTEXT POOL
 * Each thread gets its own attack context for independent state
 * ============================================================ */

typedef struct {
    uint8_t        *storage;
    size_t          ctx_size;
    int             count;
    bool            initialized;
} attack_pool_t;

static attack_ctx_t *attack_pool_ctx(attack_pool_t *pool, int idx) {
    return (attack_ctx_t *)(void *)(pool->storage + ((size_t)idx * pool->ctx_size));
}

static const attack_ctx_t *attack_pool_ctx_const(const attack_pool_t *pool, int idx) {
    return (const attack_ctx_t *)(const void *)(pool->storage + ((size_t)idx * pool->ctx_size));
}

static int attack_pool_init(attack_pool_t *pool,
                              const config_t *cfg,
                              int num_threads,
                              const resume_state_t *resume_st) {
    pool->count    = num_threads;
    pool->ctx_size = attack_ctx_size();
    if (pool->ctx_size == 0) {
        log_error("attack_pool_init: invalid attack context size");
        return -1;
    }

    pool->storage = (uint8_t *)calloc((size_t)num_threads, pool->ctx_size);
    if (!pool->storage) {
        log_error("attack_pool_init: calloc failed");
        return -1;
    }

    for (int i = 0; i < num_threads; i++) {
        attack_ctx_t *ctx = attack_pool_ctx(pool, i);
        int rc = 0;

        uint64_t dict_offset = 0;
        uint64_t skip        = cfg->skip;
        uint64_t limit       = cfg->limit;

        if (resume_st) {
            dict_offset = resume_st->wordlist_offset;
        }

        switch (cfg->attack_mode) {
            case ATTACK_DICTIONARY:
                rc = attack_ctx_init_dict(ctx,
                                           cfg->wordlist_path,
                                           dict_offset,
                                           i, num_threads);
                break;

            case ATTACK_BRUTEFORCE:
                rc = attack_ctx_init_brute(ctx,
                                            &cfg->charset,
                                            cfg->min_length,
                                            cfg->max_length,
                                            i, num_threads,
                                            skip, limit);
                break;

            case ATTACK_MASK:
                rc = attack_ctx_init_mask(ctx,
                                           &cfg->mask,
                                           i, num_threads,
                                           skip, limit);
                break;

            case ATTACK_RULE:
                rc = attack_ctx_init_rule(ctx,
                                           cfg->wordlist_path,
                                           cfg->rules_path,
                                           i, num_threads,
                                           dict_offset);
                break;

            case ATTACK_HYBRID: {
                charset_spec_t suffix_cs, prefix_cs;
                memset(&suffix_cs, 0, sizeof(suffix_cs));
                memset(&prefix_cs, 0, sizeof(prefix_cs));

                /* Build suffix charset */
                if (cfg->hybrid.suffix_charset[0]) {
                    memcpy(suffix_cs.chars, cfg->hybrid.suffix_charset,
                           strlen(cfg->hybrid.suffix_charset));
                    suffix_cs.len = (int)strlen(cfg->hybrid.suffix_charset);
                } else {
                    memcpy(suffix_cs.chars, "0123456789", 10);
                    suffix_cs.len = 10;
                }

                /* Build prefix charset */
                if (cfg->hybrid.prefix_charset[0]) {
                    memcpy(prefix_cs.chars, cfg->hybrid.prefix_charset,
                           strlen(cfg->hybrid.prefix_charset));
                    prefix_cs.len = (int)strlen(cfg->hybrid.prefix_charset);
                } else {
                    memcpy(prefix_cs.chars, "0123456789", 10);
                    prefix_cs.len = 10;
                }

                rc = attack_ctx_init_hybrid(ctx,
                                             cfg->wordlist_path,
                                             &cfg->hybrid,
                                             &suffix_cs,
                                             &prefix_cs,
                                             i, num_threads,
                                             dict_offset);
                break;
            }

            default:
                log_error("attack_pool_init: unknown attack mode %d",
                          cfg->attack_mode);
                rc = -1;
                break;
        }

        if (rc != 0) {
            log_error("attack_pool_init: init failed for thread %d", i);
            /* Cleanup already-initialized ones */
            for (int j = 0; j < i; j++) {
                attack_ctx_cleanup(attack_pool_ctx(pool, j));
            }
            free(pool->storage);
            pool->storage = NULL;
            pool->ctx_size = 0;
            return -1;
        }
    }

    pool->initialized = true;
    return 0;
}

static void attack_pool_free(attack_pool_t *pool) {
    if (!pool || !pool->initialized) return;
    for (int i = 0; i < pool->count; i++) {
        attack_ctx_cleanup(attack_pool_ctx(pool, i));
    }
    free(pool->storage);
    pool->storage     = NULL;
    pool->ctx_size    = 0;
    pool->count       = 0;
    pool->initialized = false;
}

/* ============================================================
 * PROGRESS DISPLAY THREAD
 * ============================================================ */

static void *progress_thread_fn(void *arg) {
    progress_args_t *pa = (progress_args_t *)arg;
    engine_state_t  *eng = pa->engine;
    const config_t  *cfg = pa->config;

    if (!cfg->show_progress || !cfg->interactive) {
        return NULL;
    }

    term_hide_cursor();

    while (pa->running &&
           !engine_is_found(eng) &&
           !engine_is_shutdown(eng)) {

        engine_update_speed(eng);
        status_line_update(eng, cfg->no_color);
        sleep_ms(cfg->progress_interval_ms > 0
                 ? cfg->progress_interval_ms
                 : PROGRESS_UPDATE_MS);
    }

    /* Final update */
    if (!engine_is_found(eng)) {
        engine_update_speed(eng);
        status_line_update(eng, cfg->no_color);
    }

    status_line_clear();
    term_show_cursor();
    return NULL;
}

/* ============================================================
 * RESUME SAVE THREAD
 * Periodically saves resume state in background
 * ============================================================ */

#define RESUME_SAVE_INTERVAL_SEC  30

typedef struct {
    engine_state_t     *engine;
    const config_t     *config;
    attack_pool_t      *attack_pool;
    bool                running;
    pthread_t           tid;
} resume_thread_args_t;

static void *resume_thread_fn(void *arg) {
    resume_thread_args_t *ra = (resume_thread_args_t *)arg;
    engine_state_t       *eng = ra->engine;
    const config_t       *cfg = ra->config;

    if (!cfg->save_resume) return NULL;

    while (ra->running &&
           !engine_is_found(eng) &&
           !engine_is_shutdown(eng)) {

        sleep_ms(RESUME_SAVE_INTERVAL_SEC * 1000L);

        if (!ra->running || engine_is_found(eng)) break;

        /* Build resume state */
        resume_state_t rs;
        memset(&rs, 0, sizeof(rs));

        rs.attack_mode   = cfg->attack_mode;
        rs.archive_type  = cfg->archive_type;
        rs.total_attempts = atomic_load_explicit(&eng->total_attempts,
                                                  memory_order_relaxed);

        snprintf(rs.archive_path, sizeof(rs.archive_path),
                 "%s", cfg->archive_path);
        snprintf(rs.wordlist_path, sizeof(rs.wordlist_path),
                 "%s", cfg->wordlist_path);

        /* Get state from thread 0 */
        if (ra->attack_pool && ra->attack_pool->count > 0) {
            attack_ctx_t *ctx0 = attack_pool_ctx(ra->attack_pool, 0);
            rs.wordlist_offset  = attack_ctx_get_dict_offset(ctx0);
            rs.bruteforce_index = attack_ctx_get_brute_index(ctx0);
        }

        if (resume_save(cfg->resume_path, &rs) == 0) {
            log_debug("Resume state saved to '%s'", cfg->resume_path);
        }
    }

    return NULL;
}

/* ============================================================
 * CORE WORKER FUNCTION
 * ============================================================ */

/*
 * Per-thread cracking loop.
 * - Gets batches from attack context
 * - Validates each candidate against archive
 * - Updates atomic counters
 * - Stops when found or exhausted
 */
static void *worker_thread_fn(void *arg) {
    worker_args_t   *wa    = (worker_args_t *)arg;
    engine_state_t  *eng   = wa->engine;
    const config_t  *cfg   = wa->config;
    archive_ctx_t   *arch  = wa->archive;
    attack_ctx_t    *atk   = wa->attack;
    int              tid   = wa->thread_id;

    thread_status_t *ts = &eng->thread_status[tid];
    ts->running  = true;
    ts->attempts = 0;

    /* Stack-allocated batch to avoid heap allocation in hot loop */
    candidate_batch_t batch;
    batch.count    = 0;
    batch.capacity = (int)(cfg->batch_size > BATCH_MAX_SIZE
                           ? BATCH_MAX_SIZE
                           : cfg->batch_size);

    log_debug("Worker %d: started", tid);

    while (LIKELY(!engine_is_found(eng) &&
                  !engine_is_shutdown(eng))) {

        /* Handle pause */
        while (atomic_load_explicit(&eng->paused, memory_order_relaxed) &&
               !engine_is_shutdown(eng)) {
            sleep_ms(100);
        }

        /* Get next batch of candidates */
        int n = attack_ctx_next_batch(atk, &batch);
        if (n <= 0) {
            /* Exhausted or error */
            log_debug("Worker %d: attack exhausted", tid);
            break;
        }

        /* Process each candidate in the batch */
        for (int i = 0; i < n; i++) {
            if (UNLIKELY(engine_is_found(eng))) goto done;
            if (UNLIKELY(engine_is_shutdown(eng))) goto done;

            const char *pw = batch.passwords[i];

            /* Update thread status (infrequently to reduce cache pressure) */
            if (UNLIKELY((ts->attempts & 0xFFULL) == 0)) {
                size_t pw_len = strlen(pw);
                if (pw_len >= MAX_PASSWORD_LEN) pw_len = MAX_PASSWORD_LEN - 1;
                memcpy(ts->current_password, pw, pw_len);
                ts->current_password[pw_len] = '\0';
            }

            /* THE CORE CHECK */
            if (UNLIKELY(archive_validate_password(arch, pw))) {
                engine_set_found(eng, pw);
                ts->found = true;
                log_debug("Worker %d: found password '%s'", tid, pw);
                goto done;
            }

            ts->attempts++;
        }

        /* Batch done - update global counter atomically */
        atomic_fetch_add_explicit(&eng->total_attempts,
                                   (uint_fast64_t)n,
                                   memory_order_relaxed);

        /* Check global limit */
        if (cfg->limit > 0) {
            uint64_t total = atomic_load_explicit(&eng->total_attempts,
                                                   memory_order_relaxed);
            if (total >= cfg->limit) {
                log_debug("Worker %d: limit reached", tid);
                break;
            }
        }
    }

done:
    ts->running = false;
    log_debug("Worker %d: done (attempts=%llu)", tid,
              (unsigned long long)ts->attempts);
    return NULL;
}

/* ============================================================
 * BENCHMARK WORKER
 * ============================================================ */

/* Lightweight hash operation for benchmark (simulate validation work) */
FORCE_INLINE uint32_t bench_hash(const char *pw, uint32_t seed) {
    uint32_t h = seed;
    while (*pw) {
        h ^= (uint8_t)*pw++;
        h *= 16777619U;
    }
    return h;
}

static void *bench_worker_fn(void *arg) {
    bench_worker_args_t *ba  = (bench_worker_args_t *)arg;
    engine_state_t      *eng = ba->engine;

    const char *passwords[] = {
        "password", "123456", "qwerty", "letmein", "dragon",
        "master", "monkey", "shadow", "sunshine", "princess",
        "welcome", "password1", "abc123", "football", "iloveyou",
    };
    int npw = (int)(sizeof(passwords) / sizeof(passwords[0]));

    uint64_t count  = 0;
    uint32_t result = 0; /* prevent optimization */

    uint64_t start_ms = get_time_ms();
    uint64_t end_ms   = start_ms + (uint64_t)ba->duration_ms;

    while (!engine_is_shutdown(eng)) {
        uint64_t now = get_time_ms();
        if (now >= end_ms) break;

        for (int i = 0; i < 1000; i++) {
            const char *pw = passwords[count % (uint64_t)npw];

            if (ba->archive_type == ARCHIVE_ZIP) {
                /* Simulate PKZIP key init (cheap) */
                uint32_t k0 = 305419896UL;
                uint32_t k1 = 591751049UL;
                uint32_t k2 = 878082192UL;

                for (const char *p = pw; *p; p++) {
                    /* Simulate key update */
                    k0 = bench_hash(p, k0);
                    k1 = k1 + (k0 & 0xFF);
                    k1 = k1 * 134775813UL + 1UL;
                    k2 = bench_hash((char[]){(char)(k1>>24),0}, k2);
                }
                result ^= k0 ^ k1 ^ k2;
            } else {
                /* Simulate SHA256 iteration (more expensive) */
                result ^= bench_hash(pw, result);
            }

            count++;
        }

        atomic_fetch_add_explicit(&eng->total_attempts,
                                   1000ULL,
                                   memory_order_relaxed);
    }

    ba->count = count;
    ba->speed = (ba->duration_ms > 0)
                ? ((double)count / ((double)ba->duration_ms / 1000.0))
                : 0.0;

    /* Prevent compiler from eliminating the loop */
    if (result == 0xDEADBEEFU) fprintf(stderr, "");

    return NULL;
}

/* ============================================================
 * ENGINE RUN FUNCTIONS
 * ============================================================ */

/*
 * Main cracking engine.
 * Sets up thread pool, launches workers, monitors progress.
 * Returns attack_result_t.
 */
typedef enum {
    ATTACK_RESULT_NOT_FOUND = 0,
    ATTACK_RESULT_FOUND     = 1,
    ATTACK_RESULT_EXHAUSTED = 2,
    ATTACK_RESULT_ERROR     = 3,
    ATTACK_RESULT_ABORTED   = 4,
} attack_result_t;

attack_result_t engine_run(const config_t *cfg,
                            archive_ctx_t *master_archive,
                            const resume_state_t *resume_st) {
    log_info("Engine starting: mode=%d threads=%d",
             cfg->attack_mode, cfg->num_threads);

    /* Initialize engine state */
    engine_state_t eng;
    engine_state_init_local(&eng, cfg);

    attack_result_t result = ATTACK_RESULT_NOT_FOUND;

    /* Initialize archive pool (one context per thread) */
    archive_pool_t arch_pool;
    memset(&arch_pool, 0, sizeof(arch_pool));

    if (archive_pool_init(&arch_pool, master_archive, cfg->num_threads) != 0) {
        log_error("engine_run: archive pool init failed");
        engine_state_cleanup_local(&eng);
        return ATTACK_RESULT_ERROR;
    }

    /* Initialize attack pool */
    attack_pool_t atk_pool;
    memset(&atk_pool, 0, sizeof(atk_pool));

    if (attack_pool_init(&atk_pool, cfg, cfg->num_threads, resume_st) != 0) {
        log_error("engine_run: attack pool init failed");
        archive_pool_free(&arch_pool);
        engine_state_cleanup_local(&eng);
        return ATTACK_RESULT_ERROR;
    }

    /* Get keyspace estimate */
    if (atk_pool.count > 0) {
        uint64_t ks = attack_ctx_keyspace(attack_pool_ctx(&atk_pool, 0));
        eng.keyspace_total = ks;
        if (ks > 0) {
            char ks_str[32];
            format_number(ks_str, sizeof(ks_str), ks);
            log_info("Keyspace: %s", ks_str);
        }
    }

    /* Allocate worker args */
    worker_args_t *workers = (worker_args_t *)calloc(
        (size_t)cfg->num_threads, sizeof(worker_args_t));
    if (!workers) {
        log_error("engine_run: worker args alloc failed");
        attack_pool_free(&atk_pool);
        archive_pool_free(&arch_pool);
        engine_state_cleanup_local(&eng);
        return ATTACK_RESULT_ERROR;
    }

    /* Progress thread */
    progress_args_t prog_args = {
        .engine  = &eng,
        .config  = cfg,
        .running = true,
    };
    pthread_t prog_tid = 0;

    if (cfg->show_progress && cfg->interactive) {
        if (pthread_create(&prog_tid, NULL, progress_thread_fn,
                           &prog_args) != 0) {
            log_warn("engine_run: progress thread creation failed");
            prog_tid = 0;
        }
    }

    /* Resume save thread */
    resume_thread_args_t res_args = {
        .engine      = &eng,
        .config      = cfg,
        .attack_pool = &atk_pool,
        .running     = true,
    };
    pthread_t res_tid = 0;

    if (cfg->save_resume) {
        if (pthread_create(&res_tid, NULL, resume_thread_fn,
                           &res_args) != 0) {
            log_warn("engine_run: resume thread creation failed");
            res_tid = 0;
        }
    }

    /* Launch worker threads */
    eng.start_time = get_timespec_now();
    int launched   = 0;

    for (int i = 0; i < cfg->num_threads; i++) {
        workers[i].thread_id = i;
        workers[i].engine    = &eng;
        workers[i].config    = cfg;
        workers[i].archive   = &arch_pool.contexts[i];
        workers[i].attack    = attack_pool_ctx(&atk_pool, i);
        workers[i].started   = false;

        int rc = pthread_create(&workers[i].tid, NULL,
                                worker_thread_fn, &workers[i]);
        if (rc != 0) {
            log_error("engine_run: pthread_create failed for thread %d: %s",
                      i, strerror(rc));
            /* Signal other threads to stop */
            atomic_store(&eng.shutdown, true);
            break;
        }

        workers[i].started = true;
        launched++;

        log_debug("Worker %d: launched (tid=%lu)", i,
                  (unsigned long)workers[i].tid);
    }

    log_info("Workers launched: %d/%d", launched, cfg->num_threads);

    /* Wait for all workers */
    for (int i = 0; i < cfg->num_threads; i++) {
        if (workers[i].started) {
            pthread_join(workers[i].tid, NULL);
            log_debug("Worker %d: joined (attempts=%llu)", i,
                      (unsigned long long)eng.thread_status[i].attempts);
        }
    }

    log_debug("All workers done");

    /* Stop support threads */
    prog_args.running = false;
    res_args.running  = false;

    if (prog_tid != 0) {
        pthread_join(prog_tid, NULL);
    }
    if (res_tid != 0) {
        pthread_join(res_tid, NULL);
    }

    /* Determine result */
    if (engine_is_found(&eng)) {
        result = ATTACK_RESULT_FOUND;
        log_info("Password found: '%s'", eng.found_password);
    } else if (engine_is_shutdown(&eng)) {
        result = ATTACK_RESULT_ABORTED;
        log_info("Attack aborted by signal");
    } else {
        /* Check if all attack contexts exhausted */
        bool all_exhausted = true;
        for (int i = 0; i < atk_pool.count; i++) {
            if (!attack_ctx_exhausted(attack_pool_ctx_const(&atk_pool, i))) {
                all_exhausted = false;
                break;
            }
        }
        result = all_exhausted
                 ? ATTACK_RESULT_EXHAUSTED
                 : ATTACK_RESULT_NOT_FOUND;
    }

    /* Final stats */
    double elapsed = elapsed_seconds_since(&eng.start_time);
    uint64_t total = atomic_load_explicit(&eng.total_attempts,
                                           memory_order_relaxed);

    char elapsed_str[32], speed_str[32], total_str[32];
    format_elapsed(elapsed_str, sizeof(elapsed_str), elapsed);
    double final_speed = (elapsed > 0.001)
                         ? ((double)total / elapsed)
                         : 0.0;
    format_speed(speed_str, sizeof(speed_str), final_speed);
    format_number(total_str, sizeof(total_str), total);

    log_info("Attack finished: tested=%s elapsed=%s speed=%s",
             total_str, elapsed_str, speed_str);

    /* Handle found password output */
    if (result == ATTACK_RESULT_FOUND) {
        print_found_password(eng.found_password, cfg->archive_path,
                             cfg->no_color);

        if (cfg->output_path[0] != '\0') {
            write_found_password(cfg->output_path, cfg->archive_path,
                                  eng.found_password);
        }

        /* Copy found password to master resume for reference */
        memcpy(eng.resume.brute_counter, eng.found_password,
               strlen(eng.found_password) + 1);
    }

    /* Save final resume state */
    if (cfg->save_resume && result == ATTACK_RESULT_ABORTED) {
        resume_state_t rs;
        memset(&rs, 0, sizeof(rs));
        rs.attack_mode    = cfg->attack_mode;
        rs.archive_type   = cfg->archive_type;
        rs.total_attempts = total;
        snprintf(rs.archive_path, sizeof(rs.archive_path),
                 "%s", cfg->archive_path);
        snprintf(rs.wordlist_path, sizeof(rs.wordlist_path),
                 "%s", cfg->wordlist_path);
        if (atk_pool.count > 0) {
            rs.wordlist_offset  = attack_ctx_get_dict_offset(
                                    attack_pool_ctx(&atk_pool, 0));
            rs.bruteforce_index = attack_ctx_get_brute_index(
                                    attack_pool_ctx(&atk_pool, 0));
        }
        if (resume_save(cfg->resume_path, &rs) == 0) {
            log_info("Resume state saved to: %s", cfg->resume_path);
        }
    }

    /* Cleanup */
    free(workers);
    attack_pool_free(&atk_pool);
    archive_pool_free(&arch_pool);
    engine_state_cleanup_local(&eng);

    return result;
}

/* ============================================================
 * BENCHMARK ENGINE
 * ============================================================ */

typedef struct {
    double      total_speed;
    double      peak_speed;
    uint64_t    total_hashes;
    double      duration_sec;
    int         num_threads;
} benchmark_result_t;

benchmark_result_t engine_benchmark(const config_t *cfg,
                                     archive_type_t arch_type,
                                     int duration_ms) {
    benchmark_result_t res = {0};
    res.num_threads = cfg->num_threads;

    log_info("Benchmark: type=%s threads=%d duration=%dms",
             (arch_type == ARCHIVE_ZIP) ? "ZIP" : "7Z",
             cfg->num_threads, duration_ms);

    engine_state_t eng;
    engine_state_init_local(&eng, cfg);

    bench_worker_args_t *workers = (bench_worker_args_t *)calloc(
        (size_t)cfg->num_threads, sizeof(bench_worker_args_t));
    if (!workers) {
        log_error("engine_benchmark: alloc failed");
        engine_state_cleanup_local(&eng);
        return res;
    }

    struct timespec start = get_timespec_now();

    for (int i = 0; i < cfg->num_threads; i++) {
        workers[i].thread_id   = i;
        workers[i].engine      = &eng;
        workers[i].archive_type = arch_type;
        workers[i].duration_ms = duration_ms;
        workers[i].count       = 0;
        workers[i].speed       = 0.0;

        if (pthread_create(&workers[i].tid, NULL,
                           bench_worker_fn, &workers[i]) != 0) {
            log_error("engine_benchmark: pthread_create failed for %d", i);
        }
    }

    /* Progress display during benchmark */
    if (cfg->show_progress && cfg->interactive) {
        int steps = duration_ms / 500;
        for (int s = 0; s < steps; s++) {
            sleep_ms(500);
            engine_update_speed(&eng);

            uint64_t total = atomic_load_explicit(&eng.total_attempts,
                                                   memory_order_relaxed);
            double elapsed = elapsed_seconds_since(&start);
            double speed   = (elapsed > 0.001)
                             ? ((double)total / elapsed)
                             : 0.0;

            char speed_str[32];
            format_speed(speed_str, sizeof(speed_str), speed);
            fprintf(stderr, "\r  Benchmarking... %s (%.1fs)    ",
                    speed_str, elapsed);
            fflush(stderr);
        }
        fprintf(stderr, "\n");
    }

    /* Join all benchmark workers */
    uint64_t total_hashes = 0;
    double   peak_speed   = 0.0;

    for (int i = 0; i < cfg->num_threads; i++) {
        pthread_join(workers[i].tid, NULL);
        total_hashes += workers[i].count;
        if (workers[i].speed > peak_speed) {
            peak_speed = workers[i].speed;
        }
    }

    double elapsed = elapsed_seconds_since(&start);

    res.total_hashes = total_hashes;
    res.duration_sec = elapsed;
    res.peak_speed   = peak_speed;
    res.total_speed  = (elapsed > 0.001)
                       ? ((double)total_hashes / elapsed)
                       : 0.0;

    free(workers);
    engine_state_cleanup_local(&eng);

    log_info("Benchmark complete: %.0f H/s total, %.0f H/s peak",
             res.total_speed, res.peak_speed);

    return res;
}

/* ============================================================
 * SIGNAL HANDLER INTEGRATION
 * ============================================================ */

static engine_state_t *g_engine_for_signal = NULL;

static void engine_signal_handler(int sig) {
    if (g_engine_for_signal) {
        atomic_store_explicit(&g_engine_for_signal->shutdown,
                               true,
                               memory_order_relaxed);
    }

    if (sig == SIGINT) {
        /* Don't exit immediately - let engine clean up */
        /* Second Ctrl+C will force exit */
        static volatile int sigint_count = 0;
        sigint_count++;
        if (sigint_count >= 2) {
            write(STDERR_FILENO, "\nForce exit.\n", 13);
            _exit(1);
        }
        write(STDERR_FILENO, "\nStopping... (Ctrl+C again to force)\n", 37);
    }
}

void engine_install_signal_handler(engine_state_t *eng) {
    g_engine_for_signal = eng;

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = engine_signal_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;

    sigaction(SIGINT,  &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
}

/* ============================================================
 * ENGINE ORCHESTRATOR
 * Top-level function called from main.c
 * ============================================================ */

typedef struct {
    attack_result_t     result;
    char                password[MAX_PASSWORD_LEN];
    uint64_t            total_tested;
    double              elapsed_sec;
    double              speed_avg;
    benchmark_result_t  bench;
    bool                is_benchmark;
} engine_run_result_t;

engine_run_result_t engine_orchestrate(const config_t *cfg,
                                        archive_ctx_t *archive) {
    engine_run_result_t res;
    memset(&res, 0, sizeof(res));

    /* Install signal handler */
    engine_state_t signal_eng;
    memset(&signal_eng, 0, sizeof(signal_eng));
    atomic_init(&signal_eng.shutdown, false);
    atomic_init(&signal_eng.found,    false);
    g_engine_for_signal = &signal_eng;

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = engine_signal_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags   = SA_RESTART;
    sigaction(SIGINT,  &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    if (cfg->attack_mode == ATTACK_BENCHMARK) {
        /* Benchmark mode */
        archive_type_t btype = (cfg->archive_type != ARCHIVE_UNKNOWN)
                               ? cfg->archive_type
                               : ARCHIVE_ZIP;

        res.bench       = engine_benchmark(cfg, btype,
                                            cfg->benchmark_duration * 1000);
        res.is_benchmark = true;
        res.result       = ATTACK_RESULT_NOT_FOUND;

        /* Print benchmark results */
        const char *c_l = cfg->no_color ? "" : "\033[97m";
        const char *c_v = cfg->no_color ? "" : "\033[36m";
        const char *c_r = cfg->no_color ? "" : "\033[0m";
        const char *c_y = cfg->no_color ? "" : "\033[93m";

        char speed_str[32], peak_str[32], total_str[32];
        format_speed(speed_str, sizeof(speed_str), res.bench.total_speed);
        format_speed(peak_str,  sizeof(peak_str),  res.bench.peak_speed);
        format_number(total_str, sizeof(total_str), res.bench.total_hashes);

        fprintf(stderr,
                "\n%s[Benchmark Results]%s\n"
                "  %sAverage Speed:%s %s%s%s\n"
                "  %sPeak Speed:   %s %s%s%s\n"
                "  %sTotal Hashes: %s %s%s%s\n"
                "  %sDuration:     %s %s%.1fs%s\n"
                "  %sThreads:      %s %s%d%s\n\n",
                c_l, c_r,
                c_l, c_r, c_y, speed_str, c_r,
                c_l, c_r, c_y, peak_str,  c_r,
                c_l, c_r, c_v, total_str, c_r,
                c_l, c_r, c_v, res.bench.duration_sec, c_r,
                c_l, c_r, c_v, res.bench.num_threads, c_r);

        return res;
    }

    /* Load resume state if requested */
    resume_state_t  resume_st;
    resume_state_t *p_resume = NULL;

    if (cfg->resume) {
        if (resume_load(cfg->resume_path, &resume_st) == 0) {
            p_resume = &resume_st;
            log_info("Resume state loaded from '%s'", cfg->resume_path);
            log_info("Resuming from attempt %llu",
                     (unsigned long long)resume_st.total_attempts);
        } else {
            log_warn("Could not load resume state, starting fresh");
        }
    }

    /* Run main cracking engine */
    struct timespec t_start = get_timespec_now();
    res.result = engine_run(cfg, archive, p_resume);
    double elapsed = elapsed_seconds_since(&t_start);

    res.elapsed_sec  = elapsed;
    res.total_tested = 0; /* will be updated below */

    if (res.result == ATTACK_RESULT_FOUND) {
        /* Password is printed by engine_run itself */
        /* We just record it here */
    }

    g_engine_for_signal = NULL;

    /* Restore default signal handling */
    struct sigaction sa_def;
    memset(&sa_def, 0, sizeof(sa_def));
    sa_def.sa_handler = SIG_DFL;
    sigemptyset(&sa_def.sa_mask);
    sigaction(SIGINT,  &sa_def, NULL);
    sigaction(SIGTERM, &sa_def, NULL);

    return res;
}

/* ============================================================
 * MULTI-PHASE ENGINE
 * Runs multiple attack modes sequentially
 * ============================================================ */

typedef struct {
    attack_mode_t   modes[ATTACK_MAX];
    int             num_modes;
} attack_chain_t;

engine_run_result_t engine_run_chain(const config_t *base_cfg,
                                      archive_ctx_t *archive,
                                      const attack_chain_t *chain) {
    engine_run_result_t final_res;
    memset(&final_res, 0, sizeof(final_res));

    for (int phase = 0; phase < chain->num_modes; phase++) {
        attack_mode_t mode = chain->modes[phase];

        /* Validate phase has required config */
        if ((mode == ATTACK_DICTIONARY ||
             mode == ATTACK_RULE       ||
             mode == ATTACK_HYBRID) &&
            base_cfg->wordlist_path[0] == '\0') {
            log_warn("Phase %d (%d) requires wordlist - skipping", phase, mode);
            continue;
        }

        /* Build phase config */
        config_t phase_cfg;
        memcpy(&phase_cfg, base_cfg, sizeof(phase_cfg));
        phase_cfg.attack_mode = mode;

        const char *c_h = base_cfg->no_color ? "" : "\033[95m\033[1m";
        const char *c_r = base_cfg->no_color ? "" : "\033[0m";

        fprintf(stderr, "\n%s[Phase %d] Starting %s attack%s\n",
                c_h, phase + 1,
                (mode < ATTACK_MAX) ? "unknown" : "unknown",
                c_r);

        engine_run_result_t phase_res = engine_orchestrate(&phase_cfg, archive);

        if (phase_res.result == ATTACK_RESULT_FOUND) {
            memcpy(&final_res, &phase_res, sizeof(final_res));
            return final_res;
        }

        if (phase_res.result == ATTACK_RESULT_ABORTED) {
            final_res.result = ATTACK_RESULT_ABORTED;
            return final_res;
        }
    }

    final_res.result = ATTACK_RESULT_EXHAUSTED;
    return final_res;
}

/* ============================================================
 * THREAD AFFINITY SETTER (FIXED FOR ANDROID)
 * ============================================================ */

static void engine_set_thread_affinity(pthread_t tid, int cpu_id) {
#if defined(__linux__) && !defined(__ANDROID__)
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(cpu_id % (int)sysconf(_SC_NPROCESSORS_ONLN), &cpuset);
    int rc = pthread_setaffinity_np(tid, sizeof(cpuset), &cpuset);
    if (rc != 0) {
        log_debug("set_affinity: failed for cpu %d: %s",
                  cpu_id, strerror(rc));
    }
#else
    (void)tid;
    (void)cpu_id;
#endif
}

/* ============================================================
 * ENGINE WITH AFFINITY
 * Optionally pin each worker to a CPU core
 * ============================================================ */

attack_result_t engine_run_with_affinity(const config_t *cfg,
                                          archive_ctx_t *master_archive,
                                          const resume_state_t *resume_st,
                                          bool pin_threads) {
    engine_state_t eng;
    engine_state_init_local(&eng, cfg);

    attack_result_t result = ATTACK_RESULT_NOT_FOUND;

    archive_pool_t arch_pool;
    memset(&arch_pool, 0, sizeof(arch_pool));

    if (archive_pool_init(&arch_pool, master_archive, cfg->num_threads) != 0) {
        engine_state_cleanup_local(&eng);
        return ATTACK_RESULT_ERROR;
    }

    attack_pool_t atk_pool;
    memset(&atk_pool, 0, sizeof(atk_pool));

    if (attack_pool_init(&atk_pool, cfg, cfg->num_threads, resume_st) != 0) {
        archive_pool_free(&arch_pool);
        engine_state_cleanup_local(&eng);
        return ATTACK_RESULT_ERROR;
    }

    /* Get keyspace */
    if (atk_pool.count > 0) {
        eng.keyspace_total = attack_ctx_keyspace(attack_pool_ctx(&atk_pool, 0));
    }

    worker_args_t *workers = (worker_args_t *)calloc(
        (size_t)cfg->num_threads, sizeof(worker_args_t));
    if (!workers) {
        attack_pool_free(&atk_pool);
        archive_pool_free(&arch_pool);
        engine_state_cleanup_local(&eng);
        return ATTACK_RESULT_ERROR;
    }

    progress_args_t prog_args = {
        .engine  = &eng,
        .config  = cfg,
        .running = true,
    };
    pthread_t prog_tid = 0;

    if (cfg->show_progress && cfg->interactive) {
        pthread_create(&prog_tid, NULL, progress_thread_fn, &prog_args);
    }

    resume_thread_args_t res_args = {
        .engine      = &eng,
        .config      = cfg,
        .attack_pool = &atk_pool,
        .running     = true,
    };
    pthread_t res_tid = 0;
    if (cfg->save_resume) {
        pthread_create(&res_tid, NULL, resume_thread_fn, &res_args);
    }

    eng.start_time = get_timespec_now();

    /* Create worker threads with optional affinity */
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setstacksize(&attr, 2 * MB); /* 2MB stack per thread */

    for (int i = 0; i < cfg->num_threads; i++) {
        workers[i].thread_id = i;
        workers[i].engine    = &eng;
        workers[i].config    = cfg;
        workers[i].archive   = &arch_pool.contexts[i];
        workers[i].attack    = attack_pool_ctx(&atk_pool, i);
        workers[i].started   = false;

        int rc = pthread_create(&workers[i].tid, &attr,
                                worker_thread_fn, &workers[i]);
        if (rc != 0) {
            log_error("pthread_create[%d] failed: %s", i, strerror(rc));
            atomic_store(&eng.shutdown, true);
            break;
        }

        workers[i].started = true;

        if (pin_threads) {
            engine_set_thread_affinity(workers[i].tid, i);
        }
    }

    pthread_attr_destroy(&attr);

    /* Wait for completion */
    for (int i = 0; i < cfg->num_threads; i++) {
        if (workers[i].started) {
            pthread_join(workers[i].tid, NULL);
        }
    }

    prog_args.running = false;
    res_args.running  = false;

    if (prog_tid) pthread_join(prog_tid, NULL);
    if (res_tid)  pthread_join(res_tid,  NULL);

    if (engine_is_found(&eng)) {
        result = ATTACK_RESULT_FOUND;
        print_found_password(eng.found_password, cfg->archive_path,
                             cfg->no_color);
        if (cfg->output_path[0]) {
            write_found_password(cfg->output_path, cfg->archive_path,
                                  eng.found_password);
        }
    } else if (engine_is_shutdown(&eng)) {
        result = ATTACK_RESULT_ABORTED;
    } else {
        bool all_done = true;
        for (int i = 0; i < atk_pool.count; i++) {
            if (!attack_ctx_exhausted(attack_pool_ctx_const(&atk_pool, i))) {
                all_done = false;
                break;
            }
        }
        result = all_done ? ATTACK_RESULT_EXHAUSTED : ATTACK_RESULT_NOT_FOUND;
    }

    double elapsed = elapsed_seconds_since(&eng.start_time);
    uint64_t total = atomic_load_explicit(&eng.total_attempts,
                                           memory_order_relaxed);

    char elapsed_str[32], speed_str[32], total_str[32];
    format_elapsed(elapsed_str, sizeof(elapsed_str), elapsed);
    format_speed(speed_str,  sizeof(speed_str),
                 (elapsed > 0.001) ? ((double)total / elapsed) : 0.0);
    format_number(total_str, sizeof(total_str), total);

    log_info("Finished: tested=%s elapsed=%s avg_speed=%s result=%d",
             total_str, elapsed_str, speed_str, (int)result);

    if (cfg->save_resume && result == ATTACK_RESULT_ABORTED) {
        resume_state_t rs;
        memset(&rs, 0, sizeof(rs));
        rs.attack_mode    = cfg->attack_mode;
        rs.archive_type   = cfg->archive_type;
        rs.total_attempts = total;
        snprintf(rs.archive_path,  sizeof(rs.archive_path),
                 "%s", cfg->archive_path);
        snprintf(rs.wordlist_path, sizeof(rs.wordlist_path),
                 "%s", cfg->wordlist_path);
        if (atk_pool.count > 0) {
            rs.wordlist_offset  = attack_ctx_get_dict_offset(
                                    attack_pool_ctx(&atk_pool, 0));
            rs.bruteforce_index = attack_ctx_get_brute_index(
                                    attack_pool_ctx(&atk_pool, 0));
        }
        resume_save(cfg->resume_path, &rs);
        log_info("Resume state saved: %s", cfg->resume_path);
    }

    free(workers);
    attack_pool_free(&atk_pool);
    archive_pool_free(&arch_pool);
    engine_state_cleanup_local(&eng);

    return result;
}

/* ============================================================
 * DYNAMIC BATCH SIZER
 * Adjusts batch size based on measured speed to minimize overhead
 * ============================================================ */

typedef struct {
    size_t  current_batch_size;
    double  last_speed;
    int     no_improve_count;
    size_t  min_batch;
    size_t  max_batch;
} batch_tuner_t;

static void batch_tuner_init(batch_tuner_t *bt,
                              size_t initial,
                              size_t min_batch,
                              size_t max_batch) {
    bt->current_batch_size = initial;
    bt->last_speed         = 0.0;
    bt->no_improve_count   = 0;
    bt->min_batch          = min_batch;
    bt->max_batch          = max_batch;
}

static size_t batch_tuner_update(batch_tuner_t *bt, double current_speed) {
    if (bt->last_speed > 0.0) {
        double improvement = (current_speed - bt->last_speed) / bt->last_speed;

        if (improvement > 0.05) {
            /* Getting faster - increase batch size */
            bt->current_batch_size = (bt->current_batch_size * 3) / 2;
            bt->no_improve_count = 0;
        } else if (improvement < -0.05) {
            /* Getting slower - decrease batch size */
            bt->current_batch_size = (bt->current_batch_size * 2) / 3;
            bt->no_improve_count = 0;
        } else {
            bt->no_improve_count++;
        }

        /* Clamp */
        if (bt->current_batch_size < bt->min_batch) {
            bt->current_batch_size = bt->min_batch;
        }
        if (bt->current_batch_size > bt->max_batch) {
            bt->current_batch_size = bt->max_batch;
        }
    }

    bt->last_speed = current_speed;
    return bt->current_batch_size;
}

/* ============================================================
 * WORKER THREAD (ADAPTIVE BATCH VERSION)
 * Used when dynamic batch sizing is enabled
 * ============================================================ */

static void *worker_thread_adaptive_fn(void *arg) {
    worker_args_t   *wa   = (worker_args_t *)arg;
    engine_state_t  *eng  = wa->engine;
    const config_t  *cfg  = wa->config;
    archive_ctx_t   *arch = wa->archive;
    attack_ctx_t    *atk  = wa->attack;
    int              tid  = wa->thread_id;

    thread_status_t *ts = &eng->thread_status[tid];
    ts->running = true;

    batch_tuner_t tuner;
    batch_tuner_init(&tuner,
                     cfg->batch_size,
                     64,
                     BATCH_MAX_SIZE);

    candidate_batch_t batch;
    batch.count    = 0;
    batch.capacity = (int)cfg->batch_size;

    uint64_t last_count = 0;
    uint64_t last_ns    = get_time_ns();

    while (LIKELY(!engine_is_found(eng) && !engine_is_shutdown(eng))) {

        while (atomic_load_explicit(&eng->paused,
                                    memory_order_relaxed) &&
               !engine_is_shutdown(eng)) {
            sleep_ms(50);
        }

        batch.capacity = (int)tuner.current_batch_size;
        if (batch.capacity > BATCH_MAX_SIZE) batch.capacity = BATCH_MAX_SIZE;

        int n = attack_ctx_next_batch(atk, &batch);
        if (n <= 0) break;

        for (int i = 0; i < n; i++) {
            if (UNLIKELY(engine_is_found(eng) ||
                         engine_is_shutdown(eng))) goto done;

            const char *pw = batch.passwords[i];

            if (UNLIKELY((ts->attempts & 0xFFULL) == 0)) {
                size_t pwlen = strlen(pw);
                if (pwlen >= MAX_PASSWORD_LEN) pwlen = MAX_PASSWORD_LEN - 1;
                memcpy(ts->current_password, pw, pwlen);
                ts->current_password[pwlen] = '\0';
            }

            if (UNLIKELY(archive_validate_password(arch, pw))) {
                engine_set_found(eng, pw);
                ts->found = true;
                goto done;
            }

            ts->attempts++;
        }

        atomic_fetch_add_explicit(&eng->total_attempts,
                                   (uint_fast64_t)n,
                                   memory_order_relaxed);

        /* Periodically tune batch size */
        if ((ts->attempts & 0x3FFFULL) == 0) {
            uint64_t now_ns = get_time_ns();
            uint64_t delta_ns = now_ns - last_ns;
            uint64_t delta_n  = ts->attempts - last_count;

            if (delta_ns > 0 && delta_n > 0) {
                double speed = (double)delta_n /
                               ((double)delta_ns / 1e9);
                batch_tuner_update(&tuner, speed);
            }

            last_ns    = now_ns;
            last_count = ts->attempts;
        }

        if (cfg->limit > 0) {
            uint64_t tot = atomic_load_explicit(&eng->total_attempts,
                                                 memory_order_relaxed);
            if (tot >= cfg->limit) break;
        }
    }

done:
    ts->running = false;
    return NULL;
}

/* ============================================================
 * ENGINE STATUS QUERY
 * ============================================================ */

void engine_print_thread_stats(const engine_state_t *eng,
                                bool no_color) {
    const char *c_l = no_color ? "" : "\033[97m";
    const char *c_v = no_color ? "" : "\033[36m";
    const char *c_r = no_color ? "" : "\033[0m";

    fprintf(stderr, "%s[Thread Statistics]%s\n", c_l, c_r);
    for (int i = 0; i < eng->num_threads; i++) {
        const thread_status_t *ts = &eng->thread_status[i];
        char attempts_str[32];
        format_number(attempts_str, sizeof(attempts_str), ts->attempts);
        fprintf(stderr,
                "  %sThread %2d:%s attempts=%-16s running=%s\n",
                c_l, i, c_r,
                attempts_str,
                ts->running ? "yes" : "no");
    }
    fprintf(stderr, "\n");
}

/* ============================================================
 * ENGINE PAUSE/RESUME
 * ============================================================ */

void engine_pause(engine_state_t *eng) {
    atomic_store_explicit(&eng->paused, true, memory_order_relaxed);
    log_info("Engine paused");
}

void engine_resume_exec(engine_state_t *eng) {
    atomic_store_explicit(&eng->paused, false, memory_order_relaxed);
    log_info("Engine resumed");
}

void engine_stop(engine_state_t *eng) {
    atomic_store_explicit(&eng->shutdown, true, memory_order_relaxed);
    log_info("Engine stop requested");
}

/* ============================================================
 * END OF engine.c
 * ============================================================ */

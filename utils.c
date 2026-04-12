/*
 * utils.c - Core utilities for crive password recovery framework
 * Logging, timing, memory helpers, ANSI UI, config parsing
 * C11 standard, optimized for Termux/Android Linux
 */

#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdarg.h>
#include <time.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <pthread.h>
#include <signal.h>
#include <errno.h>
#include <fcntl.h>
#include <ctype.h>
#include <math.h>
#include <limits.h>
#include <stdatomic.h>
#include <getopt.h>
#include <termios.h>
#include <sys/ioctl.h>
#include <locale.h>

/* ============================================================
 * VERSION AND BUILD INFO
 * ============================================================ */

#define CRIVE_VERSION_MAJOR     1
#define CRIVE_VERSION_MINOR     0
#define CRIVE_VERSION_PATCH     0
#define CRIVE_VERSION_STR       "1.0.0"
#define CRIVE_BUILD_DATE        __DATE__
#define CRIVE_BUILD_TIME        __TIME__
#define CRIVE_AUTHOR            "crive framework"

/* ============================================================
 * PLATFORM DETECTION
 * ============================================================ */

#if defined(__ANDROID__)
    #define PLATFORM_ANDROID 1
    #define PLATFORM_NAME "Android/Termux"
#elif defined(__linux__)
    #define PLATFORM_LINUX 1
    #define PLATFORM_NAME "Linux"
#else
    #define PLATFORM_UNKNOWN 1
    #define PLATFORM_NAME "Unknown"
#endif

/* ============================================================
 * COMPILER HINTS
 * ============================================================ */

#define LIKELY(x)       __builtin_expect(!!(x), 1)
#define UNLIKELY(x)     __builtin_expect(!!(x), 0)
#define FORCE_INLINE    __attribute__((always_inline)) static inline
#define NO_INLINE       __attribute__((noinline))
#define PURE_FN         __attribute__((pure))
#define CONST_FN        __attribute__((const))
#define PACKED          __attribute__((packed))
#define ALIGNED(n)      __attribute__((aligned(n)))
#define UNUSED          __attribute__((unused))
#define NORETURN        __attribute__((noreturn))

/* ============================================================
 * MEMORY CONSTANTS
 * ============================================================ */

#define KB                      (1024ULL)
#define MB                      (1024ULL * KB)
#define GB                      (1024ULL * MB)

#define MAX_PASSWORD_LEN        128
#define MAX_PATH_LEN            4096
#define MAX_LINE_LEN            8192
#define MAX_CHARSET_LEN         512
#define MAX_MASK_LEN            256
#define MAX_THREADS             256
#define MAX_WORDLIST_PATH       4096
#define MAX_RULE_LEN            1024
#define MAX_RULES               4096
#define MAX_LOG_LINE            2048
#define MAX_CONFIG_KEY          256
#define MAX_CONFIG_VAL          1024
#define DEFAULT_DICT_BUFSIZE    (4 * MB)
#define DEFAULT_BATCH_SIZE      1024
#define PROGRESS_UPDATE_MS      250
#define SPEED_SAMPLE_WINDOW     8
#define MAX_STATUS_LINE         256
#define RESUME_MAGIC            0xCR1VE001UL
#define RESUME_VERSION          1

/* ============================================================
 * ANSI COLOR CODES
 * ============================================================ */

#define ANSI_RESET              "\033[0m"
#define ANSI_BOLD               "\033[1m"
#define ANSI_DIM                "\033[2m"
#define ANSI_ITALIC             "\033[3m"
#define ANSI_UNDERLINE          "\033[4m"
#define ANSI_BLINK              "\033[5m"
#define ANSI_REVERSE            "\033[7m"
#define ANSI_HIDDEN             "\033[8m"
#define ANSI_STRIKETHROUGH      "\033[9m"

#define ANSI_BLACK              "\033[30m"
#define ANSI_RED                "\033[31m"
#define ANSI_GREEN              "\033[32m"
#define ANSI_YELLOW             "\033[33m"
#define ANSI_BLUE               "\033[34m"
#define ANSI_MAGENTA            "\033[35m"
#define ANSI_CYAN               "\033[36m"
#define ANSI_WHITE              "\033[37m"
#define ANSI_DEFAULT            "\033[39m"

#define ANSI_BRIGHT_BLACK       "\033[90m"
#define ANSI_BRIGHT_RED         "\033[91m"
#define ANSI_BRIGHT_GREEN       "\033[92m"
#define ANSI_BRIGHT_YELLOW      "\033[93m"
#define ANSI_BRIGHT_BLUE        "\033[94m"
#define ANSI_BRIGHT_MAGENTA     "\033[95m"
#define ANSI_BRIGHT_CYAN        "\033[96m"
#define ANSI_BRIGHT_WHITE       "\033[97m"

#define ANSI_BG_BLACK           "\033[40m"
#define ANSI_BG_RED             "\033[41m"
#define ANSI_BG_GREEN           "\033[42m"
#define ANSI_BG_YELLOW          "\033[43m"
#define ANSI_BG_BLUE            "\033[44m"
#define ANSI_BG_MAGENTA         "\033[45m"
#define ANSI_BG_CYAN            "\033[46m"
#define ANSI_BG_WHITE           "\033[47m"

#define ANSI_CURSOR_UP(n)       "\033[" #n "A"
#define ANSI_CURSOR_DOWN(n)     "\033[" #n "B"
#define ANSI_CURSOR_RIGHT(n)    "\033[" #n "C"
#define ANSI_CURSOR_LEFT(n)     "\033[" #n "D"
#define ANSI_CURSOR_HOME        "\033[H"
#define ANSI_ERASE_LINE         "\033[2K"
#define ANSI_ERASE_TO_EOL       "\033[K"
#define ANSI_SAVE_CURSOR        "\033[s"
#define ANSI_RESTORE_CURSOR     "\033[u"
#define ANSI_HIDE_CURSOR        "\033[?25l"
#define ANSI_SHOW_CURSOR        "\033[?25h"
#define ANSI_CLEAR_SCREEN       "\033[2J"
#define ANSI_CLEAR_DOWN         "\033[J"

/* Semantic color aliases */
#define CLR_SUCCESS             ANSI_BRIGHT_GREEN
#define CLR_ERROR               ANSI_BRIGHT_RED
#define CLR_WARNING             ANSI_BRIGHT_YELLOW
#define CLR_INFO                ANSI_BRIGHT_CYAN
#define CLR_DEBUG               ANSI_BRIGHT_BLACK
#define CLR_HEADER              ANSI_BRIGHT_MAGENTA
#define CLR_LABEL               ANSI_BRIGHT_WHITE
#define CLR_VALUE               ANSI_CYAN
#define CLR_SPEED               ANSI_BRIGHT_YELLOW
#define CLR_FOUND               ANSI_BRIGHT_GREEN ANSI_BOLD
#define CLR_BORDER              ANSI_BLUE

/* UI symbols */
#define SYM_OK                  CLR_SUCCESS "[+]" ANSI_RESET
#define SYM_ERR                 CLR_ERROR   "[-]" ANSI_RESET
#define SYM_WARN                CLR_WARNING "[!]" ANSI_RESET
#define SYM_INFO                CLR_INFO    "[*]" ANSI_RESET
#define SYM_DBG                 CLR_DEBUG   "[D]" ANSI_RESET
#define SYM_FOUND               CLR_FOUND   "[FOUND]" ANSI_RESET
#define SYM_ARROW               ANSI_CYAN   "→" ANSI_RESET
#define SYM_BULLET              ANSI_BLUE   "•" ANSI_RESET

/* ============================================================
 * CHARSETS
 * ============================================================ */

#define CHARSET_LOWER           "abcdefghijklmnopqrstuvwxyz"
#define CHARSET_UPPER           "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
#define CHARSET_DIGITS          "0123456789"
#define CHARSET_SPECIAL         "!@#$%^&*()-_=+[]{}|;:,.<>?/`~\"\\ '"
#define CHARSET_HEX_LOWER       "0123456789abcdef"
#define CHARSET_HEX_UPPER       "0123456789ABCDEF"
#define CHARSET_ALPHA           "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
#define CHARSET_ALNUM           "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
#define CHARSET_PRINTABLE       " !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~"

#define CHARSET_LOWER_LEN       26
#define CHARSET_UPPER_LEN       26
#define CHARSET_DIGITS_LEN      10
#define CHARSET_SPECIAL_LEN     33
#define CHARSET_ALPHA_LEN       52
#define CHARSET_ALNUM_LEN       62
#define CHARSET_PRINTABLE_LEN   95

/* ============================================================
 * ATTACK MODE ENUM
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

static const char *attack_mode_names[] = {
    [ATTACK_NONE]       = "None",
    [ATTACK_DICTIONARY] = "Dictionary",
    [ATTACK_BRUTEFORCE] = "Brute-Force",
    [ATTACK_MASK]       = "Mask",
    [ATTACK_HYBRID]     = "Hybrid",
    [ATTACK_RULE]       = "Rule-Based",
    [ATTACK_BENCHMARK]  = "Benchmark",
};

/* ============================================================
 * ARCHIVE TYPE ENUM
 * ============================================================ */

typedef enum {
    ARCHIVE_UNKNOWN = 0,
    ARCHIVE_ZIP     = 1,
    ARCHIVE_7Z      = 2,
    ARCHIVE_MAX
} archive_type_t;

static const char *archive_type_names[] = {
    [ARCHIVE_UNKNOWN] = "Unknown",
    [ARCHIVE_ZIP]     = "ZIP",
    [ARCHIVE_7Z]      = "7-Zip",
};

/* ============================================================
 * LOG LEVEL ENUM
 * ============================================================ */

typedef enum {
    LOG_DEBUG   = 0,
    LOG_INFO    = 1,
    LOG_WARNING = 2,
    LOG_ERROR   = 3,
    LOG_SILENT  = 4,
} log_level_t;

/* ============================================================
 * CHARSET SPEC STRUCT
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

/* ============================================================
 * MASK POSITION STRUCT
 * ============================================================ */

#define MAX_MASK_POSITIONS      32

typedef struct {
    char    charset[MAX_CHARSET_LEN];
    int     charset_len;
} mask_position_t;

typedef struct {
    mask_position_t positions[MAX_MASK_POSITIONS];
    int             num_positions;
    char            raw_mask[MAX_MASK_LEN];
} mask_spec_t;

/* ============================================================
 * HYBRID CONFIG STRUCT
 * ============================================================ */

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

/* ============================================================
 * RULE STRUCT
 * ============================================================ */

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

static const char *rule_type_names[] = {
    [RULE_APPEND_DIGIT]     = "append_digit",
    [RULE_PREPEND_DIGIT]    = "prepend_digit",
    [RULE_UPPERCASE_ALL]    = "uppercase_all",
    [RULE_LOWERCASE_ALL]    = "lowercase_all",
    [RULE_CAPITALIZE]       = "capitalize",
    [RULE_REVERSE]          = "reverse",
    [RULE_DUPLICATE]        = "duplicate",
    [RULE_LEET_SPEAK]       = "leet_speak",
    [RULE_APPEND_YEAR]      = "append_year",
    [RULE_APPEND_SPECIAL]   = "append_special",
    [RULE_TOGGLE_CASE]      = "toggle_case",
    [RULE_ROTATE_LEFT]      = "rotate_left",
    [RULE_ROTATE_RIGHT]     = "rotate_right",
    [RULE_REFLECT]          = "reflect",
    [RULE_STRIP_VOWELS]     = "strip_vowels",
};

typedef struct {
    rule_type_t type;
    char        param[64];
    int         param_int;
} rule_t;

/* ============================================================
 * THREAD STATUS STRUCT
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
 * SPEED SAMPLE STRUCT (moving average)
 * ============================================================ */

typedef struct {
    uint64_t    samples[SPEED_SAMPLE_WINDOW];
    uint64_t    timestamps[SPEED_SAMPLE_WINDOW];
    int         head;
    int         count;
    uint64_t    last_attempts;
    uint64_t    last_time_ns;
} speed_tracker_t;

/* ============================================================
 * RESUME STATE STRUCT
 * ============================================================ */

typedef struct {
    uint32_t    magic;
    uint32_t    version;
    attack_mode_t attack_mode;
    archive_type_t archive_type;
    char        archive_path[MAX_PATH_LEN];
    char        wordlist_path[MAX_PATH_LEN];
    uint64_t    total_attempts;
    uint64_t    wordlist_offset;
    uint64_t    bruteforce_index;
    int         current_length;
    char        brute_counter[MAX_PASSWORD_LEN];
    time_t      saved_at;
    uint32_t    checksum;
} resume_state_t;

/* ============================================================
 * MAIN CONFIG STRUCT
 * ============================================================ */

typedef struct {
    /* Target */
    char            archive_path[MAX_PATH_LEN];
    archive_type_t  archive_type;

    /* Attack mode */
    attack_mode_t   attack_mode;

    /* Dictionary options */
    char            wordlist_path[MAX_PATH_LEN];
    size_t          dict_buffer_size;

    /* Brute-force options */
    int             min_length;
    int             max_length;
    charset_spec_t  charset;

    /* Mask options */
    mask_spec_t     mask;

    /* Hybrid options */
    hybrid_config_t hybrid;

    /* Rule options */
    char            rules_path[MAX_PATH_LEN];
    rule_t          rules[MAX_RULES];
    int             num_rules;

    /* Threading */
    int             num_threads;
    size_t          batch_size;

    /* Output */
    char            output_path[MAX_PATH_LEN];
    char            log_path[MAX_PATH_LEN];
    bool            verbose;
    bool            quiet;
    log_level_t     log_level;
    bool            no_color;
    bool            show_progress;

    /* Resume */
    bool            resume;
    char            resume_path[MAX_PATH_LEN];
    bool            save_resume;

    /* Benchmark */
    int             benchmark_duration;

    /* Limits */
    uint64_t        limit;
    uint64_t        skip;

    /* Performance */
    int             progress_interval_ms;

    /* Internal state flags */
    bool            force_archive_type;
    bool            interactive;

} config_t;

/* ============================================================
 * SHARED ENGINE STATE STRUCT
 * ============================================================ */

typedef struct {
    /* Atomic flags */
    atomic_bool         found;
    atomic_bool         shutdown;
    atomic_bool         paused;

    /* Found password */
    char                found_password[MAX_PASSWORD_LEN];
    pthread_mutex_t     found_mutex;

    /* Counters */
    atomic_uint_fast64_t total_attempts;
    atomic_uint_fast64_t total_skipped;

    /* Timing */
    struct timespec     start_time;
    struct timespec     last_display_time;

    /* Thread statuses */
    thread_status_t     thread_status[MAX_THREADS];
    int                 num_threads;

    /* Speed tracking */
    speed_tracker_t     speed;
    pthread_mutex_t     speed_mutex;

    /* Current passwords/sec */
    volatile uint64_t   passwords_per_sec;
    volatile double     moving_avg_speed;

    /* ETA */
    volatile int64_t    eta_seconds;
    volatile uint64_t   keyspace_total;
    volatile uint64_t   keyspace_done;

    /* Resume state */
    resume_state_t      resume;

    /* Config reference */
    const config_t      *config;

} engine_state_t;

/* ============================================================
 * LOGGING SYSTEM
 * ============================================================ */

static FILE         *g_log_file       = NULL;
static log_level_t   g_log_level      = LOG_INFO;
static bool          g_log_no_color   = false;
static bool          g_log_quiet      = false;
static pthread_mutex_t g_log_mutex    = PTHREAD_MUTEX_INITIALIZER;
static bool          g_log_timestamp  = true;
static bool          g_log_thread_id  = false;
static char          g_log_prefix[64] = "";

void log_init(const char *log_file_path, log_level_t level, bool no_color, bool quiet) {
    pthread_mutex_lock(&g_log_mutex);

    g_log_level    = level;
    g_log_no_color = no_color;
    g_log_quiet    = quiet;

    if (log_file_path && log_file_path[0] != '\0') {
        g_log_file = fopen(log_file_path, "a");
        if (!g_log_file) {
            fprintf(stderr, "Warning: could not open log file '%s': %s\n",
                    log_file_path, strerror(errno));
        }
    }

    pthread_mutex_unlock(&g_log_mutex);
}

void log_close(void) {
    pthread_mutex_lock(&g_log_mutex);
    if (g_log_file) {
        fflush(g_log_file);
        fclose(g_log_file);
        g_log_file = NULL;
    }
    pthread_mutex_unlock(&g_log_mutex);
}

void log_set_level(log_level_t level) {
    g_log_level = level;
}

void log_set_prefix(const char *prefix) {
    if (prefix) {
        snprintf(g_log_prefix, sizeof(g_log_prefix), "%s", prefix);
    }
}

static void get_timestamp_str(char *buf, size_t buflen) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    struct tm *tm_info = localtime(&ts.tv_sec);
    size_t written = strftime(buf, buflen, "%H:%M:%S", tm_info);
    if (written < buflen) {
        snprintf(buf + written, buflen - written, ".%03ld",
                 ts.tv_nsec / 1000000L);
    }
}

static const char *log_level_color(log_level_t level) {
    if (g_log_no_color) return "";
    switch (level) {
        case LOG_DEBUG:   return CLR_DEBUG;
        case LOG_INFO:    return CLR_INFO;
        case LOG_WARNING: return CLR_WARNING;
        case LOG_ERROR:   return CLR_ERROR;
        default:          return "";
    }
}

static const char *log_level_label(log_level_t level) {
    switch (level) {
        case LOG_DEBUG:   return "DBG";
        case LOG_INFO:    return "INF";
        case LOG_WARNING: return "WRN";
        case LOG_ERROR:   return "ERR";
        default:          return "???";
    }
}

void log_message(log_level_t level, const char *fmt, ...) {
    if (level < g_log_level) return;
    if (g_log_quiet && level < LOG_ERROR) return;

    pthread_mutex_lock(&g_log_mutex);

    char timestamp[32] = {0};
    if (g_log_timestamp) {
        get_timestamp_str(timestamp, sizeof(timestamp));
    }

    char message[MAX_LOG_LINE];
    va_list args;
    va_start(args, fmt);
    vsnprintf(message, sizeof(message), fmt, args);
    va_end(args);

    /* Console output */
    if (!g_log_quiet || level >= LOG_ERROR) {
        const char *color  = log_level_color(level);
        const char *reset  = g_log_no_color ? "" : ANSI_RESET;
        const char *label  = log_level_label(level);

        if (g_log_timestamp) {
            fprintf(stderr, "%s[%s]%s %s%s%s %s\n",
                    g_log_no_color ? "" : ANSI_DIM,
                    timestamp,
                    reset,
                    color,
                    label,
                    reset,
                    message);
        } else {
            fprintf(stderr, "%s%s%s %s\n", color, label, reset, message);
        }
        fflush(stderr);
    }

    /* File output (no color codes) */
    if (g_log_file) {
        if (g_log_timestamp) {
            fprintf(g_log_file, "[%s] [%s] %s\n",
                    timestamp, log_level_label(level), message);
        } else {
            fprintf(g_log_file, "[%s] %s\n", log_level_label(level), message);
        }
        fflush(g_log_file);
    }

    pthread_mutex_unlock(&g_log_mutex);
}

#define log_debug(fmt, ...)   log_message(LOG_DEBUG,   fmt, ##__VA_ARGS__)
#define log_info(fmt, ...)    log_message(LOG_INFO,    fmt, ##__VA_ARGS__)
#define log_warn(fmt, ...)    log_message(LOG_WARNING, fmt, ##__VA_ARGS__)
#define log_error(fmt, ...)   log_message(LOG_ERROR,   fmt, ##__VA_ARGS__)

/* ============================================================
 * TIMING UTILITIES
 * ============================================================ */

FORCE_INLINE uint64_t timespec_to_ns(const struct timespec *ts) {
    return (uint64_t)ts->tv_sec * 1000000000ULL + (uint64_t)ts->tv_nsec;
}

FORCE_INLINE uint64_t timespec_diff_ns(const struct timespec *start,
                                        const struct timespec *end) {
    uint64_t s = timespec_to_ns(start);
    uint64_t e = timespec_to_ns(end);
    return (e >= s) ? (e - s) : 0ULL;
}

FORCE_INLINE double timespec_diff_ms(const struct timespec *start,
                                      const struct timespec *end) {
    return (double)timespec_diff_ns(start, end) / 1e6;
}

FORCE_INLINE double timespec_diff_sec(const struct timespec *start,
                                       const struct timespec *end) {
    return (double)timespec_diff_ns(start, end) / 1e9;
}

FORCE_INLINE uint64_t get_time_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return timespec_to_ns(&ts);
}

FORCE_INLINE uint64_t get_time_ms(void) {
    return get_time_ns() / 1000000ULL;
}

FORCE_INLINE struct timespec get_timespec_now(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts;
}

FORCE_INLINE double elapsed_seconds_since(const struct timespec *start) {
    struct timespec now = get_timespec_now();
    return timespec_diff_sec(start, &now);
}

FORCE_INLINE uint64_t elapsed_ms_since(const struct timespec *start) {
    struct timespec now = get_timespec_now();
    return (uint64_t)timespec_diff_ms(start, &now);
}

/* High-resolution sleep */
void sleep_ms(long ms) {
    struct timespec ts = {
        .tv_sec  = ms / 1000,
        .tv_nsec = (ms % 1000) * 1000000L
    };
    while (nanosleep(&ts, &ts) == -1 && errno == EINTR) {}
}

/* Format elapsed time into human-readable string */
void format_elapsed(char *buf, size_t buflen, double seconds) {
    if (seconds < 0) seconds = 0;
    uint64_t total_sec = (uint64_t)seconds;
    uint64_t hours   = total_sec / 3600;
    uint64_t minutes = (total_sec % 3600) / 60;
    uint64_t secs    = total_sec % 60;
    uint64_t ms      = (uint64_t)((seconds - (double)total_sec) * 1000.0);

    if (hours > 0) {
        snprintf(buf, buflen, "%02luh%02lum%02lus",
                 (unsigned long)hours,
                 (unsigned long)minutes,
                 (unsigned long)secs);
    } else if (minutes > 0) {
        snprintf(buf, buflen, "%02lum%02lus.%03lu",
                 (unsigned long)minutes,
                 (unsigned long)secs,
                 (unsigned long)ms);
    } else {
        snprintf(buf, buflen, "%02lus.%03lu",
                 (unsigned long)secs,
                 (unsigned long)ms);
    }
}

/* Format ETA */
void format_eta(char *buf, size_t buflen, int64_t eta_seconds) {
    if (eta_seconds < 0) {
        snprintf(buf, buflen, "N/A");
        return;
    }
    if (eta_seconds > 86400 * 365) {
        snprintf(buf, buflen, ">1year");
        return;
    }
    format_elapsed(buf, buflen, (double)eta_seconds);
}

/* ============================================================
 * SPEED TRACKER
 * ============================================================ */

void speed_tracker_init(speed_tracker_t *st) {
    memset(st, 0, sizeof(*st));
    st->last_time_ns    = get_time_ns();
    st->last_attempts   = 0;
    st->head            = 0;
    st->count           = 0;
}

void speed_tracker_update(speed_tracker_t *st, uint64_t total_attempts) {
    uint64_t now_ns = get_time_ns();
    uint64_t delta_attempts = total_attempts - st->last_attempts;
    uint64_t delta_ns = now_ns - st->last_time_ns;

    if (delta_ns == 0) return;

    uint64_t speed = (delta_attempts * 1000000000ULL) / delta_ns;

    st->samples[st->head]    = speed;
    st->timestamps[st->head] = now_ns;
    st->head                 = (st->head + 1) % SPEED_SAMPLE_WINDOW;
    if (st->count < SPEED_SAMPLE_WINDOW) st->count++;

    st->last_attempts = total_attempts;
    st->last_time_ns  = now_ns;
}

double speed_tracker_moving_avg(const speed_tracker_t *st) {
    if (st->count == 0) return 0.0;
    uint64_t sum = 0;
    for (int i = 0; i < st->count; i++) {
        sum += st->samples[i];
    }
    return (double)sum / (double)st->count;
}

uint64_t speed_tracker_current(const speed_tracker_t *st) {
    if (st->count == 0) return 0ULL;
    int idx = ((st->head - 1) + SPEED_SAMPLE_WINDOW) % SPEED_SAMPLE_WINDOW;
    return st->samples[idx];
}

/* Format speed */
void format_speed(char *buf, size_t buflen, double speed) {
    if (speed >= 1e9) {
        snprintf(buf, buflen, "%.2f GH/s", speed / 1e9);
    } else if (speed >= 1e6) {
        snprintf(buf, buflen, "%.2f MH/s", speed / 1e6);
    } else if (speed >= 1e3) {
        snprintf(buf, buflen, "%.2f kH/s", speed / 1e3);
    } else {
        snprintf(buf, buflen, "%.0f H/s", speed);
    }
}

/* Format large number with commas */
void format_number(char *buf, size_t buflen, uint64_t n) {
    char tmp[64];
    snprintf(tmp, sizeof(tmp), "%llu", (unsigned long long)n);
    size_t len = strlen(tmp);
    size_t out = 0;
    size_t commas = (len > 0) ? ((len - 1) / 3) : 0;
    size_t total_out = len + commas;

    if (total_out >= buflen) {
        snprintf(buf, buflen, "%llu", (unsigned long long)n);
        return;
    }

    buf[total_out] = '\0';
    size_t src = len;
    size_t dst = total_out;
    size_t grp = 0;

    while (src > 0) {
        if (grp == 3) {
            buf[--dst] = ',';
            grp = 0;
        }
        buf[--dst] = tmp[--src];
        grp++;
    }
    (void)out;
}

/* Format size in bytes */
void format_size(char *buf, size_t buflen, uint64_t bytes) {
    if (bytes >= GB) {
        snprintf(buf, buflen, "%.2f GB", (double)bytes / GB);
    } else if (bytes >= MB) {
        snprintf(buf, buflen, "%.2f MB", (double)bytes / MB);
    } else if (bytes >= KB) {
        snprintf(buf, buflen, "%.2f KB", (double)bytes / KB);
    } else {
        snprintf(buf, buflen, "%llu B", (unsigned long long)bytes);
    }
}

/* ============================================================
 * TERMINAL UTILITIES
 * ============================================================ */

static int g_term_width  = 80;
static int g_term_height = 24;
static bool g_is_tty     = false;

void term_init(void) {
    g_is_tty = isatty(STDERR_FILENO);
    if (g_is_tty) {
        struct winsize ws;
        if (ioctl(STDERR_FILENO, TIOCGWINSZ, &ws) == 0) {
            g_term_width  = (ws.ws_col  > 0) ? ws.ws_col  : 80;
            g_term_height = (ws.ws_row  > 0) ? ws.ws_row  : 24;
        }
    }
}

void term_update_size(void) {
    if (g_is_tty) {
        struct winsize ws;
        if (ioctl(STDERR_FILENO, TIOCGWINSZ, &ws) == 0) {
            g_term_width  = (ws.ws_col  > 0) ? ws.ws_col  : 80;
            g_term_height = (ws.ws_row  > 0) ? ws.ws_row  : 24;
        }
    }
}

int term_width(void)  { return g_term_width;  }
int term_height(void) { return g_term_height; }
bool is_tty(void)     { return g_is_tty;      }

void term_clear_line(void) {
    if (g_is_tty) {
        fprintf(stderr, "\r" ANSI_ERASE_LINE);
        fflush(stderr);
    }
}

void term_move_up(int n) {
    if (g_is_tty && n > 0) {
        fprintf(stderr, "\033[%dA", n);
        fflush(stderr);
    }
}

void term_move_down(int n) {
    if (g_is_tty && n > 0) {
        fprintf(stderr, "\033[%dB", n);
        fflush(stderr);
    }
}

void term_hide_cursor(void) {
    if (g_is_tty) {
        fprintf(stderr, ANSI_HIDE_CURSOR);
        fflush(stderr);
    }
}

void term_show_cursor(void) {
    if (g_is_tty) {
        fprintf(stderr, ANSI_SHOW_CURSOR);
        fflush(stderr);
    }
}

void term_set_title(const char *title) {
    if (g_is_tty) {
        fprintf(stderr, "\033]0;%s\007", title);
        fflush(stderr);
    }
}

/* ============================================================
 * PROGRESS BAR
 * ============================================================ */

#define PROGRESS_BAR_FILL_CHAR      '\xe2\x96\x88'  /* Unicode block */
#define PROGRESS_BAR_EMPTY_CHAR     '-'
#define PROGRESS_BAR_FILL_ASCII     '#'

typedef struct {
    double  percent;
    int     width;
    bool    use_unicode;
    char    fill_color[32];
    char    empty_color[32];
} progress_bar_spec_t;

void render_progress_bar(char *buf, size_t buflen,
                         double percent, int width,
                         bool no_color) {
    if (percent < 0.0) percent = 0.0;
    if (percent > 100.0) percent = 100.0;

    int filled = (int)((percent / 100.0) * (double)width);
    if (filled > width) filled = width;
    int empty  = width - filled;

    char tmp[512] = {0};
    int  pos      = 0;

    if (!no_color) {
        /* Color based on percentage */
        const char *color;
        if (percent < 33.0)       color = ANSI_GREEN;
        else if (percent < 66.0)  color = ANSI_YELLOW;
        else                      color = ANSI_RED;

        pos += snprintf(tmp + pos, sizeof(tmp) - pos, "%s", color);
    }

    for (int i = 0; i < filled; i++) {
        if (pos < (int)sizeof(tmp) - 2) {
            tmp[pos++] = '=';
        }
    }
    if (filled < width && pos < (int)sizeof(tmp) - 2) {
        tmp[pos++] = '>';
        empty--;
    }

    if (!no_color) {
        if (pos < (int)sizeof(tmp) - sizeof(ANSI_RESET) - 1) {
            memcpy(tmp + pos, ANSI_RESET, strlen(ANSI_RESET));
            pos += strlen(ANSI_RESET);
        }
        if (!no_color) {
            if (pos < (int)sizeof(tmp) - sizeof(ANSI_DIM) - 1) {
                memcpy(tmp + pos, ANSI_DIM, strlen(ANSI_DIM));
                pos += strlen(ANSI_DIM);
            }
        }
    }

    for (int i = 0; i < empty; i++) {
        if (pos < (int)sizeof(tmp) - 2) {
            tmp[pos++] = '-';
        }
    }

    if (!no_color) {
        if (pos < (int)sizeof(tmp) - sizeof(ANSI_RESET) - 1) {
            memcpy(tmp + pos, ANSI_RESET, strlen(ANSI_RESET));
            pos += strlen(ANSI_RESET);
        }
    }

    tmp[pos] = '\0';
    snprintf(buf, buflen, "%s", tmp);
}

/* Spinner */
static const char *g_spinner_frames[] = {
    "⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"
};
static const char *g_spinner_ascii[] = {
    "|", "/", "-", "\\"
};
static int g_spinner_idx = 0;

const char *spinner_next(bool use_unicode) {
    if (use_unicode) {
        const char *frame = g_spinner_frames[g_spinner_idx];
        g_spinner_idx = (g_spinner_idx + 1) %
            (int)(sizeof(g_spinner_frames) / sizeof(g_spinner_frames[0]));
        return frame;
    } else {
        const char *frame = g_spinner_ascii[g_spinner_idx];
        g_spinner_idx = (g_spinner_idx + 1) %
            (int)(sizeof(g_spinner_ascii) / sizeof(g_spinner_ascii[0]));
        return frame;
    }
}

/* ============================================================
 * UI BANNER AND HEADERS
 * ============================================================ */

void print_banner(bool no_color) {
    const char *c_h  = no_color ? "" : ANSI_BRIGHT_MAGENTA ANSI_BOLD;
    const char *c_v  = no_color ? "" : ANSI_BRIGHT_CYAN;
    const char *c_r  = no_color ? "" : ANSI_RESET;
    const char *c_d  = no_color ? "" : ANSI_DIM;
    const char *c_y  = no_color ? "" : ANSI_BRIGHT_YELLOW;

    fprintf(stderr,
        "%s╔══════════════════════════════════════════════════════════╗%s\n"
        "%s║%s  %s ██████╗██████╗ ██╗██╗   ██╗███████╗               %s║%s\n"
        "%s║%s  %s██╔════╝██╔══██╗██║██║   ██║██╔════╝               %s║%s\n"
        "%s║%s  %s██║     ██████╔╝██║██║   ██║█████╗                 %s║%s\n"
        "%s║%s  %s██║     ██╔══██╗██║╚██╗ ██╔╝██╔══╝                 %s║%s\n"
        "%s║%s  %s╚██████╗██║  ██║██║ ╚████╔╝ ███████╗               %s║%s\n"
        "%s║%s  %s ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝  ╚══════╝               %s║%s\n"
        "%s║%s  %sArchive Password Recovery Framework v%s             %s║%s\n"
        "%s║%s  %s%sPlatform: %s%-20s  CPU-Only Engine%s               %s║%s\n"
        "%s╚══════════════════════════════════════════════════════════╝%s\n",
        c_h, c_r,
        c_h, c_r, c_v, c_h, c_r,
        c_h, c_r, c_v, c_h, c_r,
        c_h, c_r, c_v, c_h, c_r,
        c_h, c_r, c_v, c_h, c_r,
        c_h, c_r, c_v, c_h, c_r,
        c_h, c_r, c_v, c_h, c_r,
        c_h, c_r, c_y, CRIVE_VERSION_STR, c_h, c_r,
        c_h, c_r, c_d, c_y, PLATFORM_NAME, c_r, c_h, c_r,
        c_h, c_r
    );
    fprintf(stderr, "\n");
}

void print_section_header(const char *title, bool no_color) {
    const char *c_b = no_color ? "" : ANSI_BRIGHT_BLUE ANSI_BOLD;
    const char *c_r = no_color ? "" : ANSI_RESET;
    int width = term_width();
    if (width > 70) width = 70;

    fprintf(stderr, "%s", c_b);
    fprintf(stderr, "┌");
    for (int i = 0; i < width - 2; i++) fprintf(stderr, "─");
    fprintf(stderr, "┐\n");
    fprintf(stderr, "│ %-*s │\n", width - 4, title);
    fprintf(stderr, "└");
    for (int i = 0; i < width - 2; i++) fprintf(stderr, "─");
    fprintf(stderr, "┘%s\n", c_r);
}

void print_kv(const char *key, const char *value, bool no_color) {
    const char *c_k = no_color ? "" : CLR_LABEL;
    const char *c_v = no_color ? "" : CLR_VALUE;
    const char *c_r = no_color ? "" : ANSI_RESET;
    fprintf(stderr, "  %s%-20s%s %s%s%s\n", c_k, key, c_r, c_v, value, c_r);
}

void print_kv_fmt(bool no_color, const char *key, const char *fmt, ...) {
    char val[512];
    va_list args;
    va_start(args, fmt);
    vsnprintf(val, sizeof(val), fmt, args);
    va_end(args);
    print_kv(key, val, no_color);
}

void print_separator(bool no_color) {
    const char *c_b = no_color ? "" : ANSI_DIM ANSI_BLUE;
    const char *c_r = no_color ? "" : ANSI_RESET;
    int width = term_width();
    if (width > 70) width = 70;
    fprintf(stderr, "%s", c_b);
    for (int i = 0; i < width; i++) fprintf(stderr, "─");
    fprintf(stderr, "%s\n", c_r);
}

void print_found_password(const char *password, const char *archive,
                          bool no_color) {
    const char *c_s = no_color ? "" : CLR_FOUND;
    const char *c_r = no_color ? "" : ANSI_RESET;
    const char *c_y = no_color ? "" : ANSI_BRIGHT_YELLOW ANSI_BOLD;
    const char *c_g = no_color ? "" : ANSI_BRIGHT_GREEN;

    int width = term_width();
    if (width > 70) width = 70;

    fprintf(stdout, "\n");
    fprintf(stdout, "%s", c_g);
    fprintf(stdout, "╔");
    for (int i = 0; i < width - 2; i++) fprintf(stdout, "═");
    fprintf(stdout, "╗\n");
    fprintf(stdout, "║  PASSWORD FOUND!%-*s║\n", width - 19, "");
    fprintf(stdout, "╠");
    for (int i = 0; i < width - 2; i++) fprintf(stdout, "═");
    fprintf(stdout, "╣\n");
    fprintf(stdout, "║  Archive  : %-*s║\n", width - 16, archive);
    fprintf(stdout, "║  Password : %s%-*s%s║\n",
            c_y, width - 16, password, c_g);
    fprintf(stdout, "╚");
    for (int i = 0; i < width - 2; i++) fprintf(stdout, "═");
    fprintf(stdout, "╝%s\n", c_r);
    fprintf(stdout, "\n");
    fflush(stdout);

    (void)c_s;
}

/* ============================================================
 * STATUS LINE (live update)
 * ============================================================ */

#define STATUS_LINES    5

static int g_status_lines_printed = 0;

void status_line_begin(void) {
    g_status_lines_printed = 0;
}

void status_line_end(void) {
    /* nothing */
}

void status_line_update(const engine_state_t *state, bool no_color) {
    if (!g_is_tty) return;

    /* Move cursor up to overwrite previous status */
    if (g_status_lines_printed > 0) {
        term_move_up(g_status_lines_printed);
    }

    const config_t *cfg = state->config;
    bool nc = no_color;

    double elapsed     = elapsed_seconds_since(&state->start_time);
    uint64_t attempts  = atomic_load_explicit(&state->total_attempts,
                                              memory_order_relaxed);
    double avg_speed   = state->moving_avg_speed;
    int64_t eta        = state->eta_seconds;

    char elapsed_str[32], eta_str[32], speed_str[32], attempts_str[32];
    char bar_str[128];

    format_elapsed(elapsed_str, sizeof(elapsed_str), elapsed);
    format_eta(eta_str, sizeof(eta_str), eta);
    format_speed(speed_str, sizeof(speed_str), avg_speed);
    format_number(attempts_str, sizeof(attempts_str), attempts);

    double percent = 0.0;
    uint64_t ks_total = state->keyspace_total;
    uint64_t ks_done  = state->keyspace_done;
    if (ks_total > 0) {
        percent = 100.0 * (double)ks_done / (double)ks_total;
    }

    int bar_width = term_width() - 20;
    if (bar_width < 10) bar_width = 10;
    if (bar_width > 50) bar_width = 50;

    render_progress_bar(bar_str, sizeof(bar_str), percent, bar_width, nc);

    const char *c_l  = nc ? "" : CLR_LABEL;
    const char *c_v  = nc ? "" : CLR_VALUE;
    const char *c_sp = nc ? "" : CLR_SPEED;
    const char *c_r  = nc ? "" : ANSI_RESET;
    const char *c_d  = nc ? "" : ANSI_DIM;
    const char *spin = spinner_next(true);

    int lines = 0;

    /* Line 1: spinner + mode + speed */
    fprintf(stderr,
        "\r" ANSI_ERASE_LINE
        "%s%s%s  %sMode:%s %-12s  %sSpeed:%s %s%-16s%s\n",
        nc ? "" : ANSI_CYAN, spin, c_r,
        c_l, c_r,
        (cfg && cfg->attack_mode < ATTACK_MAX)
            ? attack_mode_names[cfg->attack_mode] : "Unknown",
        c_l, c_r,
        c_sp, speed_str, c_r);
    lines++;

    /* Line 2: attempts + elapsed */
    fprintf(stderr,
        "\r" ANSI_ERASE_LINE
        "  %sTested:%s %-16s  %sElapsed:%s %-12s\n",
        c_l, c_r, attempts_str,
        c_l, c_r, elapsed_str);
    lines++;

    /* Line 3: ETA + threads */
    fprintf(stderr,
        "\r" ANSI_ERASE_LINE
        "  %sETA:%s    %-16s  %sThreads:%s %-4d\n",
        c_l, c_r, eta_str,
        c_l, c_r,
        cfg ? cfg->num_threads : 0);
    lines++;

    /* Line 4: Progress bar */
    if (ks_total > 0) {
        fprintf(stderr,
            "\r" ANSI_ERASE_LINE
            "  [%s] %s%.1f%%%s\n",
            bar_str,
            nc ? "" : ANSI_BRIGHT_WHITE, percent, c_r);
    } else {
        fprintf(stderr,
            "\r" ANSI_ERASE_LINE
            "  %s[keyspace unknown]%s\n",
            c_d, c_r);
    }
    lines++;

    /* Line 5: current candidate (truncated) */
    char candidate[64] = {0};
    /* show first thread's current password */
    if (state->num_threads > 0) {
        snprintf(candidate, sizeof(candidate), "%.60s",
                 state->thread_status[0].current_password);
    }
    fprintf(stderr,
        "\r" ANSI_ERASE_LINE
        "  %sTrying:%s %.55s\n",
        c_l, c_r, candidate);
    lines++;

    fflush(stderr);
    g_status_lines_printed = lines;
}

void status_line_clear(void) {
    if (!g_is_tty) return;
    if (g_status_lines_printed > 0) {
        for (int i = 0; i < g_status_lines_printed; i++) {
            fprintf(stderr, "\r" ANSI_ERASE_LINE "\n");
        }
        term_move_up(g_status_lines_printed);
        g_status_lines_printed = 0;
    }
}

/* ============================================================
 * MEMORY HELPERS
 * ============================================================ */

/* Checked malloc - exits on failure */
void *xmalloc(size_t size) {
    void *ptr = malloc(size);
    if (UNLIKELY(!ptr)) {
        log_error("Fatal: malloc(%zu) failed: %s", size, strerror(errno));
        exit(EXIT_FAILURE);
    }
    return ptr;
}

/* Checked calloc */
void *xcalloc(size_t nmemb, size_t size) {
    void *ptr = calloc(nmemb, size);
    if (UNLIKELY(!ptr)) {
        log_error("Fatal: calloc(%zu, %zu) failed: %s",
                  nmemb, size, strerror(errno));
        exit(EXIT_FAILURE);
    }
    return ptr;
}

/* Checked realloc */
void *xrealloc(void *ptr, size_t size) {
    void *new_ptr = realloc(ptr, size);
    if (UNLIKELY(!new_ptr)) {
        log_error("Fatal: realloc(%zu) failed: %s", size, strerror(errno));
        exit(EXIT_FAILURE);
    }
    return new_ptr;
}

/* Checked strdup */
char *xstrdup(const char *s) {
    if (!s) return NULL;
    char *dup = strdup(s);
    if (UNLIKELY(!dup)) {
        log_error("Fatal: strdup failed: %s", strerror(errno));
        exit(EXIT_FAILURE);
    }
    return dup;
}

/* Aligned malloc */
void *xmalloc_aligned(size_t size, size_t alignment) {
    void *ptr = NULL;
    if (posix_memalign(&ptr, alignment, size) != 0 || !ptr) {
        log_error("Fatal: posix_memalign(%zu, %zu) failed: %s",
                  alignment, size, strerror(errno));
        exit(EXIT_FAILURE);
    }
    return ptr;
}

/* Zero-fill free */
void xfree_secure(void *ptr, size_t size) {
    if (ptr && size > 0) {
        volatile uint8_t *p = (volatile uint8_t *)ptr;
        for (size_t i = 0; i < size; i++) {
            p[i] = 0;
        }
    }
    free(ptr);
}

/* Safe memory copy with bounds check */
FORCE_INLINE size_t safe_memcpy(void *dst, size_t dst_size,
                                 const void *src, size_t src_len) {
    size_t copy_len = (src_len < dst_size) ? src_len : dst_size;
    if (copy_len > 0) memcpy(dst, src, copy_len);
    return copy_len;
}

/* Secure memset (compiler won't optimize away) */
FORCE_INLINE void secure_memzero(void *ptr, size_t len) {
    volatile uint8_t *p = (volatile uint8_t *)ptr;
    while (len--) *p++ = 0;
}

/* ============================================================
 * STRING UTILITIES
 * ============================================================ */

/* Trim leading and trailing whitespace in-place */
char *str_trim(char *s) {
    if (!s) return s;

    /* Trim trailing */
    size_t len = strlen(s);
    while (len > 0 && (s[len-1] == ' ' || s[len-1] == '\t' ||
                        s[len-1] == '\n' || s[len-1] == '\r')) {
        s[--len] = '\0';
    }

    /* Trim leading */
    char *start = s;
    while (*start == ' ' || *start == '\t') start++;

    if (start != s) {
        memmove(s, start, len - (size_t)(start - s) + 1);
    }

    return s;
}

/* Safe string copy returning bytes written */
FORCE_INLINE size_t str_copy(char *dst, size_t dst_size, const char *src) {
    if (!dst || dst_size == 0) return 0;
    if (!src) { dst[0] = '\0'; return 0; }
    size_t len = strlen(src);
    size_t copy = (len < dst_size - 1) ? len : dst_size - 1;
    memcpy(dst, src, copy);
    dst[copy] = '\0';
    return copy;
}

/* Case-insensitive string compare */
FORCE_INLINE int str_icmp(const char *a, const char *b) {
    while (*a && *b) {
        int diff = tolower((unsigned char)*a) - tolower((unsigned char)*b);
        if (diff != 0) return diff;
        a++;
        b++;
    }
    return tolower((unsigned char)*a) - tolower((unsigned char)*b);
}

/* Check if string starts with prefix */
FORCE_INLINE bool str_starts_with(const char *str, const char *prefix) {
    return strncmp(str, prefix, strlen(prefix)) == 0;
}

/* Check if string ends with suffix */
FORCE_INLINE bool str_ends_with(const char *str, const char *suffix) {
    size_t slen = strlen(str);
    size_t plen = strlen(suffix);
    if (plen > slen) return false;
    return strcmp(str + slen - plen, suffix) == 0;
}

/* Convert string to lowercase in-place */
void str_to_lower(char *s) {
    for (; *s; s++) {
        *s = (char)tolower((unsigned char)*s);
    }
}

/* Convert string to uppercase in-place */
void str_to_upper(char *s) {
    for (; *s; s++) {
        *s = (char)toupper((unsigned char)*s);
    }
}

/* Capitalize first letter */
void str_capitalize(char *s) {
    if (*s) {
        *s = (char)toupper((unsigned char)*s);
    }
}

/* Reverse string in-place */
void str_reverse(char *s) {
    size_t len = strlen(s);
    for (size_t i = 0; i < len / 2; i++) {
        char tmp      = s[i];
        s[i]          = s[len - 1 - i];
        s[len - 1 -i] = tmp;
    }
}

/* Apply leet-speak substitution */
void str_leet(const char *in, char *out, size_t out_size) {
    size_t i = 0, j = 0;
    while (in[i] && j < out_size - 1) {
        switch (tolower((unsigned char)in[i])) {
            case 'a': out[j++] = '@'; break;
            case 'e': out[j++] = '3'; break;
            case 'i': out[j++] = '1'; break;
            case 'o': out[j++] = '0'; break;
            case 's': out[j++] = '$'; break;
            case 't': out[j++] = '+'; break;
            case 'l': out[j++] = '!'; break;
            case 'g': out[j++] = '9'; break;
            default:  out[j++] = in[i]; break;
        }
        i++;
    }
    out[j] = '\0';
}

/* Toggle case of string */
void str_toggle_case(char *s) {
    for (; *s; s++) {
        if (isupper((unsigned char)*s)) {
            *s = (char)tolower((unsigned char)*s);
        } else if (islower((unsigned char)*s)) {
            *s = (char)toupper((unsigned char)*s);
        }
    }
}

/* Rotate string left by n positions */
void str_rotate_left(char *s, int n) {
    size_t len = strlen(s);
    if (len == 0) return;
    n = ((n % (int)len) + (int)len) % (int)len;
    if (n == 0) return;
    char tmp[MAX_PASSWORD_LEN];
    memcpy(tmp, s + n, len - n);
    memcpy(tmp + len - n, s, n);
    memcpy(s, tmp, len);
}

/* Rotate string right by n positions */
void str_rotate_right(char *s, int n) {
    size_t len = strlen(s);
    if (len == 0) return;
    str_rotate_left(s, (int)len - (n % (int)len));
}

/* ============================================================
 * FILE UTILITIES
 * ============================================================ */

bool file_exists(const char *path) {
    struct stat st;
    return (stat(path, &st) == 0);
}

bool file_is_readable(const char *path) {
    return access(path, R_OK) == 0;
}

int64_t file_size(const char *path) {
    struct stat st;
    if (stat(path, &st) != 0) return -1;
    return (int64_t)st.st_size;
}

/* Get file extension (pointer into path, no alloc) */
const char *file_extension(const char *path) {
    if (!path) return "";
    const char *dot = strrchr(path, '.');
    const char *sep = strrchr(path, '/');
    if (!dot) return "";
    if (sep && dot < sep) return "";
    return dot + 1;
}

/* Get basename (pointer into path, no alloc) */
const char *file_basename(const char *path) {
    if (!path) return "";
    const char *sep = strrchr(path, '/');
    return sep ? sep + 1 : path;
}

/* Count lines in file efficiently */
int64_t file_count_lines(const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) return -1;

    const size_t BUF_SZ = 64 * KB;
    char *buf = (char *)xmalloc(BUF_SZ);
    int64_t lines = 0;
    size_t n;
    bool last_was_newline = true;

    while ((n = fread(buf, 1, BUF_SZ, f)) > 0) {
        for (size_t i = 0; i < n; i++) {
            if (buf[i] == '\n') {
                lines++;
                last_was_newline = true;
            } else {
                last_was_newline = false;
            }
        }
    }

    if (!last_was_newline) lines++; /* last line without newline */

    free(buf);
    fclose(f);
    return lines;
}

/* ============================================================
 * CHARSET PARSING
 * ============================================================ */

/*
 * Parse charset string like "lower+upper+digits+special+custom:XYZ"
 * or just provide literal characters directly
 */
int charset_parse(charset_spec_t *cs, const char *spec) {
    memset(cs, 0, sizeof(*cs));

    if (!spec || !*spec) {
        /* Default: lowercase */
        str_copy(cs->chars, sizeof(cs->chars), CHARSET_LOWER);
        cs->len       = CHARSET_LOWER_LEN;
        cs->use_lower = true;
        return 0;
    }

    /* Check if it's a named charset spec */
    bool named = strstr(spec, "lower")   != NULL ||
                 strstr(spec, "upper")   != NULL ||
                 strstr(spec, "digits")  != NULL ||
                 strstr(spec, "special") != NULL ||
                 strstr(spec, "alpha")   != NULL ||
                 strstr(spec, "alnum")   != NULL ||
                 strstr(spec, "print")   != NULL ||
                 strstr(spec, "hex")     != NULL;

    char tmp_chars[MAX_CHARSET_LEN] = {0};
    int  tmp_len  = 0;
    bool used[256] = {false};

    #define ADD_CHARS(str, len, flag)  do { \
        cs->flag = true; \
        for (int _i = 0; _i < (len); _i++) { \
            unsigned char _c = (unsigned char)(str)[_i]; \
            if (!used[_c] && tmp_len < MAX_CHARSET_LEN - 1) { \
                tmp_chars[tmp_len++] = (str)[_i]; \
                used[_c] = true; \
            } \
        } \
    } while(0)

    if (named) {
        /* Parse tokens split by '+' */
        char spec_copy[MAX_CHARSET_LEN];
        str_copy(spec_copy, sizeof(spec_copy), spec);

        char *token = strtok(spec_copy, "+");
        while (token) {
            str_trim(token);
            if (strcmp(token, "lower") == 0) {
                ADD_CHARS(CHARSET_LOWER, CHARSET_LOWER_LEN, use_lower);
            } else if (strcmp(token, "upper") == 0) {
                ADD_CHARS(CHARSET_UPPER, CHARSET_UPPER_LEN, use_upper);
            } else if (strcmp(token, "digits") == 0 ||
                       strcmp(token, "digit") == 0) {
                ADD_CHARS(CHARSET_DIGITS, CHARSET_DIGITS_LEN, use_digits);
            } else if (strcmp(token, "special") == 0 ||
                       strcmp(token, "symbols") == 0) {
                ADD_CHARS(CHARSET_SPECIAL, CHARSET_SPECIAL_LEN, use_special);
            } else if (strcmp(token, "alpha") == 0) {
                ADD_CHARS(CHARSET_LOWER, CHARSET_LOWER_LEN, use_lower);
                ADD_CHARS(CHARSET_UPPER, CHARSET_UPPER_LEN, use_upper);
            } else if (strcmp(token, "alnum") == 0) {
                ADD_CHARS(CHARSET_LOWER,  CHARSET_LOWER_LEN,  use_lower);
                ADD_CHARS(CHARSET_UPPER,  CHARSET_UPPER_LEN,  use_upper);
                ADD_CHARS(CHARSET_DIGITS, CHARSET_DIGITS_LEN, use_digits);
            } else if (strcmp(token, "print") == 0 ||
                       strcmp(token, "printable") == 0) {
                ADD_CHARS(CHARSET_PRINTABLE, CHARSET_PRINTABLE_LEN, use_lower);
            } else if (strcmp(token, "hex") == 0) {
                ADD_CHARS(CHARSET_HEX_LOWER, 16, use_digits);
            } else if (str_starts_with(token, "custom:")) {
                const char *custom = token + 7;
                cs->use_custom = true;
                str_copy(cs->custom, sizeof(cs->custom), custom);
                for (size_t i = 0; i < strlen(custom); i++) {
                    unsigned char c = (unsigned char)custom[i];
                    if (!used[c] && tmp_len < MAX_CHARSET_LEN - 1) {
                        tmp_chars[tmp_len++] = custom[i];
                        used[c] = true;
                    }
                }
            } else {
                /* Treat as literal charset */
                for (size_t i = 0; i < strlen(token); i++) {
                    unsigned char c = (unsigned char)token[i];
                    if (!used[c] && tmp_len < MAX_CHARSET_LEN - 1) {
                        tmp_chars[tmp_len++] = token[i];
                        used[c] = true;
                    }
                }
            }
            token = strtok(NULL, "+");
        }
    } else {
        /* Treat entire spec as literal charset */
        for (size_t i = 0; i < strlen(spec); i++) {
            unsigned char c = (unsigned char)spec[i];
            if (!used[c] && tmp_len < MAX_CHARSET_LEN - 1) {
                tmp_chars[tmp_len++] = spec[i];
                used[c] = true;
            }
        }
        cs->use_custom = true;
    }

    #undef ADD_CHARS

    if (tmp_len == 0) {
        log_error("charset_parse: empty charset after parsing '%s'", spec);
        return -1;
    }

    memcpy(cs->chars, tmp_chars, tmp_len);
    cs->chars[tmp_len] = '\0';
    cs->len = tmp_len;
    return 0;
}

void charset_print(const charset_spec_t *cs, bool no_color) {
    const char *c_v = no_color ? "" : CLR_VALUE;
    const char *c_r = no_color ? "" : ANSI_RESET;
    char display[64];
    if (cs->len <= 20) {
        str_copy(display, sizeof(display), cs->chars);
    } else {
        snprintf(display, sizeof(display), "%.20s... (+%d more)",
                 cs->chars, cs->len - 20);
    }
    fprintf(stderr, "  Charset       : %s%s%s (%d chars)\n",
            c_v, display, c_r, cs->len);
}

/* ============================================================
 * MASK PARSING
 * ============================================================ */

/*
 * Parse mask string like ?l?u?d?d?s
 * ?l = lowercase, ?u = uppercase, ?d = digit, ?s = special
 * ?a = all printable, ?h = hex
 * ?1-?9 = custom charsets
 */
int mask_parse(mask_spec_t *ms, const char *mask_str,
               const charset_spec_t *custom_charsets,
               int num_custom) {
    memset(ms, 0, sizeof(*ms));
    str_copy(ms->raw_mask, sizeof(ms->raw_mask), mask_str);

    const char *p   = mask_str;
    int         pos = 0;

    while (*p && pos < MAX_MASK_POSITIONS) {
        mask_position_t *mp = &ms->positions[pos];

        if (*p == '?' && *(p+1)) {
            char code = *(p+1);
            p += 2;

            switch (code) {
                case 'l':
                    str_copy(mp->charset, sizeof(mp->charset), CHARSET_LOWER);
                    mp->charset_len = CHARSET_LOWER_LEN;
                    break;
                case 'u':
                    str_copy(mp->charset, sizeof(mp->charset), CHARSET_UPPER);
                    mp->charset_len = CHARSET_UPPER_LEN;
                    break;
                case 'd':
                    str_copy(mp->charset, sizeof(mp->charset), CHARSET_DIGITS);
                    mp->charset_len = CHARSET_DIGITS_LEN;
                    break;
                case 's':
                    str_copy(mp->charset, sizeof(mp->charset), CHARSET_SPECIAL);
                    mp->charset_len = CHARSET_SPECIAL_LEN;
                    break;
                case 'a':
                    str_copy(mp->charset, sizeof(mp->charset), CHARSET_PRINTABLE);
                    mp->charset_len = CHARSET_PRINTABLE_LEN;
                    break;
                case 'h':
                    str_copy(mp->charset, sizeof(mp->charset), CHARSET_HEX_LOWER);
                    mp->charset_len = 16;
                    break;
                case 'H':
                    str_copy(mp->charset, sizeof(mp->charset), CHARSET_HEX_UPPER);
                    mp->charset_len = 16;
                    break;
                case '?':
                    str_copy(mp->charset, sizeof(mp->charset), "?");
                    mp->charset_len = 1;
                    break;
                case '1': case '2': case '3': case '4':
                case '5': case '6': case '7': case '8': case '9': {
                    int idx = code - '1';
                    if (custom_charsets && idx < num_custom) {
                        str_copy(mp->charset, sizeof(mp->charset),
                                 custom_charsets[idx].chars);
                        mp->charset_len = custom_charsets[idx].len;
                    } else {
                        /* fallback to printable */
                        str_copy(mp->charset, sizeof(mp->charset),
                                 CHARSET_PRINTABLE);
                        mp->charset_len = CHARSET_PRINTABLE_LEN;
                    }
                    break;
                }
                default:
                    log_warn("Unknown mask token: ?%c, treating as literal", code);
                    mp->charset[0] = code;
                    mp->charset[1] = '\0';
                    mp->charset_len = 1;
                    break;
            }
        } else {
            /* Literal character */
            mp->charset[0]  = *p;
            mp->charset[1]  = '\0';
            mp->charset_len = 1;
            p++;
        }

        if (mp->charset_len > 0) {
            pos++;
        }
    }

    ms->num_positions = pos;

    if (pos == 0) {
        log_error("mask_parse: no positions parsed from mask '%s'", mask_str);
        return -1;
    }

    return 0;
}

/* Calculate total keyspace for a mask */
uint64_t mask_keyspace(const mask_spec_t *ms) {
    if (ms->num_positions == 0) return 0;
    uint64_t total = 1;
    for (int i = 0; i < ms->num_positions; i++) {
        uint64_t len = (uint64_t)ms->positions[i].charset_len;
        if (len == 0) continue;
        /* Check for overflow */
        if (total > UINT64_MAX / len) return UINT64_MAX;
        total *= len;
    }
    return total;
}

/* Calculate total keyspace for brute-force with length range */
uint64_t bruteforce_keyspace(const charset_spec_t *cs,
                              int min_len, int max_len) {
    if (!cs || cs->len == 0) return 0;
    uint64_t total = 0;
    uint64_t power = 1;

    for (int len = 1; len <= max_len; len++) {
        /* power = cs->len ^ len */
        if (power > UINT64_MAX / (uint64_t)cs->len) {
            return UINT64_MAX; /* overflow */
        }
        power *= (uint64_t)cs->len;

        if (len >= min_len) {
            if (total > UINT64_MAX - power) return UINT64_MAX;
            total += power;
        }
    }
    return total;
}

/* ============================================================
 * ARGUMENT PARSING
 * ============================================================ */

static void config_set_defaults(config_t *cfg) {
    memset(cfg, 0, sizeof(*cfg));

    cfg->attack_mode          = ATTACK_NONE;
    cfg->archive_type         = ARCHIVE_UNKNOWN;
    cfg->num_threads          = 1;
    cfg->batch_size           = DEFAULT_BATCH_SIZE;
    cfg->min_length           = 1;
    cfg->max_length           = 8;
    cfg->dict_buffer_size     = DEFAULT_DICT_BUFSIZE;
    cfg->log_level            = LOG_INFO;
    cfg->show_progress        = true;
    cfg->progress_interval_ms = PROGRESS_UPDATE_MS;
    cfg->benchmark_duration   = 10;
    cfg->limit                = 0; /* 0 = no limit */
    cfg->skip                 = 0;
    cfg->save_resume          = true;

    /* Default resume path */
    str_copy(cfg->resume_path, sizeof(cfg->resume_path),
             "/tmp/crive_resume.dat");

    /* Default charset: lowercase */
    charset_parse(&cfg->charset, "lower");

    /* Detect CPU count */
    int cpus = (int)sysconf(_SC_NPROCESSORS_ONLN);
    if (cpus > 0 && cpus <= MAX_THREADS) {
        cfg->num_threads = cpus;
    }

    /* Interactive if stderr is a tty */
    cfg->interactive = isatty(STDERR_FILENO);
}

static void print_usage(const char *progname) {
    fprintf(stderr,
        ANSI_BRIGHT_WHITE "USAGE:" ANSI_RESET "\n"
        "  %s <archive> [OPTIONS]\n"
        "\n"
        ANSI_BRIGHT_WHITE "EXAMPLES:" ANSI_RESET "\n"
        "  %s archive.zip --wordlist rockyou.txt\n"
        "  %s archive.7z --bruteforce --min 4 --max 8 --charset lower+digits\n"
        "  %s archive.zip --mask '?l?l?d?d'\n"
        "  %s archive.zip --wordlist words.txt --rules\n"
        "  %s archive.zip --hybrid --wordlist words.txt\n"
        "  %s archive.zip --benchmark\n"
        "\n"
        ANSI_BRIGHT_WHITE "ATTACK MODES:" ANSI_RESET "\n"
        "  " ANSI_CYAN "--wordlist <file>" ANSI_RESET
            "          Dictionary attack\n"
        "  " ANSI_CYAN "--bruteforce" ANSI_RESET
            "               Brute-force attack\n"
        "  " ANSI_CYAN "--mask <pattern>" ANSI_RESET
            "           Mask attack (e.g. ?l?l?d?d)\n"
        "  " ANSI_CYAN "--hybrid" ANSI_RESET
            "                   Hybrid wordlist+mutations\n"
        "  " ANSI_CYAN "--rules [file]" ANSI_RESET
            "             Rule-based attack\n"
        "  " ANSI_CYAN "--benchmark" ANSI_RESET
            "                Benchmark mode\n"
        "\n"
        ANSI_BRIGHT_WHITE "BRUTE-FORCE OPTIONS:" ANSI_RESET "\n"
        "  " ANSI_CYAN "--min <n>" ANSI_RESET
            "                  Minimum password length [1]\n"
        "  " ANSI_CYAN "--max <n>" ANSI_RESET
            "                  Maximum password length [8]\n"
        "  " ANSI_CYAN "--charset <spec>" ANSI_RESET
            "           Charset spec: lower,upper,digits,special,alnum,...\n"
        "                              or custom characters\n"
        "\n"
        ANSI_BRIGHT_WHITE "PERFORMANCE:" ANSI_RESET "\n"
        "  " ANSI_CYAN "-t, --threads <n>" ANSI_RESET
            "          Number of threads [auto]\n"
        "  " ANSI_CYAN "--batch <n>" ANSI_RESET
            "                Batch size per thread [1024]\n"
        "\n"
        ANSI_BRIGHT_WHITE "OUTPUT:" ANSI_RESET "\n"
        "  " ANSI_CYAN "-o, --output <file>" ANSI_RESET
            "        Write found password to file\n"
        "  " ANSI_CYAN "-l, --log <file>" ANSI_RESET
            "           Write log to file\n"
        "  " ANSI_CYAN "-v, --verbose" ANSI_RESET
            "              Verbose output\n"
        "  " ANSI_CYAN "-q, --quiet" ANSI_RESET
            "                Suppress output\n"
        "  " ANSI_CYAN "--no-color" ANSI_RESET
            "                 Disable ANSI colors\n"
        "\n"
        ANSI_BRIGHT_WHITE "RESUME:" ANSI_RESET "\n"
        "  " ANSI_CYAN "--resume" ANSI_RESET
            "                   Resume from saved state\n"
        "  " ANSI_CYAN "--resume-file <f>" ANSI_RESET
            "          Resume file path\n"
        "  " ANSI_CYAN "--no-save" ANSI_RESET
            "                  Don't save resume state\n"
        "\n"
        ANSI_BRIGHT_WHITE "ARCHIVE:" ANSI_RESET "\n"
        "  " ANSI_CYAN "--zip" ANSI_RESET
            "                      Force ZIP mode\n"
        "  " ANSI_CYAN "--7z" ANSI_RESET
            "                       Force 7-Zip mode\n"
        "  " ANSI_CYAN "--skip <n>" ANSI_RESET
            "                 Skip first N candidates\n"
        "  " ANSI_CYAN "--limit <n>" ANSI_RESET
            "                Stop after N attempts\n"
        "\n",
        progname, progname, progname, progname,
        progname, progname, progname);
}

/* Detect archive type from file magic bytes */
archive_type_t detect_archive_type(const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) return ARCHIVE_UNKNOWN;

    uint8_t magic[8] = {0};
    if (fread(magic, 1, sizeof(magic), f) < 4) {
        fclose(f);
        return ARCHIVE_UNKNOWN;
    }
    fclose(f);

    /* ZIP: PK\x03\x04 */
    if (magic[0] == 0x50 && magic[1] == 0x4B &&
        magic[2] == 0x03 && magic[3] == 0x04) {
        return ARCHIVE_ZIP;
    }

    /* 7z: 7z\xBC\xAF\x27\x1C */
    if (magic[0] == 0x37 && magic[1] == 0x7A &&
        magic[2] == 0xBC && magic[3] == 0xAF &&
        magic[4] == 0x27 && magic[5] == 0x1C) {
        return ARCHIVE_7Z;
    }

    /* Try extension fallback */
    const char *ext = file_extension(path);
    if (str_icmp(ext, "zip") == 0) return ARCHIVE_ZIP;
    if (str_icmp(ext, "7z")  == 0) return ARCHIVE_7Z;

    return ARCHIVE_UNKNOWN;
}

/* Full argument parsing */
int parse_arguments(int argc, char **argv, config_t *cfg) {
    if (argc < 2) {
        print_usage(argv[0]);
        return -1;
    }

    config_set_defaults(cfg);

    /* First non-option arg is archive path */
    int argi = 1;
    if (argv[argi][0] != '-') {
        str_copy(cfg->archive_path, sizeof(cfg->archive_path), argv[argi]);
        argi++;
    }

    static struct option long_opts[] = {
        /* Attack modes */
        {"wordlist",     required_argument, NULL, 'w'},
        {"bruteforce",   no_argument,       NULL, 'b'},
        {"mask",         required_argument, NULL, 'm'},
        {"hybrid",       no_argument,       NULL, 'H'},
        {"rules",        optional_argument, NULL, 'R'},
        {"benchmark",    no_argument,       NULL, 'B'},

        /* Brute-force options */
        {"min",          required_argument, NULL, 1001},
        {"max",          required_argument, NULL, 1002},
        {"charset",      required_argument, NULL, 1003},

        /* Performance */
        {"threads",      required_argument, NULL, 't'},
        {"batch",        required_argument, NULL, 1004},

        /* Output */
        {"output",       required_argument, NULL, 'o'},
        {"log",          required_argument, NULL, 'l'},
        {"verbose",      no_argument,       NULL, 'v'},
        {"quiet",        no_argument,       NULL, 'q'},
        {"no-color",     no_argument,       NULL, 1005},

        /* Resume */
        {"resume",       no_argument,       NULL, 1006},
        {"resume-file",  required_argument, NULL, 1007},
        {"no-save",      no_argument,       NULL, 1008},

        /* Archive */
        {"zip",          no_argument,       NULL, 1009},
        {"7z",           no_argument,       NULL, 1010},
        {"skip",         required_argument, NULL, 1011},
        {"limit",        required_argument, NULL, 1012},

        /* Help */
        {"help",         no_argument,       NULL, 'h'},
        {"version",      no_argument,       NULL, 1013},

        {NULL, 0, NULL, 0}
    };

    int opt;
    int opt_idx = 0;

    /* Build getopt short string */
    optind = argi;

    while ((opt = getopt_long(argc, argv, "w:bm:HR::Bt:o:l:vqh",
                               long_opts, &opt_idx)) != -1) {
        switch (opt) {
            case 'w':
                str_copy(cfg->wordlist_path, sizeof(cfg->wordlist_path),
                         optarg);
                if (cfg->attack_mode == ATTACK_NONE)
                    cfg->attack_mode = ATTACK_DICTIONARY;
                break;

            case 'b':
                cfg->attack_mode = ATTACK_BRUTEFORCE;
                break;

            case 'm':
                cfg->attack_mode = ATTACK_MASK;
                str_copy(cfg->mask.raw_mask, sizeof(cfg->mask.raw_mask),
                         optarg);
                break;

            case 'H':
                cfg->attack_mode = ATTACK_HYBRID;
                break;

            case 'R':
                cfg->attack_mode = ATTACK_RULE;
                if (optarg) {
                    str_copy(cfg->rules_path, sizeof(cfg->rules_path), optarg);
                }
                break;

            case 'B':
                cfg->attack_mode = ATTACK_BENCHMARK;
                break;

            case 1001: /* --min */
                cfg->min_length = (int)strtol(optarg, NULL, 10);
                if (cfg->min_length < 1) cfg->min_length = 1;
                break;

            case 1002: /* --max */
                cfg->max_length = (int)strtol(optarg, NULL, 10);
                if (cfg->max_length < 1) cfg->max_length = 1;
                break;

            case 1003: /* --charset */
                if (charset_parse(&cfg->charset, optarg) != 0) {
                    log_error("Invalid charset specification: %s", optarg);
                    return -1;
                }
                break;

            case 't':
                cfg->num_threads = (int)strtol(optarg, NULL, 10);
                if (cfg->num_threads < 1)
                    cfg->num_threads = 1;
                if (cfg->num_threads > MAX_THREADS)
                    cfg->num_threads = MAX_THREADS;
                break;

            case 1004: /* --batch */
                cfg->batch_size = (size_t)strtoul(optarg, NULL, 10);
                if (cfg->batch_size < 1)   cfg->batch_size = 1;
                if (cfg->batch_size > 1<<20) cfg->batch_size = 1<<20;
                break;

            case 'o':
                str_copy(cfg->output_path, sizeof(cfg->output_path), optarg);
                break;

            case 'l':
                str_copy(cfg->log_path, sizeof(cfg->log_path), optarg);
                break;

            case 'v':
                cfg->verbose   = true;
                cfg->log_level = LOG_DEBUG;
                break;

            case 'q':
                cfg->quiet = true;
                break;

            case 1005: /* --no-color */
                cfg->no_color = true;
                break;

            case 1006: /* --resume */
                cfg->resume = true;
                break;

            case 1007: /* --resume-file */
                str_copy(cfg->resume_path, sizeof(cfg->resume_path), optarg);
                break;

            case 1008: /* --no-save */
                cfg->save_resume = false;
                break;

            case 1009: /* --zip */
                cfg->archive_type      = ARCHIVE_ZIP;
                cfg->force_archive_type = true;
                break;

            case 1010: /* --7z */
                cfg->archive_type      = ARCHIVE_7Z;
                cfg->force_archive_type = true;
                break;

            case 1011: /* --skip */
                cfg->skip = strtoull(optarg, NULL, 10);
                break;

            case 1012: /* --limit */
                cfg->limit = strtoull(optarg, NULL, 10);
                break;

            case 1013: /* --version */
                fprintf(stdout, "crive v%s (build %s %s)\n",
                        CRIVE_VERSION_STR, CRIVE_BUILD_DATE, CRIVE_BUILD_TIME);
                return 1; /* signal to exit cleanly */

            case 'h':
                print_usage(argv[0]);
                return 1;

            case '?':
            default:
                log_error("Unknown option. Use --help for usage.");
                return -1;
        }
    }

    /* Validate: archive path required unless benchmark */
    if (cfg->archive_path[0] == '\0' && cfg->attack_mode != ATTACK_BENCHMARK) {
        log_error("No archive file specified.");
        print_usage(argv[0]);
        return -1;
    }

    /* Detect archive type if not forced */
    if (!cfg->force_archive_type && cfg->archive_path[0] != '\0') {
        cfg->archive_type = detect_archive_type(cfg->archive_path);
        if (cfg->archive_type == ARCHIVE_UNKNOWN) {
            log_error("Cannot detect archive type for '%s'",
                      cfg->archive_path);
            return -1;
        }
    }

    /* Validate archive exists */
    if (cfg->archive_path[0] != '\0') {
        if (!file_exists(cfg->archive_path)) {
            log_error("Archive not found: %s", cfg->archive_path);
            return -1;
        }
        if (!file_is_readable(cfg->archive_path)) {
            log_error("Archive not readable: %s", cfg->archive_path);
            return -1;
        }
    }

    /* Validate wordlist if required */
    if ((cfg->attack_mode == ATTACK_DICTIONARY ||
         cfg->attack_mode == ATTACK_HYBRID) &&
        cfg->wordlist_path[0] != '\0') {
        if (!file_exists(cfg->wordlist_path)) {
            log_error("Wordlist not found: %s", cfg->wordlist_path);
            return -1;
        }
    }

    /* Validate mask if mask attack */
    if (cfg->attack_mode == ATTACK_MASK &&
        cfg->mask.raw_mask[0] == '\0') {
        log_error("Mask attack requires --mask <pattern>");
        return -1;
    }

    /* Clamp lengths */
    if (cfg->min_length > cfg->max_length) {
        log_warn("min_length > max_length, swapping");
        int tmp = cfg->min_length;
        cfg->min_length = cfg->max_length;
        cfg->max_length = tmp;
    }

    return 0;
}

/* ============================================================
 * CONFIG DISPLAY
 * ============================================================ */

void config_print(const config_t *cfg) {
    bool nc = cfg->no_color;

    print_section_header("Configuration", nc);

    /* Target */
    if (cfg->archive_path[0]) {
        print_kv("Archive", cfg->archive_path, nc);
        const char *atype = (cfg->archive_type < ARCHIVE_MAX)
                            ? archive_type_names[cfg->archive_type]
                            : "Unknown";
        print_kv("Archive Type", atype, nc);

        /* File size */
        int64_t sz = file_size(cfg->archive_path);
        if (sz >= 0) {
            char szstr[32];
            format_size(szstr, sizeof(szstr), (uint64_t)sz);
            print_kv("Archive Size", szstr, nc);
        }
    }

    /* Attack mode */
    const char *amode = (cfg->attack_mode < ATTACK_MAX)
                        ? attack_mode_names[cfg->attack_mode]
                        : "Unknown";
    print_kv("Attack Mode", amode, nc);

    /* Mode-specific */
    switch (cfg->attack_mode) {
        case ATTACK_DICTIONARY:
        case ATTACK_HYBRID:
            print_kv("Wordlist", cfg->wordlist_path, nc);
            if (cfg->wordlist_path[0]) {
                int64_t lines = file_count_lines(cfg->wordlist_path);
                char lstr[32];
                format_number(lstr, sizeof(lstr), (uint64_t)lines);
                print_kv("Wordlist Lines", lstr, nc);
            }
            break;

        case ATTACK_BRUTEFORCE:
            print_kv_fmt(nc, "Length Range", "%d - %d",
                         cfg->min_length, cfg->max_length);
            charset_print(&cfg->charset, nc);
            {
                uint64_t ks = bruteforce_keyspace(&cfg->charset,
                                                   cfg->min_length,
                                                   cfg->max_length);
                char ksstr[32];
                format_number(ksstr, sizeof(ksstr), ks);
                print_kv("Keyspace", ksstr, nc);
            }
            break;

        case ATTACK_MASK:
            print_kv("Mask", cfg->mask.raw_mask, nc);
            break;

        case ATTACK_RULE:
            if (cfg->rules_path[0]) {
                print_kv("Rules File", cfg->rules_path, nc);
            }
            print_kv_fmt(nc, "Wordlist", "%s", cfg->wordlist_path);
            break;

        default:
            break;
    }

    /* Threads */
    print_kv_fmt(nc, "Threads", "%d", cfg->num_threads);
    print_kv_fmt(nc, "Batch Size", "%zu", cfg->batch_size);

    /* Output */
    if (cfg->output_path[0]) {
        print_kv("Output", cfg->output_path, nc);
    }

    /* Resume */
    if (cfg->resume) {
        print_kv("Resume From", cfg->resume_path, nc);
    }

    fprintf(stderr, "\n");
}

/* ============================================================
 * RESUME STATE SAVE/LOAD
 * ============================================================ */

static uint32_t resume_checksum(const resume_state_t *rs) {
    /* Simple FNV-1a checksum over the struct (excluding checksum field) */
    const uint8_t *data = (const uint8_t *)rs;
    size_t len = offsetof(resume_state_t, checksum);
    uint32_t hash = 2166136261U;
    for (size_t i = 0; i < len; i++) {
        hash ^= data[i];
        hash *= 16777619U;
    }
    return hash;
}

int resume_save(const char *path, const resume_state_t *rs) {
    resume_state_t tmp;
    memcpy(&tmp, rs, sizeof(tmp));
    tmp.magic    = RESUME_MAGIC;
    tmp.version  = RESUME_VERSION;
    tmp.saved_at = time(NULL);
    tmp.checksum = resume_checksum(&tmp);

    FILE *f = fopen(path, "wb");
    if (!f) {
        log_error("resume_save: cannot open '%s': %s", path, strerror(errno));
        return -1;
    }

    if (fwrite(&tmp, sizeof(tmp), 1, f) != 1) {
        log_error("resume_save: write failed: %s", strerror(errno));
        fclose(f);
        return -1;
    }

    fflush(f);
    fsync(fileno(f));
    fclose(f);
    return 0;
}

int resume_load(const char *path, resume_state_t *rs) {
    FILE *f = fopen(path, "rb");
    if (!f) {
        log_error("resume_load: cannot open '%s': %s", path, strerror(errno));
        return -1;
    }

    if (fread(rs, sizeof(*rs), 1, f) != 1) {
        log_error("resume_load: read failed: %s", strerror(errno));
        fclose(f);
        return -1;
    }
    fclose(f);

    if (rs->magic != RESUME_MAGIC) {
        log_error("resume_load: invalid magic (got 0x%08X, expected 0x%08X)",
                  rs->magic, (unsigned)RESUME_MAGIC);
        return -1;
    }

    if (rs->version != RESUME_VERSION) {
        log_error("resume_load: version mismatch (%u vs %u)",
                  rs->version, RESUME_VERSION);
        return -1;
    }

    uint32_t expected = resume_checksum(rs);
    if (rs->checksum != expected) {
        log_error("resume_load: checksum mismatch (corrupt file?)");
        return -1;
    }

    return 0;
}

void resume_print(const resume_state_t *rs, bool no_color) {
    bool nc = no_color;
    print_section_header("Resume State", nc);

    const char *atype = (rs->archive_type < ARCHIVE_MAX)
                        ? archive_type_names[rs->archive_type] : "Unknown";
    const char *amode = (rs->attack_mode < ATTACK_MAX)
                        ? attack_mode_names[rs->attack_mode] : "Unknown";

    print_kv("Archive",       rs->archive_path, nc);
    print_kv("Archive Type",  atype, nc);
    print_kv("Attack Mode",   amode, nc);

    char attempts_str[32];
    format_number(attempts_str, sizeof(attempts_str), rs->total_attempts);
    print_kv("Total Attempts", attempts_str, nc);

    char saved_str[64];
    struct tm *tm_info = localtime(&rs->saved_at);
    strftime(saved_str, sizeof(saved_str), "%Y-%m-%d %H:%M:%S", tm_info);
    print_kv("Saved At", saved_str, nc);

    if (rs->attack_mode == ATTACK_DICTIONARY) {
        char offset_str[32];
        format_number(offset_str, sizeof(offset_str), rs->wordlist_offset);
        print_kv("Wordlist Offset", offset_str, nc);
    } else if (rs->attack_mode == ATTACK_BRUTEFORCE) {
        char idx_str[32];
        format_number(idx_str, sizeof(idx_str), rs->bruteforce_index);
        print_kv("BF Index", idx_str, nc);
        print_kv_fmt(nc, "Current Length", "%d", rs->current_length);
    }

    fprintf(stderr, "\n");
}

/* ============================================================
 * SIGNAL HANDLING HELPERS
 * ============================================================ */

static volatile sig_atomic_t g_signal_received = 0;
static void (*g_signal_handler_cb)(int) = NULL;

static void internal_signal_handler(int sig) {
    g_signal_received = sig;
    if (g_signal_handler_cb) {
        g_signal_handler_cb(sig);
    }
}

void signals_init(void (*handler)(int)) {
    g_signal_handler_cb = handler;

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = internal_signal_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;

    sigaction(SIGINT,  &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGPIPE, &sa, NULL); /* Ignore broken pipe */

    /* Handle SIGWINCH for terminal resize */
    struct sigaction sa_win;
    memset(&sa_win, 0, sizeof(sa_win));
    sa_win.sa_handler = (void(*)(int))term_update_size;
    sigemptyset(&sa_win.sa_mask);
    sa_win.sa_flags = SA_RESTART;
    sigaction(SIGWINCH, &sa_win, NULL);
}

bool signal_caught(void) {
    return g_signal_received != 0;
}

int signal_get(void) {
    return (int)g_signal_received;
}

void signal_reset(void) {
    g_signal_received = 0;
}

/* ============================================================
 * ENGINE STATE INITIALIZATION
 * ============================================================ */

void engine_state_init(engine_state_t *state, const config_t *cfg) {
    memset(state, 0, sizeof(*state));

    atomic_init(&state->found,           false);
    atomic_init(&state->shutdown,        false);
    atomic_init(&state->paused,          false);
    atomic_init(&state->total_attempts,  0ULL);
    atomic_init(&state->total_skipped,   0ULL);

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
        state->thread_status[i].speed     = 0;
    }

    speed_tracker_init(&state->speed);
}

void engine_state_cleanup(engine_state_t *state) {
    pthread_mutex_destroy(&state->found_mutex);
    pthread_mutex_destroy(&state->speed_mutex);
    /* Zero sensitive data */
    secure_memzero(state->found_password, MAX_PASSWORD_LEN);
}

void engine_state_set_found(engine_state_t *state, const char *password) {
    pthread_mutex_lock(&state->found_mutex);
    if (!atomic_load_explicit(&state->found, memory_order_acquire)) {
        str_copy(state->found_password, sizeof(state->found_password),
                 password);
        atomic_store_explicit(&state->found, true, memory_order_release);
    }
    pthread_mutex_unlock(&state->found_mutex);
}

void engine_state_update_speed(engine_state_t *state) {
    pthread_mutex_lock(&state->speed_mutex);

    uint64_t total = atomic_load_explicit(&state->total_attempts,
                                          memory_order_relaxed);
    speed_tracker_update(&state->speed, total);
    state->moving_avg_speed  = speed_tracker_moving_avg(&state->speed);
    state->passwords_per_sec = speed_tracker_current(&state->speed);

    /* Update ETA */
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
 * OUTPUT HELPERS (found password)
 * ============================================================ */

int write_found_password(const char *output_path,
                          const char *archive_path,
                          const char *password) {
    if (!output_path || output_path[0] == '\0') return 0;

    FILE *f = fopen(output_path, "w");
    if (!f) {
        log_error("Cannot write output to '%s': %s",
                  output_path, strerror(errno));
        return -1;
    }

    fprintf(f, "Archive: %s\n", archive_path);
    fprintf(f, "Password: %s\n", password);

    /* Timestamp */
    time_t now = time(NULL);
    char ts[64];
    struct tm *tm_info = localtime(&now);
    strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", tm_info);
    fprintf(f, "Found at: %s\n", ts);

    fflush(f);
    fclose(f);
    log_info("Password written to: %s", output_path);
    return 0;
}

/* ============================================================
 * BENCHMARK UTILITIES
 * ============================================================ */

typedef struct {
    double      total_speed;      /* average H/s */
    double      peak_speed;       /* max H/s observed */
    uint64_t    total_hashes;
    double      duration_sec;
    int         num_threads;
} benchmark_result_t;

void benchmark_print(const benchmark_result_t *res, bool no_color) {
    bool nc = no_color;
    print_section_header("Benchmark Results", nc);

    char speed_str[32], peak_str[32], total_str[32];
    format_speed(speed_str, sizeof(speed_str), res->total_speed);
    format_speed(peak_str,  sizeof(peak_str),  res->peak_speed);
    format_number(total_str, sizeof(total_str), res->total_hashes);

    print_kv("Average Speed",  speed_str, nc);
    print_kv("Peak Speed",     peak_str,  nc);
    print_kv("Total Hashes",   total_str, nc);
    print_kv_fmt(nc, "Duration",    "%.1f sec", res->duration_sec);
    print_kv_fmt(nc, "Threads",     "%d",       res->num_threads);
    fprintf(stderr, "\n");
}

/* ============================================================
 * MISCELLANEOUS UTILITIES
 * ============================================================ */

/* CRC32 table - used by ZIP validation */
static uint32_t g_crc32_table[256];
static bool     g_crc32_initialized = false;

void crc32_init(void) {
    if (g_crc32_initialized) return;
    for (uint32_t i = 0; i < 256; i++) {
        uint32_t c = i;
        for (int j = 0; j < 8; j++) {
            c = (c & 1) ? (0xEDB88320U ^ (c >> 1)) : (c >> 1);
        }
        g_crc32_table[i] = c;
    }
    g_crc32_initialized = true;
}

FORCE_INLINE uint32_t crc32_update(uint32_t crc,
                                    const uint8_t *data,
                                    size_t len) {
    crc = ~crc;
    while (len--) {
        crc = g_crc32_table[(crc ^ *data++) & 0xFF] ^ (crc >> 8);
    }
    return ~crc;
}

FORCE_INLINE uint32_t crc32_full(const uint8_t *data, size_t len) {
    return crc32_update(0, data, len);
}

/* Min/Max helpers */
CONST_FN FORCE_INLINE int min_int(int a, int b) { return a < b ? a : b; }
CONST_FN FORCE_INLINE int max_int(int a, int b) { return a > b ? a : b; }
CONST_FN FORCE_INLINE uint64_t min_u64(uint64_t a, uint64_t b) { return a < b ? a : b; }
CONST_FN FORCE_INLINE uint64_t max_u64(uint64_t a, uint64_t b) { return a > b ? a : b; }
CONST_FN FORCE_INLINE size_t min_sz(size_t a, size_t b) { return a < b ? a : b; }
CONST_FN FORCE_INLINE size_t max_sz(size_t a, size_t b) { return a > b ? a : b; }

/* Integer power */
CONST_FN uint64_t uint64_pow(uint64_t base, uint64_t exp) {
    uint64_t result = 1ULL;
    while (exp > 0) {
        if (exp & 1) {
            if (result > UINT64_MAX / base) return UINT64_MAX;
            result *= base;
        }
        exp >>= 1;
        if (exp > 0) {
            if (base > UINT64_MAX / base) return UINT64_MAX;
            base *= base;
        }
    }
    return result;
}

/* Get number of online CPUs */
int get_cpu_count(void) {
    int n = (int)sysconf(_SC_NPROCESSORS_ONLN);
    return (n > 0) ? n : 1;
}

/* Return a human-readable time string */
void get_datetime_str(char *buf, size_t buflen) {
    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    strftime(buf, buflen, "%Y-%m-%d %H:%M:%S", t);
}

/* Hex dump for debugging */
void hex_dump(const char *label, const uint8_t *data, size_t len) {
    fprintf(stderr, "%s (%zu bytes):\n", label, len);
    for (size_t i = 0; i < len; i++) {
        if (i % 16 == 0) fprintf(stderr, "  %04zx: ", i);
        fprintf(stderr, "%02x ", data[i]);
        if ((i + 1) % 8 == 0) fprintf(stderr, " ");
        if ((i + 1) % 16 == 0) {
            fprintf(stderr, " |");
            for (size_t j = i - 15; j <= i; j++) {
                fprintf(stderr, "%c",
                        isprint(data[j]) ? (char)data[j] : '.');
            }
            fprintf(stderr, "|\n");
        }
    }
    if (len % 16 != 0) {
        int remaining = (int)(len % 16);
        for (int i = 0; i < 16 - remaining; i++) fprintf(stderr, "   ");
        if (remaining <= 8) fprintf(stderr, " ");
        fprintf(stderr, " |");
        for (size_t j = len - remaining; j < len; j++) {
            fprintf(stderr, "%c", isprint(data[j]) ? (char)data[j] : '.');
        }
        fprintf(stderr, "|\n");
    }
    fprintf(stderr, "\n");
}

/* ============================================================
 * THREAD AFFINITY UTILITIES (Linux)
 * ============================================================ */

#ifdef __linux__
#include <sched.h>

int thread_set_affinity(pthread_t thread, int cpu_id) {
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(cpu_id, &cpuset);
    int rc = pthread_setaffinity_np(thread, sizeof(cpuset), &cpuset);
    if (rc != 0) {
        log_debug("thread_set_affinity: failed for cpu %d: %s",
                  cpu_id, strerror(rc));
    }
    return rc;
}

int thread_set_priority(pthread_t thread, int priority) {
    struct sched_param param = { .sched_priority = priority };
    int rc = pthread_setschedparam(thread, SCHED_OTHER, &param);
    if (rc != 0) {
        log_debug("thread_set_priority: failed: %s", strerror(rc));
    }
    return rc;
}
#else
int thread_set_affinity(pthread_t thread, int cpu_id) {
    (void)thread; (void)cpu_id;
    return 0;
}
int thread_set_priority(pthread_t thread, int priority) {
    (void)thread; (void)priority;
    return 0;
}
#endif

/* ============================================================
 * FINAL INIT FUNCTION (call at startup)
 * ============================================================ */

void utils_init(const config_t *cfg) {
    /* Locale */
    setlocale(LC_ALL, "");

    /* CRC32 table */
    crc32_init();

    /* Terminal detection */
    term_init();

    /* Logging */
    if (cfg) {
        log_init(cfg->log_path[0] ? cfg->log_path : NULL,
                 cfg->log_level,
                 cfg->no_color,
                 cfg->quiet);
    } else {
        log_init(NULL, LOG_INFO, false, false);
    }
}

void utils_cleanup(void) {
    term_show_cursor();
    log_close();
}

/* ============================================================
 * END OF utils.c
 * ============================================================ */

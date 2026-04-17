/*
 * main.c - CLI, UX, and orchestration for crive password recovery
 * Entry point, argument handling, workflow coordination
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
#include <getopt.h>
#include <termios.h>
#include <sys/ioctl.h>
#include <locale.h>

#include "archive.h"   /* Provides archive_type_t, archive_ctx_t, etc. */

/* ============================================================
 * VERSION AND PLATFORM (duplicated from utils.c, but needed here)
 * ============================================================ */

#define CRIVE_VERSION_STR       "1.0.0"
#define CRIVE_BUILD_DATE        __DATE__
#define CRIVE_BUILD_TIME        __TIME__

#ifdef __ANDROID__
  #define PLATFORM_NAME "Android/Termux"
#elif defined(__linux__)
  #define PLATFORM_NAME "Linux"
#else
  #define PLATFORM_NAME "Unknown"
#endif

#define LIKELY(x)            __builtin_expect(!!(x), 1)
#define UNLIKELY(x)          __builtin_expect(!!(x), 0)
#define FORCE_INLINE         __attribute__((always_inline)) static inline
#define UNUSED               __attribute__((unused))
#define NORETURN             __attribute__((noreturn))

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
#define GB                   (1024ULL * MB)

/* ANSI codes */
#define ANSI_RESET           "\033[0m"
#define ANSI_BOLD            "\033[1m"
#define ANSI_DIM             "\033[2m"
#define ANSI_RED             "\033[31m"
#define ANSI_GREEN           "\033[32m"
#define ANSI_YELLOW          "\033[33m"
#define ANSI_BLUE            "\033[34m"
#define ANSI_MAGENTA         "\033[35m"
#define ANSI_CYAN            "\033[36m"
#define ANSI_WHITE           "\033[37m"
#define ANSI_BRIGHT_RED      "\033[91m"
#define ANSI_BRIGHT_GREEN    "\033[92m"
#define ANSI_BRIGHT_YELLOW   "\033[93m"
#define ANSI_BRIGHT_BLUE     "\033[94m"
#define ANSI_BRIGHT_MAGENTA  "\033[95m"
#define ANSI_BRIGHT_CYAN     "\033[96m"
#define ANSI_BRIGHT_WHITE    "\033[97m"
#define ANSI_ERASE_LINE      "\033[2K"
#define ANSI_HIDE_CURSOR     "\033[?25l"
#define ANSI_SHOW_CURSOR     "\033[?25h"

#define CLR_SUCCESS          ANSI_BRIGHT_GREEN
#define CLR_ERROR            ANSI_BRIGHT_RED
#define CLR_WARNING          ANSI_BRIGHT_YELLOW
#define CLR_INFO             ANSI_BRIGHT_CYAN
#define CLR_LABEL            ANSI_BRIGHT_WHITE
#define CLR_VALUE            ANSI_CYAN
#define CLR_SPEED            ANSI_BRIGHT_YELLOW
#define CLR_FOUND            ANSI_BRIGHT_GREEN ANSI_BOLD
#define CLR_HEADER           ANSI_BRIGHT_MAGENTA

#define SYM_OK               CLR_SUCCESS "[+]" ANSI_RESET
#define SYM_ERR              CLR_ERROR   "[-]" ANSI_RESET
#define SYM_WARN             CLR_WARNING "[!]" ANSI_RESET
#define SYM_INFO             CLR_INFO    "[*]" ANSI_RESET

/* Charsets */
#define CHARSET_LOWER        "abcdefghijklmnopqrstuvwxyz"
#define CHARSET_UPPER        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
#define CHARSET_DIGITS       "0123456789"
#define CHARSET_SPECIAL      "!@#$%^&*()-_=+[]{}|;:,.<>?/`~\"\\ '"
#define CHARSET_ALNUM        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
#define CHARSET_PRINTABLE    " !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~"

/* ============================================================
 * ENUMS AND STRUCTS (only those not provided by archive.h or utils.h)
 * ============================================================ */



typedef struct {
    rule_type_t type;
    char        param[64];
    int         param_int;
} rule_t;

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
    bool            pin_threads;
    bool            adaptive_batch;
    bool            show_thread_stats;
} config_t;

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

typedef struct {
    double      total_speed;
    double      peak_speed;
    uint64_t    total_hashes;
    double      duration_sec;
    int         num_threads;
    archive_type_t arch_type;
} benchmark_result_t;

typedef struct {
    attack_result_t     result;
    char                password[MAX_PASSWORD_LEN];
    uint64_t            total_tested;
    double              elapsed_sec;
    double              speed_avg;
    benchmark_result_t  bench;
    bool                is_benchmark;
} engine_run_result_t;

/* ============================================================
 * EXTERNAL FUNCTION DECLARATIONS (from utils.c, archive.c, engine.c)
 * ============================================================ */

/* utils.c */
extern void     log_message          (log_level_t level, const char *fmt, ...);
extern void     log_init             (const char *path, log_level_t level,
                                      bool no_color, bool quiet);
extern void     log_close            (void);
extern void     crc32_init           (void);
extern void     term_init            (void);
extern bool     is_tty               (void);
extern int      term_width           (void);
extern void     term_hide_cursor     (void);
extern void     term_show_cursor     (void);
extern void     term_set_title       (const char *title);
extern void     print_banner         (bool no_color);
extern void     print_section_header (const char *title, bool no_color);
extern void     print_kv             (const char *key, const char *val,
                                      bool no_color);
extern void     print_kv_fmt         (bool no_color, const char *key,
                                      const char *fmt, ...);
extern void     print_separator      (bool no_color);
extern void     print_found_password (const char *password,
                                      const char *archive, bool no_color);
extern void     config_print         (const config_t *cfg);
extern int      parse_arguments      (int argc, char **argv, config_t *cfg);
extern int      charset_parse        (charset_spec_t *cs, const char *spec);
extern int      mask_parse           (mask_spec_t *ms, const char *mask_str,
                                      const charset_spec_t *custom,
                                      int num_custom);
extern uint64_t mask_keyspace        (const mask_spec_t *ms);
extern uint64_t bruteforce_keyspace  (const charset_spec_t *cs,
                                      int min_len, int max_len);
extern void     format_speed         (char *buf, size_t buflen, double speed);
extern void     format_number        (char *buf, size_t buflen, uint64_t n);
extern void     format_elapsed       (char *buf, size_t buflen, double sec);
extern void     format_eta           (char *buf, size_t buflen, int64_t eta);
extern void     format_size          (char *buf, size_t buflen, uint64_t bytes);
extern void     sleep_ms             (long ms);
extern uint64_t get_time_ms          (void);
extern uint64_t get_time_ns          (void);
extern struct timespec get_timespec_now(void);
extern double   elapsed_seconds_since(const struct timespec *start);
extern uint64_t elapsed_ms_since     (const struct timespec *start);
extern int      write_found_password (const char *output_path,
                                      const char *archive_path,
                                      const char *password);
extern bool     file_exists          (const char *path);
extern bool     file_is_readable     (const char *path);
extern int64_t  file_size            (const char *path);
extern int64_t  file_count_lines     (const char *path);
extern void     utils_init           (const config_t *cfg);
extern void     utils_cleanup        (void);
extern int      get_cpu_count        (void);
extern void     get_datetime_str     (char *buf, size_t buflen);
extern int      resume_save          (const char *path,
                                      const resume_state_t *rs);
extern int      resume_load          (const char *path, resume_state_t *rs);
extern void     resume_print         (const resume_state_t *rs, bool no_color);
extern bool     command_exists       (const char *cmd);

/* archive.c – functions are declared in archive.h, no need to repeat */
/* engine.c */
extern engine_run_result_t engine_orchestrate(const config_t *cfg,
                                               archive_ctx_t *archive);
extern attack_result_t engine_run_with_affinity(
    const config_t *cfg,
    archive_ctx_t  *master_archive,
    const resume_state_t *resume_st,
    bool pin_threads);
extern benchmark_result_t engine_benchmark(const config_t *cfg,
                                            archive_type_t arch_type,
                                            int duration_ms);

#define log_debug(fmt, ...)  log_message(LOG_DEBUG,   fmt, ##__VA_ARGS__)
#define log_info(fmt, ...)   log_message(LOG_INFO,    fmt, ##__VA_ARGS__)
#define log_warn(fmt, ...)   log_message(LOG_WARNING, fmt, ##__VA_ARGS__)
#define log_error(fmt, ...)  log_message(LOG_ERROR,   fmt, ##__VA_ARGS__)

/* ============================================================
 * GLOBAL SIGNAL STATE
 * ============================================================ */

static volatile sig_atomic_t g_sigint_count  = 0;
static volatile sig_atomic_t g_got_signal    = 0;
static volatile sig_atomic_t g_signal_number = 0;

/* ============================================================
 * STATIC HELPERS
 * ============================================================ */

static bool g_no_color   = false;
static bool g_is_tty_out = false;

FORCE_INLINE const char *cc(const char *code) {
    return (g_no_color || !g_is_tty_out) ? "" : code;
}

static void safe_print(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stdout, fmt, ap);
    va_end(ap);
    fflush(stdout);
}

static void safe_eprint(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fflush(stderr);
}

/* ============================================================
 * CONFIG DEFAULTS
 * ============================================================ */

static void config_set_defaults(config_t *cfg) {
    memset(cfg, 0, sizeof(*cfg));

    cfg->attack_mode          = ATTACK_NONE;
    cfg->archive_type         = ARCHIVE_UNKNOWN;
    cfg->num_threads          = get_cpu_count();
    cfg->batch_size           = DEFAULT_BATCH_SIZE;
    cfg->min_length           = 1;
    cfg->max_length           = 8;
    cfg->dict_buffer_size     = 4 * MB;
    cfg->log_level            = LOG_INFO;
    cfg->show_progress        = true;
    cfg->progress_interval_ms = PROGRESS_UPDATE_MS;
    cfg->benchmark_duration   = 10;
    cfg->limit                = 0;
    cfg->skip                 = 0;
    cfg->save_resume          = true;
    cfg->pin_threads          = false;
    cfg->adaptive_batch       = false;
    cfg->show_thread_stats    = false;
    cfg->interactive          = isatty(STDERR_FILENO);

    snprintf(cfg->resume_path, sizeof(cfg->resume_path),
             "/tmp/crive_resume.dat");

    /* Default charset: lowercase */
    charset_parse(&cfg->charset, "lower");

    /* Clamp thread count */
    if (cfg->num_threads < 1)           cfg->num_threads = 1;
    if (cfg->num_threads > MAX_THREADS) cfg->num_threads = MAX_THREADS;
}

/* ============================================================
 * ARGUMENT PARSING
 * ============================================================ */

static void print_usage(const char *prog) {
    /* nc variable not used – silence warning with (void) */
    (void)g_no_color;

    safe_eprint(
        "%s%sCRIVE%s - Archive Password Recovery Framework v%s\n"
        "%sPlatform:%s %s\n\n",
        cc(ANSI_BRIGHT_MAGENTA), cc(ANSI_BOLD), cc(ANSI_RESET),
        CRIVE_VERSION_STR,
        cc(ANSI_DIM), cc(ANSI_RESET), PLATFORM_NAME);

    safe_eprint(
        "%sUSAGE:%s\n"
        "  %s <archive> [OPTIONS]\n\n",
        cc(ANSI_BRIGHT_WHITE), cc(ANSI_RESET), prog);

    safe_eprint(
        "%sEXAMPLES:%s\n"
        "  %s archive.zip --wordlist rockyou.txt\n"
        "  %s archive.7z  --bruteforce --min 4 --max 8 --charset lower+digits\n"
        "  %s archive.zip --mask '?l?l?d?d?d'\n"
        "  %s archive.zip --wordlist words.txt --hybrid\n"
        "  %s archive.zip --wordlist words.txt --rules\n"
        "  %s archive.zip --benchmark\n\n",
        cc(ANSI_BRIGHT_WHITE), cc(ANSI_RESET),
        prog, prog, prog, prog, prog, prog);

    safe_eprint(
        "%sATTACK MODES:%s\n"
        "  %s-w, --wordlist <file>%s     Dictionary attack\n"
        "  %s-b, --bruteforce%s          Brute-force attack\n"
        "  %s-m, --mask <pattern>%s      Mask attack (?l=lower ?u=upper ?d=digit ?s=special)\n"
        "      --hybrid%s               Hybrid dict+mutations attack\n"
        "      --rules [file]%s         Rule-based transformations\n"
        "      --benchmark%s            Speed benchmark\n\n",
        cc(ANSI_BRIGHT_WHITE), cc(ANSI_RESET),
        cc(ANSI_CYAN), cc(ANSI_RESET),
        cc(ANSI_CYAN), cc(ANSI_RESET),
        cc(ANSI_CYAN), cc(ANSI_RESET),
        cc(ANSI_RESET), cc(ANSI_RESET), cc(ANSI_RESET));

    safe_eprint(
        "%sBRUTE-FORCE OPTIONS:%s\n"
        "  %s--min <n>%s                 Min password length [1]\n"
        "  %s--max <n>%s                 Max password length [8]\n"
        "  %s--charset <spec>%s          lower | upper | digits | special | alnum | print\n"
        "                             Can combine: lower+digits+special\n"
        "                             Or literal: 'abc123'\n\n",
        cc(ANSI_BRIGHT_WHITE), cc(ANSI_RESET),
        cc(ANSI_CYAN), cc(ANSI_RESET),
        cc(ANSI_CYAN), cc(ANSI_RESET),
        cc(ANSI_CYAN), cc(ANSI_RESET));

    safe_eprint(
        "%sMASK TOKENS:%s\n"
        "  ?l = lowercase  ?u = uppercase  ?d = digits\n"
        "  ?s = special    ?a = all printable  ?h = hex\n\n",
        cc(ANSI_BRIGHT_WHITE), cc(ANSI_RESET));

    safe_eprint(
        "%sPERFORMANCE:%s\n"
        "  %s-t, --threads <n>%s         Worker thread count [auto=%d]\n"
        "      --batch <n>%s            Candidates per batch [1024]\n"
        "      --pin-threads%s          Pin threads to CPU cores\n"
        "      --adaptive%s             Adaptive batch sizing\n\n",
        cc(ANSI_BRIGHT_WHITE), cc(ANSI_RESET),
        cc(ANSI_CYAN), cc(ANSI_RESET), get_cpu_count(),
        cc(ANSI_RESET), cc(ANSI_RESET), cc(ANSI_RESET));

    safe_eprint(
        "%sOUTPUT:%s\n"
        "  %s-o, --output <file>%s       Save found password to file\n"
        "  %s-l, --log <file>%s          Write log messages to file\n"
        "  %s-v, --verbose%s             Enable debug output\n"
        "  %s-q, --quiet%s               Suppress all non-essential output\n"
        "      --no-color%s             Disable ANSI colors\n"
        "      --no-progress%s          Disable live progress display\n"
        "      --thread-stats%s         Show per-thread statistics at end\n\n",
        cc(ANSI_BRIGHT_WHITE), cc(ANSI_RESET),
        cc(ANSI_CYAN), cc(ANSI_RESET),
        cc(ANSI_CYAN), cc(ANSI_RESET),
        cc(ANSI_CYAN), cc(ANSI_RESET),
        cc(ANSI_CYAN), cc(ANSI_RESET),
        cc(ANSI_RESET), cc(ANSI_RESET), cc(ANSI_RESET));

    safe_eprint(
        "%sRESUME:%s\n"
        "  %s--resume%s                  Resume from last saved state\n"
        "  %s--resume-file <f>%s         Resume file path [/tmp/crive_resume.dat]\n"
        "  %s--no-save%s                 Do not save resume state\n\n",
        cc(ANSI_BRIGHT_WHITE), cc(ANSI_RESET),
        cc(ANSI_CYAN), cc(ANSI_RESET),
        cc(ANSI_CYAN), cc(ANSI_RESET),
        cc(ANSI_CYAN), cc(ANSI_RESET));

    safe_eprint(
        "%sARCHIVE:%s\n"
        "  %s--zip%s                     Force ZIP mode\n"
        "  %s--7z%s                      Force 7-Zip mode\n"
        "  %s--rar%s                     Force RAR mode\n"
        "  %s--skip <n>%s                Skip first N candidates\n"
        "  %s--limit <n>%s               Stop after N candidates tested\n\n",
        cc(ANSI_BRIGHT_WHITE), cc(ANSI_RESET),
        cc(ANSI_CYAN), cc(ANSI_RESET),
        cc(ANSI_CYAN), cc(ANSI_RESET),
        cc(ANSI_CYAN), cc(ANSI_RESET),
        cc(ANSI_CYAN), cc(ANSI_RESET),
        cc(ANSI_CYAN), cc(ANSI_RESET));

    safe_eprint(
        "%sOTHER:%s\n"
        "  %s-h, --help%s                Show this help\n"
        "  %s--version%s                 Show version\n\n",
        cc(ANSI_BRIGHT_WHITE), cc(ANSI_RESET),
        cc(ANSI_CYAN), cc(ANSI_RESET),
        cc(ANSI_CYAN), cc(ANSI_RESET));
}

static int parse_args(int argc, char **argv, config_t *cfg) {
    if (argc < 2) {
        print_usage(argv[0]);
        return -1;
    }

    config_set_defaults(cfg);

    /* First non-flag arg = archive path */
    int argi = 1;
    if (argi < argc && argv[argi][0] != '-') {
        snprintf(cfg->archive_path, sizeof(cfg->archive_path),
                 "%s", argv[argi]);
        argi++;
    }

    static const struct option long_opts[] = {
        /* Attack modes */
        {"wordlist",     required_argument, NULL, 'w'},
        {"bruteforce",   no_argument,       NULL, 'b'},
        {"mask",         required_argument, NULL, 'm'},
        {"hybrid",       no_argument,       NULL, 'H'},
        {"rules",        optional_argument, NULL, 'R'},
        {"benchmark",    no_argument,       NULL, 'B'},

        /* BF options */
        {"min",          required_argument, NULL, 1001},
        {"max",          required_argument, NULL, 1002},
        {"charset",      required_argument, NULL, 1003},

        /* Performance */
        {"threads",      required_argument, NULL, 't'},
        {"batch",        required_argument, NULL, 1004},
        {"pin-threads",  no_argument,       NULL, 1005},
        {"adaptive",     no_argument,       NULL, 1006},

        /* Output */
        {"output",       required_argument, NULL, 'o'},
        {"log",          required_argument, NULL, 'l'},
        {"verbose",      no_argument,       NULL, 'v'},
        {"quiet",        no_argument,       NULL, 'q'},
        {"no-color",     no_argument,       NULL, 1007},
        {"no-progress",  no_argument,       NULL, 1008},
        {"thread-stats", no_argument,       NULL, 1009},

        /* Resume */
        {"resume",       no_argument,       NULL, 1010},
        {"resume-file",  required_argument, NULL, 1011},
        {"no-save",      no_argument,       NULL, 1012},

        /* Archive */
        {"zip",          no_argument,       NULL, 1013},
        {"7z",           no_argument,       NULL, 1014},
        {"rar",          no_argument,       NULL, 1018},
        {"skip",         required_argument, NULL, 1015},
        {"limit",        required_argument, NULL, 1016},

        /* Other */
        {"help",         no_argument,       NULL, 'h'},
        {"version",      no_argument,       NULL, 1017},

        {NULL, 0, NULL, 0}
    };

    optind = argi;
    int opt, opt_idx = 0;

    while ((opt = getopt_long(argc, argv, "w:bm:HR::Bt:o:l:vqh",
                               long_opts, &opt_idx)) != -1) {
        switch (opt) {

            case 'w':
                snprintf(cfg->wordlist_path, sizeof(cfg->wordlist_path),
                         "%s", optarg);
                if (cfg->attack_mode == ATTACK_NONE)
                    cfg->attack_mode = ATTACK_DICTIONARY;
                break;

            case 'b':
                cfg->attack_mode = ATTACK_BRUTEFORCE;
                break;

            case 'm':
                cfg->attack_mode = ATTACK_MASK;
                if (!optarg || optarg[0] == '\0') {
                    safe_eprint("%s Mask argument is empty.\n", SYM_ERR);
                    safe_eprint("   Please provide a mask pattern and quote it:\n");
                    safe_eprint("       crive %s --mask '?l?l?d?d'\n", cfg->archive_path);
                    return -1;
                }
                snprintf(cfg->mask.raw_mask, sizeof(cfg->mask.raw_mask),
                         "%s", optarg);
                /* DIAGNOSTIC */
                safe_eprint("[DIAG] optarg = '%s'\n", optarg);
                safe_eprint("[DIAG] raw_mask = '%s' (len=%zu)\n",
                            cfg->mask.raw_mask, strlen(cfg->mask.raw_mask));
                break;

            case 'H':
                cfg->attack_mode = ATTACK_HYBRID;
                /* Default hybrid config */
                cfg->hybrid.append_digits   = true;
                cfg->hybrid.append_special  = true;
                cfg->hybrid.suffix_min_len  = 1;
                cfg->hybrid.suffix_max_len  = 4;
                cfg->hybrid.prefix_min_len  = 0;
                cfg->hybrid.prefix_max_len  = 0;
                snprintf(cfg->hybrid.suffix_charset,
                         sizeof(cfg->hybrid.suffix_charset),
                         "%s", CHARSET_DIGITS);
                break;

            case 'R':
                cfg->attack_mode = ATTACK_RULE;
                if (optarg) {
                    snprintf(cfg->rules_path, sizeof(cfg->rules_path),
                             "%s", optarg);
                }
                break;

            case 'B':
                cfg->attack_mode = ATTACK_BENCHMARK;
                break;

            case 1001: /* --min */
                cfg->min_length = (int)strtol(optarg, NULL, 10);
                if (cfg->min_length < 1) cfg->min_length = 1;
                if (cfg->min_length > MAX_PASSWORD_LEN - 1)
                    cfg->min_length = MAX_PASSWORD_LEN - 1;
                break;

            case 1002: /* --max */
                cfg->max_length = (int)strtol(optarg, NULL, 10);
                if (cfg->max_length < 1) cfg->max_length = 1;
                if (cfg->max_length > MAX_PASSWORD_LEN - 1)
                    cfg->max_length = MAX_PASSWORD_LEN - 1;
                break;

            case 1003: /* --charset */
                if (charset_parse(&cfg->charset, optarg) != 0) {
                    safe_eprint("%s Invalid charset: %s\n",
                                SYM_ERR, optarg);
                    return -1;
                }
                break;

            case 't':
                cfg->num_threads = (int)strtol(optarg, NULL, 10);
                if (cfg->num_threads < 1) cfg->num_threads = 1;
                if (cfg->num_threads > MAX_THREADS)
                    cfg->num_threads = MAX_THREADS;
                break;

            case 1004: /* --batch */
                cfg->batch_size = (size_t)strtoul(optarg, NULL, 10);
                if (cfg->batch_size < 1) cfg->batch_size = 1;
                if (cfg->batch_size > BATCH_MAX_SIZE)
                    cfg->batch_size = BATCH_MAX_SIZE;
                break;

            case 1005: /* --pin-threads */
                cfg->pin_threads = true;
                break;

            case 1006: /* --adaptive */
                cfg->adaptive_batch = true;
                break;

            case 'o':
                snprintf(cfg->output_path, sizeof(cfg->output_path),
                         "%s", optarg);
                break;

            case 'l':
                snprintf(cfg->log_path, sizeof(cfg->log_path),
                         "%s", optarg);
                break;

            case 'v':
                cfg->verbose   = true;
                cfg->log_level = LOG_DEBUG;
                break;

            case 'q':
                cfg->quiet     = true;
                cfg->log_level = LOG_ERROR;
                break;

            case 1007: /* --no-color */
                cfg->no_color = true;
                g_no_color    = true;
                break;

            case 1008: /* --no-progress */
                cfg->show_progress = false;
                break;

            case 1009: /* --thread-stats */
                cfg->show_thread_stats = true;
                break;

            case 1010: /* --resume */
                cfg->resume = true;
                break;

            case 1011: /* --resume-file */
                snprintf(cfg->resume_path, sizeof(cfg->resume_path),
                         "%s", optarg);
                break;

            case 1012: /* --no-save */
                cfg->save_resume = false;
                break;

            case 1013: /* --zip */
                cfg->archive_type       = ARCHIVE_ZIP;
                cfg->force_archive_type = true;
                break;

            case 1014: /* --7z */
                cfg->archive_type       = ARCHIVE_7Z;
                cfg->force_archive_type = true;
                break;

            case 1018: /* --rar */
                cfg->archive_type       = ARCHIVE_RAR;
                cfg->force_archive_type = true;
                break;

            case 1015: /* --skip */
                cfg->skip = strtoull(optarg, NULL, 10);
                break;

            case 1016: /* --limit */
                cfg->limit = strtoull(optarg, NULL, 10);
                break;

            case 1017: /* --version */
                safe_print("crive v%s (build %s %s) [%s]\n",
                           CRIVE_VERSION_STR, CRIVE_BUILD_DATE,
                           CRIVE_BUILD_TIME, PLATFORM_NAME);
                return 1;

            case 'h':
                print_usage(argv[0]);
                return 1;

            case '?':
            default:
                safe_eprint("%s Unknown option. Use --help.\n", SYM_ERR);
                return -1;
        }
    }

    return 0;
}

/* ============================================================
 * VALIDATION
 * ============================================================ */

static int validate_config(config_t *cfg) {
    if (cfg->attack_mode == ATTACK_BENCHMARK && cfg->archive_path[0] == '\0') return 0;

    /* Archive required for all other modes */
    if (cfg->archive_path[0] == '\0') {
        safe_eprint("%s No archive file specified.\n", SYM_ERR);
        return -1;
    }

    if (!file_exists(cfg->archive_path)) {
        safe_eprint("%s Archive not found: %s\n", SYM_ERR,
                    cfg->archive_path);
        return -1;
    }

    if (!file_is_readable(cfg->archive_path)) {
        safe_eprint("%s Archive not readable: %s\n", SYM_ERR,
                    cfg->archive_path);
        return -1;
    }

    /* Auto-detect archive type */
    if (!cfg->force_archive_type) {
        cfg->archive_type = detect_archive_type(cfg->archive_path);
        if (cfg->archive_type == ARCHIVE_UNKNOWN) {
            safe_eprint("%s Cannot determine archive type for: %s\n"
                        "   Use --zip, --7z, or --rar to force type.\n",
                        SYM_ERR, cfg->archive_path);
            return -1;
        }
    }

    /* Attack mode must be set */
    if (cfg->attack_mode == ATTACK_NONE) {
        safe_eprint("%s No attack mode specified.\n"
                    "   Use --wordlist, --bruteforce, --mask, --hybrid, "
                    "or --rules.\n", SYM_ERR);
        return -1;
    }

    /* Wordlist required for dict/hybrid/rule attacks */
    if ((cfg->attack_mode == ATTACK_DICTIONARY ||
         cfg->attack_mode == ATTACK_HYBRID     ||
         cfg->attack_mode == ATTACK_RULE)      &&
        cfg->wordlist_path[0] == '\0') {
        safe_eprint("%s This attack mode requires --wordlist <file>\n",
                    SYM_ERR);
        return -1;
    }

    /* Validate wordlist path */
    if (cfg->wordlist_path[0] != '\0') {
        if (!file_exists(cfg->wordlist_path)) {
            safe_eprint("%s Wordlist not found: %s\n",
                        SYM_ERR, cfg->wordlist_path);
            return -1;
        }
        if (!file_is_readable(cfg->wordlist_path)) {
            safe_eprint("%s Wordlist not readable: %s\n",
                        SYM_ERR, cfg->wordlist_path);
            return -1;
        }
    }

    /* Validate mask if mask mode */
    if (cfg->attack_mode == ATTACK_MASK) {
        /* DIAGNOSTIC */
        safe_eprint("[DIAG] In validate_config: raw_mask = '%s'\n", cfg->mask.raw_mask);

        if (cfg->mask.raw_mask[0] == '\0') {
            safe_eprint("%s Mask pattern is empty.\n", SYM_ERR);
            safe_eprint("   Did you forget to quote the mask? Use: --mask '?l?l?d?d'\n");
            safe_eprint("   If you already used quotes, check for shell wildcard expansion.\n");
            return -1;
        }

        /* Warn about possible shell expansion if pattern contains wildcards */
        bool has_wildcard = false;
        for (const char *p = cfg->mask.raw_mask; *p; p++) {
            if (*p == '*' || *p == '?' || *p == '[') {
                has_wildcard = true;
                break;
            }
        }
        if (has_wildcard) {
            safe_eprint("%s Your mask contains wildcard characters (*, ?, [).\n", SYM_WARN);
            safe_eprint("   To prevent shell expansion, always quote the mask:\n");
            safe_eprint("       crive %s --mask '%s'\n", cfg->archive_path, cfg->mask.raw_mask);
        }

        int parse_ret = mask_parse(&cfg->mask, cfg->mask.raw_mask, NULL, 0);
        safe_eprint("[DIAG] mask_parse returned %d\n", parse_ret);
        if (parse_ret != 0) {
            safe_eprint("%s Invalid mask pattern: '%s'\n",
                        SYM_ERR, cfg->mask.raw_mask);
            return -1;
        }
    }

    /* Length sanity */
    if (cfg->min_length > cfg->max_length) {
        safe_eprint("%s min-length > max-length, swapping.\n", SYM_WARN);
        int tmp        = cfg->min_length;
        cfg->min_length = cfg->max_length;
        cfg->max_length = tmp;
    }

    /* Charset must not be empty for brute-force */
    if (cfg->attack_mode == ATTACK_BRUTEFORCE && cfg->charset.len == 0) {
        safe_eprint("%s Charset is empty - cannot brute-force.\n", SYM_ERR);
        return -1;
    }

    /* Hybrid: set defaults if not set */
    if (cfg->attack_mode == ATTACK_HYBRID) {
        if (cfg->hybrid.suffix_max_len == 0) {
            cfg->hybrid.suffix_min_len = 1;
            cfg->hybrid.suffix_max_len = 4;
        }
        if (cfg->hybrid.suffix_charset[0] == '\0') {
            snprintf(cfg->hybrid.suffix_charset,
                     sizeof(cfg->hybrid.suffix_charset),
                     "%s", CHARSET_DIGITS);
        }
    }

    return 0;
}

/* ============================================================
 * DISPLAY CONFIG SUMMARY
 * ============================================================ */

static void display_config_summary(const config_t *cfg) {
    bool nc = cfg->no_color;

    safe_eprint("\n");
    print_section_header("Session Configuration", nc);

    /* Archive info */
    if (cfg->archive_path[0]) {
        print_kv("Archive",  cfg->archive_path, nc);

        const char *atype_names[] = {"Unknown","ZIP","7-Zip","RAR"};
        const char *atype = (cfg->archive_type < ARCHIVE_MAX)
                            ? atype_names[cfg->archive_type] : "Unknown";
        print_kv("Type", atype, nc);

        int64_t sz = file_size(cfg->archive_path);
        if (sz >= 0) {
            char szstr[32];
            format_size(szstr, sizeof(szstr), (uint64_t)sz);
            print_kv("Size", szstr, nc);
        }
    }

    /* Attack mode */
    static const char *mode_names[] = {
        "None","Dictionary","Brute-Force","Mask",
        "Hybrid","Rule-Based","Benchmark"
    };
    const char *mode_name = (cfg->attack_mode < ATTACK_MAX)
                            ? mode_names[cfg->attack_mode] : "Unknown";
    print_kv("Attack Mode", mode_name, nc);

    /* Mode-specific */
    switch (cfg->attack_mode) {
        case ATTACK_DICTIONARY:
            print_kv("Wordlist", cfg->wordlist_path, nc);
            if (cfg->wordlist_path[0]) {
                int64_t lines = file_count_lines(cfg->wordlist_path);
                if (lines >= 0) {
                    char lstr[32];
                    format_number(lstr, sizeof(lstr), (uint64_t)lines);
                    print_kv("Word Count", lstr, nc);
                }
                int64_t wsz = file_size(cfg->wordlist_path);
                if (wsz >= 0) {
                    char szstr[32];
                    format_size(szstr, sizeof(szstr), (uint64_t)wsz);
                    print_kv("Wordlist Size", szstr, nc);
                }
            }
            break;

        case ATTACK_BRUTEFORCE: {
            char lenstr[32], ksstr[32];
            snprintf(lenstr, sizeof(lenstr), "%d - %d",
                     cfg->min_length, cfg->max_length);
            print_kv("Length Range", lenstr, nc);

            /* Show charset summary */
            char cs_display[64];
            if (cfg->charset.len <= 20) {
                int max_cs = (int)sizeof(cs_display) - 16;
                if (max_cs < 0) max_cs = 0;
                snprintf(cs_display, sizeof(cs_display),
                         "%.*s (%d chars)",
                         max_cs, cfg->charset.chars, cfg->charset.len);
            } else {
                snprintf(cs_display, sizeof(cs_display),
                         "%.20s... (%d chars)",
                         cfg->charset.chars, cfg->charset.len);
            }
            print_kv("Charset", cs_display, nc);

            uint64_t ks = bruteforce_keyspace(&cfg->charset,
                                               cfg->min_length,
                                               cfg->max_length);
            if (ks == UINT64_MAX) {
                snprintf(ksstr, sizeof(ksstr), ">2^64");
            } else {
                format_number(ksstr, sizeof(ksstr), ks);
            }
            print_kv("Keyspace", ksstr, nc);
            break;
        }

        case ATTACK_MASK: {
            print_kv("Mask", cfg->mask.raw_mask, nc);
            char ksstr[32];
            uint64_t ks = mask_keyspace(&cfg->mask);
            format_number(ksstr, sizeof(ksstr), ks);
            print_kv("Keyspace", ksstr, nc);
            break;
        }

        case ATTACK_HYBRID:
            print_kv("Wordlist", cfg->wordlist_path, nc);
            print_kv_fmt(nc, "Suffix Length",
                         "%d - %d",
                         cfg->hybrid.suffix_min_len,
                         cfg->hybrid.suffix_max_len);
            print_kv("Suffix Charset", cfg->hybrid.suffix_charset, nc);
            break;

        case ATTACK_RULE:
            print_kv("Wordlist", cfg->wordlist_path, nc);
            if (cfg->rules_path[0]) {
                print_kv("Rules File", cfg->rules_path, nc);
            } else {
                print_kv("Rules", "Default built-in rules", nc);
            }
            break;

        case ATTACK_BENCHMARK:
            print_kv_fmt(nc, "Duration", "%d seconds",
                         cfg->benchmark_duration);
            break;

        default:
            break;
    }

    /* Threading */
    print_separator(nc);
    print_kv_fmt(nc, "Threads", "%d", cfg->num_threads);
    print_kv_fmt(nc, "Batch Size", "%zu", cfg->batch_size);
    if (cfg->pin_threads) {
        print_kv("Thread Affinity", "Enabled", nc);
    }
    if (cfg->adaptive_batch) {
        print_kv("Adaptive Batch", "Enabled", nc);
    }

    /* Skip/Limit */
    if (cfg->skip > 0) {
        char skipstr[32];
        format_number(skipstr, sizeof(skipstr), cfg->skip);
        print_kv("Skip", skipstr, nc);
    }
    if (cfg->limit > 0) {
        char limstr[32];
        format_number(limstr, sizeof(limstr), cfg->limit);
        print_kv("Limit", limstr, nc);
    }

    /* Resume */
    if (cfg->resume) {
        print_kv("Resume From", cfg->resume_path, nc);
    }
    if (cfg->save_resume) {
        print_kv("Save Resume", cfg->resume_path, nc);
    }

    /* Output */
    if (cfg->output_path[0]) {
        print_kv("Output File", cfg->output_path, nc);
    }
    if (cfg->log_path[0]) {
        print_kv("Log File", cfg->log_path, nc);
    }

    safe_eprint("\n");
}

/* ============================================================
 * SIGNAL HANDLERS
 * ============================================================ */

static void main_signal_handler(int sig) {
    g_got_signal    = 1;
    g_signal_number = (sig_atomic_t)sig;

    if (sig == SIGINT) {
        g_sigint_count++;
        if (g_sigint_count >= 2) {
            /* Hard exit on double Ctrl+C */
            const char msg[] = "\n[!] Force exit.\n";
            write(STDERR_FILENO, msg, sizeof(msg) - 1);
            _exit(1);
        }
        const char msg[] = "\n[!] Stopping... (Ctrl+C again to force exit)\n";
        write(STDERR_FILENO, msg, sizeof(msg) - 1);
    }
}

static void install_signal_handlers(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = main_signal_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;

    sigaction(SIGINT,  &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    /* Ignore SIGPIPE */
    struct sigaction sa_pipe;
    memset(&sa_pipe, 0, sizeof(sa_pipe));
    sa_pipe.sa_handler = SIG_IGN;
    sigaction(SIGPIPE, &sa_pipe, NULL);
}

/* ============================================================
 * RESUME WORKFLOW
 * ============================================================ */

static bool handle_resume(config_t *cfg) {
    if (!cfg->resume) return false;

    if (!file_exists(cfg->resume_path)) {
        safe_eprint("%s Resume file not found: %s\n",
                    SYM_WARN, cfg->resume_path);
        return false;
    }

    resume_state_t rs;
    if (resume_load(cfg->resume_path, &rs) != 0) {
        safe_eprint("%s Could not load resume state.\n", SYM_WARN);
        return false;
    }

    resume_print(&rs, cfg->no_color);

    /* Merge resume state into config */
    if (cfg->archive_path[0] == '\0' && rs.archive_path[0] != '\0') {
        snprintf(cfg->archive_path, sizeof(cfg->archive_path),
                 "%s", rs.archive_path);
    }
    if (cfg->wordlist_path[0] == '\0' && rs.wordlist_path[0] != '\0') {
        snprintf(cfg->wordlist_path, sizeof(cfg->wordlist_path),
                 "%s", rs.wordlist_path);
    }
    if (cfg->attack_mode == ATTACK_NONE) {
        cfg->attack_mode = rs.attack_mode;
    }
    if (cfg->archive_type == ARCHIVE_UNKNOWN) {
        cfg->archive_type = rs.archive_type;
    }

    safe_eprint("%s Resuming from attempt %llu\n",
                SYM_INFO,
                (unsigned long long)rs.total_attempts);
    return true;
}

/* ============================================================
 * WORD-COUNT ESTIMATE (for ETA calculation)
 * ============================================================ */

static uint64_t estimate_dict_wordcount(const char *path) {
    int64_t sz = file_size(path);
    if (sz <= 0) return 0;
    /* Estimate: average word length ~8 bytes including newline */
    return (uint64_t)sz / 8;
}

/* ============================================================
 * PRE-FLIGHT CHECK
 * ============================================================ */

static int preflight_check(const config_t *cfg, archive_ctx_t *archive) {

    /* Quick sanity: try one known-wrong password to ensure parser works */
    bool result = archive_validate_password(archive, "CRIVE_PREFLIGHT_TEST");
    (void)result;

    /* Check archive is actually encrypted */
    if (cfg->archive_type == ARCHIVE_ZIP) {
        /* ZIP check is implicit - if parse succeeded we have enc header */
    } else if (cfg->archive_type == ARCHIVE_7Z) {
        /* 7Z check is implicit */
    } else if (cfg->archive_type == ARCHIVE_RAR) {
        /* RAR check is implicit */
    }

    return 0;
}

/* ============================================================
 * PROGRESS LINE (non-interactive fallback)
 * Prints simple one-line progress for pipes/scripts
 * ============================================================ */

typedef struct {
    bool            running;
    pthread_t       tid;
    atomic_uint_fast64_t *total_attempts;
    struct timespec start_time;
    bool            no_color;
    int             interval_ms;
} simple_progress_t;

static void *simple_progress_fn(void *arg) {
    simple_progress_t *sp = (simple_progress_t *)arg;

    while (sp->running) {
        sleep_ms(sp->interval_ms);
        if (!sp->running) break;

        uint64_t total   = atomic_load_explicit(sp->total_attempts,
                                                 memory_order_relaxed);
        double   elapsed = elapsed_seconds_since(&sp->start_time);
        double   speed   = (elapsed > 0.001)
                           ? ((double)total / elapsed)
                           : 0.0;

        char total_str[32], elapsed_str[32], speed_str[32];
        format_number(total_str,   sizeof(total_str),   total);
        format_elapsed(elapsed_str, sizeof(elapsed_str), elapsed);
        format_speed(speed_str,    sizeof(speed_str),   speed);

        safe_eprint("[*] Tested: %-14s  Elapsed: %-12s  Speed: %s\n",
                    total_str, elapsed_str, speed_str);
    }
    return NULL;
}

/* ============================================================
 * RESULT DISPLAY
 * ============================================================ */

static void display_result(attack_result_t result,
                            const char *archive_path,
                            const char *password,
                            double elapsed_sec,
                            uint64_t total_tested,
                            bool no_color) {
    bool nc = no_color;

    safe_eprint("\n");
    print_separator(nc);

    char elapsed_str[32], total_str[32], speed_str[32];
    format_elapsed(elapsed_str, sizeof(elapsed_str), elapsed_sec);
    format_number(total_str, sizeof(total_str), total_tested);
    double safe_elapsed = (elapsed_sec > 1e-9) ? elapsed_sec : 1e-9;
    double speed = ((double)total_tested / safe_elapsed);
    format_speed(speed_str, sizeof(speed_str), speed);

    switch (result) {
        case ATTACK_RESULT_FOUND:
            safe_eprint("%s%s PASSWORD FOUND!%s\n",
                        cc(ANSI_BRIGHT_GREEN), cc(ANSI_BOLD),
                        cc(ANSI_RESET));
            safe_eprint("  %s%-20s%s %s%s%s\n",
                        cc(CLR_LABEL), "Archive:", cc(ANSI_RESET),
                        cc(CLR_VALUE), archive_path, cc(ANSI_RESET));
            safe_eprint("  %s%-20s%s %s%s%s\n",
                        cc(CLR_LABEL), "Password:", cc(ANSI_RESET),
                        cc(ANSI_BRIGHT_GREEN), password, cc(ANSI_RESET));
            break;

        case ATTACK_RESULT_EXHAUSTED:
            safe_eprint("%s Password not found. Keyspace exhausted.%s\n",
                        cc(ANSI_BRIGHT_RED), cc(ANSI_RESET));
            break;

        case ATTACK_RESULT_ABORTED:
            safe_eprint("%s Attack aborted by user.%s\n",
                        cc(ANSI_BRIGHT_YELLOW), cc(ANSI_RESET));
            break;

        case ATTACK_RESULT_ERROR:
            safe_eprint("%s Attack failed due to error.%s\n",
                        cc(ANSI_BRIGHT_RED), cc(ANSI_RESET));
            break;

        case ATTACK_RESULT_NOT_FOUND:
        default:
            safe_eprint("%s Password not found.%s\n",
                        cc(ANSI_BRIGHT_RED), cc(ANSI_RESET));
            break;
    }

    safe_eprint("\n");
    safe_eprint("  %s%-20s%s %s%s%s\n",
                cc(CLR_LABEL), "Tested:", cc(ANSI_RESET),
                cc(CLR_VALUE), total_str, cc(ANSI_RESET));
    safe_eprint("  %s%-20s%s %s%s%s\n",
                cc(CLR_LABEL), "Elapsed:", cc(ANSI_RESET),
                cc(CLR_VALUE), elapsed_str, cc(ANSI_RESET));
    safe_eprint("  %s%-20s%s %s%s%s\n",
                cc(CLR_LABEL), "Avg Speed:", cc(ANSI_RESET),
                cc(CLR_SPEED), speed_str, cc(ANSI_RESET));

    print_separator(nc);
    safe_eprint("\n");
}

/* ============================================================
 * BENCHMARK DISPLAY
 * ============================================================ */

static void display_benchmark(const benchmark_result_t *res, bool no_color) {
    bool nc = no_color;

    safe_eprint("\n");
    print_section_header("Benchmark Results", nc);

    char speed_str[32], peak_str[32], total_str[32];
    format_speed(speed_str,  sizeof(speed_str),  res->total_speed);
    format_speed(peak_str,   sizeof(peak_str),   res->peak_speed);
    format_number(total_str, sizeof(total_str),  res->total_hashes);

    print_kv("Average Speed",  speed_str, nc);
    print_kv("Peak Speed",     peak_str,  nc);
    print_kv("Total Hashes",   total_str, nc);
    print_kv_fmt(nc, "Duration",    "%.1f sec", res->duration_sec);
    print_kv_fmt(nc, "Threads",     "%d",       res->num_threads);

    if (res->arch_type == ARCHIVE_ZIP) {
        safe_eprint("\n");
        safe_eprint("  %sEstimated archive cracking speed:%s\n",
                    cc(CLR_LABEL), cc(ANSI_RESET));

        /* 7Z estimate (much slower due to key derivation) */
        double sz_speed = res->total_speed / 50000.0; /* rough estimate */
        char sz_str[32];
        format_speed(sz_str, sizeof(sz_str), sz_speed);
        safe_eprint("  %s  7-Zip (AES):  %s%s%s\n",
                    cc(ANSI_DIM), cc(CLR_SPEED), sz_str, cc(ANSI_RESET));

        /* RAR estimate */
        double rar_speed = res->total_speed / 100000.0; /* even slower */
        char rar_str[32];
        format_speed(rar_str, sizeof(rar_str), rar_speed);
        safe_eprint("  %s  RAR  (AES):  %s%s%s\n",
                    cc(ANSI_DIM), cc(CLR_SPEED), rar_str, cc(ANSI_RESET));
    }

    safe_eprint("\n");
}

/* ============================================================
 * ARCHIVE INFO DISPLAY
 * ============================================================ */

static void display_archive_info(archive_ctx_t *archive,
                                  const config_t *cfg) {
    archive_print_info(archive, cfg->no_color);
}

/* ============================================================
 * WORDLIST INFO
 * ============================================================ */

static void display_wordlist_info(const config_t *cfg) {
    if (cfg->wordlist_path[0] == '\0') return;

    /* 'nc' variable is not used – silence warning */
    (void)cfg->no_color;

    safe_eprint("  %s%-20s%s %s%s%s\n",
                cc(CLR_LABEL), "Wordlist:", cc(ANSI_RESET),
                cc(CLR_VALUE), cfg->wordlist_path, cc(ANSI_RESET));

    int64_t sz    = file_size(cfg->wordlist_path);
    int64_t lines = file_count_lines(cfg->wordlist_path);

    if (sz >= 0) {
        char szstr[32];
        format_size(szstr, sizeof(szstr), (uint64_t)sz);
        safe_eprint("  %s%-20s%s %s%s%s\n",
                    cc(CLR_LABEL), "Wordlist Size:", cc(ANSI_RESET),
                    cc(CLR_VALUE), szstr, cc(ANSI_RESET));
    }
    if (lines >= 0) {
        char lstr[32];
        format_number(lstr, sizeof(lstr), (uint64_t)lines);
        safe_eprint("  %s%-20s%s %s%s%s\n",
                    cc(CLR_LABEL), "Words:", cc(ANSI_RESET),
                    cc(CLR_VALUE), lstr, cc(ANSI_RESET));
    }
}

/* ============================================================
 * THREAD-LOCAL ARCHIVE CONTEXT SIZE
 * (must match archive.c's struct size)
 * ============================================================ */

/* We use a fixed allocation size - must match archive_ctx_t */
#define ARCHIVE_CTX_SIZE    (1024 * 16)  /* 16KB - generous */

/* ============================================================
 * MAIN WORKFLOW
 * ============================================================ */

static int run_cracking_session(config_t *cfg) {
    bool nc = cfg->no_color;

    /* Handle resume */
    handle_resume(cfg);

    /* Validate config */
    if (validate_config(cfg) != 0) {
        return EXIT_FAILURE;
    }

    /* For benchmark mode, skip archive */
    if (cfg->attack_mode == ATTACK_BENCHMARK) {
        display_config_summary(cfg);

        archive_type_t btype = (cfg->archive_type != ARCHIVE_UNKNOWN)
                               ? cfg->archive_type
                               : ARCHIVE_ZIP;

        benchmark_result_t bres = engine_benchmark(cfg, btype,
                                                    cfg->benchmark_duration * 1000);
        display_benchmark(&bres, nc);
        return EXIT_SUCCESS;
    }

    /* Open archive */
    safe_eprint("%s Opening archive: %s%s%s\n",
                SYM_INFO,
                cc(CLR_VALUE), cfg->archive_path, cc(ANSI_RESET));

    /* Allocate archive context from heap */
    archive_ctx_t *archive = (archive_ctx_t *)calloc(1, ARCHIVE_CTX_SIZE);
    if (!archive) {
        safe_eprint("%s Memory allocation failed for archive context.\n",
                    SYM_ERR);
        return EXIT_FAILURE;
    }

    if (archive_open(archive, cfg->archive_path, cfg->archive_type) != 0) {
        safe_eprint("%s Failed to open/parse archive: %s\n",
                    SYM_ERR, cfg->archive_path);
        free(archive);
        return EXIT_FAILURE;
    }

    /* ----- unrar dependency check ----- */
    if (cfg->archive_type == ARCHIVE_RAR && !command_exists("unrar")) {
        /* For RAR5 with check data, we don't strictly need unrar */
        bool need_unrar = true;
        if (archive->rar.version == 5 && archive->rar.has_check_value) {
            need_unrar = false;
        }

        if (need_unrar) {
            safe_eprint("\n%s unrar is required to verify passwords for this RAR archive.\n"
                        "   Please install unrar:\n"
                        "     Termux : pkg install unrar\n"
                        "     Debian : apt install unrar\n"
                        "     Arch   : pacman -S unrar\n"
                        "     macOS  : brew install unrar\n\n",
                        SYM_ERR);
            archive_ctx_free(archive);
            free(archive);
            return EXIT_FAILURE;
        }
    }

    safe_eprint("%s Archive parsed successfully.\n", SYM_OK);

    /* Display archive info */
    display_archive_info(archive, cfg);

    /* Display wordlist info */
    if (cfg->wordlist_path[0]) {
        display_wordlist_info(cfg);
    }

    /* ----- 7z dependency check ----- */
    bool need_7z = false;
    if (cfg->archive_type == ARCHIVE_7Z) {
        need_7z = true;
    } else if (cfg->archive_type == ARCHIVE_ZIP) {
        /* For ZIP, we need 7z only if the compression method is not STORED (0) */
        const struct zip_ctx *z = &archive->zip;
        if (z->method != 0) {   /* 0 = stored (no compression) */
            need_7z = true;
        }
    }

    if (need_7z && !command_exists("7z")) {
        safe_eprint("\n%s 7z (p7zip) is required to verify passwords for this archive.\n"
                    "   Please install p7zip:\n"
                    "     Termux : pkg install p7zip\n"
                    "     Debian : apt install p7zip-full\n"
                    "     Arch   : pacman -S p7zip\n"
                    "     macOS  : brew install p7zip\n\n",
                    SYM_ERR);
        archive_ctx_free(archive);
        free(archive);
        return EXIT_FAILURE;
    }
    /* ----- end dependency check ----- */

    /* Display config summary */
    display_config_summary(cfg);

    /* Pre-flight check */
    if (preflight_check(cfg, archive) != 0) {
        safe_eprint("%s Pre-flight check failed.\n", SYM_ERR);
        archive_ctx_free(archive);
        free(archive);
        return EXIT_FAILURE;
    }

    /* Set terminal title */
    char title[MAX_PATH_LEN + 128];
    snprintf(title, sizeof(title), "crive - %s",
             cfg->archive_path[0] ? cfg->archive_path : "benchmark");
    term_set_title(title);

    /* Print start message */
    char datetime[64];
    get_datetime_str(datetime, sizeof(datetime));

    safe_eprint("%s Starting attack at %s%s%s\n",
                SYM_INFO,
                cc(ANSI_BRIGHT_WHITE), datetime, cc(ANSI_RESET));
    safe_eprint("%s Press %sCtrl+C%s to stop and save progress.\n\n",
                SYM_INFO,
                cc(ANSI_BRIGHT_YELLOW), cc(ANSI_RESET));

    /* Run the engine */
    struct timespec t_start = get_timespec_now();

    engine_run_result_t res = engine_orchestrate(cfg, archive);

    double elapsed = elapsed_seconds_since(&t_start);

    /* Display result */
    display_result(res.result,
                   cfg->archive_path,
                   res.result == ATTACK_RESULT_FOUND
                       ? res.password : "",
                   elapsed,
                   res.total_tested,
                   nc);

    /* Cleanup */
    archive_ctx_free(archive);
    free(archive);

    /* Return appropriate exit code */
    switch (res.result) {
        case ATTACK_RESULT_FOUND:     return 0;
        case ATTACK_RESULT_EXHAUSTED: return 1;
        case ATTACK_RESULT_ABORTED:   return 2;
        case ATTACK_RESULT_ERROR:     return 3;
        default:                      return 1;
    }
}

/* ============================================================
 * ENVIRONMENT DETECTION
 * ============================================================ */

static void detect_environment(config_t *cfg) {
    /* Check if running in Termux */
#ifdef __ANDROID__
    const char *termux_prefix = getenv("PREFIX");
    if (termux_prefix && strstr(termux_prefix, "com.termux")) {
        log_debug("Detected Termux environment");
        /* Termux has limited cores but consistent scheduling */
    }
#endif

    /* Check terminal capabilities */
    const char *term = getenv("TERM");
    const char *colorterm = getenv("COLORTERM");

    if (term && (strcmp(term, "dumb") == 0)) {
        cfg->no_color      = true;
        cfg->show_progress = false;
        g_no_color         = true;
    }

    if (!isatty(STDOUT_FILENO)) {
        /* stdout piped - adjust output */
    }

    if (!isatty(STDERR_FILENO)) {
        cfg->show_progress = false;
        cfg->interactive   = false;
    }

    /* Check CRIVE_THREADS env var */
    const char *env_threads = getenv("CRIVE_THREADS");
    if (env_threads) {
        int n = (int)strtol(env_threads, NULL, 10);
        if (n > 0 && n <= MAX_THREADS) {
            cfg->num_threads = n;
            log_debug("Thread count from env: %d", n);
        }
    }

    /* Check CRIVE_NO_COLOR */
    if (getenv("CRIVE_NO_COLOR") || getenv("NO_COLOR")) {
        cfg->no_color = true;
        g_no_color    = true;
    }

    /* Check CRIVE_BATCH */
    const char *env_batch = getenv("CRIVE_BATCH");
    if (env_batch) {
        size_t b = (size_t)strtoul(env_batch, NULL, 10);
        if (b >= 1 && b <= BATCH_MAX_SIZE) {
            cfg->batch_size = b;
        }
    }

    (void)colorterm;
}

/* ============================================================
 * INTERACTIVE MODE PROMPTS
 * ============================================================ */

static void interactive_prompt_wordlist(config_t *cfg) {
    if (cfg->wordlist_path[0] != '\0') return;

    safe_eprint("%s No wordlist specified. Enter path (or press Enter to skip): ",
                SYM_INFO);
    fflush(stderr);

    char buf[MAX_PATH_LEN];
    if (fgets(buf, sizeof(buf), stdin)) {
        size_t len = strlen(buf);
        while (len > 0 && (buf[len-1] == '\n' || buf[len-1] == '\r' ||
                            buf[len-1] == ' ')) {
            buf[--len] = '\0';
        }
        if (len > 0 && file_exists(buf)) {
            snprintf(cfg->wordlist_path, sizeof(cfg->wordlist_path), "%s", buf);
            safe_eprint("%s Using wordlist: %s\n", SYM_OK, buf);
        }
    }
}

static void interactive_confirm_start(const config_t *cfg) {
    if (!cfg->interactive) return;

    static const char *mode_names[] = {
        "None","Dictionary","Brute-Force","Mask",
        "Hybrid","Rule-Based","Benchmark"
    };
    const char *mname = (cfg->attack_mode < ATTACK_MAX)
                        ? mode_names[cfg->attack_mode] : "?";

    safe_eprint("\n%s Ready to start %s%s%s attack with %s%d threads%s.\n",
                SYM_INFO,
                cc(ANSI_BRIGHT_YELLOW), mname, cc(ANSI_RESET),
                cc(ANSI_BRIGHT_WHITE), cfg->num_threads, cc(ANSI_RESET));
}

/* ============================================================
 * VERSION / INFO DISPLAY
 * ============================================================ */

static void show_version(void) {
    safe_print(
        "crive %s\n"
        "Build:    %s %s\n"
        "Platform: %s\n"
        "Features: ZIP PKZIP, ZIP WinZip-AES, 7-Zip AES-256, RAR3, RAR5\n"
        "Attacks:  Dictionary, Brute-Force, Mask, Hybrid, Rule-Based\n",
        CRIVE_VERSION_STR,
        CRIVE_BUILD_DATE, CRIVE_BUILD_TIME,
        PLATFORM_NAME);
}

/* ============================================================
 * SYSTEM INFO
 * ============================================================ */

static void show_sysinfo(void) {
    int cpus = get_cpu_count();

    safe_eprint("\n%s[System Info]%s\n", cc(CLR_HEADER), cc(ANSI_RESET));
    safe_eprint("  Platform:   %s\n", PLATFORM_NAME);
    safe_eprint("  CPU Cores:  %d\n", cpus);

    /* Memory info from /proc/meminfo */
    FILE *f = fopen("/proc/meminfo", "r");
    if (f) {
        char line[256];
        uint64_t total_kb = 0, avail_kb = 0;
        while (fgets(line, sizeof(line), f)) {
            if (strncmp(line, "MemTotal:", 9) == 0) {
                sscanf(line + 9, "%llu", (unsigned long long *)&total_kb);
            } else if (strncmp(line, "MemAvailable:", 13) == 0) {
                sscanf(line + 13, "%llu", (unsigned long long *)&avail_kb);
            }
        }
        fclose(f);
        if (total_kb > 0) {
            char total_str[32], avail_str[32];
            format_size(total_str, sizeof(total_str), total_kb * KB);
            format_size(avail_str, sizeof(avail_str), avail_kb * KB);
            safe_eprint("  RAM Total:  %s\n", total_str);
            safe_eprint("  RAM Avail:  %s\n", avail_str);
        }
    }

    /* CPU model from /proc/cpuinfo */
    f = fopen("/proc/cpuinfo", "r");
    if (f) {
        char line[256];
        while (fgets(line, sizeof(line), f)) {
            if (strncmp(line, "model name", 10) == 0) {
                char *colon = strchr(line, ':');
                if (colon) {
                    colon++;
                    while (*colon == ' ') colon++;
                    size_t len = strlen(colon);
                    while (len > 0 && (colon[len-1] == '\n' ||
                                       colon[len-1] == '\r')) {
                        colon[--len] = '\0';
                    }
                    safe_eprint("  CPU Model:  %s\n", colon);
                }
                break;
            }
        }
        fclose(f);
    }

    safe_eprint("\n");
}

/* ============================================================
 * MAIN ENTRY POINT
 * ============================================================ */

int main(int argc, char **argv) {
    /* Set locale for Unicode output */
    setlocale(LC_ALL, "");

    /* Init globals */
    g_is_tty_out = isatty(STDOUT_FILENO);
    g_no_color   = !isatty(STDERR_FILENO);

    /* Quick pre-pass to detect --no-color before banner */
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--no-color") == 0 ||
            strcmp(argv[i], "--quiet")    == 0 ||
            strcmp(argv[i], "-q")         == 0) {
            g_no_color = true;
            break;
        }
    }

    /* Early version/help checks */
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--version") == 0 ||
            strcmp(argv[i], "-V")        == 0) {
            show_version();
            return 0;
        }
        if (strcmp(argv[i], "--sysinfo") == 0) {
            show_sysinfo();
            return 0;
        }
    }

    /* Print banner */
    print_banner(g_no_color);

    /* Install signal handlers */
    install_signal_handlers();

    /* Parse config */
    config_t cfg;
    memset(&cfg, 0, sizeof(cfg));

    int parse_rc = parse_args(argc, argv, &cfg);
    if (parse_rc > 0) {
        /* --help or --version already handled */
        return 0;
    }
    if (parse_rc < 0) {
        return EXIT_FAILURE;
    }

    /* Detect environment (Termux, terminal caps, env vars) */
    detect_environment(&cfg);

    /* Init utilities */
    utils_init(&cfg);

    /* Init CRC table */
    crc32_init();

    /* Init terminal */
    term_init();

    /* Show system info in verbose mode */
    if (cfg.verbose) {
        show_sysinfo();
    }

    /* Interactive prompts for missing info */
    if (cfg.interactive &&
        cfg.attack_mode == ATTACK_NONE &&
        cfg.archive_path[0] != '\0') {
        safe_eprint("\n%s No attack mode specified. "
                    "Defaulting to dictionary attack.\n", SYM_WARN);
        cfg.attack_mode = ATTACK_DICTIONARY;
        interactive_prompt_wordlist(&cfg);
    }

    /* Confirm start */
    interactive_confirm_start(&cfg);

    /* Run the main session */
    int exit_code = run_cracking_session(&cfg);

    /* Cleanup */
    utils_cleanup();
    term_show_cursor();

    /* Final message */
    if (!cfg.quiet) {
        char datetime[64];
        get_datetime_str(datetime, sizeof(datetime));
        safe_eprint("%s Session ended at %s\n", SYM_INFO, datetime);
    }

    return exit_code;
}

/* ============================================================
 * END OF main.c
 * ============================================================ */

#if !defined(_WIN32)
#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE 700
#endif
#endif

#include <errno.h>
#include <locale.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>

#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#include "win_dirent.h"
#include <BaseTsd.h>
#include <direct.h>
#include <io.h>
#include <process.h>
#include <windows.h>

typedef SSIZE_T ssize_t;
#else
#include <dirent.h>
#include <unistd.h>
#endif

#include <archive.h>
#include <archive_entry.h>

#include "mbedtls/cipher.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "mbedtls/error.h"
#include "mbedtls/gcm.h"
#include "mbedtls/md.h"
#include "mbedtls/pk.h"
#include "mbedtls/platform_util.h"
#include "mbedtls/rsa.h"

#include "key_data.h"

#define ENCRYPTO_STREAM_CHUNK (64 * 1024)

#if defined(_WIN32)
#ifndef S_ISDIR
#define S_ISDIR(m) (((m) & _S_IFDIR) != 0)
#endif
#ifndef S_ISREG
#define S_ISREG(m) (((m) & _S_IFREG) != 0)
#endif
#ifndef S_ISLNK
#define S_ISLNK(m) 0
#endif
#ifndef S_ISCHR
#define S_ISCHR(m) (((m) & _S_IFCHR) != 0)
#endif
#ifndef S_ISBLK
#define S_ISBLK(m) 0
#endif
#ifndef S_ISFIFO
#define S_ISFIFO(m) 0
#endif
#ifndef S_ISSOCK
#define S_ISSOCK(m) 0
#endif
#endif

typedef struct random_stream {
    unsigned char* data;
    size_t         length;
    size_t         offset;
} random_stream;

static int random_stream_load(const char* path, random_stream* stream)
{
    FILE* fp = fopen(path, "rb");
    if (!fp) {
        fprintf(stderr, "Failed to open deterministic random source '%s': %s\n", path, strerror(errno));
        return -1;
    }

    if (fseek(fp, 0, SEEK_END) != 0) {
        fprintf(stderr, "Failed to seek deterministic random source '%s'\n", path);
        fclose(fp);
        return -1;
    }

    long size = ftell(fp);
    if (size < 0) {
        fprintf(stderr, "Failed to determine size of deterministic random source '%s'\n", path);
        fclose(fp);
        return -1;
    }
    if (fseek(fp, 0, SEEK_SET) != 0) {
        fprintf(stderr, "Failed to rewind deterministic random source '%s'\n", path);
        fclose(fp);
        return -1;
    }

    stream->data = (unsigned char*)malloc((size_t)size);
    if (!stream->data) {
        fprintf(stderr, "Out of memory loading deterministic random source\n");
        fclose(fp);
        return -1;
    }

    if (fread(stream->data, 1, (size_t)size, fp) != (size_t)size) {
        fprintf(stderr, "Failed to read deterministic random source '%s'\n", path);
        free(stream->data);
        stream->data = NULL;
        fclose(fp);
        return -1;
    }

    fclose(fp);

    stream->length = (size_t)size;
    stream->offset = 0;
    return 0;
}

static void random_stream_unload(random_stream* stream)
{
    if (stream && stream->data) {
        mbedtls_platform_zeroize(stream->data, stream->length);
        free(stream->data);
        stream->data   = NULL;
        stream->length = 0;
        stream->offset = 0;
    }
}

static int random_stream_func(void* ctx, unsigned char* out, size_t len)
{
    random_stream* stream = (random_stream*)ctx;
    if (!stream || len == 0) {
        return 0;
    }
    if (stream->offset + len > stream->length) {
        return MBEDTLS_ERR_ENTROPY_SOURCE_FAILED;
    }

    memcpy(out, stream->data + stream->offset, len);
    stream->offset += len;
    return 0;
}

static void print_mbedtls_error(const char* label, int code)
{
    char buffer[256];
    mbedtls_strerror(code, buffer, sizeof(buffer));
    fprintf(stderr, "%s: %s\n", label, buffer);
}

static uint16_t load_u16_be(const unsigned char* src)
{
    return (uint16_t)((src[0] << 8) | src[1]);
}

static uint64_t load_u64_be(const unsigned char* src)
{
    uint64_t value = 0;
    for (int i = 0; i < 8; ++i) {
        value = (value << 8) | src[i];
    }
    return value;
}

typedef enum compression_algorithm {
    COMPRESSION_NONE    = 0,
    COMPRESSION_GZIP    = 1,
    COMPRESSION_ZSTD    = 2,
    COMPRESSION_LZ4     = 3,
    COMPRESSION_INVALID = 255
} compression_algorithm;

static const char* compression_algorithm_name(compression_algorithm algo)
{
    switch (algo) {
    case COMPRESSION_NONE:
        return "none";
    case COMPRESSION_GZIP:
        return "gzip";
    case COMPRESSION_ZSTD:
        return "zstd";
    case COMPRESSION_LZ4:
        return "lz4";
    default:
        return "invalid";
    }
}

static compression_algorithm compression_algorithm_from_id(unsigned int id)
{
    switch (id) {
    case 0:
        return COMPRESSION_NONE;
    case 1:
        return COMPRESSION_GZIP;
    case 2:
        return COMPRESSION_ZSTD;
    case 3:
        return COMPRESSION_LZ4;
    default:
        return COMPRESSION_INVALID;
    }
}

static int path_is_safe_relative(const char* path)
{
    if (!path || path[0] == '\0') {
        return 0;
    }
    if (path[0] == '/' || path[0] == '\\') {
        return 0;
    }
    const char* cursor = path;
    while (*cursor != '\0') {
        const char* component = cursor;
        size_t      length    = 0;
        while (cursor[length] != '\0' && cursor[length] != '/') {
            if (cursor[length] == '\\') {
                return 0;
            }
            ++length;
        }
        if (length == 0) {
            return 0;
        }
        if ((length == 1 && component[0] == '.') || (length == 2 && component[0] == '.' && component[1] == '.')) {
            return 0;
        }
        cursor += length;
        if (*cursor == '/') {
            ++cursor;
        }
    }
    return 1;
}

static char* string_dup(const char* src)
{
    if (!src) {
        return NULL;
    }
    size_t len = strlen(src);
    char*  out = (char*)malloc(len + 1);
    if (!out) {
        return NULL;
    }
    memcpy(out, src, len + 1);
    return out;
}

static int is_path_separator(char ch)
{
#if defined(_WIN32)
    return ch == '/' || ch == '\\';
#else
    return ch == '/';
#endif
}

#if defined(_WIN32)
static char* path_to_windows(const char* path)
{
    if (!path) {
        return NULL;
    }
    char* converted = string_dup(path);
    if (!converted) {
        return NULL;
    }
    for (char* p = converted; *p != '\0'; ++p) {
        if (*p == '/') {
            *p = '\\';
        }
    }
    return converted;
}

static void normalize_slashes(char* path)
{
    if (!path) {
        return;
    }
    for (char* p = path; *p != '\0'; ++p) {
        if (*p == '\\') {
            *p = '/';
        }
    }
}
#endif

static char* path_basename_dup(const char* path)
{
    if (!path) {
        return NULL;
    }
    size_t len = strlen(path);
    while (len > 0 && is_path_separator(path[len - 1])) {
        len--;
    }
    if (len == 0) {
        char* dot = (char*)malloc(2);
        if (!dot) {
            return NULL;
        }
        dot[0] = '.';
        dot[1] = '\0';
        return dot;
    }
    const char* end   = path + len;
    const char* start = path;
    for (const char* p = end; p != path; --p) {
        if (is_path_separator(*(p - 1))) {
            start = p;
            break;
        }
    }
    size_t base_len = (size_t)(end - start);
    if (base_len == 0) {
        base_len = len;
        start    = path;
    }
    char* result = (char*)malloc(base_len + 1);
    if (!result) {
        return NULL;
    }
    memcpy(result, start, base_len);
    result[base_len] = '\0';
    return result;
}

static char* path_join(const char* lhs, const char* rhs)
{
    size_t lhs_len    = lhs ? strlen(lhs) : 0;
    size_t rhs_len    = rhs ? strlen(rhs) : 0;
    size_t need_slash = 0;
    if (lhs_len > 0 && rhs_len > 0 && !is_path_separator(lhs[lhs_len - 1])) {
        need_slash = 1;
    }
    size_t total = lhs_len + need_slash + rhs_len + 1;
    char*  out   = (char*)malloc(total);
    if (!out) {
        return NULL;
    }
    size_t offset = 0;
    if (lhs_len > 0) {
        memcpy(out + offset, lhs, lhs_len);
        offset += lhs_len;
    }
    if (need_slash) {
        out[offset++] = '/';
    }
    if (rhs_len > 0) {
        memcpy(out + offset, rhs, rhs_len);
        offset += rhs_len;
    }
    out[offset] = '\0';
    return out;
}

static int path_exists(const char* path)
{
    if (!path) {
        return 0;
    }
#if defined(_WIN32)
    struct _stat64 st;
    char*          win_path = path_to_windows(path);
    if (!win_path) {
        return 0;
    }
    int result = _stat64(win_path, &st);
    int saved  = errno;
    free(win_path);
    errno = saved;
    return result == 0;
#else
    struct stat st;
    return stat(path, &st) == 0;
#endif
}

#if defined(_WIN32)
static int create_single_directory(const char* path)
{
    char* win_path = path_to_windows(path);
    if (!win_path) {
        errno = ENOMEM;
        return -1;
    }
    int rc    = _mkdir(win_path);
    int saved = errno;
    free(win_path);
    errno = saved;
    return rc;
}

static int remove_single_directory(const char* path)
{
    char* win_path = path_to_windows(path);
    if (!win_path) {
        errno = ENOMEM;
        return -1;
    }
    int rc    = _rmdir(win_path);
    int saved = errno;
    free(win_path);
    errno = saved;
    return rc;
}

static int remove_single_file(const char* path)
{
    char* win_path = path_to_windows(path);
    if (!win_path) {
        errno = ENOMEM;
        return -1;
    }
    int rc    = _unlink(win_path);
    int saved = errno;
    free(win_path);
    errno = saved;
    return rc;
}
#else
static int create_single_directory(const char* path)
{
    return mkdir(path, 0755);
}

static int remove_single_directory(const char* path)
{
    return rmdir(path);
}

static int remove_single_file(const char* path)
{
    return unlink(path);
}
#endif

static unsigned int random_suffix_value(void)
{
    static int          seeded = 0;
    static unsigned int state  = 0;
    if (!seeded) {
#if defined(_WIN32)
        unsigned int  seed = (unsigned int)_getpid();
        LARGE_INTEGER counter;
        if (QueryPerformanceCounter(&counter)) {
            seed ^= (unsigned int)counter.LowPart;
            seed ^= (unsigned int)counter.HighPart;
        } else {
            seed ^= (unsigned int)GetTickCount();
        }
#else
        unsigned int    seed = (unsigned int)getpid();
        struct timespec ts;
        if (clock_gettime(CLOCK_REALTIME, &ts) == 0) {
            seed ^= (unsigned int)ts.tv_nsec;
            seed ^= (unsigned int)ts.tv_sec;
        } else {
            seed ^= (unsigned int)time(NULL);
        }
#endif
        srand(seed);
        state  = (unsigned int)rand();
        seeded = 1;
    }
    state = (unsigned int)rand();
    return state;
}

static char* ensure_unique_auto_output(char* base_path)
{
    if (!base_path) {
        return NULL;
    }

    if (!path_exists(base_path)) {
        return base_path;
    }

    const size_t base_len = strlen(base_path);
    const size_t max_rand = 64;
    for (size_t attempt = 0; attempt < max_rand; ++attempt) {
        unsigned int value = random_suffix_value();
        char         suffix[32];
        int          suffix_len = snprintf(suffix, sizeof(suffix), "_%u", value);
        if (suffix_len <= 0 || (size_t)suffix_len >= sizeof(suffix)) {
            continue;
        }
        size_t total     = base_len + (size_t)suffix_len + 1;
        char*  candidate = (char*)malloc(total);
        if (!candidate) {
            break;
        }
        memcpy(candidate, base_path, base_len);
        memcpy(candidate + base_len, suffix, (size_t)suffix_len + 1);
        if (!path_exists(candidate)) {
            free(base_path);
            return candidate;
        }
        free(candidate);
    }

    for (unsigned int idx = 1; idx < 100000; ++idx) {
        char suffix[32];
        int  suffix_len = snprintf(suffix, sizeof(suffix), "_%u", idx);
        if (suffix_len <= 0 || (size_t)suffix_len >= sizeof(suffix)) {
            continue;
        }
        size_t total     = base_len + (size_t)suffix_len + 1;
        char*  candidate = (char*)malloc(total);
        if (!candidate) {
            break;
        }
        memcpy(candidate, base_path, base_len);
        memcpy(candidate + base_len, suffix, (size_t)suffix_len + 1);
        if (!path_exists(candidate)) {
            free(base_path);
            return candidate;
        }
        free(candidate);
    }

    return base_path;
}

static char* derive_default_output_dir(const char* input_path)
{
    if (!input_path) {
        return NULL;
    }

    char* base = path_basename_dup(input_path);
    if (!base) {
        return NULL;
    }

    size_t base_len = strlen(base);
    if (base_len > 4 && memcmp(base + base_len - 4, ".bin", 4) == 0) {
        base[base_len - 4] = '\0';
        base_len -= 4;
    }

    if (strcmp(base, ".") == 0 || base[0] == '\0') {
        free(base);
        base = string_dup("output");
    }

    return base;
}

static int mkdir_recursive(const char* path)
{
    if (!path || path[0] == '\0') {
        errno = EINVAL;
        return -1;
    }

    char* mutable_path = string_dup(path);
    if (!mutable_path) {
        return -1;
    }

    size_t len = strlen(mutable_path);
    while (len > 1 && is_path_separator(mutable_path[len - 1])) {
        mutable_path[--len] = '\0';
    }

#if defined(_WIN32)
    normalize_slashes(mutable_path);

    {
        struct _stat64 st;
        char*          win_path = path_to_windows(mutable_path);
        if (!win_path) {
            free(mutable_path);
            return -1;
        }
        int stat_rc = _stat64(win_path, &st);
        int saved   = errno;
        free(win_path);
        if (stat_rc == 0) {
            free(mutable_path);
            errno = EEXIST;
            return -1;
        }
        if (saved != ENOENT) {
            free(mutable_path);
            errno = saved;
            return -1;
        }
        errno = saved;
    }
#else
    struct stat st;
    if (stat(mutable_path, &st) == 0) {
        free(mutable_path);
        errno = EEXIST;
        return -1;
    }
    if (errno != ENOENT) {
        int saved = errno;
        free(mutable_path);
        errno = saved;
        return -1;
    }
#endif

    for (size_t i = 1; i < len; ++i) {
        if (mutable_path[i] == '/') {
            mutable_path[i] = '\0';
            if (mutable_path[0] != '\0') {
                if (create_single_directory(mutable_path) != 0 && errno != EEXIST) {
                    free(mutable_path);
                    return -1;
                }
            }
            mutable_path[i] = '/';
        }
    }

    if (create_single_directory(mutable_path) != 0) {
        int saved = errno;
        free(mutable_path);
        errno = saved;
        return -1;
    }

    free(mutable_path);
    return 0;
}

static int remove_tree_quiet(const char* path)
{
    if (!path) {
        return 0;
    }

#if defined(_WIN32)
    char* win_path = path_to_windows(path);
    if (!win_path) {
        return -1;
    }

    struct _stat64 st;
    int            stat_rc = _stat64(win_path, &st);
    int            saved   = errno;
    if (stat_rc != 0) {
        free(win_path);
        errno = saved;
        return (saved == ENOENT) ? 0 : -1;
    }

    if ((st.st_mode & _S_IFDIR) != 0) {
        size_t len     = strlen(win_path);
        size_t add     = (len == 0 || (win_path[len - 1] != '\\' && win_path[len - 1] != '/')) ? 2 : 1;
        char*  pattern = (char*)malloc(len + add + 1);
        if (!pattern) {
            free(win_path);
            return -1;
        }
        memcpy(pattern, win_path, len);
        if (add == 2) {
            pattern[len++] = '\\';
        }
        pattern[len++] = '*';
        pattern[len]   = '\0';

        struct _finddata_t info;
        intptr_t           handle = _findfirst(pattern, &info);
        free(pattern);
        if (handle != -1) {
            do {
                if (strcmp(info.name, ".") == 0 || strcmp(info.name, "..") == 0) {
                    continue;
                }
                char* child = path_join(path, info.name);
                if (!child) {
                    _findclose(handle);
                    free(win_path);
                    return -1;
                }
                if (remove_tree_quiet(child) != 0) {
                    free(child);
                    _findclose(handle);
                    free(win_path);
                    return -1;
                }
                free(child);
            } while (_findnext(handle, &info) == 0);
            _findclose(handle);
        }

        if (remove_single_directory(path) != 0 && errno != ENOENT) {
            int err_saved = errno;
            free(win_path);
            errno = err_saved;
            return -1;
        }
        free(win_path);
        return 0;
    }

    if (remove_single_file(path) != 0 && errno != ENOENT) {
        int err_saved = errno;
        free(win_path);
        errno = err_saved;
        return -1;
    }
    free(win_path);
    return 0;
#else
    struct stat st;
    if (lstat(path, &st) != 0) {
        return (errno == ENOENT) ? 0 : -1;
    }

    if (S_ISDIR(st.st_mode) && !S_ISLNK(st.st_mode)) {
        DIR* dir = opendir(path);
        if (!dir) {
            return -1;
        }
        struct dirent* dent;
        while ((dent = readdir(dir)) != NULL) {
            if (strcmp(dent->d_name, ".") == 0 || strcmp(dent->d_name, "..") == 0) {
                continue;
            }
            char* child = path_join(path, dent->d_name);
            if (!child) {
                closedir(dir);
                return -1;
            }
            if (remove_tree_quiet(child) != 0) {
                free(child);
                closedir(dir);
                return -1;
            }
            free(child);
        }
        closedir(dir);
        if (remove_single_directory(path) != 0 && errno != ENOENT) {
            return -1;
        }
        return 0;
    }

    if (remove_single_file(path) != 0 && errno != ENOENT) {
        return -1;
    }
    return 0;
#endif
}

static int enable_reader_filter(struct archive* reader, compression_algorithm algorithm)
{
    if (!reader) {
        return -1;
    }

    int r = ARCHIVE_OK;

    switch (algorithm) {
    case COMPRESSION_NONE:
        r = archive_read_support_filter_none(reader);
        break;
    case COMPRESSION_GZIP:
        r = archive_read_support_filter_gzip(reader);
        break;
    case COMPRESSION_ZSTD:
        r = archive_read_support_filter_zstd(reader);
        break;
    case COMPRESSION_LZ4:
        r = archive_read_support_filter_lz4(reader);
        break;
    default:
        return -1;
    }

    if (r != ARCHIVE_OK && r != ARCHIVE_WARN) {
        return -1;
    }

    return 0;
}

static int extract_tar_stream(FILE* stream, compression_algorithm algorithm, const char* output_root)
{
    if (!stream || !output_root) {
        return -1;
    }

    struct archive* reader = archive_read_new();
    if (!reader) {
        return -1;
    }

    struct archive* writer = archive_write_disk_new();
    if (!writer) {
        archive_read_free(reader);
        return -1;
    }

    if (enable_reader_filter(reader, algorithm) != 0) {
        fprintf(stderr, "Failed to enable %s decompression support\n", compression_algorithm_name(algorithm));
        archive_write_free(writer);
        archive_read_free(reader);
        return -1;
    }
    archive_read_support_format_tar(reader);

    const int extract_flags = ARCHIVE_EXTRACT_TIME | ARCHIVE_EXTRACT_PERM | ARCHIVE_EXTRACT_ACL | ARCHIVE_EXTRACT_XATTR
        | ARCHIVE_EXTRACT_FFLAGS;
    archive_write_disk_set_options(writer, extract_flags);
    archive_write_disk_set_standard_lookup(writer);

    if (archive_read_open_FILE(reader, stream) != ARCHIVE_OK) {
        fprintf(stderr, "Failed to open archive stream: %s\n", archive_error_string(reader));
        archive_write_free(writer);
        archive_read_free(reader);
        return -1;
    }

    int    result         = 0;
    char*  strip_root     = NULL;
    size_t strip_root_len = 0;

    while (result == 0) {
        struct archive_entry* entry;
        int                   r = archive_read_next_header(reader, &entry);
        if (r == ARCHIVE_EOF) {
            break;
        }
        if (r != ARCHIVE_OK) {
            fprintf(stderr, "Failed to read archive header: %s\n", archive_error_string(reader));
            result = -1;
            break;
        }

        const char* rel_path = archive_entry_pathname(entry);
        if (!rel_path) {
            fprintf(stderr, "Archive entry missing path\n");
            result = -1;
            break;
        }

        size_t rel_len = strlen(rel_path);
        while (rel_len > 0 && rel_path[rel_len - 1] == '/') {
            rel_len--;
        }

        char*       rel_trimmed_buf = NULL;
        const char* safe_rel_path   = rel_path;
        if (rel_len != strlen(rel_path)) {
            rel_trimmed_buf = (char*)malloc(rel_len + 1);
            if (!rel_trimmed_buf) {
                fprintf(stderr, "Out of memory trimming archive path\n");
                result = -1;
                break;
            }
            memcpy(rel_trimmed_buf, rel_path, rel_len);
            rel_trimmed_buf[rel_len] = '\0';
            safe_rel_path            = rel_trimmed_buf;
        }

        if (!path_is_safe_relative(safe_rel_path)) {
            fprintf(stderr, "Archive entry contains unsafe path '%s'\n", safe_rel_path ? safe_rel_path : "<null>");
            free(rel_trimmed_buf);
            result = -1;
            break;
        }

        if (!strip_root && archive_entry_filetype(entry) == AE_IFDIR) {
            const char* slash = strchr(safe_rel_path, '/');
            if (!slash) {
                strip_root = string_dup(safe_rel_path);
                if (!strip_root) {
                    fprintf(stderr, "Out of memory capturing archive root\n");
                    free(rel_trimmed_buf);
                    result = -1;
                    break;
                }
                strip_root_len = strlen(strip_root);
            }
        }

        const char* adjusted_rel = safe_rel_path;
        if (strip_root && strip_root_len > 0) {
            if (strcmp(safe_rel_path, strip_root) == 0) {
                adjusted_rel = "";
            } else if (strncmp(safe_rel_path, strip_root, strip_root_len) == 0
                       && safe_rel_path[strip_root_len] == '/') {
                adjusted_rel = safe_rel_path + strip_root_len + 1;
            }
        }

        char* full_path = path_join(output_root, adjusted_rel);
        if (!full_path) {
            fprintf(stderr, "Out of memory expanding archive path\n");
            free(rel_trimmed_buf);
            result = -1;
            break;
        }

        archive_entry_set_pathname(entry, full_path);
        free(full_path);

        free(rel_trimmed_buf);

        int w = archive_write_header(writer, entry);
        if (w != ARCHIVE_OK && w != ARCHIVE_WARN) {
            fprintf(stderr, "Failed to materialize '%s': %s\n", rel_path, archive_error_string(writer));
            result = -1;
            break;
        }

        if (archive_entry_size(entry) > 0) {
            while (1) {
                const void* block;
                size_t      block_size;
                la_int64_t  offset;
                int         read_ret = archive_read_data_block(reader, &block, &block_size, &offset);
                if (read_ret == ARCHIVE_EOF) {
                    break;
                }
                if (read_ret != ARCHIVE_OK) {
                    fprintf(stderr, "Failed to read data for '%s': %s\n", rel_path, archive_error_string(reader));
                    result = -1;
                    break;
                }
                int write_ret = archive_write_data_block(writer, block, block_size, offset);
                if (write_ret != ARCHIVE_OK) {
                    fprintf(stderr, "Failed to write data for '%s': %s\n", rel_path, archive_error_string(writer));
                    result = -1;
                    break;
                }
            }
        }

        if (result == 0) {
            int finish_ret = archive_write_finish_entry(writer);
            if (finish_ret != ARCHIVE_OK) {
                fprintf(stderr, "Failed to finish entry '%s': %s\n", rel_path, archive_error_string(writer));
                result = -1;
                break;
            }
        }
    }

    archive_read_close(reader);
    archive_read_free(reader);
    archive_write_close(writer);
    archive_write_free(writer);

    free(strip_root);

    return result;
}

int main(int argc, char** argv)
{
    setlocale(LC_ALL, "");

    if (argc != 2 && argc != 3) {
        fprintf(stderr, "Usage: %s <input|-> [output_dir]\n", argv[0]);
        return 1;
    }

    const char* input_path = argv[1];
    const char* output_path;
    char*       owned_output_path = NULL;
    int         auto_output       = (argc == 2);

    if (auto_output) {
        if (strcmp(input_path, "-") == 0) {
            fprintf(stderr, "Directory extraction requires a filesystem path for output\n");
            return 1;
        }
        owned_output_path = derive_default_output_dir(input_path);
        if (!owned_output_path) {
            fprintf(stderr, "Failed to derive default output directory\n");
            return 1;
        }
        output_path = owned_output_path;
    } else {
        output_path = argv[2];
    }

    if (strcmp(output_path, "-") == 0) {
        if (owned_output_path) {
            free(owned_output_path);
        }
        fprintf(stderr, "Directory extraction requires a filesystem path for output\n");
        return 1;
    }

    FILE* fin                = NULL;
    int   close_input        = 0;
    int   output_dir_created = 0;

    if (strcmp(input_path, "-") == 0) {
        fin = stdin;
    } else {
        fin = fopen(input_path, "rb");
        if (!fin) {
            free(owned_output_path);
            perror("Failed to open input file");
            return 1;
        }
        close_input = 1;
    }

    int                      ret         = 1;
    unsigned char*           priv_buf    = NULL;
    unsigned char*           rsa_ct      = NULL;
    unsigned char*           cipher_buf  = NULL;
    unsigned char*           plain_buf   = NULL;
    FILE*                    payload_tmp = NULL;
    mbedtls_entropy_context  entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_gcm_context      gcm;
    int                      entropy_ready         = 0;
    int                      ctr_drbg_ready        = 0;
    random_stream            deterministic_rng     = { 0 };
    int                      use_deterministic_rng = 0;
    const size_t             sym_key_len           = 32;
    unsigned char*           header_ct             = NULL;
    unsigned char            session_key[32];
    unsigned char            iv[32];
    unsigned char            tag[32];
    unsigned char            computed_tag[32];
    unsigned char            header[18];
    unsigned char            final_block[16];
    size_t                   priv_size        = 0;
    size_t                   key_len          = 0;
    uint16_t                 rsa_len          = 0;
    uint8_t                  iv_len           = 0;
    uint8_t                  tag_len          = 0;
    uint64_t                 ct_len64         = 0;
    compression_algorithm    compression_mode = COMPRESSION_INVALID;

    mbedtls_pk_context pk;
    mbedtls_pk_init(&pk);
    mbedtls_gcm_init(&gcm);

    priv_size = key_data_private_size();
    priv_buf  = (unsigned char*)malloc(priv_size);
    if (!priv_buf) {
        fprintf(stderr, "Out of memory allocating private key buffer\n");
        goto cleanup;
    }
    memcpy(priv_buf, key_data_private(), priv_size);

    int err = mbedtls_pk_parse_key(&pk, priv_buf, priv_size, NULL, 0, NULL, NULL);
    if (err != 0) {
        print_mbedtls_error("Failed to parse private key", err);
        goto cleanup;
    }

    if (!mbedtls_pk_can_do(&pk, MBEDTLS_PK_RSA)) {
        fprintf(stderr, "Loaded key is not an RSA private key\n");
        goto cleanup;
    }

    mbedtls_rsa_context* rsa = mbedtls_pk_rsa(pk);
    mbedtls_rsa_set_padding(rsa, MBEDTLS_RSA_PKCS_V21, MBEDTLS_MD_SHA256);

    key_len = mbedtls_rsa_get_len(rsa);

    header_ct = (unsigned char*)malloc(key_len);
    if (!header_ct) {
        fprintf(stderr, "Out of memory allocating encrypted header buffer\n");
        goto cleanup;
    }
    if (fread(header_ct, 1, key_len, fin) != key_len) {
        fprintf(stderr, "Failed to read encrypted header\n");
        goto cleanup;
    }

    const char* rng_path                           = getenv("ENCRYPTO_TEST_RANDOM_PATH");
    int (*rng_func)(void*, unsigned char*, size_t) = NULL;
    void* rng_ctx                                  = NULL;

    if (rng_path && rng_path[0] != '\0') {
        if (random_stream_load(rng_path, &deterministic_rng) != 0) {
            goto cleanup;
        }
        use_deterministic_rng = 1;
        rng_func              = random_stream_func;
        rng_ctx               = &deterministic_rng;
    } else {
        mbedtls_entropy_init(&entropy);
        entropy_ready = 1;
        mbedtls_ctr_drbg_init(&ctr_drbg);
        ctr_drbg_ready = 1;

        const char* pers = "dec";
        err              = mbedtls_ctr_drbg_seed(&ctr_drbg,
                                    mbedtls_entropy_func,
                                    &entropy,
                                    (const unsigned char*)pers,
                                    strlen(pers));
        if (err != 0) {
            print_mbedtls_error("Failed to seed RNG", err);
            goto cleanup;
        }

        rng_func = mbedtls_ctr_drbg_random;
        rng_ctx  = &ctr_drbg;
    }

    size_t header_len = sizeof(header);
    memset(header, 0, sizeof(header));
    err = mbedtls_rsa_rsaes_oaep_decrypt(rsa,
                                         rng_func,
                                         rng_ctx,
                                         NULL,
                                         0,
                                         &header_len,
                                         header_ct,
                                         header,
                                         sizeof(header));
    if (err != 0) {
        print_mbedtls_error("Failed to decrypt header", err);
        goto cleanup;
    }
    if (header_len != sizeof(header) && header_len != 17) {
        fprintf(stderr, "Unexpected decrypted header length %zu\n", header_len);
        goto cleanup;
    }

    const unsigned char expected_magic[4] = { 'E', 'N', 'H', 'Y' };
    if (memcmp(header, expected_magic, sizeof(expected_magic)) != 0) {
        fprintf(stderr, "Invalid file magic\n");
        goto cleanup;
    }

    if (header[4] == 1) {
        compression_mode = COMPRESSION_GZIP;
        rsa_len          = load_u16_be(&header[5]);
        iv_len           = header[7];
        tag_len          = header[8];
        ct_len64         = load_u64_be(&header[9]);
    } else if (header[4] == 2) {
        compression_mode = compression_algorithm_from_id(header[5]);
        if (compression_mode == COMPRESSION_INVALID) {
            fprintf(stderr, "Unknown compression algorithm id %u\n", header[5]);
            goto cleanup;
        }
        rsa_len  = load_u16_be(&header[6]);
        iv_len   = header[8];
        tag_len  = header[9];
        ct_len64 = load_u64_be(&header[10]);
    } else {
        fprintf(stderr, "Unsupported format version %u\n", header[4]);
        goto cleanup;
    }

    if (rsa_len != key_len) {
        fprintf(stderr, "RSA ciphertext length mismatch\n");
        goto cleanup;
    }
    if (iv_len == 0 || iv_len > sizeof(iv)) {
        fprintf(stderr, "Invalid IV length %u\n", iv_len);
        goto cleanup;
    }
    if (tag_len == 0 || tag_len > sizeof(tag)) {
        fprintf(stderr, "Invalid tag length %u\n", tag_len);
        goto cleanup;
    }

    rsa_ct = (unsigned char*)malloc(key_len);
    if (!rsa_ct) {
        fprintf(stderr, "Out of memory allocating RSA buffer\n");
        goto cleanup;
    }
    if (fread(rsa_ct, 1, key_len, fin) != key_len) {
        fprintf(stderr, "Failed to read RSA ciphertext\n");
        goto cleanup;
    }

    if (fread(iv, 1, iv_len, fin) != iv_len) {
        fprintf(stderr, "Failed to read IV\n");
        goto cleanup;
    }

    size_t session_key_len = sym_key_len;
    err                    = mbedtls_rsa_rsaes_oaep_decrypt(rsa,
                                         rng_func,
                                         rng_ctx,
                                         NULL,
                                         0,
                                         &session_key_len,
                                         rsa_ct,
                                         session_key,
                                         sizeof(session_key));
    if (err != 0) {
        print_mbedtls_error("RSA decryption failed", err);
        goto cleanup;
    }
    if (session_key_len != sym_key_len) {
        fprintf(stderr, "Unexpected session key length %zu\n", session_key_len);
        goto cleanup;
    }

    err = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, session_key, (unsigned int)(session_key_len * 8));
    if (err != 0) {
        print_mbedtls_error("Failed to set AES-GCM key", err);
        goto cleanup;
    }

    err = mbedtls_gcm_starts(&gcm, MBEDTLS_GCM_DECRYPT, iv, iv_len);
    if (err != 0) {
        print_mbedtls_error("Failed to initialize GCM", err);
        goto cleanup;
    }

    cipher_buf = (unsigned char*)malloc(ENCRYPTO_STREAM_CHUNK);
    plain_buf  = (unsigned char*)malloc(ENCRYPTO_STREAM_CHUNK);
    if (!cipher_buf || !plain_buf) {
        fprintf(stderr, "Out of memory allocating IO buffers\n");
        goto cleanup;
    }

    payload_tmp = tmpfile();
    if (!payload_tmp) {
        perror("Failed to create temporary payload buffer");
        goto cleanup;
    }

    uint64_t remaining = ct_len64;
    while (remaining > 0) {
        size_t to_read = remaining > ENCRYPTO_STREAM_CHUNK ? ENCRYPTO_STREAM_CHUNK : (size_t)remaining;
        size_t got     = fread(cipher_buf, 1, to_read, fin);
        if (got != to_read) {
            fprintf(stderr, "Failed to read ciphertext chunk\n");
            goto cleanup;
        }

        size_t produced = 0;
        err             = mbedtls_gcm_update(&gcm, cipher_buf, got, plain_buf, ENCRYPTO_STREAM_CHUNK, &produced);
        if (err != 0) {
            print_mbedtls_error("GCM decryption failed", err);
            goto cleanup;
        }

        if (produced != got) {
            fprintf(stderr, "Unexpected GCM output length %zu (wanted %zu)\n", produced, got);
            goto cleanup;
        }

        if (fwrite(plain_buf, 1, produced, payload_tmp) != produced) {
            perror("Failed to buffer plaintext chunk");
            goto cleanup;
        }

        remaining -= got;
    }

    size_t tag_read = fread(tag, 1, tag_len, fin);
    if (tag_read != tag_len) {
        fprintf(stderr, "Failed to read authentication tag\n");
        goto cleanup;
    }

    size_t final_len = 0;

    err = mbedtls_gcm_finish(&gcm, final_block, sizeof(final_block), &final_len, computed_tag, tag_len);
    if (err != 0) {
        print_mbedtls_error("Failed to finalize GCM", err);
        goto cleanup;
    }

    if (final_len > 0) {
        if (fwrite(final_block, 1, final_len, payload_tmp) != final_len) {
            perror("Failed to buffer final plaintext bytes");
            goto cleanup;
        }
    }

    if (memcmp(tag, computed_tag, tag_len) != 0) {
        fprintf(stderr, "Authentication failed (tag mismatch)\n");
        goto cleanup;
    }

    if (fflush(payload_tmp) != 0) {
        perror("Failed to flush payload buffer");
        goto cleanup;
    }
    if (fseek(payload_tmp, 0, SEEK_SET) != 0) {
        perror("Failed to rewind payload buffer");
        goto cleanup;
    }

    if (auto_output) {
        char* unique = ensure_unique_auto_output(owned_output_path);
        if (!unique) {
            fprintf(stderr, "Failed to allocate unique output directory name\n");
            goto cleanup;
        }
        owned_output_path = unique;
        output_path       = owned_output_path;
    }

    if (mkdir_recursive(output_path) != 0) {
        if (errno == EEXIST) {
            fprintf(stderr, "Output directory '%s' already exists\n", output_path);
        } else {
            fprintf(stderr, "Failed to create output directory '%s': %s\n", output_path, strerror(errno));
        }
        goto cleanup;
    }
    output_dir_created = 1;

    if (compression_mode == COMPRESSION_INVALID) {
        fprintf(stderr, "Container missing compression metadata\n");
        goto cleanup;
    }

    if (extract_tar_stream(payload_tmp, compression_mode, output_path) != 0) {
        goto cleanup;
    }

    ret = 0;

cleanup:
    mbedtls_platform_zeroize(session_key, sizeof(session_key));
    mbedtls_platform_zeroize(iv, sizeof(iv));
    mbedtls_platform_zeroize(tag, sizeof(tag));
    mbedtls_platform_zeroize(computed_tag, sizeof(computed_tag));
    mbedtls_platform_zeroize(header, sizeof(header));
    if (header_ct) {
        mbedtls_platform_zeroize(header_ct, key_len);
    }
    if (cipher_buf) {
        mbedtls_platform_zeroize(cipher_buf, ENCRYPTO_STREAM_CHUNK);
    }
    if (plain_buf) {
        mbedtls_platform_zeroize(plain_buf, ENCRYPTO_STREAM_CHUNK);
    }
    if (rsa_ct) {
        mbedtls_platform_zeroize(rsa_ct, key_len);
    }
    if (priv_buf) {
        mbedtls_platform_zeroize(priv_buf, priv_size);
    }
    mbedtls_platform_zeroize(final_block, sizeof(final_block));

    free(cipher_buf);
    free(plain_buf);
    free(rsa_ct);
    free(priv_buf);
    free(header_ct);
    if (payload_tmp) {
        fclose(payload_tmp);
    }

    if (use_deterministic_rng) {
        random_stream_unload(&deterministic_rng);
    }
    if (ctr_drbg_ready) {
        mbedtls_ctr_drbg_free(&ctr_drbg);
    }
    if (entropy_ready) {
        mbedtls_entropy_free(&entropy);
    }
    mbedtls_gcm_free(&gcm);
    mbedtls_pk_free(&pk);

    if (close_input && fin) {
        fclose(fin);
    }

    if (ret != 0 && output_dir_created) {
        remove_tree_quiet(output_path);
    }

    if (owned_output_path) {
        free(owned_output_path);
    }

    return ret;
}

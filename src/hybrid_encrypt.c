#if !defined(_WIN32)
#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE 700
#endif
#endif

#include <ctype.h>
#include <errno.h>
#include <locale.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#include "win_dirent.h"
#include <BaseTsd.h>
#include <direct.h>
#include <io.h>
#include <process.h>
#include <windows.h>

typedef SSIZE_T ssize_t;
#define lstat(path, buf) stat(path, buf)
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

static void print_mbedtls_error(const char* label, int code);

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

static int rng_bytes(int (*rng_func)(void*, unsigned char*, size_t), void* rng_ctx, unsigned char* out, size_t len)
{
    if (!rng_func || !out || len == 0) {
        return 0;
    }
    int err = rng_func(rng_ctx, out, len);
    if (err != 0) {
        return err;
    }
    return 0;
}

static void store_u16_be(unsigned char* dst, uint16_t value)
{
    dst[0] = (unsigned char)((value >> 8) & 0xFF);
    dst[1] = (unsigned char)(value & 0xFF);
}

static void store_u64_be(unsigned char* dst, uint64_t value)
{
    for (int i = 0; i < 8; ++i) {
        dst[i] = (unsigned char)((value >> (56 - 8 * i)) & 0xFF);
    }
}

typedef enum compression_algorithm {
    COMPRESSION_NONE    = 0,
    COMPRESSION_GZIP    = 1,
    COMPRESSION_ZSTD    = 2,
    COMPRESSION_LZ4     = 3,
    COMPRESSION_LZOP    = 4,
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
    case COMPRESSION_LZOP:
        return "lzop";
    default:
        return "invalid";
    }
}

static int strings_equal_icase(const char* a, const char* b)
{
    if (!a || !b) {
        return 0;
    }
    while (*a != '\0' && *b != '\0') {
        if (tolower((unsigned char)*a) != tolower((unsigned char)*b)) {
            return 0;
        }
        ++a;
        ++b;
    }
    return *a == '\0' && *b == '\0';
}

static int parse_compression_algorithm(const char* value, compression_algorithm* out)
{
    if (!out) {
        return -1;
    }
    if (!value || value[0] == '\0') {
        *out = COMPRESSION_LZ4;
        return 0;
    }

    if (strings_equal_icase(value, "none")) {
        *out = COMPRESSION_NONE;
        return 0;
    }
    if (strings_equal_icase(value, "gzip") || strings_equal_icase(value, "gz")) {
        *out = COMPRESSION_GZIP;
        return 0;
    }
    if (strings_equal_icase(value, "zstd") || strings_equal_icase(value, "zst")) {
        *out = COMPRESSION_ZSTD;
        return 0;
    }
    if (strings_equal_icase(value, "lz4")) {
        *out = COMPRESSION_LZ4;
        return 0;
    }
    if (strings_equal_icase(value, "lzop") || strings_equal_icase(value, "lzo")) {
        *out = COMPRESSION_LZOP;
        return 0;
    }

    return -1;
}

static int compression_algorithm_to_id(compression_algorithm algo)
{
    switch (algo) {
    case COMPRESSION_NONE:
        return 0;
    case COMPRESSION_GZIP:
        return 1;
    case COMPRESSION_ZSTD:
        return 2;
    case COMPRESSION_LZ4:
        return 3;
    case COMPRESSION_LZOP:
        return 4;
    default:
        return -1;
    }
}

static int configure_archive_filter(struct archive* writer, compression_algorithm algo)
{
    if (!writer) {
        return -1;
    }

    int r = ARCHIVE_OK;

    switch (algo) {
    case COMPRESSION_NONE:
        r = archive_write_add_filter_none(writer);
        break;
    case COMPRESSION_GZIP:
        r = archive_write_add_filter_gzip(writer);
        if (r == ARCHIVE_OK || r == ARCHIVE_WARN) {
            int opt_r = archive_write_set_filter_option(writer, "gzip", "timestamp", "0");
            if (opt_r != ARCHIVE_OK && opt_r != ARCHIVE_WARN) {
                return -1;
            }
            opt_r = archive_write_set_options(writer, "gzip:timestamp=0");
            if (opt_r != ARCHIVE_OK && opt_r != ARCHIVE_WARN) {
                return -1;
            }
        }
        break;
    case COMPRESSION_ZSTD:
        r = archive_write_add_filter_zstd(writer);
        if (r == ARCHIVE_OK || r == ARCHIVE_WARN) {
            archive_write_set_filter_option(writer, "zstd", "compression-level", "-3");
            archive_write_set_filter_option(writer, "zstd", "threads", "0");
        }
        break;
    case COMPRESSION_LZ4:
        r = archive_write_add_filter_lz4(writer);
        if (r == ARCHIVE_OK || r == ARCHIVE_WARN) {
            archive_write_set_filter_option(writer, "lz4", "compression-level", "1");
        }
        break;
    case COMPRESSION_LZOP:
        r = archive_write_add_filter_lzop(writer);
        if (r == ARCHIVE_OK || r == ARCHIVE_WARN) {
            archive_write_set_filter_option(writer, "lzop", "compression-level", "1");
        }
        break;
    default:
        return -1;
    }

    if (r != ARCHIVE_OK && r != ARCHIVE_WARN) {
        return -1;
    }

    return 0;
}

typedef struct archive_gcm_sink {
    mbedtls_gcm_context*  gcm;
    FILE*                 payload_stream;
    unsigned char*        out_buf;
    unsigned char*        patch_buf;
    size_t                gzip_header_bytes;
    uint64_t              total_written;
    compression_algorithm compression_mode;
} archive_gcm_sink;

static la_ssize_t archive_write_cb(struct archive* ar, void* client_data, const void* buffer, size_t length)
{
    (void)ar;
    if (!client_data || !buffer || length == 0) {
        return (la_ssize_t)length;
    }

    archive_gcm_sink* sink = (archive_gcm_sink*)client_data;

    size_t offset = 0;
    while (offset < length) {
        size_t chunk = length - offset;
        if (chunk > ENCRYPTO_STREAM_CHUNK) {
            chunk = ENCRYPTO_STREAM_CHUNK;
        }
        const unsigned char* chunk_src = (const unsigned char*)buffer + offset;
        if (sink->compression_mode == COMPRESSION_GZIP && sink->gzip_header_bytes < 10 && sink->patch_buf) {
            memcpy(sink->patch_buf, chunk_src, chunk);
            size_t remaining_header = 10 - sink->gzip_header_bytes;
            if (remaining_header > chunk) {
                remaining_header = chunk;
            }
            for (size_t i = 0; i < remaining_header; ++i) {
                size_t global_pos = sink->gzip_header_bytes + i;
                if (global_pos >= 4 && global_pos <= 7) {
                    sink->patch_buf[i] = 0;
                } else if (global_pos == 9) {
                    sink->patch_buf[i] = 3;
                }
            }
            chunk_src = sink->patch_buf;
            sink->gzip_header_bytes += remaining_header;
        }

        size_t produced = 0;
        int    err = mbedtls_gcm_update(sink->gcm, chunk_src, chunk, sink->out_buf, ENCRYPTO_STREAM_CHUNK, &produced);
        if (err != 0) {
            print_mbedtls_error("GCM encryption failed", err);
            return ARCHIVE_FATAL;
        }
        if (produced != chunk) {
            fprintf(stderr, "Unexpected GCM output length %zu (wanted %zu)\n", produced, chunk);
            return ARCHIVE_FATAL;
        }
        if (fwrite(sink->out_buf, 1, produced, sink->payload_stream) != produced) {
            perror("Failed to write ciphertext");
            return ARCHIVE_FATAL;
        }
        sink->total_written += produced;
        offset += chunk;
    }

    return (la_ssize_t)length;
}

static int archive_close_cb(struct archive* ar, void* client_data)
{
    (void)ar;
    (void)client_data;
    return ARCHIVE_OK;
}

static int is_path_separator(char ch)
{
#if defined(_WIN32)
    return ch == '/' || ch == '\\';
#else
    return ch == '/';
#endif
}

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

static int string_compare(const void* lhs, const void* rhs)
{
    const char* const* a = (const char* const*)lhs;
    const char* const* b = (const char* const*)rhs;
    return strcmp(*a, *b);
}

static int archive_add_path(struct archive* archive,
                            const char*     source_path,
                            const char*     rel_path,
                            unsigned char*  io_buf,
                            size_t          io_buf_len)
{
    if (!archive || !source_path || !rel_path) {
        return -1;
    }

    struct stat st;
    if (lstat(source_path, &st) != 0) {
        fprintf(stderr, "Failed to stat '%s': %s\n", source_path, strerror(errno));
        return -1;
    }

    struct archive_entry* entry = archive_entry_new();
    if (!entry) {
        fprintf(stderr, "Out of memory allocating archive entry\n");
        return -1;
    }

    archive_entry_set_pathname(entry, rel_path);
    archive_entry_copy_stat(entry, &st);
    archive_entry_set_size(entry, S_ISREG(st.st_mode) ? st.st_size : 0);

#if defined(_WIN32)
    if (S_ISLNK(st.st_mode)) {
        archive_entry_free(entry);
        fprintf(stderr, "Symbolic links are not supported on this platform: '%s'\n", source_path);
        return -1;
    }
#else
    if (S_ISLNK(st.st_mode)) {
        size_t target_len = st.st_size > 0 ? (size_t)st.st_size + 1 : 256;
        char*  target     = (char*)malloc(target_len);
        if (!target) {
            archive_entry_free(entry);
            fprintf(stderr, "Out of memory allocating symlink target buffer\n");
            return -1;
        }
        ssize_t read_len = readlink(source_path, target, target_len - 1);
        if (read_len < 0) {
            fprintf(stderr, "Failed to read symlink '%s': %s\n", source_path, strerror(errno));
            free(target);
            archive_entry_free(entry);
            return -1;
        }
        target[read_len] = '\0';
        archive_entry_set_symlink(entry, target);
        free(target);
    }
#endif

    int r = archive_write_header(archive, entry);
    if (r != ARCHIVE_OK) {
        fprintf(stderr, "Failed to write archive header for '%s': %s\n", rel_path, archive_error_string(archive));
        archive_entry_free(entry);
        return -1;
    }

    int  result = 0;
    DIR* dir    = NULL;
    int  is_dir = S_ISDIR(st.st_mode);

    if (S_ISREG(st.st_mode)) {
        FILE* fp = fopen(source_path, "rb");
        if (!fp) {
            fprintf(stderr, "Failed to open '%s' for reading: %s\n", source_path, strerror(errno));
            archive_entry_free(entry);
            return -1;
        }
        while (1) {
            size_t read_bytes = fread(io_buf, 1, io_buf_len, fp);
            if (read_bytes > 0) {
                const unsigned char* cursor    = io_buf;
                size_t               remaining = read_bytes;
                while (remaining > 0) {
                    ssize_t written = archive_write_data(archive, cursor, remaining);
                    if (written < 0) {
                        fprintf(stderr, "Failed to write data for '%s': %s\n", rel_path, archive_error_string(archive));
                        result = -1;
                        break;
                    }
                    cursor += (size_t)written;
                    remaining -= (size_t)written;
                }
            }

            if (ferror(fp)) {
                fprintf(stderr, "Failed to read '%s': %s\n", source_path, strerror(errno));
                result = -1;
            }

            if (result != 0 || feof(fp)) {
                break;
            }
        }
        fclose(fp);
    } else if (is_dir) {
        dir = opendir(source_path);
        if (!dir) {
            fprintf(stderr, "Failed to open directory '%s': %s\n", source_path, strerror(errno));
            archive_entry_free(entry);
            return -1;
        }
    } else if (S_ISCHR(st.st_mode) || S_ISBLK(st.st_mode) || S_ISFIFO(st.st_mode) || S_ISSOCK(st.st_mode)) {
        fprintf(stderr, "Unsupported file type for '%s'\n", source_path);
        archive_entry_free(entry);
        return -1;
    }

    if (result == 0) {
        int finish_err = archive_write_finish_entry(archive);
        if (finish_err != ARCHIVE_OK) {
            fprintf(stderr, "Failed to finish archive entry '%s': %s\n", rel_path, archive_error_string(archive));
            result = -1;
        }
    }

    if (dir) {
        struct dirent* dent;
        char**         names    = NULL;
        size_t         count    = 0;
        size_t         capacity = 0;

        while (result == 0 && (dent = readdir(dir)) != NULL) {
            if (strcmp(dent->d_name, ".") == 0 || strcmp(dent->d_name, "..") == 0) {
                continue;
            }
            if (count == capacity) {
                size_t new_capacity = capacity == 0 ? 16 : capacity * 2;
                char** tmp          = (char**)realloc(names, new_capacity * sizeof(char*));
                if (!tmp) {
                    result = -1;
                    break;
                }
                names    = tmp;
                capacity = new_capacity;
            }
            names[count] = string_dup(dent->d_name);
            if (!names[count]) {
                result = -1;
                break;
            }
            count++;
        }
        closedir(dir);

        if (result == 0) {
            qsort(names, count, sizeof(char*), string_compare);
            for (size_t i = 0; i < count; ++i) {
                char* child_rel  = path_join(rel_path, names[i]);
                char* child_path = path_join(source_path, names[i]);
                if (!child_rel || !child_path) {
                    free(child_rel);
                    free(child_path);
                    fprintf(stderr, "Out of memory expanding directory path\n");
                    result = -1;
                    break;
                }
                if (archive_add_path(archive, child_path, child_rel, io_buf, io_buf_len) != 0) {
                    result = -1;
                    free(child_rel);
                    free(child_path);
                    break;
                }
                free(child_rel);
                free(child_path);
            }
        }

        for (size_t i = 0; i < count; ++i) {
            free(names[i]);
        }
        free(names);
    }

    archive_entry_free(entry);
    return result;
}

static char* derive_default_output_path(const char* input_path)
{
    if (!input_path) {
        return NULL;
    }

    char* base = path_basename_dup(input_path);
    if (!base) {
        return NULL;
    }

    if (strcmp(base, ".") == 0 || base[0] == '\0') {
        free(base);
        base = string_dup("output");
        if (!base) {
            return NULL;
        }
    }

    size_t base_len = strlen(base);
    size_t total    = base_len + 4 + 1;
    char*  out      = (char*)malloc(total);
    if (!out) {
        free(base);
        return NULL;
    }

    memcpy(out, base, base_len);
    memcpy(out + base_len, ".bin", 5);

    free(base);
    return out;
}

int main(int argc, char** argv)
{
    setlocale(LC_ALL, "");

    if (argc != 2 && argc != 3) {
        fprintf(stderr, "Usage: %s <input_path> [output_path|-]\n", argv[0]);
        return 1;
    }

    const char* input_path = argv[1];
    const char* output_path;
    char*       owned_output_path = NULL;

    if (argc == 2) {
        if (strcmp(input_path, "-") == 0) {
            fprintf(stderr, "Streaming input '-' is not supported when compression is enabled\n");
            return 1;
        }
        owned_output_path = derive_default_output_path(input_path);
        if (!owned_output_path) {
            fprintf(stderr, "Failed to derive default output path\n");
            return 1;
        }
        output_path = owned_output_path;
    } else {
        output_path = argv[2];
    }

    FILE*                 fout            = NULL;
    FILE*                 payload_stream  = NULL;
    FILE*                 payload_tmp     = NULL;
    int                   close_output    = 0;
    int                   using_spool     = 0;
    int                   output_seekable = 0;
    struct archive*       archive_writer  = NULL;
    char*                 archive_root    = NULL;
    compression_algorithm compression_mode;

    if (strcmp(input_path, "-") == 0) {
        free(owned_output_path);
        fprintf(stderr, "Streaming input '-' is not supported when compression is enabled\n");
        return 1;
    }

    struct stat input_stat;
    if (lstat(input_path, &input_stat) != 0) {
        free(owned_output_path);
        perror("Failed to stat input path");
        return 1;
    }

    if (!S_ISREG(input_stat.st_mode) && !S_ISDIR(input_stat.st_mode) && !S_ISLNK(input_stat.st_mode)) {
        free(owned_output_path);
        fprintf(stderr, "Unsupported input type for '%s'\n", input_path);
        return 1;
    }

    const char* compression_env = getenv("ENCRYPTO_COMPRESSION");
    if (parse_compression_algorithm(compression_env, &compression_mode) != 0) {
        fprintf(stderr, "Unknown compression algorithm '%s'\n", compression_env ? compression_env : "");
        free(owned_output_path);
        return 1;
    }

    if (strcmp(output_path, "-") == 0) {
        fout = stdout;
    } else {
        fout = fopen(output_path, "wb+");
        if (!fout) {
            free(owned_output_path);
            perror("Failed to open output file");
            return 1;
        }
        close_output = 1;
    }

    if (fout != stdout && fseek(fout, 0, SEEK_CUR) == 0) {
        output_seekable = 1;
    }

    if (!output_seekable) {
        // Buffer payload when output stream cannot be rewound (e.g. stdout or a pipe).
        payload_tmp = tmpfile();
        if (!payload_tmp) {
            perror("Failed to create temporary payload buffer");
            if (close_output) {
                fclose(fout);
            }
            free(owned_output_path);
            return 1;
        }
        payload_stream = payload_tmp;
        using_spool    = 1;
    } else {
        payload_stream = fout;
    }

    int                      ret       = 1;
    unsigned char*           pub_buf   = NULL;
    unsigned char*           rsa_ct    = NULL;
    unsigned char*           header_ct = NULL;
    mbedtls_entropy_context  entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_gcm_context      gcm;
    int                      entropy_ready         = 0;
    int                      ctr_drbg_ready        = 0;
    random_stream            deterministic_rng     = { 0 };
    int                      use_deterministic_rng = 0;
    const size_t             sym_key_len           = 32;
    const size_t             iv_len                = 12;
    const size_t             tag_len               = 16;
    const unsigned char      header_magic[4]       = { 'E', 'N', 'H', 'Y' };
    const unsigned char      header_version        = 2;
    unsigned char            session_key[32];
    unsigned char            iv[12];
    unsigned char            tag[16];
    unsigned char            header[18];
    unsigned char            final_block[16];
    unsigned char*           in_buf    = NULL;
    unsigned char*           out_buf   = NULL;
    unsigned char*           patch_buf = NULL;
    archive_gcm_sink         sink;

    mbedtls_pk_context pk;
    mbedtls_pk_init(&pk);
    mbedtls_gcm_init(&gcm);

    size_t pub_size = key_data_public_size();
    pub_buf         = (unsigned char*)malloc(pub_size);
    if (!pub_buf) {
        fprintf(stderr, "Out of memory allocating public key buffer\n");
        goto cleanup;
    }
    memcpy(pub_buf, key_data_public(), pub_size);

    int err = mbedtls_pk_parse_public_key(&pk, pub_buf, pub_size);
    if (err != 0) {
        print_mbedtls_error("Failed to parse public key", err);
        goto cleanup;
    }

    if (!mbedtls_pk_can_do(&pk, MBEDTLS_PK_RSA)) {
        fprintf(stderr, "Loaded key is not an RSA public key\n");
        goto cleanup;
    }

    mbedtls_rsa_context* rsa = mbedtls_pk_rsa(pk);
    mbedtls_rsa_set_padding(rsa, MBEDTLS_RSA_PKCS_V21, MBEDTLS_MD_SHA256);

    const mbedtls_md_info_t* md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (!md_info) {
        fprintf(stderr, "Failed to obtain hash info for OAEP padding\n");
        goto cleanup;
    }

    size_t key_len    = mbedtls_rsa_get_len(rsa);
    size_t oaep_limit = key_len - 2 * mbedtls_md_get_size(md_info) - 2;
    if (sym_key_len > oaep_limit) {
        fprintf(stderr, "Symmetric key length exceeds OAEP capacity\n");
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

        const char* pers = "enc";
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

    if ((err = rng_bytes(rng_func, rng_ctx, session_key, sym_key_len)) != 0) {
        print_mbedtls_error("Failed to generate session key", err);
        goto cleanup;
    }
    if ((err = rng_bytes(rng_func, rng_ctx, iv, iv_len)) != 0) {
        print_mbedtls_error("Failed to generate IV", err);
        goto cleanup;
    }

    rsa_ct = (unsigned char*)malloc(key_len);
    if (!rsa_ct) {
        fprintf(stderr, "Out of memory allocating RSA ciphertext buffer\n");
        goto cleanup;
    }

    err = mbedtls_rsa_rsaes_oaep_encrypt(rsa, rng_func, rng_ctx, NULL, 0, sym_key_len, session_key, rsa_ct);
    if (err != 0) {
        print_mbedtls_error("RSA encryption of session key failed", err);
        goto cleanup;
    }

    err = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, session_key, (unsigned int)(sym_key_len * 8));
    if (err != 0) {
        print_mbedtls_error("Failed to set AES-GCM key", err);
        goto cleanup;
    }

    err = mbedtls_gcm_starts(&gcm, MBEDTLS_GCM_ENCRYPT, iv, iv_len);
    if (err != 0) {
        print_mbedtls_error("Failed to initialize GCM", err);
        goto cleanup;
    }

    header_ct = (unsigned char*)calloc(1, key_len);
    in_buf    = (unsigned char*)malloc(ENCRYPTO_STREAM_CHUNK);
    out_buf   = (unsigned char*)malloc(ENCRYPTO_STREAM_CHUNK);
    if (!header_ct || !in_buf || !out_buf) {
        fprintf(stderr, "Out of memory allocating IO buffers\n");
        goto cleanup;
    }
    if (compression_mode == COMPRESSION_GZIP) {
        patch_buf = (unsigned char*)malloc(ENCRYPTO_STREAM_CHUNK);
        if (!patch_buf) {
            fprintf(stderr, "Out of memory allocating gzip patch buffer\n");
            goto cleanup;
        }
    }

    if (output_seekable) {
        memset(header_ct, 0, key_len);
        if (fwrite(header_ct, 1, key_len, fout) != key_len) {
            perror("Failed to reserve encrypted header space");
            goto cleanup;
        }
    }

    int compression_id = compression_algorithm_to_id(compression_mode);
    if (compression_id < 0) {
        fprintf(stderr, "Failed to encode compression algorithm\n");
        goto cleanup;
    }

    memset(header, 0, sizeof(header));
    memcpy(header, header_magic, sizeof(header_magic));
    header[4] = header_version;
    header[5] = (unsigned char)compression_id;
    store_u16_be(&header[6], (uint16_t)key_len);
    header[8] = (unsigned char)iv_len;
    header[9] = (unsigned char)tag_len;
    store_u64_be(&header[10], 0);

    if (fwrite(rsa_ct, 1, key_len, payload_stream) != key_len) {
        perror("Failed to write RSA ciphertext");
        goto cleanup;
    }

    if (fwrite(iv, 1, iv_len, payload_stream) != iv_len) {
        perror("Failed to write IV");
        goto cleanup;
    }

    memset(&sink, 0, sizeof(sink));
    sink.gcm               = &gcm;
    sink.payload_stream    = payload_stream;
    sink.out_buf           = out_buf;
    sink.patch_buf         = patch_buf;
    sink.gzip_header_bytes = 0;
    sink.total_written     = 0;
    sink.compression_mode  = compression_mode;

    archive_writer = archive_write_new();
    if (!archive_writer) {
        fprintf(stderr, "Failed to create archive writer\n");
        goto cleanup;
    }

    if (configure_archive_filter(archive_writer, compression_mode) != 0) {
        const char* err_msg = archive_error_string(archive_writer);
        fprintf(stderr,
                "Failed to configure %s compression%s%s\n",
                compression_algorithm_name(compression_mode),
                err_msg ? ": " : "",
                err_msg ? err_msg : "");
        goto cleanup;
    }
    if (archive_write_set_bytes_per_block(archive_writer, 0) != ARCHIVE_OK) {
        fprintf(stderr, "Failed to configure archive block size: %s\n", archive_error_string(archive_writer));
        goto cleanup;
    }
    if (archive_write_set_bytes_in_last_block(archive_writer, 1) != ARCHIVE_OK) {
        fprintf(stderr, "Failed to disable archive padding: %s\n", archive_error_string(archive_writer));
        goto cleanup;
    }
    if (archive_write_set_format_pax_restricted(archive_writer) != ARCHIVE_OK) {
        fprintf(stderr, "Failed to set archive format: %s\n", archive_error_string(archive_writer));
        goto cleanup;
    }
    if (archive_write_open(archive_writer, &sink, NULL, archive_write_cb, archive_close_cb) != ARCHIVE_OK) {
        fprintf(stderr, "Failed to open archive writer: %s\n", archive_error_string(archive_writer));
        goto cleanup;
    }

    archive_root = path_basename_dup(input_path);
    if (!archive_root) {
        fprintf(stderr, "Out of memory deriving archive root name\n");
        goto cleanup;
    }

    if (archive_add_path(archive_writer, input_path, archive_root, in_buf, ENCRYPTO_STREAM_CHUNK) != 0) {
        goto cleanup;
    }

    free(archive_root);
    archive_root = NULL;

    if (archive_write_close(archive_writer) != ARCHIVE_OK) {
        fprintf(stderr, "Failed to close archive writer: %s\n", archive_error_string(archive_writer));
        goto cleanup;
    }
    archive_write_free(archive_writer);
    archive_writer = NULL;

    uint64_t total_written = sink.total_written;

    size_t final_len = 0;

    err = mbedtls_gcm_finish(&gcm, final_block, sizeof(final_block), &final_len, tag, tag_len);
    if (err != 0) {
        print_mbedtls_error("Failed to finalize GCM", err);
        goto cleanup;
    }

    if (final_len > 0) {
        if (fwrite(final_block, 1, final_len, payload_stream) != final_len) {
            perror("Failed to write final ciphertext bytes");
            goto cleanup;
        }
        total_written += final_len;
    }

    if (fwrite(tag, 1, tag_len, payload_stream) != tag_len) {
        perror("Failed to write authentication tag");
        goto cleanup;
    }

    store_u64_be(&header[10], total_written);
    err = mbedtls_rsa_rsaes_oaep_encrypt(rsa, rng_func, rng_ctx, NULL, 0, sizeof(header), header, header_ct);
    if (err != 0) {
        print_mbedtls_error("RSA encryption of header failed", err);
        goto cleanup;
    }

    if (using_spool) {
        if (fflush(payload_stream) != 0) {
            perror("Failed to flush payload buffer");
            goto cleanup;
        }
        if (fwrite(header_ct, 1, key_len, fout) != key_len) {
            perror("Failed to write encrypted header");
            goto cleanup;
        }
        if (fflush(fout) != 0) {
            perror("Failed to flush output file");
            goto cleanup;
        }
        if (fseek(payload_stream, 0, SEEK_SET) != 0) {
            perror("Failed to rewind payload buffer");
            goto cleanup;
        }
        size_t read_bytes;
        while ((read_bytes = fread(out_buf, 1, ENCRYPTO_STREAM_CHUNK, payload_stream)) > 0) {
            if (fwrite(out_buf, 1, read_bytes, fout) != read_bytes) {
                perror("Failed to stream ciphertext");
                goto cleanup;
            }
        }
        if (ferror(payload_stream)) {
            fprintf(stderr, "Failed to read buffered payload\n");
            goto cleanup;
        }
    } else {
        if (fseek(fout, 0, SEEK_SET) != 0) {
            perror("Failed to seek for header rewrite");
            goto cleanup;
        }
        if (fwrite(header_ct, 1, key_len, fout) != key_len) {
            perror("Failed to write encrypted header");
            goto cleanup;
        }
    }

    if (fflush(fout) != 0) {
        perror("Failed to flush output file");
        goto cleanup;
    }

    ret = 0;

cleanup:
    mbedtls_platform_zeroize(session_key, sizeof(session_key));
    mbedtls_platform_zeroize(iv, sizeof(iv));
    mbedtls_platform_zeroize(tag, sizeof(tag));
    mbedtls_platform_zeroize(header, sizeof(header));
    mbedtls_platform_zeroize(final_block, sizeof(final_block));
    if (rsa_ct) {
        mbedtls_platform_zeroize(rsa_ct, key_len);
    }
    if (header_ct) {
        mbedtls_platform_zeroize(header_ct, key_len);
    }
    if (in_buf) {
        mbedtls_platform_zeroize(in_buf, ENCRYPTO_STREAM_CHUNK);
    }
    if (out_buf) {
        mbedtls_platform_zeroize(out_buf, ENCRYPTO_STREAM_CHUNK);
    }
    if (patch_buf) {
        mbedtls_platform_zeroize(patch_buf, ENCRYPTO_STREAM_CHUNK);
    }

    free(in_buf);
    free(out_buf);
    free(patch_buf);
    if (payload_tmp) {
        fclose(payload_tmp);
    }
    free(pub_buf);
    free(rsa_ct);
    free(header_ct);
    if (archive_writer) {
        archive_write_close(archive_writer);
        archive_write_free(archive_writer);
    }
    free(archive_root);

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

    if (close_output && fout) {
        fclose(fout);
    }

    if (ret != 0 && close_output) {
        remove(output_path);
    }

    free(owned_output_path);

    return ret;
}

#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE 700
#endif

#include <dirent.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

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

static char* path_join(const char* lhs, const char* rhs)
{
    size_t lhs_len    = lhs ? strlen(lhs) : 0;
    size_t rhs_len    = rhs ? strlen(rhs) : 0;
    size_t need_slash = (lhs_len > 0 && rhs_len > 0 && lhs[lhs_len - 1] != '/') ? 1 : 0;
    size_t total      = lhs_len + need_slash + rhs_len + 1;
    char*  out        = (char*)malloc(total);
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

static int mkdir_recursive(const char* path)
{
    if (!path || path[0] == '\0') {
        errno = EINVAL;
        return -1;
    }

    struct stat st;
    if (stat(path, &st) == 0) {
        errno = EEXIST;
        return -1;
    } else if (errno != ENOENT) {
        return -1;
    }

    char* mutable_path = string_dup(path);
    if (!mutable_path) {
        return -1;
    }

    size_t len = strlen(mutable_path);
    while (len > 1 && mutable_path[len - 1] == '/') {
        mutable_path[--len] = '\0';
    }

    for (size_t i = 1; i < len; ++i) {
        if (mutable_path[i] == '/') {
            mutable_path[i] = '\0';
            if (mutable_path[0] != '\0') {
                if (mkdir(mutable_path, 0755) != 0 && errno != EEXIST) {
                    free(mutable_path);
                    return -1;
                }
            }
            mutable_path[i] = '/';
        }
    }

    if (mkdir(mutable_path, 0755) != 0) {
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
        if (rmdir(path) != 0 && errno != ENOENT) {
            return -1;
        }
        return 0;
    }

    if (unlink(path) != 0 && errno != ENOENT) {
        return -1;
    }
    return 0;
}

static int extract_tar_gz(FILE* stream, const char* output_root)
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

    archive_read_support_filter_gzip(reader);
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

    int result = 0;

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
        if (!path_is_safe_relative(rel_path)) {
            fprintf(stderr, "Archive entry contains unsafe path '%s'\n", rel_path ? rel_path : "<null>");
            result = -1;
            break;
        }

        char* full_path = path_join(output_root, rel_path);
        if (!full_path) {
            fprintf(stderr, "Out of memory expanding archive path\n");
            result = -1;
            break;
        }

        archive_entry_set_pathname(entry, full_path);
        free(full_path);

        int w = archive_write_header(writer, entry);
        if (w != ARCHIVE_OK) {
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

    return result;
}

int main(int argc, char** argv)
{
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <input|-> <output_dir>\n", argv[0]);
        return 1;
    }

    const char* input_path  = argv[1];
    const char* output_path = argv[2];

    if (strcmp(output_path, "-") == 0) {
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
    unsigned char            header[17];
    unsigned char            final_block[16];
    size_t                   priv_size = 0;
    size_t                   key_len   = 0;
    uint16_t                 rsa_len   = 0;
    uint8_t                  iv_len    = 0;
    uint8_t                  tag_len   = 0;
    uint64_t                 ct_len64  = 0;

    mbedtls_pk_context pk;
    mbedtls_pk_init(&pk);
    mbedtls_gcm_init(&gcm);

    priv_size = key_data_private_size();
    priv_buf  = (unsigned char*)malloc(priv_size + 1);
    if (!priv_buf) {
        fprintf(stderr, "Out of memory allocating private key buffer\n");
        goto cleanup;
    }
    memcpy(priv_buf, key_data_private(), priv_size);
    priv_buf[priv_size] = '\0';

    int err = mbedtls_pk_parse_key(&pk, priv_buf, priv_size + 1, NULL, 0, NULL, NULL);
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
    err               = mbedtls_rsa_rsaes_oaep_decrypt(rsa,
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
    if (header_len != sizeof(header)) {
        fprintf(stderr, "Unexpected decrypted header length %zu\n", header_len);
        goto cleanup;
    }

    const unsigned char expected_magic[4] = { 'E', 'N', 'H', 'Y' };
    if (memcmp(header, expected_magic, sizeof(expected_magic)) != 0) {
        fprintf(stderr, "Invalid file magic\n");
        goto cleanup;
    }

    if (header[4] != 1) {
        fprintf(stderr, "Unsupported format version %u\n", header[4]);
        goto cleanup;
    }

    rsa_len  = load_u16_be(&header[5]);
    iv_len   = header[7];
    tag_len  = header[8];
    ct_len64 = load_u64_be(&header[9]);

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

    if (mkdir_recursive(output_path) != 0) {
        if (errno == EEXIST) {
            fprintf(stderr, "Output directory '%s' already exists\n", output_path);
        } else {
            fprintf(stderr, "Failed to create output directory '%s': %s\n", output_path, strerror(errno));
        }
        goto cleanup;
    }
    output_dir_created = 1;

    if (extract_tar_gz(payload_tmp, output_path) != 0) {
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

    return ret;
}

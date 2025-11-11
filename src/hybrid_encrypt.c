#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

int main(int argc, char** argv)
{
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <input|-> <output|->\n", argv[0]);
        return 1;
    }

    const char* input_path  = argv[1];
    const char* output_path = argv[2];

    FILE* fin             = NULL;
    FILE* fout            = NULL;
    FILE* payload_stream  = NULL;
    FILE* payload_tmp     = NULL;
    int   close_input     = 0;
    int   close_output    = 0;
    int   using_spool     = 0;
    int   output_seekable = 0;

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

    if (strcmp(output_path, "-") == 0) {
        fout = stdout;
    } else {
        fout = fopen(output_path, "wb+");
        if (!fout) {
            perror("Failed to open output file");
            if (close_input) {
                fclose(fin);
            }
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
            if (close_input) {
                fclose(fin);
            }
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
    const size_t             chunk_size            = 64 * 1024;
    const unsigned char      header_magic[4]       = { 'E', 'N', 'H', 'Y' };
    const unsigned char      header_version        = 1;
    unsigned char            session_key[32];
    unsigned char            iv[12];
    unsigned char            tag[16];
    unsigned char            header[17];
    unsigned char            final_block[16];
    unsigned char*           in_buf  = NULL;
    unsigned char*           out_buf = NULL;

    mbedtls_pk_context pk;
    mbedtls_pk_init(&pk);
    mbedtls_gcm_init(&gcm);

    size_t pub_size = key_data_public_size();
    pub_buf         = (unsigned char*)malloc(pub_size + 1);
    if (!pub_buf) {
        fprintf(stderr, "Out of memory allocating public key buffer\n");
        goto cleanup;
    }
    memcpy(pub_buf, key_data_public(), pub_size);
    pub_buf[pub_size] = '\0';

    int err = mbedtls_pk_parse_public_key(&pk, pub_buf, pub_size + 1);
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
    in_buf    = (unsigned char*)malloc(chunk_size);
    out_buf   = (unsigned char*)malloc(chunk_size);
    if (!header_ct || !in_buf || !out_buf) {
        fprintf(stderr, "Out of memory allocating IO buffers\n");
        goto cleanup;
    }

    if (output_seekable) {
        memset(header_ct, 0, key_len);
        if (fwrite(header_ct, 1, key_len, fout) != key_len) {
            perror("Failed to reserve encrypted header space");
            goto cleanup;
        }
    }

    memset(header, 0, sizeof(header));
    memcpy(header, header_magic, sizeof(header_magic));
    header[4] = header_version;
    store_u16_be(&header[5], (uint16_t)key_len);
    header[7] = (unsigned char)iv_len;
    header[8] = (unsigned char)tag_len;
    store_u64_be(&header[9], 0);

    if (fwrite(rsa_ct, 1, key_len, payload_stream) != key_len) {
        perror("Failed to write RSA ciphertext");
        goto cleanup;
    }

    if (fwrite(iv, 1, iv_len, payload_stream) != iv_len) {
        perror("Failed to write IV");
        goto cleanup;
    }

    uint64_t total_written = 0;
    size_t   read_bytes;
    while ((read_bytes = fread(in_buf, 1, chunk_size, fin)) > 0) {
        size_t produced = 0;
        err             = mbedtls_gcm_update(&gcm, in_buf, read_bytes, out_buf, chunk_size, &produced);
        if (err != 0) {
            print_mbedtls_error("GCM encryption failed", err);
            goto cleanup;
        }

        if (produced != read_bytes) {
            fprintf(stderr, "Unexpected GCM output length %zu (wanted %zu)\n", produced, read_bytes);
            goto cleanup;
        }

        if (fwrite(out_buf, 1, produced, payload_stream) != produced) {
            perror("Failed to write ciphertext");
            goto cleanup;
        }
        total_written += produced;
    }

    if (ferror(fin)) {
        perror("Failed to read input file");
        goto cleanup;
    }

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

    store_u64_be(&header[9], total_written);
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
        while ((read_bytes = fread(out_buf, 1, chunk_size, payload_stream)) > 0) {
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
        mbedtls_platform_zeroize(in_buf, chunk_size);
    }
    if (out_buf) {
        mbedtls_platform_zeroize(out_buf, chunk_size);
    }

    free(in_buf);
    free(out_buf);
    if (payload_tmp) {
        fclose(payload_tmp);
    }
    free(pub_buf);
    free(rsa_ct);
    free(header_ct);

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
    if (close_input && fin) {
        fclose(fin);
    }

    if (ret != 0 && close_output) {
        remove(output_path);
    }

    return ret;
}

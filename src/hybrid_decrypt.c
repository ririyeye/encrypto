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

int main(int argc, char** argv)
{
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <input> <output>\n", argv[0]);
        return 1;
    }

    const char* input_path  = argv[1];
    const char* output_path = argv[2];

    FILE* fin = fopen(input_path, "rb");
    if (!fin) {
        perror("Failed to open input file");
        return 1;
    }

    FILE* fout = fopen(output_path, "wb");
    if (!fout) {
        perror("Failed to open output file");
        fclose(fin);
        return 1;
    }

    int                      ret        = 1;
    unsigned char*           priv_buf   = NULL;
    unsigned char*           rsa_ct     = NULL;
    unsigned char*           cipher_buf = NULL;
    unsigned char*           plain_buf  = NULL;
    mbedtls_entropy_context  entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_gcm_context      gcm;
    int                      entropy_ready         = 0;
    int                      ctr_drbg_ready        = 0;
    random_stream            deterministic_rng     = { 0 };
    int                      use_deterministic_rng = 0;
    const size_t             sym_key_len           = 32;
    const size_t             chunk_size            = 64 * 1024;
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

        const char* pers = "hybrid_decrypt";
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

    cipher_buf = (unsigned char*)malloc(chunk_size);
    plain_buf  = (unsigned char*)malloc(chunk_size);
    if (!cipher_buf || !plain_buf) {
        fprintf(stderr, "Out of memory allocating IO buffers\n");
        goto cleanup;
    }

    uint64_t remaining = ct_len64;
    while (remaining > 0) {
        size_t to_read = remaining > chunk_size ? chunk_size : (size_t)remaining;
        size_t got     = fread(cipher_buf, 1, to_read, fin);
        if (got != to_read) {
            fprintf(stderr, "Failed to read ciphertext chunk\n");
            goto cleanup;
        }

        size_t produced = 0;
        err             = mbedtls_gcm_update(&gcm, cipher_buf, got, plain_buf, chunk_size, &produced);
        if (err != 0) {
            print_mbedtls_error("GCM decryption failed", err);
            goto cleanup;
        }

        if (produced != got) {
            fprintf(stderr, "Unexpected GCM output length %zu (wanted %zu)\n", produced, got);
            goto cleanup;
        }

        if (fwrite(plain_buf, 1, produced, fout) != produced) {
            perror("Failed to write plaintext chunk");
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
        if (fwrite(final_block, 1, final_len, fout) != final_len) {
            perror("Failed to write final plaintext bytes");
            goto cleanup;
        }
    }

    if (memcmp(tag, computed_tag, tag_len) != 0) {
        fprintf(stderr, "Authentication failed (tag mismatch)\n");
        goto cleanup;
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
    mbedtls_platform_zeroize(computed_tag, sizeof(computed_tag));
    mbedtls_platform_zeroize(header, sizeof(header));
    if (header_ct) {
        mbedtls_platform_zeroize(header_ct, key_len);
    }
    if (cipher_buf) {
        mbedtls_platform_zeroize(cipher_buf, chunk_size);
    }
    if (plain_buf) {
        mbedtls_platform_zeroize(plain_buf, chunk_size);
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

    if (fout) {
        fclose(fout);
    }
    if (fin) {
        fclose(fin);
    }

    if (ret != 0) {
        remove(output_path);
    }

    return ret;
}

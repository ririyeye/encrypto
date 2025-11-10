#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mbedtls/pk.h"
#include "mbedtls/rsa.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "mbedtls/md.h"
#include "mbedtls/error.h"

#include "key_data.h"

static void print_mbedtls_error(const char *label, int code)
{
    char buffer[256];
    mbedtls_strerror(code, buffer, sizeof(buffer));
    fprintf(stderr, "%s: %s\n", label, buffer);
}

int main(int argc, char **argv)
{
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <input> <output>\n", argv[0]);
        return 1;
    }

    const char *input_path = argv[1];
    const char *output_path = argv[2];

    FILE *fin = fopen(input_path, "rb");
    if (!fin) {
        perror("Failed to open input file");
        return 1;
    }

    FILE *fout = fopen(output_path, "wb");
    if (!fout) {
        perror("Failed to open output file");
        fclose(fin);
        return 1;
    }

    int ret = 1;
    unsigned char *priv_buf = NULL;
    unsigned char *in_buf = NULL;
    unsigned char *out_buf = NULL;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    int entropy_ready = 0;
    int ctr_drbg_ready = 0;

    mbedtls_pk_context pk;
    mbedtls_pk_init(&pk);

    size_t priv_size = key_data_private_size();
    priv_buf = (unsigned char *)malloc(priv_size + 1);
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

    mbedtls_rsa_context *rsa = mbedtls_pk_rsa(pk);
    mbedtls_rsa_set_padding(rsa, MBEDTLS_RSA_PKCS_V21, MBEDTLS_MD_SHA256);

    const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (!md_info) {
        fprintf(stderr, "Failed to obtain hash info for OAEP padding\n");
        goto cleanup;
    }
    size_t hash_len = mbedtls_md_get_size(md_info);
    size_t key_len = mbedtls_rsa_get_len(rsa);
    size_t chunk_size = key_len - 2 * hash_len - 2;

    if (chunk_size == 0) {
        fprintf(stderr, "Invalid chunk size computed from key parameters\n");
        goto cleanup;
    }

    in_buf = (unsigned char *)malloc(key_len);
    out_buf = (unsigned char *)malloc(chunk_size);
    if (!in_buf || !out_buf) {
        fprintf(stderr, "Out of memory allocating buffers\n");
        goto cleanup;
    }

    mbedtls_entropy_init(&entropy);
    entropy_ready = 1;
    mbedtls_ctr_drbg_init(&ctr_drbg);
    ctr_drbg_ready = 1;

    const char *pers = "rsa_decrypt";
    err = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                (const unsigned char *)pers, strlen(pers));
    if (err != 0) {
        print_mbedtls_error("Failed to seed RNG", err);
        goto cleanup;
    }

    size_t read_bytes;
    while ((read_bytes = fread(in_buf, 1, key_len, fin)) > 0) {
        if (read_bytes != key_len) {
            fprintf(stderr, "Ciphertext length is not a multiple of RSA block size\n");
            goto cleanup;
        }

        size_t output_len = chunk_size;
        err = mbedtls_rsa_rsaes_oaep_decrypt(rsa,
                             mbedtls_ctr_drbg_random,
                             &ctr_drbg,
                             NULL,
                             0,
                             &output_len,
                             in_buf,
                             out_buf,
                             chunk_size);
        if (err != 0) {
            print_mbedtls_error("RSA decryption failed", err);
            goto cleanup;
        }

        if (fwrite(out_buf, 1, output_len, fout) != output_len) {
            perror("Failed to write decrypted data");
            goto cleanup;
        }
    }

    if (ferror(fin)) {
        perror("Failed to read input file");
        goto cleanup;
    }

    ret = 0;

cleanup:
    if (ctr_drbg_ready) {
        mbedtls_ctr_drbg_free(&ctr_drbg);
    }
    if (entropy_ready) {
        mbedtls_entropy_free(&entropy);
    }
    if (fout) {
        if (fflush(fout) != 0) {
            perror("Failed to flush output file");
            ret = 1;
        }
        fclose(fout);
    }
    if (fin) {
        fclose(fin);
    }
    free(priv_buf);
    free(in_buf);
    free(out_buf);
    mbedtls_pk_free(&pk);

    return ret;
}

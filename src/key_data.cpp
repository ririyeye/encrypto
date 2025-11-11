#include <stddef.h>

#include "key_data.h"
#include "rsa_private_key.h"
#include "rsa_public_key.h"

const unsigned char *key_data_public(void)
{
    return g_rsa_public_key;
}

size_t key_data_public_size(void)
{
    return sizeof(g_rsa_public_key);
}

const unsigned char *key_data_private(void)
{
    return g_rsa_private_key;
}

size_t key_data_private_size(void)
{
    return sizeof(g_rsa_private_key);
}

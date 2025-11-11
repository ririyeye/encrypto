#ifndef KEY_DATA_H
#define KEY_DATA_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

const unsigned char *key_data_public(void);
size_t key_data_public_size(void);

const unsigned char *key_data_private(void);
size_t key_data_private_size(void);

#ifdef __cplusplus
}
#endif

#endif /* KEY_DATA_H */

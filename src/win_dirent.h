#ifndef ENCRYPTO_WIN_DIRENT_H
#define ENCRYPTO_WIN_DIRENT_H

#if defined(_WIN32)
#include <errno.h>
#include <io.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#ifndef NAME_MAX
#define NAME_MAX 260
#endif

struct dirent {
    char d_name[NAME_MAX + 1];
};

typedef struct DIR {
    intptr_t           handle;
    struct _finddata_t data;
    int                first;
    char*              pattern;
    struct dirent      entry;
} DIR;

static DIR* opendir(const char* dirname)
{
    if (!dirname) {
        errno = EINVAL;
        return NULL;
    }

    size_t len = strlen(dirname);
    size_t add = 2; // potentially path separator + '*'
    if (len > 0) {
        char last = dirname[len - 1];
        if (last == '/' || last == '\\') {
            add = 1; // only '*'
        }
    }

    char* pattern = (char*)malloc(len + add + 1);
    if (!pattern) {
        errno = ENOMEM;
        return NULL;
    }

    memcpy(pattern, dirname, len);
    for (size_t i = 0; i < len; ++i) {
        if (pattern[i] == '/') {
            pattern[i] = '\\';
        }
    }
    if (len == 0 || (pattern[len - 1] != '/' && pattern[len - 1] != '\\')) {
        pattern[len++] = '\\';
    }
    pattern[len++] = '*';
    pattern[len]   = '\0';

    DIR* dir = (DIR*)malloc(sizeof(DIR));
    if (!dir) {
        free(pattern);
        errno = ENOMEM;
        return NULL;
    }

    dir->handle = _findfirst(pattern, &dir->data);
    if (dir->handle == -1) {
        free(pattern);
        free(dir);
        return NULL;
    }

    dir->pattern         = pattern;
    dir->first           = 1;
    dir->entry.d_name[0] = '\0';
    return dir;
}

static int closedir(DIR* dirp)
{
    if (!dirp) {
        errno = EBADF;
        return -1;
    }

    int result = 0;
    if (dirp->handle != -1) {
        result = _findclose(dirp->handle);
    }
    free(dirp->pattern);
    free(dirp);
    return result;
}

static struct dirent* readdir(DIR* dirp)
{
    if (!dirp) {
        errno = EBADF;
        return NULL;
    }

    if (dirp->first) {
        dirp->first = 0;
    } else {
        if (_findnext(dirp->handle, &dirp->data) != 0) {
            return NULL;
        }
    }

    strncpy(dirp->entry.d_name, dirp->data.name, NAME_MAX);
    dirp->entry.d_name[NAME_MAX] = '\0';
    return &dirp->entry;
}

#endif // _WIN32

#endif // ENCRYPTO_WIN_DIRENT_H

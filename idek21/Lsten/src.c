#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <fcntl.h>

#define FILENAME "flag.txt"

struct dirent *readdir(DIR *dirp)
{
    void* handle = dlopen("libc.so.6",RTLD_LAZY);
    if(!handle) {
        printf("open failed\n");
        return;
    }
    struct dirent64 *(*orig_readdir)(DIR *dir);     
    
    orig_readdir = dlsym(handle,"readdir");
    if(!orig_readdir) {
        printf("readdir lookup failed\n");
        return;
    }

     return orig_readdir(dirp);
}
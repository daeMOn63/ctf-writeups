# Are you lsntening to me ???

```
docker pull kaligulasec/idekctf2021:are_you_lstening_to_me
```

We can start by listing recent modified files:

```
$ find / -maxdepth 10 -mtime -20 -mtime +1 -type f
/root/.issthissassecretfile.txt
/var/lib/apt/lists/archive.ubuntu.com_ubuntu_dists_focal-backports_main_binary-amd64_Packages.lz4
/var/lib/apt/lists/archive.ubuntu.com_ubuntu_dists_focal-backports_InRelease
/var/lib/apt/lists/archive.ubuntu.com_ubuntu_dists_focal-updates_multiverse_binary-amd64_Packages.lz4
/var/lib/apt/lists/security.ubuntu.com_ubuntu_dists_focal-security_universe_binary-amd64_Packages.lz4
/var/lib/apt/lists/security.ubuntu.com_ubuntu_dists_focal-security_main_binary-amd64_Packages.lz4
/var/lib/apt/lists/lock
/var/lib/apt/lists/archive.ubuntu.com_ubuntu_dists_focal-updates_InRelease
/var/lib/apt/lists/archive.ubuntu.com_ubuntu_dists_focal-backports_universe_binary-amd64_Packages.lz4
/var/lib/apt/lists/security.ubuntu.com_ubuntu_dists_focal-security_restricted_binary-amd64_Packages.lz4
/var/lib/apt/lists/archive.ubuntu.com_ubuntu_dists_focal-updates_main_binary-amd64_Packages.lz4
/var/lib/apt/lists/security.ubuntu.com_ubuntu_dists_focal-security_InRelease
/var/lib/apt/lists/archive.ubuntu.com_ubuntu_dists_focal-updates_universe_binary-amd64_Packages.lz4
/var/lib/apt/lists/archive.ubuntu.com_ubuntu_dists_focal-updates_restricted_binary-amd64_Packages.lz4
/usr/lib/x86_64-linux-gnu/lsten_closer.so
/usr/lib/x86_64-linux-gnu/fallen_paper.txt
```

We have: 

- /root/.issthissassecretfile.txt: a C source aimed to build a shared lib overwritting `readdir` and `readdir64`
- /usr/lib/x86_64-linux-gnu/fallen_paper.txt: obscure hint on flag location
- /usr/lib/x86_64-linux-gnu/lsten_closer.so: custom lib, seems to match the above sources with `FILENAME=flag.txt`

We also see that ls is linked against this lsten_closer.so:
```
$ ldd /usr/bin/ls
        linux-vdso.so.1 (0x00007ffff1fcf000)
        /usr/lib/x86_64-linux-gnu/lsten_closer.so (0x00007f0102351000)
        libselinux.so.1 => /lib/x86_64-linux-gnu/libselinux.so.1 (0x00007f0102323000)
        libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f0102131000)
        libdl.so.2 => /lib/x86_64-linux-gnu/libdl.so.2 (0x00007f010212b000)
        libpcre2-8.so.0 => /lib/x86_64-linux-gnu/libpcre2-8.so.0 (0x00007f010209b000)
        /lib64/ld-linux-x86-64.so.2 (0x00007f010237d000)
        libpthread.so.0 => /lib/x86_64-linux-gnu/libpthread.so.0 (0x00007f0102078000)
```

So from the sources, we can see that the readdir function is modified to exclude the entry if `filename == flag.txt`, so we can revert this with our own readdir implementation, where we'll call the original libc readdir:

```C
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
```

Build the shared lib:

```
gcc -c src.c -D_GNU_SOURCE
gcc -shared -lc -o src.so src.o 
```

Now we can:

```
LD_PRELOAD=/home/src.so ls -R / | grep -B 5 flag.txt
lastlog
wtmp

/var/log/apt:
eipp.log.xz
flag.txt
```

and we'll get a `/var/log/apt/flag.txt` listed, 

```
cat /var/log/apt/flag.txt
idek{1!br4r1Es_m4k3_5hhHh_H4pp3n}
```
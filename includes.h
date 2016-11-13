#include <linux/err.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>

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



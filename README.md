# CSE 509 Project: Rootkit

  After attackers manage to gain access to a remote (or local) machine and
  elevate their privileges to "root", they typically want to maintain their
  access, while hiding their presence from the normal users and administrators
  of the system.

  This basic rootkit works on the Linux operating system and is a loadable kernel
  module which when loaded into the kernel (by the attacker with root privileges)
  will do the following:

  1) Hide specific files and directories from showing up when a user does "ls" and similar commands
  2) Modify the /etc/passwd and /etc/shadow file to add a backdoor account while returning the
     original contents of the files (pre-attack) when a normal user requests to see the file
  3) Hides processes from the process table when a user does a "ps"
  4) Give the ability to a malicious process to elevate its uid to 0 (root) upon demand

# Authors
  Team: ROP like it's hot
  Members:
  Amit Bapat          
  Varun Sayal
  Leixiang Wu
  Poojitha Ponakala

# Requirements

## Operating system

   Linux Distro: Ubuntu 14.04 64 bit
   Kernel: 4.2.0-42-generic
   Rootkit has been tested on Ubuntu 14.04 64 bit. The command
   line instructions given in this document use GNU Bash syntax. If you are
   using a different shell (e.g., Windows 'cmd.exe' shell), please adjust the
   commands accordingly.

# Running Rootkit

  The Rootkit software consists of a module, a makefile, and test programs.
  Under normal circumstances, you do not need to compile the rootkit module directly,
  because you can type `make` command to automically compile the module if module needs
  to be recompiled.

## Enter rootkit directory

  In all following command, please replace `<ROOTKIT DIRECTORY>` with the path of the
  Rootkit directory (the directory containing this file).

  Type:

     cd <ROOTKIT DIRECTORY>

  Example:

     cd ~/CSE509-Rootkit

## Compile the module

   If you have entered rootkit directory, type `make`:

      make
   
   After `make` is done, you will see rootkit.ko output file is generated.
 
   Otherwise, enter the rootkit directory by using `cd` command and type `make`:

      cd <ROOTKIT DIRECTORY>
      make

## Load the Rootkit module into Kernel

   To load Rootkit module, run `sudo insmod`, passing a 'rootkit.ko'
   file as argument:

      sudo insmod rootkit.ko

   Note: sudo is necessary because it requires root privileges to load
   a module into kernel

   or call the `load_rootkit.sh` script:

      ./load_rootkit.sh
      
   The `load_rootkit.sh` script will compile the Rootkit module if it is
   necessary and load the module into kernel.

## Unload the Rootkit module from the Kernel

   If you wish to unload Rootkit module, `sudo rmmod`, passing a 'rootkit'
   as argument: 

      sudo rmmod rootkit
	
   Note: sudo is necessary because it requires root privileges to unload
   a module from the kernel

   or call the `unload_rootkit.sh` script:

      ./unload_rootkit.sh

## Clean the module

   If you have entered rootkit directory, type `make clean`:

      make clean
   
   After `make clean` is done, you will see rootkit.ko output file is removed.
 
   Otherwise, enter the rootkit directory by using `cd` command and type `make clean`:

      cd <ROOTKIT DIRECTORY>
      make clean

## Running Example

   This section assumes you have unzipped Rootkit and are in rootkit
   directory; otherwise, please go to Unzip section and Enter
   rootkit directory section.

   The following commands compiles and load the module:

       make
       sudo insmod rootkit.ko
       ps
       ls
       sudo rmmod rootkit

   After running the above commands before `sudo rmmod rootkit`, you should
   notice that some processes (ps) and files (rootkit.c) are hidden.

# How Rootkit Works
	1) Give the ability to a malicious process to elevate its uid to 0 (root) upon demand
	  - To give the ability for a malicious process to elevate its uid, it must call
        setuid with a "magic number" as the uid. This argument is a number that will
        not be called normally (12345 for this case). The setuid will then elevate the
        process and grant root privileges.

	2) Modify the /etc/passwd and /etc/shadow file to add a backdoor 
       account while returning the original contents of the files (
       pre-attack) when a normal user requests to see the file
      - When the module is loaded, backdoor account is added by modifying /
	    etc/passwd and /etc/shadow files if the backdoor is not present in 
        them already
      - The read syscall was hacked and modified such that the backdoor is 
        filtered out when the files /etc/passwd and /etc/shadow are read

    3) Hide certain files.
      - The getdents and open syscalls were hijacked so that any of the files provided 
        in the includes.h array (called HIDDEN_FILES) will not be returned by getdents. 
        In the case of open if one of our hidden files is an argument, we simply return -ENOENT

    4) Hide the module from lsmod. 
      - In the hijacked read, we simply remove the entry for our
        rootkit (named  "rookit"). Once this entry is removed from /proc/modules, lsmod will cease
        printing it. It is also removed from a regular cat of the file.

    5) Hides processes from the process table when a user does a "ps"
      - When a user issues 'ps' command, getdents system call is called to find all the directories
        inside of /proc/. The name of each directory that is in /proc/ is pid. When the rootkit module
        is loaded, getdents system call is hijacked so that any of the process matches a process
        name provided in the HIDDEN_PROCESSES includes.h array will be removed from getdents. Note in hijacked getdents, we find the process name by using pid number and check whether user typed ps
        or not by using fd argument of getdents.

# How to test Rootkit and modify Rootkit to hide additional things
    1) Give the ability to a malicious process to elevate its uid to 0 (root)
     - To test, run "make" in directory testPrograms. The program "setuid" will try to
       call setuid() with the supplied argument. With an unprivileged user, run setuid 0
       and it will fail. Next, run: setuid 12345 (where 12345 is the magic number) and 
       it will succeed and print out the current privileges.

    2) Modify the /etc/passwd and /etc/shadow file to add a backdoor 
       account while returning the original contents of the files (
       pre-attack) when a normal user requests to see the file
     - Check /etc/passwd and /etc/shadow before loading module for 
       the first time
     - Load the module and check the files with cat /etc/passwd or 
       /etc/shadow, or open the files in any text reader
     - The backdoor will be not be shown while the module is loaded 
     - Unload the module and check contents again to see the backdoor 
       now

    3) Hide certain files from "ls" and similar commands:
     - There is an array specified in includes.h. This array called HIDDEN_FILES has 
       a few different file names. Add whatever file you would like to test and load the module.
       Verify that this file can not be ls'd or opened.

    4) Hide the module from lsmod
     - Load the module and run lsmod. All other modules except "rootkit" will be displayed.
       You can also remove the function "remove rootkit" to check that lsmod would show it 
       otherwise.

    5) Hides processes from the process table when a user does a "ps"
     - There is an array specified in includes.h. This array called HIDDEN_PROCESSES has
       a few processes. Add whatever process you would like to hide(test) and load the module.
       Verify that the process is not in the output of ps.

# Resources

    Location of the ISO we used for testing:
    https://drive.google.com/drive/folders/0B6BjU_C8SKLtSFdNWHc2dHJGN0E?usp=sharing

    For figuring out how to intercept syscall table:
    http://stackoverflow.com/questions/2103315/linux-kernel-system-call-hooking-example
    http://books.gigatux.nl/mirror/networksecuritytools/0596007949/networkst-CHP-7-SECT-2.html

    Other:
    http://stackoverflow.com/questions/29451920/how-to-get-process-name-from-pid-using-c
    http://stackoverflow.com/questions/8250078/how-can-i-get-a-filename-from-a-file-descriptor-inside-a-kernel-module
    http://stackoverflow.com/questions/1184274/how-to-read-write-files-within-a-linux-kernel-module
    http://lxr.free-electrons.com/
    https://www.thc.org/papers/LKM_HACKING.html
    http://commons.oreilly.com/wiki/index.php/Network_Security_Tools/Modifying_and_Hacking_Security_Tools/Fun_with_Linux_Kernel_Modules

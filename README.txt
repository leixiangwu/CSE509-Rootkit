CSE 509 Project: Rootkit
Amit Bapat


Functionality:
1) Give the ability to a malicious process to elevate its uid to 0 (root) upon demand
 - To give the ability for a malicious process to elevate its uid, it must call
setuid with a "magic number" as the uid. This argument is a number that will
not be called normally (12345 for this case). The setuid will then elevate the
process and grant root privileges.



Testing:
1) Give the ability to a malicious process to elevate its uid to 0 (root)
- To test, run "make" in directory testPrograms. The program "setuid" will try to
call setuid() with the supplied argument. With an unprivileged user, run setuid 0
and it will fail. Next, run: setuid 12345 (where 12345 is the magic number) and 
it will succeed and print out the current privileges.


Resources:

For figuring out how to intercept syscall table:
http://stackoverflow.com/questions/2103315/linux-kernel-system-call-hooking-example


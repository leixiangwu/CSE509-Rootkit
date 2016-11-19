#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>

int main(int argc, char* argv[]) {
    if (argc <= 1) {
        printf("Not enough arguments\n");
        return 1;
    }

    int ret = setuid(atoi(argv[1]));
    if (ret) {
        perror("Seteuid failed");
    }

    printf("real user ID: %d, effective user ID: %d\n", getuid(), geteuid());

    return 0;
}

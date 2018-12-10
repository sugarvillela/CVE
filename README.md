# cve: A collection of code pertaining to CVE-2016-0728 (various authors)
* Excerpts from Linux, showing the evolution and fix of the bug
* Exploit code from Perception Point with added comments that explain what each line does.
* A short script that uses the leak to increment usage count, useful for determining whether the bug exists on your system.
* A version of the exploit that bypasses the syscall wrappers (for systems that don't implement the keycntl wrappers).
* The first emergency patch from January 2016
* The best way to duplicate this exploit is to find an affected version of a Linux build, Listed below. ISO's may contain back-ported patches, so you need to download the source code and compile it yourself.
* Running the exploit on a modern version of Ubuntu (edited to retain the bug) gave strange results.  I wrote test.c to track it, outputting to the keylog file. It prints values only when the usage is decrementing; where there is no output, the usage is incrementing.  There is no pattern to the changing slope, which means the exploit fails on a modern version, edited or not. Instead, compile a version from this list.

# Affected Versions
* Red Hat Enterprise Linux 7
* CentOS Linux 7
* Scientific Linux 7
* Debian Linux stable 8.x (jessie)
* Debian Linux testing 9.x (stretch)
* SUSE Linux Enterprise Desktop 12
* SUSE Linux Enterprise Desktop 12 SP1
* SUSE Linux Enterprise Server 12
* SUSE Linux Enterprise Server 12 SP1
* SUSE Linux Enterprise Workstation Extension 12
* SUSE Linux Enterprise Workstation Extension 12 SP1
* Ubuntu Linux 14.04 LTS (Trusty Tahr)
* Ubuntu Linux 15.04 (Vivid Vervet)
* Ubuntu Linux 15.10 (Wily Werewolf)
* Opensuse Linux LEAP 42.x and version 13.x
* Oracle Linux 7



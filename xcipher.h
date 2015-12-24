/* xcipher.h
 * Copyright (C) 2015 Mohit Goyal
 * 
 * xcipher is a header file which includes all the libraries 
 * used and verify the key for new line character.
 */

#include <openssl/md5.h>
#include <asm/unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <openssl/hmac.h>

#include "common.h"

/* xcrypt syscall number */
#define __NR_xcrpyt 359

/** 
 * @npwd: char string to store key after removing new line characater
 * return: the string after new line character removal
 *
 * Description:
 * 		Removing new line character from the key
 **/
char *verify_psswd (char *pwd) 
{
	int j = 0, k = 0;
	char *npwd;
	
	/* memory allocation for temp string */
	npwd = (char *) malloc (strlen(pwd) + 1);
	if (!npwd) {
		perror("Error: Memory allocation fail during key verification\n");
		goto out;
	}
	
	/* check for new line character */
	while (pwd[j]) {
		if (pwd[j] != '\n') {
			npwd[k] = pwd[j];
			k++;
		}
		j++;
	}
	npwd[k] = '\0';
	
	strncpy(pwd, npwd, k);
	free(npwd);
	return pwd;
	
	out:
		if (npwd)
			free(npwd);
		return NULL;
}

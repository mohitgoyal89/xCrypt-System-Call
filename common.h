/* common.h
 * Copyright (C) 2015 Mohit Goyal
 * 
 * common is header file which declares MACROS used 
 * and the structure of arguments to be used in encryption/decryption of files
 */

/* Macro for size of key to be used */
#define SIZE 16

/* Macro to enable debugging of code */
// #define DEBUG

/* Macro to enable extra credit */
#define EXTRA_CREDIT

/**
 * structure of arguments which will be from user land to kernel space
 **/
typedef struct args {
	int oflags;
	unsigned char *key;
	int keylen;
	char *infile;
	char *outfile;
	unsigned int blk_size;
}arguments;

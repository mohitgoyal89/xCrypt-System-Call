/* xcipher.c
 * Copyright (C) 2015 Mohit Goyal
 *
 * xcipher program is user program to encrypt or decrypt the file 
 * which will invoke sys_xcrypt syscall for the encryption/decryption
 */

#include "xcipher.h"

/**
 * options string to get user option
 **/
#ifdef EXTRA_CREDIT
static char *opt = "p:edhu:l:";
#else
static char *opt = "p:edh";
#endif

/**
 * main function which will invoke the system call to 
 * encryption/decryption of given file
 **/
int main (int argc, char *argv[])
{
	int op, rc;
	
	#ifdef EXTRA_CREDIT
	int ret = 0;
	/* salt value for encrypting key used in PKCS5 */
	char *salt = "layogtihommanoskapeedkitsawsqpzm"; 
	int saltlen = strlen(salt);
	unsigned int key_len;
	unsigned int blck_size;
	int iteration = 10000;
	int uflag = 0;
	int lflag = 0;
	#else
	unsigned char digest[MD5_DIGEST_LENGTH];
	#endif
	
	char *psswd = NULL, *verified_psswd;
	arguments params;
	
	/* option flags used for the user options */
	int hflag = 0;
	int eflag = 0;
	int dflag = 0;
	int pflag = 0;
	
	/* set default values */
	params.oflags = -1;
	params.keylen = -1;
	params.blk_size = -1;
	params.key = NULL;
	
	while ((op = getopt(argc, argv, opt)) != -1) {
		switch(op) {
			/* option 'p' for password */
			case 'p':
				pflag = 1;
				if((strlen(optarg) < 6)) {
					errno = EINVAL;
					perror("Error: Password length should be greater than 6\nError");
					goto out;
				}
				psswd = optarg;
				break;
			
			/* option 'e' for encryption */
			case 'e':
				eflag = 1;
				break;
				
			/* option 'd' for decryption */
			case 'd':
				dflag = 1;
				break;
				
			/* option 'h' for help */
			case 'h':
				hflag = 1;
				break;
				
			#ifdef EXTRA_CREDIT
			/* option 'u' for block size */
			case 'u':
				uflag = 1;
				blck_size = atoi(optarg);
				break;
				
			/* option 'l' for key length */
			case 'l':
				lflag = 1;
				key_len = atoi(optarg) >> 3;
				break;
			#endif
			
			default :
				if (!pflag) {
					errno = EINVAL;
					perror("Error: Syntax should be ./xcipher -p \"password\" -e infile outfile\nError");
					goto out;
				}
				errno = EINVAL;
				perror("Error: Wrong flags entered\nError");
				goto out;
		}			
	}
	
	/* printing the help message */
	if (hflag) {
		printf("usage:	xcipher is used for encryption or decryption of input file into output file\n");
		printf("	Syntax: ./xcipher -p \"key\" -e -c infile1 outfile\n");
		printf("	[-e: encrypt]  [-d: deencrypt]  [-p [arg: encryption/decryption key]]\n");
		printf("	[-c [arg: specify type of cipher]]\n");
		exit(0);
	}
	
	/* check whether both encryption and decryption option are provided by user */
	if ((eflag == 1) && (dflag == 1)) {
		errno = EINVAL;
		perror("Error: Both encryption & decryption options are given\nError");
		goto out;
	}
	
	/* check for correct user arguments are given */
	#ifdef EXTRA_CREDIT
	if (argc < 7) {
		if (!pflag) {
			errno = EINVAL;
			perror("Error: Password not entered\nError");
			goto out;
		}
		errno = EINVAL;
		perror("Error: Syntax should be ./xcipher -p \"password\" -u 16000 -l 256 -e infile outfile\nError");
		goto out;
	}
	else if (argc - optind < 2) {
		errno = EINVAL;
		perror("Error: Missing input or output filenames\nError");
		goto out;
	}
	#else
	if (argc < 4) {
		if (!pflag) {
			errno = EINVAL;
			perror("Error: Password not entered\nError");
			goto out;
		}
		errno = EINVAL;
		perror("Error: Syntax should be ./xcipher -p \"password\" -e infile outfile\nError");
		goto out;
	}
	else if (argc - optind < 2) {
		errno = EINVAL;
		perror("Error: Missing input or output filenames\nError");
		goto out;
	}
	#endif
	
	/* setting encryption flag */
	if (eflag == 1) {
		params.oflags = 1;
	}
	
	/* setting decryption flag */
	if (dflag == 1) {
		params.oflags = 0;
	}
	
	#ifdef EXTRA_CREDIT
	/* setting the block size used for encryption/decryption */
	if (uflag == 1) {
		params.blk_size = blck_size;
	}
	#endif
	
	/* check the password for new line character */
	verified_psswd = verify_psswd(psswd);
	
	#ifdef EXTRA_CREDIT
		/*
		 * PKCS5 encryption for encrypting the password
		 */
		params.key = (unsigned char*) malloc(key_len);
		params.keylen = key_len;
		ret = PKCS5_PBKDF2_HMAC_SHA1((const char *)verified_psswd, strlen(verified_psswd), 
							(unsigned char *)salt, saltlen, iteration, key_len, params.key);
		if(ret <= 0){
			printf("Error: Key encryption fail\nError");
			goto out;
		}
	#else
		/*
		 * MD5 encryption for encrypting the password
		 */
		params.key = (unsigned char*) malloc(SIZE);
		params.keylen = SIZE;
		MD5((unsigned char*)verified_psswd, strlen(verified_psswd), digest);
		memcpy(params.key, digest, SIZE);
	#endif
	
	/* setting infile and outfile */
	params.infile = argv[optind];
	params.outfile = argv[optind + 1];
	
	/* checking all the values for correctness while debugging */
	#ifdef DEBUG
	printf("oflags: %d\n", params.oflags);
	printf("key: %s\n", params.key);
	printf("keylen: %d\n", params.keylen);
	printf("infile: %s\n", params.infile);
	printf("outfile: %s\n", params.outfile);
	printf("blk_size: %u\n", params.blk_size);
	#endif
	
	void *dummy = (void *) (&params);
	
	/* invoking system call for encryption */
	rc = syscall(__NR_xcrpyt, dummy);
	
	if (rc == 0) {
		printf("syscall returned %d\n", rc);
	} 
	else {
		printf("syscall returned %d\n", rc);
		if (params.oflags) {
			perror("Error: Encyrption fail\nError");
		}
		else {
			perror("Error: Decyrption fail\nError");
		}
	}
	
	exit(rc);
	
	out:
		#ifdef DEBUG
		printf("errno: %d\n", errno);
		#endif
		/* memory deallocation */
		if(params.key != NULL) {
			free(params.key);
		}
		exit(errno);
}

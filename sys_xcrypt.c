/* sys_xcrypt.c
 * Copyright (C) 2015 Mohit Goyal
 *
 * sys_xcrypt is a system call which will encrypt and decrypt file
 * and do various validation checks for files and encryption/decryption key
 */

#include <linux/linkage.h>
#include <linux/moduleloader.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/crypto.h>
#include <linux/scatterlist.h>
#include <linux/stat.h>
#include <linux/namei.h>
#include <crypto/hash.h>
#include <crypto/md5.h>
#include <crypto/aes.h>
#include <linux/ctype.h>

#include "common.h"

/* default cipher initialization vector value */
#define CEPH_IV "aykahsmanostihom"

asmlinkage extern long (*sysptr)(void *arg);

/**
 * function to encrypt the buf using the key and initialization vector
 **/
int file_encryption (void *in_buf, int in_buf_len, void *out_buf, int *out_buf_len, 
					void *key, int keylen, long page_no, long f_ino) 
{
	int err = 0, ivsize;
	struct scatterlist in_sg[1], out_sg[1];
	void *iv = NULL;
	struct crypto_blkcipher *tfm = NULL;
	struct blkcipher_desc desc;
	
	#ifdef EXTRA_CREDIT
	void *ec_iv = NULL;
	int iv_bytes = 8;
	#endif
	
	/* setting the transformation */
	tfm = crypto_alloc_blkcipher("ctr(aes)", 0, CRYPTO_ALG_ASYNC);
	
	crypto_blkcipher_setkey(tfm, key, keylen);
	
	/* set descriptor's transformation and flags */
	desc.tfm = tfm;
	desc.flags = 0;
	
	if(!(desc.tfm) || IS_ERR(desc.tfm)){
		printk("Error: Fail to load transformation for encryption\n");
		err = -PTR_ERR(desc.tfm);
		goto out;
	}
	
	/* scatterlist initializations with in buf and out buf */
	sg_init_one(in_sg, in_buf, in_buf_len);
	sg_init_one(out_sg, out_buf, in_buf_len);
	
	iv = crypto_blkcipher_crt(tfm) -> iv;
	ivsize = crypto_blkcipher_ivsize(tfm);
	
	#ifdef DEBUG
	printk("page_no: %d\n", (int)page_no);
	printk("f_ino: %d\n", (int)f_ino);
	#endif
	
	/* set iv to page number and inode number */
	#ifdef EXTRA_CREDIT
	ec_iv = kzalloc(ivsize, __GFP_WAIT);
	memcpy((void *) ec_iv, (void *) &page_no, iv_bytes);
	memcpy((void *) ec_iv + iv_bytes, (void *) &f_ino, iv_bytes);
	memcpy(iv, ec_iv, ivsize);
	#else
	memcpy(iv, (u8 *)CEPH_IV, ivsize);
	#endif	
	
	err = crypto_blkcipher_encrypt(&desc, out_sg, in_sg, in_buf_len);
	*out_buf_len = in_buf_len;
	crypto_free_blkcipher(tfm);
	
	if(err < 0 ) {
		printk("Error: Encryption fail\n");
		err = -EFAULT;
		goto out;
	}
	
	out:
		return err;
}

/**
 * function to decrypt the buf using the key and initialization vector
 **/
int file_decryption (void *in_buf, int in_buf_len, void *out_buf, int *out_buf_len, 
					void *key, int keylen, long page_no, long f_ino) 
{
	int err = 0, ivsize;
	struct scatterlist in_sg[1], out_sg[1];
	void *iv = NULL;
	struct crypto_blkcipher *tfm;
	struct blkcipher_desc desc;
	
	#ifdef EXTRA_CREDIT
	void *ec_iv = NULL;
	int iv_bytes = 8;
	#endif
	
	/* setting the transformation */
	tfm = crypto_alloc_blkcipher("ctr(aes)", 0, CRYPTO_ALG_ASYNC);
	
	crypto_blkcipher_setkey((void*)tfm, key, keylen);
	
	/* set descriptors transformation and flags */
	desc.tfm = tfm;
	desc.flags = 0;
	
	if(!(desc.tfm) || IS_ERR(desc.tfm)){
		printk("Error: Fail to load transformation for decryption\n");
		err = -PTR_ERR(desc.tfm);
		goto out;
	}
	
	/* scatterlist initializations with in buf and out buf */
	sg_init_one(in_sg, in_buf, in_buf_len);
	sg_init_one(out_sg, out_buf, in_buf_len);
	
	iv = crypto_blkcipher_crt(tfm) -> iv;
	ivsize = crypto_blkcipher_ivsize(tfm);
	
	#ifdef DEBUG
	printk("page_no: %d\n", (int)page_no);
	printk("f_ino: %d\n", (int)f_ino);
	#endif
	
	/* set iv to page number and inode number */
	#ifdef EXTRA_CREDIT
	ec_iv = kzalloc(ivsize, __GFP_WAIT);
	memcpy((void *) ec_iv, (void *) &page_no, iv_bytes);
	memcpy((void *) ec_iv + iv_bytes, (void *) &f_ino, iv_bytes);
	memcpy(iv, ec_iv, ivsize);
	#else
	memcpy(iv, (u8 *)CEPH_IV, ivsize);
	#endif
	
	err = crypto_blkcipher_decrypt(&desc, out_sg, in_sg, in_buf_len);
	*out_buf_len = in_buf_len;
	crypto_free_blkcipher(tfm);
	
	if(err < 0 ) {
		printk("Error: Decryption fail\n");
		err = -EFAULT;
		goto out;
	}
	
	out:
		return err;
}

/**
 * function to hash the key using md5 encryption
 **/
int md5_encryption (unsigned char *in_buf, unsigned char *out_buf, int in_buf_len)
{
	int err = 0;
	struct scatterlist sg[1];
	
	struct crypto_hash *tfm;
	struct hash_desc desc;
	
	/* setting the transformation */
	tfm = crypto_alloc_hash("md5", 0, CRYPTO_ALG_ASYNC);
	
	desc.tfm = tfm;
	desc.flags = CRYPTO_TFM_REQ_MAY_SLEEP;
	
	if(!(desc.tfm)||IS_ERR(desc.tfm)){
		printk("Error: Fail to load transformation for encryption\n");
		err = -PTR_ERR(desc.tfm);
		goto out;
	}
	
	/* scatterlist initialization with in buf */
	sg_init_one(sg, in_buf, in_buf_len);
	
	err = crypto_hash_digest(&desc, sg, in_buf_len, out_buf);
	
	if (err < 0){
		printk("Error: Fail while hashing the key\n");
		err = -EFAULT;
		goto out;
	}
	
	out:
		return err;
}

/**
 * checking if the arguments passed to kernel from user are valid
 **/
int is_args_valid (void *userargs) 
{
	int err = 0;
	/* check for the validity of arguments */
	if((((struct args *) userargs)->infile == NULL) || (((struct args *) userargs)->outfile == NULL) 
				|| (((struct args *) userargs)->key == NULL) || (((struct args *) userargs)->keylen == 0)) {
		printk("Error: Arguments are not valid\n");
		err = -EINVAL;
		goto out;
	}
	
	out:
		return err;
}

/**
 * checking if the infile and outfile are valid
 * check for read and write permissions and if files are same
 **/
int is_files_valid (const char *infile, const char *outfile)
{
	int err = 0;
	struct file *infilp = NULL, *outfilp = NULL;
	
	infilp = filp_open(infile, O_RDONLY, 0);
	
	/* checks for validity of file */
	if (!infilp) {
		printk("Error: Infile does not exist\n");
		err = (int) PTR_ERR(infilp);
		goto out;
	}
	
	if (IS_ERR(infilp)) {
		printk("Error: Fail to open the infile\n");
		err = (int) PTR_ERR(infilp);
		goto out;
	}
	
	/* checks for read permission of file */
	if (!infilp -> f_op -> read) {
		printk("Error: Read not allowed by file system\n");
		err = -EACCES; 
		goto out;
	}
	
	if (!(infilp -> f_mode & FMODE_READ)) {
		printk("Error: Infile inaccessible to read\n");
		err = -EIO;
		goto out;
	}
	
	outfilp = filp_open(outfile, O_WRONLY | O_CREAT, 0);
	
	/* checks for validity of file */
	if (!outfilp) {
		printk("Error: Outfile cannot be accessed\n");
		err = (int) PTR_ERR(outfilp);
		goto out;
	}

	if (IS_ERR(outfilp)) {
		printk("Error: Fail to open the outfile\n");
		err = (int) PTR_ERR(outfilp);
		goto out;
	}
	
	/* checks for write permission of file */
	if (!outfilp -> f_op -> write) {
		printk("Error: Write not allowed by file system\n");
		err = -EACCES; 
		goto out;
	}
	
	if (!(outfilp -> f_mode & FMODE_WRITE)) {
		printk("Error: Outfile inaccessible to write\n");
		err = -EIO;
		goto out;
	}
	
	/* check if infile and outfile are same */
	if (((infilp -> f_path.dentry -> d_inode -> i_ino) == (outfilp -> f_path.dentry -> d_inode -> i_ino)) 
			&& ((infilp -> 	f_path.dentry -> d_inode -> i_sb) == (outfilp -> f_path.dentry -> d_inode -> i_sb))) {
		printk("Error: Infile and outfile are same\n");
		err = -EINVAL;
		goto out;
	}
	
	out:
		if(infilp) {
			if (!IS_ERR(infilp)) {
				filp_close(infilp, NULL);
			}
		}
		if(outfilp) {
			if (!IS_ERR(outfilp)) {
				filp_close(outfilp, NULL);
			}
		}		
		return err;
}

/**
 * reading len bytes from infile into buf
 **/
int wrapfs_read_file(struct file *infilp, void *buf, int len, int offset)
{
	int err = 0, bytes;
	mm_segment_t oldfs;
	
	/* check for validity of file */
	if (!infilp || IS_ERR(infilp)) {
		printk("Error: Infile does not exist\n");
		err = -EACCES;
		goto out;
	}
	
	/* check for read permission of file */
	if (!infilp -> f_op -> read) {
		printk("Error: Read not allowed by file system\n");
		err = -EIO;
		goto out;  
	}
	
	oldfs = get_fs();
	set_fs(KERNEL_DS);
	bytes = vfs_read(infilp, buf, len, &infilp -> f_pos);
	set_fs(oldfs);
	
	return bytes;
	
	out:
		return err;
}

/**
 * writing len bytes from buf into outfile
 **/
int wrapfs_write_file(struct file *outfilp, void *buf, int len, int offset)
{
	int err = 0, bytes;
	mm_segment_t oldfs;
	
	/* check for validity of file */
	if (!outfilp || IS_ERR(outfilp)) {
		printk("Error: Outfile cannot be accessed\n");
		err = -EACCES;
		goto out;
	}
	
	/* check for write permission of file */
	if (!outfilp -> f_op -> write) {
		printk("Error: Write not allowed by file system\n");
		err = -EACCES; 
		goto out;
	}
	
	oldfs = get_fs();
	set_fs(KERNEL_DS);
	bytes = vfs_write(outfilp, buf, len, &outfilp -> f_pos);
	set_fs(oldfs);
	
	return bytes;
	
	out:
		return err;
}

asmlinkage long xcrypt(void *arg)
{
	int i = 0, err = 0, args_len = 0, hash_len = 0,  files_valid = 0, args_valid = 0;
	int copy_res = 0, read_res = 0, write_res = 0, encrypt_res = 0, read_offset = 0, write_offset = 0;
	int key_res = 0, en_res = 0, de_res = 0, rename_success = 0, success = 0;
	int infile_size = 0, bytes_to_write = 0, bytes_to_read = 0, is_lock = 0;
	char *hashed_key = NULL;
	struct file *infilp = NULL, *outfilp = NULL, *temp_filp = NULL;
	struct filename *infile = NULL, *outfile = NULL;
	struct inode *in_inode = NULL;
	struct dentry *out_dentry = NULL, *temp_dentry = NULL;
	void *in_buf = NULL, *out_buf = NULL;
	int page_no = 0;
	u32 f_ino = 0;
	arguments *params = NULL;
	int file_stat = 0;
	mm_segment_t old_fs;
	struct kstat stat;
	
	/* Validation of address of user arguements */
	if (arg == NULL) {
		printk("Error: User arguments are not valid\n");
		err = -EINVAL;
		goto out;
	}
	
	args_len = sizeof(arguments);	
	
	/* memory allocation for user arguments */
	params = kmalloc(sizeof(arguments), __GFP_WAIT);
	
	if (params == NULL) {
		printk("Error: Memory allocation for user arguments failed\n");
		err = -ENOMEM;
		goto out;
	}
	
	/* check if user space pointer is valid or not */
	if (!access_ok(VERIFY_READ, arg, sizeof(arguments))) {
		printk("Error: User space pointer is not valid\n");
		err = -EINVAL;
		goto out;
	}
	
	/* copying user arguments into kernel */
	copy_res = copy_from_user(params, arg, args_len);
	
	/* check for successful copying of user arguments into kernel */
	if (copy_res != 0) {
		printk("Error: Failed to copy user arguments into kernel space\n");
		err = -EFAULT;
		goto out;
	}
	
	/* set block size used for encryption/decryption */
	#ifdef EXTRA_CREDIT
	bytes_to_read = params -> blk_size;
	#else
	bytes_to_read = PAGE_SIZE;
	#endif
	
	/* memory allocation for password and copying it into kernel space */
	params -> key = kmalloc(params -> keylen, __GFP_WAIT);
	copy_from_user(params -> key, ((struct args*)arg) -> key, params -> keylen);
	
	hash_len = params -> keylen;
	hashed_key = kzalloc(hash_len, __GFP_WAIT);
	
	/* double encrypting the key */
	key_res = md5_encryption(params -> key, hashed_key, hash_len);
	
	if (key_res < 0) {
		printk("Error: Key encryption fail\n");
		err = key_res;
		goto out;
	}
	
	/* check for arguments validity */
	args_valid = is_args_valid(params);
	
	if (args_valid < 0) {
		printk("Error: Arguments are not valid\n");
		err = args_valid;
		goto out;
	}
	
	/* copying and validating infile name into kernel */
	infile = getname(params -> infile);
	
	if (IS_ERR(infile)) {
		printk("Error: Infile name cannot be copied from user to kernel\n");
		err = (int) PTR_ERR(infile);
		goto out;
	}
	params -> infile = (char *)infile -> name;
	
	/* copying and validating outfile name into kernel */
	outfile = getname(params -> outfile);
	
	if (IS_ERR(outfile)) {
		printk("Error: Outfile name cannot be copied from user to kernel\n");
		err = (int) PTR_ERR(outfile);
		goto out;
	}
	params -> outfile = (char *)outfile -> name;
	
	/* checking all the params for correctness while debugging */
	#ifdef DEBUG
	printk("params -> oflags : %d\n", params -> oflags);
	printk("params->key: %s\n", params -> key);
	printk("params->keylen: %d\n", params -> keylen);
	printk("params->infile: %s\n", params -> infile);
	printk("params->outfile: %s\n", params -> outfile);
	printk("params->blk_size: %d\n", params -> blk_size);
	printk("bytes_to_read: %d\n", bytes_to_read);
	printk("hash_len: %d\n", hash_len);
	printk("hashed_key: %s\n", hashed_key);
	#endif
	
	/* check for files validity */
	files_valid  = is_files_valid(params -> infile, params -> outfile);
	
	if (files_valid < 0) {
		printk("Error: Files are not valid\n");
		err = files_valid;
		goto out;
	}
		
	/* memory alloctation for in buffer */
	in_buf = kmalloc(bytes_to_read, __GFP_WAIT);
	if (!in_buf) {
		printk("Error: Memory allocation for in buf failed\n");
		err = -ENOMEM;
		goto out;
	}
	
	/* memory alloctation for in buffer */
	out_buf = kmalloc(bytes_to_read, __GFP_WAIT);
	if (!out_buf) {
		printk("Error: Memory allocation for out buf failed\n");
		err = -ENOMEM;
		goto out;
	}
	
	infilp = filp_open(params -> infile, O_RDONLY, 0);
	if (!infilp || IS_ERR(infilp)) {
		printk("Error: Infile does not exist.\n");
		err = (int) PTR_ERR(infilp);
		goto out;
	}
	
	in_inode = infilp -> f_path.dentry -> d_inode;
	infile_size = i_size_read(in_inode);	
	
	old_fs = get_fs();
	set_fs(KERNEL_DS);
	
	file_stat = vfs_stat(params -> outfile, &stat);
	if (file_stat < 0) {		
		/* outfile does not exist, creating the temp file */
		temp_filp = filp_open("outfile.tmp", O_WRONLY | O_CREAT | O_TRUNC, infilp -> f_path.dentry -> d_inode -> i_mode);
		if(!temp_filp || IS_ERR(temp_filp)){
			printk("Error: Outfile cannot be accessed.\n");
			err = (int) PTR_ERR(temp_filp);
			set_fs(old_fs);
			goto out;
		}
		temp_dentry = temp_filp -> f_path.dentry;
	}
	else {
		outfilp = filp_open(params -> outfile, O_WRONLY | O_CREAT | O_TRUNC, infilp -> f_path.dentry -> d_inode -> i_mode);
		if (!outfilp || IS_ERR(outfilp)) {
			printk("Error: Outfile does not exist.\n");
			err = (int) PTR_ERR(outfilp);
			set_fs(old_fs);
			goto out;
		}
		out_dentry = outfilp -> f_path.dentry;
		
		/* creating the temp file for encryption/decryption */
		temp_filp = filp_open("outfile.tmp", O_WRONLY | O_CREAT | O_TRUNC, infilp -> f_path.dentry -> d_inode -> i_mode);
		if(!temp_filp || IS_ERR(temp_filp)){
			printk("Error: Outfile cannot be accessed.\n");
			err = (int) PTR_ERR(temp_filp);
			set_fs(old_fs);
			goto out;
		}
		temp_dentry = temp_filp -> f_path.dentry;
	}
	set_fs(old_fs);
	
	/* check if infile and temp file are are same */
	if (((infilp -> f_path.dentry -> d_inode -> i_ino) == (temp_filp -> f_path.dentry -> d_inode -> i_ino)) 
			&& ((infilp -> 	f_path.dentry -> d_inode -> i_sb) == (temp_filp -> f_path.dentry -> d_inode -> i_sb))) {
		printk("Error: Infile and temp file are pointing to same file");
		err = -EINVAL;
		goto out;
	}
	
	/* writing encryption key to outfile as preamble */
	if (params -> oflags == 1) {
		write_res = wrapfs_write_file(temp_filp, hashed_key, hash_len, write_offset);
		if (write_res < 0) {
			printk("Error: Fail while writing encryption key in outfile\n");
			err = -EIO;
			goto out;
		}
		temp_filp->f_pos = hash_len;
		write_offset += write_res;
		bytes_to_write = infile_size;
	}
	
	/* reading preambled encryption key from infile */
	if (params -> oflags == 0) {
		read_res = wrapfs_read_file(infilp, in_buf, hash_len, read_offset);
		if (read_res < 0) {
			printk("Error: Fail to read infile\n");
			err = read_res;
			goto out;
		}
		for (i = 0; i < SIZE; i++) {
			if ((((char *) in_buf)[i]) != (hashed_key[i])) {
				printk("Error: Decryption key is not valid\n");
				err = -EINVAL;
				goto out;
			}
		}
		read_offset = 0;
		infilp -> f_pos = hash_len;
		bytes_to_write = infile_size - hash_len;
	}
	
	#ifdef EXTRA_CREDIT
	/* getting i_ino of files to be used in iv */
	if (params -> oflags) {
		f_ino = temp_filp -> f_path.dentry -> d_inode -> i_ino;
	}
	else {
		f_ino = infilp -> f_path.dentry -> d_inode -> i_ino;
	}
	#endif
	
	while (bytes_to_write > 0) {
		
		#ifdef DEBUG
		printk("read_offset: %d\n", read_offset);
		#endif
		
		/* reading bytes_to_read bytes from infile into in_buf */
		read_res = wrapfs_read_file(infilp, in_buf, bytes_to_read, read_offset);
		
		if (read_res < 0) {
			printk("Error: Fail to read infile\n");
			err = read_res;
			goto out;
		}
		else if (read_res == bytes_to_read) {
			read_offset += 1;
			bytes_to_write -= read_res;
		}
		else {
			read_offset += 1;
			bytes_to_write -= read_res;
		}
		
		#ifdef DEBUG
		printk("bytes_to_write %d\n", bytes_to_write);
		#endif
		
		if (params -> oflags) {
			/* encrypting read_res bytes from in_buf to out_buf */
			en_res = file_encryption ((char *)in_buf, read_res, (char *)out_buf, &encrypt_res, 
								params -> key, params -> keylen, (long)page_no, (long)f_ino);
			if (en_res < 0 ) {
				printk("Error: file encryption fail\n");
				goto out;
			}
		}
		else {
			/* decrypting read_res bytes from in_buf to out_buf */
			de_res = file_decryption ((char *)in_buf, read_res, (char *)out_buf, &encrypt_res, 
								params -> key, params -> keylen, (long)page_no, (long)f_ino);
			if (de_res < 0 ) {
				printk("Error: file decryption fail\n");
				goto out;
			}
		}
		
		/* writing encrypt_res bytes from out_buf into temp_file */
		write_res = wrapfs_write_file(temp_filp, out_buf, encrypt_res, write_offset);
		
		if (write_res < 0) {
			printk("Error: write fail\n");
			err = write_res;
			goto out;
		}
		else {
			write_offset += write_res;
		}
		page_no++;
	}
	
	/* renaming temp file to outfile */
	lock_rename (temp_dentry->d_parent, out_dentry->d_parent);
	is_lock = 1;
	err = vfs_rename(temp_dentry->d_parent->d_inode, temp_dentry, 
				out_dentry->d_parent->d_inode, out_dentry, NULL, 0);
	
	/* check for rename success or not */
	if (err < 0) {
		printk("Error: Fail to rename temp file.\n");
		err = -EFAULT;
		goto out;
	}
	rename_success = 1;
	
	/* copying arguments back from kernel space to user */
	copy_res = copy_to_user(arg, params, args_len);
	
	/* check for successful copying of back from kernel to user */
	if (copy_res != 0) {
		printk("Error: Failed to copy back arguments from kernel space to user space\n");
		err = -EFAULT;
		goto out;
	}
	success = 1;
	out:
		/* checking and removing the lock */
		if (is_lock == 1) {
			unlock_rename (temp_dentry->d_parent, out_dentry->d_parent);
		}
		
		if (!success) {
			if (out_dentry) {
				mutex_lock(&out_dentry -> d_parent -> d_inode -> i_mutex);
				if (vfs_unlink(out_dentry->d_parent->d_inode, out_dentry, NULL) < 0) {
					printk("Error: unlink of temp file failed\n");
					err = -EFAULT;
				}
				mutex_unlock(&out_dentry -> d_parent -> d_inode -> i_mutex);
			}
		}
		
		/* unlinking the temp file if rename fail */
		if (!rename_success) {
			if (temp_dentry) {
				mutex_lock(&temp_dentry -> d_parent -> d_inode -> i_mutex);
				if (vfs_unlink(temp_dentry->d_parent->d_inode, temp_dentry, NULL) < 0) {
					printk("Error: unlink of temp file failed\n");
					err = -EFAULT;
				}
				mutex_unlock(&temp_dentry -> d_parent -> d_inode -> i_mutex);
			}
		}
		
		/* closing the infile */
		if (infilp) {
			if (!IS_ERR(infilp)) {
				filp_close(infilp, NULL);
			}
		}
		
		/* closing the outfile */
		if (outfilp) {
			if (!IS_ERR(outfilp)) {
				filp_close(outfilp, NULL);
			}
		}
		
		/* closing the temp file */
		if (temp_filp) {
			if (!IS_ERR(temp_filp)) {
				filp_close(temp_filp, NULL);
			}
		}
		
		/* deallocating memory */
		if (params -> key != NULL) {
			kfree(params -> key);
		}
				
		if (params != NULL) {
			kfree(params);
		}
	
		if (hashed_key != NULL) {
			kfree(hashed_key);
		}
		
		if (in_buf != NULL) {
			kfree(in_buf);
		}
			
		if (out_buf != NULL) {
			kfree(out_buf);
		}
	
	return err;
}

static int __init init_sys_xcrypt(void)
{
	printk("installed new sys_xcrypt module\n");
	if (sysptr == NULL)
		sysptr = xcrypt;
	return 0;
}

static void  __exit exit_sys_xcrypt(void)
{
	if (sysptr != NULL)
		sysptr = NULL;
	printk("removed sys_xcrypt module\n");
}

module_init(init_sys_xcrypt);
module_exit(exit_sys_xcrypt);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Operating System assignment to write syscall to encrypt/decrypt file");
MODULE_AUTHOR("Mohit Goyal");

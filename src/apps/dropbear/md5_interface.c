/***************************************************************
 *
 * Copyright(c) 2005-2007 Shenzhen TP-Link Technologies Co. Ltd.
 * All right reserved.
 *
 * Filename		:	md5_interface.c
 * Version		:	1.0
 * Abstract		:	md5 make and verify response interface
 * Author		:	LI SHAOZHANG (lishaozhang@tp-link.net)
 * Created Date	:	07/11/2007
 *
 * Modified History:
 * 04Feb09, lsz add functions: md5_des and file_md5_des
 ***************************************************************/
#include <fcntl.h>
#include <string.h>
#include <stdio.h>
#include "md5.h"
#include "md5_interface.h"

/*
 * md5_make_digest:make md5 digest for 'input' and save in 'digest'
 */
void md5_make_digest(unsigned char* digest, unsigned char* input, int len)
{
	MD5_CTX ctx;
	
	MD5_Init(&ctx);
	MD5_Update(&ctx, input, len);
	MD5_Final(digest, &ctx);
}

void hex_md5_str(unsigned char* md5Str, unsigned char* digest, int len)
{
    const unsigned char hex_table[] = "0123456789abcdef";
    int i = 0, j = 0;

    for( i = 0; i < len; i++)
    {
        md5Str[j++] = hex_table[digest[i]>>4 & 0x0f];
        md5Str[j++] = hex_table[digest[i]& 0x0f];
    }
    md5Str[j]= '\0';       
}

void hex_md5_make_digest(unsigned char* md5Str, unsigned char* input, int len)
{
    unsigned char digest[MD5_DIGEST_LEN]; 
    md5_make_digest(digest, input, len);
    hex_md5_str(md5Str, digest, MD5_DIGEST_LEN);  
}

/* verify the 'digest' for 'input'*/
int md5_verify_digest(unsigned char* digest, unsigned char* input, int len)
{
	unsigned char digst[MD5_DIGEST_LEN];
	
	md5_make_digest(digst, input, len);

	if (memcmp(digst, digest, MD5_DIGEST_LEN) == 0)
		return 1;
	
	return 0;
}

int hex_md5_verify_digest(unsigned char* md5Str, unsigned char* input, int len)
{  
	unsigned char digestStr[MD5_DIGEST_LEN*2 + 1];	
	hex_md5_make_digest(digestStr, input, len);
	if (memcmp(md5Str, digestStr, MD5_DIGEST_LEN*2) == 0)
		return 1;
	
	return 0;
}
/* 
   Unix SMB/CIFS implementation.
   HMAC MD5 code for use in NTLMv2
   Copyright (C) Luke Kenneth Casson Leighton 1996-2000
   Copyright (C) Andrew Tridgell 1992-2000
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

/* taken direct from rfc2104 implementation and modified for suitable use
 * for ntlmv2.
 */

#include "includes.h"

/***********************************************************************
 the microsoft version of hmac_md5 initialisation.
***********************************************************************/
void hmac_md5_init_limK_to_64(const uchar* key, int key_len,
									HMACMD5Context *ctx)
{
        int i;

        /* if key is longer than 64 bytes truncate it */
        if (key_len > 64)
	{
                key_len = 64;
        }

        /* start out by storing key in pads */
        ZERO_STRUCT(ctx->k_ipad);
        ZERO_STRUCT(ctx->k_opad);
        memcpy( ctx->k_ipad, key, key_len);
        memcpy( ctx->k_opad, key, key_len);

        /* XOR key with ipad and opad values */
        for (i=0; i<64; i++) {
                ctx->k_ipad[i] ^= 0x36;
                ctx->k_opad[i] ^= 0x5c;
        }

        MD5Init(&ctx->ctx);
        MD5Update(&ctx->ctx, ctx->k_ipad, 64);  
}

/***********************************************************************
 update hmac_md5 "inner" buffer
***********************************************************************/
void hmac_md5_update(const uchar* text, int text_len, HMACMD5Context *ctx)
{
        MD5Update(&ctx->ctx, text, text_len); /* then text of datagram */
}

/***********************************************************************
 finish off hmac_md5 "inner" buffer and generate outer one.
***********************************************************************/
void hmac_md5_final(uchar *digest, HMACMD5Context *ctx)
{
        struct MD5Context ctx_o;

        MD5Final(digest, &ctx->ctx);          

        MD5Init(&ctx_o);
        MD5Update(&ctx_o, ctx->k_opad, 64);   
        MD5Update(&ctx_o, digest, 16); 
        MD5Final(digest, &ctx_o);
}



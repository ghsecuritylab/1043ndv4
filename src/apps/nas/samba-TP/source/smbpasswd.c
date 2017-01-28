/*
 * Unix SMB/Netbios implementation. smbpasswd module. Copyright
 * (C) Jeremy Allison 1995-1997.
 * 
 * This program is free software; you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 * 
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 * 
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 675
 * Mass Ave, Cambridge, MA 02139, USA.
 */

#include "includes.h"

/* Static buffers we will return. */
//These are sucks..... Need a better way to prevent stack flow!
static struct smb_passwd pw_buf;
static char*  user_name;
static unsigned char smbpwd[16];
static unsigned char smbntpwd[16];

//extern int DEBUGLEVEL;
extern int errno;

static void E_md4hash(uchar *passwd, uchar *p16)
{
	int len;
	smb_ucs2_t wpwd[129];
	
	/* Password must be converted to NT unicode - null terminated. */
	push_ucs2(NULL, wpwd, (const char *)passwd, 256, STR_UNICODE|STR_NOALIGN|STR_TERMINATE);
	/* Calculate length in bytes */
	len = strlen_w(wpwd) * sizeof(int16);

	mdfour(p16, (unsigned char *)wpwd, len);
	ZERO_STRUCT(wpwd);	
}

static int gethexpwd(char *p, char *pwd)
{
	int i;
	unsigned char   lonybble, hinybble;
	char           *hexchars = "0123456789ABCDEF";
	char           *p1, *p2;
	for (i = 0; i < 32; i += 2) {
		hinybble = toupper(p[i]);
		lonybble = toupper(p[i + 1]);

		p1 = strchr(hexchars, hinybble);
		p2 = strchr(hexchars, lonybble);
		if (!p1 || !p2)
			return (False);

		hinybble = PTR_DIFF(p1, hexchars);
		lonybble = PTR_DIFF(p2, hexchars);

		pwd[i / 2] = (hinybble << 4) | lonybble;
	}
	return (True);
}

static struct smb_passwd *
_my_get_smbpwnam(FILE * fp, char *name, BOOL * valid_old_pwd, 
		BOOL *got_valid_nt_entry, long *pwd_seekpos)
{
	char            linebuf[256];
	unsigned char   c;
	unsigned char  *p;
	long            uidval;
	long            linebuf_len;

	/*
	 * Scan the file, a line at a time and check if the name matches.
	 */
	while (!feof(fp)) {
		linebuf[0] = '\0';
		*pwd_seekpos = ftell(fp);

		fgets(linebuf, 256, fp);
		if (ferror(fp))
			return NULL;

		/*
		 * Check if the string is terminated with a newline - if not
		 * then we must keep reading and discard until we get one.
		 */
		linebuf_len = strlen(linebuf);
		if (linebuf[linebuf_len - 1] != '\n') {
			c = '\0';
			while (!ferror(fp) && !feof(fp)) {
				c = fgetc(fp);
				if (c == '\n')
					break;
			}
		} else
			linebuf[linebuf_len - 1] = '\0';

		if ((linebuf[0] == 0) && feof(fp))
			break;
		/*
		 * The line we have should be of the form :-
		 * 
		 * username:uid:[32hex bytes]:....other flags presently
		 * ignored....
		 * 
		 * or,
		 * 
		 * username:uid:[32hex bytes]:[32hex bytes]:....ignored....
		 * 
		 * if Windows NT compatible passwords are also present.
		 */

		if (linebuf[0] == '#' || linebuf[0] == '\0')
			continue;
		p = (unsigned char *) strchr(linebuf, ':');
		if (p == NULL)
			continue;
		/*
		 * As 256 is shorter than a pstring we don't need to check
		 * length here - if this ever changes....
		 */
		strncpy(user_name, linebuf, PTR_DIFF(p, linebuf));
		user_name[PTR_DIFF(p, linebuf)] = '\0';
		if (!strequal(user_name, name))
			continue;

		/* User name matches - get uid and password */
		p++;		/* Go past ':' */
		if (!isdigit(*p))
			return (False);

		uidval = atoi((char *) p);
		while (*p && isdigit(*p))
			p++;

		if (*p != ':')
			return (False);

		/*
		 * Now get the password value - this should be 32 hex digits
		 * which are the ascii representations of a 16 byte string.
		 * Get two at a time and put them into the password.
		 */
		p++;
		*pwd_seekpos += PTR_DIFF(p, linebuf);	/* Save exact position
							 * of passwd in file -
							 * this is used by
							 * smbpasswd.c */
		if (*p == '*' || *p == 'X') {
			/* Password deliberately invalid - end here. */
			*valid_old_pwd = False;
			*got_valid_nt_entry = False;
			pw_buf.smb_nt_passwd = NULL;	/* No NT password (yet)*/

			/* Now check if the NT compatible password is
			   available. */
			p += 33; /* Move to the first character of the line after 
						the lanman password. */
			if ((linebuf_len >= (PTR_DIFF(p, linebuf) + 33)) && (p[32] == ':')) {
				/* NT Entry was valid - even if 'X' or '*', can be overwritten */
				*got_valid_nt_entry = True;
				if (*p != '*' && *p != 'X') {
				  if (gethexpwd((char *)p,(char *)smbntpwd))
				    pw_buf.smb_nt_passwd = smbntpwd;
				}
			}
			pw_buf.smb_name = user_name;
			pw_buf.smb_userid = uidval;
			pw_buf.smb_passwd = NULL;	/* No password */
			return (&pw_buf);
		}
		if (linebuf_len < (PTR_DIFF(p, linebuf) + 33))
			return (False);

		if (p[32] != ':')
			return (False);

		if (!strncasecmp((char *)p, "NO PASSWORD", 11)) {
		  pw_buf.smb_passwd = NULL;	/* No password */
		} else {
		  if(!gethexpwd((char *)p,(char *)smbpwd))
		    return False;
		  pw_buf.smb_passwd = smbpwd;
		}

		pw_buf.smb_name = user_name;
		pw_buf.smb_userid = uidval;
		pw_buf.smb_nt_passwd = NULL;
		*got_valid_nt_entry = False;
		*valid_old_pwd = True;

		/* Now check if the NT compatible password is
		   available. */
		p += 33; /* Move to the first character of the line after 
					the lanman password. */
		if ((linebuf_len >= (PTR_DIFF(p, linebuf) + 33)) && (p[32] == ':')) {
			/* NT Entry was valid - even if 'X' or '*', can be overwritten */
			*got_valid_nt_entry = True;
			if (*p != '*' && *p != 'X') {
			  if (gethexpwd((char *)p,(char *)smbntpwd))
			    pw_buf.smb_nt_passwd = smbntpwd;
			}
		}
		return &pw_buf;
	}
	return NULL;
}

//return 0 means success!
int do_smbpasswd(char* new_user_name, char* new_passwd)
{
	int             real_uid;
	struct passwd  *pwd;
	uchar           new_p16[16];
	uchar           new_nt_p16[16];
	char           *p;
	struct smb_passwd *smb_pwent;
	FILE           *fp;
	BOOL            valid_old_pwd = False;
	BOOL 			got_valid_nt_entry = False;
	long            seekpos;
	int             pwfd;
	char            ascii_p16[66];
	char            c;
	int             ret, i, err, writelen;
	int             lockfd = -1;
	char           *pfile = SMB_PASSWD_FILE;
	char            readbuf[16 * 1024];
	int ch;
	
	load_case_tables();
	
	/* Get the real uid */
	real_uid = getuid();
	
	if(real_uid != 0){
		return(1);
	}

	user_name = (char *)calloc(512, sizeof(char));
	user_name = strdup(new_user_name);
	
	if (new_passwd[0] == '\0' || user_name[0] == '\0')
	{
		return(1);
	}
	
	pwd = getpwnam(user_name);
	if (pwd == 0) {
		return(1);
	}
	
	/* Calculate the MD4 hash (NT compatible) of the old and new passwords */
	memset(new_nt_p16, '\0', 16);
	E_md4hash((uchar *) new_passwd, new_nt_p16);
  
	/* Mangle the passwords into Lanman format */
	new_passwd[14] = '\0';
	strupper_m(new_passwd);
  
  	/*
   	* Calculate the SMB (lanman) hash functions of both old and new passwords.
   	*/
  
	memset(new_p16, '\0', 16);
	E_P16((uchar *) new_passwd, new_p16);
	
	/*
   	* Open the smbpaswd file XXXX - we need to parse smb.conf to get the
   	* filename
   	*/
	fp = fopen(pfile, "r+");
	if (!fp && errno == ENOENT) {
		fp = fopen(pfile, "w");
		if (fp) {
		  	fprintf(fp, "SMB password file\n");
		  	fclose(fp);
		  	fp = fopen(pfile, "r+");
		}
	}
	
	if (!fp) {
		err = errno;
		return(err);
	}
	
	/* Set read buffer to 16k for effiecient reads */
	setvbuf(fp, readbuf, _IOFBF, sizeof(readbuf));
  
	/* make sure it is only rw by the owner */
	chmod(pfile, 0600);

	/* Lock the smbpasswd file for write. */
	if ((lockfd = pw_file_lock(pfile, F_WRLCK, 5)) < 0) {
		err = errno;
		fclose(fp);
		return(err);
	}
	
	/* Get the smb passwd entry for this user */
	smb_pwent = _my_get_smbpwnam(fp, pwd->pw_name, &valid_old_pwd, 
			       				&got_valid_nt_entry, &seekpos);
								
	if (smb_pwent == NULL) 
	{
    /* Create a new smb passwd entry and set it to the given password. */
		int fd;
		int new_entry_length;
		char *new_entry;
		long offpos;

      /* The add user write needs to be atomic - so get the fd from 
         the fp and do a raw write() call.
       */
		fd = fileno(fp);

		if((offpos = lseek(fd, 0, SEEK_END)) == -1) {
			fclose(fp);
			pw_file_unlock(lockfd);
			return(1);
		}

		new_entry_length = strlen(pwd->pw_name) + 1 + 15 + 1 + 
                         		32 + 1 + 32 + 1 + strlen(pwd->pw_gecos) + 
                         		1 + strlen(pwd->pw_dir) + 1 + 
                         		strlen(pwd->pw_shell) + 1;
	  
		if((new_entry = (char *)malloc( new_entry_length )) == 0) {
			fclose(fp);
			pw_file_unlock(lockfd);
			return(1);
		}

		sprintf(new_entry, "%s:%u:", pwd->pw_name, (unsigned)pwd->pw_uid);
		p = &new_entry[strlen(new_entry)];
	  
		for( i = 0; i < 16; i++)
			sprintf(&p[i*2], "%02X", new_p16[i]);
	  
		p += 32;
		*p++ = ':';
	  
		for( i = 0; i < 16; i++)
			sprintf(&p[i*2], "%02X", new_nt_p16[i]);
	  
		p += 32;
		*p++ = ':';
		sprintf(p, "%s:%s:%s\n", pwd->pw_gecos, 
              	pwd->pw_dir, pwd->pw_shell);
	  
		if(write(fd, new_entry, strlen(new_entry)) != strlen(new_entry)) {
        /* Remove the entry we just wrote. */
			ftruncate(fd, offpos);
			fclose(fp);
			pw_file_unlock(lockfd);
			return(1);
		}
      
		fclose(fp);  
		pw_file_unlock(lockfd);  
		return(0);
	} 
	else {
	  /* the entry already existed. Do nothing...*/
	}
	
	/*
   	* If we get here either we were root or the old password checked out
   	* ok.
   	*/
	for (i = 0; i < 16; i++) {
		sprintf(&ascii_p16[i * 2], "%02X", (uchar) new_p16[i]);
	}
  
	if(got_valid_nt_entry) {
    /* Add on the NT md4 hash */
		ascii_p16[32] = ':';
		for (i = 0; i < 16; i++) {
			sprintf(&ascii_p16[(i * 2)+33], "%02X", (uchar) new_nt_p16[i]);
		}
	}
	
	 /*
   * Do an atomic write into the file at the position defined by
   * seekpos.
   */
	pwfd = fileno(fp);
	ret = lseek(pwfd, seekpos - 1, SEEK_SET);
	if (ret != seekpos - 1) {
		err = errno;
		fclose(fp);
		pw_file_unlock(lockfd);
		return(err);
	}
	
	/* Sanity check - ensure the character is a ':' */
	if (read(pwfd, &c, 1) != 1) {
		err = errno;
		fclose(fp);
		pw_file_unlock(lockfd);
		return(err);
	}
	
	if (c != ':') {
		fclose(fp);
		pw_file_unlock(lockfd);
		return(1);
	}
	
	writelen = (got_valid_nt_entry) ? 65 : 32;
	if (write(pwfd, ascii_p16, writelen) != writelen) {
		err = errno;
		fclose(fp);
		pw_file_unlock(lockfd);
		return(err);
	}
	
	fclose(fp);
	pw_file_unlock(lockfd);
	return(0);
}


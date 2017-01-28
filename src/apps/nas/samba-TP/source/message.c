/* 
   Unix SMB/Netbios implementation.
   Version based 3.0.
   SMB messaging
   Copyright (C) Andrew Tridgell 1992-1997
   
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
/*
   This file handles the messaging system calls for winpopup style
   messages
*/


#include "includes.h"

/* look in server.c for some explanation of these variables */
extern int DEBUGLEVEL;
extern BOOL case_sensitive;
extern BOOL case_preserve;
extern BOOL short_case_preserve;
extern connection_struct Connections[];

BOOL rmdir_internals(int cnum, char *directory)
{
	BOOL ok = False;
	
	ok = (sys_rmdir(directory) == 0);
	if(!ok && (errno == ENOTEMPTY) && lp_veto_files(SNUM(cnum))){
		BOOL all_veto_files = True;
          	char *dname;
          	void *dirptr = OpenDir(cnum, directory, False);

          	if(dirptr != NULL)
            	{
              		int dirpos = TellDir(dirptr);
	          	while ((dname = ReadDirName(dirptr)))
	            	{
                  		if((strcmp(dname, ".") == 0) || (strcmp(dname, "..")==0))
                    			continue;
                  		if(!IS_VETO_PATH(cnum, dname))
                    		{
                      		all_veto_files = False;
                      		break;
                    		}
                	}
             		if(all_veto_files)
                	{
                  		SeekDir(dirptr,dirpos);
                  		while ((dname = ReadDirName(dirptr)))
                    		{
                      		pstring fullname;
				SMB_STRUCT_STAT st;

                      		if((strcmp(dname, ".") == 0) || (strcmp(dname, "..")==0))
                        			continue;

                      		/* Construct the full name. */
                      		if(strlen(directory) + strlen(dname) + 1 >= sizeof(fullname))
                        		{
                          			errno = ENOMEM;
                          			break;
                        		}
                      		pstrcpy(fullname, directory);
                      		strcat(fullname, "/");
                      		strcat(fullname, dname);
                      
                      		if(sys_lstat(fullname, &st) != 0)
                        			break;
                      		if(st.st_mode & S_IFDIR)
                      		{
                        			if(lp_recursive_veto_delete(SNUM(cnum)))
                        			{
                          				if(recursive_rmdir(fullname) != 0)
                            					break;
                        			}
                        			if(sys_rmdir(fullname) != 0)
                          				break;
                      		}
                      		else if(sys_unlink(fullname) != 0)
                        			break;
                    		}
                  		CloseDir(dirptr);
                  /* Retry the rmdir */
                  		ok = (sys_rmdir(directory) == 0);
                	}
              		else
                		CloseDir(dirptr);
            	}
          	else
            		errno = ENOTEMPTY;
	}

	if (!ok)
        	DEBUG(3,("couldn't remove directory %s : %s\n",
		 		directory,strerror(errno)));
	return ok;
}

NTSTATUS mv_internals(int cnum, char *name, char *newname)
{
	int count = 0; 
	
	BOOL bad_path1 = False;
	BOOL bad_path2 = False;
	pstring newname_last_component;
	pstring last_component_src;
	BOOL rc = True;

	pstring directory, mask;
	*directory = *mask = 0;

	char *p;
	BOOL has_wild;
	BOOL exists=False;
	NTSTATUS error = NT_STATUS_OK;

	BOOL is_short_name;
#ifndef USE_83_NAME
	is_short_name = True;
#endif
	
	rc = unix_convert(name,cnum,last_component_src,&bad_path1);
	
	if (!rc && bad_path1) {
		if (ms_has_wild(last_component_src))
			return NT_STATUS_OBJECT_NAME_NOT_FOUND;
		return NT_STATUS_OBJECT_PATH_NOT_FOUND;
	}

	/* Quick check for "." and ".." */
	if (last_component_src[0] == '.') {
		if (!last_component_src[1] || (last_component_src[1] == '.' && !last_component_src[2])) {
			return NT_STATUS_OBJECT_NAME_INVALID;
		}
	}
	
  	unix_convert(newname,cnum,newname_last_component,&bad_path2);

  /*
   * Split the old name into directory and last component
   * strings. Note that unix_convert may have stripped off a 
   * leading ./ from both name and newname if the rename is 
   * at the root of the share. We need to make sure either both
   * name and newname contain a / character or neither of them do
   * as this is checked in resolve_wildcards().
   */

  	p = strrchr_m(name,'/');
  	if (!p) {
    		strcpy(directory,".");
    		strcpy(mask,name);
  	} else {
    		*p = 0;
    		strcpy(directory,name);
    		strcpy(mask,p+1);
    		*p = '/'; /* Replace needed for exceptional test below. */
  	}

#ifdef USE_83_NAME
  	if (is_mangled(mask))
    		check_mangled_stack(mask);
#endif

  	has_wild = ms_has_wild(mask);

  	if (!has_wild) {
#ifdef USE_83_NAME
    		is_short_name = is_8_3(name, True);
#endif

    /* Add a terminating '/' to the directory name. */
    		strcat(directory,"/");
    		strcat(directory,mask);

    /* Ensure newname contains a '/' also */
   		if(strrchr_m(newname,'/') == 0) {
	      		pstring tmpstr;

	      		strcpy(tmpstr, "./");
	      		strcat(tmpstr, newname);
	      		strcpy(newname, tmpstr);
	    	}

    /*
     * Check for special case with case preserving and not
     * case sensitive, if directory and newname are identical,
     * and the old last component differs from the original
     * last component only by case, then we should allow
     * the rename (user is trying to change the case of the
     * filename).
     */
	    	if((case_sensitive == False) && 
		    ( ((case_preserve == True) && 
		    (is_short_name == False)) || 
	       	    ((short_case_preserve == True) && (is_short_name == True))) &&
	       	    strcsequal(directory, newname)) {
	      		pstring newname_modified_last_component;

      /*
       * Get the last component of the modified name.
       * Note that we guarantee that newname contains a '/'
       * character above.
       */
	      		p = strrchr_m(newname,'/');
	      		strcpy(newname_modified_last_component,p+1);

	      		if(strcsequal(newname_modified_last_component, newname_last_component) == False) {
		/*
		 * Replace the modified last component with
		 * the original.
		 */
	        		strcpy(p+1, newname_last_component);
	      		}
	    	}

		resolve_wildcards(directory,newname);

		if(!file_exist(directory, NULL)){
			DEBUG(0,("no src when doing rename!\n"));
			return map_nt_error_from_unix(errno);
		}

		if(!can_rename(directory,cnum)){
			DEBUG(0,("can not write when doing rename!\n"));
			return NT_STATUS_MEDIA_WRITE_PROTECTED;
		}

		if(file_exist(newname,NULL)){
			DEBUG(0,("dest exist when doing rename!\n"));
			return NT_STATUS_OBJECT_NAME_COLLISION;
		}

		if(!sys_rename(directory,newname)){
			DEBUG(3,("reply_mv : %s doing rename on %s -> %s\n",(count != 0) ? "succeeded" : "failed",
	                         directory,newname));
			count++;
		}

#if 0	
//######################################################
	    	if (resolve_wildcards(directory,newname) && 
			can_rename(directory,cnum) && 
			!file_exist(newname,NULL) &&
			!sys_rename(directory,newname)) 
			count++;

	    	DEBUG(3,("reply_mv : %s doing rename on %s -> %s\n",(count != 0) ? "succeeded" : "failed",
	                         directory,newname));

	    	if (!count) 
			exists = file_exist(directory,NULL);
	    	if (!count && exists && file_exist(newname,NULL)) {
	      		exists = True;
	      		error = NT_STATUS_OBJECT_NAME_COLLISION;
	    	}
#endif
    	} else {
	    void *dirptr = NULL;
	    char *dname;
	    pstring destname;

	    if (check_name(directory,cnum))
	      dirptr = OpenDir(cnum, directory, True);

	    if (dirptr)
	      {
		error = NT_STATUS_NO_SUCH_FILE;

		if (strequal(mask,"????????.???"))
		  strcpy(mask,"*");

		while ((dname = ReadDirName(dirptr)))
		  {
		    pstring fname;
		    pstrcpy(fname,dname);
		    
		    if(!mask_match(fname, mask, case_sensitive, False)) 
				continue;

		    error = NT_STATUS_ACCESS_DENIED;
		    sprintf(fname,"%s/%s",directory,dname);
		    if (!can_rename(fname,cnum)) {
			    DEBUG(6,("rename %s refused\n", fname));
			    continue;
		    }
		    pstrcpy(destname,newname);

		    if (!resolve_wildcards(fname,destname)) {
			    DEBUG(6,("resolve_wildcards %s %s failed\n", fname, destname));
			    continue;
		    }

		    if (file_exist(destname,NULL)) {
			    DEBUG(6,("file_exist %s\n", destname));
			    error = NT_STATUS_OBJECT_NAME_COLLISION;
			    continue;
		    }
			
		    if (!sys_rename(fname,destname)){ 
				count++;
		    		DEBUG(3,("reply_mv : doing rename on %s -> %s\n",fname,destname));
		    }
		  }
		CloseDir(dirptr);
	      }
	  }

  	if (count == 0) {
    		error = map_nt_error_from_unix(errno);
	}

	if(NT_STATUS_IS_OK(error)){
		extern pid_t m_pid;
		DEBUG(0,("\n###############(%s)yes, file(%s) needs to be sync!!!!######\n", 			
				__FUNCTION__, name));  	
		kill(m_pid, SIGUSR1);
	}

	return error;
}


/*
 * WE DO NOT SUPPORT MAGIC SHELL IN THIS SMB PLATFORM.....
*/
/****************************************************************************
  reply to a sends
****************************************************************************/
int reply_sends(char *inbuf,char *outbuf)
{
	return(ERROR_DOS(ERRSRV,ERRmsgoff));
#if 0
  int len;
  char *p, *msg;
  int outsize = 0;

  msgpos = 0;


  if (! (*lp_msg_command()))
    return(ERROR_DOS(ERRSRV,ERRmsgoff));

  outsize = set_message(outbuf,0,0,True);

  p = smb_buf(inbuf)+1;
  p += srvstr_pull_buf(inbuf, msgfrom, p, sizeof(msgfrom), STR_ASCII|STR_TERMINATE) + 1;
  p += srvstr_pull_buf(inbuf, msgto, p, sizeof(msgto), STR_ASCII|STR_TERMINATE) + 1;

  msg = p;

  len = SVAL(msg,0);
  len = MIN(len,sizeof(msgbuf)-msgpos);

  memset(msgbuf,'\0',sizeof(msgbuf));

  memcpy(&msgbuf[msgpos],msg+2,len);
  msgpos += len;

//  msg_deliver();

  return(outsize);
#endif
}


/****************************************************************************
  reply to a sendstrt
****************************************************************************/
int reply_sendstrt(char *inbuf,char *outbuf)
{
	return(ERROR_DOS(ERRSRV,ERRmsgoff));
#if 0
  char *p;
  int outsize = 0;

  if (! (*lp_msg_command()))
    return(ERROR_DOS(ERRSRV,ERRmsgoff));

  outsize = set_message(outbuf,1,0,True);

  memset(msgbuf,'\0',sizeof(msgbuf));
  msgpos = 0;

  p = smb_buf(inbuf)+1;
  p += srvstr_pull_buf(inbuf, msgfrom, p, sizeof(msgfrom), STR_ASCII|STR_TERMINATE) + 1;
  p += srvstr_pull_buf(inbuf, msgto, p, sizeof(msgto), STR_ASCII|STR_TERMINATE) + 1;

  return(outsize);
#endif
}


/****************************************************************************
  reply to a sendtxt
****************************************************************************/
int reply_sendtxt(char *inbuf,char *outbuf)
{
	return(ERROR_DOS(ERRSRV,ERRmsgoff));
#if 0
  int len;
  int outsize = 0;
  char *msg;

  if (! (*lp_msg_command()))
    return(ERROR_DOS(ERRSRV,ERRmsgoff));

  outsize = set_message(outbuf,0,0,True);

  msg = smb_buf(inbuf) + 1;

  len = SVAL(msg,0);
  len = MIN(len,1600-msgpos);

  memcpy(&msgbuf[msgpos],msg+2,len);
  msgpos += len;

  DEBUG(3,("%s SMBsendtxt\n",timestring()));

  return(outsize);
#endif
}


/****************************************************************************
  reply to a sendend
****************************************************************************/
int reply_sendend(char *inbuf,char *outbuf)
{
	return(ERROR_DOS(ERRSRV,ERRmsgoff));
#if 0
  int outsize = 0;

  if (! (*lp_msg_command()))
    return(ERROR_DOS(ERRSRV,ERRmsgoff));

  outsize = set_message(outbuf,0,0,True);

  DEBUG(3,("%s SMBsendend\n",timestring()));

//  msg_deliver();

  return(outsize);
#endif
}


/* 
   Unix SMB/Netbios implementation.
   Version based 3.0.
   SMB transaction2 handling
   Copyright (C) Jeremy Allison 1994-1997

   Extensively modified by Andrew Tridgell, 1995

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

#include "includes.h"

extern int DEBUGLEVEL;
extern int Protocol;
#ifdef OPLOCK_ENABLE
extern int global_oplock_break;
extern int oplock_sock;
#endif
extern connection_struct Connections[];
extern files_struct Files[];
extern BOOL case_sensitive;
extern int Client;
extern int smb_read_error;
extern fstring local_machine;

/****************************************************************************
 Utility function to set bad path error.
****************************************************************************/

int set_bad_path_error(char *outbuf, int err, BOOL bad_path, int def_class, uint32 def_code)
{
	if(err == ENOENT) {
		if (bad_path) {
			return ERROR_NT(NT_STATUS_OBJECT_PATH_NOT_FOUND);
		} else {
			return ERROR_NT(NT_STATUS_OBJECT_NAME_NOT_FOUND);
		}
	}
	
	return UNIXERROR(def_class,def_code);
}

//####################################################//

/****************************************************************************
  Send the required number of replies back.
  We assume all fields other than the data fields are
  set correctly for the type of call.
  HACK ! Always assumes smb_setup field is zero.
****************************************************************************/
static int send_trans2_replies(char *outbuf, int bufsize, char *params, 
			 int paramsize, char *pdata, int datasize)
{
  /* As we are using a protocol > LANMAN1 then the max_send
     variable must have been set in the sessetupX call.
     This takes precedence over the max_xmit field in the
     global struct. These different max_xmit variables should
     be merged as this is now too confusing */

  extern int max_send;
  int data_to_send = datasize;
  int params_to_send = paramsize;
  int useable_space;
  char *pp = params;
  char *pd = pdata;
  int params_sent_thistime, data_sent_thistime, total_sent_thistime;
  int alignment_offset = 1;

  /* Initially set the wcnt area to be 10 - this is true for all
     trans2 replies */
  set_message(outbuf,10,0,True);

  /* If there genuinely are no parameters or data to send just send
     the empty packet */
  if(params_to_send == 0 && data_to_send == 0)
    {
      send_smb(Client,outbuf);
      return 0;
    }

  /* Space is bufsize minus Netbios over TCP header minus SMB header */
  /* The alignment_offset is to align the param and data bytes on an even byte
     boundary. NT 4.0 Beta needs this to work correctly. */
  useable_space = bufsize - ((smb_buf(outbuf)+alignment_offset) - outbuf);
  /* useable_space can never be more than max_send minus the
     alignment offset. */
  useable_space = MIN(useable_space, max_send - alignment_offset);

  while( params_to_send || data_to_send)
    {
      /* Calculate whether we will totally or partially fill this packet */
      total_sent_thistime = params_to_send + data_to_send + alignment_offset;
      /* We can never send more than useable_space */
      total_sent_thistime = MIN(total_sent_thistime, useable_space);

      set_message(outbuf, 10, total_sent_thistime, True);

      /* Set total params and data to be sent */
      SSVAL(outbuf,smb_tprcnt,paramsize);
      SSVAL(outbuf,smb_tdrcnt,datasize);

      /* Calculate how many parameters and data we can fit into
	 this packet. Parameters get precedence */

      params_sent_thistime = MIN(params_to_send,useable_space);
      data_sent_thistime = useable_space - params_sent_thistime;
      data_sent_thistime = MIN(data_sent_thistime,data_to_send);

      SSVAL(outbuf,smb_prcnt, params_sent_thistime);
      if(params_sent_thistime == 0)
	{
	  SSVAL(outbuf,smb_proff,0);
	  SSVAL(outbuf,smb_prdisp,0);
	} else {
	  /* smb_proff is the offset from the start of the SMB header to the
	     parameter bytes, however the first 4 bytes of outbuf are
	     the Netbios over TCP header. Thus use smb_base() to subtract
	     them from the calculation */
	  SSVAL(outbuf,smb_proff,((smb_buf(outbuf)+alignment_offset) - smb_base(outbuf)));
	  /* Absolute displacement of param bytes sent in this packet */
	  SSVAL(outbuf,smb_prdisp,pp - params);
	}

      SSVAL(outbuf,smb_drcnt, data_sent_thistime);
      if(data_sent_thistime == 0)
	{
	  SSVAL(outbuf,smb_droff,0);
	  SSVAL(outbuf,smb_drdisp, 0);
	} else {
	  /* The offset of the data bytes is the offset of the
	     parameter bytes plus the number of parameters being sent this time */
	  SSVAL(outbuf,smb_droff,((smb_buf(outbuf)+alignment_offset) - 
				  smb_base(outbuf)) + params_sent_thistime);
	  SSVAL(outbuf,smb_drdisp, pd - pdata);
	}

      /* Copy the param bytes into the packet */
      if(params_sent_thistime)
	memcpy((smb_buf(outbuf)+alignment_offset),pp,params_sent_thistime);
      /* Copy in the data bytes */
      if(data_sent_thistime)
	memcpy(smb_buf(outbuf)+alignment_offset+params_sent_thistime,pd,data_sent_thistime);

      DEBUG(9,("t2_rep: params_sent_thistime = %d, data_sent_thistime = %d, useable_space = %d\n",
	       params_sent_thistime, data_sent_thistime, useable_space));
      DEBUG(9,("t2_rep: params_to_send = %d, data_to_send = %d, paramsize = %d, datasize = %d\n",
	       params_to_send, data_to_send, paramsize, datasize));

      /* Send the packet */
      send_smb(Client,outbuf);

      pp += params_sent_thistime;
      pd += data_sent_thistime;

      params_to_send -= params_sent_thistime;
      data_to_send -= data_sent_thistime;

      /* Sanity check */
      if(params_to_send < 0 || data_to_send < 0)
	{
	  DEBUG(2,("send_trans2_replies failed sanity check pts = %d, dts = %d\n!!!",
		   params_to_send, data_to_send));
	  return -1;
	}
    }

  return 0;
}


/****************************************************************************
  reply to a TRANSACT2_OPEN
****************************************************************************/
static int call_trans2open(char *inbuf, char *outbuf, int bufsize, int cnum, 
		    char **pparams, char **ppdata)
{
  char *params = *pparams;
  int16 open_mode = SVAL(params, 2);
  int16 open_attr = SVAL(params,6);
  BOOL oplock_request = (((SVAL(params,0)|(1<<1))>>1) | ((SVAL(params,0)|(1<<2))>>1));
#if 0
  BOOL return_additional_info = BITSETW(params,0);
  int16 open_sattr = SVAL(params, 4);
  time_t open_time = make_unix_date3(params+8);
#endif
  int16 open_ofun = SVAL(params,12);
  int32 open_size = IVAL(params,14);
  char *pname = &params[28];
  int16 namelen = strlen(pname)+1;

  pstring fname;
  int fnum = -1;
  int unixmode;
  int size=0,fmode=0,mtime=0,rmode;
  int32 inode = 0;
  SMB_STRUCT_STAT sbuf;
  int smb_action = 0;
  BOOL bad_path = False;
  NTSTATUS status;

  srvstr_get_path(inbuf, fname, pname, sizeof(fname), -1, STR_TERMINATE, &status, False);
  if (!NT_STATUS_IS_OK(status)) {
	return ERROR_NT(status);
  }

  DEBUG(3,("trans2open %s cnum=%d mode=%d attr=%d ofun=%d size=%d\n",
	   fname,cnum,open_mode, open_attr, open_ofun, open_size));

  /* XXXX we need to handle passed times, sattr and flags */

  unix_convert(fname,cnum,0,&bad_path);
    
  fnum = find_free_file();
  if (fnum < 0)
    return(ERROR_DOS(ERRSRV,ERRnofids));

  if (!check_name(fname,cnum))
  {
    	return set_bad_path_error(outbuf, errno, bad_path, ERRDOS,ERRnoaccess);
  }

  unixmode = unix_mode(cnum,open_attr | aARCH);
      
      
  open_file_shared(fnum,cnum,fname,open_mode,open_ofun,unixmode,
		   oplock_request, &rmode,&smb_action);
      
  if (!Files[fnum].open)
  {
    	return set_bad_path_error(outbuf, errno, bad_path, ERRDOS,ERRnoaccess);
  }

  if (sys_fstat(Files[fnum].fd_ptr->fd,&sbuf) != 0) {
    close_file(fnum,False);
    return(ERROR_DOS(ERRDOS,ERRnoaccess));
  }
    
  size = sbuf.st_size;
  fmode = dos_mode(cnum,fname,&sbuf);
  mtime = sbuf.st_mtime;
  inode = sbuf.st_ino;
  if (fmode & aDIR) {
    close_file(fnum,False);
    return(ERROR_DOS(ERRDOS,ERRnoaccess));
  }

  /* Realloc the size of parameters and data we will return */
  params = *pparams = Realloc(*pparams, 28);
  if(params == NULL)
    return(ERROR_DOS(ERRDOS,ERRnomem));

  bzero(params,28);
  SSVAL(params,0,fnum);
  SSVAL(params,2,fmode);
  put_dos_date2(params,4, mtime);
  SIVAL(params,8, size);
  SSVAL(params,12,rmode);

  if (oplock_request && lp_fake_oplocks(SNUM(cnum))) {
    smb_action |= EXTENDED_OPLOCK_GRANTED;
  }

  SSVAL(params,18,smb_action);
  SIVAL(params,20,inode);
 
  /* Send the required number of replies */
  send_trans2_replies(outbuf, bufsize, params, 28, *ppdata, 0);

  return -1;
}

static BOOL exact_match(char *str,char *mask, BOOL case_sig) 
{
	if (mask[0] == '.' && mask[1] == 0)
		return False;
	if (case_sig)	
		return strcmp(str,mask)==0;
	if (StrCaseCmp(str,mask) != 0) {
		return False;
	}
	if (ms_has_wild(str)) {
		return False;
	}
	return True;
}

/****************************************************************************
  get a level dependent lanman2 dir entry.
****************************************************************************/
static int get_lanman2_dir_entry(void *inbuf, void *outbuf,
				int cnum,char *path_mask,int dirtype,int info_level,
				 int requires_resume_key,
				 BOOL dont_descend,char **ppdata, 
				 char *base_data, int space_remaining, 
				 BOOL *out_of_space,
				 int *last_name_off)
{
  char *dname;
  BOOL found = False;
  SMB_STRUCT_STAT sbuf;
  pstring mask;
  pstring pathreal;
  pstring fname;
  BOOL matched;
  char *p, *q, *pdata = *ppdata;
  int reskey=0, prev_dirpos=0;
  int mode=0;
  SMB_OFF_T size=0;
  SMB_BIG_UINT allocation_size = 0;
  uint32 len;
  uint32 mdate=0, adate=0, cdate=0;
  char *nameptr;
  BOOL isrootdir = (strequal(Connections[cnum].dirpath,"./") ||
		    strequal(Connections[cnum].dirpath,".") ||
		    strequal(Connections[cnum].dirpath,"/"));
  BOOL was_8_3;
  int nt_extmode; /* Used for NT connections instead of mode */
  BOOL needslash = ( Connections[cnum].dirpath[strlen(Connections[cnum].dirpath) -1] != '/');

  *fname = 0;
  *out_of_space = False;

  if (!Connections[cnum].dirptr)
    return(False);

  p = strrchr_m(path_mask,'/');
  if(p != NULL)
    {
      if(p[1] == '\0')
	strcpy(mask,"*.*");
      else
	pstrcpy(mask, p+1);
    }
  else
    pstrcpy(mask, path_mask);

  while (!found)
    {
      BOOL got_match;
      /* Needed if we run out of space */
      long curr_dirpos = prev_dirpos = TellDir(Connections[cnum].dirptr);
      dname = ReadDirName(Connections[cnum].dirptr);

      /*
		 * Due to bugs in NT client redirectors we are not using
		 * resume keys any more - set them to zero.
		 * Check out the related comments in findfirst/findnext.
		 * JRA.
		 */

	reskey = 0;

      DEBUG(8,("get_lanman2_dir_entry:readdir on dirptr 0x%x now at offset %d\n",
	       Connections[cnum].dirptr,TellDir(Connections[cnum].dirptr)));
      
      if (!dname) 
	return(False);

      pstrcpy(fname,dname);   

	if(!(got_match = exact_match(fname, mask, case_sensitive)))
			got_match = mask_match(fname, mask, case_sensitive, True);

	if(!got_match
#ifdef USE_83_NAME
		&& !is_8_3(fname, False)
#endif
	) {

			/*
			 * It turns out that NT matches wildcards against
			 * both long *and* short names. This may explain some
			 * of the wildcard wierdness from old DOS clients
			 * that some people have been seeing.... JRA.
			 */

		pstring newname;
		pstrcpy( newname, fname);
		
#ifdef USE_83_NAME
		name_map_mangle( newname, True, SNUM(cnum));
#endif

		if(!(got_match =  exact_match(newname, mask, case_sensitive)))
			got_match = mask_match(newname, mask, case_sensitive, False/*useless parameter*/);
	}

	if(got_match) {
		BOOL isdots = (strequal(fname,"..") || strequal(fname,"."));
		if (dont_descend && !isdots)
			continue;

		pstrcpy(pathreal,Connections[cnum].dirpath);
         	if(needslash)
  	    		strcat(pathreal,"/");
	  	strcat(pathreal,dname);

		DEBUG(0,("dname is: %s\n", dname));
	  
	 	if (sys_stat(pathreal,&sbuf) != 0) 
	    	{
	      		DEBUG(5,("get_lanman2_dir_entry:Couldn't stat [%s] (%s)\n",pathreal,strerror(errno)));
	      		continue;
	    	}
	

	 	mode = dos_mode(cnum,pathreal,&sbuf);

	 	if (!dir_check_ftype(cnum,mode,&sbuf,dirtype)) {
	    		DEBUG(5,("[%s] attribs didn't match %x\n",fname,dirtype));
	    		continue;
	  	}

	 	size = sbuf.st_size;

		SMB_BIG_UINT ret;
		ret = (SMB_BIG_UINT)STAT_ST_BLOCKSIZE * (SMB_BIG_UINT)sbuf.st_blocks;
		allocation_size = smb_roundup(ret);
		
		mdate = sbuf.st_mtime;
	  	adate = sbuf.st_atime;
	  	cdate = sbuf.st_ctime;
	 	 if(mode & aDIR)
	    		size = 0;

	 	 DEBUG(5,("get_lanman2_dir_entry found %s fname=%s\n",pathreal,fname));
	  
	  	found = True;
	  }
  	}
  
#ifdef USE_83_NAME  
  	name_map_mangle(fname,False,SNUM(cnum));
#endif
	
#if 0
//#####################################################//

      if(mask_match(fname, mask, case_sensitive, True))
	{
	  BOOL isdots = (strequal(fname,"..") || strequal(fname,"."));
	  if (dont_descend && !isdots)
	    continue;
	  
	  if (isrootdir && isdots)
	    continue;

	  pstrcpy(pathreal,Connections[cnum].dirpath);
          if(needslash)
  	    strcat(pathreal,"/");
	  strcat(pathreal,dname);
	  
	  DEBUG(0,("dname is: %s\n", dname));
	  
	  if (sys_stat(pathreal,&sbuf) != 0) 
	    {
	      DEBUG(5,("get_lanman2_dir_entry:Couldn't stat [%s] (%s)\n",pathreal,strerror(errno)));
	      continue;
	    }

	  mode = dos_mode(cnum,pathreal,&sbuf);

	  if (!dir_check_ftype(cnum,mode,&sbuf,dirtype)) {
	    DEBUG(5,("[%s] attribs didn't match %x\n",fname,dirtype));
	    continue;
	  }

	  size = sbuf.st_size;
	  mdate = sbuf.st_mtime;
	  adate = sbuf.st_atime;
	  cdate = sbuf.st_ctime;
	  if(mode & aDIR)
	    size = 0;

	  DEBUG(5,("get_lanman2_dir_entry found %s fname=%s\n",pathreal,fname));
	  
	  found = True;
	}
    }

  name_map_mangle(fname,False,SNUM(cnum));
#endif

  p = pdata;
  nameptr = p;

  nt_extmode = mode ? mode : NT_FILE_ATTRIBUTE_NORMAL;

  switch (info_level)
    {
    case 1:
	DEBUG(0,("get_lanman2_dir_entry: 1\n"));
	if(requires_resume_key) {
		SIVAL(p,0,reskey);
		p += 4;
	}
	put_dos_date2(p,l1_fdateCreation,cdate);
	put_dos_date2(p,l1_fdateLastAccess,adate);
	put_dos_date2(p,l1_fdateLastWrite,mdate);
	SIVAL(p,l1_cbFile, (uint32)size);
	SIVAL(p,l1_cbFileAlloc,(uint32)allocation_size);
	SSVAL(p,l1_attrFile,mode);
	p += l1_achName;
	nameptr = p;
	p += align_string(outbuf, p, 0);
	len = srvstr_push(outbuf, p, fname, -1, STR_TERMINATE);
	if (SVAL(outbuf, smb_flg2) & FLAGS2_UNICODE_STRINGS) {
		if (len > 2) {
			SCVAL(nameptr, -1, len - 2);
		} else {
			SCVAL(nameptr, -1, 0);
		}
	} else {
		if (len > 1) {
			SCVAL(nameptr, -1, len - 1);
		} else {
			SCVAL(nameptr, -1, 0);
		}
	}
	p += len;
	break;
/*
      if(requires_resume_key) {
	SIVAL(p,0,reskey);
	p += 4;
      }
      put_dos_date2(p,l1_fdateCreation,cdate);
      put_dos_date2(p,l1_fdateLastAccess,adate);
      put_dos_date2(p,l1_fdateLastWrite,mdate);
      SIVAL(p,l1_cbFile,size);
      SIVAL(p,l1_cbFileAlloc,ROUNDUP(size,1024));
      SSVAL(p,l1_attrFile,mode);
      SCVAL(p,l1_cchName,strlen(fname));
      strcpy(p + l1_achName, fname);
      nameptr = p + l1_achName;
      p += l1_achName + strlen(fname) + 1;
      break;
*/
    case 2:
		DEBUG(0,("get_lanman2_dir_entry: 2\n"));
      /* info_level 2 */
      if(requires_resume_key) {
	SIVAL(p,0,reskey);
	p += 4;
      }
	  
      put_dos_date2(p,l2_fdateCreation,cdate);
      put_dos_date2(p,l2_fdateLastAccess,adate);
      put_dos_date2(p,l2_fdateLastWrite,mdate);
      SIVAL(p,l2_cbFile,(uint32)size);
      SIVAL(p,l2_cbFileAlloc,(uint32)allocation_size);
      SSVAL(p,l2_attrFile,mode);
      SIVAL(p,l2_cbList,0); /* No extended attributes */
	p += l2_achName;
	nameptr = p - 1;
	len = srvstr_push(outbuf, p, fname, -1, STR_TERMINATE | STR_NOALIGN);
	if (SVAL(outbuf, smb_flg2) & FLAGS2_UNICODE_STRINGS) {
		if (len > 2) {
			len -= 2;
		} else {
			len = 0;
		}
	} else {
		if (len > 1) {
			len -= 1;
		} else {
			len = 0;
		}
	}
	SCVAL(nameptr,0,len);
	p += len;
	SCVAL(p,0,0); p += 1; /* Extra zero byte ? - why.. */
	break;
/*
      SCVAL(p,l2_cchName,strlen(fname));
      strcpy(p + l2_achName, fname);
      nameptr = p + l2_achName;
      p += l2_achName + strlen(fname) + 1;
      break;
*/

#if 0		//seems that in new SMB there has no 3/4 cases
    case 3:
      SIVAL(p,0,reskey);
      put_dos_date2(p,4,cdate);
      put_dos_date2(p,8,adate);
      put_dos_date2(p,12,mdate);
      SIVAL(p,16,size);
      SIVAL(p,20,ROUNDUP(size,1024));
      SSVAL(p,24,mode);
      SIVAL(p,26,4);
      CVAL(p,30) = strlen(fname);
      strcpy(p+31, fname);
      nameptr = p+31;
      p += 31 + strlen(fname) + 1;
      break;

    case 4:
      if(requires_resume_key) {
	SIVAL(p,0,reskey);
	p += 4;
      }
      SIVAL(p,0,33+strlen(fname)+1);
      put_dos_date2(p,4,cdate);
      put_dos_date2(p,8,adate);
      put_dos_date2(p,12,mdate);
      SIVAL(p,16,size);
      SIVAL(p,20,ROUNDUP(size,1024));
      SSVAL(p,24,mode);
      CVAL(p,32) = strlen(fname);
      strcpy(p + 33, fname);
      nameptr = p+33;
      p += 33 + strlen(fname) + 1;
      break;
#endif

    case SMB_FIND_FILE_BOTH_DIRECTORY_INFO:
		DEBUG(0,("get_lanman2_dir_entry: 3\n"));
#ifdef USE_83_NAME
      was_8_3 = is_8_3(fname, True);
 #endif
      p += 4;
      SIVAL(p,0,reskey); p += 4;
      put_long_date(p,cdate); p += 8;
      put_long_date(p,adate); p += 8;
      put_long_date(p,mdate); p += 8;
      put_long_date(p,mdate); p += 8;
      SOFF_T(p,0,size); p += 8;
      SOFF_T(p,0,allocation_size); p += 8;	//maybe we have some problem in WINDOWS because of the hole file...
      SIVAL(p,0,nt_extmode); p += 4;
      q= p; p += 4;
	SIVAL(p,0,0); p += 4;
	
/* Clear the short name buffer. This is
	* IMPORTANT as not doing so will trigger
	* a Win2k client bug. JRA.
*/
	memset(p,'\0',26);

#ifdef USE_83_NAME	  
       if (!was_8_3 && lp_manglednames(SNUM(cnum))) {
	  	pstring mangled_name;
		pstrcpy(mangled_name, fname);

		name_map_mangle(mangled_name,True,SNUM(cnum));

		mangled_name[12] = 0;
		len = srvstr_push(outbuf, p+2, mangled_name, 24, STR_UPPER|STR_UNICODE);
		SSVAL(p, 0, len);
       } else
#endif
	{
		SSVAL(p,0,0);
		*(p+2) = 0;
	}

	p += 2 + 24;
	len = srvstr_push(outbuf, p, fname, -1, STR_TERMINATE_ASCII);
	SIVAL(q,0,len);
	p += len;
	len = PTR_DIFF(p, pdata);
	len = (len + 3) & ~3;
	SIVAL(pdata,0,len);
	p = pdata + len;
	break;

    case SMB_FIND_FILE_DIRECTORY_INFO:
DEBUG(0,("get_lanman2_dir_entry: 4\n"));
	p += 4;
	SIVAL(p,0,reskey); p += 4;
	put_long_date(p,cdate); p += 8;
	put_long_date(p,adate); p += 8;
	put_long_date(p,mdate); p += 8;
	put_long_date(p,mdate); p += 8;
	SOFF_T(p,0,size); p += 8;
	SOFF_T(p,0,allocation_size); p += 8;
	SIVAL(p,0,nt_extmode); p += 4;
	len = srvstr_push(outbuf, p + 4, fname, -1, STR_TERMINATE_ASCII);
	SIVAL(p,0,len);
	p += 4 + len;
	len = PTR_DIFF(p, pdata);
	len = (len + 3) & ~3;
	SIVAL(pdata,0,len);
	p = pdata + len;
	break;     
      
    case SMB_FIND_FILE_FULL_DIRECTORY_INFO:
		DEBUG(0,("get_lanman2_dir_entry: 5\n"));
	p += 4;
	SIVAL(p,0,reskey); p += 4;
	put_long_date(p,cdate); p += 8;
	put_long_date(p,adate); p += 8;
	put_long_date(p,mdate); p += 8;
	put_long_date(p,mdate); p += 8;
	SOFF_T(p,0,size); p += 8;
	SOFF_T(p,0,allocation_size); p += 8;
	SIVAL(p,0,nt_extmode); p += 4;
	q = p; p += 4; /* q is placeholder for name length. */
	{
		SIVAL(p,0,0); /* Extended attributes */
		p +=4;
	}
	len = srvstr_push(outbuf, p, fname, -1, STR_TERMINATE_ASCII);
	SIVAL(q, 0, len);
	p += len;

	len = PTR_DIFF(p, pdata);
	len = (len + 3) & ~3;
	SIVAL(pdata,0,len);
	p = pdata + len;
	break;

    case SMB_FIND_FILE_NAMES_INFO:
		DEBUG(0,("get_lanman2_dir_entry: 6\n"));
	p += 4;
	SIVAL(p,0,reskey); p += 4;
	p += 4;
/* this must *not* be null terminated or w2k gets in a loop trying to set an
	acl on a dir (tridge) */
	len = srvstr_push(outbuf, p, fname, -1, STR_TERMINATE_ASCII);
	SIVAL(p, -4, len);
	p += len;
	len = PTR_DIFF(p, pdata);
	len = (len + 3) & ~3;
	SIVAL(pdata,0,len);
	p = pdata + len;
	break;

    default:  
		DEBUG(0,("get_lanman2_dir_entry: FALSE!!!\n"));
      return(False);
    }


	DEBUG(0, ("####\nspace_remaining: %d, len: %d\n####\n", space_remaining, PTR_DIFF(p,pdata)));
	
  if (PTR_DIFF(p,pdata) > space_remaining) {
    /* Move the dirptr back to prev_dirpos */
    SeekDir(Connections[cnum].dirptr, prev_dirpos);
    *out_of_space = True;
    DEBUG(9,("#####\nget_lanman2_dir_entry: out of space\n"));
	
    return False; /* Not finished - just out of space */
  }

  /* Setup the last_filename pointer, as an offset from base_data */
  *last_name_off = PTR_DIFF(nameptr,base_data);
  /* Advance the data pointer to the next slot */
  *ppdata = p;
  DEBUG(0,("done get_lanman2_dir_entry!\n"));
  return(found);

}

  
/****************************************************************************
  reply to a TRANS2_FINDFIRST
****************************************************************************/
static int call_trans2findfirst(char *inbuf, char *outbuf, int bufsize, int cnum, 
			 char **pparams, char **ppdata)
{
  /* We must be careful here that we don't return more than the
     allowed number of data bytes. If this means returning fewer than
     maxentries then so be it. We assume that the redirector has
     enough room for the fixed number of parameter bytes it has
     requested. */
  uint32 max_data_bytes = SVAL(inbuf, smb_mdrcnt);
  char *params = *pparams;
  char *pdata = *ppdata;
  int dirtype = SVAL(params,0);
  int maxentries = SVAL(params,2);
  uint16 findfirst_flags = SVAL(params,4);
  BOOL close_after_first = (findfirst_flags & FLAG_TRANS2_FIND_CLOSE);
  BOOL close_if_end = (findfirst_flags & FLAG_TRANS2_FIND_CLOSE_IF_END);
  BOOL requires_resume_key = BITSETW(params+4,2);
  int info_level = SVAL(params,6);
  pstring directory;
  pstring mask;
  char *p, *wcard;
  int last_name_off=0;
  int dptr_num = -1;
  int numentries = 0;
  int i;
  BOOL finished = False;
  BOOL dont_descend = False;
  BOOL out_of_space = False;
  int space_remaining;
  BOOL bad_path = False;
  NTSTATUS ntstatus = NT_STATUS_OK;

  *directory = *mask = 0;

  DEBUG(3,("call_trans2findfirst: dirtype = %d, maxentries = %d, close_after_first=%d, close_if_end = %d requires_resume_key = %d level = %d, max_data_bytes = %d\n",
	   dirtype, maxentries, close_after_first, close_if_end, requires_resume_key,
	   info_level, max_data_bytes));
  
  switch (info_level) 
    {
    case 1:
    case 2:
    case 3:
    case 4:
    case SMB_FIND_FILE_DIRECTORY_INFO:
    case SMB_FIND_FILE_FULL_DIRECTORY_INFO:
    case SMB_FIND_FILE_NAMES_INFO:
    case SMB_FIND_FILE_BOTH_DIRECTORY_INFO:
      break;
    default:
      return(ERROR_DOS(ERRDOS,ERRunknownlevel));
    }

  srvstr_get_path(inbuf, directory, params+12, sizeof(directory), -1, STR_TERMINATE, &ntstatus, True);	
  if (!NT_STATUS_IS_OK(ntstatus)) {
		return ERROR_NT(ntstatus);
  }
  
//  pstrcpy(directory, params + 12); /* Complete directory path with 
//				     wildcard mask appended */

  DEBUG(5,("path=%s\n",directory));

  unix_convert(directory,cnum,0,&bad_path);
  
  if(!check_name(directory,cnum)) {
    	return set_bad_path_error(outbuf, errno, bad_path, ERRDOS,ERRbadpath);
  }

  p = strrchr_m(directory,'/');
  if(p == NULL) {
    strcpy(mask,directory);
    strcpy(directory,"./");
  } else {
    strcpy(mask,p+1);
    *p = 0;
  }

  DEBUG(5,("dir=%s, mask = %s\n",directory, mask));

  pdata = *ppdata = Realloc(*ppdata, max_data_bytes + 1024);
  if(!*ppdata)
    return(ERROR_DOS(ERRDOS,ERRnomem));
  bzero(pdata,max_data_bytes);

  /* Realloc the params space */
  params = *pparams = Realloc(*pparams, 10);
  if(params == NULL)
    return(ERROR_DOS(ERRDOS,ERRnomem));

  dptr_num = dptr_create(cnum,directory, True ,SVAL(inbuf,smb_pid));
  if (dptr_num < 0)
    return(ERROR_DOS(ERRDOS,ERRbadfile));

  /* convert the formatted masks */
  {
    p = mask;
    while (*p) {
      if (*p == '<') *p = '*';
      if (*p == '>') *p = '?';
      if (*p == '"') *p = '.';
      p++;
    }
  }
  
  /* a special case for 16 bit apps */
  if (strequal(mask,"????????.???")) strcpy(mask,"*");

  /* handle broken clients that send us old 8.3 format */
  string_sub(mask,"????????","*");
  string_sub(mask,".???",".*");

  /* Save the wildcard match and attribs we are using on this directory - 
     needed as lanman2 assumes these are being saved between calls */

  if(!(wcard = strdup(mask))) {
    dptr_close(dptr_num);
    return(ERROR_DOS(ERRDOS,ERRnomem));
  }

  dptr_set_wcard(dptr_num, wcard);
  dptr_set_attr(dptr_num, dirtype);

  DEBUG(4,("dptr_num is %d, wcard = %s, attr = %d\n",dptr_num, wcard, dirtype));

  /* We don't need to check for VOL here as this is returned by 
     a different TRANS2 call. */
  
  DEBUG(8,("dirpath=<%s> dontdescend=<%s>\n",
	   Connections[cnum].dirpath,lp_dontdescend(SNUM(cnum))));
  if (in_list(Connections[cnum].dirpath,lp_dontdescend(SNUM(cnum)),case_sensitive))
    dont_descend = True;
    
  p = pdata;
  space_remaining = max_data_bytes;
  out_of_space = False;

  for (i=0;(i<maxentries) && !finished && !out_of_space;i++)
    {

      /* this is a heuristic to avoid seeking the dirptr except when 
	 absolutely necessary. It allows for a filename of about 40 chars */
      if (space_remaining < DIRLEN_GUESS && numentries > 0)
	{
	  out_of_space = True;
	  finished = False;
	}
      else
	{
	  finished = 
	    !get_lanman2_dir_entry(inbuf,outbuf,cnum,mask,dirtype,info_level,
				   requires_resume_key,dont_descend,
				   &p,pdata,space_remaining, &out_of_space,
				   &last_name_off);
	}

      if (finished && out_of_space)
	finished = False;

      if (!finished && !out_of_space)
	numentries++;
      space_remaining = max_data_bytes - PTR_DIFF(p,pdata);
    }
  
  /* Check if we can close the dirptr */
  if(close_after_first || (finished && close_if_end))
    {
      dptr_close(dptr_num);
      DEBUG(5,("call_trans2findfirst - (2) closing dptr_num %d\n", dptr_num));
      dptr_num = -1;
    }

  /* 
   * If there are no matching entries we must return ERRDOS/ERRbadfile - 
   * from observation of NT.
   */

  if(numentries == 0){
	if (Protocol < PROTOCOL_NT1) {
		return ERROR_DOS(ERRDOS,ERRnofiles);
	} else {
		return ERROR_BOTH(NT_STATUS_NO_SUCH_FILE,ERRDOS,ERRbadfile);
	}
  }

  /* At this point pdata points to numentries directory entries. */

  /* Set up the return parameter block */
  SSVAL(params,0,dptr_num);
  SSVAL(params,2,numentries);
  SSVAL(params,4,finished);
  SSVAL(params,6,0); /* Never an EA error */
  SSVAL(params,8,last_name_off);

  send_trans2_replies( outbuf, bufsize, params, 10, pdata, PTR_DIFF(p,pdata));

  if ((! *directory) && dptr_path(dptr_num))
    sprintf(directory,"(%s)",dptr_path(dptr_num));

  DEBUG(4,("%s %s mask=%s directory=%s cnum=%d dirtype=%d numentries=%d\n",
	timestring(),
	smb_fn_name(CVAL(inbuf,smb_com)), 
	mask,directory,cnum,dirtype,numentries));

  return(-1);
}


/****************************************************************************
  reply to a TRANS2_FINDNEXT
****************************************************************************/
static int call_trans2findnext(char *inbuf, char *outbuf, int length, int bufsize,
			int cnum, char **pparams, char **ppdata)
{
  /* We must be careful here that we don't return more than the
     allowed number of data bytes. If this means returning fewer than
     maxentries then so be it. We assume that the redirector has
     enough room for the fixed number of parameter bytes it has
     requested. */
  int max_data_bytes = SVAL(inbuf, smb_mdrcnt);
  char *params = *pparams;
  char *pdata = *ppdata;
  int16 dptr_num = SVAL(params,0);
  int maxentries = SVAL(params,2);
  uint16 info_level = SVAL(params,4);
  uint32 resume_key = IVAL(params,6);
  BOOL close_after_request = BITSETW(params+10,0);
  BOOL close_if_end = BITSETW(params+10,1);
  BOOL requires_resume_key = BITSETW(params+10,2);
  BOOL continue_bit = BITSETW(params+10,3);
  pstring mask;
  pstring directory;
  char *p;
  uint16 dirtype;
  int numentries = 0;
  int i, last_name_off=0;
  BOOL finished = False;
  BOOL dont_descend = False;
  BOOL out_of_space = False;
  int space_remaining;
  pstring resume_name;
  NTSTATUS ntstatus = NT_STATUS_OK;

  *mask = *directory = *resume_name = 0;

  srvstr_get_path(inbuf, resume_name, params+12, sizeof(resume_name), -1, STR_TERMINATE, &ntstatus, True);
  if (!NT_STATUS_IS_OK(ntstatus)) {
		/* Win9x or OS/2 can send a resume name of ".." or ".". This will cause the parser to
		   complain (it thinks we're asking for the directory above the shared
		   path or an invalid name). Catch this as the resume name is only compared, never used in
		   a file access. JRA. */
	if (NT_STATUS_EQUAL(ntstatus,NT_STATUS_OBJECT_PATH_SYNTAX_BAD)) {
		pstrcpy(resume_name, "..");
	} else if (NT_STATUS_EQUAL(ntstatus,NT_STATUS_OBJECT_NAME_INVALID)) {
		pstrcpy(resume_name, ".");
	} else {
		return ERROR_NT(ntstatus);
	}
  }

  DEBUG(3,("call_trans2findnext: dirhandle = %d, max_data_bytes = %d, maxentries = %d," 
  		"close_after_request=%d, close_if_end = %d requires_resume_key = %d resume_key = %d" 
  		"continue=%d level = %d resume name = %s\n",
	   dptr_num, max_data_bytes, maxentries, close_after_request, close_if_end, 
	   requires_resume_key, resume_key, continue_bit, info_level, resume_name));

  switch (info_level) 
    {
    case 1:
    case 2:
    case 3:
    case 4:
    case SMB_FIND_FILE_DIRECTORY_INFO:
    case SMB_FIND_FILE_FULL_DIRECTORY_INFO:
    case SMB_FIND_FILE_NAMES_INFO:
    case SMB_FIND_FILE_BOTH_DIRECTORY_INFO:
      break;
    default:
      return(ERROR_DOS(ERRDOS,ERRunknownlevel));
    }

  pdata = *ppdata = Realloc( *ppdata, max_data_bytes + 1024);
  if(!*ppdata)
    return(ERROR_DOS(ERRDOS,ERRnomem));
  bzero(pdata,max_data_bytes);

  /* Realloc the params space */
  params = *pparams = Realloc(*pparams, 6*SIZEOFWORD);
  if(!params)
    return(ERROR_DOS(ERRDOS,ERRnomem));

  /* Check that the dptr is valid */
  if(!(Connections[cnum].dirptr = dptr_fetch_lanman2(params, dptr_num)))
    return(ERROR_DOS(ERRDOS,ERRnofiles));

  string_set(&Connections[cnum].dirpath,dptr_path(dptr_num));

  /* Get the wildcard mask from the dptr */
  if((p = dptr_wcard(dptr_num))== NULL) {
    DEBUG(2,("dptr_num %d has no wildcard\n", dptr_num));
    return (ERROR_DOS(ERRDOS,ERRnofiles));
  }
  strcpy(mask, p);
  strcpy(directory,Connections[cnum].dirpath);

  /* Get the attr mask from the dptr */
  dirtype = dptr_attr(dptr_num);

  DEBUG(3,("dptr_num is %d, mask = %s, attr = %x, dirptr=(0x%X,%d)\n",
	   dptr_num, mask, dirtype, 
	   Connections[cnum].dirptr,
	   TellDir(Connections[cnum].dirptr)));

  /* We don't need to check for VOL here as this is returned by 
     a different TRANS2 call. */

  DEBUG(8,("dirpath=<%s> dontdescend=<%s>\n",Connections[cnum].dirpath,lp_dontdescend(SNUM(cnum))));
  if (in_list(Connections[cnum].dirpath,lp_dontdescend(SNUM(cnum)),case_sensitive))
    dont_descend = True;
    
  p = pdata;
  space_remaining = max_data_bytes;
  out_of_space = False;

  /* 
	* Seek to the correct position. We no longer use the resume key but
	* depend on the last file name instead.
  */
  if(*resume_name && !continue_bit) {
	finished = !SearchDir(cnum, resume_name);
  }

  for (i=0;(i<(int)maxentries) && !finished && !out_of_space ;i++)
    {
      /* this is a heuristic to avoid seeking the dirptr except when 
	 absolutely necessary. It allows for a filename of about 40 chars */
      if (space_remaining < DIRLEN_GUESS && numentries > 0)
	{
	  out_of_space = True;
	  finished = False;
	}
      else
	{
	  finished = 
	    !get_lanman2_dir_entry(inbuf,outbuf,cnum,mask,dirtype,info_level,
				   requires_resume_key,dont_descend,
				   &p,pdata,space_remaining, &out_of_space,
				   &last_name_off);
	}

      if (finished && out_of_space)
	finished = False;

      if (!finished && !out_of_space)
	numentries++;
      space_remaining = max_data_bytes - PTR_DIFF(p,pdata);
    }
  
  /* Check if we can close the dirptr */
  if(close_after_request || (finished && close_if_end))
    {
      dptr_close(dptr_num); /* This frees up the saved mask */
      DEBUG(5,("call_trans2findnext: closing dptr_num = %d\n", dptr_num));
      dptr_num = -1;
    }


  /* Set up the return parameter block */
  SSVAL(params,0,numentries);
  SSVAL(params,2,finished);
  SSVAL(params,4,0); /* Never an EA error */
  SSVAL(params,6,last_name_off);

  send_trans2_replies( outbuf, bufsize, params, 8, pdata, PTR_DIFF(p,pdata));

  if ((! *directory) && dptr_path(dptr_num))
    sprintf(directory,"(%s)",dptr_path(dptr_num));

  DEBUG(3,("%s %s mask=%s directory=%s cnum=%d dirtype=%d numentries=%d\n",
	   timestring(),
	   smb_fn_name(CVAL(inbuf,smb_com)), 
	   mask,directory,cnum,dirtype,numentries));

  return(-1);
}

/****************************************************************************
  reply to a TRANS2_QFSINFO (query filesystem info)
****************************************************************************/
static int call_trans2qfsinfo(char *inbuf, char *outbuf, int length, int bufsize,
			int cnum, char **pparams, char **ppdata)
{
  char *pdata = *ppdata;
  char *params = *pparams;
  uint16 info_level = SVAL(params,0);
  int data_len, len;
  SMB_STRUCT_STAT st;
  char *vname = volume_label(SNUM(cnum));
  
  DEBUG(3,("call_trans2qfsinfo: cnum = %d, level = %d\n", cnum, info_level));

  if(sys_stat(".",&st)!=0) {
    DEBUG(2,("call_trans2qfsinfo: stat of . failed (%s)\n", strerror(errno)));
    return (ERROR_DOS(ERRSRV,ERRinvdevice));
  }

  pdata = *ppdata = Realloc(*ppdata, 1024); bzero(pdata,1024);

  switch (info_level) 
    {
    case 1:
      {
	SMB_BIG_UINT dfree,dsize,bsize;
	data_len = 18;
	sys_disk_free(".",&bsize,&dfree,&dsize);	
	SIVAL(pdata,l1_idFileSystem,st.st_dev);
	SIVAL(pdata,l1_cSectorUnit,bsize/512);
	SIVAL(pdata,l1_cUnit,dsize);
	SIVAL(pdata,l1_cUnitAvail,dfree);
	SSVAL(pdata,l1_cbSector,512);
	DEBUG(5,("call_trans2qfsinfo : bsize=%d, id=%x, cSectorUnit=%d, cUnit=%d, cUnitAvail=%d, cbSector=%d\n",
		 bsize, st.st_dev, bsize/512, dsize, dfree, 512));
	break;
    }
	
    case 2:
    { 

	SIVAL(pdata,0,str_checksum(lp_servicename(cnum)) ^ (str_checksum(local_machine)<<16) );
	len = srvstr_push(outbuf, pdata+l2_vol_szVolLabel, vname, -1, STR_NOALIGN);
	SCVAL(pdata,l2_vol_cch,len);
	data_len = l2_vol_szVolLabel + len;
	DEBUG(5,("call_trans2qfsinfo : time = %x, namelen = %d, name = %s\n",
				(unsigned)st.st_ctime, len, vname));
#if 0	
      /* Return volume name */
      int volname_len = MIN(strlen(vname),11);
      data_len = l2_vol_szVolLabel + volname_len + 1;
      put_dos_date2(pdata,l2_vol_fdateCreation,st.st_ctime);
      SCVAL(pdata,l2_vol_cch,volname_len);
      StrnCpy(pdata+l2_vol_szVolLabel,vname,volname_len);
      DEBUG(5,("call_trans2qfsinfo : time = %x, namelen = %d, name = %s\n",st.st_ctime, volname_len,
	       pdata+l2_vol_szVolLabel));
#endif
      break;
    }
	
    case SMB_QUERY_FS_ATTRIBUTE_INFO:

	SIVAL(pdata,0,0x4006); /* FS ATTRIBUTES == long filenames supported? */

	SIVAL(pdata,4,255); /* Max filename component length */
	/* NOTE! the fstype must *not* be null terminated or win98 won't recognise it
				and will think we can't do long filenames */
	len = srvstr_push(outbuf, pdata+12, FSTYPE_STRING, -1, STR_UNICODE);
	SIVAL(pdata,8,len);
	data_len = 12 + len;
#if 0	
      data_len = 12 + 2*strlen(FSTYPE_STRING);
      SIVAL(pdata,0,0x4006); /* FS ATTRIBUTES == long filenames supported? */
      SIVAL(pdata,4,128); /* Max filename component length */
      SIVAL(pdata,8,2*strlen(FSTYPE_STRING));
      PutUniCode(pdata+12,FSTYPE_STRING);
#endif
      break;

    case SMB_QUERY_FS_LABEL_INFO:

	len = srvstr_push(outbuf, pdata+4, vname, -1, 0);
	data_len = 4 + len;
	SIVAL(pdata,0,len);
      break;
	  
    case SMB_QUERY_FS_VOLUME_INFO:   

/* 
	* Add volume serial number - hash of a combination of
	* the called hostname and the service name.
 */
	SIVAL(pdata,8,str_checksum(lp_servicename(cnum)) ^ 
			(str_checksum(local_machine)<<16));

	len = srvstr_push(outbuf, pdata+18, vname, -1, STR_UNICODE);
	SIVAL(pdata,12,len);
	data_len = 18+len;
	DEBUG(5,("call_trans2qfsinfo : SMB_QUERY_FS_VOLUME_INFO namelen = %d, vol=%s serv=%s\n", 
				(int)strlen(vname),vname, lp_servicename(cnum)));
      break;
	  
    case SMB_QUERY_FS_SIZE_INFO:
      {
	SMB_BIG_UINT dfree,dsize,bsize,block_size,sectors_per_unit,bytes_per_sector;
	data_len = 24;
	block_size = 1024;
	
	sys_disk_free(".",&bsize,&dfree,&dsize);	
	
	if (bsize < block_size) {
		SMB_BIG_UINT factor = block_size/bsize;
		bsize = block_size;
		dsize /= factor;
		dfree /= factor;
	}
	if (bsize > block_size) {
		SMB_BIG_UINT factor = bsize/block_size;
		bsize = block_size;
		dsize *= factor;
		dfree *= factor;
	}
	bytes_per_sector = 512;
	sectors_per_unit = bsize/bytes_per_sector;
	
	SBIG_UINT(pdata,0,dsize);
	SBIG_UINT(pdata,8,dfree);
	SIVAL(pdata,16,sectors_per_unit);
	SIVAL(pdata,20,bytes_per_sector);
	break;
      }
	  
    case SMB_QUERY_FS_DEVICE_INFO:
      data_len = 8;
      SIVAL(pdata,0,0); /* dev type */
      SIVAL(pdata,4,0); /* characteristics */
      break;
	  
    default:
      return(ERROR_DOS(ERRDOS,ERRunknownlevel));
    }


  send_trans2_replies( outbuf, bufsize, params, 0, pdata, data_len);

  DEBUG(4,("%s %s info_level =%d\n",timestring(),smb_fn_name(CVAL(inbuf,smb_com)), info_level));

  return -1;
}

/****************************************************************************
  reply to a TRANS2_SETFSINFO (set filesystem info)
****************************************************************************/
static int call_trans2setfsinfo(char *inbuf, char *outbuf, int length, int bufsize,
			int cnum, char **pparams, char **ppdata)
{
  /* Just say yes we did it - there is nothing that
     can be set here so it doesn't matter. */
  int outsize;
  DEBUG(3,("call_trans2setfsinfo\n"));

  if (!CAN_WRITE(cnum))
    return(ERROR_DOS(ERRSRV,ERRaccess));

  outsize = set_message(outbuf,10,0,True);

  return outsize;
}

/****************************************************************************
  reply to a TRANS2_QFILEINFO (query file info by fileid)
****************************************************************************/
static int call_trans2qfilepathinfo(char *inbuf, char *outbuf, int length, 
				    int bufsize,int cnum,
				    char **pparams,char **ppdata,
				    int total_data)
{
  char *params = *pparams;
  char *pdata = *ppdata;
  uint16 tran_call = SVAL(inbuf, smb_setup0);
  uint16 info_level;
  int mode=0;
  SMB_OFF_T size=0;
  unsigned int data_size;
  SMB_STRUCT_STAT sbuf;
  pstring fname;
  char *p;
  SMB_OFF_T pos;
  BOOL bad_path = False;
  NTSTATUS status = NT_STATUS_OK;
  int len;
  BOOL delete_pending = False;
  uint32 desired_access = 0x12019F;
  SMB_BIG_UINT allocation_size=0;

  if (tran_call == TRANSACT2_QFILEINFO) {
    int16 fnum = GETFNUM(params,0);
    info_level = SVAL(params,2);

    if(check_dir(Files[fnum].name) || Files[fnum].fd_ptr->fd == -1){
	pstrcpy(fname, Files[fnum].name);
	if (INFO_LEVEL_IS_UNIX(info_level)) {
				/* Always do lstat for UNIX calls. */
		if (sys_lstat(fname,&sbuf)) {
			DEBUG(3,("call_trans2qfilepathinfo: SMB_VFS_LSTAT of %s failed (%s)\n",fname,strerror(errno)));
			return set_bad_path_error(outbuf, errno, bad_path, ERRDOS,ERRbadpath);
//			return ERROR_DOS(ERRDOS,ERRbadpath);
		}
	} 
	else if (sys_stat(fname,&sbuf)) {
		DEBUG(3,("call_trans2qfilepathinfo: SMB_VFS_STAT of %s failed (%s)\n",fname,strerror(errno)));
		return set_bad_path_error(outbuf, errno, bad_path, ERRDOS,ERRbadpath);
//		return ERROR_DOS(ERRDOS,ERRbadpath);
	}

	delete_pending = check_dir(Files[fnum].name) ? Files[fnum].directory_delete_on_close : 0;
    }
    else{
	CHECK_FNUM(fnum,cnum);
    	CHECK_ERROR(fnum);
		
	pstrcpy(fname, Files[fnum].name);
	if (sys_fstat(Files[fnum].fd_ptr->fd,&sbuf) != 0) {
      		DEBUG(3,("fstat of fnum %d failed (%s)\n",fnum, strerror(errno)));
      		return(UNIXERROR(ERRDOS,ERRbadfid));
    	}
	pos = sys_lseek(Files[fnum].fd_ptr->fd,0,SEEK_CUR);;
	delete_pending = Files[fnum].delete_on_close;
	desired_access = Files[fnum].desired_access;
    }
  } else {
    /* qpathinfo */
    info_level = SVAL(params,0);
    srvstr_get_path(inbuf, fname, &params[6], sizeof(fname), -1, STR_TERMINATE, &status, False);
    if (!NT_STATUS_IS_OK(status)) {
	return ERROR_NT(status);
    }
	
    unix_convert(fname,cnum,0,&bad_path);
    if(bad_path)
		return ERROR_NT(NT_STATUS_OBJECT_PATH_NOT_FOUND);
    
    if (!check_name(fname,cnum)) {
	DEBUG(3,("call_trans2qfilepathinfo: fileinfo of %s failed (%s)\n",fname,strerror(errno)));
	return set_bad_path_error(outbuf, errno, bad_path, ERRDOS,ERRbadpath);
    }

    if (INFO_LEVEL_IS_UNIX(info_level)) {
			/* Always do lstat for UNIX calls. */
	if (sys_lstat(fname,&sbuf)) {
		DEBUG(3,("call_trans2qfilepathinfo: SMB_VFS_LSTAT of %s failed (%s)\n",fname,strerror(errno)));
		return set_bad_path_error(outbuf, errno, bad_path, ERRDOS,ERRbadpath);
	}
    } else if (sys_stat(fname,&sbuf) && (info_level != SMB_INFO_IS_NAME_VALID)) {
	DEBUG(3,("call_trans2qfilepathinfo: SMB_VFS_STAT of %s failed (%s)\n",fname,strerror(errno)));
	return set_bad_path_error(outbuf, errno, bad_path, ERRDOS,ERRbadpath);
    }
    pos = 0;	//???
  }


  DEBUG(3,("call_trans2qfilepathinfo %s level=%d call=%d total_data=%d\n",
	   fname,info_level,tran_call,total_data));

  p = strrchr_m(fname,'/'); 
  if (!p) 
    p = fname;
  else
    p++;
  
  mode = dos_mode(cnum,fname,&sbuf);
  size = sbuf.st_size;
  
  SMB_BIG_UINT ret;
  ret = (SMB_BIG_UINT)STAT_ST_BLOCKSIZE * (SMB_BIG_UINT)sbuf.st_blocks;
  allocation_size = smb_roundup(ret);
  
  if (mode & aDIR)	//this is for some special files... 
  	size = 0;
  
  params = *pparams = Realloc(*pparams,2); bzero(params,2);
  data_size = 1024 + DIR_ENTRY_SAFETY_MARGIN;
  pdata = *ppdata = Realloc(*ppdata, data_size); 

  if (total_data > 0 && IVAL(pdata,0) == total_data) {
    /* uggh, EAs for OS2 */
    DEBUG(4,("Rejecting EA request with total_data=%d\n",total_data));
    return(ERROR_DOS(ERRDOS,ERReasnotsupported));
  }

  bzero(pdata,data_size);

  /* NT expects the name to be in an exact form of the *full*
	   filename. See the trans2 torture test */
	pstring dos_fname;
	if (strequal(p,".")) {
		pstrcpy(dos_fname, "\\");
	} else {
		sprintf(dos_fname, "\\%s", fname);
		string_replace(dos_fname, '/', '\\');
	}

  DEBUG(0,("going to switch info_level: %d\n", info_level));
  
  switch (info_level) 
    {
    case SMB_INFO_STANDARD:
	DEBUG(0,("call_trans2qfilepathinfo: SMB_INFO_STANDARD\n"));
	data_size = 22;
	put_dos_date2(pdata,l1_fdateCreation,sbuf.st_ctime);
	put_dos_date2(pdata,l1_fdateLastAccess,sbuf.st_atime);
	put_dos_date2(pdata,l1_fdateLastWrite,sbuf.st_mtime); /* write time */
	SIVAL(pdata,l1_cbFile,(uint32)size);
	SIVAL(pdata,l1_cbFileAlloc,(uint32)allocation_size);
	SSVAL(pdata,l1_attrFile,mode);
	break;
	
    case SMB_INFO_QUERY_EA_SIZE:
      DEBUG(0,("call_trans2qfilepathinfo: SMB_INFO_QUERY_EA_SIZE\n"));
      data_size = 26;
      put_dos_date2(pdata,l1_fdateCreation,sbuf.st_ctime); /* create = inode mod */
      put_dos_date2(pdata,l1_fdateLastAccess,sbuf.st_atime); /* access time */
      put_dos_date2(pdata,l1_fdateLastWrite,sbuf.st_mtime); /* write time */
      SIVAL(pdata,l1_cbFile,(uint32)size);
      SIVAL(pdata,l1_cbFileAlloc,(uint32)allocation_size);
      SSVAL(pdata,l1_attrFile,mode);
      SIVAL(pdata,l1_attrFile+2,4); /* this is what OS2 does */
      break;

    case SMB_INFO_IS_NAME_VALID:
	DEBUG(0,("call_trans2qfilepathinfo: SMB_INFO_IS_NAME_VALID\n"));
	if (tran_call == TRANSACT2_QFILEINFO) {
		/* os/2 needs this ? really ?*/      
		return ERROR_DOS(ERRDOS,ERRbadfunc); 
	}
	data_size = 0;
//	param_size = 0;
	break;

    case SMB_INFO_QUERY_EAS_FROM_LIST:
      DEBUG(0,("call_trans2qfilepathinfo: SMB_INFO_QUERY_EAS_FROM_LIST\n"));
      data_size = 24;
      put_dos_date2(pdata,0,sbuf.st_ctime); /* create time = inode mod time */
      put_dos_date2(pdata,4,sbuf.st_atime);
      put_dos_date2(pdata,8,sbuf.st_mtime);
      SIVAL(pdata,12,(uint32)size);
      SIVAL(pdata,16,(uint32)allocation_size);
      SIVAL(pdata,20,mode);
      break;

    case SMB_INFO_QUERY_ALL_EAS:
      data_size = 4;
      SIVAL(pdata,0,data_size);
      break;

    case SMB_QUERY_FILE_BASIC_INFO:
    case SMB_FILE_BASIC_INFORMATION:
      if (info_level == SMB_QUERY_FILE_BASIC_INFO) {
		DEBUG(0,("call_trans2qfilepathinfo: SMB_QUERY_FILE_BASIC_INFO\n"));
		data_size = 36; /* w95 returns 40 bytes not 36 - why ?. */
      } else {
		DEBUG(0,("call_trans2qfilepathinfo: SMB_FILE_BASIC_INFORMATION\n"));
		data_size = 40;
		SIVAL(pdata,36,0);
      }
      put_long_date(pdata,sbuf.st_ctime); /* create time = inode mod time */
      put_long_date(pdata+8,sbuf.st_atime); /* access time */
      put_long_date(pdata+16,sbuf.st_mtime); /* write time */
      put_long_date(pdata+24,sbuf.st_mtime); /* change time */
      SIVAL(pdata,32,mode);

      DEBUG(5,("SMB_QFBI - "));
      DEBUG(5,("create: %s ", ctime(&sbuf.st_ctime)));
      DEBUG(5,("access: %s ", ctime(&sbuf.st_atime)));
      DEBUG(5,("write: %s ", ctime(&sbuf.st_mtime)));
      DEBUG(5,("change: %s ", ctime(&sbuf.st_mtime)));
      DEBUG(5,("mode: %x\n", mode));

      break;

    case SMB_QUERY_FILE_STANDARD_INFO:
    case SMB_FILE_STANDARD_INFORMATION:
      	DEBUG(0,("call_trans2qfilepathinfo: SMB_QUERY_FILE_STANDARD_INFO\n"));
      	data_size = 24;
	SOFF_T(pdata,0,allocation_size);
	SOFF_T(pdata,8,size);

	if (delete_pending & sbuf.st_nlink)
		SIVAL(pdata,16,sbuf.st_nlink - 1);
	else
		SIVAL(pdata,16,sbuf.st_nlink);
      
      	SCVAL(pdata,20,0);
	SCVAL(pdata,21,(mode&aDIR)?1:0);
      	break;

    case SMB_QUERY_FILE_EA_INFO:
    case SMB_FILE_EA_INFORMATION:
      data_size = 4;
      break;

    /* Get the 8.3 name - used if NT SMB was negotiated. */
    case SMB_QUERY_FILE_ALT_NAME_INFO:
    case SMB_FILE_ALTERNATE_NAME_INFORMATION:
      {
	 DEBUG(0,("call_trans2qfilepathinfo: SMB_QUERY_FILE_ALT_NAME_INFO\n"));
        pstring short_name;
        pstrcpy(short_name,p);
		
//we do not support 8.3 file name	now	
#ifdef USE_83_NAME
        /* Mangle if not already 8.3 */
        if(!is_8_3(short_name, True))
        {
          if(!name_map_mangle(short_name,True,SNUM(cnum)))
            *short_name = '\0';
        }
#endif

	len = srvstr_push(outbuf, pdata+4, short_name, -1, STR_UNICODE);
	data_size = 4 + len;
	SIVAL(pdata,0,len);
/*
        strncpy(pdata + 4,short_name,12);
        (pdata + 4)[12] = 0;
        strupper_m(pdata + 4);
        l = strlen(pdata + 4);
        data_size = 4 + l;
        */
      }
      break;

    case SMB_QUERY_FILE_NAME_INFO:
	DEBUG(0,("call_trans2qfilepathinfo: SMB_QUERY_FILE_NAME_INFO\n"));
//      data_size = 4 + l;
//      SIVAL(pdata,0,l);
 //     pstrcpy(pdata+4,fname);
 	len = srvstr_push(outbuf, pdata+4, dos_fname, -1, STR_UNICODE);
 	data_size = 4 + len;
	SIVAL(pdata,0,len);
      break;

    case SMB_FILE_ALLOCATION_INFORMATION:
    case SMB_QUERY_FILE_ALLOCATION_INFO:
	DEBUG(0,("call_trans2qfilepathinfo: SMB_FILE_ALLOCATION_INFORMATION\n"));
	data_size = 8;
	SOFF_T(pdata,0,allocation_size);
	break;

    case SMB_FILE_END_OF_FILE_INFORMATION:
    case SMB_QUERY_FILE_END_OF_FILEINFO:
	DEBUG(0,("call_trans2qfilepathinfo: SMB_FILE_END_OF_FILE_INFORMATION\n"));
	data_size = 8;
	SOFF_T(pdata,0,size);
	break;

    case SMB_QUERY_FILE_ALL_INFO:
    case SMB_FILE_ALL_INFORMATION:
      DEBUG(0,("call_trans2qfilepathinfo: SMB_QUERY_FILE_ALL_INFO\n"));
      put_long_date(pdata,sbuf.st_ctime); /* create time = inode mod time */
      put_long_date(pdata+8,sbuf.st_atime); /* access time */
      put_long_date(pdata+16,sbuf.st_mtime); /* write time */
      put_long_date(pdata+24,sbuf.st_mtime); /* change time */
      SIVAL(pdata,32,mode);
      pdata += 40;
      SOFF_T(pdata,0,allocation_size);
      SOFF_T(pdata,8,size);
      if (delete_pending && sbuf.st_nlink)
		SIVAL(pdata,16,sbuf.st_nlink - 1);
      else
		SIVAL(pdata,16,sbuf.st_nlink);
      SCVAL(pdata,20,delete_pending);
      SCVAL(pdata,21,(mode&aDIR)?1:0);
      pdata += 24;
      pdata += 8; /* index number */
      pdata += 4; /* EA info */
      if (mode & aRONLY)
	SIVAL(pdata,0,0xA9);
      else
	SIVAL(pdata,0,0xd01BF);
      pdata += 4;
      SIVAL(pdata,0,pos); /* current offset */
      pdata += 8;
      SIVAL(pdata,0,mode); /* is this the right sort of mode info? */
      pdata += 4;
      pdata += 4; /* alignment */
      len = srvstr_push(outbuf, pdata+4, dos_fname, -1, STR_UNICODE);
      SIVAL(pdata,0,len);
      pdata += 4 + len;
      data_size = PTR_DIFF(pdata,(*ppdata));
/*
      SIVAL(pdata,0,l);
      pstrcpy(pdata+4,fname);
      pdata += 4 + l;
      data_size = PTR_DIFF(pdata,(*ppdata));
      */
      break;

    case SMB_FILE_INTERNAL_INFORMATION:
		/* This should be an index number - looks like
		dev/ino to me :-) */

	DEBUG(0,("call_trans2qfilepathinfo: SMB_FILE_INTERNAL_INFORMATION\n"));
	SIVAL(pdata,0,sbuf.st_dev);
	SIVAL(pdata,4,sbuf.st_ino);
	data_size = 8;
	break;

    case SMB_FILE_ACCESS_INFORMATION:
	DEBUG(0,("call_trans2qfilepathinfo: SMB_FILE_ACCESS_INFORMATION\n"));
	SIVAL(pdata,0,desired_access);
	data_size = 4;
	break;

    case SMB_FILE_NAME_INFORMATION:
    {
//Pathname with leading '\'
	size_t byte_len;
	byte_len = dos_PutUniCode(pdata+4,dos_fname,1024,False);
	DEBUG(0,("call_trans2qfilepathinfo: SMB_FILE_NAME_INFORMATION\n"));
	SIVAL(pdata,0,byte_len);
	data_size = 4 + byte_len;
	break;
    }

    case SMB_FILE_DISPOSITION_INFORMATION:
	DEBUG(0,("call_trans2qfilepathinfo: SMB_FILE_DISPOSITION_INFORMATION\n"));
	data_size = 1;
	SCVAL(pdata,0,delete_pending);
	break;

    case SMB_FILE_POSITION_INFORMATION:
	DEBUG(0,("call_trans2qfilepathinfo: SMB_FILE_POSITION_INFORMATION\n"));
	data_size = 8;
	SOFF_T(pdata,0,pos);
	break;

    case SMB_FILE_MODE_INFORMATION:
	DEBUG(0,("call_trans2qfilepathinfo: SMB_FILE_MODE_INFORMATION\n"));
	SIVAL(pdata,0,mode);
	data_size = 4;
	break;

    case SMB_FILE_ALIGNMENT_INFORMATION:
	DEBUG(0,("call_trans2qfilepathinfo: SMB_FILE_ALIGNMENT_INFORMATION\n"));
	SIVAL(pdata,0,0); /* No alignment needed. */
	data_size = 4;
	break;

    case SMB_QUERY_FILE_STREAM_INFO:
      DEBUG(0,("call_trans2qfilepathinfo: SMB_FILE_STREAM_INFORMATION\n"));
	if (mode & aDIR) {
		data_size = 0;
	} else {
		size_t byte_len = dos_PutUniCode(pdata+24,"::$DATA", 0xE, False);
		SIVAL(pdata,0,0); /* ??? */
		SIVAL(pdata,4,byte_len); /* Byte length of unicode string ::$DATA */
		SOFF_T(pdata,8,size);
		SIVAL(pdata,16,allocation_size);
		SIVAL(pdata,20,0); /* ??? */
		data_size = 24 + byte_len;
	}
	break;

    case SMB_QUERY_COMPRESSION_INFO:
    case SMB_FILE_COMPRESSION_INFORMATION:
	DEBUG(0,("call_trans2qfilepathinfo: SMB_FILE_COMPRESSION_INFORMATION\n"));
	SOFF_T(pdata,0,size);
	SIVAL(pdata,8,0); /* ??? */
	SIVAL(pdata,12,0); /* ??? */
	data_size = 16;
	break;

    case SMB_FILE_NETWORK_OPEN_INFORMATION:
	DEBUG(0,("call_trans2qfilepathinfo: SMB_FILE_NETWORK_OPEN_INFORMATION\n"));
	put_long_date(pdata,sbuf.st_ctime);
	put_long_date(pdata+8,sbuf.st_atime);
	put_long_date(pdata+16,sbuf.st_mtime); /* write time */
	put_long_date(pdata+24,sbuf.st_mtime); /* change time */
	SIVAL(pdata,32,allocation_size);
	SOFF_T(pdata,40,size);
	SIVAL(pdata,48,mode);
	SIVAL(pdata,52,0); /* ??? */
	data_size = 56;
	break;

    case SMB_FILE_ATTRIBUTE_TAG_INFORMATION:
	DEBUG(0,("call_trans2qfilepathinfo: SMB_FILE_ATTRIBUTE_TAG_INFORMATION\n"));
	SIVAL(pdata,0,mode);
	SIVAL(pdata,4,0);
	data_size = 8;
	break;
	
    default:
      DEBUG(0,("call_trans2qfilepathinfo: unknow info_level: 0x%x!\n", info_level));
      return(ERROR_DOS(ERRDOS,ERRunknownlevel));
    }

  send_trans2_replies( outbuf, bufsize, params, 2, *ppdata, data_size);

  return(-1);
}


/****************************************************************************
  reply to a TRANS2_SETFILEINFO (set file info by fileid)
****************************************************************************/
static int call_trans2setfilepathinfo(char *inbuf, char *outbuf, int length, 
				      int bufsize, int cnum, char **pparams, 
				      char **ppdata, int total_data)
{
  char *params = *pparams;
  char *pdata = *ppdata;
  uint16 tran_call = SVAL(inbuf, smb_setup0);
  uint16 info_level;
  int mode=0;
  SMB_OFF_T size=0;
  struct utimbuf tvs;
  SMB_STRUCT_STAT st;
//  pstring fname1;
  pstring fname;
  int fd = -1;
  BOOL bad_path = False;
  NTSTATUS status;
  int16 fnum = -1;

  if (!CAN_WRITE(cnum))
    return(ERROR_DOS(ERRSRV,ERRaccess));

  if (tran_call == TRANSACT2_SETFILEINFO) {
    fnum = GETFNUM(params,0);
    info_level = SVAL(params,2);    

    if(check_dir(Files[fnum].name) || Files[fnum].fd_ptr->fd == -1){
	pstrcpy(fname, Files[fnum].name);
	if(sys_stat(fname, &st) != 0)
		return set_bad_path_error(outbuf, errno, bad_path, ERRDOS,ERRbadpath);
    }
    else{
	CHECK_FNUM(fnum,cnum);
    	CHECK_ERROR(fnum);
		
	pstrcpy(fname, Files[fnum].name);
	fd = Files[fnum].fd_ptr->fd;
	if(sys_fstat(fd, &st) != 0)
		return(UNIXERROR(ERRDOS,ERRbadpath));
    }
  } else {
    /* set path info */
    info_level = SVAL(params,0);    
 //   fname = fname1;
 //   pstrcpy(fname,&params[6]);
	srvstr_get_path(inbuf, fname, &params[6], sizeof(fname), -1, STR_TERMINATE, &status, False);
	DEBUG(0,("###(%s:%d)name: %s\n", __FUNCTION__, __LINE__, fname));
	if (!NT_STATUS_IS_OK(status)) {
		return ERROR_NT(status);
	}
	
    unix_convert(fname,cnum,0,&bad_path);
    if (bad_path) {
	return ERROR_NT(NT_STATUS_OBJECT_PATH_NOT_FOUND);
    }
	
    if(!check_name(fname, cnum))
    {
      	return set_bad_path_error(outbuf, errno, bad_path, ERRDOS,ERRbadpath);
    }
 
    if(sys_stat(fname,&st)!=0) {
      DEBUG(3,("stat of %s failed (%s)\n", fname, strerror(errno)));
      return set_bad_path_error(outbuf, errno, bad_path, ERRDOS,ERRbadpath);
    }
  }

  DEBUG(3,("call_trans2setfilepathinfo(%d) %s info_level=%d totdata=%d\n",
	   tran_call,fname,info_level,total_data));

  /* Realloc the parameter and data sizes */
  params = *pparams = Realloc(*pparams,2); 
  
  if(params == NULL)
    return(ERROR_DOS(ERRDOS,ERRnomem));

  SSVAL(params,0,0);
  
  size = st.st_size;
  tvs.modtime = st.st_mtime;
  tvs.actime = st.st_atime;
  mode = dos_mode(cnum,fname,&st);
  
/*
  if (total_data > 0 && IVAL(pdata,0) == total_data) {
    DEBUG(4,("Rejecting EA request with total_data=%d\n",total_data));
    return(ERROR(ERRDOS,ERROR_EAS_NOT_SUPPORTED));
  }
*/

  switch (info_level)
  {
    case SMB_INFO_STANDARD:
    case SMB_INFO_QUERY_EA_SIZE:
    {
      /* access time */
      tvs.actime = make_unix_date2(pdata+l1_fdateLastAccess);

      /* write time */
      tvs.modtime = make_unix_date2(pdata+l1_fdateLastWrite);

      mode = SVAL(pdata,l1_attrFile);
      size = IVAL(pdata,l1_cbFile);
      break;
    }

    /* XXXX um, i don't think this is right.
       it's also not in the cifs6.txt spec.
     */
    case SMB_INFO_QUERY_EAS_FROM_LIST:
      tvs.actime = make_unix_date2(pdata+8);
      tvs.modtime = make_unix_date2(pdata+12);
      size = IVAL(pdata,16);
      mode = IVAL(pdata,24);
      break;

    /* XXXX nor this.  not in cifs6.txt, either. */
    case SMB_INFO_QUERY_ALL_EAS:
      tvs.actime = make_unix_date2(pdata+8);
      tvs.modtime = make_unix_date2(pdata+12);
      size = IVAL(pdata,16);
      mode = IVAL(pdata,24);
      break;

    case SMB_SET_FILE_BASIC_INFO:
    case SMB_FILE_BASIC_INFORMATION:
    {
	time_t changed_time;
	time_t write_time;
      /* Ignore create time at offset pdata. */

      /* access time */
      tvs.actime = interpret_long_date(pdata+8);

      /* write time + changed time, combined. */
      write_time = MAX(interpret_long_date(pdata+16),
      changed_time = interpret_long_date(pdata+24));

	tvs.modtime = MIN(write_time, changed_time);

	if (write_time > tvs.modtime && write_time != (time_t)-1) {
				tvs.modtime = write_time;
	}
			/* Prefer a defined time to an undefined one. */
	if (null_mtime(tvs.modtime)) {
		tvs.modtime = null_mtime(write_time) ? changed_time : write_time;
	}

      /* attributes */
      mode = IVAL(pdata,32);
      break;
    }
//##################################################//
   case SMB_FILE_ALLOCATION_INFORMATION:
   case SMB_SET_FILE_ALLOCATION_INFO:
   {
	int ret = -1;
	SMB_BIG_UINT allocation_size;

	allocation_size = (SMB_BIG_UINT)IVAL(pdata,0);
	
#ifdef LARGE_FILE_SUPPORT
			allocation_size |= (((SMB_BIG_UINT)IVAL(pdata,4)) << 32);
#else
	if (IVAL(pdata,4) != 0) /* more than 32 bits? */
		return ERROR_DOS(ERRDOS,ERRunknownlevel);
#endif

	DEBUG(10,("call_trans2setfilepathinfo: Set file allocation info for file %s to %.0f\n",
			fname, (double)allocation_size ));

	if (allocation_size) {
		allocation_size = smb_roundup(allocation_size);
	}

	DEBUG(0,("allocation size after roundup: %lld\n", allocation_size));

	if(allocation_size != st.st_size) {
		SMB_STRUCT_STAT new_sbuf;
 
		DEBUG(10,("call_trans2setfilepathinfo: file %s : setting new allocation size to %.0f\n",
				fname, (double)allocation_size ));

		if (fd == -1) {
			files_struct *new_fsp;
			int new_fnum = find_free_file();
			int access_mode = 0;
			int action = 0;
			
#ifdef OPLOCK_ENABLE			
			if(global_oplock_break) {
				/* Queue this file modify as we are the process of an oplock break.  */
				return -1;
			}
#endif

//do we need to use open_share_file function???
			open_nt_file_shared(new_fnum, cnum, fname,
						FILE_WRITE_DATA, DOS_OPEN_RDWR,
						(FILE_FAIL_IF_NOT_EXIST|FILE_EXISTS_OPEN),
						FILE_ATTRIBUTE_NORMAL,
						8/*need to update?*/, &access_mode, &action);

			new_fsp = &Files[new_fnum];

//			new_fd = sys_open(fname,O_RDWR,0);

			if (!new_fsp->open)
				return(UNIXERROR(ERRDOS,ERRbadpath));
			
/*do not allocate file space here and below. Do it at last if we really need to create this file...!*/			
//			ret = set_filelen(new_fsp->fd_ptr->fd, allocation_size);
			
			if (sys_fstat(new_fsp->fd_ptr->fd,&new_sbuf) != 0) {
				DEBUG(3,("call_trans2setfilepathinfo: fstat of fnum %d failed (%s)\n",
						new_fnum, strerror(errno)));
				ret = -1;
			}
			
			ret = 0;
			close_file(new_fnum, True);
		}
		else{
//			ret = set_filelen(fd, allocation_size);
			if (sys_fstat(fd,&new_sbuf) != 0) {
				DEBUG(3,("call_trans2setfilepathinfo: fstat of fnum %d failed (%s)\n",
						fnum, strerror(errno)));
				ret = -1;
			}
			ret = 0;
		}
		if (ret == -1)
			return ERROR_NT(NT_STATUS_DISK_FULL);
		
		/* Allocate can truncate size... */
		size = new_sbuf.st_size;
	}
	break;
   }

    case SMB_SET_FILE_END_OF_FILE_INFO:
    case SMB_FILE_END_OF_FILE_INFORMATION:
    {
      size = IVAL(pdata,0);
#ifdef LARGE_FILE_SUPPORT
	size |= (((SMB_OFF_T)IVAL(pdata,4)) << 32);
#else 
	if (IVAL(pdata,4) != 0)	/* more than 32 bits? */
		return ERROR_DOS(ERRDOS,ERRunknownlevel);
#endif 
      break;
    }

    case SMB_FILE_DISPOSITION_INFORMATION:
    case SMB_SET_FILE_DISPOSITION_INFO:
    {
	DEBUG(0,("call_trans2setfilepathinfo: SMB_SET_FILE_DISPOSITION_INFO\n"));
	BOOL delete_on_close;
	delete_on_close = (CVAL(pdata,0) ? True : False);

	/* Just ignore this set on a path. */
	if (tran_call != TRANSACT2_SETFILEINFO)
		break;

	if(fnum == -1)
		return(UNIXERROR(ERRDOS,ERRbadfid));

	status = set_delete_on_close_internal(cnum, &Files[fnum], 
									  delete_on_close, mode);
	
	if (NT_STATUS_V(status) !=  NT_STATUS_V(NT_STATUS_OK))
				return ERROR_NT(status);

	break;
    }

    case SMB_FILE_POSITION_INFORMATION:
    {
//we actually do not support this methold.....
#ifndef LARGE_FILE_SUPPORT
	if (IVAL(pdata,4) != 0) /* more than 32 bits? */
		return ERROR_DOS(ERRDOS,ERRunknownlevel);
#endif

	break;
    }

    case SMB_FILE_RENAME_INFORMATION:
    {
	BOOL overwrite;
	uint32 root_fid;
	uint32 len;
	pstring newname;
	pstring base_name;
	char *p;
	NTSTATUS error;

	overwrite = (CVAL(pdata,0) ? True : False);
	root_fid = IVAL(pdata,4);
	len = IVAL(pdata,8);
	srvstr_get_path(inbuf, newname, &pdata[12], sizeof(newname), len, 0, &status, False);
	if (!NT_STATUS_IS_OK(status)) {
		return ERROR_NT(status);
	}

	if (strchr_m(newname, '/'))
		return ERROR_NT(NT_STATUS_NOT_SUPPORTED);

	/* Create the base directory. */
	pstrcpy(base_name, fname);
	p = strrchr_m(base_name, '/');
	if (p)
		*p = '\0';
	/* Append the new name. */
	pstrcat(base_name, "/");
	pstrcat(base_name, newname);

	if (fnum != -1) {
		DEBUG(10,("call_trans2setfilepathinfo: SMB_FILE_RENAME_INFORMATION (fnum %d) %s -> %s\n",
				fnum, Files[fnum].name, base_name ));
//could be in trouble when renaming an open file....
		error = mv_internals(cnum, Files[fnum].name, base_name);
	} else {
		DEBUG(10,("call_trans2setfilepathinfo: SMB_FILE_RENAME_INFORMATION %s -> %s\n",
				fname, newname ));
		error = mv_internals(cnum, fname, base_name);
	}
	
	if (!NT_STATUS_IS_OK(error)) {
		return ERROR_NT(error);
	}

	SSVAL(params,0,0);
	send_trans2_replies(outbuf, bufsize, params, 2, *ppdata, 0);
	return(-1);
    }
		
    default:
    {
      return(ERROR_DOS(ERRDOS,ERRunknownlevel));
    }
  }

  DEBUG(6,("actime: %s " , ctime(&tvs.actime)));
  DEBUG(6,("modtime: %s ", ctime(&tvs.modtime)));
  DEBUG(6,("size: %x "   , size));
  DEBUG(6,("mode: %x\n"  , mode));

  /* get some defaults (no modifications) if any info is zero. */
  if (null_mtime(tvs.actime)) 
  	tvs.actime = st.st_atime;

  if (null_mtime(tvs.modtime)) 
  	tvs.modtime = st.st_mtime;

  if(!((info_level == SMB_SET_FILE_END_OF_FILE_INFO) ||
		(info_level == SMB_SET_FILE_ALLOCATION_INFO) ||
		(info_level == SMB_FILE_ALLOCATION_INFORMATION) ||
		(info_level == SMB_FILE_END_OF_FILE_INFORMATION))) {

		/*
		 * Only do this test if we are not explicitly
		 * changing the size of a file.
		 */
	if (!size)
		size = st.st_size;
  }

  if (mode) {
	if (S_ISDIR(st.st_mode))
		mode |= aDIR;
	else
		mode &= ~aDIR;
  }

  DEBUG(6,("dosmode: %x\n"  , mode));

  /* Try and set the times, size and mode of this file -
     if they are different from the current values
   */
  if (st.st_mtime != tvs.modtime || st.st_atime != tvs.actime)
  {
    if(file_utime(cnum, fname, &tvs)!=0)
    {
      return(ERROR_DOS(ERRDOS,ERRnoaccess));
    }
  }

  if(!VALID_STAT(st)){
	DEBUG(0,("stat is not valid???\n"));
	return ERROR_DOS(ERRDOS,ERRnoaccess);
  }
  
  /* check the mode isn't different, before changing it */
  if (mode != dos_mode(cnum, fname, &st) && (mode != 0))
  {
    DEBUG(2,("set the mode of file (%s) in trans2setfilepathinfo!\n", fname));
    if(dos_chmod(cnum, fname, mode, NULL)){
    	DEBUG(2,("chmod of %s failed (%s)\n", fname, strerror(errno)));
    	return(UNIXERROR(ERRDOS,ERRnoaccess));
    }
  }

//now set the size for all info_level....
  if(size != st.st_size)
  {
    int filelen_res;
    if (fd == -1)
    {
      	int new_fnum = find_free_file();
	files_struct *new_fsp;
	int access_mode = 0;
	int action = 0;

	open_file_shared(new_fnum, cnum, fname,
					DOS_OPEN_RDWR,
					(FILE_FAIL_IF_NOT_EXIST|FILE_EXISTS_OPEN),
					FILE_ATTRIBUTE_NORMAL,
					8, &access_mode, &action);
	
	new_fsp = &Files[new_fnum];
	
//      fd = sys_open(fname,O_RDWR,0);
      	if (!new_fsp->open)
      	{
        	return(UNIXERROR(ERRDOS,ERRbadpath));
      	}
      	filelen_res = set_filelen(new_fsp->fd_ptr->fd, size);
      	close_file(new_fnum, True);
    }
    else
    {
      	filelen_res = set_filelen(fd, size);
    }

    if(filelen_res == -1){	
	return ERROR_NT(NT_STATUS_DISK_FULL);
    }
  }

  SSVAL(params,0,0);

  send_trans2_replies(outbuf, bufsize, params, 2, *ppdata, 0);
  
  return(-1);
}

/****************************************************************************
  reply to a TRANS2_MKDIR (make directory with extended attributes).
****************************************************************************/
static int call_trans2mkdir(char *inbuf, char *outbuf, int length, int bufsize,
			int cnum, char **pparams, char **ppdata)
{
  char *params = *pparams;
  pstring directory;
  int ret = -1;
  BOOL bad_path = False;
  NTSTATUS status;

  if (!CAN_WRITE(cnum))
    return(ERROR_DOS(ERRSRV,ERRaccess));

//  pstrcpy(directory, &params[4]);
	srvstr_get_path(inbuf, directory, &params[4], sizeof(directory), -1, STR_TERMINATE, &status, False);
	if (!NT_STATUS_IS_OK(status)) {
		return ERROR_NT(status);
	}

  DEBUG(3,("call_trans2mkdir : name = %s\n", directory));

  unix_convert(directory,cnum,0,&bad_path);
  if (bad_path) {
	return ERROR_NT(NT_STATUS_OBJECT_PATH_NOT_FOUND);
  }
  
  if (check_name(directory,cnum))
    ret = sys_mkdir(directory,unix_mode(cnum,aDIR));
  
  if(ret < 0)
    {
      DEBUG(5,("call_trans2mkdir error (%s)\n", strerror(errno)));
      return set_bad_path_error(outbuf, errno, bad_path, ERRDOS,ERRnoaccess);
    }

  /* Realloc the parameter and data sizes */
  params = *pparams = Realloc(*pparams,2);
  if(params == NULL)
    return(ERROR_DOS(ERRDOS,ERRnomem));

  SSVAL(params,0,0);

  send_trans2_replies(outbuf, bufsize, params, 2, *ppdata, 0);
  
  return(-1);
}

/****************************************************************************
  reply to a TRANS2_FINDNOTIFYFIRST (start monitoring a directory for changes)
  We don't actually do this - we just send a null response.
****************************************************************************/
static int call_trans2findnotifyfirst(char *inbuf, char *outbuf, int length, int bufsize,
			int cnum, char **pparams, char **ppdata)
{
  static uint16 fnf_handle = 257;
  char *params = *pparams;
  uint16 info_level = SVAL(params,4);

  DEBUG(3,("call_trans2findnotifyfirst - info_level %d\n", info_level));

  switch (info_level) 
    {
    case 1:
    case 2:
      break;
    default:
      return(ERROR_DOS(ERRDOS,ERRunknownlevel));
    }

  /* Realloc the parameter and data sizes */
  params = *pparams = Realloc(*pparams,6);
  if(params == NULL)
    return(ERROR_DOS(ERRDOS,ERRnomem));

  SSVAL(params,0,fnf_handle);
  SSVAL(params,2,0); /* No changes */
  SSVAL(params,4,0); /* No EA errors */

  fnf_handle++;

  if(fnf_handle == 0)
    fnf_handle = 257;

  send_trans2_replies(outbuf, bufsize, params, 6, *ppdata, 0);
  
  return(-1);
}

/****************************************************************************
  reply to a TRANS2_FINDNOTIFYNEXT (continue monitoring a directory for 
  changes). Currently this does nothing.
****************************************************************************/
static int call_trans2findnotifynext(char *inbuf, char *outbuf, int length, int bufsize,
			int cnum, char **pparams, char **ppdata)
{
  char *params = *pparams;

  DEBUG(3,("call_trans2findnotifynext\n"));

  /* Realloc the parameter and data sizes */
  params = *pparams = Realloc(*pparams,4);
  if(params == NULL)
    return(ERROR_DOS(ERRDOS,ERRnomem));

  SSVAL(params,0,0); /* No changes */
  SSVAL(params,2,0); /* No EA errors */

  send_trans2_replies(outbuf, bufsize, params, 4, *ppdata, 0);
  
  return(-1);
}

/****************************************************************************
  reply to a SMBfindclose (stop trans2 directory search)
****************************************************************************/
int reply_findclose(char *inbuf,char *outbuf,int length,int bufsize)
{
  int cnum;
  int outsize = 0;
  int16 dptr_num=SVALS(inbuf,smb_vwv0);

  cnum = SVAL(inbuf,smb_tid);

  DEBUG(3,("reply_findclose, cnum = %d, dptr_num = %d\n", cnum, dptr_num));

  dptr_close(dptr_num);

  outsize = set_message(outbuf,0,0,True);

  DEBUG(3,("%s SMBfindclose cnum=%d, dptr_num = %d\n",timestring(),cnum,dptr_num));

  return(outsize);
}

/****************************************************************************
  reply to a SMBfindnclose (stop FINDNOTIFYFIRST directory search)
****************************************************************************/
int reply_findnclose(char *inbuf,char *outbuf,int length,int bufsize)
{
  int cnum;
  int outsize = 0;
  int dptr_num= -1;

  cnum = SVAL(inbuf,smb_tid);
  dptr_num = SVAL(inbuf,smb_vwv0);

  DEBUG(3,("reply_findnclose, cnum = %d, dptr_num = %d\n", cnum, dptr_num));

  /* We never give out valid handles for a 
     findnotifyfirst - so any dptr_num is ok here. 
     Just ignore it. */

  outsize = set_message(outbuf,0,0,True);

  DEBUG(3,("%s SMB_findnclose cnum=%d, dptr_num = %d\n",timestring(),cnum,dptr_num));

  return(outsize);
}


/****************************************************************************
  reply to a SMBtranss2 - just ignore it!
****************************************************************************/
int reply_transs2(char *inbuf,char *outbuf,int length,int bufsize)
{
  DEBUG(4,("Ignoring transs2 of length %d\n",length));
  return(-1);
}

/****************************************************************************
  reply to a SMBtrans2
****************************************************************************/
int reply_trans2(char *inbuf,char *outbuf,int length,int bufsize)
{
  int outsize = 0;
  int cnum = SVAL(inbuf,smb_tid);
  unsigned int total_params = SVAL(inbuf, smb_tpscnt);
  unsigned int total_data =SVAL(inbuf, smb_tdscnt);
#if 0
  unsigned int max_param_reply = SVAL(inbuf, smb_mprcnt);
  unsigned int max_data_reply = SVAL(inbuf, smb_mdrcnt);
  unsigned int max_setup_fields = SVAL(inbuf, smb_msrcnt);
  BOOL close_tid = BITSETW(inbuf+smb_flags,0);
  BOOL no_final_response = BITSETW(inbuf+smb_flags,1);
  int32 timeout = IVALS(inbuf,smb_timeout);
#endif
  unsigned int suwcnt = SVAL(inbuf, smb_suwcnt);
  unsigned int tran_call = SVAL(inbuf, smb_setup0);
  char *params = NULL, *data = NULL;
  int num_params, num_params_sofar, num_data, num_data_sofar;

  if (IS_IPC(cnum) && (tran_call != TRANSACT2_OPEN)
            && (tran_call != TRANSACT2_GET_DFS_REFERRAL)) {
		return ERROR_DOS(ERRSRV,ERRaccess);
  }

  outsize = set_message(outbuf,0,0,True);

  /* All trans2 messages we handle have smb_sucnt == 1 - ensure this
     is so as a sanity check */
  if(suwcnt != 1 )
    {
      DEBUG(2,("Invalid smb_sucnt in trans2 call\n"));
      return(ERROR_DOS(ERRSRV,ERRerror));
    }
    
  /* Allocate the space for the maximum needed parameters and data */
  if (total_params > 0)
    params = (char *)malloc(total_params);
  if (total_data > 0)
    data = (char *)malloc(total_data);
  
  if ((total_params && !params)  || (total_data && !data))
    {
      DEBUG(2,("Out of memory in reply_trans2\n"));
      return(ERROR_DOS(ERRDOS,ERRnomem));
    }

  /* Copy the param and data bytes sent with this request into
     the params buffer */
  num_params = num_params_sofar = SVAL(inbuf,smb_pscnt);
  num_data = num_data_sofar = SVAL(inbuf, smb_dscnt);

  if (num_params > total_params || num_data > total_data)
	  exit_server("invalid params in reply_trans2");

  memcpy( params, smb_base(inbuf) + SVAL(inbuf, smb_psoff), num_params);
  memcpy( data, smb_base(inbuf) + SVAL(inbuf, smb_dsoff), num_data);

  if(num_data_sofar < total_data || num_params_sofar < total_params)
    {
    /* We need to send an interim response then receive the rest
       of the parameter/data bytes */
      outsize = set_message(outbuf,0,0,True);
      send_smb(Client,outbuf);

      while( num_data_sofar < total_data || num_params_sofar < total_params)
	{
          BOOL ret;

          ret = receive_next_smb(Client,
#ifdef OPLOCK_ENABLE
		  				oplock_sock,
#endif
		  				inbuf,bufsize,
                             		SMB_SECONDARY_WAIT);

	  if((ret && (CVAL(inbuf, smb_com) != SMBtranss2)) || !ret)
	    {
	      outsize = set_message(outbuf,0,0,True);
              if(ret)
                DEBUG(0,("reply_trans2: Invalid secondary trans2 packet\n"));
              else
                DEBUG(0,("reply_trans2: %s in getting secondary trans2 response.\n",
                         (smb_read_error == READ_ERROR) ? "error" : "timeout" ));
	      free(params);
	      free(data);
	      return(ERROR_NT(NT_STATUS_INVALID_PARAMETER));
	    }
      
	  /* Revise total_params and total_data in case they have changed downwards */
	  total_params = SVAL(inbuf, smb_tpscnt);
	  total_data = SVAL(inbuf, smb_tdscnt);
	  num_params_sofar += (num_params = SVAL(inbuf,smb_spscnt));
	  num_data_sofar += ( num_data = SVAL(inbuf, smb_sdscnt));
	  if (num_params_sofar > total_params || num_data_sofar > total_data)
		  exit_server("data overflow in trans2");

	  memcpy( &params[ SVAL(inbuf, smb_spsdisp)], 
		 smb_base(inbuf) + SVAL(inbuf, smb_spsoff), num_params);
	  memcpy( &data[SVAL(inbuf, smb_sdsdisp)],
		 smb_base(inbuf)+ SVAL(inbuf, smb_sdsoff), num_data);
	}
    }

  if (Protocol >= PROTOCOL_NT1) {
    uint16 flg2 = SVAL(outbuf,smb_flg2);
    SSVAL(outbuf,smb_flg2,flg2 | 0x40); /* IS_LONG_NAME */
  }

  /* Now we must call the relevant TRANS2 function */
  DEBUG(0,("tran_call is: %d!\n", tran_call));
  
  switch(tran_call) 
    {
    case TRANSACT2_OPEN:
      outsize = call_trans2open(inbuf, outbuf, bufsize, cnum, &params, &data);
      break;
    case TRANSACT2_FINDFIRST:
      outsize = call_trans2findfirst(inbuf, outbuf, bufsize, cnum, &params, &data);
      break;
    case TRANSACT2_FINDNEXT:
      outsize = call_trans2findnext(inbuf, outbuf, length, bufsize, cnum, &params, &data);
      break;
    case TRANSACT2_QFSINFO:
      outsize = call_trans2qfsinfo(inbuf, outbuf, length, bufsize, cnum, &params, &data);
      break;
    case TRANSACT2_SETFSINFO:
      outsize = call_trans2setfsinfo(inbuf, outbuf, length, bufsize, cnum, &params, &data);
      break;
    case TRANSACT2_QPATHINFO:
    case TRANSACT2_QFILEINFO:
      outsize = call_trans2qfilepathinfo(inbuf, outbuf, length, bufsize, cnum, &params, &data, total_data);
      break;
    case TRANSACT2_SETPATHINFO:
    case TRANSACT2_SETFILEINFO:
      outsize = call_trans2setfilepathinfo(inbuf, outbuf, length, bufsize, cnum, &params, &data, total_data);
      break;
    case TRANSACT2_FINDNOTIFYFIRST:
      outsize = call_trans2findnotifyfirst(inbuf, outbuf, length, bufsize, cnum, &params, &data);
      break;
    case TRANSACT2_FINDNOTIFYNEXT:
      outsize = call_trans2findnotifynext(inbuf, outbuf, length, bufsize, cnum, &params, &data);
      break;
    case TRANSACT2_MKDIR:
      outsize = call_trans2mkdir(inbuf, outbuf, length, bufsize, cnum, &params, &data);
      break;
    default:
      /* Error in request */
      DEBUG(2,("%s Unknown request %d in trans2 call\n",timestring(), tran_call));
      SAFE_FREE(params);
      SAFE_FREE(data);
      
      return (ERROR_DOS(ERRSRV,ERRnosupport));
    }

  /* As we do not know how many data packets will need to be
     returned here the various call_trans2xxxx calls
     must send their own. Thus a call_trans2xxx routine only
     returns a value other than -1 when it wants to send
     an error packet. 
  */

  SAFE_FREE(params);;
  SAFE_FREE(data);
  return outsize; /* If a correct response was needed the call_trans2xxx 
		     calls have already sent it. If outsize != -1 then it is
		     returning an error packet. */
}

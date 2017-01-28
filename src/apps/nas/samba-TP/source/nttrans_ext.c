#include "includes.h"


//NOTE: MANY STATIC FUNCTIONS IN server.c are changed into normal functions...not sure if
//any other problem would be caused...

extern int DEBUGLEVEL;
extern connection_struct Connections[];
extern files_struct Files[];

#ifdef OPLOCK_ENABLE
extern int32 global_oplocks_open;
extern uint16 oplock_port;
#endif

extern NTSTATUS unix_ERR_ntstatus;

struct generic_mapping file_generic_mapping = {
	FILE_GENERIC_READ,
	FILE_GENERIC_WRITE,
	FILE_GENERIC_EXECUTE,
	FILE_GENERIC_ALL
};

#define GetTimeOfDay(x) gettimeofday(x,NULL)

/****************************************************************************
 Utility function to map create disposition.
****************************************************************************/

static int map_create_disposition( uint32 create_disposition)
{
	int ret;

	switch( create_disposition ) {
		case FILE_CREATE:
			/* create if not exist, fail if exist */
			ret = (FILE_CREATE_IF_NOT_EXIST|FILE_EXISTS_FAIL);
			break;
		case FILE_SUPERSEDE:
		case FILE_OVERWRITE_IF:
			/* create if not exist, trunc if exist */
			ret = (FILE_CREATE_IF_NOT_EXIST|FILE_EXISTS_TRUNCATE);
			break;
		case FILE_OPEN:
			/* fail if not exist, open if exists */
			ret = (FILE_FAIL_IF_NOT_EXIST|FILE_EXISTS_OPEN);
			break;
		case FILE_OPEN_IF:
			/* create if not exist, open if exists */
			ret = (FILE_CREATE_IF_NOT_EXIST|FILE_EXISTS_OPEN);
			break;
		case FILE_OVERWRITE:
			/* fail if not exist, truncate if exists */
			ret = (FILE_FAIL_IF_NOT_EXIST|FILE_EXISTS_TRUNCATE);
			break;
		default:
			DEBUG(0,("map_create_disposition: Incorrect value for create_disposition"));
			return -1;
	}

	DEBUG(10,("map_create_disposition: Mapped create_disposition to 0x%x\n",ret ));

	return ret;
}

void se_map_generic(uint32 *access_mask, struct generic_mapping *mapping)
{
	uint32 old_mask = *access_mask;

	if (*access_mask & GENERIC_READ_ACCESS) {
		*access_mask &= ~GENERIC_READ_ACCESS;
		*access_mask |= mapping->generic_read;
	}

	if (*access_mask & GENERIC_WRITE_ACCESS) {
		*access_mask &= ~GENERIC_WRITE_ACCESS;
		*access_mask |= mapping->generic_write;
	}

	if (*access_mask & GENERIC_EXECUTE_ACCESS) {
		*access_mask &= ~GENERIC_EXECUTE_ACCESS;
		*access_mask |= mapping->generic_execute;
	}

	if (*access_mask & GENERIC_ALL_ACCESS) {
		*access_mask &= ~GENERIC_ALL_ACCESS;
		*access_mask |= mapping->generic_all;
	}

	if (old_mask != *access_mask) {
		DEBUG(10, ("se_map_generic(): mapped mask 0x%08x to 0x%08x\n",
			   old_mask, *access_mask));
	}
}

static int map_share_mode( char *fname, uint32 create_options,
			uint32 *desired_access, uint32 share_access, uint32 file_attributes)
{
	int smb_open_mode = -1;
	uint32 original_desired_access = *desired_access;

	/*
	 * Convert GENERIC bits to specific bits.
	 */

	se_map_generic(desired_access, &file_generic_mapping);

	switch( *desired_access & (FILE_READ_DATA|FILE_WRITE_DATA|FILE_APPEND_DATA) ) {
		case FILE_READ_DATA:
			smb_open_mode = DOS_OPEN_RDONLY;
			break;
		case FILE_WRITE_DATA:
		case FILE_APPEND_DATA:
		case FILE_WRITE_DATA|FILE_APPEND_DATA:
			smb_open_mode = DOS_OPEN_WRONLY;
			break;
		case FILE_READ_DATA|FILE_WRITE_DATA:
		case FILE_READ_DATA|FILE_WRITE_DATA|FILE_APPEND_DATA:
		case FILE_READ_DATA|FILE_APPEND_DATA:
			smb_open_mode = DOS_OPEN_RDWR;
			break;
	}

	/*
	 * NB. For DELETE_ACCESS we should really check the
	 * directory permissions, as that is what controls
	 * delete, and for WRITE_DAC_ACCESS we should really
	 * check the ownership, as that is what controls the
	 * chmod. Note that this is *NOT* a security hole (this
	 * note is for you, Andrew) as we are not *allowing*
	 * the access at this point, the actual unlink or
	 * chown or chmod call would do this. We are just helping
	 * clients out by telling them if they have a hope
	 * of any of this succeeding. POSIX acls may still
	 * deny the real call. JRA.
	 */

	if (smb_open_mode == -1) {

		if(*desired_access & (DELETE_ACCESS|WRITE_DAC_ACCESS|WRITE_OWNER_ACCESS|SYNCHRONIZE_ACCESS|
					FILE_EXECUTE|FILE_READ_ATTRIBUTES|
					FILE_READ_EA|FILE_WRITE_EA|SYSTEM_SECURITY_ACCESS|
					FILE_WRITE_ATTRIBUTES|READ_CONTROL_ACCESS)) {
			smb_open_mode = DOS_OPEN_RDONLY;
		} else if(*desired_access == 0) {

			/* 
			 * JRA - NT seems to sometimes send desired_access as zero. play it safe
			 * and map to a stat open.
			 */

			smb_open_mode = DOS_OPEN_RDONLY;

		} else {
			DEBUG(0,("map_share_mode: Incorrect value 0x%lx for desired_access to file %s\n",
				(unsigned long)*desired_access, fname));
			return -1;
		}
	}

	/*
	 * Set the special bit that means allow share delete.
	 * This is held outside the normal share mode bits at 1<<15.
	 * JRA.
	 */

	if(share_access & FILE_SHARE_DELETE) {
		smb_open_mode |= ALLOW_SHARE_DELETE;
		DEBUG(10,("map_share_mode: FILE_SHARE_DELETE requested. open_mode = 0x%x\n", smb_open_mode));
	}

	if(*desired_access & DELETE_ACCESS) {
		DEBUG(10,("map_share_mode: DELETE_ACCESS requested. open_mode = 0x%x\n", smb_open_mode));
	}

	/*
	 * We need to store the intent to open for Delete. This
	 * is what determines if a delete on close flag can be set.
	 * This is the wrong way (and place) to store this, but for 2.2 this
	 * is the only practical way. JRA.
	 */

	if (create_options & FILE_DELETE_ON_CLOSE) {
		/*
		 * W2K3 bug compatibility mode... To set delete on close
		 * the redirector must have *specifically* set DELETE_ACCESS
		 * in the desired_access field. Just asking for GENERIC_ALL won't do. JRA.
		 */

		if (!(original_desired_access & DELETE_ACCESS)) {
			DEBUG(5,("map_share_mode: FILE_DELETE_ON_CLOSE requested without \
DELETE_ACCESS for file %s. (desired_access = 0x%lx)\n",
				fname, (unsigned long)*desired_access));
			return -1;
		}
		/* Implicit delete access is *NOT* requested... */
		smb_open_mode |= DELETE_ON_CLOSE_FLAG;
		DEBUG(10,("map_share_mode: FILE_DELETE_ON_CLOSE requested. open_mode = 0x%x\n", smb_open_mode));
	}

	/* Add in the requested share mode. */
	switch( share_access & (FILE_SHARE_READ|FILE_SHARE_WRITE)) {
		case FILE_SHARE_READ:
			smb_open_mode |= SET_DENY_MODE(DENY_WRITE);
			break;
		case FILE_SHARE_WRITE:
			smb_open_mode |= SET_DENY_MODE(DENY_READ);
			break;
		case (FILE_SHARE_READ|FILE_SHARE_WRITE):
			smb_open_mode |= SET_DENY_MODE(DENY_NONE);
			break;
		case FILE_SHARE_NONE:
			smb_open_mode |= SET_DENY_MODE(DENY_ALL);
			break;
	}

	/*
	 * Handle an O_SYNC request.
	 */

	if(file_attributes & FILE_FLAG_WRITE_THROUGH)
		smb_open_mode |= FILE_SYNC_OPENMODE;

	DEBUG(10,("map_share_mode: Mapped desired access 0x%lx, share access 0x%lx, file attributes 0x%lx \
to open_mode 0x%x\n", (unsigned long)*desired_access, (unsigned long)share_access,
		(unsigned long)file_attributes, smb_open_mode ));
 
	return smb_open_mode;
}

NTSTATUS set_delete_on_close_internal(int cnum, files_struct *fsp, BOOL delete_on_close, uint32 dosmode)
{
	if (delete_on_close) {
		/*
		 * Only allow delete on close for writable files.
		 */

		if (!lp_delete_readonly(SNUM(cnum))) {
			if (dosmode & aRONLY) {
				DEBUG(10,("set_delete_on_close_internal: file %s delete on close flag set but file attribute is readonly.\n",
					fsp->name ));
				return NT_STATUS_CANNOT_DELETE;
			}
		}

		/*
		 * Only allow delete on close for writable shares.
		 */

		if (!CAN_WRITE(cnum)) {
			DEBUG(10,("set_delete_on_close_internal: file %s delete on close flag set but write access denied on share.\n",
				fsp->name ));
			return NT_STATUS_ACCESS_DENIED;
		}

		/*
		 * Only allow delete on close for files/directories opened with delete intent.
		 */

		if (!(fsp->desired_access & DELETE_ACCESS)) {
			DEBUG(10,("set_delete_on_close_internal: file %s delete on close flag set but delete access denied.\n",
				fsp->name ));
			return NT_STATUS_ACCESS_DENIED;
		}
	}

	if(check_dir(fsp->name)) {
		fsp->directory_delete_on_close = delete_on_close;
	} else {
		fsp->delete_on_close = delete_on_close;
	}

	return NT_STATUS_OK;
}

files_struct *open_directory(int fnum, int cnum, char *fname, SMB_STRUCT_STAT *psbuf,
			uint32 desired_access, int share_mode, int smb_ofun, int *action)
{
	extern struct current_user current_user;
	BOOL got_stat = False;
	files_struct *fsp = &Files[fnum];
	BOOL delete_on_close = GET_DELETE_ON_CLOSE_FLAG(share_mode);

	if(!fsp)
		return NULL;

	if (VALID_STAT(*psbuf))
		got_stat = True;

	if (got_stat && (GET_FILE_OPEN_DISPOSITION(smb_ofun) == FILE_EXISTS_FAIL)) {
		errno = EEXIST; /* Setup so correct error is returned to client. */
		return NULL;
	}

	if (GET_FILE_CREATE_DISPOSITION(smb_ofun) == FILE_CREATE_IF_NOT_EXIST) {

		if (got_stat) {

			if(!S_ISDIR(psbuf->st_mode)) {
				DEBUG(0,("open_directory: %s is not a directory !\n", fname ));
				errno = EACCES;
				return NULL;
			}
			*action = FILE_WAS_OPENED;

		} else {

			/*
			 * Try and create the directory.
			 */

			if(!CAN_WRITE(cnum)) {
				DEBUG(2,("open_directory: failing create on read-only share\n"));
				errno = EACCES;
				return NULL;
			}

			if (ms_has_wild(fname))  {
				DEBUG(5,("open_directory: failing create on filename %s with wildcards\n", fname));
				unix_ERR_class = ERRDOS;
				unix_ERR_code = ERRinvalidname;
				unix_ERR_ntstatus = NT_STATUS_OBJECT_NAME_INVALID;
				return NULL;
			}

			if( strchr_m(fname, ':')) {
				DEBUG(5,("open_directory: failing create on filename %s with colon in name\n", fname));
				unix_ERR_class = ERRDOS;
				unix_ERR_code = ERRinvalidname;
				unix_ERR_ntstatus = NT_STATUS_NOT_A_DIRECTORY;
				return NULL;
			}

			if(mkdir_wrapper(fname, unix_mode(cnum,aDIR)) < 0) {
				DEBUG(2,("open_directory: unable to create %s. Error was %s\n",
					 fname, strerror(errno) ));
				return NULL;
			}

			if(sys_stat(fname, psbuf) != 0) {
				return NULL;
			}

			*action = FILE_WAS_CREATED;

		}
	} else {

		/*
		 * Don't create - just check that it *was* a directory.
		 */

		if(!got_stat) {
			DEBUG(3,("open_directory: unable to stat name = %s. Error was %s\n",
				 fname, strerror(errno) ));
			return NULL;
		}

		if(!S_ISDIR(psbuf->st_mode)) {
			DEBUG(0,("open_directory: %s is not a directory !\n", fname ));
			return NULL;
		}

		*action = FILE_WAS_OPENED;
	}
	
	DEBUG(5,("open_directory: opening directory %s\n", fname));

	/*
	 * Setup the files_struct for it.
	 */
	 
	fsp->cnum = cnum;
	fsp->mode = psbuf->st_mode;

//do we need to run fd_get_new() to get new filefd for dir entry???	
	file_fd_struct *fd_tmp;
	fd_tmp = (file_fd_struct *)calloc(1, sizeof(file_fd_struct));
	fd_tmp->inode = (uint32)psbuf->st_ino;
	fd_tmp->dev = (uint32)psbuf->st_dev;
	fd_tmp->fd = -1;	//we set -1 to indicates that it is a directory!
	fsp->fd_ptr = fd_tmp;
	
	fsp->open = True;
	fsp->size = psbuf->st_size;
	fsp->uid = current_user.id;
	fsp->can_lock = True;
	fsp->can_read = False;
	fsp->can_write = False;
	fsp->share_mode = share_mode;
	fsp->desired_access = desired_access;	//*
	fsp->modified = False;
	fsp->granted_oplock = False;
	fsp->sent_oplock_break = False;
	fsp->directory_delete_on_close = False;	//*
	string_set(&fsp->name,fname);

	if (delete_on_close) {
		NTSTATUS result = set_delete_on_close_internal(cnum, fsp, delete_on_close, 0);

		if (NT_STATUS_V(result) !=  NT_STATUS_V(NT_STATUS_OK)) {
			return NULL;
		}
	}
	
	Connections[cnum].num_files_open++;
	DEBUG(0,("!Done in open_dir with: %s\n", fname));

	return fsp;
}


static void open_nt_file(int fnum,int cnum,char *fname1,int flags,int mode, SMB_STRUCT_STAT *sbuf, uint32 desired_access)
{
  extern struct current_user current_user;
  pstring fname;
  SMB_STRUCT_STAT statbuf;
  file_fd_struct *fd_ptr;
  files_struct *fsp = &Files[fnum];
   int accmode = (flags & (O_RDONLY | O_WRONLY | O_RDWR));

  fsp->open = False;
  fsp->fd_ptr = 0;
  fsp->granted_oplock = False;
  errno = EPERM;

  pstrcpy(fname,fname1);

  /* check permissions */

  /*
   * This code was changed after seeing a client open request 
   * containing the open mode of (DENY_WRITE/read-only) with
   * the 'create if not exist' bit set. The previous code
   * would fail to open the file read only on a read-only share
   * as it was checking the flags parameter  directly against O_RDONLY,
   * this was failing as the flags parameter was set to O_RDONLY|O_CREAT.
   * JRA.
   */

  if (!CAN_WRITE(cnum)) {
    /* It's a read-only share - fail if we wanted to write. */
    if(accmode != O_RDONLY) {
      DEBUG(3,("Permission denied opening %s\n",fname));
      check_for_pipe(fname);
      return;
    }
    else if(flags & O_CREAT) {
      /* We don't want to write - but we must make sure that O_CREAT
         doesn't create the file if we have write access into the
         directory.
       */
      flags &= ~O_CREAT;
    }
  }

  /* this handles a bug in Win95 - it doesn't say to create the file when it 
     should */
  if (Connections[cnum].printer)	//sucks!!!
    flags |= O_CREAT;


/*
  if (flags == O_WRONLY)
    DEBUG(3,("Bug in client? Set O_WRONLY without O_CREAT\n"));
*/

  /*
   * Ensure we have a valid struct stat so we can search the
   * open fd table.
   */
  if(sbuf == 0) {
    if(sys_stat(fname, &statbuf) < 0) {
      if(errno != ENOENT) {
        DEBUG(3,("Error doing stat on file %s (%s)\n",
                 fname,strerror(errno)));

        check_for_pipe(fname);
        return;
      }
      sbuf = 0;
    } else {
      sbuf = &statbuf;
    }
  }

  /*
   * Check to see if we have this file already
   * open. If we do, just use the already open fd and increment the
   * reference count (fd_get_already_open increments the ref_count).
   */
  if((fd_ptr = (file_fd_struct *)fd_get_already_open(sbuf))!= 0) {

    /* File was already open. */
    if((flags & O_CREAT) && (flags & O_EXCL)) {
      fd_ptr->ref_count--;
      errno = EEXIST;
      return;
    }

    /* 
     * If not opened O_RDWR try
     * and do that here - a chmod may have been done
     * between the last open and now. 
     */
    if(fd_ptr->real_open_flags != O_RDWR)
      fd_attempt_reopen(fname, mode, fd_ptr);

    /*
     * Ensure that if we wanted write access
     * it has been opened for write, and if we wanted read it
     * was open for read. 
     */
    if(((accmode == O_WRONLY) && (fd_ptr->real_open_flags == O_RDONLY)) ||
       ((accmode == O_RDONLY) && (fd_ptr->real_open_flags == O_WRONLY)) ||
       ((accmode == O_RDWR) && (fd_ptr->real_open_flags != O_RDWR))) {
      DEBUG(3,("Error opening (already open for flags=%d) file %s (%s) (flags=%d)\n",
               fd_ptr->real_open_flags, fname,strerror(EACCES),flags));
      check_for_pipe(fname);
      fd_ptr->ref_count--;
      return;
    }

  } else {
    int open_flags;
    /* We need to allocate a new file_fd_struct (this increments the
       ref_count). */
    if((fd_ptr = (file_fd_struct *)fd_get_new()) == 0)
      return;
    /*
     * Whatever the requested flags, attempt read/write access,
     * as we don't know what flags future file opens may require.
     * If this fails, try again with the required flags. 
     * Even if we open read/write when only read access was 
     * requested the setting of the can_write flag in
     * the file_struct will protect us from errant
     * write requests. We never need to worry about O_APPEND
     * as this is not set anywhere in Samba.
     */
    fd_ptr->real_open_flags = O_RDWR;
    /* Set the flags as needed without the read/write modes. */
    open_flags = flags & ~(O_RDWR|O_WRONLY|O_RDONLY);
    fd_ptr->fd = fd_attempt_open(fname, open_flags|O_RDWR, mode);
    /*
     * On some systems opening a file for R/W access on a read only
     * filesystems sets errno to EROFS.
     */

    if((fd_ptr->fd == -1) && (errno == EACCES)) {
      if(flags & O_WRONLY) {
        fd_ptr->fd = fd_attempt_open(fname, open_flags|O_WRONLY, mode);
        fd_ptr->real_open_flags = O_WRONLY;
      } else {
	fd_ptr->fd = fd_attempt_open(fname, open_flags|O_RDONLY, mode);
        fd_ptr->real_open_flags = O_RDONLY;
      }
    }
  }
    
  if (fd_ptr->fd < 0)
    {
      DEBUG(3,("Error opening file %s (%s) (flags=%d)\n",
	       fname,strerror(errno),flags));
      /* Ensure the ref_count is decremented. */
      fd_attempt_close(fd_ptr);
      check_for_pipe(fname);
      return;
    }

  if (fd_ptr->fd >= 0)
    {
      if(sbuf == 0) {
        /* Do the fstat */
        if(sys_fstat(fd_ptr->fd, &statbuf) == -1) {
          /* Error - backout !! */
          DEBUG(3,("Error doing fstat on fd %d, file %s (%s)\n",
                   fd_ptr->fd, fname,strerror(errno)));
          /* Ensure the ref_count is decremented. */
          fd_attempt_close(fd_ptr);
          return;
        }
        sbuf = &statbuf;
      }
      /* Set the correct entries in fd_ptr. */
      fd_ptr->dev = (uint32)sbuf->st_dev;
      fd_ptr->inode = (uint32)sbuf->st_ino;

      fsp->fd_ptr = fd_ptr;
      Connections[cnum].num_files_open++;
      fsp->mode = sbuf->st_mode;
      GetTimeOfDay(&fsp->open_time);
      fsp->uid = current_user.id;
      fsp->size = 0;
      fsp->pos = -1;
      fsp->open = True;
//     fsp->mmap_ptr = NULL;
//      fsp->mmap_size = 0;
      fsp->can_lock = True;
      fsp->can_read = ((flags & O_WRONLY)==0);
      fsp->can_write = ((flags & (O_WRONLY|O_RDWR))!=0);
      fsp->share_mode = 0;
      fsp->modified = False;
      fsp->granted_oplock = False;
      fsp->sent_oplock_break = False;
      fsp->cnum = cnum;
      string_set(&fsp->name,dos_to_unix(fname,False));
      fsp->wbmpx_ptr = NULL;   
//for NT!
      fsp->desired_access = desired_access;
      fsp->directory_delete_on_close = False;
      
      DEBUG(2,("%s %s opened file %s read=%s write=%s (numopen=%d fnum=%d)\n",
	       timestring(),Connections[cnum].user,fname,
	       BOOLSTR(fsp->can_read),BOOLSTR(fsp->can_write),
	       Connections[cnum].num_files_open,fnum));
    }
}

time_t get_create_time(SMB_STRUCT_STAT *st,BOOL fake_dirs)
{
	time_t ret, ret1;

	if(S_ISDIR(st->st_mode) && fake_dirs)
		return (time_t)315493200L;          /* 1/1/1980 */
    
	ret = MIN(st->st_ctime, st->st_mtime);
	ret1 = MIN(ret, st->st_atime);

	if(ret1 != (time_t)0)
		return ret1;

	/*
	 * One of ctime, mtime or atime was zero (probably atime).
	 * Just return MIN(ctime, mtime).
	 */
	return ret;
}

void open_nt_file_shared(int fnum,int cnum,char *fname,uint32 desired_access,
			int share_mode,int ofun, uint32 mode/*old_dos_mode*/,
		      	int oplock_request, int *Access,int *action)
{
	DEBUG(0,("In open_nt_file with: %s\n", fname));
  files_struct *fs_p = &Files[fnum];
  int flags=0;
  int flags2=0;
  int deny_mode = (share_mode>>4)&7;
  BOOL allow_share_delete = GET_ALLOW_SHARE_DELETE(share_mode);
  BOOL delete_on_close = GET_DELETE_ON_CLOSE_FLAG(share_mode);
  SMB_STRUCT_STAT sbuf;
  BOOL file_existed = file_exist(fname,&sbuf);
  BOOL share_locked = False;
  BOOL fcbopen = False;
  int token;
  uint32 dev = 0;
  uint32 inode = 0;
  int num_share_modes = 0;
  uint32 existing_dos_mode = 0;
  BOOL add_share_mode = True;

  if (oplock_request == 8) {		//8 means we open file only for internal use. Do not do oplock!
	oplock_request = 0;
  }

#ifndef OPLOCK_ENABLE
  oplock_request = 0;
#endif

  fs_p->open = False;
  fs_p->fd_ptr = 0;

  if (!check_name(fname,cnum)) {
  	DEBUG(0,("failed in check_name for open nt file!\n"));
	return;
  } 

  if (file_existed) {
	existing_dos_mode = dos_mode(cnum, fname, &sbuf);
  }

  /* this is for OS/2 EAs - try and say we don't support them */
  if (strstr(fname,".+,;=[].")) 
  {
   	unix_ERR_class = ERRDOS;
/* OS/2 Workplace shell fix may be main code stream in a later release. */ 
	unix_ERR_code = ERRcannotopen;
	unix_ERR_ntstatus = NT_STATUS_OBJECT_NAME_NOT_FOUND;
	errno = 0;
	
    	return;
  }

  if ((ofun & 0x3) == 0 && file_existed)  
  {
  	DEBUG(0,("open nt file exists!!!\n"));
    	if(check_dir(fname))
		errno = EISDIR;
	else
    		errno = EEXIST;
	
    	return;
  }
      
  if (CAN_WRITE(cnum) && ((ofun & 0x10) == 0x10))
    flags2 |= O_CREAT;
  if (CAN_WRITE(cnum) && ((ofun & 0x3) == 2))
    flags2 |= O_TRUNC;

  /* note that we ignore the append flag as 
     append does not mean the same thing under dos and unix */

  switch (share_mode&0xF)
  {
    case 1: 
      	flags = O_WRONLY;
	if (desired_access == 0)
		desired_access = FILE_WRITE_DATA;
      break;
    case 0xF: 
      	fcbopen = True;
      	flags = O_RDWR;
	if (desired_access == 0)
		desired_access = FILE_READ_DATA|FILE_WRITE_DATA;
      break;
    case 2: 
      	flags = O_RDWR;
	if (desired_access == 0)
		desired_access = FILE_READ_DATA|FILE_WRITE_DATA;
      break;
    default:
     	flags = O_RDONLY;
	if (desired_access == 0)
		desired_access = FILE_READ_DATA;
      break;
  }
  
  if (flags != O_RDONLY && file_existed && 
      (!CAN_WRITE(cnum) || IS_DOS_READONLY(dos_mode(cnum,fname,&sbuf)))) 
  {
    if (!fcbopen) 
    {
    	DEBUG(0,("fucking 1!!!!!!\n"));
      errno = EACCES;
      return;
    }
    flags = O_RDONLY;
  }

  if (deny_mode > DENY_NONE && deny_mode!=DENY_FCB) 
  {
    DEBUG(2,("Invalid deny mode %d on file %s\n",deny_mode,fname));
    errno = EINVAL;
    return;
  }

  if (deny_mode == DENY_FCB) deny_mode = DENY_DOS;

  if (desired_access && ((desired_access & ~(SYNCHRONIZE_ACCESS|FILE_READ_ATTRIBUTES|FILE_WRITE_ATTRIBUTES))==0) &&
		((desired_access & (SYNCHRONIZE_ACCESS|FILE_READ_ATTRIBUTES|FILE_WRITE_ATTRIBUTES)) != 0))
  {
		/* Stat open that doesn't trigger oplock breaks or share mode checks... ! JRA. */
	deny_mode = DENY_NONE;
	if (file_existed) {
		oplock_request = 0;
		add_share_mode = False;
		flags2 &= ~O_CREAT;
	}
  }

  if (lp_share_modes(SNUM(cnum))) 
  {
    int i;
    share_mode_entry *old_shares = 0;

    if (file_existed)
    {
      dev = (uint32)sbuf.st_dev;
      inode = (uint32)sbuf.st_ino;
      lock_share_entry(cnum, dev, inode, &token);
      share_locked = True;
      num_share_modes = get_share_modes(cnum, token, dev, inode, &old_shares);
    }

    /*
     * Check if the share modes will give us access.
     */

    if(share_locked && (num_share_modes != 0))
    {
      BOOL broke_oplock;

      do
      {

        broke_oplock = False;
        for(i = 0; i < num_share_modes; i++)
        {
          share_mode_entry *share_entry = &old_shares[i];

          /* 
           * By observation of NetBench, oplocks are broken *before* share
           * modes are checked. This allows a file to be closed by the client
           * if the share mode would deny access and the client has an oplock. 
           * Check if someone has an oplock on this file. If so we must break 
           * it before continuing. 
           */
          if(share_entry->op_type & (EXCLUSIVE_OPLOCK|BATCH_OPLOCK))
          {

            DEBUG(5,("open_file_shared: breaking oplock (%x) on file %s, \
dev = %x, inode = %x\n", share_entry->op_type, fname, dev, inode));

            /* Oplock break.... */
            unlock_share_entry(cnum, dev, inode, token);
#ifdef OPLOCK_ENABLE
            if(request_oplock_break(share_entry, dev, inode) == False)
#endif
            {
              free((char *)old_shares);
              DEBUG(0,("open_file_shared: FAILED when breaking oplock (%x) on file %s, \
dev = %x, inode = %x\n", old_shares[i].op_type, fname, dev, inode));
              	errno = EACCES;
              	unix_ERR_class = ERRDOS;
              	unix_ERR_code = ERRbadshare;
		unix_ERR_ntstatus = NT_STATUS_SHARING_VIOLATION;
              return;
            }

            lock_share_entry(cnum, dev, inode, &token);
            broke_oplock = True;
            break;
          }

          /* someone else has a share lock on it, check to see 
             if we can too */
          if(check_share_mode(share_entry, share_mode, desired_access, fname, fcbopen, &flags) == False)
          {
            free((char *)old_shares);
            unlock_share_entry(cnum, dev, inode, token);
            errno = EACCES;
            unix_ERR_class = ERRDOS;
            unix_ERR_code = ERRbadshare;
	     unix_ERR_ntstatus = NT_STATUS_SHARING_VIOLATION;
	     DEBUG(0,("fucking share failed in nt file open!!!!!!\n"));
            return;
          }

        } /* end for */

        if(broke_oplock)
        {
          free((char *)old_shares);
          num_share_modes = get_share_modes(cnum, token, dev, inode, &old_shares);
        }
      } while(broke_oplock);
    }

    if(old_shares != 0)
      free((char *)old_shares);
  }

  DEBUG(4,("calling open_file with flags=0x%X flags2=0x%X mode=0%o\n",
	   flags,flags2,mode));

  open_nt_file(fnum,cnum,fname,
  		flags|(flags2&~(O_TRUNC)),mode,file_existed ? &sbuf : 0, desired_access);
  
  if (!fs_p->open && flags==O_RDWR && errno!=ENOENT && fcbopen) 
  {
    flags = O_RDONLY;
    open_nt_file(fnum,cnum,fname,flags,mode,file_existed ? &sbuf : 0, desired_access);
  }

  if (fs_p->open) 
  {
    int open_mode=0;

    if((share_locked == False) && lp_share_modes(SNUM(cnum)))
    {
      /* We created the file - thus we must now lock the share entry before creating it. */
      dev = fs_p->fd_ptr->dev;
      inode = fs_p->fd_ptr->inode;
      lock_share_entry(cnum, dev, inode, &token);
      share_locked = True;
    }

    switch (flags) 
    {
      case O_RDONLY:
        open_mode = 0;
        break;
      case O_RDWR:
        open_mode = 2;
        break;
      case O_WRONLY:
        open_mode = 1;
        break;
    }

    fs_p->share_mode = (deny_mode<<4) | open_mode
					| SET_ALLOW_SHARE_DELETE(allow_share_delete);

    if (Access)
      (*Access) = open_mode;

    if (action) 
    {
      if (file_existed && !(flags2 & O_TRUNC)) *action = 1;
      if (!file_existed) *action = 2;
      if (file_existed && (flags2 & O_TRUNC)) *action = 3;
    }
    /* We must create the share mode entry before truncate as
       truncate can fail due to locking and have to close the
       file (which expects the share_mode_entry to be there).
     */
    if (lp_share_modes(SNUM(cnum)))
    {
      uint16 port = 0;
      /* JRA. Currently this only services Exlcusive and batch
         oplocks (no other opens on this file). This needs to
         be extended to level II oplocks (multiple reader
         oplocks). */

#ifdef OPLOCK_ENABLE
      if(oplock_request && (num_share_modes == 0) && lp_oplocks(SNUM(cnum)) && 
	      !IS_VETO_OPLOCK_PATH(cnum,fname))
      {
        fs_p->granted_oplock = True;
        fs_p->sent_oplock_break = False;
        global_oplocks_open++;
        port = oplock_port;

        DEBUG(5,("open_file_shared: granted oplock (%x) on file %s, \
dev = %x, inode = %x\n", oplock_request, fname, dev, inode));

      }
      else
#endif
      {
        port = 0;
        oplock_request = 0;
      }
      set_share_mode(token, fnum, port, oplock_request);
    }

//d.o.c is the most important thing for NT when deleting files!!!!
    if (delete_on_close) {
	uint32 dosmode = existing_dos_mode;
	NTSTATUS result;

	if (*action == FILE_WAS_OVERWRITTEN || *action == FILE_WAS_CREATED) {
		dosmode = mode;
	}
	result = set_delete_on_close_internal(cnum, fs_p, delete_on_close, dosmode);

	if (NT_STATUS_V(result) !=  NT_STATUS_V(NT_STATUS_OK)) {
			
			/* Remember to delete the mode we just added. */
		if (add_share_mode) {
			del_share_mode(token, fnum);
		}
			
		unlock_share_entry(cnum, fs_p->fd_ptr->dev, 
							fs_p->fd_ptr->inode, token);
			
		close_file(fnum,False);

		int u_e_c;
		uint32 u_e_code;
		ntstatus_to_dos(result, &u_e_c, &u_e_code);
			
               unix_ERR_ntstatus = result;
               unix_ERR_class = u_e_c;
               unix_ERR_code = u_e_code;
		DEBUG(0,("set DOC failed in nt file open!!!!!!\n"));
		return;
	}
    }

    if ((flags2&O_TRUNC) && file_existed)
      truncate_unless_locked(fnum,cnum,token,&share_locked);
  }

  if (share_locked && lp_share_modes(SNUM(cnum)))
    unlock_share_entry( cnum, dev, inode, token);
}

SMB_BIG_UINT smb_roundup(SMB_BIG_UINT val)
{
	SMB_BIG_UINT rval = 0x100000;

	/* Only roundup for Windows clients. */
	enum remote_arch_types ra_type = get_remote_arch();
	if (rval && (ra_type != RA_SAMBA) && (ra_type != RA_CIFSFS)) {
		return SMB_ROUNDUP(val,rval);
	}
	
	DEBUG(0,("size after roundup: %lld\n", val));
	return val;
}

SMB_BIG_UINT get_allocation_size(files_struct *fsp, SMB_STRUCT_STAT *sbuf, SMB_BIG_UINT size)
{
	SMB_BIG_UINT ret;


	ret = (SMB_BIG_UINT)STAT_ST_BLOCKSIZE * (SMB_BIG_UINT)sbuf->st_blocks;


	if (!ret && fsp && size)
		ret = size;

	return smb_roundup(ret);
}
//##########################################################//

int reply_ntcreate_and_X(char *inbuf,char *outbuf,int length,int bufsize)
{  
	int cnum = SVAL(inbuf,smb_tid);
	int result;
	pstring fname;
	enum FAKE_FILE_TYPE fake_file_type = FAKE_FILE_TYPE_NONE;
	uint32 flags = IVAL(inbuf,smb_ntcreate_Flags);
	uint32 desired_access = IVAL(inbuf,smb_ntcreate_DesiredAccess);
	uint32 file_attributes = IVAL(inbuf,smb_ntcreate_FileAttributes);
	uint32 share_access = IVAL(inbuf,smb_ntcreate_ShareAccess);
	uint32 create_disposition = IVAL(inbuf,smb_ntcreate_CreateDisposition);
	uint32 create_options = IVAL(inbuf,smb_ntcreate_CreateOptions);
	uint16 root_dir_fid = (uint16)IVAL(inbuf,smb_ntcreate_RootDirectoryFid);
	SMB_BIG_UINT allocation_size = 0;
	int smb_ofun;
	int smb_open_mode;
	/* Breakout the oplock request bits so we can set the
	   reply bits separately. */
	int oplock_request = 0;
	int fmode=0,rmode=0;
	SMB_OFF_T file_len = 0;
	SMB_STRUCT_STAT sbuf;
	int smb_action = 0;
	BOOL bad_path = False;
//	files_struct *fsp=NULL;
	char *p = NULL;
	time_t c_time;
	BOOL extended_oplock_granted = False;
	NTSTATUS status;
	files_struct *fsp=NULL;
	int fsp_id;
	int smb_attr = (file_attributes & SAMBA_ATTRIBUTES_MASK);
	mode_t unixmode;

	DEBUG(10,("reply_ntcreateX: flags = 0x%x, desired_access = 0x%x \
file_attributes = 0x%x, share_access = 0x%x, create_disposition = 0x%x \
create_options = 0x%x root_dir_fid = 0x%x\n", flags, desired_access, file_attributes,
			share_access, create_disposition,
			create_options, root_dir_fid ));

/*
	if (IS_IPC(cnum)) {
		return(ERROR_DOS(ERRDOS,ERRnoaccess));
	}
*/

	if (create_options & FILE_OPEN_BY_FILE_ID) {
		return ERROR_NT(NT_STATUS_NOT_SUPPORTED);
	}

	/* 
	 * We need to construct the open_and_X ofun value from the
	 * NT values, as that's what our code is structured to accept.
	 */    
	
	if((smb_ofun = map_create_disposition( create_disposition )) == -1) {
		return (ERROR_DOS(ERRDOS,ERRnoaccess));
	}

	/*
	 * Get the file name.
	 */

	if(root_dir_fid != 0) {
		/*
		 * This filename is relative to a directory fid.
		 */
		pstring rel_fname;
		//TO DO???
		int fnum = GETFNUM(inbuf,smb_ntcreate_RootDirectoryFid);
//		files_struct *dir_fsp = file_fsp(inbuf,smb_ntcreate_RootDirectoryFid);
		size_t dir_name_len;

		CHECK_FNUM(fnum,cnum);

		if(!check_dir(Files[fnum].name)) {
			DEBUG(0,("It is a file: %s\n", Files[fnum].name));
			
			srvstr_get_path(inbuf, fname, smb_buf(inbuf), sizeof(fname), 0, STR_TERMINATE, &status,False);
			if (!NT_STATUS_IS_OK(status)) {
				return ERROR_NT(status);
			}

			/* 
			 * Check to see if this is a mac fork of some kind.
			 */

			if( strchr_m(fname, ':')) {
				return ERROR_NT(NT_STATUS_OBJECT_PATH_NOT_FOUND);
			}

			/*
			  we need to handle the case when we get a
			  relative open relative to a file and the
			  pathname is blank - this is a reopen!
			  (hint from demyn plantenberg)
			*/

			return(ERROR_DOS(ERRDOS,ERRbadfid));
		}

		/*
		 * Copy in the base directory name.
		 */

		pstrcpy( fname, Files[fnum].name);
		dir_name_len = strlen(fname);

		/*
		 * Ensure it ends in a '\'.
		 */

		if(fname[dir_name_len-1] != '\\' && fname[dir_name_len-1] != '/') {
			pstrcat(fname, "/");
			dir_name_len++;
		}

		srvstr_get_path(inbuf, rel_fname, smb_buf(inbuf), sizeof(rel_fname), 0, STR_TERMINATE, &status,False);
		if (!NT_STATUS_IS_OK(status)) {
			return ERROR_NT(status);
		}
		pstrcat(fname, rel_fname);

		chain_fnum = fnum;
	} else {
		srvstr_get_path(inbuf, fname, smb_buf(inbuf), sizeof(fname), 0, STR_TERMINATE, &status,False);
		if (!NT_STATUS_IS_OK(status)) {
			return ERROR_NT(status);
		}

		/* 
		 * Check to see if this is a mac fork of some kind.
		 */

		if( strchr_m(fname, ':')) {
			return ERROR_NT(NT_STATUS_OBJECT_PATH_NOT_FOUND);
		}
	}

	
	/*
	 * Now contruct the smb_open_mode value from the filename, 
	 * desired access and the share access.
	 */

	if((smb_open_mode = map_share_mode(fname, create_options, &desired_access, 
					   share_access, 
					   file_attributes)) == -1) {
		return ERROR_NT(NT_STATUS_INVALID_PARAMETER);
	}

	oplock_request = (flags & REQUEST_OPLOCK) ? EXCLUSIVE_OPLOCK : 0;
	if (oplock_request) {
		oplock_request |= (flags & REQUEST_BATCH_OPLOCK) ? BATCH_OPLOCK : 0;
	}

	/*
	 * Ordinary file or directory.
	 */
		
	/*
	 * Check if POSIX semantics are wanted.
	 */
		
//	set_posix_case_semantics(conn, file_attributes);
		
	unix_convert(fname,cnum,0,&bad_path);
	ZERO_STRUCTP(&sbuf);
	sys_stat(fname, &sbuf);

	unixmode = unix_mode(cnum,smb_attr | aARCH);

	DEBUG(0,("fname 1 in ntcreate is: %s\n", fname));

	/* FAKE_FILE is a special case */
	if (fake_file_type == FAKE_FILE_TYPE_NONE) {
		/* Normal file. */
		if (bad_path) {
			return ERROR_NT(NT_STATUS_OBJECT_PATH_NOT_FOUND);
		}
		/* All file access must go through check_name() */
		if (!check_name(fname,cnum)) {
			return set_bad_path_error(outbuf, errno, bad_path, ERRDOS,ERRbadpath);
		}
	}


	/* 
	 * If it's a request for a directory open, deal with it separately.
	 */

	if(create_options & FILE_DIRECTORY_FILE) {
		oplock_request = 0;
		
		/* Can't open a temp directory. IFS kit test. */
		if (file_attributes & FILE_ATTRIBUTE_TEMPORARY) {
			return ERROR_NT(NT_STATUS_INVALID_PARAMETER);
		}

		fsp_id = find_free_file();
		if (fsp_id < 0)
    			return(ERROR_DOS(ERRSRV,ERRnofids));

		fsp = open_directory(fsp_id, cnum, fname, &sbuf, desired_access, smb_open_mode, smb_ofun, &smb_action);
			
		if(!fsp) {
			DEBUG(0,("open directory failed!!!!\n"));
			return set_bad_path_error(outbuf, errno, bad_path, ERRDOS,ERRnoaccess);
		}
	} else {
		/*
		 * Ordinary file case.
		 */

		fsp_id = find_free_file();

		/* NB. We have a potential bug here. If we
		 * cause an oplock break to ourselves, then we
		 * could end up processing filename related
		 * SMB requests whilst we await the oplock
		 * break response. As we may have changed the
		 * filename case semantics to be POSIX-like,
		 * this could mean a filename request could
		 * fail when it should succeed. This is a rare
		 * condition, but eventually we must arrange
		 * to restore the correct case semantics
		 * before issuing an oplock break request to
		 * our client. JRA.  */

		if (fake_file_type==FAKE_FILE_TYPE_NONE) {	
			open_nt_file_shared(fsp_id, cnum, fname, desired_access,
					smb_open_mode,
					smb_ofun, unixmode, oplock_request,
					&rmode, &smb_action);
			fsp = &Files[fsp_id];
		} else {
				/*leave it blank, we may have problems.....*/
		}
		
		if (!fsp->open && !IS_IPC(cnum)) {
			DEBUG(0,("we cheat here for dir open or ipc pipe!\n"));
			/* We cheat here. There are two cases we
			 * care about. One is a directory rename,
			 * where the NT client will attempt to
			 * open the source directory for
			 * DELETE access. Note that when the
			 * NT client does this it does *not*
			 * set the directory bit in the
			 * request packet. This is translated
			 * into a read/write open
			 * request. POSIX states that any open
			 * for write request on a directory
			 * will generate an EISDIR error, so
			 * we can catch this here and open a
			 * pseudo handle that is flagged as a
			 * directory. The second is an open
			 * for a permissions read only, which
			 * we handle in the open_file_stat case. JRA.
			 */

			if(errno == EISDIR) {

				/*
				 * Fail the open if it was explicitly a non-directory file.
				 */

				if (create_options & FILE_NON_DIRECTORY_FILE) {
					SSVAL(outbuf, smb_flg2, 
					      SVAL(outbuf,smb_flg2) | FLAGS2_32_BIT_ERROR_CODES);
					DEBUG(0,("open wrong file . maybe a dir?\n"));
					return ERROR_NT(NT_STATUS_FILE_IS_A_DIRECTORY);
				}
	
				oplock_request = 0;
				fsp = open_directory(fsp_id,cnum, fname, &sbuf, desired_access, smb_open_mode, smb_ofun, &smb_action);
				
				if(!fsp) {
					DEBUG(0,("open file without access!\n"));
					return set_bad_path_error(outbuf, errno, bad_path, ERRDOS,ERRnoaccess);
				}
			} else {
				DEBUG(0,("open file 2 wrong!\n"));
				return set_bad_path_error(outbuf, errno, bad_path, ERRDOS,ERRnoaccess);
			}
		} 
	}
		
	
	file_len = sbuf.st_size;
	fmode = dos_mode(cnum,fname,&sbuf);
	if(fmode == 0)
		fmode = FILE_ATTRIBUTE_NORMAL;
	
	if (!check_dir(fsp->name) && (fmode & aDIR)) {
		close_file(fsp_id,False);
		DEBUG(0,("wrong file 3 open!\n"));
		return ERROR_DOS(ERRDOS,ERRnoaccess);
	} 

#if 1		//we do not give an attribute of initial_allocation_size for file_struct!
	/* Save the requested allocation size. */
	SMB_BIG_UINT initial_allocation_size;
	allocation_size = (SMB_BIG_UINT)IVAL(inbuf,smb_ntcreate_AllocationSize);
#ifdef LARGE_FILE_SUPPORT
	allocation_size |= (((SMB_BIG_UINT)IVAL(inbuf,smb_ntcreate_AllocationSize + 4)) << 32);
#endif

	if (allocation_size && (allocation_size > (SMB_BIG_UINT)file_len)) {
		initial_allocation_size = smb_roundup(allocation_size);
		
		if (check_dir(fsp->name)) {
			close_file(fsp_id,False);
			/* Can't set allocation size on a directory. */
			return ERROR_NT(NT_STATUS_ACCESS_DENIED);
		}
//we do not allocate file space here!!!
/*
		if (set_filelen(fsp->fd_ptr->fd, initial_allocation_size) == -1) {
			close_file(fsp_id,False);
			DEBUG(0,("disk is full?!\n"));
			return ERROR_NT(NT_STATUS_DISK_FULL);
		}
*/
	} else {
		initial_allocation_size = smb_roundup((SMB_BIG_UINT)file_len);
	}
#endif

	/* 
	 * If the caller set the extended oplock request bit
	 * and we granted one (by whatever means) - set the
	 * correct bit for extended oplock reply.
	 */
	
	if (oplock_request && lp_fake_oplocks(SNUM(cnum)))
		extended_oplock_granted = True;

#if 0
	/* W2K sends back 42 words here ! If we do the same it breaks offline sync. Go figure... ? JRA. */
	set_message(outbuf,42,0,True);
#else
	set_message(outbuf,34,0,True);
#endif
	
	p = outbuf + smb_vwv2;
	
	/*
	 * Currently as we don't support level II oplocks we just report
	 * exclusive & batch here.
	 */

	if (extended_oplock_granted) {
		if (flags & REQUEST_BATCH_OPLOCK) {
			SCVAL(p,0, 2);
		} else {
			SCVAL(p,0, 1);
		}
	}else {
		SCVAL(p,0,0);
	}
	
	p++;
	SSVAL(p,0,fsp_id);
	p += 2;
	if ((create_disposition == FILE_SUPERSEDE) && (smb_action == FILE_WAS_OVERWRITTEN))
		SIVAL(p,0,0);
	else
		SIVAL(p,0,smb_action);
	p += 4;
	
	/* Create time. */  
	c_time = get_create_time(&sbuf,False);

	put_long_date(p,c_time);
	p += 8;
	put_long_date(p,sbuf.st_atime); /* access time */
	p += 8;
	put_long_date(p,sbuf.st_mtime); /* write time */
	p += 8;
	put_long_date(p,sbuf.st_mtime); /* change time */
	p += 8;
	SIVAL(p,0,fmode); /* File Attributes. */
	p += 4;
	SOFF_T(p, 0, get_allocation_size(fsp,&sbuf, initial_allocation_size));
	p += 8;
	SOFF_T(p,0,file_len);
	p += 8;
	if (flags & 0x10)
		SSVAL(p,2,0x7);
	p += 4;
	SCVAL(p,0,check_dir(fsp->name) ? 1 : 0);

	DEBUG(5,("reply_ntcreate_and_X: fnum = %d, open name = %s\n", fsp_id, fsp->name));

	result = chain_reply(inbuf,outbuf,length,bufsize);
	
	return result;
}


int reply_nttrans(char *inbuf,char *outbuf,int length,int bufsize)
{
//hmmmm....I do not think it is neccessary to support this methold
	DEBUG(0,("Ignoring nttrans of length %d\n",length));
	return(ERROR_DOS(ERRSRV,ERRnosupport));
}

int reply_nttranss(char *inbuf,char *outbuf,int length,int bufsize)
{
//just say yes to return.....do nothing!
	DEBUG(0,("Ignoring nttranss of length %d\n",length));
	return -1;
}

int reply_ntcancel(char *inbuf,char *outbuf,int length,int bufsize)
{
//hmmmm....I do not think it is neccessary to support this methold
	DEBUG(0,("Ignoring ntcancel of length %d\n",length));
	return(ERROR_DOS(ERRSRV,ERRnosupport));
}



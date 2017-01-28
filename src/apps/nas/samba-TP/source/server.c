/* 
   Unix SMB/Netbios implementation.
   Version based 3.0.
   Main SMB server routines
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

#include "includes.h"

extern uint32 global_client_caps;

#define ZERO_ARRAY(x) memset((char *)(x), 0, sizeof(x))

static uint32 common_flags2 = FLAGS2_LONG_PATH_COMPONENTS|FLAGS2_32_BIT_ERROR_CODES;

//we cant get the correct timezone from our linux platform, so need to get it from web_server
char *TIME_ZONE = NULL;
int TZ_FD;

//make val global for timer.....sucks
pid_t m_pid;	//main process pid

static timer_t uni_timer;
static BOOL timer_st;
//static BOOL timer_mutex;	//this is for multiple porcess concern

pstring servicesf = CONFIGFILE;
extern pstring debugf;
extern pstring sesssetup_user;
extern fstring myworkgroup;

char *InBuffer = NULL;
char *OutBuffer = NULL;
char *last_inbuf = NULL;

int am_parent = 1;
int atexit_set = 0;

/* the last message the was processed */
int last_message = -1;

/* a useful macro to debug the last message processed */
#define LAST_MESSAGE() smb_fn_name(last_message)

extern pstring scope;
extern int DEBUGLEVEL;
extern int case_default;
extern BOOL case_sensitive;
extern BOOL case_preserve;
extern BOOL use_mangled_map;
extern BOOL short_case_preserve;
extern BOOL case_mangle;
time_t smb_last_time=(time_t)0;

extern int smb_read_error;

extern pstring user_socket_options;

connection_struct Connections[MAX_CONNECTIONS];
files_struct Files[MAX_OPEN_FILES];

/*
 * Indirection for file fd's. Needed as POSIX locking
 * is based on file/process, not fd/process.
 */
file_fd_struct FileFd[MAX_OPEN_FILES];
int max_file_fd_used = 0;

extern int Protocol;

/* 
 * Size of data we can send to client. Set
 *  by the client for all protocols above CORE.
 *  Set by us for CORE protocol.
 */
int max_send = BUFFER_SIZE;
/*
 * Size of the data we can receive. Set by us.
 * Can be modified by the max xmit parameter.
 */
int max_recv = BUFFER_SIZE;

/* number of open connections */
static int num_connections_open = 0;

#ifdef OPLOCK_ENABLE
/* Oplock ipc UDP socket. */
int oplock_sock = -1;

uint16 oplock_port = 0;
/* Current number of oplocks we have outstanding. */
int32 global_oplocks_open = 0;

BOOL global_oplock_break = False;
#endif

extern fstring remote_machine;

extern pstring OriginalDir;

/* these can be set by some functions to override the error codes */
int unix_ERR_class=SUCCESS;
int unix_ERR_code=0;
NTSTATUS unix_ERR_ntstatus = NT_STATUS_OK;


extern int extra_time_offset;

extern pstring myhostname;

static int find_free_connection(int hash);

/* for readability... */
#define IS_DOS_DIR(test_mode) (((test_mode) & aDIR) != 0)
#define IS_DOS_ARCHIVE(test_mode) (((test_mode) & aARCH) != 0)
#define IS_DOS_SYSTEM(test_mode) (((test_mode) & aSYSTEM) != 0)
#define IS_DOS_HIDDEN(test_mode) (((test_mode) & aHIDDEN) != 0)

void add_to_common_flags2(uint32 v)
{
	common_flags2 |= v;
}

void remove_from_common_flags2(uint32 v)
{
	common_flags2 &= ~v;
}

//avoid to use signal directly. Using CatchSignal() could let interrupted system calls reload
void (*CatchSignal(int signum,void (*handler)(int )))(int)
{
	struct sigaction act;
	struct sigaction oldact;

	ZERO_STRUCT(act);

	act.sa_handler = handler;
	
#ifdef SA_RESTART
	/*
	 * We *want* SIGALRM to interrupt a system call.
	 */
	if(signum != SIGALRM)
		act.sa_flags = SA_RESTART;
#endif

	sigemptyset(&act.sa_mask);
	sigaddset(&act.sa_mask,signum);
	sigaction(signum,&act,&oldact);
	return oldact.sa_handler;
}

/****************************************************************************
  when exiting, take the whole family
****************************************************************************/
static void  *dflt_sig(void)
{
  exit_server("caught signal");
  return 0; /* Keep -Wall happy :-) */
}
/****************************************************************************
  Send a SIGTERM to our process group.
*****************************************************************************/
void  killkids(void)
{
  if(am_parent){ 
	DEBUG(0,("kill all kids before main process exits!\n"));
	kill(0,SIGTERM);
  }
}

/****************************************************************************
  change a dos mode to a unix mode
    base permission for files:
         everybody gets read bit set
         dos readonly is represented in unix by removing everyone's write bit
         dos archive is represented in unix by the user's execute bit
         dos system is represented in unix by the group's execute bit
         dos hidden is represented in unix by the other's execute bit
         Then apply create mask,
         then add force bits.
    base permission for directories:
         dos directory is represented in unix by unix's dir bit and the exec bit
         Then apply create mask,
         then add force bits.
****************************************************************************/
mode_t unix_mode(int cnum,int dosmode)
{
  mode_t result = (S_IRUSR | S_IRGRP | S_IROTH);

  if ( !IS_DOS_READONLY(dosmode) )
    result |= (S_IWUSR | S_IWGRP | S_IWOTH);
 
  if (IS_DOS_DIR(dosmode)) {
    /* We never make directories read only for the owner as under DOS a user
       can always create a file in a read-only directory. */
    result |= (S_IFDIR | S_IXUSR | S_IXGRP | S_IXOTH | S_IWUSR);
    /* Apply directory mask */
    result &= lp_dir_mode(SNUM(cnum));
    /* Add in force bits */
    result |= lp_force_dir_mode(SNUM(cnum));
  } else { 
    if (MAP_ARCHIVE(cnum) && IS_DOS_ARCHIVE(dosmode))
      result |= S_IXUSR;

    if (MAP_SYSTEM(cnum) && IS_DOS_SYSTEM(dosmode))
      result |= S_IXGRP;
 
    if (MAP_HIDDEN(cnum) && IS_DOS_HIDDEN(dosmode))
      result |= S_IXOTH;  
 
    /* Apply mode mask */
    result &= lp_create_mode(SNUM(cnum));
    /* Add in force bits */
    result |= lp_force_create_mode(SNUM(cnum));
  }
  return(result);
}


/****************************************************************************
  change a unix mode to a dos mode
****************************************************************************/
int dos_mode(int cnum,char *path,SMB_STRUCT_STAT *sbuf)
{
  int result = 0;
  extern struct current_user current_user;

  DEBUG(8,("dos_mode: %d %s\n", cnum, path));

  if (CAN_WRITE(cnum) && !lp_alternate_permissions(SNUM(cnum))) {
    if (!((sbuf->st_mode & S_IWOTH) ||
	  Connections[cnum].admin_user ||
	  ((sbuf->st_mode & S_IWUSR) && current_user.uid==sbuf->st_uid) ||
	  ((sbuf->st_mode & S_IWGRP) && 
	   in_group(sbuf->st_gid,current_user.gid,
		    current_user.ngroups,current_user.igroups))))
      result |= aRONLY;
  } else {
    if ((sbuf->st_mode & S_IWUSR) == 0)
      result |= aRONLY;
  }

  if (MAP_ARCHIVE(cnum) && ((sbuf->st_mode & S_IXUSR) != 0))
    result |= aARCH;

  if (MAP_SYSTEM(cnum) && ((sbuf->st_mode & S_IXGRP) != 0))
    result |= aSYSTEM;

  if (MAP_HIDDEN(cnum) && ((sbuf->st_mode & S_IXOTH) != 0))
    result |= aHIDDEN;   
  
  if (S_ISDIR(sbuf->st_mode))
    result = aDIR | (result & aRONLY);

#ifdef S_ISLNK
#if LINKS_READ_ONLY
  if (S_ISLNK(sbuf->st_mode) && S_ISDIR(sbuf->st_mode))
    result |= aRONLY;
#endif
#endif

  /* hide files with a name starting with a . */
  if (lp_hide_dot_files(SNUM(cnum)))
    {
      char *p = strrchr_m(path,'/');
      if (p)
	p++;
      else
	p = path;
      
      if (p[0] == '.' && p[1] != '.' && p[1] != 0)
	result |= aHIDDEN;
    }

  /* Optimization : Only call is_hidden_path if it's not already
     hidden. */
  if (!(result & aHIDDEN) && IS_HIDDEN_PATH(cnum,path))
  {
    result |= aHIDDEN;
  }

  DEBUG(8,("dos_mode returning "));

  if (result & aHIDDEN) DEBUG(8, ("h"));
  if (result & aRONLY ) DEBUG(8, ("r"));
  if (result & aSYSTEM) DEBUG(8, ("s"));
  if (result & aDIR   ) DEBUG(8, ("d"));
  if (result & aARCH  ) DEBUG(8, ("a"));

  DEBUG(8,("\n"));

  return(result);
}

/*******************************************************************
chmod a file - but preserve some bits
********************************************************************/
int dos_chmod(int cnum,char *fname,int dosmode,SMB_STRUCT_STAT *st)
{
  SMB_STRUCT_STAT st1;
  int mask=0;
  int tmp;
  int unixmode;
  int ret = -1;

  if (!st) {
    st = &st1;
    if (sys_stat(fname,st)){
	DEBUG(0,("cant stat in dos_chmod!\n"));
	return(-1);
    }
  }

  if (S_ISDIR(st->st_mode)) 
  	dosmode |= aDIR;
  else
  	dosmode &= ~aDIR;

  if (dos_mode(cnum,fname,st) == dosmode) 
  	return(0);

  unixmode = unix_mode(cnum,dosmode);

  /* preserve the s bits */
  mask |= (S_ISUID | S_ISGID);

  /* possibly preserve the x bits */
  if (!MAP_ARCHIVE(cnum)) 
  	mask |= S_IXUSR;
  if (!MAP_SYSTEM(cnum)) 
  	mask |= S_IXGRP;
  if (!MAP_HIDDEN(cnum)) 
  	mask |= S_IXOTH;

  unixmode |= (st->st_mode & mask);

  /* if we previously had any r bits set then leave them alone */
  if ((tmp = st->st_mode & (S_IRUSR|S_IRGRP|S_IROTH))) {
    unixmode &= ~(S_IRUSR|S_IRGRP|S_IROTH);
    unixmode |= tmp;
  }

  /* if we previously had any w bits set then leave them alone 
   if the new mode is not rdonly */
  if (!IS_DOS_READONLY(dosmode)) {
	unixmode |= (st->st_mode & (S_IWUSR|S_IWGRP|S_IWOTH));
  }

  if((ret = sys_chmod(fname,unixmode)) == 0)
  	return 0;

  if((errno != EPERM) && (errno != EACCES)){
  	DEBUG(0,("fuck!!!no access right!?\n"));
	return -1;
  }

  if (CAN_WRITE(cnum)) {	
		int fd;
		fd = sys_open(fname, O_WRONLY, 0);
		
		if (fd == -1){
			DEBUG(0,("can not open in dos_chmod?!\n"));
			return -1;
		}
		
		become_root(False);
		ret = fchmod(fd, unixmode);
		unbecome_root(False);
		close(fd);
  }
  return ret;
}

/*******************************************************************
Wrapper around sys_utime that possibly allows DOS semantics rather
than POSIX.
*******************************************************************/

int file_utime(int cnum, char *fname, struct utimbuf *times)
{
  extern struct current_user current_user;
  SMB_STRUCT_STAT sb;
  int ret = -1;

  errno = 0;

  if(sys_utime(fname, times) == 0)
    return 0;

  if((errno != EPERM) && (errno != EACCES))
    return -1;

  if(!lp_dos_filetimes(SNUM(cnum)))
    return -1;

  /* We have permission (given by the Samba admin) to
     break POSIX semantics and allow a user to change
     the time on a file they don't own but can write to
     (as DOS does).
   */

  if(sys_stat(fname,&sb) != 0)
    return -1;

  /* Check if we have write access. */
  if (CAN_WRITE(cnum)) {
	  if (((sb.st_mode & S_IWOTH) ||
	       Connections[cnum].admin_user ||
	       ((sb.st_mode & S_IWUSR) && current_user.uid==sb.st_uid) ||
	       ((sb.st_mode & S_IWGRP) &&
		in_group(sb.st_gid,current_user.gid,
			 current_user.ngroups,current_user.igroups)))) {
		  /* We are allowed to become root and change the filetime. */
		  become_root(False);
		  ret = sys_utime(fname, times);
		  unbecome_root(False);
	  }
  }

  return ret;
}
  
/*******************************************************************
Change a filetime - possibly allowing DOS semantics.
*******************************************************************/

BOOL set_filetime(int cnum, char *fname, time_t mtime)
{
  struct utimbuf times;

  if (null_mtime(mtime)) return(True);

  times.modtime = times.actime = mtime;

  if (file_utime(cnum, fname, &times)) {
    DEBUG(4,("set_filetime(%s) failed: %s\n",fname,strerror(errno)));
  }
  
  return(True);
} 

/****************************************************************************
check if two filenames are equal

this needs to be careful about whether we are case sensitive
****************************************************************************/
static BOOL fname_equal(char *name1, char *name2)
{
  int l1 = strlen(name1);
  int l2 = strlen(name2);

  /* handle filenames ending in a single dot */
  if (l1-l2 == 1 && name1[l1-1] == '.' && lp_strip_dot())
    {
      BOOL ret;
      name1[l1-1] = 0;
      ret = fname_equal(name1,name2);
      name1[l1-1] = '.';
      return(ret);
    }

  if (l2-l1 == 1 && name2[l2-1] == '.' && lp_strip_dot())
    {
      BOOL ret;
      name2[l2-1] = 0;
      ret = fname_equal(name1,name2);
      name2[l2-1] = '.';
      return(ret);
    }

  /* now normal filename handling */
  if (case_sensitive)
    return(strcmp(name1,name2) == 0);

  return(strequal(name1,name2));
}


#ifdef USE_83_NAME
/****************************************************************************
mangle the 2nd name and check if it is then equal to the first name
****************************************************************************/
static BOOL mangled_equal(char *name1, char *name2, int snum)
{
  pstring tmpname;


  if (is_8_3(name2, True))
    return(False);

  strcpy(tmpname,name2);
  name_map_mangle(tmpname, True, snum);

  return(strequal(name1,tmpname));
}
#endif


/****************************************************************************
scan a directory to find a filename, matching without case sensitivity

If the name looks like a mangled name then try via the mangling functions
****************************************************************************/
static BOOL scan_directory(char *path, char *name,int cnum,BOOL docache)
{
  void *cur_dir;
  char *dname;
  pstring name2;

#ifdef USE_83_NAME
  BOOL mangled;
  mangled = is_mangled(name);
#endif

  /* handle null paths */
  if (*path == 0)
    path = ".";

//why do we need to cache the dir content???
  if (docache && (dname = DirCacheCheck(path,name,SNUM(cnum)))) {
    strcpy(name, dname);	
    return(True);
  }      

#if 0
  /* 
   * The incoming name can be mangled, and if we de-mangle it
   * here it will not compare correctly against the filename (name2)
   * read from the directory and then mangled by the name_map_mangle()
   * call. We need to mangle both names or neither.
   * (JRA).
   */
  if (mangled)
    mangled = !check_mangled_stack(name);
#endif 

  /* open the directory */
  if (!(cur_dir = OpenDir(cnum, path, True))) 
    {
      DEBUG(3,("scan dir didn't open dir [%s]\n",path));
      return(False);
    }

  /* now scan for matching names */
  while ((dname = ReadDirName(cur_dir))) 
    {
      if (*dname == '.' &&
	  (strequal(dname,".") || strequal(dname,"..")))
		continue;

/*
      pstrcpy(name2,dname);
      if (!name_map_mangle(name2,False,SNUM(cnum))) continue;
*/
      if (
#ifdef USE_83_NAME
	  (mangled && mangled_equal(name,name2, SNUM(cnum))) || 
#endif
	  fname_equal(name, name2)) /* name2 here was changed to dname - since 1.9.16p2 - not sure of reason (jra) */
	{
	  /* we've found the file, change it's name and return */
	  if (docache) 
	  	DirCacheAdd(path,name,dname,SNUM(cnum));
	  
	  strcpy(name, dname);
	  CloseDir(cur_dir);
	  return(True);
	}
    }

  CloseDir(cur_dir);
  return(False);
}

/****************************************************************************
This routine is called to convert names from the dos namespace to unix
namespace. It needs to handle any case conversions, mangling, format
changes etc.

We assume that we have already done a chdir() to the right "root" directory
for this service.

The function will return False if some part of the name except for the last
part cannot be resolved

If the saved_last_component != 0, then the unmodified last component
of the pathname is returned there. This is used in an exceptional
case in reply_mv (so far). If saved_last_component == 0 then nothing
is returned there.

The bad_path arg is set to True if the filename walk failed. This is
used to pick the correct error code to return between ENOENT and ENOTDIR
as Windows applications depend on ERRbadpath being returned if a component
of a pathname does not exist.
****************************************************************************/

BOOL unix_convert(char *name,int cnum,pstring saved_last_component, BOOL *bad_path)
{
  SMB_STRUCT_STAT st;
  char *start, *end;
  pstring dirpath;
  int saved_errno;

  *dirpath = 0;
  *bad_path = False;
  BOOL name_has_wildcard = False;
  BOOL component_was_mangled = False;

  if(saved_last_component)
    *saved_last_component = 0;
  
#if 0
   if (Connections[cnum].printer)
    {
      /*do not convert the filename on a printer!*/
      return(True);
    }
#endif

  /* convert to basic unix format - removing \ chars and cleaning it up */
//  unix_format(name);
//  unix_clean_name(name);

  DEBUG(0,("file name 1:%s\n",name));

  /* names must be relative to the root of the service - trim any leading /.
   also trim trailing /'s */
  trim_string(name,"/","/");

  /*
	 * If we trimmed down to a single '\0' character
	 * then we should use the "." directory to avoid
	 * searching the cache, but not if we are in a
	 * printing share.
  */

	if (!*name) {
		name[0] = '.';
		name[1] = '\0';
	}

  /*
   * Ensure saved_last_component is valid even if file exists.
   */
  if(saved_last_component) {
    end = strrchr_m(name, '/');
    if(end)
      strcpy(saved_last_component, end + 1);
    else
      strcpy(saved_last_component, name);
  }

  if (!case_sensitive && 
      (!case_preserve || (
#ifdef USE_83_NAME
  	is_8_3(name, False) && 
#endif
	!short_case_preserve))){
		DEBUG(0,("file name 3:%s\n",name));
		
		strnorm(name);
  }

   DEBUG(0,("file name 2:%s\n",name));

   start = name;

  /* stat the name - if it exists then we are all done! */
  if (sys_stat(name,&st) == 0)
    return(True);

  saved_errno = errno;

  DEBUG(5,("unix_convert(%s,%d)\n",name,cnum));

  /* a special case - if we don't have any mangling chars and are case
     sensitive then searching won't help */
  if (case_sensitive && 
#ifdef USE_83_NAME
  	!is_mangled(name) && 
#endif
      	!lp_strip_dot() && !use_mangled_map && (saved_errno != ENOENT)){
	DEBUG(0,("searching won't help!!!!!!???????\n"));
    	return(False);
  }
 
   name_has_wildcard = ms_has_wild(start);

#ifdef USE_83_NAME
   /* 
	 * is_mangled() was changed to look at an entire pathname, not 
	 * just a component. JRA.
   */
	if (is_mangled(start))
		component_was_mangled = True;
#endif

	/* 
	 * Now we need to recursively match the name against the real 
	 * directory structure.
	 */

	/* 
	 * Match each part of the path name separately, trying the names
	 * as is first, then trying to scan the directory for matching names.
	 */
   
	for (; start ; start = (end?end+1:(char *)NULL)) {
		/* 
		 * Pinpoint the end of this section of the filename.
		 */
		end = strchr_m(start, '/');

		/* 
		 * Chop the name at this point.
		 */
		if (end) 
			*end = 0;

		if(saved_last_component != 0)
			pstrcpy(saved_last_component, end ? end + 1 : start);

		/* 
		 * Check if the name exists up to this point.
		 */

		if (sys_stat(name, &st) == 0) {
			/*
			 * It exists. it must either be a directory or this must be
			 * the last part of the path for it to be OK.
			 */
			if (end && !(st.st_mode & S_IFDIR)) {
				/*
				 * An intermediate part of the name isn't a directory.
				 */
				DEBUG(5,("Not a dir %s\n",start));
				*end = '/';
				/* 
				 * We need to return the fact that the intermediate
				 * name resolution failed. This is used to return an
				 * error of ERRbadpath rather than ERRbadfile. Some
				 * Windows applications depend on the difference between
				 * these two errors.
				 */
				errno = ENOTDIR;
				*bad_path = True;
				return(False);
			}
		}
		else{
			pstring rest;

			*rest = 0;

			/*
			 * Remember the rest of the pathname so it can be restored
			 * later.
			 */

			if (end)
				pstrcpy(rest,end+1);

			/* Reset errno so we can detect directory open errors. */
			errno = 0;

			if (ms_has_wild(start) || 
			    !scan_directory(dirpath, start, cnum, end?True:False)) {
				if (end) {
					/*
					 * An intermediate part of the name can't be found.
					 */
					DEBUG(5,("Intermediate not found %s\n",start));
					*end = '/';

					/* 
					 * We need to return the fact that the intermediate
					 * name resolution failed. This is used to return an
					 * error of ERRbadpath rather than ERRbadfile. Some
					 * Windows applications depend on the difference between
					 * these two errors.
					 */
					*bad_path = True;
					return(False);
				}
	      
				/* 
				 * Just the last part of the name doesn't exist.
				 * We may need to strupper() or strlower() it in case
				 * this conversion is being used for file creation 
				 * purposes. If the filename is of mixed case then 
				 * don't normalise it.
				 */

				if (!case_preserve)
					if( !strhasupper(start) || !strhaslower(start))
						strnorm(start);

#ifdef USE_83_NAME
				/*
				 * check on the mangled stack to see if we can recover the 
				 * base of the filename.
				 */
				if (is_mangled(start)) {
					//mangle_check_cache( start, sizeof(pstring) - 1 - (start - name) );
					check_mangled_stack(start);
				}
#endif

				DEBUG(5,("New file %s\n",start));
				return(True); 
			}
			/* 
			 * Restore the rest of the string. If the string was mangled the size
			 * may have changed.
			 */
			if (end) {
				end = start + strlen(start);
				if (!safe_strcat_fn(start, "/", sizeof(pstring) - 1 - (start - name)) ||
				    !safe_strcat_fn(start, rest, sizeof(pstring) - 1 - (start - name))) {
					return False;
				}
				*end = '\0';
			} 
		}

		/* 
		 * Add to the dirpath that we have resolved so far.
		 */
		if (*dirpath)
			strcat(dirpath,"/");

		strcat(dirpath,start);

		/* 
		 * Restore the / that we wiped out earlier.
		 */
		if (end)
			*end = '/';

	}

	DEBUG(5,("conversion finished %s\n",name));
	return(True);
}

/****************************************************************************
normalise for DOS usage 
****************************************************************************/
static void disk_norm(SMB_BIG_UINT *bsize,SMB_BIG_UINT *dfree,SMB_BIG_UINT *dsize)
{
  /* check if the disk is beyond the max disk size */
  SMB_BIG_UINT maxdisksize = lp_maxdisksize();
  if (maxdisksize) {
    /* convert to blocks - and don't overflow */
    maxdisksize = ((maxdisksize*1024)/(*bsize))*1024;
    if (*dsize > maxdisksize) *dsize = maxdisksize;
    if (*dfree > maxdisksize) *dfree = maxdisksize-1; /* the -1 should stop 
							 applications getting 
							 div by 0 errors */
  }  

  while (*dfree > WORDMAX || *dsize > WORDMAX || *bsize < 512) 
    {
      *dfree /= 2;
      *dsize /= 2;
      *bsize *= 2;
	  
      if (*bsize > (WORDMAX*512)) {
		*bsize = (WORDMAX*512);
		if (*dsize > WORDMAX)
			*dsize = WORDMAX;
		if (*dfree >  WORDMAX)
			*dfree = WORDMAX;
		break;
	}
    }
}

/****************************************************************************
  return number of 1K blocks available on a path and total number 
****************************************************************************/
static SMB_BIG_UINT adjust_blocks(SMB_BIG_UINT blocks, SMB_BIG_UINT fromsize, SMB_BIG_UINT tosize)
{
	if (fromsize == tosize)	{ /* e.g., from 512 to 512 */
		return blocks;
	} else if (fromsize > tosize) { /* e.g., from 2048 to 512 */
		return blocks * (fromsize / tosize);
	} else { /* e.g., from 256 to 512 */
		/* Protect against broken filesystems... */
		if (fromsize == 0) {
			fromsize = tosize;
		}
		return (blocks + 1) / (tosize / fromsize);
	}
}

static int sys_fsusage(const char *path, SMB_BIG_UINT *dfree, SMB_BIG_UINT *dsize)
{
# define CONVERT_BLOCKS(B) \
	adjust_blocks ((SMB_BIG_UINT)(B), fsd.f_frsize ? (SMB_BIG_UINT)fsd.f_frsize : (SMB_BIG_UINT)fsd.f_bsize, (SMB_BIG_UINT)512)

	struct statvfs fsd;
	if (statvfs(path, &fsd) < 0) 
		return -1;

	(*dsize) = CONVERT_BLOCKS (fsd.f_blocks);
	(*dfree) = CONVERT_BLOCKS (fsd.f_bavail);

	return 0;
}

static SMB_BIG_UINT disk_free(char *path,SMB_BIG_UINT *bsize,SMB_BIG_UINT *dfree,SMB_BIG_UINT *dsize)
{
 	int dfree_retval;

  	if (sys_fsusage(path, dfree, dsize) != 0) {
		DEBUG (0, ("disk_free: sys_fsusage() failed. Error was : %s\n",
				strerror(errno) ));
		return (SMB_BIG_UINT)-1;
	}

	if (*bsize < 256) {
		DEBUG(5,("disk_free:Warning: bsize == %d < 256 . Changing to assumed correct bsize = 512\n",(int)*bsize));
		*bsize = 512;
	}

	if ((*dsize)<1) {
		DEBUG(0,("WARNING: dfree is broken on this system\n"));
		*dsize = 20*1024*1024/(*bsize);
		*dfree = MAX(1,*dfree);
	}

	disk_norm(bsize,dfree,dsize);

	if ((*bsize) < 1024) {
		dfree_retval = (*dfree)/(1024/(*bsize));
	} else {
		dfree_retval = ((*bsize)/1024)*(*dfree);
	}

	return(dfree_retval);

#if 0
  strunct statfs fs;

  /* possibly use system() to get the result */
  if (df_command && *df_command)
    {
      int ret;
      pstring syscmd;
      pstring outfile;
	  
      sprintf(outfile,"%s/dfree.smb.%d",tmpdir(),(int)sys_getpid());
      sprintf(syscmd,"%s %s",df_command,path);
      standard_sub_basic(syscmd);

      ret = smbrun(syscmd,outfile,False);
      DEBUG(3,("Running the command `%s' gave %d\n",syscmd,ret)); 
      {
        FILE *f = fopen(outfile,"r");	
        *dsize = 0;
        *dfree = 0;
        *bsize = 1024;
        if (f)
        {
            fscanf(f,"%d %d %d",dsize,dfree,bsize);
            fclose(f);
        }
        else
          DEBUG(0,("Can't open %s\n",outfile));
      }
	  
      unlink(outfile);
      disk_norm(bsize,dfree,dsize);
      dfree_retval = ((*bsize)/1024)*(*dfree);
	  
      return(dfree_retval);
    }


  if (statfs(path,&fs) == -1)
  {
	    DEBUG(3,("dfree call failed code errno=%d\n",errno));
	    *bsize = 1024;
	    *dfree = 1;
	    *dsize = 1;
	    return(((*bsize)/1024)*(*dfree));
  }

  *bsize = fs.f_bsize;

  *dfree = fs.f_bavail;

  *dsize = fs.f_blocks;

  disk_norm(bsize,dfree,dsize);

  if (*bsize < 256)
    *bsize = 512;
  
  if ((*dsize)<1)
    {
      DEBUG(0,("dfree seems to be broken on your system\n"));
      *dsize = 20*1024*1024/(*bsize);
      *dfree = MAX(1,*dfree);
    }

  if ((*bsize) < 1024) {
	dfree_retval = (*dfree)/(1024/(*bsize));
  } else {
	dfree_retval = ((*bsize)/1024)*(*dfree);
  }

  return(dfree_retval);
#endif
}


/****************************************************************************
wrap it to get filenames right
****************************************************************************/
SMB_BIG_UINT sys_disk_free(char *path,SMB_BIG_UINT *bsize,SMB_BIG_UINT *dfree,SMB_BIG_UINT *dsize)
{
  return(disk_free(dos_to_unix(path,False),bsize,dfree,dsize));
}



/****************************************************************************
check a filename - possibly caling reducename

This is called by every routine before it allows an operation on a filename.
It does any final confirmation necessary to ensure that the filename is
a valid one for the user to access.
****************************************************************************/
BOOL check_name(char *name,int cnum)
{
  BOOL ret;

  errno = 0;

  if( IS_VETO_PATH(cnum, name)) 
    {
      DEBUG(5,("file path name %s vetoed\n",name));
      return(0);
    }

  ret = reduce_name(name,Connections[cnum].connectpath,lp_widelinks(SNUM(cnum)));

  /* Check if we are allowing users to follow symlinks */
  /* Patch from David Clerc <David.Clerc@cui.unige.ch>
     University of Geneva */

#ifdef S_ISLNK
  if (!lp_symlinks(SNUM(cnum)))
    {
      SMB_STRUCT_STAT statbuf;
      if ( (sys_lstat(name,&statbuf) != -1) &&
          (S_ISLNK(statbuf.st_mode)) )
        {
          DEBUG(3,("check_name: denied: file path name %s is a symlink\n",name));
          ret=0; 
        }
    }
#endif

  if (!ret)
    DEBUG(5,("check_name on %s failed\n",name));

  return(ret);
}

/****************************************************************************
check a filename - possibly caling reducename
****************************************************************************/
void check_for_pipe(char *fname)
{
  /* special case of pipe opens */
  char s[10];
  StrnCpy(s,fname,9);
  strlower_m(s);
  if (strstr(s,"pipe/"))
    {
      DEBUG(3,("Rejecting named pipe open for %s\n",fname));
      unix_ERR_class = ERRSRV;
      unix_ERR_code = ERRaccess;
    }
}

/****************************************************************************
fd support routines - attempt to do a sys_open
****************************************************************************/
int fd_attempt_open(char *fname, int flags, int mode)
{
	DEBUG(0,("in fd_attempt_open with fname 1: %s\n", fname));
	
	pstring tmp;
	pstrcpy(tmp,fname);

//	DEBUG(0,("in fd_attempt_open with fname 2: %s\n", dos2unix_format(tmp, False)));

	unix_format(tmp);
  	unix_clean_name(tmp);

	DEBUG(0,("in fd_attempt_open with fname 2: %s\n", tmp));
  
  int fd = sys_open(fname,flags,mode);

  /* Fix for files ending in '.' */
  if((fd == -1) && (errno == ENOENT) &&
     (strchr_m(fname,'.')==NULL))
    {
    	DEBUG(0,("here 1????????\n"));
      strcat(fname,".");
      fd = sys_open(fname,flags,mode);
    }

#if (defined(ENAMETOOLONG) && defined(HAVE_PATHCONF))
  if ((fd == -1) && (errno == ENAMETOOLONG))
    {
    DEBUG(0,("here 2???????can not be.....!\n"));
      int max_len;
      char *p = strrchr_m(fname, '/');

      if (p == fname)   /* name is "/xxx" */
        {
          max_len = pathconf("/", _PC_NAME_MAX);
          p++;
        }
      else if ((p == NULL) || (p == fname))
        {
          p = fname;
          max_len = pathconf(".", _PC_NAME_MAX);
        }
      else
        {
          *p = '\0';
          max_len = pathconf(fname, _PC_NAME_MAX);
          *p = '/';
          p++;
        }
      if (strlen(p) > max_len)
        {
          char tmp = p[max_len];

          p[max_len] = '\0';
          if ((fd = sys_open(fname,flags,mode)) == -1)
            p[max_len] = tmp;
        }
    }
#endif
	
  return fd;
}

/****************************************************************************
fd support routines - attempt to find an already open file by dev
and inode - increments the ref_count of the returned file_fd_struct *.
****************************************************************************/
file_fd_struct *fd_get_already_open(SMB_STRUCT_STAT *sbuf)
{
  int i;
  file_fd_struct *fd_ptr;

  if(sbuf == 0)
    return 0;

  for(i = 0; i <= max_file_fd_used; i++) {
    fd_ptr = &FileFd[i];
    if((fd_ptr->ref_count > 0) &&
       (((uint32)sbuf->st_dev) == fd_ptr->dev) &&
       (((uint32)sbuf->st_ino) == fd_ptr->inode)) {
      fd_ptr->ref_count++;
      DEBUG(3,
       ("Re-used file_fd_struct %d, dev = %x, inode = %x, ref_count = %d\n",
        i, fd_ptr->dev, fd_ptr->inode, fd_ptr->ref_count));
      return fd_ptr;
    }
  }
  return 0;
}

/****************************************************************************
fd support routines - attempt to find a empty slot in the FileFd array.
Increments the ref_count of the returned entry.
****************************************************************************/
file_fd_struct *fd_get_new()
{
  int i;
  file_fd_struct *fd_ptr;

  for(i = 0; i < MAX_OPEN_FILES; i++) {
    fd_ptr = &FileFd[i];
    if(fd_ptr->ref_count == 0) {
      fd_ptr->dev = (uint32)-1;
      fd_ptr->inode = (uint32)-1;
      fd_ptr->fd = -1;
      fd_ptr->fd_readonly = -1;
      fd_ptr->fd_writeonly = -1;
      fd_ptr->real_open_flags = -1;
      fd_ptr->ref_count++;
      /* Increment max used counter if neccessary, cuts down
	 on search time when re-using */
      if(i > max_file_fd_used)
        max_file_fd_used = i;
      DEBUG(3,("Allocated new file_fd_struct %d, dev = %x, inode = %x\n",
               i, fd_ptr->dev, fd_ptr->inode));
      return fd_ptr;
    }
  }
  DEBUG(1,("ERROR! Out of file_fd structures - perhaps increase MAX_OPEN_FILES?\
n"));
  return 0;
}

/****************************************************************************
fd support routines - attempt to re-open an already open fd as O_RDWR.
Save the already open fd (we cannot close due to POSIX file locking braindamage.
****************************************************************************/
void fd_attempt_reopen(char *fname, int mode, file_fd_struct *fd_ptr)
{
  int fd = sys_open( fname, O_RDWR, mode);

  if(fd == -1)
    return;

  if(fd_ptr->real_open_flags == O_RDONLY)
    fd_ptr->fd_readonly = fd_ptr->fd;
  if(fd_ptr->real_open_flags == O_WRONLY)
    fd_ptr->fd_writeonly = fd_ptr->fd;

  fd_ptr->fd = fd;
  fd_ptr->real_open_flags = O_RDWR;
}

/****************************************************************************
fd support routines - attempt to close the file referenced by this fd.
Decrements the ref_count and returns it.
****************************************************************************/
int fd_attempt_close(file_fd_struct *fd_ptr)
{
  DEBUG(3,("fd_attempt_close on file_fd_struct %d, fd = %d, dev = %x, inode = %x, open_flags = %d, ref_count = %d.\n",
	   fd_ptr - &FileFd[0],
	   fd_ptr->fd, fd_ptr->dev, fd_ptr->inode,
	   fd_ptr->real_open_flags,
	   fd_ptr->ref_count));
  
  if(fd_ptr->ref_count > 0) {
    	fd_ptr->ref_count--;
    	if(fd_ptr->ref_count == 0) {
      		if(fd_ptr->fd != -1)
        		close(fd_ptr->fd);
      		if(fd_ptr->fd_readonly != -1)
			close(fd_ptr->fd_readonly);
      		if(fd_ptr->fd_writeonly != -1)
			close(fd_ptr->fd_writeonly);
      		fd_ptr->fd = -1;
      		fd_ptr->fd_readonly = -1;
      		fd_ptr->fd_writeonly = -1;
      		fd_ptr->real_open_flags = -1;
      		fd_ptr->dev = (uint32)-1;
      		fd_ptr->inode = (uint32)-1;
    	}
  } 
  
  return fd_ptr->ref_count;
}

/*******************************************************************
sync a file
********************************************************************/
void sync_file(int fnum)
{
#ifndef NO_FSYNC
  fsync(Files[fnum].fd_ptr->fd);
#endif
}

void increase_trans(int fnum)
{
	Files[fnum].trans_times++;
}
int get_increae_trans(int fnum)
{
	return Files[fnum].trans_times;
}
void reset_increae_trans(int fnum)
{
	Files[fnum].trans_times = 0;
}

/****************************************************************************
close a file - possibly invalidating the read prediction

If normal_close is 1 then this came from a normal SMBclose (or equivalent)
operation otherwise it came as the result of some other operation such as
the closing of the connection. In the latter case printing and
magic scripts are not run
****************************************************************************/
static void close_normal_file(int fnum, BOOL normal_close)
{
	files_struct *fsp = &Files[fnum];
	BOOL delete_on_close = fsp->delete_on_close;
	int cnum = fsp->cnum;
	uint32 dev = fsp->fd_ptr->dev;
  	uint32 inode = fsp->fd_ptr->inode;
	int token;
	BOOL last_reference = False;

	fsp->open = False;	//set false indicates we free this file struct!
  	Connections[cnum].num_files_open--;

	if(fsp->wbmpx_ptr) 
  	{
    		free((char *)fsp->wbmpx_ptr);
    		fsp->wbmpx_ptr = NULL;
  	}

	 if (lp_share_modes(SNUM(cnum)))
  	{
    		lock_share_entry( cnum, dev, inode, &token);
    		del_share_mode(token, fnum);
  	}

	if(fd_attempt_close(fsp->fd_ptr) == 0)
		last_reference = True;

	if (lp_share_modes(SNUM(cnum)))
		unlock_share_entry(cnum, dev, inode, token);

//	if (normal_close)
//    		check_magic(fnum,cnum);

#ifdef OPLOCK_ENABLE
	if(fsp->granted_oplock == True)
    		global_oplocks_open--;
#endif

  	fsp->sent_oplock_break = False;

//deal with d.o.c bit for NT SMB!
	if (normal_close && last_reference && delete_on_close) {
        	DEBUG(5,("close_file: file %s. Delete on close was set - deleting file.\n",
	    			fsp->name));
		if(sys_unlink(fsp->name) != 0) {

          /*
           * This call can potentially fail as another smbd may have
           * had the file open with delete on close set and deleted
           * it when its last reference to this file went away. Hence
           * we log this but not at debug level zero.
           */

          		DEBUG(5,("close_file: file %s. Delete on close was set and unlink failed \
			with error %s\n", fsp->name, strerror(errno) ));
        	}
    	}

	if (fsp->name)
		string_free(&(fsp->name));

	DEBUG(0,("Done with close_normal_file!\n"));
	
}

static void close_dir(int fnum, BOOL normal_close)
{
	files_struct *fsp = &Files[fnum];
	int cnum = fsp->cnum;

	if(normal_close && fsp->directory_delete_on_close){
		BOOL ok = rmdir_internals(cnum, fsp->name);
		DEBUG(5,("close_directory: %s. Delete on close was set - deleting directory %s.\n",
				fsp->name, ok ? "succeeded" : "failed" ));
	}

	fsp->open = False;
	Connections[cnum].num_files_open--;
	free(fsp->fd_ptr);	//must free this because we do not use the global filefd struct!

	 if(fsp->wbmpx_ptr) 
  	{
    		free((char *)fsp->wbmpx_ptr);
    		fsp->wbmpx_ptr = NULL;
  	}

	if (fsp->name)
		string_free(&fsp->name);

	DEBUG(0,("done with close_dir!\n"));
}

void close_file(int fnum, BOOL normal_close)
{
	if(check_dir(Files[fnum].name))
		close_dir(fnum, normal_close);
	else
		close_normal_file(fnum, normal_close);
}

static BOOL is_executable(char *fname)
{
	if ((fname = strrchr_m(fname,'.'))) {
		if (strequal(fname,".com") ||
		    strequal(fname,".dll") ||
		    strequal(fname,".exe") ||
		    strequal(fname,".sym")) {
			return True;
		}
	}
	return False;
}

enum {AFAIL,AREAD,AWRITE,AALL};

/*******************************************************************
reproduce the share mode access table
********************************************************************/
static int access_table(int new_deny,int old_deny,int old_mode,
			int same_pid,char *fname)
{
  BOOL isexe = is_executable(fname);

  if (new_deny == DENY_ALL || old_deny == DENY_ALL) return(AFAIL);

	  if (same_pid) {
		  if (isexe && old_mode == DOS_OPEN_RDONLY && 
		      old_deny == DENY_DOS && new_deny == DENY_READ) {
			  return AFAIL;
		  }
		  if (!isexe && old_mode == DOS_OPEN_RDONLY && 
		      old_deny == DENY_DOS && new_deny == DENY_DOS) {
			  return AREAD;
		  }
		  if (new_deny == DENY_FCB && old_deny == DENY_DOS) {
			  if (isexe) return AFAIL;
			  if (old_mode == DOS_OPEN_RDONLY) return AFAIL;
			  return AALL;
		  }
		  if (old_mode == DOS_OPEN_RDONLY && old_deny == DENY_DOS) {
			  if (new_deny == DENY_FCB || new_deny == DENY_READ) {
				  if (isexe) return AREAD;
				  return AFAIL;
			  }
		  }
		  if (old_deny == DENY_FCB) {
			  if (new_deny == DENY_DOS || new_deny == DENY_FCB) return AALL;
			  return AFAIL;
		  }
	  }

	  if (old_deny == DENY_DOS || new_deny == DENY_DOS || 
	      old_deny == DENY_FCB || new_deny == DENY_FCB) {
		  if (isexe) {
			  if (old_deny == DENY_FCB || new_deny == DENY_FCB) {
				  return AFAIL;
			  }
			  if (old_deny == DENY_DOS) {
				  if (new_deny == DENY_READ && 
				      (old_mode == DOS_OPEN_RDONLY || 
				       old_mode == DOS_OPEN_RDWR)) {
					  return AFAIL;
				  }
				  if (new_deny == DENY_WRITE && 
				      (old_mode == DOS_OPEN_WRONLY || 
				       old_mode == DOS_OPEN_RDWR)) {
					  return AFAIL;
				  }
				  return AALL;
			  }
			  if (old_deny == DENY_NONE) return AALL;
			  if (old_deny == DENY_READ) return AWRITE;
			  if (old_deny == DENY_WRITE) return AREAD;
		  }
		  /* it isn't a exe, dll, sym or com file */
		  if (old_deny == new_deny && same_pid)
			  return(AALL);    

		  if (old_deny == DENY_READ || new_deny == DENY_READ) return AFAIL;
		  if (old_mode == DOS_OPEN_RDONLY) return(AREAD);
		  
		  return(AFAIL);
	  }
	  
	  switch (new_deny) 
		  {
		  case DENY_WRITE:
			  if (old_deny==DENY_WRITE && old_mode==DOS_OPEN_RDONLY) return(AREAD);
			  if (old_deny==DENY_READ && old_mode==DOS_OPEN_RDONLY) return(AWRITE);
			  if (old_deny==DENY_NONE && old_mode==DOS_OPEN_RDONLY) return(AALL);
			  return(AFAIL);
		  case DENY_READ:
			  if (old_deny==DENY_WRITE && old_mode==DOS_OPEN_WRONLY) return(AREAD);
			  if (old_deny==DENY_READ && old_mode==DOS_OPEN_WRONLY) return(AWRITE);
			  if (old_deny==DENY_NONE && old_mode==DOS_OPEN_WRONLY) return(AALL);
			  return(AFAIL);
		  case DENY_NONE:
			  if (old_deny==DENY_WRITE) return(AREAD);
			  if (old_deny==DENY_READ) return(AWRITE);
			  if (old_deny==DENY_NONE) return(AALL);
			  return(AFAIL);      
		  }
	  return(AFAIL);
}

/*******************************************************************
check if the share mode on a file allows it to be deleted or unlinked
return True if sharing doesn't prevent the operation
********************************************************************/
BOOL check_file_sharing(int cnum,char *fname)
{
  int i;
  int ret = False;
  share_mode_entry *old_shares = 0;
  int num_share_modes;
  SMB_STRUCT_STAT sbuf;
  int token;
  int pid = sys_getpid();
  uint32 dev, inode;

  if(!lp_share_modes(SNUM(cnum)))
    return True;

  if (sys_stat(fname,&sbuf) == -1) return(True);

  dev = (uint32)sbuf.st_dev;
  inode = (uint32)sbuf.st_ino;

  lock_share_entry(cnum, dev, inode, &token);
  num_share_modes = get_share_modes(cnum, token, dev, inode, &old_shares);

  /*
   * Check if the share modes will give us access.
   */

  if(num_share_modes != 0)
  {
    BOOL broke_oplock;

    do
    {

      broke_oplock = False;
      for(i = 0; i < num_share_modes; i++)
      {
        share_mode_entry *share_entry = &old_shares[i];

        /* 
         * Break oplocks before checking share modes. See comment in
         * open_file_shared for details. 
         * Check if someone has an oplock on this file. If so we must 
         * break it before continuing. 
         */
        if(share_entry->op_type & BATCH_OPLOCK)
        {

          DEBUG(5,("check_file_sharing: breaking oplock (%x) on file %s, \
dev = %x, inode = %x\n", share_entry->op_type, fname, dev, inode));

          /* Oplock break.... */
          unlock_share_entry(cnum, dev, inode, token);
#ifdef OPLOCK_ENABLE
          if(request_oplock_break(share_entry, dev, inode) == False)
#endif
          {
            free((char *)old_shares);
            DEBUG(0,("check_file_sharing: FAILED when breaking oplock (%x) on file %s, \
dev = %x, inode = %x\n", old_shares[i].op_type, fname, dev, inode));
            return False;
          }

          lock_share_entry(cnum, dev, inode, &token);
          broke_oplock = True;
          break;
        }

        /* someone else has a share lock on it, check to see 
           if we can too */
        if ((share_entry->share_mode != DENY_DOS) || (share_entry->pid != pid))
          goto free_and_exit;

      } /* end for */

      if(broke_oplock)
      {
        free((char *)old_shares);
        num_share_modes = get_share_modes(cnum, token, dev, inode, &old_shares);
      }
    } while(broke_oplock);
  }

  /* XXXX exactly what share mode combinations should be allowed for
     deleting/renaming? */
  /* If we got here then either there were no share modes or
     all share modes were DENY_DOS and the pid == getpid() */
  ret = True;

free_and_exit:

  unlock_share_entry(cnum, dev, inode, token);
  if(old_shares != NULL)
    free((char *)old_shares);
  return(ret);
}

/****************************************************************************
  C. Hoch 11/22/95
  Helper for open_file_shared. 
  Truncate a file after checking locking; close file if locked.
  **************************************************************************/
void truncate_unless_locked(int fnum, int cnum, int token, 
				   BOOL *share_locked)
{
  if (Files[fnum].can_write){
    if (is_locked(fnum,cnum,0x3FFFFFFF,0)){
      /* If share modes are in force for this connection we
         have the share entry locked. Unlock it before closing. */
      if (*share_locked && lp_share_modes(SNUM(cnum)))
        unlock_share_entry( cnum, Files[fnum].fd_ptr->dev, 
                            Files[fnum].fd_ptr->inode, token);
      close_file(fnum,False);   
      /* Share mode no longer locked. */
      *share_locked = False;
      errno = EACCES;
      unix_ERR_class = ERRDOS;
      unix_ERR_code = ERRlock;
    }
    else
      sys_ftruncate(Files[fnum].fd_ptr->fd,0);	//shrink...works fine with ftruncate! 
  }
}

/****************************************************************************
check if we can open a file with a share mode
****************************************************************************/
BOOL check_share_mode( share_mode_entry *share, int share_mode, uint32 desired_access,
						char *fname, BOOL fcbopen, int *flags)
{
	int deny_mode = (share_mode>>4)&7;
	int old_open_mode = share->share_mode &0xF;
  	int old_deny_mode = (share->share_mode >>4)&7;
  	BOOL non_io_open_request;
  	BOOL non_io_open_existing;

	if (desired_access & ~(SYNCHRONIZE_ACCESS|READ_CONTROL_ACCESS|FILE_READ_ATTRIBUTES|FILE_WRITE_ATTRIBUTES)) {
		non_io_open_request = False;
	} else {
		non_io_open_request = True;
	}

	if (share->desired_access & ~(SYNCHRONIZE_ACCESS|READ_CONTROL_ACCESS|FILE_READ_ATTRIBUTES|FILE_WRITE_ATTRIBUTES)) {
		non_io_open_existing = False;
	} else {
		non_io_open_existing = True;
	}

	if (GET_DELETE_ON_CLOSE_FLAG(share->share_mode)) {
		DEBUG(5,("check_share_mode: Failing open on file %s as delete on close flag is set.\n",
			fname ));

		return False;
	}

	if (non_io_open_request && non_io_open_existing) {

		/*
		 * Wrinkle discovered by smbtorture....
		 * If both are non-io open and requester is asking for delete and current open has delete access
		 * but neither open has allowed file share delete then deny.... this is very strange and
		 * seems to be the only case in which non-io opens conflict. JRA.
		 */

		if ((desired_access & DELETE_ACCESS) && (share->desired_access & DELETE_ACCESS) && 
				(!GET_ALLOW_SHARE_DELETE(share->share_mode) || !GET_ALLOW_SHARE_DELETE(share_mode))) {
			DEBUG(5,("check_share_mode: Failing open on file %s as delete access requests conflict.\n",
				fname ));

			return False;
		}

		DEBUG(5,("check_share_mode: Allowing open on file %s as both desired access (0x%x) \
and existing desired access (0x%x) are non-data opens\n", 
			fname, (unsigned int)desired_access, (unsigned int)share->desired_access ));
		return True;
	} 
	else if (non_io_open_request || non_io_open_existing) {
		/*
		 * If either are non-io opens then share modes don't conflict.
		 */
		DEBUG(5,("check_share_mode: One non-io open. Allowing open on file %s as desired access (0x%x) doesn't conflict with\
existing desired access (0x%x).\n", fname, (unsigned int)desired_access, (unsigned int)share->desired_access ));
		return True;
	}

  	if (old_deny_mode > 4 || old_open_mode > 2)
  	{
   		 DEBUG(0,("Invalid share mode found (%d,%d,%d) on file %s\n",
               		deny_mode,old_deny_mode,old_open_mode,fname));
    		return False;
  	}

	if ((desired_access & DELETE_ACCESS) && !GET_ALLOW_SHARE_DELETE(share->share_mode)) {
		DEBUG(5,("check_share_mode: Failing open on file %s as delete access requested and allow share delete not set.\n",
			fname ));
		
		return False;
	}

	if ((share->desired_access & DELETE_ACCESS) && !GET_ALLOW_SHARE_DELETE(share_mode)) {
		DEBUG(5,("check_share_mode: Failing open on file %s as delete access granted and allow share delete not requested.\n",
			fname ));
		
		return False;
	}

	if ( !(desired_access & (FILE_READ_DATA|FILE_WRITE_DATA|FILE_APPEND_DATA|FILE_EXECUTE)) ||
		!(share->desired_access & (FILE_READ_DATA|FILE_WRITE_DATA|FILE_APPEND_DATA|FILE_EXECUTE)) ) {
		DEBUG(5,("check_share_mode: Allowing open on file %s as desired access (0x%x) doesn't conflict with \
existing desired access (0x%x).\n", fname, (unsigned int)desired_access, (unsigned int)share->desired_access ));
		return True;
	}

  	{
    		int access_allowed = access_table(deny_mode,old_deny_mode,old_open_mode,
                                						share->pid,fname);

    		if ((access_allowed == AFAIL) ||
        	(!fcbopen && (access_allowed == AREAD && *flags == O_RDWR)) ||
        	(access_allowed == AREAD && *flags == O_WRONLY) ||
        	(access_allowed == AWRITE && *flags == O_RDONLY))
    		{
      			DEBUG(2,("Share violation on file (%d,%d,%d,%d,%s,fcbopen = %d, flags = %d) = %d\n",
                			deny_mode,old_deny_mode,old_open_mode,
                			share->pid,fname, fcbopen, *flags, access_allowed));
			
      			return False;
    		}

    		if (access_allowed == AREAD)
      			*flags = O_RDONLY;

    		if (access_allowed == AWRITE)
      			*flags = O_WRONLY;

  	}
  	return True;
}

/****************************************************************************
open a file with a share mode
****************************************************************************/
void open_file_shared(int fnum,int cnum,char *fname,int share_mode,int ofun,
		      int mode,int oplock_request, int *Access,int *action)
{
	open_nt_file_shared(fnum, cnum, fname, 0, 
					share_mode, ofun, mode, 
					oplock_request, Access, action);
}

/****************************************************************************
seek a file. Try to avoid the seek if possible
****************************************************************************/
SMB_OFF_T seek_file(int fnum,SMB_OFF_T pos)
{
  SMB_OFF_T offset = 0;
  if (POSTSCRIPT(Files[fnum].cnum))
    offset = 3;

  Files[fnum].pos =sys_lseek(Files[fnum].fd_ptr->fd, pos+offset, SEEK_SET) - offset;
  return(Files[fnum].pos);
}

/****************************************************************************
read from a file
****************************************************************************/
ssize_t read_file(int fnum,char *data,SMB_OFF_T pos,size_t n)
{
  ssize_t ret=0,readret;

#if USE_MMAP		//not using mmap to fast file I/O...
  if (Files[fnum].mmap_ptr)
    {
      int num = MIN(n,(int)(Files[fnum].mmap_size-pos));	//make sure we wont be out of memory!
      if (num > 0)
	{
	  memcpy(data,Files[fnum].mmap_ptr+pos,num);
	  data += num;	//why we need to add the offset??
	  pos += num;
	  n -= num;
	  ret += num;
	}
    }
#else
  if (n <= 0)
    return(ret);

  do{
	readret = sys_pread(Files[fnum].fd_ptr->fd,data,n,pos);
  }while(readret == -1 && errno == EINTR);

  ret += readret;
#endif
  
  return(ret);
}

ssize_t real_write_file(int fnum,char *data, size_t n, SMB_OFF_T pos)
{
	ssize_t ret;

        if (pos == -1)
                ret = write_data(Files[fnum].fd_ptr->fd, data, n);
        else {
		Files[fnum].pos = pos;
                ret = pwrite_data(Files[fnum].fd_ptr->fd, data, n, pos);
	}

	if (ret != -1) {
		Files[fnum].pos += ret;		//remember to update the pos for files
	}

	return ret;
}

/****************************************************************************
write to a file
****************************************************************************/
ssize_t new_write_file(int fnum,char *data,size_t n,SMB_OFF_T pos)
{		
  if (!Files[fnum].can_write) {
    errno = EPERM;
    return(0);
  }

  if (!Files[fnum].modified) {
    	SMB_STRUCT_STAT st;
    	Files[fnum].modified = True;
   	if (sys_fstat(Files[fnum].fd_ptr->fd,&st) == 0) {
      		int dosmode = dos_mode(Files[fnum].cnum,Files[fnum].name,&st);
      		if (MAP_ARCHIVE(Files[fnum].cnum) && !IS_DOS_ARCHIVE(dosmode))	
			dos_chmod(Files[fnum].cnum,Files[fnum].name,dosmode | aARCH,&st);
    	}  
  }

  /*we do not support oplock???*/

//  return(write_data(Files[fnum].fd_ptr->fd,data,n));
	return(real_write_file(fnum, data, n, pos));
}


/****************************************************************************
load parameters specific to a connection/service
****************************************************************************/
BOOL become_service(int cnum,BOOL do_chdir)
{
  extern char magic_char;
  static int last_cnum = -1;
  int snum;

  if (!OPEN_CNUM(cnum))
    {
      last_cnum = -1;
      return(False);
    }

  Connections[cnum].lastused = smb_last_time;

  snum = SNUM(cnum);
  
  if (do_chdir &&
      ChDir(Connections[cnum].connectpath) != 0 &&
      ChDir(Connections[cnum].origpath) != 0)
    {
      DEBUG(0,("%s chdir (%s) failed cnum=%d\n",timestring(),
	    Connections[cnum].connectpath,cnum));     
      return(False);
    }

  if (cnum == last_cnum)
    return(True);

  last_cnum = cnum;

  case_default = lp_defaultcase(snum);
  case_preserve = lp_preservecase(snum);
  short_case_preserve = lp_shortpreservecase(snum);
  case_mangle = lp_casemangle(snum);
  case_sensitive = lp_casesensitive(snum);
  magic_char = lp_magicchar(snum);
  use_mangled_map = (*lp_mangled_map(snum) ? True:False);
  return(True);
}


/****************************************************************************
  find a service entry
****************************************************************************/
int find_service(char *service)
{
   int iService;

   string_sub(service,"\\","/");

   iService = lp_servicenumber(service);

   /* now handle the special case of a home directory */
   if (iService < 0)
   {
      char *phome_dir = get_home_dir(service);
      DEBUG(3,("checking for home directory %s gave %s\n",service,
	    phome_dir?phome_dir:"(NULL)"));
      if (phome_dir)
      {   
	 int iHomeService;
	 if ((iHomeService = lp_servicenumber(HOMES_NAME)) >= 0)
	 {
	    lp_add_home(service,iHomeService,phome_dir);
	    iService = lp_servicenumber(service);
	 }
      }
   }

   if (iService < 0) 
     {
       char *defservice = lp_defaultservice();
       if (defservice && *defservice && !strequal(defservice,service)) {
	 iService = find_service(defservice);
	 if (iService >= 0) {
	   string_sub(service,"_","/");
	   iService = lp_add_service(service,iService);
	 }
       }
     }

   if (iService >= 0)
      if (!VALID_SNUM(iService))
      {
         DEBUG(0,("Invalid snum %d for %s\n",iService,service));
	 iService = -1;
      }

   if (iService < 0)
      DEBUG(3,("find_service() failed to find service %s\n", service));

   return (iService);
}


/****************************************************************************
  create an error packet from a cached error.
****************************************************************************/
int cached_error_packet(char *inbuf,char *outbuf,int fnum,int line)
{
  write_bmpx_struct *wbmpx = Files[fnum].wbmpx_ptr;

  int32 eclass = wbmpx->wr_errclass;
  int32 err = wbmpx->wr_error;

  /* We can now delete the auxiliary struct */
  free((char *)wbmpx);
  Files[fnum].wbmpx_ptr = NULL;
  return ERROR_DOS(eclass,err);
}

/*
struct
{
  int unixerror;
  int smbclass;
  int smbcode;
} unix_smb_errmap[] =
{
  {EPERM,ERRDOS,ERRnoaccess},
  {EACCES,ERRDOS,ERRnoaccess},
  {ENOENT,ERRDOS,ERRbadfile},
  {ENOTDIR,ERRDOS,ERRbadpath},
  {EIO,ERRHRD,ERRgeneral},
  {EBADF,ERRSRV,ERRsrverror},
  {EINVAL,ERRSRV,ERRsrverror},
  {EEXIST,ERRDOS,ERRfilexists},
  {ENFILE,ERRDOS,ERRnofids},
  {EMFILE,ERRDOS,ERRnofids},
  {ENOSPC,ERRHRD,ERRdiskfull},
#ifdef EDQUOT
  {EDQUOT,ERRHRD,ERRdiskfull},
#endif
#ifdef ENOTEMPTY
  {ENOTEMPTY,ERRDOS,ERRnoaccess},
#endif
#ifdef EXDEV
  {EXDEV,ERRDOS,ERRdiffdevice},
#endif
  {EROFS,ERRHRD,ERRnowrite},
  {0,0,0}
};
*/

struct unix_error_map {
	int unix_error;
	int dos_class;
	int dos_code;
	NTSTATUS nt_error;
};

const struct unix_error_map unix_dos_nt_errmap[] = {
	{ EPERM, ERRDOS, ERRnoaccess, NT_STATUS_ACCESS_DENIED },
	{ EACCES, ERRDOS, ERRnoaccess, NT_STATUS_ACCESS_DENIED },
	{ ENOENT, ERRDOS, ERRbadfile, NT_STATUS_OBJECT_NAME_NOT_FOUND },
	{ ENOTDIR, ERRDOS, ERRbadpath,  NT_STATUS_NOT_A_DIRECTORY },
	{ EIO, ERRHRD, ERRgeneral, NT_STATUS_IO_DEVICE_ERROR },
	{ EBADF, ERRSRV, ERRsrverror, NT_STATUS_INVALID_HANDLE },
	{ EINVAL, ERRSRV, ERRsrverror, NT_STATUS_INVALID_HANDLE },
	{ EEXIST, ERRDOS, ERRfilexists, NT_STATUS_OBJECT_NAME_COLLISION},
	{ ENFILE, ERRDOS, ERRnofids, NT_STATUS_TOO_MANY_OPENED_FILES },
	{ EMFILE, ERRDOS, ERRnofids, NT_STATUS_TOO_MANY_OPENED_FILES },
	{ ENOSPC, ERRHRD, ERRdiskfull, NT_STATUS_DISK_FULL },
	{ ENOMEM, ERRDOS, ERRnomem, NT_STATUS_NO_MEMORY },
	{ EISDIR, ERRDOS, ERRnoaccess, NT_STATUS_FILE_IS_A_DIRECTORY},
#ifdef EDQUOT
	{ EDQUOT, ERRHRD, ERRdiskfull, NT_STATUS_DISK_FULL },
#endif
#ifdef ENOTEMPTY
	{ ENOTEMPTY, ERRDOS, ERRnoaccess, NT_STATUS_DIRECTORY_NOT_EMPTY },
#endif
#ifdef EXDEV
	{ EXDEV, ERRDOS, ERRdiffdevice, NT_STATUS_NOT_SAME_DEVICE },
#endif
#ifdef EROFS
	{ EROFS, ERRHRD, ERRnowrite, NT_STATUS_ACCESS_DENIED },
#endif
#ifdef ENAMETOOLONG
	{ ENAMETOOLONG, ERRDOS, 206, NT_STATUS_OBJECT_NAME_INVALID },
#endif
#ifdef EFBIG
	{ EFBIG, ERRHRD, ERRdiskfull, NT_STATUS_DISK_FULL },
#endif
	{ 0, 0, 0, NT_STATUS_OK }
};

/* dos -> nt status error map */
static const struct {
	uint8 dos_class;
	uint32 dos_code;
	NTSTATUS ntstatus;
} dos_to_ntstatus_map[] = {
	{ERRDOS,	ERRbadfunc,	NT_STATUS_NOT_IMPLEMENTED},
	{ERRDOS,	ERRbadfile,	NT_STATUS_NO_SUCH_FILE},
	{ERRDOS,	ERRbadpath,	NT_STATUS_OBJECT_PATH_NOT_FOUND},
	{ERRDOS,	ERRnofids,	NT_STATUS_TOO_MANY_OPENED_FILES},
	{ERRDOS,	ERRnoaccess,	NT_STATUS_ACCESS_DENIED},
	{ERRDOS,	ERRbadfid,	NT_STATUS_INVALID_HANDLE},
	{ERRDOS,	ERRnomem,	NT_STATUS_INSUFFICIENT_RESOURCES},
	{ERRDOS,	ERRbadaccess,	NT_STATUS_ACCESS_DENIED},
	{ERRDOS,	ERRbaddata,	NT_STATUS_DATA_ERROR},
	{ERRDOS,	14,	NT_STATUS_SECTION_NOT_EXTENDED},
	{ERRDOS,	ERRremcd,	NT_STATUS_DIRECTORY_NOT_EMPTY},
	{ERRDOS,	ERRdiffdevice,	NT_STATUS_NOT_SAME_DEVICE},
	{ERRDOS,	ERRnofiles,	STATUS_NO_MORE_FILES},
	{ERRDOS,	19,	NT_STATUS_MEDIA_WRITE_PROTECTED},
	{ERRDOS,	21,	NT_STATUS_NO_MEDIA_IN_DEVICE},
	{ERRDOS,	22,	NT_STATUS_INVALID_DEVICE_STATE},
	{ERRDOS,	23,	NT_STATUS_DATA_ERROR},
	{ERRDOS,	24,	NT_STATUS_DATA_ERROR},
	{ERRDOS,	26,	NT_STATUS_DISK_CORRUPT_ERROR},
	{ERRDOS,	27,	NT_STATUS_NONEXISTENT_SECTOR},
	{ERRDOS,	28,	NT_STATUS(0x8000000e)},
	{ERRDOS,	31,	NT_STATUS_UNSUCCESSFUL},
	{ERRDOS,	ERRbadshare,	NT_STATUS_SHARING_VIOLATION},
	{ERRDOS,	ERRlock,	NT_STATUS_FILE_LOCK_CONFLICT},
	{ERRDOS,	34,	NT_STATUS_WRONG_VOLUME},
	{ERRDOS,	38,	NT_STATUS_END_OF_FILE},
	{ERRDOS,	ERRunsup,	NT_STATUS_CTL_FILE_NOT_SUPPORTED},
	{ERRDOS,	51,	NT_STATUS_REMOTE_NOT_LISTENING},
	{ERRDOS,	52,	NT_STATUS_DUPLICATE_NAME},
	{ERRDOS,	53,	NT_STATUS_BAD_NETWORK_PATH},
	{ERRDOS,	54,	NT_STATUS_NETWORK_BUSY},
	{ERRDOS,	55,	NT_STATUS_DEVICE_DOES_NOT_EXIST},
	{ERRDOS,	56,	NT_STATUS_TOO_MANY_COMMANDS},
	{ERRDOS,	57,	NT_STATUS_ADAPTER_HARDWARE_ERROR},
	{ERRDOS,	58,	NT_STATUS_INVALID_NETWORK_RESPONSE},
	{ERRDOS,	59,	NT_STATUS_UNEXPECTED_NETWORK_ERROR},
	{ERRDOS,	60,	NT_STATUS_BAD_REMOTE_ADAPTER},
	{ERRDOS,	61,	NT_STATUS_PRINT_QUEUE_FULL},
	{ERRDOS,	62,	NT_STATUS_NO_SPOOL_SPACE},
	{ERRDOS,	63,	NT_STATUS_PRINT_CANCELLED},
	{ERRDOS,	64,	NT_STATUS_NETWORK_NAME_DELETED},
	{ERRDOS,	65,	NT_STATUS_NETWORK_ACCESS_DENIED},
	{ERRDOS,	66,	NT_STATUS_BAD_DEVICE_TYPE},
	{ERRDOS,	ERRnosuchshare,	NT_STATUS_BAD_NETWORK_NAME},
	{ERRDOS,	68,	NT_STATUS_TOO_MANY_GUIDS_REQUESTED},
	{ERRDOS,	69,	NT_STATUS_TOO_MANY_SESSIONS},
	{ERRDOS,	70,	NT_STATUS_SHARING_PAUSED},
	{ERRDOS,	71,	NT_STATUS_REQUEST_NOT_ACCEPTED},
	{ERRDOS,	72,	NT_STATUS_REDIRECTOR_PAUSED},
	{ERRDOS,	ERRfilexists,	NT_STATUS_OBJECT_NAME_COLLISION},
	{ERRDOS,	86,	NT_STATUS_WRONG_PASSWORD},
	{ERRDOS,	87,	NT_STATUS_INVALID_INFO_CLASS},
	{ERRDOS,	88,	NT_STATUS_NET_WRITE_FAULT},
	{ERRDOS,	109,	NT_STATUS_PIPE_BROKEN},
	{ERRDOS,	111,	STATUS_MORE_ENTRIES},
	{ERRDOS,	112,	NT_STATUS_DISK_FULL},
	{ERRDOS,	121,	NT_STATUS_IO_TIMEOUT},
	{ERRDOS,	122,	NT_STATUS_BUFFER_TOO_SMALL},
	{ERRDOS,	ERRinvalidname,	NT_STATUS_OBJECT_NAME_INVALID},
	{ERRDOS,	124,	NT_STATUS_INVALID_LEVEL},
	{ERRDOS,	126,	NT_STATUS_DLL_NOT_FOUND},
	{ERRDOS,	127,	NT_STATUS_PROCEDURE_NOT_FOUND},
	{ERRDOS,	145,	NT_STATUS_DIRECTORY_NOT_EMPTY},
	{ERRDOS,	154,	NT_STATUS_INVALID_VOLUME_LABEL},
	{ERRDOS,	156,	NT_STATUS_SUSPEND_COUNT_EXCEEDED},
	{ERRDOS,	158,	NT_STATUS_NOT_LOCKED},
	{ERRDOS,	161,	NT_STATUS_OBJECT_PATH_INVALID},
	{ERRDOS,	170,	NT_STATUS(0x80000011)},
	{ERRDOS,	182,	NT_STATUS_ORDINAL_NOT_FOUND},
	{ERRDOS,	183,	NT_STATUS_OBJECT_NAME_COLLISION},
	{ERRDOS,	193,	NT_STATUS_BAD_INITIAL_PC},
	{ERRDOS,	203,	NT_STATUS(0xc0000100)},
	{ERRDOS,	206,	NT_STATUS_NAME_TOO_LONG},
	{ERRDOS,	ERRbadpipe,	NT_STATUS_INVALID_INFO_CLASS},
	{ERRDOS,	ERRpipebusy,	NT_STATUS_INSTANCE_NOT_AVAILABLE},
	{ERRDOS,	ERRpipeclosing,	NT_STATUS_PIPE_CLOSING},
	{ERRDOS,	ERRnotconnected,	NT_STATUS_PIPE_DISCONNECTED},
	{ERRDOS,	ERRmoredata,	NT_STATUS_MORE_PROCESSING_REQUIRED},
	{ERRDOS,	240,	NT_STATUS_VIRTUAL_CIRCUIT_CLOSED},
	{ERRDOS,	254,	NT_STATUS(0x80000013)},
	{ERRDOS,	255,	NT_STATUS_EA_TOO_LARGE},
	{ERRDOS,	259,	NT_STATUS_GUIDS_EXHAUSTED},
	{ERRDOS,	267,	NT_STATUS_NOT_A_DIRECTORY},
	{ERRDOS,	275,	NT_STATUS_EA_TOO_LARGE},
	{ERRDOS,	276,	NT_STATUS_NONEXISTENT_EA_ENTRY},
	{ERRDOS,	277,	NT_STATUS_NONEXISTENT_EA_ENTRY},
	{ERRDOS,	278,	NT_STATUS_NONEXISTENT_EA_ENTRY},
	{ERRDOS,	282,	NT_STATUS_EAS_NOT_SUPPORTED},
	{ERRDOS,	288,	NT_STATUS_MUTANT_NOT_OWNED},
	{ERRDOS,	298,	NT_STATUS_SEMAPHORE_LIMIT_EXCEEDED},
	{ERRDOS,	299,	NT_STATUS(0x8000000d)},
	{ERRDOS,	300,	NT_STATUS_OPLOCK_NOT_GRANTED},
	{ERRDOS,	301,	NT_STATUS_INVALID_OPLOCK_PROTOCOL},
	{ERRDOS,	487,	NT_STATUS_CONFLICTING_ADDRESSES},
	{ERRDOS,	534,	NT_STATUS_INTEGER_OVERFLOW},
	{ERRDOS,	535,	NT_STATUS_PIPE_CONNECTED},
	{ERRDOS,	536,	NT_STATUS_PIPE_LISTENING},
	{ERRDOS,	995,	NT_STATUS_CANCELLED},
	{ERRDOS,	997,	NT_STATUS(0x00000103)},
	{ERRDOS,	998,	NT_STATUS_ACCESS_VIOLATION},
	{ERRDOS,	999,	NT_STATUS_IN_PAGE_ERROR},
	{ERRDOS,	1001,	NT_STATUS_BAD_INITIAL_STACK},
	{ERRDOS,	1005,	NT_STATUS_UNRECOGNIZED_VOLUME},
	{ERRDOS,	1006,	NT_STATUS_FILE_INVALID},
	{ERRDOS,	1007,	NT_STATUS_FULLSCREEN_MODE},
	{ERRDOS,	1008,	NT_STATUS_NO_TOKEN},
	{ERRDOS,	1009,	NT_STATUS_REGISTRY_CORRUPT},
	{ERRDOS,	1016,	NT_STATUS_REGISTRY_IO_FAILED},
	{ERRDOS,	1017,	NT_STATUS_NOT_REGISTRY_FILE},
	{ERRDOS,	1018,	NT_STATUS_KEY_DELETED},
	{ERRDOS,	1019,	NT_STATUS_NO_LOG_SPACE},
	{ERRDOS,	1020,	NT_STATUS_KEY_HAS_CHILDREN},
	{ERRDOS,	1021,	NT_STATUS_CHILD_MUST_BE_VOLATILE},
	{ERRDOS,	1022,	NT_STATUS(0x0000010c)},
	{ERRSRV,	ERRbadpw,	NT_STATUS_WRONG_PASSWORD},
	{ERRSRV,	ERRbadtype,	NT_STATUS_BAD_DEVICE_TYPE},
	{ERRSRV,	ERRaccess,	NT_STATUS_NETWORK_ACCESS_DENIED},
	{ERRSRV,	ERRinvnid,	NT_STATUS_NETWORK_NAME_DELETED},
	{ERRSRV,	ERRinvnetname,	NT_STATUS_BAD_NETWORK_NAME},
	{ERRSRV,	ERRinvdevice,	NT_STATUS_BAD_DEVICE_TYPE},
	{ERRSRV,	ERRqfull,	NT_STATUS_PRINT_QUEUE_FULL},
	{ERRSRV,	ERRqtoobig,	NT_STATUS_NO_SPOOL_SPACE},
	{ERRSRV,	ERRinvpfid,	NT_STATUS_PRINT_CANCELLED},
	{ERRSRV,	ERRsmbcmd,	NT_STATUS_NOT_IMPLEMENTED},
	{ERRSRV,	ERRbadpermits,	NT_STATUS_NETWORK_ACCESS_DENIED},
	{ERRSRV,	ERRpaused,	NT_STATUS_SHARING_PAUSED},
	{ERRSRV,	ERRmsgoff,	NT_STATUS_REQUEST_NOT_ACCEPTED},
	{ERRSRV,	ERRnoroom,	NT_STATUS_DISK_FULL},
	{ERRSRV,	ERRnoresource,	NT_STATUS_REQUEST_NOT_ACCEPTED},
	{ERRSRV,	ERRtoomanyuids,	NT_STATUS_TOO_MANY_SESSIONS},
	{ERRSRV,	123,	NT_STATUS_OBJECT_NAME_INVALID},
	{ERRSRV,	206,	NT_STATUS_OBJECT_NAME_INVALID},
	{ERRHRD,	1,	NT_STATUS_NOT_IMPLEMENTED},
	{ERRHRD,	2,	NT_STATUS_NO_SUCH_DEVICE},
	{ERRHRD,	3,	NT_STATUS_OBJECT_PATH_NOT_FOUND},
	{ERRHRD,	4,	NT_STATUS_TOO_MANY_OPENED_FILES},
	{ERRHRD,	5,	NT_STATUS_INVALID_LOCK_SEQUENCE},
	{ERRHRD,	6,	NT_STATUS_INVALID_HANDLE},
	{ERRHRD,	8,	NT_STATUS_INSUFFICIENT_RESOURCES},
	{ERRHRD,	12,	NT_STATUS_INVALID_LOCK_SEQUENCE},
	{ERRHRD,	13,	NT_STATUS_DATA_ERROR},
	{ERRHRD,	14,	NT_STATUS_SECTION_NOT_EXTENDED},
	{ERRHRD,	16,	NT_STATUS_DIRECTORY_NOT_EMPTY},
	{ERRHRD,	17,	NT_STATUS_NOT_SAME_DEVICE},
	{ERRHRD,	18,	NT_STATUS(0x80000006)},
	{ERRHRD,	ERRnowrite,	NT_STATUS_MEDIA_WRITE_PROTECTED},
	{ERRHRD,	ERRnotready,	NT_STATUS_NO_MEDIA_IN_DEVICE},
	{ERRHRD,	ERRbadcmd,	NT_STATUS_INVALID_DEVICE_STATE},
	{ERRHRD,	ERRdata,	NT_STATUS_DATA_ERROR},
	{ERRHRD,	ERRbadreq,	NT_STATUS_DATA_ERROR},
	{ERRHRD,	ERRbadmedia,	NT_STATUS_DISK_CORRUPT_ERROR},
	{ERRHRD,	ERRbadsector,	NT_STATUS_NONEXISTENT_SECTOR},
	{ERRHRD,	ERRnopaper,	NT_STATUS(0x8000000e)},
	{ERRHRD,	ERRgeneral,	NT_STATUS_UNSUCCESSFUL},
	{ERRHRD,	ERRbadshare,	NT_STATUS_SHARING_VIOLATION},
	{ERRHRD,	ERRlock,	NT_STATUS_FILE_LOCK_CONFLICT},
	{ERRHRD,	ERRwrongdisk,	NT_STATUS_WRONG_VOLUME},
	{ERRHRD,	38,	NT_STATUS_END_OF_FILE},
	{ERRHRD,	ERRdiskfull,	NT_STATUS_DISK_FULL},
	{ERRHRD,	50,	NT_STATUS_CTL_FILE_NOT_SUPPORTED},
	{ERRHRD,	51,	NT_STATUS_REMOTE_NOT_LISTENING},
	{ERRHRD,	52,	NT_STATUS_DUPLICATE_NAME},
	{ERRHRD,	53,	NT_STATUS_BAD_NETWORK_PATH},
	{ERRHRD,	54,	NT_STATUS_NETWORK_BUSY},
	{ERRHRD,	55,	NT_STATUS_DEVICE_DOES_NOT_EXIST},
	{ERRHRD,	56,	NT_STATUS_TOO_MANY_COMMANDS},
	{ERRHRD,	57,	NT_STATUS_ADAPTER_HARDWARE_ERROR},
	{ERRHRD,	58,	NT_STATUS_INVALID_NETWORK_RESPONSE},
	{ERRHRD,	59,	NT_STATUS_UNEXPECTED_NETWORK_ERROR},
	{ERRHRD,	60,	NT_STATUS_BAD_REMOTE_ADAPTER},
	{ERRHRD,	61,	NT_STATUS_PRINT_QUEUE_FULL},
	{ERRHRD,	62,	NT_STATUS_NO_SPOOL_SPACE},
	{ERRHRD,	63,	NT_STATUS_PRINT_CANCELLED},
	{ERRHRD,	64,	NT_STATUS_NETWORK_NAME_DELETED},
	{ERRHRD,	65,	NT_STATUS_NETWORK_ACCESS_DENIED},
	{ERRHRD,	66,	NT_STATUS_BAD_DEVICE_TYPE},
	{ERRHRD,	67,	NT_STATUS_BAD_NETWORK_NAME},
	{ERRHRD,	68,	NT_STATUS_TOO_MANY_GUIDS_REQUESTED},
	{ERRHRD,	69,	NT_STATUS_TOO_MANY_SESSIONS},
	{ERRHRD,	70,	NT_STATUS_SHARING_PAUSED},
	{ERRHRD,	71,	NT_STATUS_REQUEST_NOT_ACCEPTED},
	{ERRHRD,	72,	NT_STATUS_REDIRECTOR_PAUSED},
	{ERRHRD,	80,	NT_STATUS_OBJECT_NAME_COLLISION},
	{ERRHRD,	86,	NT_STATUS_WRONG_PASSWORD},
	{ERRHRD,	87,	NT_STATUS_INVALID_INFO_CLASS},
	{ERRHRD,	88,	NT_STATUS_NET_WRITE_FAULT},
	{ERRHRD,	109,	NT_STATUS_PIPE_BROKEN},
	{ERRHRD,	111,	STATUS_MORE_ENTRIES},
	{ERRHRD,	112,	NT_STATUS_DISK_FULL},
	{ERRHRD,	121,	NT_STATUS_IO_TIMEOUT},
	{ERRHRD,	122,	NT_STATUS_BUFFER_TOO_SMALL},
	{ERRHRD,	123,	NT_STATUS_OBJECT_NAME_INVALID},
	{ERRHRD,	124,	NT_STATUS_INVALID_LEVEL},
	{ERRHRD,	126,	NT_STATUS_DLL_NOT_FOUND},
	{ERRHRD,	127,	NT_STATUS_PROCEDURE_NOT_FOUND},
	{ERRHRD,	145,	NT_STATUS_DIRECTORY_NOT_EMPTY},
	{ERRHRD,	154,	NT_STATUS_INVALID_VOLUME_LABEL},
	{ERRHRD,	156,	NT_STATUS_SUSPEND_COUNT_EXCEEDED},
	{ERRHRD,	158,	NT_STATUS_NOT_LOCKED},
	{ERRHRD,	161,	NT_STATUS_OBJECT_PATH_INVALID},
	{ERRHRD,	170,	NT_STATUS(0x80000011)},
	{ERRHRD,	182,	NT_STATUS_ORDINAL_NOT_FOUND},
	{ERRHRD,	183,	NT_STATUS_OBJECT_NAME_COLLISION},
	{ERRHRD,	193,	NT_STATUS_BAD_INITIAL_PC},
	{ERRHRD,	203,	NT_STATUS(0xc0000100)},
	{ERRHRD,	206,	NT_STATUS_NAME_TOO_LONG},
	{ERRHRD,	230,	NT_STATUS_INVALID_INFO_CLASS},
	{ERRHRD,	231,	NT_STATUS_INSTANCE_NOT_AVAILABLE},
	{ERRHRD,	232,	NT_STATUS_PIPE_CLOSING},
	{ERRHRD,	233,	NT_STATUS_PIPE_DISCONNECTED},
	{ERRHRD,	234,	STATUS_MORE_ENTRIES},
	{ERRHRD,	240,	NT_STATUS_VIRTUAL_CIRCUIT_CLOSED},
	{ERRHRD,	254,	NT_STATUS(0x80000013)},
	{ERRHRD,	255,	NT_STATUS_EA_TOO_LARGE},
	{ERRHRD,	259,	NT_STATUS_GUIDS_EXHAUSTED},
	{ERRHRD,	267,	NT_STATUS_NOT_A_DIRECTORY},
	{ERRHRD,	275,	NT_STATUS_EA_TOO_LARGE},
	{ERRHRD,	276,	NT_STATUS_NONEXISTENT_EA_ENTRY},
	{ERRHRD,	277,	NT_STATUS_NONEXISTENT_EA_ENTRY},
	{ERRHRD,	278,	NT_STATUS_NONEXISTENT_EA_ENTRY},
	{ERRHRD,	282,	NT_STATUS_EAS_NOT_SUPPORTED},
	{ERRHRD,	288,	NT_STATUS_MUTANT_NOT_OWNED},
	{ERRHRD,	298,	NT_STATUS_SEMAPHORE_LIMIT_EXCEEDED},
	{ERRHRD,	299,	NT_STATUS(0x8000000d)},
	{ERRHRD,	300,	NT_STATUS_OPLOCK_NOT_GRANTED},
	{ERRHRD,	301,	NT_STATUS_INVALID_OPLOCK_PROTOCOL},
	{ERRHRD,	487,	NT_STATUS_CONFLICTING_ADDRESSES},
	{ERRHRD,	534,	NT_STATUS_INTEGER_OVERFLOW},
	{ERRHRD,	535,	NT_STATUS_PIPE_CONNECTED},
	{ERRHRD,	536,	NT_STATUS_PIPE_LISTENING},
	{ERRHRD,	995,	NT_STATUS_CANCELLED},
	{ERRHRD,	997,	NT_STATUS(0x00000103)},
	{ERRHRD,	998,	NT_STATUS_ACCESS_VIOLATION},
	{ERRHRD,	999,	NT_STATUS_IN_PAGE_ERROR},
	{ERRHRD,	1001,	NT_STATUS_BAD_INITIAL_STACK},
	{ERRHRD,	1005,	NT_STATUS_UNRECOGNIZED_VOLUME},
	{ERRHRD,	1006,	NT_STATUS_FILE_INVALID},
	{ERRHRD,	1007,	NT_STATUS_FULLSCREEN_MODE},
	{ERRHRD,	1008,	NT_STATUS_NO_TOKEN},
	{ERRHRD,	1009,	NT_STATUS_REGISTRY_CORRUPT},
	{ERRHRD,	1016,	NT_STATUS_REGISTRY_IO_FAILED},
	{ERRHRD,	1017,	NT_STATUS_NOT_REGISTRY_FILE},
	{ERRHRD,	1018,	NT_STATUS_KEY_DELETED},
	{ERRHRD,	1019,	NT_STATUS_NO_LOG_SPACE},
	{ERRHRD,	1020,	NT_STATUS_KEY_HAS_CHILDREN},
	{ERRHRD,	1021,	NT_STATUS_CHILD_MUST_BE_VOLATILE},
	{ERRHRD,	1022,	NT_STATUS(0x0000010c)},
};

/* NT status -> dos error map */
static const struct {
	uint8 dos_class;
	uint32 dos_code;
	NTSTATUS ntstatus;
} ntstatus_to_dos_map[] = {
	{ERRDOS,	ERRgeneral,	NT_STATUS_UNSUCCESSFUL},
	{ERRDOS,	ERRbadfunc,	NT_STATUS_NOT_IMPLEMENTED},
	{ERRDOS,	87,	NT_STATUS_INVALID_INFO_CLASS},
	{ERRDOS,	24,	NT_STATUS_INFO_LENGTH_MISMATCH},
	{ERRHRD,	ERRgeneral,	NT_STATUS_ACCESS_VIOLATION},
	{ERRHRD,	ERRgeneral,	NT_STATUS_IN_PAGE_ERROR},
	{ERRHRD,	ERRgeneral,	NT_STATUS_PAGEFILE_QUOTA},
	{ERRDOS,	ERRbadfid,	NT_STATUS_INVALID_HANDLE},
	{ERRHRD,	ERRgeneral,	NT_STATUS_BAD_INITIAL_STACK},
	{ERRDOS,	193,	NT_STATUS_BAD_INITIAL_PC},
	{ERRDOS,	87,	NT_STATUS_INVALID_CID},
	{ERRHRD,	ERRgeneral,	NT_STATUS_TIMER_NOT_CANCELED},
	{ERRDOS,	87,	NT_STATUS_INVALID_PARAMETER},
	{ERRDOS,	ERRbadfile,	NT_STATUS_NO_SUCH_DEVICE},
	{ERRDOS,	ERRbadfile,	NT_STATUS_NO_SUCH_FILE},
	{ERRDOS,	ERRbadfunc,	NT_STATUS_INVALID_DEVICE_REQUEST},
	{ERRDOS,	38,	NT_STATUS_END_OF_FILE},
	{ERRDOS,	34,	NT_STATUS_WRONG_VOLUME},
	{ERRDOS,	21,	NT_STATUS_NO_MEDIA_IN_DEVICE},
	{ERRHRD,	ERRgeneral,	NT_STATUS_UNRECOGNIZED_MEDIA},
	{ERRDOS,	27,	NT_STATUS_NONEXISTENT_SECTOR},
/** Session setup succeeded.  This shouldn't happen...*/
/** Session setup succeeded.  This shouldn't happen...*/
/** NT error on DOS connection! (NT_STATUS_OK) */
/*	{ This NT error code was 'sqashed'
	 from NT_STATUS_MORE_PROCESSING_REQUIRED to NT_STATUS_OK 
	 during the session setup }
*/
#if 0
	{SUCCESS,	0,	NT_STATUS_OK},
#endif
	{ERRDOS,	ERRnomem,	NT_STATUS_NO_MEMORY},
	{ERRDOS,	487,	NT_STATUS_CONFLICTING_ADDRESSES},
	{ERRDOS,	487,	NT_STATUS_NOT_MAPPED_VIEW},
	{ERRDOS,	87,	NT_STATUS_UNABLE_TO_FREE_VM},
	{ERRDOS,	87,	NT_STATUS_UNABLE_TO_DELETE_SECTION},
	{ERRDOS,	2142,	NT_STATUS_INVALID_SYSTEM_SERVICE},
	{ERRHRD,	ERRgeneral,	NT_STATUS_ILLEGAL_INSTRUCTION},
	{ERRDOS,	ERRnoaccess,	NT_STATUS_INVALID_LOCK_SEQUENCE},
	{ERRDOS,	ERRnoaccess,	NT_STATUS_INVALID_VIEW_SIZE},
	{ERRDOS,	193,	NT_STATUS_INVALID_FILE_FOR_SECTION},
	{ERRDOS,	ERRnoaccess,	NT_STATUS_ALREADY_COMMITTED},
/*	{ This NT error code was 'sqashed'
	 from NT_STATUS_ACCESS_DENIED to NT_STATUS_TRUSTED_RELATIONSHIP_FAILURE 
	 during the session setup }
*/
	{ERRDOS,	ERRnoaccess,	NT_STATUS_ACCESS_DENIED},
	{ERRDOS,	111,	NT_STATUS_BUFFER_TOO_SMALL},
/*
 * Not an official error, as only bit 0x80000000, not bits 0xC0000000 are set.
 */
	{ERRDOS,	ERRmoredata,	STATUS_BUFFER_OVERFLOW},
	{ERRDOS,	ERRnofiles,	STATUS_NO_MORE_FILES},
	{ERRDOS,	ERRbadfid,	NT_STATUS_OBJECT_TYPE_MISMATCH},
	{ERRHRD,	ERRgeneral,	NT_STATUS_NONCONTINUABLE_EXCEPTION},
	{ERRHRD,	ERRgeneral,	NT_STATUS_INVALID_DISPOSITION},
	{ERRHRD,	ERRgeneral,	NT_STATUS_UNWIND},
	{ERRHRD,	ERRgeneral,	NT_STATUS_BAD_STACK},
	{ERRHRD,	ERRgeneral,	NT_STATUS_INVALID_UNWIND_TARGET},
	{ERRDOS,	158,	NT_STATUS_NOT_LOCKED},
	{ERRHRD,	ERRgeneral,	NT_STATUS_PARITY_ERROR},
	{ERRDOS,	487,	NT_STATUS_UNABLE_TO_DECOMMIT_VM},
	{ERRDOS,	487,	NT_STATUS_NOT_COMMITTED},
	{ERRHRD,	ERRgeneral,	NT_STATUS_INVALID_PORT_ATTRIBUTES},
	{ERRHRD,	ERRgeneral,	NT_STATUS_PORT_MESSAGE_TOO_LONG},
	{ERRDOS,	87,	NT_STATUS_INVALID_PARAMETER_MIX},
	{ERRHRD,	ERRgeneral,	NT_STATUS_INVALID_QUOTA_LOWER},
	{ERRHRD,	ERRgeneral,	NT_STATUS_DISK_CORRUPT_ERROR},
	{ERRDOS,	ERRinvalidname,	NT_STATUS_OBJECT_NAME_INVALID},
	{ERRDOS,	ERRbadfile,	NT_STATUS_OBJECT_NAME_NOT_FOUND},
	{ERRDOS,	183,	NT_STATUS_OBJECT_NAME_COLLISION},
	{ERRHRD,	ERRgeneral,	NT_STATUS_HANDLE_NOT_WAITABLE},
	{ERRDOS,	ERRbadfid,	NT_STATUS_PORT_DISCONNECTED},
	{ERRHRD,	ERRgeneral,	NT_STATUS_DEVICE_ALREADY_ATTACHED},
	{ERRDOS,	161,	NT_STATUS_OBJECT_PATH_INVALID},
	{ERRDOS,	ERRbadpath,	NT_STATUS_OBJECT_PATH_NOT_FOUND},
	{ERRDOS,	161,	NT_STATUS_OBJECT_PATH_SYNTAX_BAD},
	{ERRHRD,	ERRgeneral,	NT_STATUS_DATA_OVERRUN},
	{ERRHRD,	ERRgeneral,	NT_STATUS_DATA_LATE_ERROR},
	{ERRDOS,	23,	NT_STATUS_DATA_ERROR},
	{ERRDOS,	23,	NT_STATUS_CRC_ERROR},
	{ERRDOS,	ERRnomem,	NT_STATUS_SECTION_TOO_BIG},
	{ERRDOS,	ERRnoaccess,	NT_STATUS_PORT_CONNECTION_REFUSED},
	{ERRDOS,	ERRbadfid,	NT_STATUS_INVALID_PORT_HANDLE},
	{ERRDOS,	ERRbadshare,	NT_STATUS_SHARING_VIOLATION},
	{ERRHRD,	ERRgeneral,	NT_STATUS_QUOTA_EXCEEDED},
	{ERRDOS,	87,	NT_STATUS_INVALID_PAGE_PROTECTION},
	{ERRDOS,	288,	NT_STATUS_MUTANT_NOT_OWNED},
	{ERRDOS,	298,	NT_STATUS_SEMAPHORE_LIMIT_EXCEEDED},
	{ERRDOS,	87,	NT_STATUS_PORT_ALREADY_SET},
	{ERRDOS,	87,	NT_STATUS_SECTION_NOT_IMAGE},
	{ERRDOS,	156,	NT_STATUS_SUSPEND_COUNT_EXCEEDED},
	{ERRDOS,	ERRnoaccess,	NT_STATUS_THREAD_IS_TERMINATING},
	{ERRDOS,	87,	NT_STATUS_BAD_WORKING_SET_LIMIT},
	{ERRDOS,	87,	NT_STATUS_INCOMPATIBLE_FILE_MAP},
	{ERRDOS,	87,	NT_STATUS_SECTION_PROTECTION},
	{ERRDOS,	282,	NT_STATUS_EAS_NOT_SUPPORTED},
	{ERRDOS,	255,	NT_STATUS_EA_TOO_LARGE},
	{ERRHRD,	ERRgeneral,	NT_STATUS_NONEXISTENT_EA_ENTRY},
	{ERRHRD,	ERRgeneral,	NT_STATUS_NO_EAS_ON_FILE},
	{ERRHRD,	ERRgeneral,	NT_STATUS_EA_CORRUPT_ERROR},
	{ERRDOS,	ERRlock,	NT_STATUS_FILE_LOCK_CONFLICT},
	{ERRDOS,	ERRlock,	NT_STATUS_LOCK_NOT_GRANTED},
	{ERRDOS,	ERRnoaccess,	NT_STATUS_DELETE_PENDING},
	{ERRDOS,	ERRunsup,	NT_STATUS_CTL_FILE_NOT_SUPPORTED},
	{ERRHRD,	ERRgeneral,	NT_STATUS_UNKNOWN_REVISION},
	{ERRHRD,	ERRgeneral,	NT_STATUS_REVISION_MISMATCH},
	{ERRHRD,	ERRgeneral,	NT_STATUS_INVALID_OWNER},
	{ERRHRD,	ERRgeneral,	NT_STATUS_INVALID_PRIMARY_GROUP},
	{ERRHRD,	ERRgeneral,	NT_STATUS_NO_IMPERSONATION_TOKEN},
	{ERRHRD,	ERRgeneral,	NT_STATUS_CANT_DISABLE_MANDATORY},
	{ERRDOS,	2215,	NT_STATUS_NO_LOGON_SERVERS},
	{ERRHRD,	ERRgeneral,	NT_STATUS_NO_SUCH_LOGON_SESSION},
	{ERRHRD,	ERRgeneral,	NT_STATUS_NO_SUCH_PRIVILEGE},
	{ERRDOS,	ERRnoaccess,	NT_STATUS_PRIVILEGE_NOT_HELD},
	{ERRHRD,	ERRgeneral,	NT_STATUS_INVALID_ACCOUNT_NAME},
	{ERRHRD,	ERRgeneral,	NT_STATUS_USER_EXISTS},
/*	{ This NT error code was 'sqashed'
	 from NT_STATUS_NO_SUCH_USER to NT_STATUS_LOGON_FAILURE 
	 during the session setup }
*/
	{ERRDOS,	ERRnoaccess,	NT_STATUS_NO_SUCH_USER},
	{ERRHRD,	ERRgeneral,	NT_STATUS_GROUP_EXISTS},
	{ERRHRD,	ERRgeneral,	NT_STATUS_NO_SUCH_GROUP},
	{ERRHRD,	ERRgeneral,	NT_STATUS_MEMBER_IN_GROUP},
	{ERRHRD,	ERRgeneral,	NT_STATUS_MEMBER_NOT_IN_GROUP},
	{ERRHRD,	ERRgeneral,	NT_STATUS_LAST_ADMIN},
/*	{ This NT error code was 'sqashed'
	 from NT_STATUS_WRONG_PASSWORD to NT_STATUS_LOGON_FAILURE 
	 during the session setup }
*/
	{ERRSRV,	ERRbadpw,	NT_STATUS_WRONG_PASSWORD},
	{ERRHRD,	ERRgeneral,	NT_STATUS_ILL_FORMED_PASSWORD},
	{ERRHRD,	ERRgeneral,	NT_STATUS_PASSWORD_RESTRICTION},
	{ERRDOS,	ERRnoaccess,	NT_STATUS_LOGON_FAILURE},
	{ERRHRD,	ERRgeneral,	NT_STATUS_ACCOUNT_RESTRICTION},
	{ERRSRV,	2241,	NT_STATUS_INVALID_LOGON_HOURS},
	{ERRSRV,	2240,	NT_STATUS_INVALID_WORKSTATION},
	{ERRSRV,	2242,	NT_STATUS_PASSWORD_EXPIRED},
	{ERRSRV,	2239,	NT_STATUS_ACCOUNT_DISABLED},
	{ERRHRD,	ERRgeneral,	NT_STATUS_NONE_MAPPED},
	{ERRHRD,	ERRgeneral,	NT_STATUS_TOO_MANY_LUIDS_REQUESTED},
	{ERRHRD,	ERRgeneral,	NT_STATUS_LUIDS_EXHAUSTED},
	{ERRHRD,	ERRgeneral,	NT_STATUS_INVALID_SUB_AUTHORITY},
	{ERRHRD,	ERRgeneral,	NT_STATUS_INVALID_ACL},
	{ERRHRD,	ERRgeneral,	NT_STATUS_INVALID_SID},
	{ERRHRD,	ERRgeneral,	NT_STATUS_INVALID_SECURITY_DESCR},
	{ERRDOS,	127,	NT_STATUS_PROCEDURE_NOT_FOUND},
	{ERRDOS,	193,	NT_STATUS_INVALID_IMAGE_FORMAT},
	{ERRHRD,	ERRgeneral,	NT_STATUS_NO_TOKEN},
	{ERRHRD,	ERRgeneral,	NT_STATUS_BAD_INHERITANCE_ACL},
	{ERRDOS,	158,	NT_STATUS_RANGE_NOT_LOCKED},
	{ERRDOS,	112,	NT_STATUS_DISK_FULL},
	{ERRHRD,	ERRgeneral,	NT_STATUS_SERVER_DISABLED},
	{ERRHRD,	ERRgeneral,	NT_STATUS_SERVER_NOT_DISABLED},
	{ERRDOS,	68,	NT_STATUS_TOO_MANY_GUIDS_REQUESTED},
	{ERRDOS,	259,	NT_STATUS_GUIDS_EXHAUSTED},
	{ERRHRD,	ERRgeneral,	NT_STATUS_INVALID_ID_AUTHORITY},
	{ERRDOS,	259,	NT_STATUS_AGENTS_EXHAUSTED},
	{ERRDOS,	154,	NT_STATUS_INVALID_VOLUME_LABEL},
	{ERRDOS,	ERRres,	NT_STATUS_SECTION_NOT_EXTENDED},
	{ERRDOS,	487,	NT_STATUS_NOT_MAPPED_DATA},
	{ERRHRD,	ERRgeneral,	NT_STATUS_RESOURCE_DATA_NOT_FOUND},
	{ERRHRD,	ERRgeneral,	NT_STATUS_RESOURCE_TYPE_NOT_FOUND},
	{ERRHRD,	ERRgeneral,	NT_STATUS_RESOURCE_NAME_NOT_FOUND},
	{ERRHRD,	ERRgeneral,	NT_STATUS_ARRAY_BOUNDS_EXCEEDED},
	{ERRHRD,	ERRgeneral,	NT_STATUS_FLOAT_DENORMAL_OPERAND},
	{ERRHRD,	ERRgeneral,	NT_STATUS_FLOAT_DIVIDE_BY_ZERO},
	{ERRHRD,	ERRgeneral,	NT_STATUS_FLOAT_INEXACT_RESULT},
	{ERRHRD,	ERRgeneral,	NT_STATUS_FLOAT_INVALID_OPERATION},
	{ERRHRD,	ERRgeneral,	NT_STATUS_FLOAT_OVERFLOW},
	{ERRHRD,	ERRgeneral,	NT_STATUS_FLOAT_STACK_CHECK},
	{ERRHRD,	ERRgeneral,	NT_STATUS_FLOAT_UNDERFLOW},
	{ERRHRD,	ERRgeneral,	NT_STATUS_INTEGER_DIVIDE_BY_ZERO},
	{ERRDOS,	534,	NT_STATUS_INTEGER_OVERFLOW},
	{ERRHRD,	ERRgeneral,	NT_STATUS_PRIVILEGED_INSTRUCTION},
	{ERRDOS,	ERRnomem,	NT_STATUS_TOO_MANY_PAGING_FILES},
	{ERRHRD,	ERRgeneral,	NT_STATUS_FILE_INVALID},
	{ERRHRD,	ERRgeneral,	NT_STATUS_ALLOTTED_SPACE_EXCEEDED},
/*	{ This NT error code was 'sqashed'
	 from NT_STATUS_INSUFFICIENT_RESOURCES to NT_STATUS_INSUFF_SERVER_RESOURCES 
	 during the session setup }
*/
	{ERRDOS,	ERRnomem,	NT_STATUS_INSUFFICIENT_RESOURCES},
	{ERRDOS,	ERRbadpath,	NT_STATUS_DFS_EXIT_PATH_FOUND},
	{ERRDOS,	23,	NT_STATUS_DEVICE_DATA_ERROR},
	{ERRHRD,	ERRgeneral,	NT_STATUS_DEVICE_NOT_CONNECTED},
	{ERRDOS,	21,	NT_STATUS_DEVICE_POWER_FAILURE},
	{ERRDOS,	487,	NT_STATUS_FREE_VM_NOT_AT_BASE},
	{ERRDOS,	487,	NT_STATUS_MEMORY_NOT_ALLOCATED},
	{ERRHRD,	ERRgeneral,	NT_STATUS_WORKING_SET_QUOTA},
	{ERRDOS,	19,	NT_STATUS_MEDIA_WRITE_PROTECTED},
	{ERRDOS,	21,	NT_STATUS_DEVICE_NOT_READY},
	{ERRHRD,	ERRgeneral,	NT_STATUS_INVALID_GROUP_ATTRIBUTES},
	{ERRHRD,	ERRgeneral,	NT_STATUS_BAD_IMPERSONATION_LEVEL},
	{ERRHRD,	ERRgeneral,	NT_STATUS_CANT_OPEN_ANONYMOUS},
	{ERRHRD,	ERRgeneral,	NT_STATUS_BAD_VALIDATION_CLASS},
	{ERRHRD,	ERRgeneral,	NT_STATUS_BAD_TOKEN_TYPE},
	{ERRDOS,	87,	NT_STATUS_BAD_MASTER_BOOT_RECORD},
	{ERRHRD,	ERRgeneral,	NT_STATUS_INSTRUCTION_MISALIGNMENT},
	{ERRDOS,	ERRpipebusy,	NT_STATUS_INSTANCE_NOT_AVAILABLE},
	{ERRDOS,	ERRpipebusy,	NT_STATUS_PIPE_NOT_AVAILABLE},
	{ERRDOS,	ERRbadpipe,	NT_STATUS_INVALID_PIPE_STATE},
	{ERRDOS,	ERRpipebusy,	NT_STATUS_PIPE_BUSY},
	{ERRDOS,	ERRbadfunc,	NT_STATUS_ILLEGAL_FUNCTION},
	{ERRDOS,	ERRnotconnected,	NT_STATUS_PIPE_DISCONNECTED},
	{ERRDOS,	ERRpipeclosing,	NT_STATUS_PIPE_CLOSING},
	{ERRHRD,	ERRgeneral,	NT_STATUS_PIPE_CONNECTED},
	{ERRHRD,	ERRgeneral,	NT_STATUS_PIPE_LISTENING},
	{ERRDOS,	ERRbadpipe,	NT_STATUS_INVALID_READ_MODE},
	{ERRDOS,	121,	NT_STATUS_IO_TIMEOUT},
	{ERRDOS,	38,	NT_STATUS_FILE_FORCED_CLOSED},
	{ERRHRD,	ERRgeneral,	NT_STATUS_PROFILING_NOT_STARTED},
	{ERRHRD,	ERRgeneral,	NT_STATUS_PROFILING_NOT_STOPPED},
	{ERRHRD,	ERRgeneral,	NT_STATUS_COULD_NOT_INTERPRET},
	{ERRDOS,	ERRnoaccess,	NT_STATUS_FILE_IS_A_DIRECTORY},
	{ERRDOS,	ERRunsup,	NT_STATUS_NOT_SUPPORTED},
	{ERRDOS,	51,	NT_STATUS_REMOTE_NOT_LISTENING},
	{ERRDOS,	52,	NT_STATUS_DUPLICATE_NAME},
	{ERRDOS,	53,	NT_STATUS_BAD_NETWORK_PATH},
	{ERRDOS,	54,	NT_STATUS_NETWORK_BUSY},
	{ERRDOS,	55,	NT_STATUS_DEVICE_DOES_NOT_EXIST},
	{ERRDOS,	56,	NT_STATUS_TOO_MANY_COMMANDS},
	{ERRDOS,	57,	NT_STATUS_ADAPTER_HARDWARE_ERROR},
	{ERRDOS,	58,	NT_STATUS_INVALID_NETWORK_RESPONSE},
	{ERRDOS,	59,	NT_STATUS_UNEXPECTED_NETWORK_ERROR},
	{ERRDOS,	60,	NT_STATUS_BAD_REMOTE_ADAPTER},
	{ERRDOS,	61,	NT_STATUS_PRINT_QUEUE_FULL},
	{ERRDOS,	62,	NT_STATUS_NO_SPOOL_SPACE},
	{ERRDOS,	63,	NT_STATUS_PRINT_CANCELLED},
	{ERRDOS,	64,	NT_STATUS_NETWORK_NAME_DELETED},
	{ERRDOS,	65,	NT_STATUS_NETWORK_ACCESS_DENIED},
	{ERRDOS,	66,	NT_STATUS_BAD_DEVICE_TYPE},
	{ERRDOS,	ERRnosuchshare,	NT_STATUS_BAD_NETWORK_NAME},
	{ERRDOS,	68,	NT_STATUS_TOO_MANY_NAMES},
	{ERRDOS,	69,	NT_STATUS_TOO_MANY_SESSIONS},
	{ERRDOS,	70,	NT_STATUS_SHARING_PAUSED},
	{ERRDOS,	71,	NT_STATUS_REQUEST_NOT_ACCEPTED},
	{ERRDOS,	72,	NT_STATUS_REDIRECTOR_PAUSED},
	{ERRDOS,	88,	NT_STATUS_NET_WRITE_FAULT},
	{ERRHRD,	ERRgeneral,	NT_STATUS_PROFILING_AT_LIMIT},
	{ERRDOS,	ERRdiffdevice,	NT_STATUS_NOT_SAME_DEVICE},
	{ERRDOS,	ERRnoaccess,	NT_STATUS_FILE_RENAMED},
	{ERRDOS,	240,	NT_STATUS_VIRTUAL_CIRCUIT_CLOSED},
	{ERRHRD,	ERRgeneral,	NT_STATUS_NO_SECURITY_ON_OBJECT},
	{ERRHRD,	ERRgeneral,	NT_STATUS_CANT_WAIT},
	{ERRDOS,	ERRpipeclosing,	NT_STATUS_PIPE_EMPTY},
	{ERRHRD,	ERRgeneral,	NT_STATUS_CANT_ACCESS_DOMAIN_INFO},
	{ERRHRD,	ERRgeneral,	NT_STATUS_CANT_TERMINATE_SELF},
	{ERRHRD,	ERRgeneral,	NT_STATUS_INVALID_SERVER_STATE},
	{ERRHRD,	ERRgeneral,	NT_STATUS_INVALID_DOMAIN_STATE},
	{ERRHRD,	ERRgeneral,	NT_STATUS_INVALID_DOMAIN_ROLE},
	{ERRHRD,	ERRgeneral,	NT_STATUS_NO_SUCH_DOMAIN},
	{ERRHRD,	ERRgeneral,	NT_STATUS_DOMAIN_EXISTS},
	{ERRHRD,	ERRgeneral,	NT_STATUS_DOMAIN_LIMIT_EXCEEDED},
	{ERRDOS,	300,	NT_STATUS_OPLOCK_NOT_GRANTED},
	{ERRDOS,	301,	NT_STATUS_INVALID_OPLOCK_PROTOCOL},
	{ERRHRD,	ERRgeneral,	NT_STATUS_INTERNAL_DB_CORRUPTION},
	{ERRHRD,	ERRgeneral,	NT_STATUS_INTERNAL_ERROR},
	{ERRHRD,	ERRgeneral,	NT_STATUS_GENERIC_NOT_MAPPED},
	{ERRHRD,	ERRgeneral,	NT_STATUS_BAD_DESCRIPTOR_FORMAT},
	{ERRHRD,	ERRgeneral,	NT_STATUS_INVALID_USER_BUFFER},
	{ERRHRD,	ERRgeneral,	NT_STATUS_UNEXPECTED_IO_ERROR},
	{ERRHRD,	ERRgeneral,	NT_STATUS_UNEXPECTED_MM_CREATE_ERR},
	{ERRHRD,	ERRgeneral,	NT_STATUS_UNEXPECTED_MM_MAP_ERROR},
	{ERRHRD,	ERRgeneral,	NT_STATUS_UNEXPECTED_MM_EXTEND_ERR},
	{ERRHRD,	ERRgeneral,	NT_STATUS_NOT_LOGON_PROCESS},
	{ERRHRD,	ERRgeneral,	NT_STATUS_LOGON_SESSION_EXISTS},
	{ERRDOS,	87,	NT_STATUS_INVALID_PARAMETER_1},
	{ERRDOS,	87,	NT_STATUS_INVALID_PARAMETER_2},
	{ERRDOS,	87,	NT_STATUS_INVALID_PARAMETER_3},
	{ERRDOS,	87,	NT_STATUS_INVALID_PARAMETER_4},
	{ERRDOS,	87,	NT_STATUS_INVALID_PARAMETER_5},
	{ERRDOS,	87,	NT_STATUS_INVALID_PARAMETER_6},
	{ERRDOS,	87,	NT_STATUS_INVALID_PARAMETER_7},
	{ERRDOS,	87,	NT_STATUS_INVALID_PARAMETER_8},
	{ERRDOS,	87,	NT_STATUS_INVALID_PARAMETER_9},
	{ERRDOS,	87,	NT_STATUS_INVALID_PARAMETER_10},
	{ERRDOS,	87,	NT_STATUS_INVALID_PARAMETER_11},
	{ERRDOS,	87,	NT_STATUS_INVALID_PARAMETER_12},
	{ERRDOS,	ERRbadpath,	NT_STATUS_REDIRECTOR_NOT_STARTED},
	{ERRHRD,	ERRgeneral,	NT_STATUS_REDIRECTOR_STARTED},
	{ERRHRD,	ERRgeneral,	NT_STATUS_STACK_OVERFLOW},
	{ERRHRD,	ERRgeneral,	NT_STATUS_NO_SUCH_PACKAGE},
	{ERRHRD,	ERRgeneral,	NT_STATUS_BAD_FUNCTION_TABLE},
	{ERRDOS,	203,	NT_STATUS(0xc0000100)},
	{ERRDOS,	145,	NT_STATUS_DIRECTORY_NOT_EMPTY},
	{ERRHRD,	ERRgeneral,	NT_STATUS_FILE_CORRUPT_ERROR},
	{ERRDOS,	267,	NT_STATUS_NOT_A_DIRECTORY},
	{ERRHRD,	ERRgeneral,	NT_STATUS_BAD_LOGON_SESSION_STATE},
	{ERRHRD,	ERRgeneral,	NT_STATUS_LOGON_SESSION_COLLISION},
	{ERRDOS,	206,	NT_STATUS_NAME_TOO_LONG},
	{ERRDOS,	2401,	NT_STATUS_FILES_OPEN},
	{ERRDOS,	2404,	NT_STATUS_CONNECTION_IN_USE},
	{ERRHRD,	ERRgeneral,	NT_STATUS_MESSAGE_NOT_FOUND},
	{ERRDOS,	ERRnoaccess,	NT_STATUS_PROCESS_IS_TERMINATING},
	{ERRHRD,	ERRgeneral,	NT_STATUS_INVALID_LOGON_TYPE},
	{ERRHRD,	ERRgeneral,	NT_STATUS_NO_GUID_TRANSLATION},
	{ERRHRD,	ERRgeneral,	NT_STATUS_CANNOT_IMPERSONATE},
	{ERRHRD,	ERRgeneral,	NT_STATUS_IMAGE_ALREADY_LOADED},
	{ERRHRD,	ERRgeneral,	NT_STATUS_ABIOS_NOT_PRESENT},
	{ERRHRD,	ERRgeneral,	NT_STATUS_ABIOS_LID_NOT_EXIST},
	{ERRHRD,	ERRgeneral,	NT_STATUS_ABIOS_LID_ALREADY_OWNED},
	{ERRHRD,	ERRgeneral,	NT_STATUS_ABIOS_NOT_LID_OWNER},
	{ERRHRD,	ERRgeneral,	NT_STATUS_ABIOS_INVALID_COMMAND},
	{ERRHRD,	ERRgeneral,	NT_STATUS_ABIOS_INVALID_LID},
	{ERRHRD,	ERRgeneral,	NT_STATUS_ABIOS_SELECTOR_NOT_AVAILABLE},
	{ERRHRD,	ERRgeneral,	NT_STATUS_ABIOS_INVALID_SELECTOR},
	{ERRHRD,	ERRgeneral,	NT_STATUS_NO_LDT},
	{ERRHRD,	ERRgeneral,	NT_STATUS_INVALID_LDT_SIZE},
	{ERRHRD,	ERRgeneral,	NT_STATUS_INVALID_LDT_OFFSET},
	{ERRHRD,	ERRgeneral,	NT_STATUS_INVALID_LDT_DESCRIPTOR},
	{ERRDOS,	193,	NT_STATUS_INVALID_IMAGE_NE_FORMAT},
	{ERRHRD,	ERRgeneral,	NT_STATUS_RXACT_INVALID_STATE},
	{ERRHRD,	ERRgeneral,	NT_STATUS_RXACT_COMMIT_FAILURE},
	{ERRHRD,	ERRgeneral,	NT_STATUS_MAPPED_FILE_SIZE_ZERO},
	{ERRDOS,	ERRnofids,	NT_STATUS_TOO_MANY_OPENED_FILES},
	{ERRHRD,	ERRgeneral,	NT_STATUS_CANCELLED},
	{ERRDOS,	ERRnoaccess,	NT_STATUS_CANNOT_DELETE},
	{ERRHRD,	ERRgeneral,	NT_STATUS_INVALID_COMPUTER_NAME},
	{ERRDOS,	ERRnoaccess,	NT_STATUS_FILE_DELETED},
	{ERRHRD,	ERRgeneral,	NT_STATUS_SPECIAL_ACCOUNT},
	{ERRHRD,	ERRgeneral,	NT_STATUS_SPECIAL_GROUP},
	{ERRHRD,	ERRgeneral,	NT_STATUS_SPECIAL_USER},
	{ERRHRD,	ERRgeneral,	NT_STATUS_MEMBERS_PRIMARY_GROUP},
	{ERRDOS,	ERRbadfid,	NT_STATUS_FILE_CLOSED},
	{ERRHRD,	ERRgeneral,	NT_STATUS_TOO_MANY_THREADS},
	{ERRHRD,	ERRgeneral,	NT_STATUS_THREAD_NOT_IN_PROCESS},
	{ERRHRD,	ERRgeneral,	NT_STATUS_TOKEN_ALREADY_IN_USE},
	{ERRHRD,	ERRgeneral,	NT_STATUS_PAGEFILE_QUOTA_EXCEEDED},
	{ERRHRD,	ERRgeneral,	NT_STATUS_COMMITMENT_LIMIT},
	{ERRDOS,	193,	NT_STATUS_INVALID_IMAGE_LE_FORMAT},
	{ERRDOS,	193,	NT_STATUS_INVALID_IMAGE_NOT_MZ},
	{ERRDOS,	193,	NT_STATUS_INVALID_IMAGE_PROTECT},
	{ERRDOS,	193,	NT_STATUS_INVALID_IMAGE_WIN_16},
	{ERRHRD,	ERRgeneral,	NT_STATUS_LOGON_SERVER_CONFLICT},
	{ERRHRD,	ERRgeneral,	NT_STATUS_TIME_DIFFERENCE_AT_DC},
	{ERRHRD,	ERRgeneral,	NT_STATUS_SYNCHRONIZATION_REQUIRED},
	{ERRDOS,	126,	NT_STATUS_DLL_NOT_FOUND},
	{ERRHRD,	ERRgeneral,	NT_STATUS_OPEN_FAILED},
	{ERRHRD,	ERRgeneral,	NT_STATUS_IO_PRIVILEGE_FAILED},
	{ERRDOS,	182,	NT_STATUS_ORDINAL_NOT_FOUND},
	{ERRDOS,	127,	NT_STATUS_ENTRYPOINT_NOT_FOUND},
	{ERRHRD,	ERRgeneral,	NT_STATUS_CONTROL_C_EXIT},
	{ERRDOS,	64,	NT_STATUS_LOCAL_DISCONNECT},
	{ERRDOS,	64,	NT_STATUS_REMOTE_DISCONNECT},
	{ERRDOS,	51,	NT_STATUS_REMOTE_RESOURCES},
	{ERRDOS,	59,	NT_STATUS_LINK_FAILED},
	{ERRDOS,	59,	NT_STATUS_LINK_TIMEOUT},
	{ERRDOS,	59,	NT_STATUS_INVALID_CONNECTION},
	{ERRDOS,	59,	NT_STATUS_INVALID_ADDRESS},
	{ERRHRD,	ERRgeneral,	NT_STATUS_DLL_INIT_FAILED},
	{ERRHRD,	ERRgeneral,	NT_STATUS_MISSING_SYSTEMFILE},
	{ERRHRD,	ERRgeneral,	NT_STATUS_UNHANDLED_EXCEPTION},
	{ERRHRD,	ERRgeneral,	NT_STATUS_APP_INIT_FAILURE},
	{ERRHRD,	ERRgeneral,	NT_STATUS_PAGEFILE_CREATE_FAILED},
	{ERRHRD,	ERRgeneral,	NT_STATUS_NO_PAGEFILE},
	{ERRDOS,	124,	NT_STATUS_INVALID_LEVEL},
	{ERRDOS,	86,	NT_STATUS_WRONG_PASSWORD_CORE},
	{ERRHRD,	ERRgeneral,	NT_STATUS_ILLEGAL_FLOAT_CONTEXT},
	{ERRDOS,	109,	NT_STATUS_PIPE_BROKEN},
	{ERRHRD,	ERRgeneral,	NT_STATUS_REGISTRY_CORRUPT},
	{ERRHRD,	ERRgeneral,	NT_STATUS_REGISTRY_IO_FAILED},
	{ERRHRD,	ERRgeneral,	NT_STATUS_NO_EVENT_PAIR},
	{ERRHRD,	ERRgeneral,	NT_STATUS_UNRECOGNIZED_VOLUME},
	{ERRHRD,	ERRgeneral,	NT_STATUS_SERIAL_NO_DEVICE_INITED},
	{ERRHRD,	ERRgeneral,	NT_STATUS_NO_SUCH_ALIAS},
	{ERRHRD,	ERRgeneral,	NT_STATUS_MEMBER_NOT_IN_ALIAS},
	{ERRHRD,	ERRgeneral,	NT_STATUS_MEMBER_IN_ALIAS},
	{ERRHRD,	ERRgeneral,	NT_STATUS_ALIAS_EXISTS},
	{ERRHRD,	ERRgeneral,	NT_STATUS_LOGON_NOT_GRANTED},
	{ERRHRD,	ERRgeneral,	NT_STATUS_TOO_MANY_SECRETS},
	{ERRHRD,	ERRgeneral,	NT_STATUS_SECRET_TOO_LONG},
	{ERRHRD,	ERRgeneral,	NT_STATUS_INTERNAL_DB_ERROR},
	{ERRHRD,	ERRgeneral,	NT_STATUS_FULLSCREEN_MODE},
	{ERRHRD,	ERRgeneral,	NT_STATUS_TOO_MANY_CONTEXT_IDS},
	{ERRDOS,	ERRnoaccess,	NT_STATUS_LOGON_TYPE_NOT_GRANTED},
	{ERRHRD,	ERRgeneral,	NT_STATUS_NOT_REGISTRY_FILE},
	{ERRHRD,	ERRgeneral,	NT_STATUS_NT_CROSS_ENCRYPTION_REQUIRED},
	{ERRHRD,	ERRgeneral,	NT_STATUS_DOMAIN_CTRLR_CONFIG_ERROR},
	{ERRHRD,	ERRgeneral,	NT_STATUS_FT_MISSING_MEMBER},
	{ERRHRD,	ERRgeneral,	NT_STATUS_ILL_FORMED_SERVICE_ENTRY},
	{ERRHRD,	ERRgeneral,	NT_STATUS_ILLEGAL_CHARACTER},
	{ERRHRD,	ERRgeneral,	NT_STATUS_UNMAPPABLE_CHARACTER},
	{ERRHRD,	ERRgeneral,	NT_STATUS_UNDEFINED_CHARACTER},
	{ERRHRD,	ERRgeneral,	NT_STATUS_FLOPPY_VOLUME},
	{ERRHRD,	ERRgeneral,	NT_STATUS_FLOPPY_ID_MARK_NOT_FOUND},
	{ERRHRD,	ERRgeneral,	NT_STATUS_FLOPPY_WRONG_CYLINDER},
	{ERRHRD,	ERRgeneral,	NT_STATUS_FLOPPY_UNKNOWN_ERROR},
	{ERRHRD,	ERRgeneral,	NT_STATUS_FLOPPY_BAD_REGISTERS},
	{ERRHRD,	ERRgeneral,	NT_STATUS_DISK_RECALIBRATE_FAILED},
	{ERRHRD,	ERRgeneral,	NT_STATUS_DISK_OPERATION_FAILED},
	{ERRHRD,	ERRgeneral,	NT_STATUS_DISK_RESET_FAILED},
	{ERRHRD,	ERRgeneral,	NT_STATUS_SHARED_IRQ_BUSY},
	{ERRHRD,	ERRgeneral,	NT_STATUS_FT_ORPHANING},
	{ERRHRD,	ERRgeneral,	NT_STATUS(0xc000016e)},
	{ERRHRD,	ERRgeneral,	NT_STATUS(0xc000016f)},
	{ERRHRD,	ERRgeneral,	NT_STATUS(0xc0000170)},
	{ERRHRD,	ERRgeneral,	NT_STATUS(0xc0000171)},
	{ERRHRD,	ERRgeneral,	NT_STATUS_PARTITION_FAILURE},
	{ERRHRD,	ERRgeneral,	NT_STATUS_INVALID_BLOCK_LENGTH},
	{ERRHRD,	ERRgeneral,	NT_STATUS_DEVICE_NOT_PARTITIONED},
	{ERRHRD,	ERRgeneral,	NT_STATUS_UNABLE_TO_LOCK_MEDIA},
	{ERRHRD,	ERRgeneral,	NT_STATUS_UNABLE_TO_UNLOAD_MEDIA},
	{ERRHRD,	ERRgeneral,	NT_STATUS_EOM_OVERFLOW},
	{ERRHRD,	ERRgeneral,	NT_STATUS_NO_MEDIA},
	{ERRHRD,	ERRgeneral,	NT_STATUS(0xc0000179)},
	{ERRHRD,	ERRgeneral,	NT_STATUS_NO_SUCH_MEMBER},
	{ERRHRD,	ERRgeneral,	NT_STATUS_INVALID_MEMBER},
	{ERRHRD,	ERRgeneral,	NT_STATUS_KEY_DELETED},
	{ERRHRD,	ERRgeneral,	NT_STATUS_NO_LOG_SPACE},
	{ERRHRD,	ERRgeneral,	NT_STATUS_TOO_MANY_SIDS},
	{ERRHRD,	ERRgeneral,	NT_STATUS_LM_CROSS_ENCRYPTION_REQUIRED},
	{ERRHRD,	ERRgeneral,	NT_STATUS_KEY_HAS_CHILDREN},
	{ERRHRD,	ERRgeneral,	NT_STATUS_CHILD_MUST_BE_VOLATILE},
	{ERRDOS,	87,	NT_STATUS_DEVICE_CONFIGURATION_ERROR},
	{ERRHRD,	ERRgeneral,	NT_STATUS_DRIVER_INTERNAL_ERROR},
	{ERRDOS,	22,	NT_STATUS_INVALID_DEVICE_STATE},
	{ERRHRD,	ERRgeneral,	NT_STATUS_IO_DEVICE_ERROR},
	{ERRHRD,	ERRgeneral,	NT_STATUS_DEVICE_PROTOCOL_ERROR},
	{ERRHRD,	ERRgeneral,	NT_STATUS_BACKUP_CONTROLLER},
	{ERRHRD,	ERRgeneral,	NT_STATUS_LOG_FILE_FULL},
	{ERRDOS,	19,	NT_STATUS_TOO_LATE},
	{ERRDOS,	ERRnoaccess,	NT_STATUS_NO_TRUST_LSA_SECRET},
/*	{ This NT error code was 'sqashed'
	 from NT_STATUS_NO_TRUST_SAM_ACCOUNT to NT_STATUS_TRUSTED_RELATIONSHIP_FAILURE 
	 during the session setup }
*/
	{ERRDOS,	ERRnoaccess,	NT_STATUS_NO_TRUST_SAM_ACCOUNT},
	{ERRDOS,	ERRnoaccess,	NT_STATUS_TRUSTED_DOMAIN_FAILURE},
	{ERRDOS,	ERRnoaccess,	NT_STATUS_TRUSTED_RELATIONSHIP_FAILURE},
	{ERRHRD,	ERRgeneral,	NT_STATUS_EVENTLOG_FILE_CORRUPT},
	{ERRHRD,	ERRgeneral,	NT_STATUS_EVENTLOG_CANT_START},
	{ERRDOS,	ERRnoaccess,	NT_STATUS_TRUST_FAILURE},
	{ERRHRD,	ERRgeneral,	NT_STATUS_MUTANT_LIMIT_EXCEEDED},
	{ERRDOS,	ERRinvgroup,	NT_STATUS_NETLOGON_NOT_STARTED},
	{ERRSRV,	2239,	NT_STATUS_ACCOUNT_EXPIRED},
	{ERRHRD,	ERRgeneral,	NT_STATUS_POSSIBLE_DEADLOCK},
	{ERRHRD,	ERRgeneral,	NT_STATUS_NETWORK_CREDENTIAL_CONFLICT},
	{ERRHRD,	ERRgeneral,	NT_STATUS_REMOTE_SESSION_LIMIT},
	{ERRHRD,	ERRgeneral,	NT_STATUS_EVENTLOG_FILE_CHANGED},
	{ERRDOS,	ERRnoaccess,	NT_STATUS_NOLOGON_INTERDOMAIN_TRUST_ACCOUNT},
	{ERRDOS,	ERRnoaccess,	NT_STATUS_NOLOGON_WORKSTATION_TRUST_ACCOUNT},
	{ERRDOS,	ERRnoaccess,	NT_STATUS_NOLOGON_SERVER_TRUST_ACCOUNT},
/*	{ This NT error code was 'sqashed'
	 from NT_STATUS_DOMAIN_TRUST_INCONSISTENT to NT_STATUS_LOGON_FAILURE 
	 during the session setup }
*/
	{ERRDOS,	ERRnoaccess,	NT_STATUS_DOMAIN_TRUST_INCONSISTENT},
	{ERRHRD,	ERRgeneral,	NT_STATUS_FS_DRIVER_REQUIRED},
	{ERRHRD,	ERRgeneral,	NT_STATUS_NO_USER_SESSION_KEY},
	{ERRDOS,	59,	NT_STATUS_USER_SESSION_DELETED},
	{ERRHRD,	ERRgeneral,	NT_STATUS_RESOURCE_LANG_NOT_FOUND},
	{ERRDOS,	ERRnomem,	NT_STATUS_INSUFF_SERVER_RESOURCES},
	{ERRHRD,	ERRgeneral,	NT_STATUS_INVALID_BUFFER_SIZE},
	{ERRHRD,	ERRgeneral,	NT_STATUS_INVALID_ADDRESS_COMPONENT},
	{ERRHRD,	ERRgeneral,	NT_STATUS_INVALID_ADDRESS_WILDCARD},
	{ERRDOS,	68,	NT_STATUS_TOO_MANY_ADDRESSES},
	{ERRDOS,	52,	NT_STATUS_ADDRESS_ALREADY_EXISTS},
	{ERRDOS,	64,	NT_STATUS_ADDRESS_CLOSED},
	{ERRDOS,	64,	NT_STATUS_CONNECTION_DISCONNECTED},
	{ERRDOS,	64,	NT_STATUS_CONNECTION_RESET},
	{ERRDOS,	68,	NT_STATUS_TOO_MANY_NODES},
	{ERRDOS,	59,	NT_STATUS_TRANSACTION_ABORTED},
	{ERRDOS,	59,	NT_STATUS_TRANSACTION_TIMED_OUT},
	{ERRDOS,	59,	NT_STATUS_TRANSACTION_NO_RELEASE},
	{ERRDOS,	59,	NT_STATUS_TRANSACTION_NO_MATCH},
	{ERRDOS,	59,	NT_STATUS_TRANSACTION_RESPONDED},
	{ERRDOS,	59,	NT_STATUS_TRANSACTION_INVALID_ID},
	{ERRDOS,	59,	NT_STATUS_TRANSACTION_INVALID_TYPE},
	{ERRDOS,	ERRunsup,	NT_STATUS_NOT_SERVER_SESSION},
	{ERRDOS,	ERRunsup,	NT_STATUS_NOT_CLIENT_SESSION},
	{ERRHRD,	ERRgeneral,	NT_STATUS_CANNOT_LOAD_REGISTRY_FILE},
	{ERRHRD,	ERRgeneral,	NT_STATUS_DEBUG_ATTACH_FAILED},
	{ERRHRD,	ERRgeneral,	NT_STATUS_SYSTEM_PROCESS_TERMINATED},
	{ERRHRD,	ERRgeneral,	NT_STATUS_DATA_NOT_ACCEPTED},
	{ERRHRD,	ERRgeneral,	NT_STATUS_NO_BROWSER_SERVERS_FOUND},
	{ERRHRD,	ERRgeneral,	NT_STATUS_VDM_HARD_ERROR},
	{ERRHRD,	ERRgeneral,	NT_STATUS_DRIVER_CANCEL_TIMEOUT},
	{ERRHRD,	ERRgeneral,	NT_STATUS_REPLY_MESSAGE_MISMATCH},
	{ERRHRD,	ERRgeneral,	NT_STATUS_MAPPED_ALIGNMENT},
	{ERRDOS,	193,	NT_STATUS_IMAGE_CHECKSUM_MISMATCH},
	{ERRHRD,	ERRgeneral,	NT_STATUS_LOST_WRITEBEHIND_DATA},
	{ERRHRD,	ERRgeneral,	NT_STATUS_CLIENT_SERVER_PARAMETERS_INVALID},
	{ERRSRV,	2242,	NT_STATUS_PASSWORD_MUST_CHANGE},
	{ERRHRD,	ERRgeneral,	NT_STATUS_NOT_FOUND},
	{ERRHRD,	ERRgeneral,	NT_STATUS_NOT_TINY_STREAM},
	{ERRHRD,	ERRgeneral,	NT_STATUS_RECOVERY_FAILURE},
	{ERRHRD,	ERRgeneral,	NT_STATUS_STACK_OVERFLOW_READ},
	{ERRHRD,	ERRgeneral,	NT_STATUS_FAIL_CHECK},
	{ERRHRD,	ERRgeneral,	NT_STATUS_DUPLICATE_OBJECTID},
	{ERRHRD,	ERRgeneral,	NT_STATUS_OBJECTID_EXISTS},
	{ERRHRD,	ERRgeneral,	NT_STATUS_CONVERT_TO_LARGE},
	{ERRHRD,	ERRgeneral,	NT_STATUS_RETRY},
	{ERRHRD,	ERRgeneral,	NT_STATUS_FOUND_OUT_OF_SCOPE},
	{ERRHRD,	ERRgeneral,	NT_STATUS_ALLOCATE_BUCKET},
	{ERRHRD,	ERRgeneral,	NT_STATUS_PROPSET_NOT_FOUND},
	{ERRHRD,	ERRgeneral,	NT_STATUS_MARSHALL_OVERFLOW},
	{ERRHRD,	ERRgeneral,	NT_STATUS_INVALID_VARIANT},
	{ERRHRD,	ERRgeneral,	NT_STATUS_DOMAIN_CONTROLLER_NOT_FOUND},
	{ERRDOS,	ERRnoaccess,	NT_STATUS_ACCOUNT_LOCKED_OUT},
	{ERRDOS,	ERRbadfid,	NT_STATUS_HANDLE_NOT_CLOSABLE},
	{ERRHRD,	ERRgeneral,	NT_STATUS_CONNECTION_REFUSED},
	{ERRHRD,	ERRgeneral,	NT_STATUS_GRACEFUL_DISCONNECT},
	{ERRHRD,	ERRgeneral,	NT_STATUS_ADDRESS_ALREADY_ASSOCIATED},
	{ERRHRD,	ERRgeneral,	NT_STATUS_ADDRESS_NOT_ASSOCIATED},
	{ERRHRD,	ERRgeneral,	NT_STATUS_CONNECTION_INVALID},
	{ERRHRD,	ERRgeneral,	NT_STATUS_CONNECTION_ACTIVE},
	{ERRHRD,	ERRgeneral,	NT_STATUS_NETWORK_UNREACHABLE},
	{ERRHRD,	ERRgeneral,	NT_STATUS_HOST_UNREACHABLE},
	{ERRHRD,	ERRgeneral,	NT_STATUS_PROTOCOL_UNREACHABLE},
	{ERRHRD,	ERRgeneral,	NT_STATUS_PORT_UNREACHABLE},
	{ERRHRD,	ERRgeneral,	NT_STATUS_REQUEST_ABORTED},
	{ERRHRD,	ERRgeneral,	NT_STATUS_CONNECTION_ABORTED},
	{ERRHRD,	ERRgeneral,	NT_STATUS_BAD_COMPRESSION_BUFFER},
	{ERRHRD,	ERRgeneral,	NT_STATUS_USER_MAPPED_FILE},
	{ERRHRD,	ERRgeneral,	NT_STATUS_AUDIT_FAILED},
	{ERRHRD,	ERRgeneral,	NT_STATUS_TIMER_RESOLUTION_NOT_SET},
	{ERRHRD,	ERRgeneral,	NT_STATUS_CONNECTION_COUNT_LIMIT},
	{ERRHRD,	ERRgeneral,	NT_STATUS_LOGIN_TIME_RESTRICTION},
	{ERRHRD,	ERRgeneral,	NT_STATUS_LOGIN_WKSTA_RESTRICTION},
	{ERRDOS,	193,	NT_STATUS_IMAGE_MP_UP_MISMATCH},
	{ERRHRD,	ERRgeneral,	NT_STATUS(0xc000024a)},
	{ERRHRD,	ERRgeneral,	NT_STATUS(0xc000024b)},
	{ERRHRD,	ERRgeneral,	NT_STATUS(0xc000024c)},
	{ERRHRD,	ERRgeneral,	NT_STATUS(0xc000024d)},
	{ERRHRD,	ERRgeneral,	NT_STATUS(0xc000024e)},
	{ERRHRD,	ERRgeneral,	NT_STATUS(0xc000024f)},
	{ERRHRD,	ERRgeneral,	NT_STATUS_INSUFFICIENT_LOGON_INFO},
	{ERRHRD,	ERRgeneral,	NT_STATUS_BAD_DLL_ENTRYPOINT},
	{ERRHRD,	ERRgeneral,	NT_STATUS_BAD_SERVICE_ENTRYPOINT},
	{ERRHRD,	ERRgeneral,	NT_STATUS_LPC_REPLY_LOST},
	{ERRHRD,	ERRgeneral,	NT_STATUS_IP_ADDRESS_CONFLICT1},
	{ERRHRD,	ERRgeneral,	NT_STATUS_IP_ADDRESS_CONFLICT2},
	{ERRHRD,	ERRgeneral,	NT_STATUS_REGISTRY_QUOTA_LIMIT},
	{ERRSRV,	ERRbadtype,	NT_STATUS_PATH_NOT_COVERED},
	{ERRHRD,	ERRgeneral,	NT_STATUS_NO_CALLBACK_ACTIVE},
	{ERRHRD,	ERRgeneral,	NT_STATUS_LICENSE_QUOTA_EXCEEDED},
	{ERRHRD,	ERRgeneral,	NT_STATUS_PWD_TOO_SHORT},
	{ERRHRD,	ERRgeneral,	NT_STATUS_PWD_TOO_RECENT},
	{ERRHRD,	ERRgeneral,	NT_STATUS_PWD_HISTORY_CONFLICT},
	{ERRHRD,	ERRgeneral,	NT_STATUS(0xc000025d)},
	{ERRHRD,	ERRgeneral,	NT_STATUS_PLUGPLAY_NO_DEVICE},
	{ERRHRD,	ERRgeneral,	NT_STATUS_UNSUPPORTED_COMPRESSION},
	{ERRHRD,	ERRgeneral,	NT_STATUS_INVALID_HW_PROFILE},
	{ERRHRD,	ERRgeneral,	NT_STATUS_INVALID_PLUGPLAY_DEVICE_PATH},
	{ERRDOS,	182,	NT_STATUS_DRIVER_ORDINAL_NOT_FOUND},
	{ERRDOS,	127,	NT_STATUS_DRIVER_ENTRYPOINT_NOT_FOUND},
	{ERRDOS,	288,	NT_STATUS_RESOURCE_NOT_OWNED},
	{ERRHRD,	ERRgeneral,	NT_STATUS_TOO_MANY_LINKS},
	{ERRHRD,	ERRgeneral,	NT_STATUS_QUOTA_LIST_INCONSISTENT},
	{ERRHRD,	ERRgeneral,	NT_STATUS_FILE_IS_OFFLINE},
	{ERRDOS,	21,	NT_STATUS(0xc000026e)},
	{ERRDOS,	161,	NT_STATUS(0xc0000281)},
	{ERRDOS,	ERRnoaccess,	NT_STATUS(0xc000028a)},
	{ERRDOS,	ERRnoaccess,	NT_STATUS(0xc000028b)},
	{ERRHRD,	ERRgeneral,	NT_STATUS(0xc000028c)},
	{ERRDOS,	ERRnoaccess,	NT_STATUS(0xc000028d)},
	{ERRDOS,	ERRnoaccess,	NT_STATUS(0xc000028e)},
	{ERRDOS,	ERRnoaccess,	NT_STATUS(0xc000028f)},
	{ERRDOS,	ERRnoaccess,	NT_STATUS(0xc0000290)},
	{ERRDOS,	ERRbadfunc,	NT_STATUS(0xc000029c)},
};

/****************************************************************************
  create an error packet from errno
****************************************************************************/
int unix_error_packet(char *outbuf,int def_class,uint32 def_code,int line)
{
	int eclass=def_class;
	int ecode=def_code;
	NTSTATUS ntstatus = NT_STATUS_OK;
	int i=0;

	if (unix_ERR_class != SMB_SUCCESS) {
		eclass = unix_ERR_class;
		ecode = unix_ERR_code;
		ntstatus = unix_ERR_ntstatus;
		unix_ERR_class = SMB_SUCCESS;
		unix_ERR_code = 0;
		unix_ERR_ntstatus = NT_STATUS_OK;
	} else {
		while (unix_dos_nt_errmap[i].dos_class != 0) {
			if (unix_dos_nt_errmap[i].unix_error == errno) {
				eclass = unix_dos_nt_errmap[i].dos_class;
				ecode = unix_dos_nt_errmap[i].dos_code;
				ntstatus = unix_dos_nt_errmap[i].nt_error;
				break;
			}
			i++;
		}
	}

	return error_packet(outbuf,ntstatus,eclass,ecode,line);
}

NTSTATUS dos_to_ntstatus(uint8 eclass, uint32 ecode)
{
	int i;
	if (eclass == 0 && ecode == 0) return NT_STATUS_OK;
	for (i=0; NT_STATUS_V(dos_to_ntstatus_map[i].ntstatus); i++) {
		if (eclass == dos_to_ntstatus_map[i].dos_class &&
		    ecode == dos_to_ntstatus_map[i].dos_code) {
			return dos_to_ntstatus_map[i].ntstatus;
		}
	}
	return NT_STATUS_UNSUCCESSFUL;
}

NTSTATUS map_nt_error_from_unix(int unix_error)
{
	int i = 0;

	if (unix_error == 0)
		return NT_STATUS_OK;

	/* Look through list */
	while(unix_dos_nt_errmap[i].unix_error != 0) {
		if (unix_dos_nt_errmap[i].unix_error == unix_error)
			return unix_dos_nt_errmap[i].nt_error;
		i++;
	}

	/* Default return */
	return NT_STATUS_ACCESS_DENIED;
}


void ntstatus_to_dos(NTSTATUS ntstatus, int *eclass, uint32 *ecode)
{
	int i;
	if (NT_STATUS_IS_OK(ntstatus)) {
		*eclass = 0;
		*ecode = 0;
		return;
	}
	for (i=0; NT_STATUS_V(ntstatus_to_dos_map[i].ntstatus); i++) {
		if (NT_STATUS_V(ntstatus) == 
		    NT_STATUS_V(ntstatus_to_dos_map[i].ntstatus)) {
			*eclass = ntstatus_to_dos_map[i].dos_class;
			*ecode = ntstatus_to_dos_map[i].dos_code;
			return;
		}
	}
	*eclass = ERRHRD;
	*ecode = ERRgeneral;
}

/****************************************************************************
  WE NOW SUPPORT NT ERROR STATUS:)
****************************************************************************/
int error_packet(char *outbuf,NTSTATUS ntstatus,int eclass,uint32 ecode,int line)
{
  int outsize = set_message(outbuf,0,0,True);

  if (errno != 0)
	DEBUG(3,("error string = %s\n",strerror(errno)));

  if (((SVAL(outbuf,smb_flg2) & FLAGS2_32_BIT_ERROR_CODES)) && (global_client_caps & CAP_STATUS32)) {
  	if (NT_STATUS_V(ntstatus) == 0 && eclass)
		ntstatus = dos_to_ntstatus(eclass, ecode);
	SIVAL(outbuf,smb_rcls,NT_STATUS_V(ntstatus));
	SSVAL(outbuf,smb_flg2, SVAL(outbuf,smb_flg2)|FLAGS2_32_BIT_ERROR_CODES);
	DEBUG(3, ("error packet at %d cmd=%d (%s)\n",
			line,
			(int)CVAL(outbuf,smb_com),
			smb_fn_name(CVAL(outbuf,smb_com))));
		
	return outsize;
  }

  if (eclass == 0 && NT_STATUS_V(ntstatus))
	ntstatus_to_dos(ntstatus, &eclass, &ecode);

  SSVAL(outbuf,smb_flg2, SVAL(outbuf,smb_flg2)&~FLAGS2_32_BIT_ERROR_CODES);
  SSVAL(outbuf,smb_rcls,eclass);
  SSVAL(outbuf,smb_err,ecode);  

  DEBUG(3,("error packet at %d cmd=%d (%s) eclass=%d ecode=%d\n",
		  line,
		  (int)CVAL(outbuf,smb_com),
		  smb_fn_name(CVAL(outbuf,smb_com)),
		  eclass,
		  ecode));

  return outsize;
}


/****************************************************************************
this prevents zombie child processes
****************************************************************************/
static void sig_cld(int signum)
{
	DEBUG(0,("get SIGCLD, clear child process!\n"));
	
	while (waitpid((pid_t)-1,(int *)NULL, WNOHANG) > 0)
		;
}

/****************************************************************************
  open the socket communication
****************************************************************************/
static BOOL open_sockets_inetd(void)
{
	extern int Client;

	/* Started from inetd. fd 0 is the socket. */
	/* We will abort gracefully when the client or remote system 
	   goes away */
	Client = dup(0);
	
	/* close our standard file descriptors */
	close_low_fds();
	
	set_socket_options(Client,"SO_KEEPALIVE");
	set_socket_options(Client,user_socket_options);

	return True;
}


static BOOL open_sockets(BOOL is_daemon,int *port)
{
	extern int Client;
	int num_interfaces = iface_count();
	int fd_listenset[FD_SETSIZE];
	fd_set listen_set;
	int s;
	int i, j;
	int maxfd, num_sockets;
	maxfd = 0;	
	num_sockets = 0;

	if (!is_daemon) {
		return open_sockets_inetd();
	}

		
#ifdef HAVE_ATEXIT
	{
		static int atexit_set;
		if(atexit_set == 0) {
			atexit_set=1;
			atexit(killkids);
		}
	}
#endif

	/* Stop zombies */
	CatchSignal(SIGCLD, SIGNAL_CAST sig_cld);
		
		
	FD_ZERO(&listen_set);

	if(lp_interfaces() && lp_bind_interfaces_only()) {
		/* We have been given an interfaces line, and been 
		   told to only bind to those interfaces. Create a
		   socket per interface and bind to only these.
		*/
		
		if(num_interfaces > FD_SETSIZE) {
			DEBUG(0,("open_sockets: Too many interfaces specified to bind to. Number was %d \
max can be %d\n", 
				 num_interfaces, FD_SETSIZE));
			return False;
		}
		
		/* Now open a listen socket for each of the
		   interfaces. */
		for(i = 0; i < num_interfaces; i++) {
			struct in_addr *ifip = iface_n_ip(i);
			
			if(ifip == NULL) {
				DEBUG(0,("open_sockets: interface %d has NULL IP address !\n", i));
				continue;
			}

			for(j=0;j<DEFAULT_PORT_NUM;j++){
				if(port[j] == 0)	//user defined case
					continue;
				
				s = open_socket_in(SOCK_STREAM, port[j], 0, ifip->s_addr);
				if(s == -1)
					return False;
			
			/* ready to listen */
				set_socket_options(s,"SO_KEEPALIVE"); 
				set_socket_options(s,user_socket_options);

				set_blocking(s,False); 
			
				if (listen(s, 50) == -1) {
					DEBUG(0,("listen: %s\n",strerror(errno)));
					close(s);
					return False;
				}

				fd_listenset[num_sockets] = s;
				FD_SET(s,&listen_set);
				maxfd = MAX( maxfd, s);
				
				num_sockets++;
				if (num_sockets >= FD_SETSIZE) {
					DEBUG(0,("open_sockets_smbd: Too many sockets to bind to\n"));
				return False;
				}
			}
		}
	} else {
		/* Just bind to 0.0.0.0 - accept connections
		   from anywhere. */
		num_interfaces = 1;

		for(j=0;j<DEFAULT_PORT_NUM;j++){
			if(port[j] == 0)	//user defined case
				continue;
			
			/* open an incoming socket */
			s = open_socket_in(SOCK_STREAM, port[j], 0,
				   			interpret_addr(lp_socket_address()));
			if (s == -1)
				return(False);

			set_socket_options(s,"SO_KEEPALIVE"); 
			set_socket_options(s,user_socket_options);

			set_blocking(s,False); 
		
		/* ready to listen */
			if (listen(s, 50) == -1) {
				DEBUG(0,("open_sockets: listen: %s\n", strerror(errno)));
				close(s);
				return False;
			}
		
			fd_listenset[num_sockets] = s;
			FD_SET(s,&listen_set);
			maxfd = MAX( maxfd, s);

			num_sockets++;

			if (num_sockets >= FD_SETSIZE) {
				DEBUG(0,("open_sockets_smbd: Too many sockets to bind to\n"));
				return False;
			}
		}
	} 

	/* now accept incoming connections - forking a new process
	   for each incoming connection */
	DEBUG(2,("waiting for a connection\n"));

	while (1) {
		int num;
		fd_set lfds;

		memcpy((char *)&lfds, (char *)&listen_set, sizeof(listen_set));
		
		num = sys_select(maxfd+1, &lfds, NULL,NULL,NULL);
		
		if (num == -1 && errno == EINTR){
			continue;
		}
		
		/* Find the sockets that are read-ready -
		   accept on these. */
		for( ; num > 0; num--) {
			struct sockaddr addr;
			int in_addrlen = sizeof(addr);
			
			s = -1;
			for(i = 0; i < num_sockets; i++) {
				if(FD_ISSET(fd_listenset[i],&lfds)) {
					s = fd_listenset[i];
					/* Clear this so we don't look
					   at it again. */
					FD_CLR(fd_listenset[i],&lfds);
					break;
				}
			}

			Client = accept(s,&addr,&in_addrlen);
			
			if (Client == -1 && errno == EINTR)
				continue;
			
			if (Client == -1) {
				DEBUG(0,("open_sockets: accept: %s\n",
					 strerror(errno)));
				continue;
			}
			
			if (Client != -1 && sys_fork()==0) {
				/* Child code ... */
				
				/* close the listening socket(s) */
				for(i = 0; i < num_sockets; i++)
					close(fd_listenset[i]);
				
				/* close our standard file
				   descriptors */
				close_low_fds();
				am_parent = 0;
				
				set_socket_options(Client,"SO_KEEPALIVE");
				set_socket_options(Client,user_socket_options);
				
				/* Reset global variables in util.c so
				   that client substitutions will be
				   done correctly in the process.  */
				reset_globals_after_fork();

				return True; 
			}
			/* The parent doesn't need this socket */
			close(Client);
			//reset the socket fd for the next select....
			Client = -1;
		} /* end for num */
	} /* end while 1 */

/* NOTREACHED	return True; */
}

/****************************************************************************
  process an smb from the client - split out from the process() code so
  it can be used by the oplock break code.
****************************************************************************/

static void process_smb(char *inbuf, char *outbuf)
{
  extern int Client;
  static int trans_num;
  int msg_type = CVAL(inbuf,0);
  int32 len = smb_len(inbuf);
  int nread = len + 4;

  if (trans_num == 0) {
	  /* on the first packet, check the global hosts allow/ hosts
	     deny parameters before doing any parsing of the packet
	     passed to us by the client.  This prevents attacks on our
	     parsing code from hosts not in the hosts allow list */
	  if (!check_access(-1)) {
		  /* send a negative session response "not listining on calling
		   name" */
		  static unsigned char buf[5] = {0x83, 0, 0, 1, 0x81};
		  DEBUG(1,("%s Connection denied from %s\n",
			   timestring(),client_addr()));
		  send_smb(Client,(char *)buf);
		  exit_server("connection denied");
	  }
  }

  DEBUG(6,("got message type 0x%x of len 0x%x\n",msg_type,len));
  DEBUG(3,("%s Transaction %d of length %d\n",timestring(),trans_num,nread));

  if (msg_type == 0)
    show_msg(inbuf);
  else if(msg_type == 0x85)
    return; /* Keepalive packet. */

  nread = construct_reply(inbuf,outbuf,nread,max_send);

  DEBUG(0,("done construct_reply!\n"));
      
  if(nread > 0) 
  {
    if (CVAL(outbuf,0) == 0)
      show_msg(outbuf);
	
    if (nread != smb_len(outbuf) + 4) 
    {
      DEBUG(0,("ERROR: Invalid message response size! %d %d\n",
                 nread, smb_len(outbuf)));
    }
    else
      send_smb(Client,outbuf);
  }
  trans_num++;
}

#ifdef OPLOCK_ENABLE
/****************************************************************************
  open the oplock IPC socket communication
****************************************************************************/
static BOOL open_oplock_ipc()
{
  struct sockaddr_in sock_name;
  int len = sizeof(sock_name);

  DEBUG(3,("open_oplock_ipc: opening loopback UDP socket.\n"));

  /* Open a lookback UDP socket on a random port. */
  oplock_sock = open_socket_in(SOCK_DGRAM, 0, 0, htonl(INADDR_LOOPBACK));
  if (oplock_sock == -1)
  {
    DEBUG(0,("open_oplock_ipc: Failed to get local UDP socket for \
address %x. Error was %s\n", htonl(INADDR_LOOPBACK), strerror(errno)));
    oplock_port = 0;
    return(False);
  }

  /* Find out the transient UDP port we have been allocated. */
  if(getsockname(oplock_sock, (struct sockaddr *)&sock_name, &len)<0)
  {
    DEBUG(0,("open_oplock_ipc: Failed to get local UDP port. Error was %s\n",
            strerror(errno)));
    close(oplock_sock);
    oplock_sock = -1;
    oplock_port = 0;
    return False;
  }
  oplock_port = ntohs(sock_name.sin_port);

  DEBUG(3,("open_oplock ipc: pid = %d, oplock_port = %u\n", 
            sys_getpid(), oplock_port));

  return True;
}

/****************************************************************************
  process an oplock break message.
****************************************************************************/
static BOOL process_local_message(int sock, char *buffer, int buf_size)
{
  int32 msg_len;
  uint16 from_port;
  char *msg_start;

  msg_len = IVAL(buffer,UDP_CMD_LEN_OFFSET);
  from_port = SVAL(buffer,UDP_CMD_PORT_OFFSET);

  msg_start = &buffer[UDP_CMD_HEADER_LEN];

  DEBUG(5,("process_local_message: Got a message of length %d from port (%d)\n", 
            msg_len, from_port));

  /* Switch on message command - currently OPLOCK_BREAK_CMD is the
     only valid request. */

  switch(SVAL(msg_start,UDP_MESSAGE_CMD_OFFSET))
  {
    case OPLOCK_BREAK_CMD:
    case LEVEL_II_OPLOCK_BREAK_CMD:
		
      /* Ensure that the msg length is correct. */
      if(msg_len != OPLOCK_BREAK_MSG_LEN)
      {
        DEBUG(0,("process_local_message: incorrect length for OPLOCK_BREAK_CMD (was %d, \
should be %d).\n", msg_len, OPLOCK_BREAK_MSG_LEN));
        return False;
      }
      {
        uint32 remotepid = IVAL(msg_start,OPLOCK_BREAK_PID_OFFSET);
        uint32 dev = IVAL(msg_start,OPLOCK_BREAK_DEV_OFFSET);
        uint32 inode = IVAL(msg_start, OPLOCK_BREAK_INODE_OFFSET);
        struct timeval tval;
        struct sockaddr_in toaddr;

        tval.tv_sec = IVAL(msg_start, OPLOCK_BREAK_SEC_OFFSET);
        tval.tv_usec = IVAL(msg_start, OPLOCK_BREAK_USEC_OFFSET);

        DEBUG(5,("process_local_message: oplock break request from \
pid %d, port %d, dev = %x, inode = %x\n", remotepid, from_port, dev, inode));

        /*
         * If we have no record of any currently open oplocks,
         * it's not an error, as a close command may have
         * just been issued on the file that was oplocked.
         * Just return success in this case.
         */

        if(global_oplocks_open != 0)
        {
          if(oplock_break(dev, inode, &tval) == False)
          {
            DEBUG(0,("process_local_message: oplock break failed - \
not returning udp message.\n"));
            return False;
          }
        }
        else
        {
          DEBUG(3,("process_local_message: oplock break requested with no outstanding \
oplocks. Returning success.\n"));
        }

        /* Send the message back after OR'ing in the 'REPLY' bit. */
        SSVAL(msg_start,UDP_MESSAGE_CMD_OFFSET,OPLOCK_BREAK_CMD | CMD_REPLY);
  
        bzero((char *)&toaddr,sizeof(toaddr));
        toaddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        toaddr.sin_port = htons(from_port);
        toaddr.sin_family = AF_INET;

        if(sendto( sock, msg_start, OPLOCK_BREAK_MSG_LEN, 0,
                (struct sockaddr *)&toaddr, sizeof(toaddr)) < 0) 
        {
          DEBUG(0,("process_local_message: sendto process %d failed. Errno was %s\n",
                    remotepid, strerror(errno)));
          return False;
        }

        DEBUG(5,("process_local_message: oplock break reply sent to \
pid %d, port %d, for file dev = %x, inode = %x\n", remotepid, 
                from_port, dev, inode));

      }
      break;
    /* 
     * Keep this as a debug case - eventually we can remove it.
     */
    case 0x8001:
      DEBUG(0,("process_local_message: Received unsolicited break \
reply - dumping info.\n"));

      if(msg_len != OPLOCK_BREAK_MSG_LEN)
      {
        DEBUG(0,("process_local_message: ubr: incorrect length for reply \
(was %d, should be %d).\n", msg_len, OPLOCK_BREAK_MSG_LEN));
        return False;
      }

      {
        uint32 remotepid = IVAL(msg_start,OPLOCK_BREAK_PID_OFFSET);
        uint32 dev = IVAL(msg_start,OPLOCK_BREAK_DEV_OFFSET);
        uint32 inode = IVAL(msg_start, OPLOCK_BREAK_INODE_OFFSET);

        DEBUG(0,("process_local_message: unsolicited oplock break reply from \
pid %d, port %d, dev = %x, inode = %x\n", remotepid, from_port, dev, inode));

       }
       return False;

    default:
      DEBUG(0,("process_local_message: unknown UDP message command code (%x) - ignoring.\n",
                (unsigned int)SVAL(msg_start,0)));
      return False;
  }
  return True;
}

/****************************************************************************
 Process an oplock break directly.
****************************************************************************/
BOOL oplock_break(uint32 dev, uint32 inode, struct timeval *tval)
{
  extern int Client;
  static char *inbuf = NULL;
  static char *outbuf = NULL;
  files_struct *fsp = NULL;
  int fnum;
  time_t start_time;
  BOOL shutdown_server = False;

  DEBUG(3,("%s oplock_break: called for dev = %x, inode = %x. Current \
global_oplocks_open = %d\n", timestring(), dev, inode, global_oplocks_open));

  /* We need to search the file open table for the
     entry containing this dev and inode, and ensure
     we have an oplock on it. */
  for( fnum = 0; fnum < MAX_OPEN_FILES; fnum++)
  {
    if(OPEN_FNUM(fnum))
    {
      if((Files[fnum].fd_ptr->dev == dev) && (Files[fnum].fd_ptr->inode == inode) &&
         (Files[fnum].open_time.tv_sec == tval->tv_sec) && 
         (Files[fnum].open_time.tv_usec == tval->tv_usec)) {
	      fsp = &Files[fnum];
	      break;
      }
    }
  }

  if(fsp == NULL)
  {
    /* The file could have been closed in the meantime - return success. */
    DEBUG(0,("%s oplock_break: cannot find open file with dev = %x, inode = %x (fnum = %d) \
allowing break to succeed.\n", timestring(), dev, inode, fnum));
    return True;
  }

  /* Ensure we have an oplock on the file */

  /* There is a potential race condition in that an oplock could
     have been broken due to another udp request, and yet there are
     still oplock break messages being sent in the udp message
     queue for this file. So return true if we don't have an oplock,
     as we may have just freed it.
   */

  if(!fsp->granted_oplock)
  {
    DEBUG(0,("%s oplock_break: file %s (fnum = %d, dev = %x, inode = %x) has no oplock. Allowing break to succeed regardless.\n", timestring(), fsp->name, fnum, dev, inode));
    return True;
  }

  /* mark the oplock break as sent - we don't want to send twice! */
  if (fsp->sent_oplock_break)
  {
    DEBUG(0,("%s oplock_break: ERROR: oplock_break already sent for file %s (fnum = %d, dev = %x, inode = %x)\n", timestring(), fsp->name, fnum, dev, inode));

    /* We have to fail the open here as we cannot send another oplock break on this
       file whilst we are awaiting a response from the client - neither can we
       allow another open to succeed while we are waiting for the client. */
    return False;
  }

  /* Now comes the horrid part. We must send an oplock break to the client,
     and then process incoming messages until we get a close or oplock release.
     At this point we know we need a new inbuf/outbuf buffer pair.
     We cannot use these staticaly as we may recurse into here due to
     messages crossing on the wire.
   */

  if((inbuf = (char *)malloc(BUFFER_SIZE + SAFETY_MARGIN))==NULL)
  {
    DEBUG(0,("oplock_break: malloc fail for input buffer.\n"));
    return False;
  }

  if((outbuf = (char *)malloc(BUFFER_SIZE + SAFETY_MARGIN))==NULL)
  {
    DEBUG(0,("oplock_break: malloc fail for output buffer.\n"));
    free(inbuf);
    inbuf = NULL;
    return False;
  }

  /* Prepare the SMBlockingX message. */
  bzero(outbuf,smb_size);
  set_message(outbuf,8,0,True);

  SCVAL(outbuf,smb_com,SMBlockingX);
  SSVAL(outbuf,smb_tid,fsp->cnum);
  SSVAL(outbuf,smb_pid,0xFFFF);
  SSVAL(outbuf,smb_uid,0);
  SSVAL(outbuf,smb_mid,0xFFFF);
  SCVAL(outbuf,smb_vwv0,0xFF);
  SSVAL(outbuf,smb_vwv2,fnum);
  SCVAL(outbuf,smb_vwv3,LOCKING_ANDX_OPLOCK_RELEASE);
  /* Change this when we have level II oplocks. */
  SCVAL(outbuf,smb_vwv3+1,OPLOCKLEVEL_NONE);
 
  send_smb(Client, outbuf);

  /* Remember we just sent an oplock break on this file. */
  fsp->sent_oplock_break = True;

  /* We need this in case a readraw crosses on the wire. */
  global_oplock_break = True;
 
  /* Process incoming messages. */

  /* JRA - If we don't get a break from the client in OPLOCK_BREAK_TIMEOUT
     seconds we should just die.... */

  start_time = time(NULL);

  while(OPEN_FNUM(fnum) && fsp->granted_oplock)
  {
    if(receive_smb(Client,inbuf,OPLOCK_BREAK_TIMEOUT * 1000) == False)
    {
      /*
       * Die if we got an error.
       */

      if (smb_read_error == READ_EOF)
        DEBUG(0,("%s oplock_break: end of file from client\n", timestring()));
 
      if (smb_read_error == READ_ERROR)
        DEBUG(0,("%s oplock_break: receive_smb error (%s)\n",
                  timestring(), strerror(errno)));

      if (smb_read_error == READ_TIMEOUT)
        DEBUG(0,("%s oplock_break: receive_smb timed out after %d seconds.\n",
                  timestring(), OPLOCK_BREAK_TIMEOUT));

      DEBUG(0,("%s oplock_break failed for file %s (fnum = %d, dev = %x, \
inode = %x).\n", timestring(), fsp->name, fnum, dev, inode));
      shutdown_server = True;
      break;
    }
    process_smb(inbuf, outbuf);

    /*
     * Die if we go over the time limit.
     */

    if((time(NULL) - start_time) > OPLOCK_BREAK_TIMEOUT)
    {
      DEBUG(0,("%s oplock_break: no break received from client within \
%d seconds.\n", timestring(), OPLOCK_BREAK_TIMEOUT));
      DEBUG(0,("%s oplock_break failed for file %s (fnum = %d, dev = %x, \
inode = %x).\n", timestring(), fsp->name, fnum, dev, inode));
      shutdown_server = True;
      break;
    }
  }

  /* Free the buffers we've been using to recurse. */
  free(inbuf);
  free(outbuf);

  /* We need this in case a readraw crossed on the wire. */
  if(global_oplock_break)
    global_oplock_break = False;

  /*
   * If the client did not respond we must die.
   */

  if(shutdown_server)
  {
    DEBUG(0,("%s oplock_break: client failure in break - shutting down this smbd.\n",
          timestring()));
    close_sockets();
    close(oplock_sock);
    exit_server("oplock break failure");
  }

  if(OPEN_FNUM(fnum))
  {
    /* The lockingX reply will have removed the oplock flag 
       from the sharemode. */
    /* Paranoia.... */
    fsp->granted_oplock = False;
    fsp->sent_oplock_break = False;
    global_oplocks_open--;
  }

  /* Santity check - remove this later. JRA */
  if(global_oplocks_open < 0)
  {
    DEBUG(0,("oplock_break: global_oplocks_open < 0 (%d). PANIC ERROR\n",
              global_oplocks_open));
    exit_server("oplock_break: global_oplocks_open < 0");
  }

  DEBUG(3,("%s oplock_break: returning success for fnum = %d, dev = %x, inode = %x. Current \
global_oplocks_open = %d\n", timestring(), fnum, dev, inode, global_oplocks_open));

  return True;
}

/****************************************************************************
Send an oplock break message to another smbd process. If the oplock is held 
by the local smbd then call the oplock break function directly.
****************************************************************************/

BOOL request_oplock_break(share_mode_entry *share_entry, 
                          uint32 dev, uint32 inode)
{
  char op_break_msg[OPLOCK_BREAK_MSG_LEN];
  struct sockaddr_in addr_out;
  int pid = sys_getpid();

  if(pid == share_entry->pid)
  {
    /* We are breaking our own oplock, make sure it's us. */
    if(share_entry->op_port != oplock_port)
    {
      DEBUG(0,("request_oplock_break: corrupt share mode entry - pid = %d, port = %d \
should be %d\n", pid, share_entry->op_port, oplock_port));
      return False;
    }

    DEBUG(5,("request_oplock_break: breaking our own oplock\n"));

    /* Call oplock break direct. */
    return oplock_break(dev, inode, &share_entry->time);
  }

  /* We need to send a OPLOCK_BREAK_CMD message to the
     port in the share mode entry. */

  SSVAL(op_break_msg,UDP_MESSAGE_CMD_OFFSET,OPLOCK_BREAK_CMD);
  SIVAL(op_break_msg,OPLOCK_BREAK_PID_OFFSET,pid);
  SIVAL(op_break_msg,OPLOCK_BREAK_DEV_OFFSET,dev);
  SIVAL(op_break_msg,OPLOCK_BREAK_INODE_OFFSET,inode);
  SIVAL(op_break_msg,OPLOCK_BREAK_SEC_OFFSET,(uint32)share_entry->time.tv_sec);
  SIVAL(op_break_msg,OPLOCK_BREAK_USEC_OFFSET,(uint32)share_entry->time.tv_usec);

  /* set the address and port */
  bzero((char *)&addr_out,sizeof(addr_out));
  addr_out.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  addr_out.sin_port = htons( share_entry->op_port );
  addr_out.sin_family = AF_INET;
   
  DEBUG(3,("%s request_oplock_break: sending a oplock break message to pid %d on port %d \
for dev = %x, inode = %x\n", timestring(), share_entry->pid, share_entry->op_port, dev, inode));

  if(sendto(oplock_sock,op_break_msg,OPLOCK_BREAK_MSG_LEN,0,
         (struct sockaddr *)&addr_out,sizeof(addr_out)) < 0)
  {
    DEBUG(0,("%s request_oplock_break: failed when sending a oplock break message \
to pid %d on port %d for dev = %x, inode = %x. Error was %s\n",
         timestring(), share_entry->pid, share_entry->op_port, dev, inode,
         strerror(errno)));
    return False;
  }

  /*
   * Now we must await the oplock broken message coming back
   * from the target smbd process. Timeout if it fails to
   * return in (OPLOCK_BREAK_TIMEOUT + OPLOCK_BREAK_TIMEOUT_FUDGEFACTOR) seconds.
   * While we get messages that aren't ours, loop.
   */

  while(1)
  {
    char op_break_reply[UDP_CMD_HEADER_LEN+OPLOCK_BREAK_MSG_LEN];
    int32 reply_msg_len;
    uint16 reply_from_port;
    char *reply_msg_start;

    if(receive_local_message(oplock_sock, op_break_reply, sizeof(op_break_reply),
               (OPLOCK_BREAK_TIMEOUT+OPLOCK_BREAK_TIMEOUT_FUDGEFACTOR) * 1000) == False)
    {
      if(smb_read_error == READ_TIMEOUT)
      {
        DEBUG(0,("%s request_oplock_break: no response received to oplock break request to \
pid %d on port %d for dev = %x, inode = %x\n", timestring(), share_entry->pid, 
                           share_entry->op_port, dev, inode));
        /*
         * This is a hack to make handling of failing clients more robust.
         * If a oplock break response message is not received in the timeout
         * period we may assume that the smbd servicing that client holding
         * the oplock has died and the client changes were lost anyway, so
         * we should continue to try and open the file.
         */
        break;
      }
      else
        DEBUG(0,("%s request_oplock_break: error in response received to oplock break request to \
pid %d on port %d for dev = %x, inode = %x. Error was (%s).\n", timestring, share_entry->pid, 
                         share_entry->op_port, dev, inode, strerror(errno)));
      return False;
    }

    /* 
     * If the response we got was not an answer to our message, but
     * was a completely different request, push it onto the pending
     * udp message stack so that we can deal with it in the main loop.
     * It may be another oplock break request to us.
     */

    /*
     * Local note from JRA. There exists the possibility of a denial
     * of service attack here by allowing non-root processes running
     * on a local machine sending many of these pending messages to
     * a smbd port. Currently I'm not sure how to restrict the messages
     * I will queue (although I could add a limit to the queue) to
     * those received by root processes only. There should be a 
     * way to make this bulletproof....
     */

    reply_msg_len = IVAL(op_break_reply,UDP_CMD_LEN_OFFSET);
    reply_from_port = SVAL(op_break_reply,UDP_CMD_PORT_OFFSET);

    reply_msg_start = &op_break_reply[UDP_CMD_HEADER_LEN];

    if(reply_msg_len != OPLOCK_BREAK_MSG_LEN)
    {
      /* Ignore it. */
      DEBUG(0,("%s request_oplock_break: invalid message length received. Ignoring\n",
             timestring()));
      continue;
    }

    if(((SVAL(reply_msg_start,UDP_MESSAGE_CMD_OFFSET) & CMD_REPLY) == 0) ||
       (reply_from_port != share_entry->op_port) ||
       (memcmp(&reply_msg_start[OPLOCK_BREAK_PID_OFFSET], 
               &op_break_msg[OPLOCK_BREAK_PID_OFFSET],
               OPLOCK_BREAK_MSG_LEN - OPLOCK_BREAK_PID_OFFSET) != 0))
    {
      DEBUG(3,("%s request_oplock_break: received other message whilst awaiting \
oplock break response from pid %d on port %d for dev = %x, inode = %x.\n",
             timestring(), share_entry->pid, share_entry->op_port, dev, inode));
      if(push_local_message(op_break_reply, sizeof(op_break_reply)) == False)
        return False;
      continue;
    }

    break;
  }

  DEBUG(3,("%s request_oplock_break: broke oplock.\n", timestring()));

  return True;
}
#endif

/****************************************************************************
Get the next SMB packet, doing the local message processing automatically.
****************************************************************************/

BOOL receive_next_smb(int smbfd, 
#ifdef OPLOCK_ENABLE
						int oplockfd, 
#endif
						char *inbuf, int bufsize, int timeout)
{
  BOOL got_smb = False;
  BOOL ret;

  do
  {
    ret = receive_message_or_smb(smbfd,
#ifdef OPLOCK_ENABLE
							oplockfd,
#endif
							inbuf,bufsize,
                                 			timeout,&got_smb);

#ifdef OPLOCK_ENABLE
    if(ret && !got_smb)
    {
      /* Deal with oplock break requests from other smbd's. */
      process_local_message(oplock_sock, inbuf, bufsize);
      continue;
    }
#endif

    if(ret && (CVAL(inbuf,0) == 0x85))
    {
      /* Keepalive packet. */
      got_smb = False;
    }

  }
  while(ret && !got_smb);

  return ret;
}

/****************************************************************************
check if a snum is in use
****************************************************************************/
BOOL snum_used(int snum)
{
  int i;
  for (i=0;i<MAX_CONNECTIONS;i++)
    if (OPEN_CNUM(i) && (SNUM(i) == snum))
      return(True);
  return(False);
}

/****************************************************************************
  reload the services file
  **************************************************************************/
BOOL reload_services(BOOL test)
{
  BOOL ret;

  if (lp_loaded())
    {
      pstring fname;
      pstrcpy(fname,lp_configfile());
      if (file_exist(fname,NULL) && !strcsequal(fname,servicesf))
	{
	  pstrcpy(servicesf,fname);
	  test = False;
	}
    }

  reopen_logs();

  if (test && !lp_file_list_changed())
    return(True);

  lp_killunused(snum_used);

  ret = lp_load(servicesf,False);

  /* perhaps the config filename is now set */
  if (!test)
    reload_services(True);

  reopen_logs();

  load_interfaces();

  {
    extern int Client;
    if (Client != -1) {      
      set_socket_options(Client,"SO_KEEPALIVE");
      set_socket_options(Client,user_socket_options);
    }
  }

#ifdef USE_83_NAME
  reset_mangled_stack( lp_mangledstack() );
#endif

  /* this forces service parameters to be flushed */
  become_service(-1,True);

  return(ret);
}

/****************************************************************************
start timer for data sync
****************************************************************************/
#if 0
static void *sync_disk(void *no_use)
{
	timer_mutex = False;
	
	DEBUG(0,("###%s\n", __FUNCTION__));
	pthread_detach(pthread_self());
	sync();
	timer_st = False;
	timer_mutex = True;
}
#endif

static void sync_timer()
{
//we only have one timer for data sync, so no need to block signal here
	DEBUG(0,("###%s###\n", __FUNCTION__));
#if 0
//fork a thread to do sync in case system gets blocked.....
	if(timer_mutex){	//lock free~
		int res;
		res = pthread_create(&uni_threadId, NULL, sync_disk, NULL);
		if(res)
			exit_server("sync_timer failed");
	}
#endif

/*
 * Ok seems I encounter a problem that if I create another thread to do the sync, it has a chance under multiple
 * users env that a Z process/thread will come out.....Not sure why.....
*/
	sync();	//this may block and not safe....sucks!
	timer_st = False;
}

static void start_timer()
{
	struct sigevent evp;
	int res;
	memset(&evp, 0, sizeof(struct sigevent));
	//init timer (...stupid uclibc does not support thread way to invoke a timer :-()
	evp.sigev_notify = SIGEV_SIGNAL;
	evp.sigev_signo = SIGUSR2;

	res = timer_create(CLOCK_REALTIME, &evp, &uni_timer);
	if(res){
		exit_server("timer_create failed");
	}
		
	//start a timer
	struct itimerspec ts;
	ts.it_interval.tv_sec = 0;
	ts.it_interval.tv_nsec = 0;
	ts.it_value.tv_sec = 2;	//every 2 sec
	ts.it_value.tv_nsec = 0;

	res = timer_settime(uni_timer, 0, &ts, NULL);
	if(res){
		exit_server("timer_settime failed");
	}
}

#if 0
static void reset_timezone()
{
	BlockSignals(True, 16);

	int tmp_fd;
	tmp_fd = open("/tmp/samba/var/timezone", O_RDONLY);
	char timezone[5];
	timezone[0] = '\0';
	
	read(tmp_fd, timezone, 5);
	TIME_ZONE = atoi(timezone);
	DEBUG(0,("timezone changed to %d\n", TIME_ZONE));
	close(tmp_fd);
	
	BlockSignals(False, 16);	
}
#endif

static void reset_timer()
{	
	BlockSignals(True, SIGUSR1);

	if(timer_st == False){	//no timer starts
		DEBUG(0,("start a new timer for sync!\n"));
		start_timer();	
		timer_st = True;	//start a new timer	
	}	
	else{	//already has a timer running		
	//delete the old timer first!	
		DEBUG(0, ("reset a timer for sync!\n"));
		int res;		
		res = timer_delete(uni_timer);		
		if(res){
			exit_server("timer_delete failed");
		}	
#if 0
	//remember to cancel the thread created by our timer!	it is Ok if we fail here:)		
			pthread_join(uni_threadId, NULL);	
#endif

	//restart a timer!	
		start_timer();
		timer_st = True;
	}
	
	BlockSignals(False, SIGUSR1);
}

/****************************************************************************
this prevents zombie child processes
****************************************************************************/
static int sig_hup()
{ 
  BlockSignals(True,SIGHUP);
  
  sys_select_signal();
  DEBUG(0,("Got SIGHUP\n"));
  reload_services(False);

  BlockSignals(False,SIGHUP);
  return(0);
}

/****************************************************************************
Setup the groups a user belongs to.
****************************************************************************/
int setup_groups(char *user, int uid, int gid, int *p_ngroups, 
		 int **p_igroups, gid_t **p_groups,
         int **p_attrs)
{
  if (-1 == initgroups(user,gid))
    {
      if (getuid() == 0)
	{
	  DEBUG(0,("Unable to initgroups!\n"));
	  if (gid < 0 || gid > 16000 || uid < 0 || uid > 16000)
	    DEBUG(0,("This is probably a problem with the account %s\n",user));
	}
    }
  else
    {
      int i,ngroups;
      int *igroups;
      int *attrs;
      gid_t grp = 0;
      ngroups = getgroups(0,&grp);
      if (ngroups <= 0)
        ngroups = 32;
      igroups = (int *)malloc(sizeof(int)*ngroups);
      attrs   = (int *)malloc(sizeof(int)*ngroups);
      for (i=0;i<ngroups;i++)
      {
        attrs  [i] = 0x7; /* XXXX don't know what NT user attributes are yet! */
        igroups[i] = 0x42424242;
      }
      ngroups = getgroups(ngroups,(gid_t *)igroups);

      if (igroups[0] == 0x42424242)
        ngroups = 0;

      *p_ngroups = ngroups;
      *p_attrs   = attrs;

      /* The following bit of code is very strange. It is due to the
         fact that some OSes use int* and some use gid_t* for
         getgroups, and some (like SunOS) use both, one in prototypes,
         and one in man pages and the actual code. Thus we detect it
         dynamically using some very ugly code */
      if (ngroups > 0)
        {
	  /* does getgroups return ints or gid_t ?? */
	  static BOOL groups_use_ints = True;

	  if (groups_use_ints && 
	      ngroups == 1 && 
	      SVAL(igroups,2) == 0x4242)
	    groups_use_ints = False;
	  
          for (i=0;groups_use_ints && i<ngroups;i++)
            if (igroups[i] == 0x42424242)
    	      groups_use_ints = False;
	      
          if (groups_use_ints)
          {
    	      *p_igroups = igroups;
    	      *p_groups = (gid_t *)igroups;	  
          }
          else
          {
	      gid_t *groups = (gid_t *)igroups;
	      igroups = (int *)malloc(sizeof(int)*ngroups);
	      for (i=0;i<ngroups;i++)
          {
	        igroups[i] = groups[i];
          }
	      *p_igroups = igroups;
	      *p_groups = (gid_t *)groups;
	    }
	}
      DEBUG(3,("%s is in %d groups\n",user,ngroups));
      for (i=0;i<ngroups;i++)
        DEBUG(3,("%d ",igroups[i]));
      DEBUG(3,("\n"));
    }
  return 0;
}

/****************************************************************************
  make a connection to a service
****************************************************************************/
int make_connection(char *service,char *user,char *password, int pwlen, char *dev,uint16 vuid)
{
  int cnum;
  int snum;
  struct passwd *pass = NULL;
  connection_struct *pcon;
  BOOL guest = False;
  BOOL force = False;
  static BOOL first_connection = True;

  strlower_m(service);

  snum = find_service(service);
  if (snum < 0)
    {
      if (strequal(service,"IPC$"))
	{	  
	  DEBUG(3,("%s refusing IPC connection\n",timestring()));
	  return(-3);
	}

      DEBUG(0,("%s couldn't find service %s\n",timestring(),service));      
      return(-2);
    }

  if (strequal(service,HOMES_NAME)) {
	if (*user && Get_Pwnam(user,True))
		return(make_connection(user,user,password,
					       pwlen,dev,vuid));

	if(lp_security() != SEC_SHARE) {
		if (validated_username(vuid)) {
			pstrcpy(user,validated_username(vuid));
			return(make_connection(user,user,password,pwlen,dev,vuid));
		}
	} else {
/* Security = share. Try with sesssetup_user as the username.  */
		if(*sesssetup_user) {
			pstrcpy(user,sesssetup_user);
			return(make_connection(user,user,password,pwlen,dev,vuid));
		}
	}
  }

  if (!lp_snum_ok(snum) || !check_access(snum)) {    
    return(-4);
  }


  /* you can only connect to the IPC$ service as an ipc device */
  if (strequal(service,"IPC$"))
    strcpy(dev,"IPC");

  strupper_m(dev);
  
#if 0
  if (*dev == '?' || !*dev)
    {
      if (lp_print_ok(snum))
	strcpy(dev,"LPT1:");
      else
	strcpy(dev,"A:");
    }

  /* if the request is as a printer and you can't print then refuse */
  strupper_m(dev);
  if (!lp_print_ok(snum) && (strncmp(dev,"LPT",3) == 0)) {
    DEBUG(1,("Attempt to connect to non-printer as a printer\n"));
    return(-6);
  }
#endif

  /* lowercase the user name */
  strlower_m(user);

  /* add it as a possible user name */
  add_session_user(service);

  /* shall we let them in? */
  DEBUG(0, ("username: %s, passwd: %s, vuid: %d\n", user, password, vuid));

  if (!authorise_login(snum,user,password,pwlen,&guest,&force,vuid))
  {
      DEBUG(2,("%s invalid username/password for %s\n",timestring(),service));
      return(-1);
  }
  
  cnum = find_free_connection(str_checksum(service) + str_checksum(user));
  if (cnum < 0)
    {
      DEBUG(0,("%s couldn't find free connection\n",timestring()));      
      return(-1);
    }

  pcon = &Connections[cnum];
  bzero((char *)pcon,sizeof(*pcon));

  /* find out some info about the user */
  pass = Get_Pwnam(user,True);

  if (pass == NULL)
    {
      DEBUG(0,("%s couldn't find account %s\n",timestring(),user)); 
      return(-7);
    }

  pcon->read_only = lp_readonly(snum);

  {
    pstring list;
    StrnCpy(list,lp_readlist(snum),sizeof(pstring)-1);
    string_sub(list,"%S",service);

    if (user_in_list(user,list))
      pcon->read_only = True;

    StrnCpy(list,lp_writelist(snum),sizeof(pstring)-1);
    string_sub(list,"%S",service);

    if (user_in_list(user,list))
      pcon->read_only = False;    
  }

  /* admin user check */

  /* JRA - original code denied admin user if the share was
     marked read_only. Changed as I don't think this is needed,
     but old code left in case there is a problem here.
   */
  if (user_in_list(user,lp_admin_users(snum)) 
#if 0
      && !pcon->read_only)
#else
      )
#endif
    {
      pcon->admin_user = True;
      DEBUG(0,("%s logged in as admin user (root privileges)\n",user));
    }
  else
    pcon->admin_user = False;
    
  pcon->force_user = force;
  pcon->vuid = vuid;
  pcon->uid = pass->pw_uid;
  pcon->gid = pass->pw_gid;
  pcon->num_files_open = 0;
  pcon->lastused = time(NULL);
  pcon->service = snum;
  pcon->used = True;
//  pcon->printer = (strncmp(dev,"LPT",3) == 0);
  pcon->ipc = ((strncmp(dev,"IPC",3) == 0) || strequal(dev,"ADMIN$"));
  pcon->dirptr = NULL;
  pcon->veto_list = NULL;
  pcon->hide_list = NULL;
  pcon->veto_oplock_list = NULL;
  string_set(&pcon->dirpath,"");
  string_set(&pcon->user,user);

#if HAVE_GETGRNAM 
  if (*lp_force_group(snum))
    {
      struct group *gptr;
      pstring gname;

      StrnCpy(gname,lp_force_group(snum),sizeof(pstring)-1);
      /* default service may be a group name 		*/
      string_sub(gname,"%S",service);
      gptr = (struct group *)getgrnam(gname);

      if (gptr)
	{
	  pcon->gid = gptr->gr_gid;
	  DEBUG(3,("Forced group %s\n",gname));
	}
      else
	DEBUG(1,("Couldn't find group %s\n",gname));
    }
#endif

  if (*lp_force_user(snum))
    {
      struct passwd *pass2;
      fstring fuser;
      fstrcpy(fuser,lp_force_user(snum));
      pass2 = (struct passwd *)Get_Pwnam(fuser,True);
      if (pass2)
	{
	  pcon->uid = pass2->pw_uid;
	  string_set(&pcon->user,fuser);
	  fstrcpy(user,fuser);
	  pcon->force_user = True;
	  DEBUG(3,("Forced user %s\n",fuser));	  
	}
      else
	DEBUG(1,("Couldn't find user %s\n",fuser));
    }

  {
    pstring s;
    pstrcpy(s,lp_pathname(snum));
    standard_sub(cnum,s);
    string_set(&pcon->connectpath,s);
    DEBUG(3,("Connect path is %s\n",s));
  }

  /* groups stuff added by ih */
  pcon->ngroups = 0;
  pcon->igroups = NULL;
  pcon->groups = NULL;
  pcon->attrs = NULL;

#if 1
  if (!IS_IPC(cnum))
    {
      /* Find all the groups this uid is in and store them. Used by become_user() */
      setup_groups(pcon->user,pcon->uid,pcon->gid,
                  &pcon->ngroups,&pcon->igroups,&pcon->groups,&pcon->attrs);
      
      /* check number of connections */
      if (!claim_connection(cnum,
			    lp_servicename(SNUM(cnum)),
			    lp_max_connections(SNUM(cnum)),False))
	{
	  DEBUG(1,("too many connections - rejected\n"));
	  return(-8);
	}  

      if (lp_status(SNUM(cnum)))
	claim_connection(cnum,"STATUS.",MAXSTATUS,first_connection);

      first_connection = False;
    } /* IS_IPC */
#endif

  pcon->open = True;

#if 0
  /* execute any "root preexec = " line */
  if (*lp_rootpreexec(SNUM(cnum)))
    {
      pstring cmd;
      pstrcpy(cmd,lp_rootpreexec(SNUM(cnum)));
      standard_sub(cnum,cmd);
      DEBUG(5,("cmd=%s\n",cmd));
      smbrun(cmd,NULL,False);
    }
#endif

  if (!become_user(&Connections[cnum], cnum,pcon->vuid))
    {
      DEBUG(0,("Can't become connected user!\n"));
      pcon->open = False;
	  
#if 1
      if (!IS_IPC(cnum)) {
		yield_connection(cnum,
			 lp_servicename(SNUM(cnum)),
			 lp_max_connections(SNUM(cnum)));
	if (lp_status(SNUM(cnum))) 
		yield_connection(cnum,"STATUS.",MAXSTATUS);
      }
#endif

      return(-1);
    }

  if (ChDir(pcon->connectpath) != 0)
    {
      DEBUG(0,("Can't change directory to %s (%s)\n",
	       pcon->connectpath,strerror(errno)));
      pcon->open = False;
      unbecome_user();
	  
#if 1
      if (!IS_IPC(cnum)) {
		yield_connection(cnum,
			 lp_servicename(SNUM(cnum)),
			 lp_max_connections(SNUM(cnum)));
	if (lp_status(SNUM(cnum))) 
		yield_connection(cnum,"STATUS.",MAXSTATUS);
      }
#endif

      return(-5);      
    }

  string_set(&pcon->origpath,pcon->connectpath);

#if SOFTLINK_OPTIMISATION
  /* resolve any soft links early */
  {
    pstring s;
    pstrcpy(s,pcon->connectpath);
    GetWd(s);
    string_set(&pcon->connectpath,s);
    ChDir(pcon->connectpath);
  }
#endif

  num_connections_open++;
  add_session_user(user);

#if 0
  /* execute any "preexec = " line */
  if (*lp_preexec(SNUM(cnum)))
    {
      pstring cmd;
      pstrcpy(cmd,lp_preexec(SNUM(cnum)));
      standard_sub(cnum,cmd);
      smbrun(cmd,NULL,False);
    }
#endif
  
  /* we've finished with the sensitive stuff */
  unbecome_user();

#if 1
  /* Add veto/hide lists */
  if (!IS_IPC(cnum))
  {
    set_namearray( &pcon->veto_list, lp_veto_files(SNUM(cnum)));
    set_namearray( &pcon->hide_list, lp_hide_files(SNUM(cnum)));
    set_namearray( &pcon->veto_oplock_list, lp_veto_oplocks(SNUM(cnum)));
  }
#endif

  return(cnum);
}


/****************************************************************************
  find first available file slot
****************************************************************************/
int find_free_file(void )
{
	int i;
	static int first_file;

	/* we want to give out file handles differently on each new
	   connection because of a common bug in MS clients where they try to
	   reuse a file descriptor from an earlier smb connection. This code
	   increases the chance that the errant client will get an error rather
	   than causing corruption */
	if (first_file == 0) {
		first_file = (sys_getpid() ^ (int)time(NULL)) % MAX_OPEN_FILES;
		if (first_file == 0) first_file = 1;
	}

	for (i=first_file;i<MAX_OPEN_FILES;i++)
		if (!Files[i].open) {
			memset(&Files[i], 0, sizeof(Files[i]));
			return(i);
		}

	/* returning a file handle of 0 is a bad idea - so we start at 1 */
	for (i=1;i<first_file;i++)
		if (!Files[i].open) {
			memset(&Files[i], 0, sizeof(Files[i]));
			return(i);
		}


	DEBUG(1,("ERROR! Out of file structures - perhaps increase MAX_OPEN_FILES?\n"));
	return(-1);
}

/****************************************************************************
  find first available connection slot, starting from a random position.
The randomisation stops problems with the server dieing and clients
thinking the server is still available.
****************************************************************************/
static int find_free_connection(int hash )
{
  int i;
  BOOL used=False;
  hash = (hash % (MAX_CONNECTIONS-2))+1;

 again:

  for (i=hash+1;i!=hash;)
    {
      if (!Connections[i].open && Connections[i].used == used) 
	{
	  DEBUG(3,("found free connection number %d\n",i));
	  return(i);
	}
      i++;
      if (i == MAX_CONNECTIONS)
	i = 1;
    }

  if (!used)
    {
      used = !used;
      goto again;
    }

  DEBUG(1,("ERROR! Out of connection structures\n"));
  return(-1);
}


/****************************************************************************
reply for the core protocol
****************************************************************************/
int reply_corep(char *inbuf, char *outbuf)
{
  int outsize = set_message(outbuf,1,0,True);

  Protocol = PROTOCOL_CORE;

  return outsize;
}


/****************************************************************************
reply for the coreplus protocol
****************************************************************************/
int reply_coreplus(char *inbuf, char *outbuf)
{
  int raw = (lp_readraw()?1:0) | (lp_writeraw()?2:0);
  int outsize = set_message(outbuf,13,0,True);
  SSVAL(outbuf,smb_vwv5,raw); /* tell redirector we support
				 readbraw and writebraw (possibly) */
  SCVAL(outbuf,smb_flg, 0x81); /* Reply, SMBlockread, SMBwritelock supported */
  SSVAL(outbuf,smb_vwv1,0x1); /* user level security, don't encrypt */	

  Protocol = PROTOCOL_COREPLUS;

  return outsize;
}


/****************************************************************************
reply for the lanman 1.0 protocol
****************************************************************************/
int reply_lanman1(char *inbuf, char *outbuf)
{
  int raw = (lp_readraw()?1:0) | (lp_writeraw()?2:0);
  int secword=0;
  BOOL doencrypt = SMBENCRYPT();
  time_t t = time(NULL);

  if (lp_security()>=SEC_USER) secword |= 1;
  if (doencrypt) secword |= 2;

  set_message(outbuf,13,doencrypt?8:0,True);
  SSVAL(outbuf,smb_vwv1,secword); 
  /* Create a token value and add it to the outgoing packet. */
  if (doencrypt) 
    generate_next_challenge(smb_buf(outbuf));

  Protocol = PROTOCOL_LANMAN1;

  SCVAL(outbuf,smb_flg, 0X81); /* Reply, SMBlockread, SMBwritelock supported */
  SSVAL(outbuf,smb_vwv2,max_recv);
  SSVAL(outbuf,smb_vwv3,lp_maxmux()); /* maxmux */
  SSVAL(outbuf,smb_vwv4,1);
  SSVAL(outbuf,smb_vwv5,raw); /* tell redirector we support
				 readbraw writebraw (possibly) */
  SIVAL(outbuf,smb_vwv6,sys_getpid());
  SSVAL(outbuf,smb_vwv10, TimeDiff(t)/60);

  put_dos_date(outbuf,smb_vwv8,t);

  return (smb_len(outbuf)+4);
}


/****************************************************************************
reply for the lanman 2.0 protocol
****************************************************************************/
int reply_lanman2(char *inbuf, char *outbuf)
{
  int raw = (lp_readraw()?1:0) | (lp_writeraw()?2:0);
  int secword=0;
  BOOL doencrypt = SMBENCRYPT();
  time_t t = time(NULL);
  struct cli_state *cli = NULL;
  char cryptkey[8];
  char crypt_len = 0;

#if 0
  if (lp_security() == SEC_SERVER) {
	  cli = server_cryptkey();
  }
#endif

  if (cli) {
	  DEBUG(3,("using password server validation\n"));
	  doencrypt = ((cli->sec_mode & 2) != 0);
  }

  if (lp_security()>=SEC_USER) secword |= 1;
  if (doencrypt) secword |= 2;

  if (doencrypt) {
	  crypt_len = 8;
	  if (!cli) {
		  generate_next_challenge(cryptkey);
	  } else {
		  memcpy(cryptkey, cli->cryptkey, 8);
		  set_challenge(cli->cryptkey);
	  }
  }

  set_message(outbuf,13,crypt_len,True);
  SSVAL(outbuf,smb_vwv1,secword); 
  SIVAL(outbuf,smb_vwv6,sys_getpid());
  if (doencrypt) 
	  memcpy(smb_buf(outbuf), cryptkey, 8);

  Protocol = PROTOCOL_LANMAN2;

  SCVAL(outbuf,smb_flg, 0X81); /* Reply, SMBlockread, SMBwritelock supported */
  SSVAL(outbuf,smb_vwv2,max_recv);
  SSVAL(outbuf,smb_vwv3,lp_maxmux()); 
  SSVAL(outbuf,smb_vwv4,1);
  SSVAL(outbuf,smb_vwv5,raw); /* readbraw and/or writebraw */
  SSVAL(outbuf,smb_vwv10, TimeDiff(t)/60);
  put_dos_date(outbuf,smb_vwv8,t);

  return (smb_len(outbuf)+4);
}


/****************************************************************************
reply for the nt protocol
****************************************************************************/
int reply_nt1(char *inbuf, char *outbuf)
{
//Do not modify the capability of our smb!I make it fixed in codes!  
  int capabilities = CAP_NT_FIND | CAP_LOCK_AND_READ | 
  				CAP_UNICODE | CAP_NT_SMBS /*| CAP_RPC_REMOTE_APIS*/;

//support large_read/write to speed up file transfer!
  capabilities |= CAP_LARGE_READX|CAP_LARGE_WRITEX | 
  				CAP_STATUS32 | CAP_LARGE_FILES;

  int secword=0;
  BOOL doencrypt = SMBENCRYPT();	//by default we do not encrypt the password....
  time_t t = time(NULL);
  char cryptkey[8];
  int crypt_len = 0;
  char *p, *q;

  if (lp_readraw() && lp_writeraw()) {
	  capabilities |= CAP_RAW_MODE;
  }

  if (lp_security() >= SEC_USER) 
  	secword |= 1;

  if (doencrypt) 
  	secword |= 2;

	set_message(outbuf,17,0,True);
	
	SCVAL(outbuf,smb_vwv1,secword);
	
	Protocol = PROTOCOL_NT1;
	
	SSVAL(outbuf,smb_vwv1+1,lp_maxmux()); /* maxmpx */
	SSVAL(outbuf,smb_vwv2+1,1); /* num vcs */
	SIVAL(outbuf,smb_vwv3+1,max_recv); /* max buffer. LOTS! */
	SIVAL(outbuf,smb_vwv5+1,0x10000); /* raw size. full 64k */
	SIVAL(outbuf,smb_vwv7+1,sys_getpid()); /* session key */
	SIVAL(outbuf,smb_vwv9+1,capabilities); /* capabilities */
	put_long_date(outbuf+smb_vwv11+1,t);
	SSVALS(outbuf,smb_vwv15+1,TimeDiff(t)/60);

	p = q = smb_buf(outbuf);

//Bug fixed & use better challenge method
	if (doencrypt){ 
		crypt_len = 8;
		generate_next_challenge(p);	//we add it here only for ntlm auth
		
		SSVALS(outbuf,smb_vwv16+1,crypt_len);
		p += crypt_len;
  	}

//DO NOT USE pstrcpy!!!
	p += srvstr_push(outbuf, p, myworkgroup, -1, 
				 STR_UNICODE|STR_TERMINATE|STR_NOALIGN);

	SSVAL(outbuf,smb_vwv17, p - q); /* length of challenge+domain strings */
	set_message_end(outbuf, p);

  return (smb_len(outbuf)+4);
}

/* these are the protocol lists used for auto architecture detection:

WinNT 3.51:
protocol [PC NETWORK PROGRAM 1.0]
protocol [XENIX CORE]
protocol [MICROSOFT NETWORKS 1.03]
protocol [LANMAN1.0]
protocol [Windows for Workgroups 3.1a]
protocol [LM1.2X002]
protocol [LANMAN2.1]
protocol [NT LM 0.12]

Win95:
protocol [PC NETWORK PROGRAM 1.0]
protocol [XENIX CORE]
protocol [MICROSOFT NETWORKS 1.03]
protocol [LANMAN1.0]
protocol [Windows for Workgroups 3.1a]
protocol [LM1.2X002]
protocol [LANMAN2.1]
protocol [NT LM 0.12]

OS/2:
protocol [PC NETWORK PROGRAM 1.0]
protocol [XENIX CORE]
protocol [LANMAN1.0]
protocol [LM1.2X002]
protocol [LANMAN2.1]
*/

/*
  * Modified to recognize the architecture of the remote machine better.
  *
  * This appears to be the matrix of which protocol is used by which
  * MS product.
       Protocol                       WfWg    Win95   WinNT  OS/2
       PC NETWORK PROGRAM 1.0          1       1       1      1
       XENIX CORE                                      2      2
       MICROSOFT NETWORKS 3.0          2       2       
       DOS LM1.2X002                   3       3       
       MICROSOFT NETWORKS 1.03                         3
       DOS LANMAN2.1                   4       4       
       LANMAN1.0                                       4      3
       Windows for Workgroups 3.1a     5       5       5
       LM1.2X002                                       6      4
       LANMAN2.1                                       7      5
       NT LM 0.12                              6       8
  *
  *  tim@fsg.com 09/29/95
  */
  
#define ARCH_WFWG     0x3      /* This is a fudge because WfWg is like Win95 */
#define ARCH_WIN95    0x2
#define ARCH_WINNT    0x4
#define ARCH_WIN2K    0xC      /* Win2K is like NT */
#define ARCH_OS2      0x14     /* Again OS/2 is like NT */
#define ARCH_SAMBA    0x20
#define ARCH_CIFSFS   0x40
 
#define ARCH_ALL      0x1F
 
/* List of supported protocols, most desired first */
struct {
  char *proto_name;
  char *short_name;
  int (*proto_reply_fn)(char *, char*);
  int protocol_level;
} supported_protocols[] = {
  {"NT LANMAN 1.0",           "NT1",      reply_nt1,      PROTOCOL_NT1},
  {"NT LM 0.12",              "NT1",      reply_nt1,      PROTOCOL_NT1},
  {"POSIX 2",                 "NT1",      reply_nt1,      PROTOCOL_NT1},
  {"LM1.2X002",               "LANMAN2",  reply_lanman2,  PROTOCOL_LANMAN2},
  {"Samba",                   "LANMAN2",  reply_lanman2,  PROTOCOL_LANMAN2},
  {"DOS LM1.2X002",           "LANMAN2",  reply_lanman2,  PROTOCOL_LANMAN2},
  {"LANMAN1.0",               "LANMAN1",  reply_lanman1,  PROTOCOL_LANMAN1},
  {"MICROSOFT NETWORKS 3.0",  "LANMAN1",  reply_lanman1,  PROTOCOL_LANMAN1},
  {"MICROSOFT NETWORKS 1.03", "COREPLUS", reply_coreplus, PROTOCOL_COREPLUS},
  {"PC NETWORK PROGRAM 1.0",  "CORE",     reply_corep,    PROTOCOL_CORE}, 
  {NULL,NULL},
};


/****************************************************************************
  reply to a negprot
****************************************************************************/
static int reply_negprot(char *inbuf,char *outbuf)
{
  int outsize = set_message(outbuf,1,0,True);
  int Index=0;
  int choice= -1;
  int protocol;
  char *p;
  int bcc = SVAL(smb_buf(inbuf),-2);
  int arch = ARCH_ALL;

  p = smb_buf(inbuf)+1;
  while (p < (smb_buf(inbuf) + bcc))
    { 
      Index++;
      DEBUG(3,("Requested protocol [%s]\n",p));

	if (strcsequal(p,"Windows for Workgroups 3.1a"))
			arch &= ( ARCH_WFWG | ARCH_WIN95 | ARCH_WINNT | ARCH_WIN2K );
		else if (strcsequal(p,"DOS LM1.2X002"))
			arch &= ( ARCH_WFWG | ARCH_WIN95 );
		else if (strcsequal(p,"DOS LANMAN2.1"))
			arch &= ( ARCH_WFWG | ARCH_WIN95 );
		else if (strcsequal(p,"NT LM 0.12"))
			arch &= ( ARCH_WIN95 | ARCH_WINNT | ARCH_WIN2K | ARCH_CIFSFS);
		else if (strcsequal(p,"LANMAN2.1"))
			arch &= ( ARCH_WINNT | ARCH_WIN2K | ARCH_OS2 );
		else if (strcsequal(p,"LM1.2X002"))
			arch &= ( ARCH_WINNT | ARCH_WIN2K | ARCH_OS2 );
		else if (strcsequal(p,"MICROSOFT NETWORKS 1.03"))
			arch &= ARCH_WINNT;
		else if (strcsequal(p,"XENIX CORE"))
			arch &= ( ARCH_WINNT | ARCH_OS2 );
		else if (strcsequal(p,"Samba")) {
			arch = ARCH_SAMBA;
			break;
		} else if (strcsequal(p,"POSIX 2")) {
			arch = ARCH_CIFSFS;
			break;
		}
 
      p += strlen(p) + 2;
    }
    
  /* CIFSFS can send one arch only, NT LM 0.12. */
	if (Index == 1 && (arch & ARCH_CIFSFS)) {
		arch = ARCH_CIFSFS;
	}

	switch ( arch ) {
		case ARCH_CIFSFS:
			set_remote_arch(RA_CIFSFS);
			break;
		case ARCH_SAMBA:
			set_remote_arch(RA_SAMBA);
			break;
		case ARCH_WFWG:
			set_remote_arch(RA_WFWG);
			break;
		case ARCH_WIN95:
			set_remote_arch(RA_WIN95);
			break;
		case ARCH_WINNT:
			if(SVAL(inbuf,smb_flg2)==FLAGS2_WIN2K_SIGNATURE)
				set_remote_arch(RA_WIN2K);
			else
				set_remote_arch(RA_WINNT);
			break;
		case ARCH_WIN2K:
			set_remote_arch(RA_WIN2K);
			break;
		case ARCH_OS2:
			set_remote_arch(RA_OS2);
			break;
		default:
			set_remote_arch(RA_UNKNOWN);
		break;
	}
 
  /* possibly reload - change of architecture */
  reload_services(True);      
    
  /* a special case to stop password server loops */
  if (Index == 1 && strequal(remote_machine,myhostname) && 
      lp_security()==SEC_SERVER)
    exit_server("Password server loop!");
  
  /* Check for protocols, most desirable first */
  for (protocol = 0; supported_protocols[protocol].proto_name; protocol++)
    {
      p = smb_buf(inbuf)+1;
      Index = 0;
      if ((lp_maxprotocol() >= supported_protocols[protocol].protocol_level) &&
	  	(supported_protocols[protocol].protocol_level >= lp_minprotocol()))
	while (p < (smb_buf(inbuf) + bcc))
	  { 
	    if (strequal(p,supported_protocols[protocol].proto_name))
	      choice = Index;
	    Index++;
	    p += strlen(p) + 2;
	  }
      if(choice != -1)
	break;
    }
  
  SSVAL(outbuf,smb_vwv0,choice);
  if(choice != -1) {
    extern fstring remote_proto;
    fstrcpy(remote_proto,supported_protocols[protocol].short_name);
    reload_services(True);          
    outsize = supported_protocols[protocol].proto_reply_fn(inbuf, outbuf);
    DEBUG(3,("Selected protocol %s\n",supported_protocols[protocol].proto_name));
  }
  else {
    DEBUG(0,("No protocol supported !\n"));
  }
  SSVAL(outbuf,smb_vwv0,choice);
  
  DEBUG(5,("%s negprot index=%d\n",timestring(),choice));

  return(outsize);
}


/****************************************************************************
close all open files for a connection
****************************************************************************/
static void close_open_files(int cnum)
{
  int i;
  for (i=0;i<MAX_OPEN_FILES;i++)
    if( Files[i].cnum == cnum && Files[i].open) {
      close_file(i,False);
    }
}



/****************************************************************************
close a cnum
****************************************************************************/
void close_cnum(int cnum, uint16 vuid)
{
  DirCacheFlush(SNUM(cnum));

  unbecome_user();

  if (!OPEN_CNUM(cnum))
    {
      DEBUG(0,("Can't close cnum %d\n",cnum));
      return;
    }

#if 0
  DEBUG(IS_IPC(cnum)?3:1,("%s %s (%s) closed connection to service %s\n",
			  timestring(),
			  remote_machine,client_addr(),
			  lp_servicename(SNUM(cnum))));
#endif

  yield_connection(cnum,
		   lp_servicename(SNUM(cnum)),
		   lp_max_connections(SNUM(cnum)));

  if (lp_status(SNUM(cnum)))
    yield_connection(cnum,"STATUS.",MAXSTATUS);

  close_open_files(cnum);
  dptr_closecnum(cnum);

#if 0
  /* execute any "postexec = " line */
  if (*lp_postexec(SNUM(cnum)) && become_user(&Connections[cnum], cnum,vuid))
    {
      pstring cmd;
      strcpy(cmd,lp_postexec(SNUM(cnum)));
      standard_sub(cnum,cmd);
      smbrun(cmd,NULL,False);
      unbecome_user();
    }
#endif

  unbecome_user();
#if 0
  /* execute any "root postexec = " line */
  if (*lp_rootpostexec(SNUM(cnum)))
    {
      pstring cmd;
      strcpy(cmd,lp_rootpostexec(SNUM(cnum)));
      standard_sub(cnum,cmd);
      smbrun(cmd,NULL,False);
    }
#endif

  Connections[cnum].open = False;
  num_connections_open--;
  if (Connections[cnum].ngroups && Connections[cnum].groups)
    {
      if (Connections[cnum].igroups != (int *)Connections[cnum].groups)
	free(Connections[cnum].groups);
      free(Connections[cnum].igroups);
      Connections[cnum].groups = NULL;
      Connections[cnum].igroups = NULL;
      Connections[cnum].ngroups = 0;
    }

  free_namearray(Connections[cnum].veto_list);
  free_namearray(Connections[cnum].hide_list);
  free_namearray(Connections[cnum].veto_oplock_list);

  string_set(&Connections[cnum].user,"");
  string_set(&Connections[cnum].dirpath,"");
  string_set(&Connections[cnum].connectpath,"");
}


/****************************************************************************
simple routines to do connection counting
****************************************************************************/
BOOL yield_connection(int cnum,char *name,int max_connections)
{
  struct connect_record crec;
  pstring fname;
  FILE *f;
  int mypid = sys_getpid();
  int i;

  DEBUG(3,("Yielding connection to %d %s\n",cnum,name));

  if (max_connections <= 0)
    return(True);

  bzero(&crec,sizeof(crec));

  pstrcpy(fname,lp_lockdir());
  standard_sub(cnum,fname);
  trim_string(fname,"","/");

  strcat(fname,"/");
  strcat(fname,name);
  strcat(fname,".LCK");

  f = fopen(fname,"r+");
  if (!f)
    {
      DEBUG(2,("Couldn't open lock file %s (%s)\n",fname,strerror(errno)));
      return(False);
    }

  fseek(f,0,SEEK_SET);

  /* find a free spot */
  for (i=0;i<max_connections;i++)
    {
      if (fread(&crec,sizeof(crec),1,f) != 1)
	{
	  DEBUG(2,("Entry not found in lock file %s\n",fname));
	  fclose(f);
	  return(False);
	}
      if (crec.pid == mypid && crec.cnum == cnum)
	break;
    }

  if (crec.pid != mypid || crec.cnum != cnum)
    {
      fclose(f);
      DEBUG(2,("Entry not found in lock file %s\n",fname));
      return(False);
    }

  bzero((void *)&crec,sizeof(crec));
  
  /* remove our mark */
  if (fseek(f,i*sizeof(crec),SEEK_SET) != 0 ||
      fwrite(&crec,sizeof(crec),1,f) != 1)
    {
      DEBUG(2,("Couldn't update lock file %s (%s)\n",fname,strerror(errno)));
      fclose(f);
      return(False);
    }

  DEBUG(3,("Yield successful\n"));

  fclose(f);
  return(True);
}


/****************************************************************************
simple routines to do connection counting
****************************************************************************/
BOOL claim_connection(int cnum,char *name,int max_connections,BOOL Clear)
{
	extern int Client;
	struct connect_record crec;
	pstring fname;
	int fd=-1;
	int i,foundi= -1;
	int total_recs;
	
	if (max_connections <= 0)
		return(True);
	
	DEBUG(5,("trying claim %s %s %d\n",lp_lockdir(),name,max_connections));
	
	pstrcpy(fname,lp_lockdir());
	standard_sub(cnum,fname);		
	trim_string(fname,"","/");
	
	if (!directory_exist(fname,NULL))
		mkdir(fname,0755);
	
	strcat(fname,"/");
	strcat(fname,name);
	strcat(fname,".LCK");
	
	if (!file_exist(fname,NULL)) {
		fd = open(fname,O_RDWR|O_CREAT|O_EXCL, 0644);
	}

	if (fd == -1) {
		fd = open(fname,O_RDWR,0);
	}
	
	if (fd == -1) {
		DEBUG(1,("couldn't open lock file %s\n",fname));
		return(False);
	}

	if (fcntl_lock(fd,F_SETLKW,0,1,F_WRLCK)==False) {
		DEBUG(0,("ERROR: can't get lock on %s\n", fname));
		return False;
	}

	total_recs = file_size(fname) / sizeof(crec);
			
	/* find a free spot */
	for (i=0;i<max_connections;i++) {
		if (i>=total_recs || 
		    sys_lseek(fd,i*sizeof(crec),SEEK_SET) != i*sizeof(crec) ||
		    read(fd,&crec,sizeof(crec)) != sizeof(crec)) {
			if (foundi < 0) foundi = i;
			break;
		}
		
		if (Clear && crec.pid && !process_exists(crec.pid)) {
			if(sys_lseek(fd,i*sizeof(crec),SEEK_SET) != i*sizeof(crec)) {
              			DEBUG(0,("claim_connection: ERROR: sys_lseek failed to seek \
						to %d\n", (int)(i*sizeof(crec)) ));
              		continue;
            }
			bzero((void *)&crec,sizeof(crec));
			write(fd, &crec,sizeof(crec));
			if (foundi < 0) foundi = i;
			continue;
		}
		if (foundi < 0 && (!crec.pid || !process_exists(crec.pid))) {
			foundi=i;
			if (!Clear) break;
		}
	}  
	
	if (foundi < 0) {
		DEBUG(3,("no free locks in %s\n",fname));
		if (fcntl_lock(fd,F_SETLKW,0,1,F_UNLCK)==False) {
			DEBUG(0,("ERROR: can't release lock on %s\n", fname));
		}
		close(fd);
		return(False);
	}      
	
	/* fill in the crec */
	bzero((void *)&crec,sizeof(crec));
		
	crec.magic = 0x280267;
	crec.pid = sys_getpid();
  	crec.cnum = cnum;
  	crec.uid = Connections[cnum].uid;
  	crec.gid = Connections[cnum].gid;
  	StrnCpy(crec.name,lp_servicename(SNUM(cnum)),sizeof(crec.name)-1);
  	crec.start = time(NULL);
	
	StrnCpy(crec.machine,remote_machine,sizeof(crec.machine)-1);
	StrnCpy(crec.addr,client_addr(),sizeof(crec.addr)-1);
	
	/* make our mark */
	if (sys_lseek(fd,foundi*sizeof(crec),SEEK_SET) != foundi*sizeof(crec) ||
	    write(fd, &crec,sizeof(crec)) != sizeof(crec)) {

		if (fcntl_lock(fd,F_SETLKW,0,1,F_UNLCK)==False) {
			DEBUG(0,("ERROR: can't release lock on %s\n", fname));
		}

		close(fd);
		return(False);
	}


	if (fcntl_lock(fd,F_SETLKW,0,1,F_UNLCK)==False) {
		DEBUG(0,("ERROR: can't release lock on %s\n", fname));
	}


	close(fd);
	return(True);
}

#if DUMP_CORE
/*******************************************************************
prepare to dump a core file - carefully!
********************************************************************/
static BOOL dump_core(void)
{
  char *p;
  pstring dname;
  pstrcpy(dname,debugf);
  if ((p=strrchr_m(dname,'/'))) *p=0;
  strcat(dname,"/corefiles");
  mkdir(dname,0700);
  sys_chown(dname,getuid(),getgid());
  chmod(dname,0700);
  if (chdir(dname)) return(False);
  umask(~(0700));

#ifndef NO_GETRLIMIT
#ifdef RLIMIT_CORE
  {
    struct rlimit rlp;
    getrlimit(RLIMIT_CORE, &rlp);
    rlp.rlim_cur = MAX(4*1024*1024,rlp.rlim_cur);
    setrlimit(RLIMIT_CORE, &rlp);
    getrlimit(RLIMIT_CORE, &rlp);
    DEBUG(3,("Core limits now %d %d\n",rlp.rlim_cur,rlp.rlim_max));
  }
#endif
#endif


  DEBUG(0,("Dumping core in %s\n",dname));
  return(True);
}
#endif

/****************************************************************************
exit the server
****************************************************************************/
void exit_server(char *reason)
{
  //clear the share memory for timezone feature
  munmap(TIME_ZONE, 5);
  close(TZ_FD);
  
  static int firsttime=1;
  int i;

  if (!firsttime) exit(0);
  firsttime = 0;

  unbecome_user();
  DEBUG(2,("Closing connections\n"));
  
  for (i=0;i<MAX_CONNECTIONS;i++)
    if (Connections[i].open)
      close_cnum(i,(uint16)-1);
	
#ifdef DFS_AUTH
  if (dcelogin_atmost_once)
    dfs_unlogin();
#endif

  if (!reason) {   
    int oldlevel = DEBUGLEVEL;
    DEBUGLEVEL = 10;
    DEBUG(0,("Last message was %s\n",smb_fn_name(last_message)));
    if (last_inbuf)
      show_msg(last_inbuf);
    DEBUGLEVEL = oldlevel;
    DEBUG(0,("===============================================================\n"));
#if DUMP_CORE
    if (dump_core()) return;
#endif
  }    

  locking_end();

  DEBUG(3,("%s Server exit  (%s)\n",timestring(),reason?reason:""));
  exit(0);
}

/****************************************************************************
do some standard substitutions in a string
****************************************************************************/
void standard_sub(int cnum,char *str)
{
  if (VALID_CNUM(cnum)) {
    char *p, *s, *home;

    for ( s=str ; (p=strchr_m(s, '%')) != NULL ; s=p ) {
      switch (*(p+1)) {
        case 'H' : if ((home = get_home_dir(Connections[cnum].user))!=NULL)
                     string_sub(p,"%H",home);
                   else
                     p += 2;
                   break;
        case 'P' : string_sub(p,"%P",Connections[cnum].connectpath); break;
        case 'S' : string_sub(p,"%S",lp_servicename(Connections[cnum].service)); break;
        case 'g' : string_sub(p,"%g",gidtoname(Connections[cnum].gid)); break;
        case 'u' : string_sub(p,"%u",Connections[cnum].user); break;
        case '\0' : p++; break; /* don't run off the end of the string */
        default  : p+=2; break;
      }
    }
  }
  standard_sub_basic(str);
}

/*
These flags determine some of the permissions required to do an operation 

Note that I don't set NEED_WRITE on some write operations because they
are used by some brain-dead clients when printing, and I don't want to
force write permissions on print services.
*/
#define AS_USER (1<<0)
#define NEED_WRITE (1<<1)
#define TIME_INIT (1<<2)
#define CAN_IPC (1<<3)
#define AS_GUEST (1<<5)
#define QUEUE_IN_OPLOCK (1<<6)
#define DO_CHDIR (1<<7)

/* 
   define a list of possible SMB messages and their corresponding
   functions. Any message that has a NULL function is unimplemented -
   please feel free to contribute implementations!
*/

/*DO NOT CHANGE THE ODERS!!!!*/
struct smb_message_struct
{
  char *name;
  int (*fn)();
  int flags;
}
 smb_messages[256] = {

/* 0x00 */ { "SMBmkdir",reply_mkdir,AS_USER | NEED_WRITE},
/* 0x01 */ { "SMBrmdir",reply_rmdir,AS_USER | NEED_WRITE},
/* 0x02 */ { "SMBopen",reply_open,AS_USER},
/* 0x03 */ { "SMBcreate",reply_mknew,AS_USER},
/* 0x04 */ { "SMBclose",reply_close,AS_USER | CAN_IPC},
/* 0x05 */ { "SMBflush",reply_flush,AS_USER},
/* 0x06 */ { "SMBunlink",reply_unlink,AS_USER | NEED_WRITE},
/* 0x07 */ { "SMBmv",reply_mv,AS_USER | NEED_WRITE},
/* 0x08 */ { "SMBgetatr",reply_getatr,AS_USER},
/* 0x09 */ { "SMBsetatr",reply_setatr,AS_USER | NEED_WRITE},
/* 0x0a */ { "SMBread",reply_read,AS_USER},
/* 0x0b */ { "SMBwrite",reply_write,AS_USER | CAN_IPC},
/* 0x0c */ { "SMBlock",reply_lock,AS_USER},
/* 0x0d */ { "SMBunlock",reply_unlock,AS_USER},
/* 0x0e */ { "SMBctemp",reply_ctemp,AS_USER },
/* 0x0f */ { "SMBmknew",reply_mknew,AS_USER}, 
/* 0x10 */ { "SMBchkpth",reply_chkpth,AS_USER},
/* 0x11 */ { "SMBexit",reply_exit,0},
/* 0x12 */ { "SMBlseek",reply_lseek,AS_USER},
/* 0x13 */ { "SMBlockread",reply_lockread,AS_USER},
/* 0x14 */ { "SMBwriteunlock",reply_writeunlock,AS_USER},
/* 0x15 */ { NULL, NULL, 0 },
/* 0x16 */ { NULL, NULL, 0 },
/* 0x17 */ { NULL, NULL, 0 },
/* 0x18 */ { NULL, NULL, 0 },
/* 0x19 */ { NULL, NULL, 0 },
/* 0x1a */ { "SMBreadbraw",reply_readbraw,AS_USER},
/* 0x1b */ { "SMBreadBmpx",reply_readbmpx,AS_USER},
/* 0x1c */ { "SMBreadBs",NULL,0},
/* 0x1d */ { "SMBwritebraw",reply_writebraw,AS_USER},
/* 0x1e */ { "SMBwriteBmpx",reply_writebmpx,AS_USER},
/* 0x1f */ { "SMBwriteBs",reply_writebs,AS_USER},
/* 0x20 */ { "SMBwritec",NULL,0},
/* 0x21 */ { NULL, NULL, 0 },
/* 0x22 */ { "SMBsetattrE",reply_setattrE,AS_USER | NEED_WRITE },
/* 0x23 */ { "SMBgetattrE",reply_getattrE,AS_USER },
/* 0x24 */ { "SMBlockingX",reply_lockingX,AS_USER },
/* 0x25 */ { "SMBtrans",reply_trans,AS_USER | CAN_IPC},
///* 0x25 */ { "SMBtrans",NULL,AS_USER | CAN_IPC },
/* 0x26 */ { "SMBtranss",NULL,AS_USER},
/* 0x27 */ { "SMBioctl",reply_ioctl,0},
/* 0x28 */ { "SMBioctls",NULL,AS_USER},
/* 0x29 */ { "SMBcopy",reply_copy,AS_USER | NEED_WRITE },
/* 0x2a */ { "SMBmove",NULL, AS_USER | NEED_WRITE },
/* 0x2b */ { "SMBecho",reply_echo,0},
/* 0x2c */ { "SMBwriteclose",reply_writeclose,AS_USER},
/* 0x2d */ { "SMBopenX",reply_open_and_X,AS_USER},
/* 0x2e */ { "SMBreadX",reply_read_and_X,AS_USER},
/* 0x2f */ { "SMBwriteX",reply_write_and_X,AS_USER},
/* 0x30 */ { NULL, NULL, 0 },
/* 0x31 */ { NULL, NULL, 0 },
/* 0x32 */ { "SMBtrans2", reply_trans2, AS_USER | CAN_IPC},
/* 0x33 */ { "SMBtranss2", reply_transs2, AS_USER},
/* 0x34 */ { "SMBfindclose", reply_findclose,AS_USER},
/* 0x35 */ { "SMBfindnclose", reply_findnclose, AS_USER},
/* 0x36 */ { NULL, NULL, 0 },
/* 0x37 */ { NULL, NULL, 0 },
/* 0x38 */ { NULL, NULL, 0 },
/* 0x39 */ { NULL, NULL, 0 },
/* 0x3a */ { NULL, NULL, 0 },
/* 0x3b */ { NULL, NULL, 0 },
/* 0x3c */ { NULL, NULL, 0 },
/* 0x3d */ { NULL, NULL, 0 },
/* 0x3e */ { NULL, NULL, 0 },
/* 0x3f */ { NULL, NULL, 0 },
/* 0x40 */ { NULL, NULL, 0 },
/* 0x41 */ { NULL, NULL, 0 },
/* 0x42 */ { NULL, NULL, 0 },
/* 0x43 */ { NULL, NULL, 0 },
/* 0x44 */ { NULL, NULL, 0 },
/* 0x45 */ { NULL, NULL, 0 },
/* 0x46 */ { NULL, NULL, 0 },
/* 0x47 */ { NULL, NULL, 0 },
/* 0x48 */ { NULL, NULL, 0 },
/* 0x49 */ { NULL, NULL, 0 },
/* 0x4a */ { NULL, NULL, 0 },
/* 0x4b */ { NULL, NULL, 0 },
/* 0x4c */ { NULL, NULL, 0 },
/* 0x4d */ { NULL, NULL, 0 },
/* 0x4e */ { NULL, NULL, 0 },
/* 0x4f */ { NULL, NULL, 0 },
/* 0x50 */ { NULL, NULL, 0 },
/* 0x51 */ { NULL, NULL, 0 },
/* 0x52 */ { NULL, NULL, 0 },
/* 0x53 */ { NULL, NULL, 0 },
/* 0x54 */ { NULL, NULL, 0 },
/* 0x55 */ { NULL, NULL, 0 },
/* 0x56 */ { NULL, NULL, 0 },
/* 0x57 */ { NULL, NULL, 0 },
/* 0x58 */ { NULL, NULL, 0 },
/* 0x59 */ { NULL, NULL, 0 },
/* 0x5a */ { NULL, NULL, 0 },
/* 0x5b */ { NULL, NULL, 0 },
/* 0x5c */ { NULL, NULL, 0 },
/* 0x5d */ { NULL, NULL, 0 },
/* 0x5e */ { NULL, NULL, 0 },
/* 0x5f */ { NULL, NULL, 0 },
/* 0x60 */ { NULL, NULL, 0 },
/* 0x61 */ { NULL, NULL, 0 },
/* 0x62 */ { NULL, NULL, 0 },
/* 0x63 */ { NULL, NULL, 0 },
/* 0x64 */ { NULL, NULL, 0 },
/* 0x65 */ { NULL, NULL, 0 },
/* 0x66 */ { NULL, NULL, 0 },
/* 0x67 */ { NULL, NULL, 0 },
/* 0x68 */ { NULL, NULL, 0 },
/* 0x69 */ { NULL, NULL, 0 },
/* 0x6a */ { NULL, NULL, 0 },
/* 0x6b */ { NULL, NULL, 0 },
/* 0x6c */ { NULL, NULL, 0 },
/* 0x6d */ { NULL, NULL, 0 },
/* 0x6e */ { NULL, NULL, 0 },
/* 0x6f */ { NULL, NULL, 0 },
/* 0x70 */ { "SMBtcon",reply_tcon,0},
/* 0x71 */ { "SMBtdis",reply_tdis,DO_CHDIR},
/* 0x72 */ { "SMBnegprot",reply_negprot,0},
/* 0x73 */ { "SMBsesssetupX",reply_sesssetup_and_X,0},
/* 0x74 */ { "SMBulogoffX", reply_ulogoffX, 0}, /* ulogoff doesn't give a valid TID */
/* 0x75 */ { "SMBtconX",reply_tcon_and_X,0},
/* 0x76 */ { NULL, NULL, 0 },
/* 0x77 */ { NULL, NULL, 0 },
/* 0x78 */ { NULL, NULL, 0 },
/* 0x79 */ { NULL, NULL, 0 },
/* 0x7a */ { NULL, NULL, 0 },
/* 0x7b */ { NULL, NULL, 0 },
/* 0x7c */ { NULL, NULL, 0 },
/* 0x7d */ { NULL, NULL, 0 },
/* 0x7e */ { NULL, NULL, 0 },
/* 0x7f */ { NULL, NULL, 0 },
/* 0x80 */ { "SMBdskattr",reply_dskattr,AS_USER},
/* 0x81 */ { "SMBsearch",reply_search,AS_USER},
/* 0x82 */ { "SMBffirst",reply_search,AS_USER},
/* 0x83 */ { "SMBfunique",reply_search,AS_USER},
/* 0x84 */ { "SMBfclose",reply_fclose,AS_USER},
/* 0x85 */ { NULL, NULL, 0 },
/* 0x86 */ { NULL, NULL, 0 },
/* 0x87 */ { NULL, NULL, 0 },
/* 0x88 */ { NULL, NULL, 0 },
/* 0x89 */ { NULL, NULL, 0 },
/* 0x8a */ { NULL, NULL, 0 },
/* 0x8b */ { NULL, NULL, 0 },
/* 0x8c */ { NULL, NULL, 0 },
/* 0x8d */ { NULL, NULL, 0 },
/* 0x8e */ { NULL, NULL, 0 },
/* 0x8f */ { NULL, NULL, 0 },
/* 0x90 */ { NULL, NULL, 0 },
/* 0x91 */ { NULL, NULL, 0 },
/* 0x92 */ { NULL, NULL, 0 },
/* 0x93 */ { NULL, NULL, 0 },
/* 0x94 */ { NULL, NULL, 0 },
/* 0x95 */ { NULL, NULL, 0 },
/* 0x96 */ { NULL, NULL, 0 },
/* 0x97 */ { NULL, NULL, 0 },
/* 0x98 */ { NULL, NULL, 0 },
/* 0x99 */ { NULL, NULL, 0 },
/* 0x9a */ { NULL, NULL, 0 },
/* 0x9b */ { NULL, NULL, 0 },
/* 0x9c */ { NULL, NULL, 0 },
/* 0x9d */ { NULL, NULL, 0 },
/* 0x9e */ { NULL, NULL, 0 },
/* 0x9f */ { NULL, NULL, 0 },
/*########TODO: NEED TO UPDATE THESE FUNCTIONS???########*/
/* 0xa0 */ { "SMBnttrans", reply_nttrans/*reply_nttrans*/, AS_USER},
/* 0xa1 */ { "SMBnttranss", reply_nttranss/*reply_nttranss*/, AS_USER},
/* 0xa2 */ { "SMBntcreateX", reply_ntcreate_and_X, AS_USER | CAN_IPC},
/* 0xa3 */ { NULL, NULL, 0 },
/* 0xa4 */ { "SMBntcancel", reply_ntcancel/*reply_ntcancel*/, 0 },
/*###############################################*/
/* 0xa5 */ { NULL, NULL, 0 },
/* 0xa6 */ { NULL, NULL, 0 },
/* 0xa7 */ { NULL, NULL, 0 },
/* 0xa8 */ { NULL, NULL, 0 },
/* 0xa9 */ { NULL, NULL, 0 },
/* 0xaa */ { NULL, NULL, 0 },
/* 0xab */ { NULL, NULL, 0 },
/* 0xac */ { NULL, NULL, 0 },
/* 0xad */ { NULL, NULL, 0 },
/* 0xae */ { NULL, NULL, 0 },
/* 0xaf */ { NULL, NULL, 0 },
/* 0xb0 */ { NULL, NULL, 0 },
/* 0xb1 */ { NULL, NULL, 0 },
/* 0xb2 */ { NULL, NULL, 0 },
/* 0xb3 */ { NULL, NULL, 0 },
/* 0xb4 */ { NULL, NULL, 0 },
/* 0xb5 */ { NULL, NULL, 0 },
/* 0xb6 */ { NULL, NULL, 0 },
/* 0xb7 */ { NULL, NULL, 0 },
/* 0xb8 */ { NULL, NULL, 0 },
/* 0xb9 */ { NULL, NULL, 0 },
/* 0xba */ { NULL, NULL, 0 },
/* 0xbb */ { NULL, NULL, 0 },
/* 0xbc */ { NULL, NULL, 0 },
/* 0xbd */ { NULL, NULL, 0 },
/* 0xbe */ { NULL, NULL, 0 },
/* 0xbf */ { NULL, NULL, 0 },
/* 0xc0 */ { "SMBsplopen",NULL,AS_USER},	//we do not support printer here...
/* 0xc1 */ { "SMBsplwr",NULL,AS_USER},
/* 0xc2 */ { "SMBsplclose",NULL,AS_USER},
/* 0xc3 */ { "SMBsplretq",NULL,AS_USER},
/* 0xc4 */ { NULL, NULL, 0 },
/* 0xc5 */ { NULL, NULL, 0 },
/* 0xc6 */ { NULL, NULL, 0 },
/* 0xc7 */ { NULL, NULL, 0 },
/* 0xc8 */ { NULL, NULL, 0 },
/* 0xc9 */ { NULL, NULL, 0 },
/* 0xca */ { NULL, NULL, 0 },
/* 0xcb */ { NULL, NULL, 0 },
/* 0xcc */ { NULL, NULL, 0 },
/* 0xcd */ { NULL, NULL, 0 },
/* 0xce */ { NULL, NULL, 0 },
/* 0xcf */ { NULL, NULL, 0 },
/* 0xd0 */ { "SMBsends",reply_sends,AS_GUEST},
/* 0xd1 */ { "SMBsendb",NULL,AS_GUEST},
/* 0xd2 */ { "SMBfwdname",NULL,AS_GUEST},
/* 0xd3 */ { "SMBcancelf",NULL,AS_GUEST},
/* 0xd4 */ { "SMBgetmac",NULL,AS_GUEST},
/* 0xd5 */ { "SMBsendstrt",reply_sendstrt,AS_GUEST},
/* 0xd6 */ { "SMBsendend",reply_sendend,AS_GUEST},
/* 0xd7 */ { "SMBsendtxt",reply_sendtxt,AS_GUEST},
/* 0xd8 */ { NULL, NULL, 0 },
/* 0xd9 */ { NULL, NULL, 0 },
/* 0xda */ { NULL, NULL, 0 },
/* 0xdb */ { NULL, NULL, 0 },
/* 0xdc */ { NULL, NULL, 0 },
/* 0xdd */ { NULL, NULL, 0 },
/* 0xde */ { NULL, NULL, 0 },
/* 0xdf */ { NULL, NULL, 0 },
/* 0xe0 */ { NULL, NULL, 0 },
/* 0xe1 */ { NULL, NULL, 0 },
/* 0xe2 */ { NULL, NULL, 0 },
/* 0xe3 */ { NULL, NULL, 0 },
/* 0xe4 */ { NULL, NULL, 0 },
/* 0xe5 */ { NULL, NULL, 0 },
/* 0xe6 */ { NULL, NULL, 0 },
/* 0xe7 */ { NULL, NULL, 0 },
/* 0xe8 */ { NULL, NULL, 0 },
/* 0xe9 */ { NULL, NULL, 0 },
/* 0xea */ { NULL, NULL, 0 },
/* 0xeb */ { NULL, NULL, 0 },
/* 0xec */ { NULL, NULL, 0 },
/* 0xed */ { NULL, NULL, 0 },
/* 0xee */ { NULL, NULL, 0 },
/* 0xef */ { NULL, NULL, 0 },
/* 0xf0 */ { NULL, NULL, 0 },
/* 0xf1 */ { NULL, NULL, 0 },
/* 0xf2 */ { NULL, NULL, 0 },
/* 0xf3 */ { NULL, NULL, 0 },
/* 0xf4 */ { NULL, NULL, 0 },
/* 0xf5 */ { NULL, NULL, 0 },
/* 0xf6 */ { NULL, NULL, 0 },
/* 0xf7 */ { NULL, NULL, 0 },
/* 0xf8 */ { NULL, NULL, 0 },
/* 0xf9 */ { NULL, NULL, 0 },
/* 0xfa */ { NULL, NULL, 0 },
/* 0xfb */ { NULL, NULL, 0 },
/* 0xfc */ { NULL, NULL, 0 },
/* 0xfd */ { NULL, NULL, 0 },
/* 0xfe */ { NULL, NULL, 0 },
/* 0xff */ { NULL, NULL, 0 }

};

/****************************************************************************
return a string containing the function name of a SMB command
****************************************************************************/
char *smb_fn_name(int type)
{
	static char *unknown_name = "SMBunknown";

	if (smb_messages[type].name == NULL)
		return(unknown_name);

	return(smb_messages[type].name);
}


/****************************************************************************
do a switch on the message type, and return the response size
****************************************************************************/
static int switch_message(int type,char *inbuf,char *outbuf,int size,int bufsize)
{
  static pid_t pid= (pid_t)-1;
  int outsize = 0;

  type &= 0xff;	//fancy~

  if (pid == (pid_t)-1)
    pid = sys_getpid();

  errno = 0;
  last_message = type;

  /* make sure this is an SMB packet */
  if (strncmp(smb_base(inbuf),"\377SMB",4) != 0)
  {
    DEBUG(2,("Non-SMB packet of length %d\n",smb_len(inbuf)));
    exit_server("Non-SMB packet");
    return(-1);
  }

  if (smb_messages[type].fn == NULL) {
	DEBUG(0,("Unknown message type %d!\n",type));
	outsize = reply_unknown(inbuf,outbuf);
  }
  else
  {
    int cnum = SVAL(inbuf,smb_tid);
    int flags = smb_messages[type].flags;
    static uint16 last_session_tag = UID_FIELD_INVALID;
    uint16 session_tag = (lp_security() == SEC_SHARE) ? UID_FIELD_INVALID : SVAL(inbuf,smb_uid);
	
    DEBUG(3,("switch message %s (pid %d)\n",smb_messages[type].name,(int)pid));

#ifdef OPLOCK_ENABLE
    if(global_oplock_break)
    {
      if(flags & QUEUE_IN_OPLOCK)
      {
        /* 
         * Queue this message as we are the process of an oplock break.
         */

        DEBUG( 2, 
        ( "switch_message: queueing message due to being in oplock break state.\n" ) );

 //       push_oplock_pending_smb_message( inbuf, size );
        return -1;
      }          
    }
#endif

      /* Ensure this value is replaced in the incoming packet. */
      SSVAL(inbuf,smb_uid,session_tag);

      /*
       * Ensure the correct username is in sesssetup_user.
       * This is a really ugly bugfix for problems with
       * multiple session_setup_and_X's being done and
       * allowing %U and %G substitutions to work correctly.
       * There is a reason this code is done here, don't
       * move it unless you know what you're doing... :-).
       * JRA.
       */
        if (session_tag != last_session_tag) {
        	user_struct *vuser = NULL;

       		last_session_tag = session_tag;
        	if(session_tag != UID_FIELD_INVALID)
          		vuser = get_valid_user_struct(session_tag);         
			
        	if(vuser != NULL)
          		pstrcpy(sesssetup_user, vuser->requested_name);
      }

      /* does this protocol need to be run as root? */
      if (!(flags & AS_USER))
        unbecome_user();

      /* does this protocol need to be run as the connected user? */
      if ((flags & AS_USER) && !become_user(&Connections[cnum],cnum,session_tag)) {
        if (flags & AS_GUEST) 
          flags &= ~AS_USER;
        else
          return(ERROR_DOS(ERRSRV,ERRinvnid));
      }
      /* this code is to work around a bug is MS client 3 without
         introducing a security hole - it needs to be able to do
         print queue checks as guest if it isn't logged in properly */
      if (flags & AS_USER)
        flags &= ~AS_GUEST;

      /* does it need write permission? */
      if ((flags & NEED_WRITE) && !CAN_WRITE(cnum)){
	  	DEBUG(0,("fuck1!!!!!\n"));
        	return(ERROR_DOS(ERRSRV,ERRaccess));
	 //return(UNIXERROR(ERRDOS,ERRnoaccess));
      	}

#if 1
      /* ipc services are limited */
      if (IS_IPC(cnum) && (flags & AS_USER) && !(flags & CAN_IPC)) {
	  	DEBUG(0,("fuck2!!!!\n"));
        	return(ERROR_DOS(ERRSRV,ERRaccess));	    
      }
#endif

      /* load service specific parameters */
	if (OPEN_CNUM(cnum) && !become_service(cnum,(flags & AS_USER)?True:False)){
		DEBUG(0,("fuck3!!!!!\n"));
		return(ERROR_DOS(ERRSRV,ERRaccess));
	}

      /* does this protocol need to be run as guest? */
      if ((flags & AS_GUEST) && 
	  (!become_guest() || 
	   !check_access(-1))) {
	   	DEBUG(0,("fuck4!!!!!\n"));
        	return(ERROR_DOS(ERRSRV,ERRaccess));
      }

      last_inbuf = inbuf;

      outsize = smb_messages[type].fn(inbuf,outbuf,size,bufsize);
    }
   ///////////////////////////////////////////////////////////////////
   
    return(outsize);
}

/****************************************************************************
  construct a chained reply and add it to the already made reply
  **************************************************************************/
int chain_reply(char *inbuf,char *outbuf,int size,int bufsize)
{
	extern int chain_size;
	static char *orig_inbuf;
	static char *orig_outbuf;
	int smb_com1, smb_com2 = CVAL(inbuf,smb_vwv0);
	unsigned smb_off2 = SVAL(inbuf,smb_vwv1);
	char *inbuf2, *outbuf2;
	int outsize2;
	char inbuf_saved[smb_wct];
	char outbuf_saved[smb_wct];
	
	int wct = CVAL(outbuf,smb_wct);
	int outsize = smb_size + 2*wct + SVAL(outbuf,smb_vwv0+2*wct);

	/* maybe its not chained */
	if (smb_com2 == 0xFF) {
		SCVAL(outbuf,smb_vwv0,0xFF);
		return outsize;
	}

	if (chain_size == 0) {
		/* this is the first part of the chain */
		orig_inbuf = inbuf;
		orig_outbuf = outbuf;
	}

	/*
	 * The original Win95 redirector dies on a reply to
	 * a lockingX and read chain unless the chain reply is
	 * 4 byte aligned. JRA.
	 */

	outsize = (outsize + 3) & ~3;

	/* we need to tell the client where the next part of the reply will be */
	SSVAL(outbuf,smb_vwv1,smb_offset(outbuf+outsize,outbuf));
	SCVAL(outbuf,smb_vwv0,smb_com2);

	/* remember how much the caller added to the chain, only counting stuff
		after the parameter words */
	chain_size += outsize - smb_wct;

	/* work out pointers into the original packets. The
		headers on these need to be filled in */
	inbuf2 = orig_inbuf + smb_off2 + 4 - smb_wct;
	outbuf2 = orig_outbuf + SVAL(outbuf,smb_vwv1) + 4 - smb_wct;

	/* remember the original command type */
	smb_com1 = CVAL(orig_inbuf,smb_com);

	/* save the data which will be overwritten by the new headers */
	memcpy(inbuf_saved,inbuf2,smb_wct);
	memcpy(outbuf_saved,outbuf2,smb_wct);

	/* give the new packet the same header as the last part of the SMB */
	memmove(inbuf2,inbuf,smb_wct);

	/* create the in buffer */
	SCVAL(inbuf2,smb_com,smb_com2);

	/* create the out buffer */
	construct_reply_common(inbuf2, outbuf2);

	DEBUG(3,("Chained message\n"));
	show_msg(inbuf2);

	/* process the request */
	outsize2 = switch_message(smb_com2,inbuf2,outbuf2,size-chain_size,
				bufsize-chain_size);

	/* copy the new reply and request headers over the old ones, but
		preserve the smb_com field */
	memmove(orig_outbuf,outbuf2,smb_wct);
	SCVAL(orig_outbuf,smb_com,smb_com1);

	/* restore the saved data, being careful not to overwrite any
		data from the reply header */
	memcpy(inbuf2,inbuf_saved,smb_wct);

	{
		int ofs = smb_wct - PTR_DIFF(outbuf2,orig_outbuf);
		if (ofs < 0) ofs = 0;
			memmove(outbuf2+ofs,outbuf_saved+ofs,smb_wct-ofs);
	}

	return outsize2;
}

void construct_reply_common(char *inbuf,char *outbuf)
{
  memset(outbuf,'\0',smb_size);

  set_message(outbuf,0,0,True);
  SCVAL(outbuf,smb_com,CVAL(inbuf,smb_com));

  memcpy(outbuf+4,inbuf+4,4);
  SCVAL(outbuf,smb_rcls,SUCCESS);
  SCVAL(outbuf,smb_reh,0);
  SCVAL(outbuf,smb_flg, FLAG_REPLY | (CVAL(inbuf,smb_flg) & FLAG_CASELESS_PATHNAMES)); /* bit 7 set
                                 means a reply */
//  SSVAL(outbuf,smb_flg2,FLAGS2_LONG_PATH_COMPONENTS);

  SSVAL(outbuf,smb_flg2,
		(SVAL(inbuf,smb_flg2) & FLAGS2_UNICODE_STRINGS) |
		common_flags2);
	/* say we support long filenames */

  SSVAL(outbuf,smb_err,SUCCESS);
  SSVAL(outbuf,smb_tid,SVAL(inbuf,smb_tid));
  SSVAL(outbuf,smb_pid,SVAL(inbuf,smb_pid));
  SSVAL(outbuf,smb_uid,SVAL(inbuf,smb_uid));
  SSVAL(outbuf,smb_mid,SVAL(inbuf,smb_mid));
}


/****************************************************************************
  construct a reply to the incoming packet
****************************************************************************/
int construct_reply(char *inbuf,char *outbuf,int size,int bufsize)
{
  int type = CVAL(inbuf,smb_com);
  int outsize = 0;
  int msg_type = CVAL(inbuf,0);
  extern int chain_size;

  smb_last_time = time(NULL);

  chain_size = 0;
  chain_fnum = -1;
  
//  reset_chain_pnum();

  bzero(outbuf,smb_size);

  if (msg_type != 0)
    return(reply_special(inbuf,outbuf));  

  construct_reply_common(inbuf, outbuf);

  outsize = switch_message(type,inbuf,outbuf,size,bufsize);

  outsize += chain_size;

  if(outsize > 4)
    smb_setlen(outbuf,outsize - 4);
  return(outsize);
}


static BOOL timeout_processing(int deadtime, time_t *last_timeout_processing_time)
{
	int i;
	extern int Client;
  	static time_t last_smb_conf_reload_time = 0;
  	static time_t last_keepalive_sent_time = 0;
	static time_t last_idle_closed_check = 0;
	time_t t;
	BOOL allidle = True;
	extern int keepalive;

	if (smb_read_error == READ_EOF) 
	{
	    DEBUG(3,("end of file from client\n"));
	    return False;
	}

	 if (smb_read_error == READ_ERROR) 
	{
	    DEBUG(3,("receive_smb error (%s) exiting\n",
	              strerror(errno)));
	    return False;
	}

	*last_timeout_processing_time = t = time(NULL);

	if(last_smb_conf_reload_time == 0)
	    last_smb_conf_reload_time = t;

	if(last_keepalive_sent_time == 0)
	    last_keepalive_sent_time = t;

	if(last_idle_closed_check == 0)
	    last_idle_closed_check = t;

	  /* become root again if waiting */
	unbecome_user();

	  /* check for smb.conf reload */
	if (t >= last_smb_conf_reload_time + SMBD_RELOAD_CHECK)
	{
	    /* reload services, if files have changed. */
	    reload_services(True);
	    last_smb_conf_reload_time = t;
	}

	/* automatic timeout if all connections are closed */      
      if (num_connections_open==0 &&  (t - last_idle_closed_check)  >= IDLE_CLOSED_TIMEOUT) 
      {
        DEBUG(2,("Closing idle connection\n"));
        return False;
      }
      else
    	last_idle_closed_check = t;

	if (keepalive && (t - last_keepalive_sent_time)>keepalive) 
  	{
    		struct cli_state *cli = server_client();
    		if (!send_keepalive(Client)) {
      			DEBUG( 2, ( "Keepalive failed - exiting.\n" ) );
      			return False;
    		}	    
    /* also send a keepalive to the password server if its still
       connected */
    		if (cli && cli->initialised)
      			send_keepalive(cli->fd);
    		last_keepalive_sent_time = t;
  	}

	/* check for connection timeouts */
      for (i=0;i<MAX_CONNECTIONS;i++)
        if (Connections[i].open)
        {
          /* close dirptrs on connections that are idle */
          if ((t-Connections[i].lastused)>DPTR_IDLE_TIMEOUT)
            dptr_idlecnum(i);

          if (Connections[i].num_files_open > 0 ||
                     (t-Connections[i].lastused)<deadtime)
            allidle = False;
        }

      if (allidle && num_connections_open>0) 
      {
        DEBUG(2,("Closing idle connection 2\n"));
        return False;
      }

	return True;
}


/****************************************************************************
  process commands from the client
****************************************************************************/
void process(void)
{
  extern int Client;
  extern int smb_echo_count;
  time_t last_timeout_processing_time = time(NULL);
  unsigned int num_smbs = 0;

  InBuffer = (char *)malloc(BUFFER_SIZE + LARGE_WRITEX_HDR_SIZE + SAFETY_MARGIN);
  OutBuffer = (char *)malloc(BUFFER_SIZE + LARGE_WRITEX_HDR_SIZE + SAFETY_MARGIN);
  if ((InBuffer == NULL) || (OutBuffer == NULL)) 
    return;

  max_recv = MIN(lp_maxxmit(),BUFFER_SIZE);

  /* re-initialise the timezone */
  TimeInit();

  while (True)
  {
    int deadtime = lp_deadtime()*60;
    BOOL got_smb = False;
    int select_timeout = SMBD_SELECT_LOOP*1000;

    if (deadtime <= 0)
      deadtime = DEFAULT_SMBD_TIMEOUT;


    errno = 0;      

    while(!receive_message_or_smb(Client,
#ifdef OPLOCK_ENABLE
							oplock_sock,
#endif
							InBuffer, BUFFER_SIZE+LARGE_WRITEX_HDR_SIZE,
							select_timeout,&got_smb))
    {
      if(!timeout_processing( deadtime, &last_timeout_processing_time)){
	  	DEBUG(0,("timeout 0!!!!\n"));
       		return;
      	}
      num_smbs = 0; /* Reset smb counter. */
    }

    if(got_smb) {
      /*
       * Ensure we do timeout processing if the SMB we just got was
       * only an echo request. This allows us to set the select
       * timeout in 'receive_message_or_smb()' to any value we like
       * without worrying that the client will send echo requests
       * faster than the select timeout, thus starving out the
       * essential processing (change notify, blocking locks) that
       * the timeout code does. JRA.
       */ 
      int num_echos = smb_echo_count;

      process_smb(InBuffer, OutBuffer);

	DEBUG(0,("done process_smb!!!\n"));

      if(smb_echo_count != num_echos) {
       		if(!timeout_processing( deadtime, &last_timeout_processing_time)){
			DEBUG(0,("return from timeout 1!\n"));		
          		return;
       		}
        	num_smbs = 0; /* Reset smb counter. */
      }

      num_smbs++;

      /*
       * If we are getting smb requests in a constant stream
       * with no echos, make sure we attempt timeout processing
       * every select_timeout milliseconds - but only check for this
       * every 200 smb requests.
       */

      if((num_smbs % 200) == 0) {
        time_t new_check_time = time(NULL);
        if(last_timeout_processing_time - new_check_time >= (select_timeout/1000)) {
          if(!timeout_processing( deadtime, &last_timeout_processing_time)){
		  	DEBUG(0,("timeout 2\n"));
            		return;
          }
          num_smbs = 0; /* Reset smb counter. */
          last_timeout_processing_time = new_check_time; /* Reset time. */
        }
      }
    }
#ifdef OPLOCK_ENABLE
    else
      process_local_message(oplock_sock, InBuffer, BUFFER_SIZE);
#endif
  }
}

/****************************************************************************
  initialise connect, service and file structs
****************************************************************************/
static void init_structs(void )
{
  chain_fnum = -1;
  
  int i;
  get_myname(myhostname,NULL);

//I fix the smb workgroup name here. It seems we MUST give a name for it. So do not modify this
//unless you give the name somewhere else!!!!
  strcpy(myworkgroup, WORKGROUP);

//initialise the connection
  for (i=0;i<MAX_CONNECTIONS;i++)
    {
      Connections[i].open = False;
      Connections[i].num_files_open=0;
      Connections[i].lastused=0;
      Connections[i].used=False;
      string_init(&Connections[i].user,"");
      string_init(&Connections[i].dirpath,"");
      string_init(&Connections[i].connectpath,"");
      string_init(&Connections[i].origpath,"");
    }

//initialise the files
  for (i=0;i<MAX_OPEN_FILES;i++)
    {
      Files[i].open = False;
      string_init(&Files[i].name,"");

    }

  for (i=0;i<MAX_OPEN_FILES;i++)
    {
      file_fd_struct *fd_ptr = &FileFd[i];
      fd_ptr->ref_count = 0;
      fd_ptr->dev = (uint32)-1;
      fd_ptr->inode = (uint32)-1;
      fd_ptr->fd = -1;
      fd_ptr->fd_readonly = -1;
      fd_ptr->fd_writeonly = -1;
      fd_ptr->real_open_flags = -1;
    }

  init_dptrs();

  TimeZoneInit();
}

pid_t pidfile_pid(char *name)
{
	int fd;
	char pidstr[20];
	unsigned ret;
	pstring pidFile;

	sprintf(pidFile, "%s/%s.pid", lp_lockdir(), name);

	fd = open(pidFile, O_NONBLOCK | O_RDWR, 0644);
	if (fd == -1) {
		return 0;
	}

	ZERO_ARRAY(pidstr);

	if (read(fd, pidstr, sizeof(pidstr)-1) <= 0) {
		goto ok;
	}

	ret = atoi(pidstr);
	
	if (!process_exists((pid_t)ret)) {
		goto ok;
	}

	if (fcntl_lock(fd, F_SETLK, 0, 1, F_WRLCK)) {
		/* we could get the lock - it can't be a Samba process */
		goto ok;
	}

	close(fd);
	return (pid_t)ret;

 ok:
	close(fd);
	unlink(pidFile);
	return 0;
}

void pidfile_create(char *name)
{
	int     fd;
	char    buf[20];
	pstring pidFile;
	pid_t pid;

	sprintf(pidFile, "%s/%s.pid", lp_lockdir(), name);

	pid = pidfile_pid(name);
	if (pid != 0) {
		DEBUG(0,("ERROR: %s is already running. File %s exists and process id %d is running.\n", 
			 name, pidFile, (int)pid));
		exit(1);
	}

	fd = open(pidFile, O_NONBLOCK | O_CREAT | O_WRONLY | O_EXCL, 0644);
	if (fd == -1) {
		DEBUG(0,("ERROR: can't open %s: Error was %s\n", pidFile, 
			 strerror(errno)));
		exit(1);
	}

	if (fcntl_lock(fd, F_SETLK, 0, 1, F_WRLCK)==False) {
		DEBUG(0,("ERROR: %s : fcntl lock of file %s failed. Error was %s\n",  
              name, pidFile, strerror(errno)));
		exit(1);
	}

	memset(buf, 0, sizeof(buf));
	sprintf(buf, "%u\n", (unsigned int) sys_getpid());
	if (write(fd, buf, sizeof(buf)) != sizeof(buf)) {
		DEBUG(0,("ERROR: can't write to file %s: %s\n", 
			 pidFile, strerror(errno)));
		exit(1);
	}
	/* Leave pid file open & locked for the duration... */
}

/****************************************************************************
 * Provide a checksum on a string
 *
 *  Input:  s - the nul-terminated character string for which the checksum
 *              will be calculated.
 *  Output: The checksum value calculated for s.
 *
 ****************************************************************************/
int str_checksum(char *s)
{
  int res = 0;
  int c;
  int i=0;

  while( *s )
    {
    c = *s;
    res ^= (c << (i % 15)) ^ (c >> (15-(i%15)));
    s++; i++;
    }
  return(res);
} /* str_checksum */

/****************************************************************************
  main program
****************************************************************************/
int main(int argc,char *argv[])
{
  extern BOOL append_log;
  /* shall I run as a daemon */
  BOOL is_daemon = False;
  int port[2];
  port[0] = SMB_PORT1;
  port[1] = SMB_PORT2;
  int opt;
  extern char *optarg;
  char pidFile[100];

  *pidFile = '\0';

  append_log = True;
  
  timer_st = False;	//it is TRUE only if the timer starts
  //timer_mutex = True;

  TimeInit();

  strcpy(debugf,SMBLOGFILE);  

  setup_logging(argv[0],False);

//  charset_initialise();
   load_case_tables();

  /* make absolutely sure we run as root - to handle cases whre people
     are crazy enough to have it setuid */

  setresuid(0,0,0);	//gain root privilege
  setresgid(0,0,0);	//gain root group privilege
	
  fault_setup((void (*)(void *))exit_server);

  CatchSignal(SIGTERM , SIGNAL_CAST dflt_sig);
  CatchSignal(SIGHUP,SIGNAL_CAST sig_hup);
  CatchSignal(SIGUSR1, SIGNAL_CAST reset_timer);
//  CatchSignal(16, SIGNAL_CAST reset_timezone);
  CatchSignal(SIGUSR2, SIGNAL_CAST sync_timer);

//we are not interesting in SIGPIPE!
  BlockSignals(True,SIGPIPE);
  
  BlockSignals(False, SIGHUP);
  BlockSignals(False, SIGUSR1);
  BlockSignals(False, SIGUSR2);
  BlockSignals(False, SIGTERM);

  /* we want total control over the permissions on created files,
     so set our umask to 0 */
  umask(0);

  GetWd(OriginalDir);

  init_uid();

  int smbpasswd_flag = 0;
  pstring  smbpwd_user_name;
  fstring   smb_new_passwd;

  /* this is for people who can't start the program correctly */
	/* this is for people who can't start the program correctly */
	while (argc > 1 && (*argv[1] != '-')) {
		argv++;
		argc--;
	}

/*
 *	USAGE: run smbd -D [-s <config file> -p <PORT>] as the basic smb application
 *		     run smbd -P <passwd> -a <user_name> as smbpasswd application
*/
	while ( EOF != (opt = getopt(argc, argv, "s:Dp:P:a:")) )	
		switch (opt)  {
		case 's':
			pstrcpy(servicesf,optarg);
			break;

		case 'D':
			is_daemon = True;
			break;

		case 'p':
			port[0] = atoi(optarg);
			port[1] = 0;	//user defines the port, so we only open the specified port
			break;

                case 'P':
			pstrcpy(smb_new_passwd, optarg);
			smbpasswd_flag++;
			break;
			
		case 'a':
			pstrcpy(smbpwd_user_name, optarg);			
//			pwd = getpwnam(smbpwd_user_name);
			smbpasswd_flag++;
			break;

		default:
			DEBUG(0,("Incorrect program usage - are you sure the command line is correct?\n"));
//			usage(argv[0]);
			exit(1);
		}

        if((smbpasswd_flag != 0) && (smbpasswd_flag != 2)){
		DEBUG(0,("wrong parameters!\n"));
		exit(1);
	}

	if(smbpasswd_flag == 2){		//act as smbpasswd!
		int smbpwd_res = do_smbpasswd(smbpwd_user_name, smb_new_passwd);
		exit(smbpwd_res);
	}

  reopen_logs();

  DEBUG(2,("uid=%d gid=%d euid=%d egid=%d\n",
		getuid(),getgid(),geteuid(),getegid()));

  if (sizeof(uint16) < 2 || sizeof(uint32) < 4)
    {
      DEBUG(0,("ERROR: Samba is not configured correctly for the word size on your machine\n"));
      exit(1);
    }

  init_structs();

  if (!reload_services(False))
    return(-1);	

//  codepage_initialise(lp_client_code_page());	//TODO: maybe we could do something for the reducing...

#if 0
  /* Setup the signals that allow the debug log level
     to by dynamically changed. useless....only for debug mode :)*/
 
#if defined(SIGUSR1)
  CatchSignal( SIGUSR1, SIGNAL_CAST sig_usr1 );
#endif /* SIGUSR1 */
   
#if defined(SIGUSR2)
  CatchSignal( SIGUSR2, SIGNAL_CAST sig_usr2 );
#endif /* SIGUSR2 */
#endif

  DEBUG(3,("%s loaded services\n",timestring()));

  if (!is_daemon && !is_a_socket(0))
    {
      DEBUG(0,("standard input is not a socket, assuming -D option\n"));
      is_daemon = True;
    }

  if (is_daemon)
    {
      DEBUG(3,("%s becoming a daemon\n",timestring()));
      become_daemon();
    }

  if (!directory_exist(lp_lockdir(), NULL)) {
	  mkdir(lp_lockdir(), 0755);
  }

  if (is_daemon) {
	pidfile_create("smbd");
  }

  m_pid = sys_getpid();
  DEBUG(0,("#####smbd pid: %d\n", m_pid));
  
  if (!open_sockets(is_daemon,port))
    exit(1);

  if (!locking_init(0))
    exit(1);

  /* possibly reload the services file. */
  reload_services(True);

  if (*lp_rootdir())
    {
      if (sys_chroot(lp_rootdir()) == 0)
	DEBUG(2,("%s changed root to %s\n",timestring(),lp_rootdir()));
    }

#ifdef OPLOCK_ENABLE		//by default we trun oplock off....
  /* Setup the oplock IPC socket. */
  if(!open_oplock_ipc())
    exit(1);
#endif

  process();	//To save the resource on our system, we only run the master process on port 455!
  close_sockets();

  exit_server("normal exit");
  return(0);
}



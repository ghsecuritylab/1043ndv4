/* 
   Unix SMB/Netbios implementation.
   Version based 3.0.
   Samba system utilities
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

extern int DEBUGLEVEL;
extern connection_struct Connections[];
extern BOOL case_sensitive;
extern BOOL case_preserve;
extern BOOL short_case_preserve;


/*
   The idea is that this file will eventually have wrappers around all
   important system calls in samba. The aims are:

   - to enable easier porting by putting OS dependent stuff in here

   - to allow for hooks into other "pseudo-filesystems"

   - to allow easier integration of things like the japanese extensions

   - to support the philosophy of Samba to expose the features of
     the OS within the SMB model. In general whatever file/printer/variable
     expansions/etc make sense to the OS should be acceptable to Samba.
*/

static int select_pipe[2];
static pid_t initialised;
static pid_t mypid = (pid_t)-1;
static volatile unsigned pipe_written, pipe_read;

/*******************************************************************
this replaces the normal select() system call
return if some data has arrived on one of the file descriptors
return -1 means error
********************************************************************/
void sys_select_signal(void)
{
	char c = 1;
	if (!initialised) return;

	if (pipe_written > pipe_read+256) return;

	if (write(select_pipe[1], &c, 1) == 1) pipe_written++;
}


pid_t sys_getpid(void)
{
	if (mypid == (pid_t)-1)
		mypid = getpid();

	return mypid;
}

pid_t sys_fork(void)
{
	DEBUG(0,("=========>###%s\n", __FUNCTION__));
	pid_t forkret = fork();

	if (forkret == (pid_t)0) /* Child - reset mypid so sys_getpid does a system call. */
		mypid = (pid_t) -1;

	return forkret;
}

int sys_select(int maxfd, fd_set *readfds, fd_set *writefds, fd_set *errorfds, struct timeval *tval)
{
	int ret, saved_errno;
	fd_set *readfds2, readfds_buf;

	if (initialised != sys_getpid()) {
		pipe(select_pipe);

		/*
		 * These next two lines seem to fix a bug with the Linux
		 * 2.0.x kernel (and probably other UNIXes as well) where
		 * the one byte read below can block even though the
		 * select returned that there is data in the pipe and
		 * the pipe_written variable was incremented. Thanks to
		 * HP for finding this one. JRA.
		 */

		if(set_blocking(select_pipe[0],0)==-1)
			DEBUG(0,("select_pipe[0]: O_NONBLOCK failed.\n"));
		if(set_blocking(select_pipe[1],0)==-1)
			DEBUG(0,("select_pipe[1]: O_NONBLOCK failed.\n"));

		initialised = sys_getpid();
	}

	maxfd = MAX(select_pipe[0]+1, maxfd);

	/* If readfds is NULL we need to provide our own set. */
	if (readfds) {
		readfds2 = readfds;
	} else {
		readfds2 = &readfds_buf;
		FD_ZERO(readfds2);
	}
	FD_SET(select_pipe[0], readfds2);

	errno = 0;
	ret = select(maxfd,readfds2,writefds,errorfds,tval);

	if (ret <= 0) {
		FD_ZERO(readfds2);
		if (writefds)
			FD_ZERO(writefds);
		if (errorfds)
			FD_ZERO(errorfds);
	}

	if (FD_ISSET(select_pipe[0], readfds2)) {
		char c;
		saved_errno = errno;
		if (read(select_pipe[0], &c, 1) == 1) {
			pipe_read++;
		}
		errno = saved_errno;
		FD_CLR(select_pipe[0], readfds2);
		ret--;
		if (ret == 0) {
			ret = -1;
			errno = EINTR;
		}
	}

	return ret;
}

int mkdir_wrapper(const char *name, mode_t mode)
{
	int ret;
	SMB_STRUCT_STAT sbuf;

	if(!(ret=sys_mkdir(name, mode))) {

		/*
		 * Check if high bits should have been set,
		 * then (if bits are missing): add them.
		 * Consider bits automagically set by UNIX, i.e. SGID bit from parent dir.
		 */
		if(mode & ~(S_IRWXU|S_IRWXG|S_IRWXO) &&
				!sys_stat(name,&sbuf) && (mode & ~sbuf.st_mode))
			chmod(name,sbuf.st_mode | (mode & ~sbuf.st_mode));
	}
	return ret;
}

/*******************************************************************
now for utime()
********************************************************************/
int sys_utime(char *fname,struct utimbuf *times)
{
  /* if the modtime is 0 or -1 then ignore the call and
     return success */
  if (times->modtime == (time_t)0 || times->modtime == (time_t)-1)
    return 0;
  
  /* if the access time is 0 or -1 then set it to the modtime */
  if (times->actime == (time_t)0 || times->actime == (time_t)-1)
    times->actime = times->modtime;
   
  return(utime(dos_to_unix(fname,False),times));
}

/*********************************************************
for rename across filesystems Patch from Warren Birnbaum 
<warrenb@hpcvscdp.cv.hp.com>
**********************************************************/

static int copy_reg(char *source, const char *dest)
{
  SMB_STRUCT_STAT source_stats;
  int ifd;
  int full_write();
  int safe_read();
  int ofd;
  char *buf;
  int len;                      /* Number of bytes read into `buf'. */

  sys_lstat (source, &source_stats);
  if (!S_ISREG (source_stats.st_mode))
    {
      return 1;
    }

  if (unlink (dest) && errno != ENOENT)
    {
      return 1;
    }

  if((ifd = open (source, O_RDONLY, 0)) < 0)
    {
      return 1;
    }
  if((ofd = open (dest, O_WRONLY | O_CREAT | O_TRUNC, 0600)) < 0 )
    {
      close (ifd);
      return 1;
    }

  if((buf = malloc( COPYBUF_SIZE )) == NULL)
    {
      close (ifd);  
      close (ofd);  
      unlink (dest);
      return 1;
    }

  while ((len = read(ifd, buf, COPYBUF_SIZE)) > 0)
    {
      if (write_data(ofd, buf, len) < 0)
        {
          close (ifd);
          close (ofd);
          unlink (dest);
          free(buf);
          return 1;
        }
    }
  free(buf);
  if (len < 0)
    {
      close (ifd);
      close (ofd);
      unlink (dest);
      return 1;
    }

  if (close (ifd) < 0)
    {
      close (ofd);
      return 1;
    }
  if (close (ofd) < 0)
    {
      return 1;
    }

  /* chown turns off set[ug]id bits for non-root,
     so do the chmod last.  */

  /* Try to copy the old file's modtime and access time.  */
  {
    struct utimbuf tv;

    tv.actime = source_stats.st_atime;
    tv.modtime = source_stats.st_mtime;
    if (utime (dest, &tv))
      {
        return 1;
      }
  }

  /* Try to preserve ownership.  For non-root it might fail, but that's ok.
     But root probably wants to know, e.g. if NFS disallows it.  */
  if (chown (dest, source_stats.st_uid, source_stats.st_gid)
      && (errno != EPERM))
    {
      return 1;
    }

  if (chmod (dest, source_stats.st_mode & 07777))
    {
      return 1;
    }
  unlink (source);
  return 0;
}

/*******************************************************************
for rename()
********************************************************************/
int sys_rename(char *from, char *to)
{
    int rcode;  
    pstring zfrom, zto;

    pstrcpy (zfrom, dos_to_unix (from, False));
    pstrcpy (zto, dos_to_unix (to, False));
    rcode = rename (zfrom, zto);

    if (errno == EXDEV) 
      {
        /* Rename across filesystems needed. */
        rcode = copy_reg (zfrom, zto);        
      }
    return rcode;
}

/**************************************************************************
A wrapper for gethostbyname() that tries avoids looking up hostnames 
in the root domain, which can cause dial-on-demand links to come up for no
apparent reason.
****************************************************************************/
struct hostent *sys_gethostbyname(char *name)
{
#ifdef REDUCE_ROOT_DNS_LOOKUPS
  char query[256], hostname[256];
  char *domain;

  /* Does this name have any dots in it? If so, make no change */

  if (strchr_m(name, '.'))
    return(gethostbyname(name));

  /* Get my hostname, which should have domain name 
     attached. If not, just do the gethostname on the
     original string. 
  */

  gethostname(hostname, sizeof(hostname) - 1);
  hostname[sizeof(hostname) - 1] = 0;
  if ((domain = strchr_m(hostname, '.')) == NULL)
    return(gethostbyname(name));

  /* Attach domain name to query and do modified query.
     If names too large, just do gethostname on the
     original string.
  */

  if((strlen(name) + strlen(domain)) >= sizeof(query))
    return(gethostbyname(name));

  sprintf(query, "%s%s", name, domain);
  return(gethostbyname(query));
#else /* REDUCE_ROOT_DNS_LOOKUPS */
  return(gethostbyname(name));
#endif /* REDUCE_ROOT_DNS_LOOKUPS */
}

int check_dir(char* fname)
{
	SMB_STRUCT_STAT buf;
	
	if(!sys_stat(fname, &buf))
		return (S_ISDIR(buf.st_mode)?1:0);

	return -1;
}

static int do_reseed(int fd)
{
	fd = open( "/dev/urandom", O_RDONLY, 0);
	if(fd >= 0)
		return fd;
}

void generate_random_buffer( unsigned char *out, int len)
{
	int urand_fd = -1;
	unsigned char md4_buf[64];
	unsigned char tmp_buf[16];
	unsigned char *p;

	urand_fd = do_reseed(urand_fd);

	if (urand_fd != -1 && len > 0) {
		if (read(urand_fd, out, len) == len){
			close(urand_fd);
			return; /* len bytes of random data read from urandom. */
		}
	}
	else
		DEBUG(0,("######fucked up#########\n"));
}

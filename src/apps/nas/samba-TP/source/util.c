/* 
   Unix SMB/Netbios implementation.
   Version based 3.0.
   Samba utility functions
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

pstring scope = "";

int DEBUGLEVEL = 1;

BOOL passive = False;

int Protocol = PROTOCOL_COREPLUS;

/* a default finfo structure to ensure all fields are sensible */
file_info def_finfo = {-1,0,0,0,0,0,0,""};

/* these are some file handles where debug info will be stored */
FILE *dbf = NULL;

/* the client file descriptor */
int Client = -1;

/* the last IP received from */
struct in_addr lastip;

/* the last port received from */
int lastport=0;

/* this is used by the chaining code */
int chain_size = 0;

int trans_num = 0;

char magic_char = '~';

pstring debugf = "";
int syslog_level;

/* the following control case operations - they are put here so the
   client can link easily */
BOOL case_sensitive;
BOOL case_preserve;
BOOL use_mangled_map = False;
BOOL short_case_preserve;
BOOL case_mangle;

fstring remote_machine="";
fstring local_machine="";
fstring remote_arch="UNKNOWN";
static enum remote_arch_types ra_type = RA_UNKNOWN;
fstring remote_proto="UNKNOWN";
pstring myhostname="";
pstring user_socket_options="";   

pstring sesssetup_user="";
pstring samlogon_user="";

BOOL sam_logon_in_ssb = False;

pstring myname = "";
fstring myworkgroup = "";
char **my_netbios_names;

int smb_read_error = 0;

static BOOL stdout_logging = False;

/*########################################################*/

static char *filename_dos(char *path,char *buf);

BOOL append_log=False;


/****************************************************************************
reopen the log files
****************************************************************************/
void reopen_logs(void)
{
#ifdef _DEBUG
  extern FILE *dbf;
  pstring fname;
  
  if (DEBUGLEVEL > 0)
    {
      strcpy(fname,debugf);
      if (lp_loaded() && (*lp_logfile()))
	strcpy(fname,lp_logfile());

      if (!strcsequal(fname,debugf) || !dbf || !file_exist(debugf,NULL))
	{
	  int oldumask = umask(022);
	  strcpy(debugf,fname);
	  if (dbf) fclose(dbf);
	  if (append_log)
	    dbf = fopen(debugf,"a");
	  else
	    dbf = fopen(debugf,"w");
	  if (dbf) setbuf(dbf,NULL);
	  umask(oldumask);
	}
    }
  else
    {
      if (dbf)
	{
	  fclose(dbf);
	  dbf = NULL;
	}
    }
#endif	/*_DEBUG*/
}

/*******************************************************************
check if the log has grown too big
********************************************************************/
static void check_log_size(void)
{
#ifdef _DEBUG
  static int debug_count=0;
  int maxlog;
  struct stat st;

  if (debug_count++ < 100 || getuid() != 0) return;

  maxlog = lp_max_log_size() * 1024;
  
  if (!dbf || maxlog <= 0) 
  	return;

  if (fstat(fileno(dbf),&st) == 0 && st.st_size > maxlog) {
    fclose(dbf); 
    dbf = NULL;
    reopen_logs();
    if (dbf && file_size(debugf) > maxlog) {
      pstring name;
      fclose(dbf); dbf = NULL;
      sprintf(name,"%s.old",debugf);
      sys_rename(debugf,name);
      reopen_logs();
    }
  }
  debug_count=0;
#endif	/*_DEBUG*/
}


/*******************************************************************
write an debug message on the debugfile. This is called by the DEBUG
macro
********************************************************************/
#ifdef _DEBUG
#ifdef __STDC__
 int Debug1(char *format_str, ...)
{
#else
 int Debug1(va_alist)
va_dcl
{  
  char *format_str;
#endif
  va_list ap;  
  int old_errno = errno;

  if (stdout_logging) {
#ifdef __STDC__
    va_start(ap, format_str);
#else
    va_start(ap);
    format_str = va_arg(ap,char *);
#endif
    vfprintf(dbf,format_str,ap);
    va_end(ap);
    errno = old_errno;
    return(0);
  }
  
#ifdef SYSLOG
  if (!lp_syslog_only())
#endif  
    {
      if (!dbf) {
	      int oldumask = umask(022);
	      dbf = fopen(debugf,"w");
	      umask(oldumask);
	      if (dbf) {
		      setbuf(dbf,NULL);
	      } else {
		      errno = old_errno;
		      return(0);
	      }
      }
    }

#ifdef SYSLOG
  if (syslog_level < lp_syslog())
    {
      /* 
       * map debug levels to syslog() priorities
       * note that not all DEBUG(0, ...) calls are
       * necessarily errors
       */
      static int priority_map[] = { 
	LOG_ERR,     /* 0 */
	LOG_WARNING, /* 1 */
	LOG_NOTICE,  /* 2 */
	LOG_INFO,    /* 3 */
      };
      int priority;
      pstring msgbuf;
      
      if (syslog_level >= sizeof(priority_map) / sizeof(priority_map[0]) ||
	  syslog_level < 0)
	priority = LOG_DEBUG;
      else
	priority = priority_map[syslog_level];
      
#ifdef __STDC__
      va_start(ap, format_str);
#else
      va_start(ap);
      format_str = va_arg(ap,char *);
#endif
      vsprintf(msgbuf, format_str, ap);
      va_end(ap);
      
      msgbuf[255] = '\0';
      syslog(priority, "%s", msgbuf);
    }
#endif
  
#ifdef SYSLOG
  if (!lp_syslog_only())
#endif
    {
#ifdef __STDC__
      va_start(ap, format_str);
#else
      va_start(ap);
      format_str = va_arg(ap,char *);
#endif
      vfprintf(dbf,format_str,ap);
      va_end(ap);
      fflush(dbf);
    }

  check_log_size();

  errno = old_errno;

  return(0);
}
#endif	/*_DEBUG*/


/****************************************************************************
  find a suitable temporary directory. The result should be copied immediately
  as it may be overwritten by a subsequent call
  ****************************************************************************/
char *tmpdir(void)
{
  char *p;
  if ((p = getenv("TMPDIR"))) {
    return p;
  }
  return "/tmp";	//tmp dir for our samba
}



/****************************************************************************
determine if a file descriptor is in fact a socket
****************************************************************************/
BOOL is_a_socket(int fd)
{
  int v,l;
  l = sizeof(int);
  return(getsockopt(fd, SOL_SOCKET, SO_TYPE, (char *)&v, &l) == 0);
}


static const char *last_ptr=NULL;

/****************************************************************************
  Get the next token from a string, return False if none found
  handles double-quotes. 
Based on a routine by GJC@VILLAGE.COM. 
Extensively modified by Andrew.Tridgell@anu.edu.au
****************************************************************************/
BOOL next_token(const char **ptr,char *buff,const char *sep)
{
  const char *s;
  BOOL quoted;

  if (!ptr) ptr = &last_ptr;
  if (!ptr) return(False);

  s = *ptr;

  /* default to simple separators */
  if (!sep) sep = " \t\n\r";

  /* find the first non sep char */
  while(*s && strchr_m(sep,*s)) s++;

  /* nothing left? */
  if (! *s) return(False);

  /* copy over the token */
  for (quoted = False; *s && (quoted || !strchr_m(sep,*s)); s++)
    {
      if (*s == '\"') 
	quoted = !quoted;
      else
	*buff++ = *s;
    }

  *ptr = (*s) ? s+1 : s;  
  *buff = 0;
  last_ptr = *ptr;

  return(True);
}

#if 0
/****************************************************************************
Convert list of tokens to array; dependent on above routine.
Uses last_ptr from above - bit of a hack.
****************************************************************************/
char **toktocliplist(int *ctok, char *sep)
{
  char *s=last_ptr;
  int ictok=0;
  char **ret, **iret;

  if (!sep) sep = " \t\n\r";

  while(*s && strchr_m(sep,*s)) s++;

  /* nothing left? */
  if (!*s) return(NULL);

  do {
    ictok++;
    while(*s && (!strchr_m(sep,*s))) s++;
    while(*s && strchr_m(sep,*s)) *s++=0;
  } while(*s);

  *ctok=ictok;
  s=last_ptr;

  if (!(ret=iret=malloc(ictok*sizeof(char *)))) return NULL;
  
  while(ictok--) {    
    *iret++=s;
    while(*s++);
    while(!*s) s++;
  }

  return ret;
}
#endif

#if 0		//we have memmove
#ifndef HAVE_MEMMOVE
/*******************************************************************
safely copies memory, ensuring no overlap problems.
this is only used if the machine does not have it's own memmove().
this is not the fastest algorithm in town, but it will do for our
needs.
********************************************************************/
void *MemMove(void *dest,void *src,int size)
{
  unsigned long d,s;
  int i;
  if (dest==src || !size) return(dest);

  d = (unsigned long)dest;
  s = (unsigned long)src;

  if ((d >= (s+size)) || (s >= (d+size))) {
    /* no overlap */
    memcpy(dest,src,size);
    return(dest);
  }

  if (d < s)
    {
      /* we can forward copy */
      if (s-d >= sizeof(int) && 
	  !(s%sizeof(int)) && !(d%sizeof(int)) && !(size%sizeof(int))) {
	/* do it all as words */
	int *idest = (int *)dest;
	int *isrc = (int *)src;
	size /= sizeof(int);
	for (i=0;i<size;i++) idest[i] = isrc[i];
      } else {
	/* simplest */
	char *cdest = (char *)dest;
	char *csrc = (char *)src;
	for (i=0;i<size;i++) cdest[i] = csrc[i];
      }
    }
  else
    {
      /* must backward copy */
      if (d-s >= sizeof(int) && 
	  !(s%sizeof(int)) && !(d%sizeof(int)) && !(size%sizeof(int))) {
	/* do it all as words */
	int *idest = (int *)dest;
	int *isrc = (int *)src;
	size /= sizeof(int);
	for (i=size-1;i>=0;i--) idest[i] = isrc[i];
      } else {
	/* simplest */
	char *cdest = (char *)dest;
	char *csrc = (char *)src;
	for (i=size-1;i>=0;i--) cdest[i] = csrc[i];
      }      
    }
  return(dest);
}
#endif
#endif

/****************************************************************************
prompte a dptr (to make it recently used)
****************************************************************************/
void array_promote(char *array,int elsize,int element)
{
  char *p;
  if (element == 0)
    return;

  p = (char *)malloc(elsize);

  if (!p)
    {
      DEBUG(5,("Ahh! Can't malloc\n"));
      return;
    }
  memcpy(p,array + element * elsize, elsize);
  memmove(array + elsize,array,elsize*element);
  memcpy(array,p,elsize);
  free(p);
}

enum SOCK_OPT_TYPES {OPT_BOOL,OPT_INT,OPT_ON};

struct
{
  char *name;
  int level;
  int option;
  int value;
  int opttype;
} socket_options[] = {
  {"SO_KEEPALIVE",      SOL_SOCKET,    SO_KEEPALIVE,    0,                 OPT_BOOL},
  {"SO_REUSEADDR",      SOL_SOCKET,    SO_REUSEADDR,    0,                 OPT_BOOL},
  {"SO_BROADCAST",      SOL_SOCKET,    SO_BROADCAST,    0,                 OPT_BOOL},
#ifdef TCP_NODELAY
  {"TCP_NODELAY",       IPPROTO_TCP,   TCP_NODELAY,     0,                 OPT_BOOL},
#endif
#ifdef IPTOS_LOWDELAY
  {"IPTOS_LOWDELAY",    IPPROTO_IP,    IP_TOS,          IPTOS_LOWDELAY,    OPT_ON},
#endif
#ifdef IPTOS_THROUGHPUT
  {"IPTOS_THROUGHPUT",  IPPROTO_IP,    IP_TOS,          IPTOS_THROUGHPUT,  OPT_ON},
#endif
#ifdef SO_SNDBUF
  {"SO_SNDBUF",         SOL_SOCKET,    SO_SNDBUF,       0,                 OPT_INT},
#endif
#ifdef SO_RCVBUF
  {"SO_RCVBUF",         SOL_SOCKET,    SO_RCVBUF,       0,                 OPT_INT},
#endif
#ifdef SO_SNDLOWAT
  {"SO_SNDLOWAT",       SOL_SOCKET,    SO_SNDLOWAT,     0,                 OPT_INT},
#endif
#ifdef SO_RCVLOWAT
  {"SO_RCVLOWAT",       SOL_SOCKET,    SO_RCVLOWAT,     0,                 OPT_INT},
#endif
#ifdef SO_SNDTIMEO
  {"SO_SNDTIMEO",       SOL_SOCKET,    SO_SNDTIMEO,     0,                 OPT_INT},
#endif
#ifdef SO_RCVTIMEO
  {"SO_RCVTIMEO",       SOL_SOCKET,    SO_RCVTIMEO,     0,                 OPT_INT},
#endif
  {NULL,0,0,0,0}};

	

/****************************************************************************
set user socket options
****************************************************************************/
void set_socket_options(int fd, const char *options)
{
  char tok[128];

  while (next_token(&options,tok," \t,"))
    {
      int ret=0,i;
      int value = 1;
      char *p;
      BOOL got_value = False;

      if ((p = strchr_m(tok,'=')))
	{
	  *p = 0;
	  value = atoi(p+1);
	  got_value = True;
	}

      for (i=0;socket_options[i].name;i++)
	if (strequal(socket_options[i].name,tok))
	  break;

      if (!socket_options[i].name)
	{
	  DEBUG(0,("Unknown socket option %s\n",tok));
	  continue;
	}

      switch (socket_options[i].opttype)
	{
	case OPT_BOOL:
	case OPT_INT:
	  ret = setsockopt(fd,socket_options[i].level,
			   socket_options[i].option,(char *)&value,sizeof(int));
	  break;

	case OPT_ON:
	  if (got_value)
	    DEBUG(0,("syntax error - %s does not take a value\n",tok));

	  {
	    int on = socket_options[i].value;
	    ret = setsockopt(fd,socket_options[i].level,
			     socket_options[i].option,(char *)&on,sizeof(int));
	  }
	  break;	  
	}
      
      if (ret != 0)
	DEBUG(0,("Failed to set socket option %s\n",tok));
    }
}



/****************************************************************************
  close the socket communication
****************************************************************************/
void close_sockets(void )
{
  close(Client);
  Client = 0;
}

/****************************************************************************
determine whether we are in the specified group
****************************************************************************/
BOOL in_group(gid_t group, int current_gid, int ngroups, int *groups)
{
  int i;

  if (group == current_gid) return(True);

  for (i=0;i<ngroups;i++)
    if (group == groups[i])
      return(True);

  return(False);
}

/*******************************************************************
copy an IP address from one buffer to another
********************************************************************/
void putip(void *dest,void *src)
{
  memcpy(dest,src,4);
}


/****************************************************************************
interpret the weird netbios "name". Return the name type
****************************************************************************/
static int name_interpret(char *in,char *out)
{
  int ret;
  int len = (*in++) / 2;

  *out=0;

  if (len > 30 || len<1) return(0);

  while (len--)
    {
      if (in[0] < 'A' || in[0] > 'P' || in[1] < 'A' || in[1] > 'P') {
	*out = 0;
	return(0);
      }
      *out = ((in[0]-'A')<<4) + (in[1]-'A');
      in += 2;
      out++;
    }
  *out = 0;
  ret = out[-1];

#ifdef NETBIOS_SCOPE
  /* Handle any scope names */
  while(*in) 
    {
      *out++ = '.'; /* Scope names are separated by periods */
      len = *(unsigned char *)in++;
      StrnCpy(out, in, len);
      out += len;
      *out=0;
      in += len;
    }
#endif
  return(ret);
}

/*******************************************************************
  check if a file exists
********************************************************************/
BOOL file_exist(char *fname,SMB_STRUCT_STAT *sbuf)
{
  SMB_STRUCT_STAT st;
  if (!sbuf) sbuf = &st;
  
  if (sys_stat(fname,sbuf) != 0){
  	DEBUG(0,("stat failed when checking file exist!\n"));
    	return(False);
  }

//I guess we only need to check files or dirs whether they exist.....
  return(S_ISREG(sbuf->st_mode) || S_ISDIR(sbuf->st_mode));
}

/*******************************************************************
check a files mod time
********************************************************************/
time_t file_modtime(char *fname)
{
  SMB_STRUCT_STAT st;
  
  if (sys_stat(fname,&st) != 0) 
    return(0);

  return(st.st_mtime);
}

/*******************************************************************
  check if a directory exists
********************************************************************/
BOOL directory_exist(char *dname,SMB_STRUCT_STAT *st)
{
  SMB_STRUCT_STAT st2;
  BOOL ret;

  if (!st) st = &st2;

  if (sys_stat(dname,st) != 0) 
    return(False);

  ret = S_ISDIR(st->st_mode);
  if(!ret)
    errno = ENOTDIR;
  return ret;
}

/*******************************************************************
returns the size in bytes of the named file
********************************************************************/
uint32 file_size(char *file_name)
{
  SMB_STRUCT_STAT buf;
  buf.st_size = 0;
  sys_stat(file_name,&buf);
  return(buf.st_size);
}


/*******************************************************************
  show a smb message structure
********************************************************************/
void show_msg(char *buf)
{
#ifdef _DEBUG
  int i;
  int bcc=0;

  if (DEBUGLEVEL < 5) return;

  DEBUG(5,("size=%d\nsmb_com=0x%x\nsmb_rcls=%d\nsmb_reh=%d\nsmb_err=%d\nsmb_flg=%d\nsmb_flg2=%d\n",
	  smb_len(buf),
	  (int)CVAL(buf,smb_com),
	  (int)CVAL(buf,smb_rcls),
	  (int)CVAL(buf,smb_reh),
	  (int)SVAL(buf,smb_err),
	  (int)CVAL(buf,smb_flg),
	  (int)SVAL(buf,smb_flg2)));
  DEBUG(5,("smb_tid=%d\nsmb_pid=%d\nsmb_uid=%d\nsmb_mid=%d\nsmt_wct=%d\n",
	  (int)SVAL(buf,smb_tid),
	  (int)SVAL(buf,smb_pid),
	  (int)SVAL(buf,smb_uid),
	  (int)SVAL(buf,smb_mid),
	  (int)CVAL(buf,smb_wct)));

  for (i=0;i<(int)CVAL(buf,smb_wct);i++)
    DEBUG(5,("smb_vwv[%d]=%d (0x%X)\n",i,
	  SVAL(buf,smb_vwv+2*i),SVAL(buf,smb_vwv+2*i)));

  bcc = (int)SVAL(buf,smb_vwv+2*(CVAL(buf,smb_wct)));
  DEBUG(5,("smb_bcc=%d\n",bcc));

  if (DEBUGLEVEL < 10) return;

  dump_data(10, smb_buf(buf), MIN(bcc, 512));
#endif	/*_DEBUG*/
}


/*******************************************************************
  set the length and marker of an smb packet
********************************************************************/
void smb_setlen(char *buf,int len)
{
  _smb_setlen(buf,len);

  SCVAL(buf,4, 0XFF);
  SCVAL(buf,5, 'S');
  SCVAL(buf,6, 'M');
  SCVAL(buf,7, 'B');
}

/*******************************************************************
  setup the word count and byte count for a smb message
********************************************************************/
int set_message(char *buf,int num_words,int num_bytes,BOOL zero)
{
  if (zero)
    bzero(buf + smb_size,num_words*2 + num_bytes);
  SCVAL(buf,smb_wct, num_words);
  SSVAL(buf,smb_vwv + num_words*SIZEOFWORD,num_bytes);  
  smb_setlen(buf,smb_size + num_words*2 + num_bytes - 4);
  return (smb_size + num_words*2 + num_bytes);
}

/*******************************************************************
reduce a file name, removing .. elements. 
********************************************************************/
void unix_clean_name(char *s)
{
  char *p=NULL;

  DEBUG(3,("unix_clean_name [%s]\n",s));

  /* remove any double slashes */
  string_sub(s, "//","/");

  /* Remove leading ./ characters */
  if(strncmp(s, "./", 2) == 0) {
    trim_string(s, "./", NULL);
    if(*s == 0)
      strcpy(s,"./");
  }

  while ((p = strstr_m(s,"/../")) != NULL)
    {
      pstring s1;

      *p = 0;
      pstrcpy(s1,p+3);

      if ((p=strrchr_m(s,'/')) != NULL)
	*p = 0;
      else
	*s = 0;
      strcat(s,s1);
    }  

  trim_string(s,NULL,"/..");
}

/*******************************************************************
a wrapper for the normal chdir() function
********************************************************************/
int ChDir(char *path)
{
  int res;
  static pstring LastDir="";

  if (strcsequal(path,".")) return(0);

  if (*path == '/' && strcsequal(LastDir,path)) return(0);
  DEBUG(3,("chdir to %s\n",path));
//  path = dos2unix_format(path,False);	//Do not need this now???
  res = sys_chdir(path);
  if (!res)
    pstrcpy(LastDir,path);
  return(res);
}

/* number of list structures for a caching GetWd function. */
#define MAX_GETWDCACHE (50)

struct
{
  SMB_INO_T inode;
  SMB_DEV_T dev;
  char *text;
  BOOL valid;
} ino_list[MAX_GETWDCACHE];

BOOL use_getwd_cache=True;

/*******************************************************************
  return the absolute current directory path
********************************************************************/
char *GetWd(char *str)
{
  pstring s;
  static BOOL getwd_cache_init = False;
  SMB_STRUCT_STAT st, st2;
  int i;

  *s = 0;

  if (!use_getwd_cache)
    return(sys_getwd(str));

  /* init the cache */
  if (!getwd_cache_init)
    {
      getwd_cache_init = True;
      for (i=0;i<MAX_GETWDCACHE;i++)
	{
	  string_init(&ino_list[i].text,"");
	  ino_list[i].valid = False;
	}
    }

  /*  Get the inode of the current directory, if this doesn't work we're
      in trouble :-) */

  if (sys_stat(".",&st) == -1) 
    {
      DEBUG(0,("Very strange, couldn't stat \".\"\n"));
      return(sys_getwd(str));
    }


  for (i=0; i<MAX_GETWDCACHE; i++)
    if (ino_list[i].valid)
      {

	/*  If we have found an entry with a matching inode and dev number
	    then find the inode number for the directory in the cached string.
	    If this agrees with that returned by the stat for the current
	    directory then all is o.k. (but make sure it is a directory all
	    the same...) */
      
	if (st.st_ino == ino_list[i].inode &&
	    st.st_dev == ino_list[i].dev)
	  {
	    if (sys_stat(ino_list[i].text,&st2) == 0)
	      {
		if (st.st_ino == st2.st_ino &&
		    st.st_dev == st2.st_dev &&
		    (st2.st_mode & S_IFMT) == S_IFDIR)
		  {
		    strcpy (str, ino_list[i].text);

		    /* promote it for future use */
		    array_promote((char *)&ino_list[0],sizeof(ino_list[0]),i);
		    return (str);
		  }
		else
		  {
		    /*  If the inode is different then something's changed, 
			scrub the entry and start from scratch. */
		    ino_list[i].valid = False;
		  }
	      }
	  }
      }


  /*  We don't have the information to hand so rely on traditional methods.
      The very slow getcwd, which spawns a process on some systems, or the
      not quite so bad getwd. */

  if (!sys_getwd(s))
    {
      DEBUG(0,("Getwd failed, errno %s\n",strerror(errno)));
      return (NULL);
    }

  strcpy(str,s);

  DEBUG(5,("GetWd %s, inode %d, dev %x\n",s,(int)st.st_ino,(int)st.st_dev));

  /* add it to the cache */
  i = MAX_GETWDCACHE - 1;
  string_set(&ino_list[i].text,s);
  ino_list[i].dev = st.st_dev;
  ino_list[i].inode = st.st_ino;
  ino_list[i].valid = True;

  /* put it at the top of the list */
  array_promote((char *)&ino_list[0],sizeof(ino_list[0]),i);

  return (str);
}

/*******************************************************************
reduce a file name, removing .. elements and checking that 
it is below dir in the heirachy. This uses GetWd() and so must be run
on the system that has the referenced file system.

widelinks are allowed if widelinks is true
********************************************************************/
BOOL reduce_name(char *s,char *dir,BOOL widelinks)
{
#ifndef REDUCE_PATHS
  return True;
#else
  pstring dir2;
  pstring wd;
  pstring basename;
  pstring newname;
  char *p=NULL;
  BOOL relative = (*s != '/');

  *dir2 = *wd = *basename = *newname = 0;

  if (widelinks)
    {
      unix_clean_name(s);
      /* can't have a leading .. */
      if (strncmp(s,"..",2) == 0 && (s[2]==0 || s[2]=='/'))
	{
	  DEBUG(3,("Illegal file name? (%s)\n",s));
	  return(False);
	}

      if (strlen(s) == 0)
        strcpy(s,"./");

      return(True);
    }
  
  DEBUG(3,("reduce_name [%s] [%s]\n",s,dir));

  /* remove any double slashes */
  string_sub(s,"//","/");

  pstrcpy(basename,s);
  p = strrchr_m(basename,'/');

  if (!p)
    return(True);

  if (!GetWd(wd))
    {
      DEBUG(0,("couldn't getwd for %s %s\n",s,dir));
      return(False);
    }

  if (ChDir(dir) != 0)
    {
      DEBUG(0,("couldn't chdir to %s\n",dir));
      return(False);
    }

  if (!GetWd(dir2))
    {
      DEBUG(0,("couldn't getwd for %s\n",dir));
      ChDir(wd);
      return(False);
    }


    if (p && (p != basename))
      {
	*p = 0;
	if (strcmp(p+1,".")==0)
	  p[1]=0;
	if (strcmp(p+1,"..")==0)
	  *p = '/';
      }

  if (ChDir(basename) != 0)
    {
      ChDir(wd);
      DEBUG(3,("couldn't chdir for %s %s basename=%s\n",s,dir,basename));
      return(False);
    }

  if (!GetWd(newname))
    {
      ChDir(wd);
      DEBUG(2,("couldn't get wd for %s %s\n",s,dir2));
      return(False);
    }

  if (p && (p != basename))
    {
      strcat(newname,"/");
      strcat(newname,p+1);
    }

  {
    int l = strlen(dir2);    
    if (dir2[l-1] == '/')
      l--;

    if (strncmp(newname,dir2,l) != 0)
      {
	ChDir(wd);
	DEBUG(2,("Bad access attempt? s=%s dir=%s newname=%s l=%d\n",s,dir2,newname,l));
	return(False);
      }

    if (relative)
      {
	if (newname[l] == '/')
	  pstrcpy(s,newname + l + 1);
	else
	  pstrcpy(s,newname+l);
      }
    else
      pstrcpy(s,newname);
  }

  ChDir(wd);

  if (strlen(s) == 0)
    strcpy(s,"./");

  DEBUG(3,("reduced to %s\n",s));
  return(True);
#endif
}

/****************************************************************************
  make a dir struct
****************************************************************************/
void make_dir_struct(char *buf,char *mask,char *fname,SMB_OFF_T size,int mode,time_t date)
{  
  char *p;
  pstring mask2;

  pstrcpy(mask2,mask);

  if ((mode & aDIR) != 0)
    size = 0;

  memset(buf+1,' ',11);
  if ((p = strchr_m(mask2,'.')) != NULL)
    {
      *p = 0;
 //     memcpy(buf+1,mask2,MIN(strlen(mask2),8));
	  push_ascii(buf+1,mask2,8, 0);
 //     memcpy(buf+9,p+1,MIN(strlen(p+1),3));
	  push_ascii(buf+9,p+1,3, 0);
      *p = '.';
    }
  else
    //memcpy(buf+1,mask2,MIN(strlen(mask2),11));
  push_ascii(buf+1,mask2,11, 0);

  bzero(buf+21,DIR_STRUCT_SIZE-21);
  /*
  CVAL(buf,21) = mode;
  put_dos_date(buf,22,date);
  SSVAL(buf,26,size & 0xFFFF);
  SSVAL(buf,28,size >> 16);
  StrnCpy(buf+30,fname,12);
  if (!case_sensitive)
    strupper(buf+30);
    */
    SCVAL(buf,21,mode);
    put_dos_date(buf,22,date);
    SSVAL(buf,26,size & 0xFFFF);
    SSVAL(buf,28,(size >> 16)&0xFFFF);
    push_ascii(buf+30,fname,12,0);
  DEBUG(8,("put name [%s] into dir struct\n",buf+30));
}


/*******************************************************************
close the low 3 fd's and open dev/null in their place
********************************************************************/
void close_low_fds(void)
{
  int fd;
  int i;
  close(0); close(1); close(2);
  /* try and use up these file descriptors, so silly
     library routines writing to stdout etc won't cause havoc */
  for (i=0;i<3;i++) {
    fd = open("/dev/null",O_RDWR,0);
    if (fd < 0) fd = open("/dev/null",O_WRONLY,0);
    if (fd < 0) {
      DEBUG(0,("Can't open /dev/null\n"));
      return;
    }
    if (fd != i) {
      DEBUG(0,("Didn't get file descriptor %d\n",i));
      return;
    }
  }
}

/****************************************************************************
Set a fd into blocking/nonblocking mode. Uses POSIX O_NONBLOCK if available,
else
if SYSV use O_NDELAY
if BSD use FNDELAY
****************************************************************************/
int set_blocking(int fd, BOOL set)
{
  int val;
#ifdef O_NONBLOCK
#define FLAG_TO_SET O_NONBLOCK
#else
#ifdef SYSV
#define FLAG_TO_SET O_NDELAY
#else /* BSD */
#define FLAG_TO_SET FNDELAY
#endif
#endif

  if((val = fcntl(fd, F_GETFL, 0)) == -1)
	return -1;
  if(set) /* Turn blocking on - ie. clear nonblock flag */
	val &= ~FLAG_TO_SET;
  else
    val |= FLAG_TO_SET;
  return fcntl( fd, F_SETFL, val);
#undef FLAG_TO_SET
}


/****************************************************************************
write to a socket
****************************************************************************/
ssize_t write_socket(int fd,char *buf,size_t len)
{
  ssize_t ret=0;

  if (passive)
    return(len);

  ret = write_data(fd,buf,len);
     
  return(ret);
}

/****************************************************************************
read data from a device with a timout in msec.
mincount = if timeout, minimum to read before returning
maxcount = number to be read.
****************************************************************************/
ssize_t read_with_timeout(int fd,char *buf,size_t mincnt,size_t maxcnt,long time_out)
{
  fd_set fds;
  int selrtn;
  ssize_t readret;
  size_t nread = 0;
  struct timeval timeout;

  /* just checking .... */
  if (maxcnt <= 0) 
  	return(0);

  smb_read_error = 0;

  /* Blocking read */
  if (time_out <= 0) {
    	if (mincnt == 0) 
		mincnt = maxcnt;

    while (nread < mincnt) {
      readret = sys_read(fd, buf + nread, maxcnt - nread);
      if (readret == 0) {
	smb_read_error = READ_EOF;
	return -1;
      }

      if (readret == -1) {
	smb_read_error = READ_ERROR;
	return -1;
      }
      nread += readret;
    }
    return((ssize_t)nread);
  }
  
  /* Most difficult - timeout read */
  /* If this is ever called on a disk file and 
	 mincnt is greater then the filesize then
	 system performance will suffer severely as 
	 select always return true on disk files */

  /* Set initial timeout */
  timeout.tv_sec = time_out / 1000;
  timeout.tv_usec = 1000 * (time_out % 1000);

  for (nread=0; nread<mincnt; ) 
    {      
      FD_ZERO(&fds);
      FD_SET(fd,&fds);
      
      selrtn = sys_select(fd+1,&fds,NULL,NULL,&timeout);

      /* Check if error */
      if(selrtn == -1) {
	/* something is wrong. Maybe the socket is dead? */
	smb_read_error = READ_ERROR;
	return -1;
      }
      
      /* Did we timeout ? */
      if (selrtn == 0) {
	smb_read_error = READ_TIMEOUT;
	return -1;
      }
      
      readret = sys_read(fd, buf+nread, maxcnt-nread);
      if (readret == 0) {
	/* we got EOF on the file descriptor */
	smb_read_error = READ_EOF;
	return -1;
      }

      if (readret == -1) {
	/* the descriptor is probably dead */
	smb_read_error = READ_ERROR;
	return -1;
      }
      
      nread += readret;
    }

  /* Return the number we got */
  return((ssize_t)nread);
}

/****************************************************************************
send a keepalive packet (rfc1002)
****************************************************************************/
BOOL send_keepalive(int client)
{
  unsigned char buf[4];

  buf[0] = 0x85;
  buf[1] = buf[2] = buf[3] = 0;

  return(write_data(client,(char *)buf,4) == 4);
}

ssize_t sys_read(int fd, void *buf, size_t count)
{
	ssize_t ret;

	do {
		ret = read(fd, buf, count);
	} while (ret == -1 && errno == EINTR);
	return ret;
}

/****************************************************************************
  read data from the client, reading exactly N bytes. 
****************************************************************************/
ssize_t read_data(int fd,char *buffer,size_t N)
{
  ssize_t  ret;
  size_t total=0;  
 
  smb_read_error = 0;

  while (total < N)
    {
      ret = sys_read(fd,buffer + total,N - total);
      if (ret == 0) {
	  	DEBUG(0,("read eof with %s %d\n", strerror(errno), errno));	
		smb_read_error = READ_EOF;
		return 0;
      }
      if (ret == -1) {
	  	DEBUG(0,("read error with %s\n", strerror(errno)));
		smb_read_error = READ_ERROR;
		return -1;
      }
      total += ret;
    }
  return total;
}

ssize_t sys_write(int s, const void *msg, size_t len)
{
	ssize_t ret;

	do {
		ret = write(s, msg, len);
	} while (ret == -1 && errno == EINTR);
	return ret;
}

ssize_t sys_pwrite(int fd, const void *buf, size_t count, SMB_OFF_T off)
{
	ssize_t ret;

	do {
#ifdef LARGE_FILE_SUPPORT
		ret = pwrite64(fd, buf, count, off);
#else
		ret = pwrite(fd, buf, count, off);
#endif
	} while (ret == -1 && errno == EINTR);
	return ret;
}

/****************************************************************************
  write data to a fd 
****************************************************************************/
ssize_t write_data(int fd,char *buffer,size_t N)
{
  size_t total=0;
  ssize_t ret;

  while (total < N)
    {
      ret = sys_write(fd,buffer + total,N - total);

      if (ret == -1) return -1;
      if (ret == 0) return total;

      total += ret;
    }
  return total;
}

ssize_t pwrite_data(int fd, char *buffer, size_t N, SMB_OFF_T offset)
{
	size_t total=0;
	ssize_t ret;

	while (total < N) {
		ret = sys_pwrite(fd, buffer + total, N - total, offset + total);

		if (ret == -1)
			return -1;
		if (ret == 0)
			return total;

		total += ret;
	}
	return (ssize_t)total;
}


/****************************************************************************
transfer some data between two fd's
****************************************************************************/
SMB_OFF_T transfer_file(int infd,int outfd,size_t n,char *header,size_t headlen,SMB_OFF_T align)
{
  static char *buf=NULL;  
  static size_t size=0;
  char *buf1,*abuf;
  SMB_OFF_T total = 0;

  if (size == 0) {
    size = lp_readsize();
    size = MAX(size,1024);
  }

  while (!buf && size>0) {
    buf = (char *)Realloc(buf,size+8);
    if (!buf) size /= 2;
  }

  if (!buf) {
    DEBUG(0,("Can't allocate transfer buffer!\n"));
    exit(1);
  }

  abuf = buf + (align%8);

  if (header)
    n += headlen;

  while (n > 0)
    {
      size_t s = MIN(n,size);
      size_t ret,ret2=0;

      ret = 0;

      if (header && (headlen >= MIN(s,1024))) {
		buf1 = header;
		s = headlen;
		ret = headlen;
		headlen = 0;
		header = NULL;
      } else {
		buf1 = abuf;
      }

      if (header && headlen > 0)
	{
		ret = MIN(headlen,size);
		memcpy(buf1,header,ret);
		headlen -= ret;
		header += ret;
		if (headlen <= 0) header = NULL;
	}

      if (s > ret)
		ret += read_data(infd,buf1+ret,s-ret);

      if (ret > 0)
	{
	  ret2 = (outfd>=0?write_data(outfd,buf1,ret):ret);
	  if (ret2 > 0) 
	  	total += (SMB_OFF_T)ret2;
	  /* if we can't write then dump excess data */
	  if (ret2 != ret)
	    	transfer_file(infd,-1,n-(ret+headlen),NULL,0,0);
	}
      if (ret <= 0 || ret2 != ret)
		return(total);
      n -= ret;
    }
  return(total);
}


/****************************************************************************
read 4 bytes of a smb packet and return the smb length of the packet
store the result in the buffer
This version of the function will return a length of zero on receiving
a keepalive packet.
****************************************************************************/
static ssize_t read_smb_length_return_keepalive(int fd,char *inbuf,int timeout)
{
  ssize_t len=0;
  int msg_type;
  BOOL ok=False;

  while (!ok)
    {
      if (timeout > 0){
	  	DEBUG(0,("read with timeout!\n"));
		ok = (read_with_timeout(fd,inbuf,4,4,timeout) == 4);
      	}
      else 
		ok = (read_data(fd,inbuf,4) == 4);

      if (!ok)
	return(-1);

      len = smb_len(inbuf);
      msg_type = CVAL(inbuf,0);

      if (msg_type == 0x85) 
        DEBUG(5,("Got keepalive packet\n"));
    }

  DEBUG(10,("got smb length of %d\n",len));

  return(len);
}

/****************************************************************************
read 4 bytes of a smb packet and return the smb length of the packet
store the result in the buffer. This version of the function will
never return a session keepalive (length of zero).
****************************************************************************/
ssize_t read_smb_length(int fd,char *inbuf,int timeout)
{
  ssize_t len;

  for(;;)
  {
    len = read_smb_length_return_keepalive(fd, inbuf, timeout);

    if(len < 0)
      return len;

    /* Ignore session keepalives. */
    if(CVAL(inbuf,0) != 0x85)
      break;
  }

  return len;
}

/****************************************************************************
  read an smb from a fd. Note that the buffer *MUST* be of size
  BUFFER_SIZE+SAFETY_MARGIN.
  The timeout is in milli seconds. 

  This function will return on a
  receipt of a session keepalive packet.
****************************************************************************/
BOOL receive_smb(int fd,char *buffer, int timeout)
{
  ssize_t ret, len;

  smb_read_error = 0;

  bzero(buffer,smb_size + 100);

  len = read_smb_length_return_keepalive(fd,buffer,timeout);
  
  if (len < 0){
	DEBUG(0,("receive smb len < 0!!!\n"));
	if (smb_read_error == 0)
		smb_read_error = READ_ERROR;
	return False;
  }


  if (len > (BUFFER_SIZE + LARGE_WRITEX_HDR_SIZE)) {
    	DEBUG(0,("Invalid packet length! (%d bytes).\n",len));
    	if (len > BUFFER_SIZE + (SAFETY_MARGIN/2))
      		if (smb_read_error == 0)
			smb_read_error = READ_ERROR;
		return False;
  }

  if(len > 0) {
    ret = read_data(fd,buffer+4,len);
    if (ret != len) {
	DEBUG(0,("read error!\n"));
      	smb_read_error = READ_ERROR;
      	return False;
    }
	SSVAL(buffer+4,len, 0);
  }
  return(True);
}

#ifdef OPLOCK_ENABLE
/****************************************************************************
  read a message from a udp fd.
The timeout is in milli seconds
****************************************************************************/
BOOL receive_local_message(int fd, char *buffer, int buffer_len, int timeout)
{
  struct sockaddr_in from;
  int fromlen = sizeof(from);
  int32 msg_len = 0;

  if(timeout != 0)
  {
    struct timeval to;
    fd_set fds;
    int selrtn;

    FD_ZERO(&fds);
    FD_SET(fd,&fds);

    to.tv_sec = timeout / 1000;
    to.tv_usec = (timeout % 1000) * 1000;

    selrtn = sys_select(fd+1,&fds,NULL,NULL,&to);

    /* Check if error */
    if(selrtn == -1) 
    {
      /* something is wrong. Maybe the socket is dead? */
      smb_read_error = READ_ERROR;
      return False;
    } 
    
    /* Did we timeout ? */
    if (selrtn == 0) 
    {
      smb_read_error = READ_TIMEOUT;
      return False;
    }
  }

  /*
   * Read a loopback udp message.
   */
  msg_len = recvfrom(fd, &buffer[UDP_CMD_HEADER_LEN], 
                     buffer_len - UDP_CMD_HEADER_LEN, 0,
                     (struct sockaddr *)&from, &fromlen);

  if(msg_len < 0)
  {
    DEBUG(0,("receive_local_message. Error in recvfrom. (%s).\n",strerror(errno)));
    return False;
  }

  /* Validate message length. */
  if(msg_len > (buffer_len - UDP_CMD_HEADER_LEN))
  {
    DEBUG(0,("receive_local_message: invalid msg_len (%d) max can be %d\n",
              msg_len, 
              buffer_len  - UDP_CMD_HEADER_LEN));
    return False;
  }

  /* Validate message from address (must be localhost). */
  if(from.sin_addr.s_addr != htonl(INADDR_LOOPBACK))
  {
    DEBUG(0,("receive_local_message: invalid 'from' address \
(was %x should be 127.0.0.1\n", from.sin_addr.s_addr));
   return False;
  }

  /* Setup the message header */
  SIVAL(buffer,UDP_CMD_LEN_OFFSET,msg_len);
  SSVAL(buffer,UDP_CMD_PORT_OFFSET,ntohs(from.sin_port));

  return True;
}

/****************************************************************************
 structure to hold a linked list of local udp messages.
 for processing.
****************************************************************************/

typedef struct _udp_message_list {
   struct _udp_message_list *msg_next;
   char *msg_buf;
   int msg_len;
} udp_message_list;

static udp_message_list *udp_msg_head = NULL;

/****************************************************************************
 Function to push a linked list of local udp messages ready
 for processing.
****************************************************************************/
BOOL push_local_message(char *buf, int msg_len)
{
  udp_message_list *msg = (udp_message_list *)malloc(sizeof(udp_message_list));

  if(msg == NULL)
  {
    DEBUG(0,("push_local_message: malloc fail (1)\n"));
    return False;
  }

  msg->msg_buf = (char *)malloc(msg_len);
  if(msg->msg_buf == NULL)
  {
    DEBUG(0,("push_local_message: malloc fail (2)\n"));
    free((char *)msg);
    return False;
  }

  memcpy(msg->msg_buf, buf, msg_len);
  msg->msg_len = msg_len;

  msg->msg_next = udp_msg_head;
  udp_msg_head = msg;

  return True;
}
#endif

/****************************************************************************
  Do a select on an two fd's - with timeout. 

  If a local udp message has been pushed onto the
  queue (this can only happen during oplock break
  processing) return this first.

  If the first smbfd is ready then read an smb from it.
  if the second (loopback UDP) fd is ready then read a message
  from it and setup the buffer header to identify the length
  and from address.
  Returns False on timeout or error.
  Else returns True.

The timeout is in milli seconds
****************************************************************************/
BOOL receive_message_or_smb(int smbfd, 
#ifdef OPLOCK_ENABLE
								int oplock_fd,
#endif
                           					char *buffer, int buffer_len, 
                           					int timeout, BOOL *got_smb)
{
  fd_set fds;
  int selrtn;
  struct timeval to;

  *got_smb = False;

#ifdef OPLOCK_ENABLE
  /*
   * Check to see if we already have a message on the udp queue.
   * If so - copy and return it.
   */

  if(udp_msg_head)
  {
    udp_message_list *msg = udp_msg_head;
    memcpy(buffer, msg->msg_buf, MIN(buffer_len, msg->msg_len));
    udp_msg_head = msg->msg_next;

    /* Free the message we just copied. */
    free((char *)msg->msg_buf);
    free((char *)msg);
    return True;
  }
#endif

  FD_ZERO(&fds);
  FD_SET(smbfd,&fds);
  
#ifdef OPLOCK_ENABLE
  FD_SET(oplock_fd,&fds);
#endif

  to.tv_sec = timeout / 1000;
  to.tv_usec = (timeout % 1000) * 1000;

  int max_fd;
#ifdef OPLOCK_ENABLE
  max_fd = MAX(smbfd, oplock_fd);
#else
  max_fd = smbfd;
#endif

  selrtn = sys_select(max_fd+1,&fds,NULL,NULL,timeout>0?&to:NULL);

  /* Check if error */
  if(selrtn == -1) {
    /* something is wrong. Maybe the socket is dead? */
    smb_read_error = READ_ERROR;
    return False;
  } 
    
  /* Did we timeout ? */
  if (selrtn == 0) {
    smb_read_error = READ_TIMEOUT;
    return False;
  }

  if (FD_ISSET(smbfd,&fds))
  {
    	*got_smb = True;
    	return  receive_smb(smbfd, buffer, 0);
  }
  else
  {
#ifdef OPLOCK_ENABLE
    return receive_local_message(oplock_fd, buffer, buffer_len, 0);
#else
    return False;
#endif
  }
}

/****************************************************************************
  send an smb to a fd 
****************************************************************************/
BOOL send_smb(int fd,char *buffer)
{
  size_t len, nwritten=0;
  ssize_t ret;
  len = smb_len(buffer) + 4;

  while (nwritten < len)
    {
      ret = write_socket(fd,buffer+nwritten,len - nwritten);
      if (ret <= 0)
	{
	  DEBUG(0,("Error writing %d bytes to client. %d. Exiting\n",len,ret));
          close_sockets();
	  exit(1);
	}
      nwritten += ret;
    }


  return True;
}


/****************************************************************************
find a pointer to a netbios name
****************************************************************************/
char *name_ptr(char *buf,int ofs)
{
  unsigned char c = *(unsigned char *)(buf+ofs);

  if ((c & 0xC0) == 0xC0)
    {
      uint16 l;
      char p[2];
      memcpy(p,buf+ofs,2);
      p[0] &= ~0xC0;
      l = RSVAL(p,0);
      DEBUG(5,("name ptr to pos %d from %d is %s\n",l,ofs,buf+l));
      return(buf + l);
    }
  else
    return(buf+ofs);
}  

/****************************************************************************
extract a netbios name from a buf
****************************************************************************/
int name_extract(char *buf,int ofs,char *name)
{
  char *p = name_ptr(buf,ofs);
  int d = PTR_DIFF(p,buf+ofs);
  strcpy(name,"");
  if (d < -50 || d > 50) return(0);
  return(name_interpret(p,name));
}
  
/****************************************************************************
return the total storage length of a mangled name
****************************************************************************/
int name_len( char *s )
{
  int len;

  /* If the two high bits of the byte are set, return 2. */
  if( 0xC0 == (*(unsigned char *)s & 0xC0) )
    return(2);

  /* Add up the length bytes. */
  for( len = 1; (*s); s += (*s) + 1 )
    {
    len += *s + 1;
    }

  return( len );
} /* name_len */

/****************************************************************************
check if a string is part of a list
****************************************************************************/
BOOL in_list(char *s,char *list,BOOL casesensitive)
{
  pstring tok;
  const char *p=list;

  if (!list) return(False);

  while (next_token(&p,tok,LIST_SEP))
    {
      if (casesensitive) {
	if (strcmp(tok,s) == 0)
	  return(True);
      } else {
	if (StrCaseCmp(tok,s) == 0)
	  return(True);
      }
    }
  return(False);
}

/****************************************************************************
become a daemon, discarding the controlling terminal
****************************************************************************/
void become_daemon(void)
{
#ifndef NO_FORK_DEBUG
  if (sys_fork())
    	_exit(0);

  /* detach from the terminal */
#ifdef USE_SETSID
  setsid();
#else /* USE_SETSID */
#ifdef TIOCNOTTY
  {
    int i = open("/dev/tty", O_RDWR);
    if (i >= 0) 
      {
	ioctl(i, (int) TIOCNOTTY, (char *)0);      
	close(i);
      }
  }
#endif /* TIOCNOTTY */
#endif /* USE_SETSID */
  /* Close fd's 0,1,2. Needed if started by rsh */
  close_low_fds();
#endif /* NO_FORK_DEBUG */
}

/****************************************************************************
read a line from a file with possible \ continuation chars. 
Blanks at the start or end of a line are stripped.
The string will be allocated if s2 is NULL
****************************************************************************/
char *fgets_slash(char *s2,int maxlen,FILE *f)
{
  char *s=s2;
  int len = 0;
  int c;
  BOOL start_of_line = True;

  if (feof(f))
    return(NULL);

  if (!s2)
    {
      maxlen = MIN(maxlen,8);
      s = (char *)Realloc(s,maxlen);
    }

  if (!s || maxlen < 2) return(NULL);

  *s = 0;

  while (len < maxlen-1)
    {
      c = getc(f);
      switch (c)
	{
	case '\r':
	  break;
	case '\n':
	  while (len > 0 && s[len-1] == ' ')
	    {
	      s[--len] = 0;
	    }
	  if (len > 0 && s[len-1] == '\\')
	    {
	      s[--len] = 0;
	      start_of_line = True;
	      break;
	    }
	  return(s);
	case EOF:
	  if (len <= 0 && !s2) 
	    free(s);
	  return(len>0?s:NULL);
	case ' ':
	  if (start_of_line)
	    break;
	default:
	  start_of_line = False;
	  s[len++] = c;
	  s[len] = 0;
	}
      if (!s2 && len > maxlen-3)
	{
	  maxlen *= 2;
	  s = (char *)Realloc(s,maxlen);
	  if (!s) return(NULL);
	}
    }
  return(s);
}



/****************************************************************************
set the length of a file from a filedescriptor.
Returns 0 on success, -1 on failure.
NOTE: WE CURRENTLY DO NOT ADD SUPPORT FOR FILES LARGER THAN 4GB!!!
****************************************************************************/
int set_filelen(int fd, SMB_OFF_T len)
{
	DEBUG(0,("====>%s\n", __FUNCTION__));
	
	int result = -1;
	SMB_STRUCT_STAT st;
	char c = 0;
	SMB_OFF_T currpos;

	struct statfs fs_buf;
	fstatfs(fd, &fs_buf);

	if(fs_buf.f_type == 0x4d44){	//we do not preallocate space for FAT system, instead give a special handle here. The issue is that we increase disk fragment by doing so---wubaijun
		if (len > 0xffffffff ) /* larger than 4GB */
		{
			errno = EFBIG;
			goto done;
		}	

		double space_avail;

		space_avail = (double)(fs_buf.f_bfree/256)*1024;	//not sure 256 is correct on other platforms, need to confirm this---wubaijun

		DEBUG(1,("avail space is %f, file len is: 0x%x\n", space_avail, len));

		if(space_avail == -1){
			goto done;
		}

		if((double)(len/1024) > space_avail){	//instead we just check if the file space needed is bigger than the available space on usb---wubaijun
			errno = ENOSPC;
			goto done;
		}

		
		if((double)(len/1024) < space_avail){	//shrink the file size should work fine for FAT---wubaijun
			if (sys_fstat(fd, &st) == -1){
				DEBUG(0, ("error happened....%s(%d)\n", __FUNCTION__, __LINE__));
				goto done;
			}

			if(st.st_size <= len){	//do not ftruncate if we need to expand the size
				result = 0;
				goto done;
			}
			
			result = sys_ftruncate(fd, len);
			if(result == 0)
				goto done;
			else
				DEBUG(0, ("error happened....%s(%d)\n", __FUNCTION__, __LINE__));
		
			if (result != 0 && errno == EPERM) 
			{
				DEBUG(0, ("error happened....%s(%d)\n", __FUNCTION__, __LINE__));
				errno = EINVAL;
				result = 0;
				goto done;
			}

			goto done;
		}
		
		result = 0;
		goto done;
	}

	//after this point, below is all related to file systems other than FAT---wubaijun
	DEBUG(0,("file len is: 0x%x\n", len));
	
	result = sys_ftruncate(fd, (SMB_OFF_T)len);
	if(result == 0)
		goto done;

	/* According to W. R. Stevens advanced UNIX prog. Pure 4.3 BSD cannot
	   extend a file with ftruncate. Provide alternate implementation
	   for this */
	currpos = sys_lseek(fd, 0, SEEK_CUR);	//to check if we could modify the file---wubaijun
	if (currpos == -1) {
		DEBUG(0, ("error happened(%s) at %s(%d)\n", __FUNCTION__, __LINE__,
				strerror(errno)));

		goto done;
	}

	/* Do an fstat to see if the file is longer than the requested
	   size in which case the ftruncate above should have
	   succeeded or shorter, in which case seek to len - 1 and
	   write 1 byte of zero */
	if (sys_fstat(fd, &st) == -1) {
		DEBUG(0, ("error happened(%s) at %s(%d)\n", __FUNCTION__, __LINE__,
				strerror(errno)));
		goto done;
	}

#ifdef S_ISFIFO
	if (S_ISFIFO(st.st_mode)) {
		result = 0;
		goto done;
	}
#endif

	if (st.st_size == (SMB_OFF_T)len) {
		result = 0;
		goto done;
	}

	if (st.st_size > (SMB_OFF_T)len) {	//ftruncate should work for shrinking file anyway---wubaijun
		DEBUG(0, ("error happened(%s) at %s(%d)\n", __FUNCTION__, __LINE__,
				strerror(errno)));
		goto done;
	}	

	if(sys_pwrite(fd, &c, 1, (SMB_OFF_T)len-1) != 1){	//using pwrite is better---wubaijun
		DEBUG(0, ("error happened(%s) at %s(%d)\n", __FUNCTION__, __LINE__,
				strerror(errno)));
		goto done;
	}
	
	result = 0;

  done:
  	DEBUG(0, ("<=============out %s with res: %d\n", __FUNCTION__, result));
	return result;
}

/****************************************************************************
expand a pointer to be a particular size
****************************************************************************/
void *Realloc(void *p,int size)
{
  void *ret=NULL;

  if (size == 0) {
    if (p) free(p);
    DEBUG(5,("Realloc asked for 0 bytes\n"));
    return NULL;
  }

  if (!p)
    ret = (void *)malloc(size);
  else
    ret = (void *)realloc(p,size);

  if (!ret)
    DEBUG(0,("Memory allocation error: failed to expand to %d bytes\n",size));

  return(ret);
}

#ifdef NOSTRDUP
/****************************************************************************
duplicate a string
****************************************************************************/
 char *strdup(char *s)
{
  char *ret = NULL;
  if (!s) return(NULL);
  ret = (char *)malloc(strlen(s)+1);
  if (!ret) return(NULL);
  strcpy(ret,s);
  return(ret);
}
#endif

/****************************************************************************
get my own name and IP
****************************************************************************/
BOOL get_myname(char *my_name,struct in_addr *ip)
{
  struct hostent *hp;
  pstring hostname;

  *hostname = 0;

  /* get my host name */
  if (gethostname(hostname, MAXHOSTNAMELEN) == -1) 
    {
      DEBUG(0,("gethostname failed\n"));
      return False;
    } 

  if (my_name)
    {
      /* split off any parts after an initial . */
      char *p = strchr_m(hostname,'.');
      if (p) *p = 0;

      fstrcpy(my_name,hostname);
    }

  if (ip){
  /* get host info 
    * On realtek platform, I can not run gethostbyname().... What's worse, this function may block for
    * a long while if wan is plugin..........
    */
  	if ((hp = Get_Hostbyname(hostname)) == 0) 
    	{
      		DEBUG(0,( "Get_Hostbyname: Unknown host %s.\n",hostname));
      		return False;
    	}

	putip((char *)ip,(char *)hp->h_addr);
  }

  return(True);
}


/****************************************************************************
true if two IP addresses are equal
****************************************************************************/
BOOL ip_equal(struct in_addr ip1,struct in_addr ip2)
{
  uint32 a1,a2;
  a1 = ntohl(ip1.s_addr);
  a2 = ntohl(ip2.s_addr);
  return(a1 == a2);
}


/****************************************************************************
open a socket of the specified type, port and address for incoming data
****************************************************************************/
int open_socket_in(int type, int port, int dlevel,uint32 socket_addr)
{
	struct sockaddr_in sock;
	int res;

	memset( (char *)&sock, '\0', sizeof(sock) );
	
	sock.sin_port        = htons( port );
	sock.sin_family      = AF_INET;
	sock.sin_addr.s_addr = socket_addr;

	res = socket( AF_INET, type, 0 );
	if( res == -1 ) {
		return -1;
	}
	
	{
		int val = 1;
		setsockopt(res,SOL_SOCKET,SO_REUSEADDR,(char *)&val,sizeof(val));
	}
	
	if( bind( res, (struct sockaddr *)&sock, sizeof(sock) ) == -1 ) {
		close( res ); 
		return( -1 ); 
	}

	DEBUG( 3, ( "bind succeeded on port %d\n", port ) );

	return( res );
}

/****************************************************************************
interpret an internet address or name into an IP address in 4 byte form
****************************************************************************/
uint32 interpret_addr(char *str)
{
  struct hostent *hp;
  uint32 res;
  int i;
  BOOL pure_address = True;

  if (strcmp(str,"0.0.0.0") == 0) return(0);
  if (strcmp(str,"255.255.255.255") == 0) return(0xFFFFFFFF);

  for (i=0; pure_address && str[i]; i++)
    if (!(isdigit(str[i]) || str[i] == '.')) 
      pure_address = False;

  /* if it's in the form of an IP address then get the lib to interpret it */
  if (pure_address) {
    res = inet_addr(str);
  } else {
    /* otherwise assume it's a network name of some sort and use 
       Get_Hostbyname */
    if ((hp = Get_Hostbyname(str)) == 0) {
      DEBUG(3,("Get_Hostbyname: Unknown host. %s\n",str));
      return 0;
    }
    if(hp->h_addr == NULL) {
      DEBUG(3,("Get_Hostbyname: host address is invalid for host %s.\n",str));
      return 0;
    }
    putip((char *)&res,(char *)hp->h_addr);
  }

  if (res == (uint32)-1) return(0);

  return(res);
}

/*******************************************************************
  a convenient addition to interpret_addr()
  ******************************************************************/
struct in_addr *interpret_addr2(char *str)
{
  static struct in_addr ret;
  uint32 a = interpret_addr(str);
  ret.s_addr = a;
  return(&ret);
}

/*******************************************************************
  check if an IP is the 0.0.0.0
  ******************************************************************/
BOOL zero_ip(struct in_addr ip)
{
  uint32 a;
  putip((char *)&a,(char *)&ip);
  return(a == 0);
}


/*******************************************************************
 matchname - determine if host name matches IP address 
 ******************************************************************/
static BOOL matchname(char *remotehost,struct in_addr  addr)
{
  struct hostent *hp;
  int     i;
  
  if ((hp = Get_Hostbyname(remotehost)) == 0) {
    DEBUG(0,("Get_Hostbyname(%s): lookup failure", remotehost));
    return False;
  } 

  /*
   * Make sure that gethostbyname() returns the "correct" host name.
   * Unfortunately, gethostbyname("localhost") sometimes yields
   * "localhost.domain". Since the latter host name comes from the
   * local DNS, we just have to trust it (all bets are off if the local
   * DNS is perverted). We always check the address list, though.
   */
  
  if (strcasecmp(remotehost, hp->h_name)
      && strcasecmp(remotehost, "localhost")) {
    DEBUG(0,("host name/name mismatch: %s != %s",
	     remotehost, hp->h_name));
    return False;
  }
	
  /* Look up the host address in the address list we just got. */
  for (i = 0; hp->h_addr_list[i]; i++) {
    if (memcmp(hp->h_addr_list[i], (caddr_t) & addr, sizeof(addr)) == 0)
      return True;
  }

  /*
   * The host name does not map to the original host address. Perhaps
   * someone has compromised a name server. More likely someone botched
   * it, but that could be dangerous, too.
   */
  
  DEBUG(0,("host name/address mismatch: %s != %s",
	   inet_ntoa(addr), hp->h_name));
  return False;
}

/*******************************************************************
 Reset the 'done' variables so after a client process is created
 from a fork call these calls will be re-done. This should be
 expanded if more variables need reseting.
 ******************************************************************/

static BOOL global_client_name_done = False;
static BOOL global_client_addr_done = False;

void reset_globals_after_fork()
{
  global_client_name_done = False;
  global_client_addr_done = False;
}
 
/*******************************************************************
 return the DNS name of the client 
 ******************************************************************/
char *client_name(void)
{
  extern int Client;
  struct sockaddr sa;
  struct sockaddr_in *sockin = (struct sockaddr_in *) (&sa);
  int     length = sizeof(sa);
  static pstring name_buf;
  struct hostent *hp;

  if (global_client_name_done) 
    return name_buf;

  strcpy(name_buf,"UNKNOWN");

  if (Client == -1) {
	  return name_buf;
  }

  if (getpeername(Client, &sa, &length) < 0) {
    DEBUG(0,("getpeername failed\n"));
    return name_buf;
  }

  /* Look up the remote host name. */
  if ((hp = gethostbyaddr((char *) &sockin->sin_addr,
			  sizeof(sockin->sin_addr),
			  AF_INET)) == 0) {
    DEBUG(1,("Gethostbyaddr failed for %s\n",client_addr()));
    StrnCpy(name_buf,client_addr(),sizeof(name_buf) - 1);
  } else {
    StrnCpy(name_buf,(char *)hp->h_name,sizeof(name_buf) - 1);
    if (!matchname(name_buf, sockin->sin_addr)) {
      DEBUG(0,("Matchname failed on %s %s\n",name_buf,client_addr()));
      strcpy(name_buf,"UNKNOWN");
    }
  }
  global_client_name_done = True;
  return name_buf;
}

/*******************************************************************
 return the IP addr of the client as a string 
 ******************************************************************/
char *client_addr(void)
{
  extern int Client;
  struct sockaddr sa;
  struct sockaddr_in *sockin = (struct sockaddr_in *) (&sa);
  int     length = sizeof(sa);
  static fstring addr_buf;

  if (global_client_addr_done) 
    return addr_buf;

  strcpy(addr_buf,"0.0.0.0");

  if (Client == -1) {
	  return addr_buf;
  }

  if (getpeername(Client, &sa, &length) < 0) {
    DEBUG(0,("getpeername failed\n"));
    return addr_buf;
  }

  fstrcpy(addr_buf,(char *)inet_ntoa(sockin->sin_addr));

  global_client_addr_done = True;
  return addr_buf;
}

char *automount_server(char *user_name)
{
	static pstring server_name;

#if (defined(NETGROUP) && defined (AUTOMOUNT))
	int nis_error;        /* returned by yp all functions */
	char *nis_result;     /* yp_match inits this */
	int nis_result_len;  /* and set this */
	char *nis_domain;     /* yp_get_default_domain inits this */
	char *nis_map = (char *)lp_nis_home_map_name();
	int home_server_len;

	/* set to default of local machine */
	pstrcpy(server_name, local_machine);

	if ((nis_error = yp_get_default_domain(&nis_domain)) != 0)
	{
		DEBUG(3, ("YP Error: %s\n", yperr_string(nis_error)));
	}

	DEBUG(5, ("NIS Domain: %s\n", nis_domain));

	if ((nis_error = yp_match(nis_domain, nis_map,
			user_name, strlen(user_name),
			&nis_result, &nis_result_len)) != 0)
	{
		DEBUG(3, ("YP Error: %s\n", yperr_string(nis_error)));
	}

	if (!nis_error && lp_nis_home_map())
	{
		home_server_len = strcspn(nis_result,":");
		DEBUG(5, ("NIS lookup succeeded.  Home server length: %d\n",home_server_len));
		if (home_server_len > sizeof(pstring))
		{
			home_server_len = sizeof(pstring);
		}
		strncpy(server_name, nis_result, home_server_len);
	}
#else
	/* use the local machine name instead of the auto-map server */
	pstrcpy(server_name, local_machine);
#endif

	DEBUG(4,("Home server: %s\n", server_name));

	return server_name;
}

/*******************************************************************
sub strings with useful parameters
Rewritten by Stefaan A Eeckels <Stefaan.Eeckels@ecc.lu> and
Paul Rippin <pr3245@nopc.eurostat.cec.be>
********************************************************************/
void standard_sub_basic(char *str)
{
	char *s, *p;
	char pidstr[10];
	struct passwd *pass;
	char *username = sam_logon_in_ssb ? samlogon_user : sesssetup_user;

	for (s = str ; s && *s && (p = strchr_m(s,'%')); s = p )
	{
		switch (*(p+1))
		{
			case 'G' :
			{
				if ((pass = Get_Pwnam(username,False))!=NULL)
				{
					string_sub(p,"%G",gidtoname(pass->pw_gid));
				}
				else
				{
					p += 2;
				}
				break;
			}
			case 'N' : string_sub(p,"%N", automount_server(username)); break;
			case 'I' : string_sub(p,"%I", client_addr()); break;
			case 'L' : string_sub(p,"%L", local_machine); break;
			case 'M' : string_sub(p,"%M", client_name()); break;
			case 'R' : string_sub(p,"%R", remote_proto); break;
			case 'T' : string_sub(p,"%T", timestring()); break;
			case 'U' : string_sub(p,"%U", username); break;
			case 'a' : string_sub(p,"%a", remote_arch); break;
			case 'd' :
			{
				sprintf(pidstr,"%d",(int)sys_getpid());
				string_sub(p,"%d", pidstr);
				break;
			}
			case 'h' : string_sub(p,"%h", myhostname); break;
			case 'm' : string_sub(p,"%m", remote_machine); break;
			case 'v' : string_sub(p,"%v", VERSION); break;
			case '\0': p++; break; /* don't run off end if last character is % */
			default  : p+=2; break;
		}
	}
	return;
}

/*******************************************************************
are two IPs on the same subnet?
********************************************************************/
BOOL same_net(struct in_addr ip1,struct in_addr ip2,struct in_addr mask)
{
  uint32 net1,net2,nmask;

  nmask = ntohl(mask.s_addr);
  net1  = ntohl(ip1.s_addr);
  net2  = ntohl(ip2.s_addr);
            
  return((net1 & nmask) == (net2 & nmask));
}

/****************************************************************************
a wrapper for gethostbyname() that tries with all lower and all upper case 
if the initial name fails
****************************************************************************/
struct hostent *Get_Hostbyname(char *name)
{
  char *name2 = strdup(name);
  struct hostent *ret;

  if (!name2)
    {
      DEBUG(0,("Memory allocation error in Get_Hostbyname! panic\n"));
      exit(0);
    }

#if 0
  if (!isalnum(*name2))
    {
      free(name2);
      return(NULL);
    }
 #endif

  ret = sys_gethostbyname(name2);
  if (ret != NULL)
    {
      free(name2);
      return(ret);
    }

  /* try with all lowercase */
  strlower_m(name2);
  ret = sys_gethostbyname(name2);
  if (ret != NULL)
    {
      free(name2);
      return(ret);
    }

  /* try with all uppercase */
  strupper_m(name2);
  ret = sys_gethostbyname(name2);
  if (ret != NULL)
    {
      free(name2);
      return(ret);
    }
  
  /* nothing works :-( */
  free(name2);
  return(NULL);
}


/****************************************************************************
check if a process exists. Does this work on all unixes?
****************************************************************************/
BOOL process_exists(int pid)
{
	return(kill(pid,0) == 0 || errno != ESRCH);
}

/*******************************************************************
turn a gid into a group name
********************************************************************/
char *gidtoname(int gid)
{
  static char name[40];
  struct group *grp = getgrgid(gid);
  if (grp) return(grp->gr_name);
  sprintf(name,"%d",gid);
  return(name);
}

/*******************************************************************
block sigs
********************************************************************/
void BlockSignals(BOOL block,int signum)
{
#ifdef USE_SIGBLOCK
  int block_mask = sigmask(signum);
  static int oldmask = 0;
  if (block) 
    oldmask = sigblock(block_mask);
  else
    sigsetmask(oldmask);
#elif defined(USE_SIGPROCMASK)
  sigset_t set;
  sigemptyset(&set);
  sigaddset(&set,signum);
  sigprocmask(block?SIG_BLOCK:SIG_UNBLOCK,&set,NULL);
#endif
}

#ifdef LARGE_FILE_SUPPORT
#define DIRECT dirent64
#else
#define DIRECT dirent
#endif

/*******************************************************************
a readdir wrapper which just returns the file name
also return the inode number if requested
********************************************************************/
char *readdirname(void *p)
{
  struct DIRECT *ptr;
  char *dname;

  if (!p) return(NULL);
  
  ptr = (struct DIRECT *)sys_readdir(p);
  
  if (!ptr){ 
	DEBUG(0,("error? with: %s\n",strerror(errno)));
	return(NULL);
  }

  dname = ptr->d_name;

  {
    static pstring buf;
    pstrcpy(buf, dname);
    dname = buf;
  }

  return(dname);
}

/*******************************************************************
 Utility function used to decide if the last component 
 of a path matches a (possibly wildcarded) entry in a namelist.
********************************************************************/

BOOL is_in_path(const char *name, name_compare_entry *namelist)
{
  pstring last_component;
  char *p;

//  DEBUG(8, ("is_in_path: %s\n", name));	/*we do not have namelist??? why?*/

  /* if we have no list it's obviously not in the path */
  if((namelist == NULL ) || ((namelist != NULL) && (namelist[0].name == NULL))) 
  {
//    DEBUG(8,("is_in_path: no name list.\n"));
    return False;
  }

  /* Get the last component of the unix name. */
  p = strrchr_m(name, '/');
  strncpy(last_component, p ? p : name, sizeof(last_component)-1);
  last_component[sizeof(last_component)-1] = '\0'; 

  for(; namelist->name != NULL; namelist++)
  {
    if(namelist->is_wild)
    {
      /* look for a wildcard match. */
      if (mask_match(last_component, namelist->name, case_sensitive, False))
      {
         DEBUG(8,("is_in_path: mask match succeeded\n"));
         return True;
      }
    }
    else
    {
      if((case_sensitive && (strcmp(last_component, namelist->name) == 0))||
       (!case_sensitive && (StrCaseCmp(last_component, namelist->name) == 0)))
        {
         DEBUG(8,("is_in_path: match succeeded\n"));
         return True;
        }
    }
  }
  DEBUG(8,("is_in_path: match not found\n"));
 
  return False;
}

/*******************************************************************
 Strip a '/' separated list into an array of 
 name_compare_enties structures suitable for 
 passing to is_in_path(). We do this for
 speed so we can pre-parse all the names in the list 
 and don't do it for each call to is_in_path().
 namelist is modified here and is assumed to be 
 a copy owned by the caller.
 We also check if the entry contains a wildcard to
 remove a potentially expensive call to mask_match
 if possible.
********************************************************************/
 
void set_namearray(name_compare_entry **ppname_array, char *namelist)
{
  char *name_end;
  char *nameptr = namelist;
  int num_entries = 0;
  int i;

  (*ppname_array) = NULL;

  if((nameptr == NULL ) || ((nameptr != NULL) && (*nameptr == '\0'))) 
    return;

  /* We need to make two passes over the string. The
     first to count the number of elements, the second
     to split it.
   */
  while(*nameptr) 
    {
      if ( *nameptr == '/' ) 
        {
          /* cope with multiple (useless) /s) */
          nameptr++;
          continue;
        }
      /* find the next / */
      name_end = strchr_m(nameptr, '/');

      /* oops - the last check for a / didn't find one. */
      if (name_end == NULL)
        break;

      /* next segment please */
      nameptr = name_end + 1;
      num_entries++;
    }

  if(num_entries == 0)
    return;

  if(( (*ppname_array) = (name_compare_entry *)malloc( 
           (num_entries + 1) * sizeof(name_compare_entry))) == NULL)
        {
    DEBUG(0,("set_namearray: malloc fail\n"));
    return;
        }

  /* Now copy out the names */
  nameptr = namelist;
  i = 0;
  while(*nameptr)
             {
      if ( *nameptr == '/' ) 
      {
          /* cope with multiple (useless) /s) */
          nameptr++;
          continue;
      }
      /* find the next / */
      if ((name_end = strchr_m(nameptr, '/')) != NULL) 
      {
          *name_end = 0;
         }

      /* oops - the last check for a / didn't find one. */
      if(name_end == NULL) 
        break;

      (*ppname_array)[i].is_wild = ms_has_wild(nameptr);
      if(((*ppname_array)[i].name = strdup(nameptr)) == NULL)
      {
        DEBUG(0,("set_namearray: malloc fail (1)\n"));
        return;
      }

      /* next segment please */
      nameptr = name_end + 1;
      i++;
    }
  
  (*ppname_array)[i].name = NULL;

  return;
}

/****************************************************************************
routine to free a namearray.
****************************************************************************/

void free_namearray(name_compare_entry *name_array)
{
  if(name_array == 0)
    return;

  if(name_array->name != NULL)
    free(name_array->name);

  free((char *)name_array);
}

/****************************************************************************
routine to do file locking
****************************************************************************/
int sys_fcntl_ptr(int fd, int cmd, void *arg)
{
	int ret;

	do {
		ret = fcntl(fd, cmd, arg);
	} while (ret == -1 && errno == EINTR);
	return ret;
}


BOOL fcntl_lock(int fd,int op,SMB_OFF_T offset,SMB_OFF_T count,int type)
{
  SMB_STRUCT_FLOCK lock;
  int ret;

  lock.l_type = type;
  lock.l_whence = SEEK_SET;
  lock.l_start = offset;
  lock.l_len = count;
  lock.l_pid = 0;

  ret = sys_fcntl_ptr(fd,op,&lock);

  if (ret == -1 && errno != 0)
    DEBUG(3,("fcntl_lock: fcntl lock gave errno %d (%s)\n",errno,strerror(errno)));

  /* a lock query */
  if (op == SMB_F_GETLK)
  {
    if ((ret != -1) &&
        (lock.l_type != F_UNLCK) && 
        (lock.l_pid != 0) && 
        (lock.l_pid != sys_getpid()))
    {
      DEBUG(3,("fcntl_lock: fd %d is locked by pid %d\n",fd,(int)lock.l_pid));
      return(True);
    }

    /* it must be not locked or locked by me */
    return(False);
  }

  /* a lock set or unset */
  if (ret == -1)
  {
    DEBUG(3,("fcntl_lock: lock failed at offset %.0f count %.0f op %d type %d (%s)\n",
          (double)offset,(double)count,op,type,strerror(errno)));
    return(False);
  }

  /* everything went OK */
  DEBUG(8,("fcntl_lock: Lock call successful\n"));

  return(True);
}

/*******************************************************************
set the horrid remote_arch string based on an enum.
********************************************************************/
void set_remote_arch(enum remote_arch_types type)
{
  ra_type = type;
  switch( type ) {
	case RA_WFWG:
		fstrcpy(remote_arch, "WfWg");
		break;
	case RA_OS2:
		fstrcpy(remote_arch, "OS2");
		break;
	case RA_WIN95:
		fstrcpy(remote_arch, "Win95");
		break;
	case RA_WINNT:
		fstrcpy(remote_arch, "WinNT");
		break;
	case RA_WIN2K:
		fstrcpy(remote_arch, "Win2K");
		break;
	case RA_WINXP:
		fstrcpy(remote_arch, "WinXP");
		break;
	case RA_WIN2K3:
		fstrcpy(remote_arch, "Win2K3");
		break;
	case RA_SAMBA:
		fstrcpy(remote_arch,"Samba");
		break;
	case RA_CIFSFS:
		fstrcpy(remote_arch,"CIFSFS");
		break;
	default:
		ra_type = RA_UNKNOWN;
		fstrcpy(remote_arch, "UNKNOWN");
		break;
	}

  	DEBUG(0,("set_remote_arch: Client arch is \'%s\'\n", remote_arch));
}

/*******************************************************************
 Get the remote_arch type.
********************************************************************/
enum remote_arch_types get_remote_arch()
{
  return ra_type;
}

/*******************************************************************
safe string copy into a fstring
********************************************************************/
void fstrcpy(char *dest, const char *src)
{
    int maxlength = sizeof(fstring) - 1;
    if (!dest) {
        DEBUG(0,("ERROR: NULL dest in fstrcpy\n"));
        return;
    }

    if (!src) {
        *dest = 0;
        return;
    }  
      
    while (maxlength-- && *src)
        *dest++ = *src++;
    *dest = 0;
    if (*src) {
        DEBUG(0,("ERROR: string overflow by %d in fstrcpy\n",
             strlen(src)));
    }    
}   

/*******************************************************************
safe string copy into a pstring
********************************************************************/
void pstrcpy(char *dest, const char *src)
{
    int maxlength = sizeof(pstring) - 1;
    if (!dest) {
        DEBUG(0,("ERROR: NULL dest in pstrcpy\n"));
        return;
    }
   
    if (!src) {
        *dest = 0;
        return;
    }
   
    while (maxlength-- && *src)
        *dest++ = *src++;
    *dest = 0;
    if (*src) {
        DEBUG(0,("ERROR: string overflow by %d in pstrcpy\n",
             strlen(src)));
    }
}  

#ifdef _DEBUG
void print_asc(int level, unsigned char *buf,int len)
{
	int i;
	for (i=0;i<len;i++)
		DEBUG(level,("%c", isprint(buf[i])?buf[i]:'.'));
}

void dump_data(int level,char *buf1,int len)
{
  unsigned char *buf = (unsigned char *)buf1;
  int i=0;
  if (len<=0) return;

  DEBUG(level,("[%03X] ",i));
  for (i=0;i<len;) {
    DEBUG(level,("%02X ",(int)buf[i]));
    i++;
    if (i%8 == 0) DEBUG(level,(" "));
    if (i%16 == 0) {      
      print_asc(level,&buf[i-16],8); DEBUG(level,(" "));
      print_asc(level,&buf[i-8],8); DEBUG(level,("\n"));
      if (i<len) DEBUG(level,("[%03X] ",i));
    }
  }
  if (i%16) {
    int n;

    n = 16 - (i%16);
    DEBUG(level,(" "));
    if (n>8) DEBUG(level,(" "));
    while (n--) DEBUG(level,("   "));

    n = MIN(8,i%16);
    print_asc(level,&buf[i-(i%16)],n); DEBUG(level,(" "));
    n = (i%16) - n;
    if (n>0) print_asc(level,&buf[i-n],n); 
    DEBUG(level,("\n"));    
  }
}
#endif	/*_DEBUG*/

char *tab_depth(int depth)
{
	static pstring spaces;
	memset(spaces, ' ', depth * 4);
	spaces[depth * 4] = 0;
	return spaces;
}

ssize_t sendfile_wrapper(int tofd, int fromfd, const DATA_HEAD *header, SMB_OFF_T offset, size_t count)
{
	size_t total=0;
	ssize_t ret;
	size_t hdr_len = 0;

	if (header) {
		hdr_len = header->length;
		while (total < hdr_len) {
//we use MSG_MORE instead of set the tcp opt with TCP_CORK :)
			ret = send(tofd, header->data + total,hdr_len - total, MSG_MORE);
			if (ret == -1)
				return -1;
			total += ret;
		}
	}

	total = count;
	while (total) {
		ssize_t nwritten;
		do {
			nwritten = sys_sendfile(tofd, fromfd, &offset, total);
		} while (nwritten == -1 && errno == EINTR);
		if (nwritten == -1) {
			if (errno == ENOSYS) {
				errno = EINTR; /* Normally we can never return this. */
			}
			return -1;
		}
		if (nwritten == 0)
			return -1; /* we're at EOF here... */
		total -= nwritten;
	}
	return count + hdr_len;
}

/*******************************************************************
  get ready for syslog stuff
  ******************************************************************/
void setup_logging(char *pname,BOOL interactive)
{
#ifdef _DEBUG
#ifdef SYSLOG
  if (!interactive) {
    char *p = strrchr_m(pname,'/');
    if (p) pname = p+1;
#ifdef LOG_DAEMON
    openlog(pname, LOG_PID, SYSLOG_FACILITY);
#else /* for old systems that have no facility codes. */
    openlog(pname, LOG_PID);
#endif
  }
#endif
  if (interactive) {	//set interactive to be true to print debug messages on screen:)
    stdout_logging = True;
    dbf = stdout;
  }
#endif	/*_DEBUG*/
}

/*******************************************************************
 Determine if a pattern contains any Microsoft wildcard characters.
*******************************************************************/

BOOL ms_has_wild(const char *s)
{
	char c;
	while ((c = *s++)) {
		switch (c) {
		case '*':
		case '?':
		case '<':
		case '>':
		case '"':
			return True;
		}
	}
	return False;
}

void sub_set_smb_name(const char *name)
{
	fstring tmp;

	/* don't let anonymous logins override the name */
	if (! *name)
		return;

	fstrcpy(tmp,name);
	trim_char(tmp,' ',' ');
	strlower_m(tmp);
	alpha_strcpy(sesssetup_user,tmp,SAFE_NETBIOS_CHARS,sizeof(sesssetup_user)-1);
}




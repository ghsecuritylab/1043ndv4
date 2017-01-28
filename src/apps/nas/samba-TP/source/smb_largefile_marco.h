#ifdef LARGE_FILE_SUPPORT
#define SMB_STRUCT_STAT struct stat64
#define SMB_STRUCT_FLOCK struct flock64
#define SMB_F_SETLKW F_SETLKW64
#define SMB_F_SETLK F_SETLK64
#define SMB_F_GETLK F_GETLK64
#define SMB_OFF_T off64_t
#else
#define SMB_STRUCT_STAT struct stat
#define SMB_STRUCT_FLOCK struct flock
#define SMB_F_SETLKW F_SETLKW
#define SMB_F_SETLK F_SETLK
#define SMB_F_GETLK F_GETLK
#define SMB_OFF_T off_t
#endif

#define SMB_INO_T ino_t
#define SMB_DEV_T dev_t

#ifdef LARGE_FILE_SUPPORT
#define sys_open(x,y,z) open64(x,y,z)
#define sys_stat(x,y) stat64(x,y)
#define sys_lstat(x,y) lstat64(x,y)
#define sys_fstat(x,y) fstat64(x,y)
#define sys_lseek(x,y,z) lseek64(x,y,z)
#define sys_readdir(x) readdir64(x)
#define sys_sendfile(a,b,c,d) sendfile64(a,b,c,d)
#define sys_pread(a,b,c,d) pread64(a,b,c,d)
#define sys_ftruncate(x,y) ftruncate64(x,y)		//take care of this! Otherwise some data may be over written...
#else
#define sys_open(x,y,z) open(x,y,z)
#define sys_stat(x,y) stat(x,y)
#define sys_lstat(x,y) lstat(x,y)
#define sys_fstat(x,y) fstat(x,y)
#define sys_lseek(x,y,z) lseek(x,y,z)
#define sys_readdir(x) readdir(x)
#define sys_sendfile(a,b,c,d) sendfile(a,b,c,d)
#define sys_pread(a,b,c,d) pread(a,b,c,d)
#define sys_ftruncate(x,y) ftruncate(x,y)	
#endif

#define sys_unlink(x) unlink(x)
#define sys_closedir(x) closedir(x)
#define sys_opendir(x) opendir(x)
#define sys_waitpid(x,y,z) waitpid(x,y,z)
#define sys_mkdir(x,y) mkdir(x,y)
#define sys_rmdir(x) rmdir(x)
#define sys_chdir(x) chdir(x)
#define sys_chmod(x,y) chmod(x,y)
#define sys_getwd(x) getcwd(x,sizeof (pstring))
#define sys_chown(x,y,z) chown(x,y,z)
#define sys_chroot(x) chroot(x)

#define SMB_BIG_UINT unsigned long long
#define SBIG_UINT(p, ofs, v) (SIVAL(p,ofs,(v)&0xFFFFFFFF), SIVAL(p,(ofs)+4,(v)>>32))

#ifdef LARGE_FILE_SUPPORT
#define SOFF_T(p, ofs, v) (SIVAL(p,ofs,(v)&0xFFFFFFFF), SIVAL(p,(ofs)+4,(v)>>32))
#define IVAL_TO_SMB_OFF_T(buf,off) ((SMB_OFF_T)(( ((SMB_BIG_UINT)(IVAL((buf),(off)))) & ((SMB_BIG_UINT)0xFFFFFFFF) )))
#else
#define IVAL_TO_SMB_OFF_T(buf,off) ((SMB_OFF_T)(( ((SMB_BIG_UINT)(IVAL((buf),(off)))) & ((SMB_BIG_UINT)0xFFFFFFFF) )))
#define SOFF_T(p, ofs, v) (SIVAL(p,ofs,v),SIVAL(p,(ofs)+4,0))
#endif



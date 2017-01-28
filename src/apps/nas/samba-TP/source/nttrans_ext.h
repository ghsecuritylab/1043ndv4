#define MAX_OPEN_PIPES 100
#define PIPE_HANDLE_OFFSET 0x800

enum FAKE_FILE_TYPE {
	FAKE_FILE_TYPE_NONE = 0,
	FAKE_FILE_TYPE_QUOTA	
};

typedef struct data_head{
	uint8 *data;
	size_t length;
}DATA_HEAD;

/* Standard access rights. */

#define STD_RIGHT_DELETE_ACCESS		0x00010000
#define STD_RIGHT_READ_CONTROL_ACCESS	0x00020000
#define STD_RIGHT_WRITE_DAC_ACCESS	0x00040000
#define STD_RIGHT_WRITE_OWNER_ACCESS	0x00080000
#define STD_RIGHT_SYNCHRONIZE_ACCESS	0x00100000

#define STD_RIGHT_ALL_ACCESS		0x001F0000

#define STANDARD_RIGHTS_REQUIRED_ACCESS \
		(STD_RIGHT_DELETE_ACCESS	| \
		STD_RIGHT_READ_CONTROL_ACCESS	| \
		STD_RIGHT_WRITE_DAC_ACCESS	| \
		STD_RIGHT_WRITE_OWNER_ACCESS)	/* 0x000f0000 */

/* these are for the NT create_and_X */
#define smb_ntcreate_NameLength (smb_vwv0 + 5)
#define smb_ntcreate_Flags (smb_vwv0 + 7)
#define smb_ntcreate_RootDirectoryFid (smb_vwv0 + 11)
#define smb_ntcreate_DesiredAccess (smb_vwv0 + 15)
#define smb_ntcreate_AllocationSize (smb_vwv0 + 19)
#define smb_ntcreate_FileAttributes (smb_vwv0 + 27)
#define smb_ntcreate_ShareAccess (smb_vwv0 + 31)
#define smb_ntcreate_CreateDisposition (smb_vwv0 + 35)
#define smb_ntcreate_CreateOptions (smb_vwv0 + 39)
#define smb_ntcreate_ImpersonationLevel (smb_vwv0 + 43)
#define smb_ntcreate_SecurityFlags (smb_vwv0 + 47)

/* CreateOptions field. */
#define FILE_DIRECTORY_FILE       0x0001
#define FILE_WRITE_THROUGH        0x0002
#define FILE_SEQUENTIAL_ONLY      0x0004
#define FILE_NON_DIRECTORY_FILE   0x0040
#define FILE_NO_EA_KNOWLEDGE      0x0200
#define FILE_EIGHT_DOT_THREE_ONLY 0x0400
#define FILE_RANDOM_ACCESS        0x0800
#define FILE_DELETE_ON_CLOSE      0x1000
#define FILE_OPEN_BY_FILE_ID	  0x2000

/* CreateDisposition field. */
#define FILE_SUPERSEDE 0
#define FILE_OPEN 1
#define FILE_CREATE 2
#define FILE_OPEN_IF 3
#define FILE_OVERWRITE 4
#define FILE_OVERWRITE_IF 5

/* open disposition values */
#define FILE_EXISTS_FAIL 0
#define FILE_EXISTS_OPEN 1
#define FILE_EXISTS_TRUNCATE 2

#define FILE_CREATE_IF_NOT_EXIST 0x10
#define FILE_FAIL_IF_NOT_EXIST 0

#define SYNCHRONIZE_ACCESS   (1L<<20) /* 0x00100000 */
#define FILE_ALL_ACCESS       0x000001FF
#define STANDARD_RIGHTS_READ_ACCESS	STD_RIGHT_READ_CONTROL_ACCESS /* 0x00020000 */
#define FILE_READ_DATA        0x00000001
#define FILE_READ_ATTRIBUTES  0x00000080
#define FILE_READ_EA          0x00000008 /* File and directory */
#define FILE_WRITE_DATA       0x00000002
#define FILE_WRITE_ATTRIBUTES 0x00000100
#define FILE_WRITE_EA         0x00000010 /* File and directory */
#define FILE_APPEND_DATA      0x00000004
#define STANDARD_RIGHTS_EXECUTE_ACCESS	STD_RIGHT_READ_CONTROL_ACCESS /* 0x00020000 */
#define FILE_EXECUTE          0x00000020
#define DELETE_ACCESS        (1L<<16) /* 0x00010000 */
#define WRITE_DAC_ACCESS     (1L<<18) /* 0x00040000 */
#define WRITE_OWNER_ACCESS   (1L<<19) /* 0x00080000 */
#define SYSTEM_SECURITY_ACCESS (1L<<24)           /* 0x01000000 */
#define READ_CONTROL_ACCESS  (1L<<17) /* 0x00020000 */

#define SHARE_MODE_MASK 0x7
#define SHARE_MODE_SHIFT 4
#define ALLOW_SHARE_DELETE (1<<15)
#define FILE_DELETE_ON_CLOSE      0x1000
#define DELETE_ON_CLOSE_FLAG (1<<16)
#define SET_DENY_MODE(x) (((x) & SHARE_MODE_MASK) <<SHARE_MODE_SHIFT)
#define FILE_FLAG_WRITE_THROUGH    0x80000000L
#define FILE_SYNC_OPENMODE (1<<14)

#define REQUEST_OPLOCK 2
#define REQUEST_BATCH_OPLOCK 4

#define FILE_ATTRIBUTE_TEMPORARY	0x100L

/* ShareAccess field. */
#define FILE_SHARE_NONE 0 /* Cannot be used in bitmask. */
#define FILE_SHARE_READ 1
#define FILE_SHARE_WRITE 2
#define FILE_SHARE_DELETE 4

typedef struct generic_mapping {
	uint32 generic_read;
	uint32 generic_write;
	uint32 generic_execute;
	uint32 generic_all;
} GENERIC_MAPPING;

/* Mapping of generic access rights for files to specific rights. */

#define FILE_GENERIC_ALL (STANDARD_RIGHTS_REQUIRED_ACCESS| SYNCHRONIZE_ACCESS|FILE_ALL_ACCESS)

#define FILE_GENERIC_READ (STANDARD_RIGHTS_READ_ACCESS|FILE_READ_DATA|FILE_READ_ATTRIBUTES|\
							FILE_READ_EA|SYNCHRONIZE_ACCESS)

#define FILE_GENERIC_WRITE (STD_RIGHT_READ_CONTROL_ACCESS|FILE_WRITE_DATA|FILE_WRITE_ATTRIBUTES|\
							FILE_WRITE_EA|FILE_APPEND_DATA|SYNCHRONIZE_ACCESS)

#define FILE_GENERIC_EXECUTE (STANDARD_RIGHTS_EXECUTE_ACCESS|\
								FILE_EXECUTE|SYNCHRONIZE_ACCESS)

#define GENERIC_ALL_ACCESS     (1<<28)            /* 0x10000000 */
#define GENERIC_EXECUTE_ACCESS (1<<29)            /* 0x20000000 */
#define GENERIC_WRITE_ACCESS   (1<<30)            /* 0x40000000 */
#define GENERIC_READ_ACCESS   (((unsigned)1)<<31) /* 0x80000000 */

#define SAMBA_ATTRIBUTES_MASK		0x7F

#define GET_DELETE_ON_CLOSE_FLAG(x) (((x) & DELETE_ON_CLOSE_FLAG) ? True : False)
#define VALID_STAT(st) ((st).st_nlink != 0)  
#define GET_FILE_CREATE_DISPOSITION(x) ((x) & (FILE_CREATE_IF_NOT_EXIST|FILE_FAIL_IF_NOT_EXIST))
#define GET_ALLOW_SHARE_DELETE(x) (((x) & ALLOW_SHARE_DELETE) ? True : False)
#define SET_ALLOW_SHARE_DELETE(x) ((x) ? ALLOW_SHARE_DELETE : 0)

#define FILE_WAS_OPENED 1
#define FILE_WAS_CREATED 2
#define FILE_WAS_OVERWRITTEN 3

#define FILE_ATTRIBUTE_NORMAL		0x080L

/* mask for open disposition. */
#define FILE_OPEN_MASK 0x3
#define GET_FILE_OPEN_DISPOSITION(x) ((x) & FILE_OPEN_MASK)

#define SMB_ROUNDUP(x,r) ( ((x)%(r)) ? ( (((x)+(r))/(r))*(r) ) : (x))


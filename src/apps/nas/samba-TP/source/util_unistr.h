/* generic iconv conversion structure */

#define DEFAULT_DISPLAY_CHARSET "UTF8"

/* Default dos charset name */
//#define DEFAULT_DOS_CHARSET "CP850"
#define DEFAULT_DOS_CHARSET "ASSCII"

/* Default unix charset name */
#define DEFAULT_UNIX_CHARSET "UTF8"

#define HAVE_SETLOCALE 1

/* string manipulation flags - see clistr.c and srvstr.c */
#define STR_TERMINATE 1
#define STR_UPPER 2
#define STR_ASCII 4
#define STR_UNICODE 8
#define STR_NOALIGN 16
#define STR_TERMINATE_ASCII 128

typedef uint16 smb_ucs2_t;

/* this defines the charset types used in samba */
typedef enum {CH_UCS2=0, CH_UNIX=1, CH_DISPLAY=2, CH_DOS=3, CH_UTF8=4} charset_t;

typedef struct _smb_iconv_t {
	size_t (*direct)(void *cd, const char **inbuf, size_t *inbytesleft,
			 char **outbuf, size_t *outbytesleft);
	size_t (*pull)(void *cd, const char **inbuf, size_t *inbytesleft,
		       char **outbuf, size_t *outbytesleft);
	size_t (*push)(void *cd, const char **inbuf, size_t *inbytesleft,
		       char **outbuf, size_t *outbytesleft);
	void *cd_direct, *cd_pull, *cd_push;
	char *from_name, *to_name;
} *smb_iconv_t;

struct max_n {
	const smb_ucs2_t *predot;
	const smb_ucs2_t *postdot;
};

#define SAFE_STRING_FUNCTION_NAME ("")
#define SAFE_STRING_LINE (0)
#define CHECK_STRING_SIZE(d, len) (sizeof(d) != (len) && sizeof(d) != sizeof(char *))

size_t __unsafe_string_function_usage_here_size_t__(void);

#define srvstr_push(base_ptr, dest, src, dest_len, flags) srvstr_push_fn2(SAFE_STRING_FUNCTION_NAME, SAFE_STRING_LINE, base_ptr, dest, src, dest_len, flags)

#define srvstr_push_fn2(fn_name, fn_line, base_ptr, dest, src, dest_len, flags) \
   	 	(CHECK_STRING_SIZE(dest, dest_len) \
    		? __unsafe_string_function_usage_here_size_t__() \
    		: srvstr_push_fn(fn_name, fn_line, base_ptr, dest, src, dest_len, flags))

/* Max allowable allococation - 256mb - 0x10000000 */
#define MAX_ALLOC_SIZE (1024*1024*256)

#define PSTRING_LEN 1024
typedef smb_ucs2_t wpstring[PSTRING_LEN];

#define pull_string_fn2(fn_name, fn_line, base_ptr, dest, src, dest_len, src_len, flags) \
    		(CHECK_STRING_SIZE(dest, dest_len) \
    		? __unsafe_string_function_usage_here_size_t__() \
    		: pull_string_fn(fn_name, fn_line, base_ptr, dest, src, dest_len, src_len, flags))

#define pull_string(base_ptr, dest, src, dest_len, src_len, flags) \
		pull_string_fn2(SAFE_STRING_FUNCTION_NAME, SAFE_STRING_LINE, base_ptr, dest, src, dest_len, src_len, flags)

#define srvstr_pull_buf(inbuf, dest, src, dest_len, flags) \
    		pull_string(inbuf, dest, src, dest_len, smb_bufrem(inbuf, src), flags)

#define srvstr_pull(base_ptr, dest, src, dest_len, src_len, flags) \
    		pull_string(base_ptr, dest, src, dest_len, src_len, flags)

#define alpha_strcpy(dest,src,other_safe_chars,maxlength) alpha_strcpy_fn(SAFE_STRING_FUNCTION_NAME,SAFE_STRING_LINE,dest,src,other_safe_chars,maxlength)

#define SAFE_NETBIOS_CHARS ". -_"

#define strcasecmp(s1,s2) StrCaseCmp(s1,s2)
#define strncasecmp(s1,s2,n) StrnCaseCmp(s1,s2,n)

#if 0
struct max_n {
	const smb_ucs2_t *predot;
	const smb_ucs2_t *postdot;
};

char *lib_path(const char *name);
char *fd_load(int fd, size_t *size);
char *file_load(const char *fname, size_t *size);
void *map_file(char *fname, size_t size);
void load_case_tables(void);
void lazy_initialize_conv(void);
static const char *charset_name(charset_t ch);
void init_iconv(void);
void init_valid_table(void);
int check_dos_char(smb_ucs2_t c);
void init_doschar_table(void);
static int check_dos_char_slowly(smb_ucs2_t c);
size_t convert_string(charset_t from, charset_t to, void const *src, size_t srclen, void *dest, size_t destlen, BOOL allow_bad_conv);
size_t strlen_w(const smb_ucs2_t *src);
static size_t convert_string_internal(charset_t from, charset_t to, void const *src, size_t srclen, void *dest, size_t destlen, BOOL allow_bad_conv);
char lp_failed_convert_char(void);
size_t convert_string_allocate(charset_t from, charset_t to, void const *src, size_t srclen, void **dest, BOOL allow_bad_conv);
size_t push_ucs2_allocate(smb_ucs2_t **dest, const char *src);
smb_ucs2_t toupper_w(smb_ucs2_t val);
smb_ucs2_t tolower_w( smb_ucs2_t val );
int strcasecmp_w(const smb_ucs2_t *a, const smb_ucs2_t *b);
char *strchr_m(const char *src, char c);
size_t pull_ucs2_pstring(char *dest, const void *src);
size_t pull_ucs2(const void *base_ptr, char *dest, const void *src, size_t dest_len, size_t src_len, int flags);
size_t strnlen_w(const smb_ucs2_t *src, size_t max);
smb_ucs2_t *strchr_w(const smb_ucs2_t *s, smb_ucs2_t c);
static size_t ucs2_align(const void *base_ptr, const void *p, int flags);
size_t push_ucs2(const void *base_ptr, void *dest, const char *src, size_t dest_len, int flags);
char *strrchr_m(const char *s, char c);
size_t unix_strupper(const char *src, size_t srclen, char *dest, size_t destlen);
BOOL strupper_w(smb_ucs2_t *s);
size_t unix_strlower(const char *src, size_t srclen, char *dest, size_t destlen);
BOOL strlower_w(smb_ucs2_t *s);
BOOL islower_w(smb_ucs2_t c);
BOOL isupper_w(smb_ucs2_t c);
void string_replace_w(smb_ucs2_t *s, smb_ucs2_t oldc, smb_ucs2_t newc);
char *strstr_m(const char *src, const char *findstr);
size_t pull_ucs2_allocate(char **dest, const smb_ucs2_t *src);
smb_ucs2_t *strstr_w(const smb_ucs2_t *s, const smb_ucs2_t *ins);
int strncmp_w(const smb_ucs2_t *a, const smb_ucs2_t *b, size_t len);
size_t push_ascii(void *dest, const char *src, size_t dest_len, int flags);
int ms_fnmatch(const char *pattern, const char *string, enum protocol_types protocol, BOOL is_case_sensitive);
static int null_match(const smb_ucs2_t *p);
static int ms_fnmatch_core(const smb_ucs2_t *p, const smb_ucs2_t *n, struct max_n *max_n, const smb_ucs2_t *ldot,BOOL is_case_sensitive);
void *calloc_array(size_t size, size_t nmemb);
smb_ucs2_t *strrchr_w(const smb_ucs2_t *s, smb_ucs2_t c);
char *string_truncate(char *s, unsigned int length);
size_t align_string(const void *base_ptr, const char *p, int flags);
size_t srvstr_push_fn(const char *function, unsigned int line, const char *base_ptr,
					void *dest, const char *src, int dest_len, int flags);
size_t push_string_fn(const char *function, unsigned int line, const void *base_ptr, 
				void *dest, const char *src, size_t dest_len, int flags);
size_t pull_string_fn(const char *function, unsigned int line, const void *base_ptr, char *dest, const void *src, size_t dest_len, size_t src_len, int flags);
size_t pull_ascii(char *dest, const void *src, size_t dest_len, size_t src_len, int flags);
int set_message_end(void *outbuf,void *end_ptr);
int set_message_bcc(char *buf,int num_bytes);
size_t srvstr_get_path(char *inbuf, char *dest, const char *src, size_t dest_len, size_t src_len, int flags, NTSTATUS *err, BOOL allow_wcard_names);
NTSTATUS check_path_syntax(pstring destname, const pstring srcname, BOOL allow_wcard_names);
size_t next_mb_char_size(const char *s);
int add_signature(char *outbuf, char *p);
size_t push_ascii_fstring(void *dest, const char *src);
size_t dos_PutUniCode(char *dst,const char *src, ssize_t len, BOOL null_terminate);
char *alpha_strcpy_fn(const char *fn, int line, char *dest, const char *src, const char *other_safe_chars, size_t maxlength);
//size_t str_charnum(const char *s);
//size_t str_ascii_charnum(const char *s);
BOOL trim_char(char *s,char cfront,char cback);
#endif


/*
*
*##############this file is added additionally to support ANSI & UTF8 convertion##########################
*
*/
//#include "util_unistr.h"
#include "includes.h"

extern int DEBUGLEVEL;

#ifndef MAXUNI
#define MAXUNI 1024
#endif

#define NUM_CHARSETS 5

static smb_iconv_t conv_handles[NUM_CHARSETS][NUM_CHARSETS];
static BOOL conv_silent; /* Should we do a debug if the conversion fails ? */

/* these 3 tables define the unicode case handling.  They are loaded
   at startup either via mmap() or read() from the lib directory */
static smb_ucs2_t *upcase_table;
static smb_ucs2_t *lowcase_table;
static uint8 *valid_table;

extern fstring myworkgroup;
extern int Protocol;

#define IS_DIRECTORY_SEP(c) ((c) == '\\' || (c) == '/')

/**
 * This table says which Unicode characters are valid dos
 * characters.
 *
 * Each value is just a single bit.
 **/
static uint8 doschar_table[8192]; /* 65536 characters / 8 bits/byte */

static uint16 tmpbuf[sizeof(pstring)];

/* this is used to prevent lots of mallocs of size 1 */
static char *null_string = NULL;

/*
   case handling on filenames 
*/
int case_default = CASE_LOWER;

//static function declare for unistr....
static size_t convert_string_internal(charset_t from, charset_t to,
		      							void const *src, size_t srclen, 
		      							void *dest, size_t destlen, 
		      							BOOL allow_bad_conv);
static const char *charset_name(charset_t ch);
static void init_valid_table(void);
static int check_dos_char(smb_ucs2_t c);
static void init_doschar_table(void);
static char lp_failed_convert_char(void);
static size_t convert_string_allocate(charset_t from, charset_t to,
			       						void const *src, size_t srclen, 
			       						void **dest, BOOL allow_bad_conv);
static smb_ucs2_t toupper_w(smb_ucs2_t val);
static smb_ucs2_t tolower_w( smb_ucs2_t val );
static size_t pull_ucs2_pstring(char *dest, const void *src);
static size_t strnlen_w(const smb_ucs2_t *src, size_t max);
static smb_ucs2_t *strchr_w(const smb_ucs2_t *s, smb_ucs2_t c);
static size_t ucs2_align(const void *base_ptr, const void *p, int flags);
static BOOL strlower_w(smb_ucs2_t *s);
static size_t pull_ucs2_allocate(char **dest, const smb_ucs2_t *src);
static smb_ucs2_t *strstr_w(const smb_ucs2_t *s, const smb_ucs2_t *ins);
static int strncmp_w(const smb_ucs2_t *a, const smb_ucs2_t *b, size_t len);
static smb_ucs2_t *strrchr_w(const smb_ucs2_t *s, smb_ucs2_t c);
static int ms_fnmatch_core(const smb_ucs2_t *p, const smb_ucs2_t *n, 
			   				struct max_n *max_n, const smb_ucs2_t *ldot,
			   				BOOL is_case_sensitive);
static size_t push_string_fn(const char *function, unsigned int line, 
							const void *base_ptr, void *dest, const char *src, 
							size_t dest_len, int flags);
static size_t pull_ascii(char *dest, const void *src, size_t dest_len, size_t src_len, int flags);
static NTSTATUS check_path_syntax(pstring destname, const pstring srcname, BOOL allow_wcard_names);
static size_t next_mb_char_size(const char *s);
static void lazy_initialize_conv(void);
//##################################################//


//#define LIBDIR "/etc/samba/lib"	//we will add this in Makefile at last....
static char *lib_path(const char *name)
{
	static pstring fname;
	sprintf(fname, "%s/%s", LIBDIR, name);
	return fname;
}


/****************************************************************************
 Load a file into memory from a fd.
****************************************************************************/ 

static char *fd_load(int fd, size_t *size)
{
	struct stat sbuf;
	char *p;

	if (fstat(fd, &sbuf) != 0) {
		return NULL;
	}

	p = (char *)SMB_MALLOC(sbuf.st_size+1);
	if (!p) {
		return NULL;
	}

	if (read(fd, p, sbuf.st_size) != sbuf.st_size) {
		SAFE_FREE(p);
		return NULL;
	}
	p[sbuf.st_size] = 0;

	if (size) {
		*size = sbuf.st_size;
	}

	return p;
}

/****************************************************************************
 Load a file into memory.
****************************************************************************/

static char *file_load(const char *fname, size_t *size)
{
	int fd;
	char *p;

	if (!fname || !*fname) {
		return NULL;
	}
	
	fd = open(fname,O_RDONLY);
	if (fd == -1) {
		return NULL;
	}

	p = fd_load(fd, size);
	close(fd);
	return p;
}


/*******************************************************************
 mmap (if possible) or read a file.
********************************************************************/

static void *map_file(char *fname, size_t size)
{
	size_t s2 = 0;
	void *p = NULL;

	int fd;
	fd = open(fname, O_RDONLY, 0);
	if (fd == -1) {
		DEBUG(2,("map_file: Failed to load %s - %s\n", fname, strerror(errno)));
		return NULL;
	}
	p = mmap(NULL, size, PROT_READ, MAP_SHARED|MAP_FILE, fd, 0);
	close(fd);
	if (p == MAP_FAILED) {
		DEBUG(1,("map_file: Failed to mmap %s - %s\n", fname, strerror(errno)));
		return NULL;
	}

	if (!p) {
		p = file_load(fname, &s2);
		if (!p) {
			return NULL;
		}
		if (s2 != size) {
			DEBUG(1,("map_file: incorrect size for %s - got %lu expected %lu\n",
				 fname, (unsigned long)s2, (unsigned long)size));
			SAFE_FREE(p);	
			return NULL;
		}
	}
	return p;
}

/**
 * Load or generate the case handling tables.
 *
 * The case tables are defined in UCS2 and don't depend on any
 * configured parameters, so they never need to be reloaded.
 **/
void load_case_tables(void)
{
	static int initialised;
	int i;

	if (initialised) return;
	initialised = 1;

	upcase_table = map_file(lib_path("upcase.dat"), 0x20000);
	lowcase_table = map_file(lib_path("lowcase.dat"), 0x20000);

	/* we would like Samba to limp along even if these tables are
	   not available */
	if (!upcase_table) {
		DEBUG(1,("creating lame upcase table\n"));
		upcase_table = SMB_MALLOC(0x20000);
		for (i=0;i<0x10000;i++) {
			smb_ucs2_t v;
			SSVAL(&v, 0, i);
			upcase_table[v] = i;
		}
		for (i=0;i<256;i++) {
			smb_ucs2_t v;
			SSVAL(&v, 0, UCS2_CHAR(i));
			upcase_table[v] = UCS2_CHAR(islower(i)?toupper(i):i);
		}
	}

	if (!lowcase_table) {
		DEBUG(1,("creating lame lowcase table\n"));
		lowcase_table = SMB_MALLOC(0x20000);
		for (i=0;i<0x10000;i++) {
			smb_ucs2_t v;
			SSVAL(&v, 0, i);
			lowcase_table[v] = i;
		}
		for (i=0;i<256;i++) {
			smb_ucs2_t v;
			SSVAL(&v, 0, UCS2_CHAR(i));
			lowcase_table[v] = UCS2_CHAR(isupper(i)?tolower(i):i);
		}
	}
}

static void lazy_initialize_conv(void)
{
	static int initialized = False;

	if (!initialized) {
		initialized = True;
		load_case_tables();
		init_iconv();
	}
}

/**
 * Return the name of a charset to give to iconv().
 **/
static const char *charset_name(charset_t ch)
{
	const char *ret = NULL;

	if (ch == CH_UCS2) ret = "UTF-16LE";
	else if (ch == CH_UNIX) ret = DEFAULT_DISPLAY_CHARSET;
	else if (ch == CH_DOS) ret = DEFAULT_DOS_CHARSET;
	else if (ch == CH_DISPLAY) ret = DEFAULT_UNIX_CHARSET;
	else if (ch == CH_UTF8) ret = "UTF8";


	#if defined(HAVE_NL_LANGINFO) && defined(CODESET)
	if (ret && !strcmp(ret, "LOCALE")) {
		const char *ln = NULL;

		setlocale(LC_ALL, "");
	
		ln = nl_langinfo(CODESET);
		if (ln) {
			/* Check whether the charset name is supported
			   by iconv */
			smb_iconv_t handle = smb_iconv_open(ln,"UCS-2LE");
			if (handle == (smb_iconv_t) -1) {
				DEBUG(5,("Locale charset '%s' unsupported, using ASCII instead\n", ln));
				ln = NULL;
			} else {
				DEBUG(5,("Substituting charset '%s' for LOCALE\n", ln));
				smb_iconv_close(handle);
			}
		}
		ret = ln;
	}
#ifdef HAVE_SETLOCALE
	/* We set back the locale to C to get ASCII-compatible toupper/lower functions.
	   For now we do not need any other POSIX localisations anyway. When we should
	   really need localized string functions one day we need to write our own
	   ascii_tolower etc.
	*/
	setlocale(LC_ALL, "C");
 #endif

#endif

	if (!ret || !*ret) ret = "ASCII";
	return ret;
}

void init_iconv(void)
{
	int c1, c2;
	BOOL did_reload = False;

	/* so that charset_name() works we need to get the UNIX<->UCS2 going
	   first */
	if (!conv_handles[CH_UNIX][CH_UCS2])
		conv_handles[CH_UNIX][CH_UCS2] = smb_iconv_open(charset_name(CH_UCS2), "ASCII");

	if (!conv_handles[CH_UCS2][CH_UNIX])
		conv_handles[CH_UCS2][CH_UNIX] = smb_iconv_open("ASCII", charset_name(CH_UCS2));

	for (c1=0;c1<NUM_CHARSETS;c1++) {
		for (c2=0;c2<NUM_CHARSETS;c2++) {
			const char *n1 = charset_name((charset_t)c1);
			const char *n2 = charset_name((charset_t)c2);
			if (conv_handles[c1][c2] &&
			    strcmp(n1, conv_handles[c1][c2]->from_name) == 0 &&
			    strcmp(n2, conv_handles[c1][c2]->to_name) == 0)
				continue;

			did_reload = True;

			if (conv_handles[c1][c2])
				smb_iconv_close(conv_handles[c1][c2]);

			conv_handles[c1][c2] = smb_iconv_open(n2,n1);
			if (conv_handles[c1][c2] == (smb_iconv_t)-1) {
				DEBUG(0,("init_iconv: Conversion from %s to %s not supported\n",
					 charset_name((charset_t)c1), charset_name((charset_t)c2)));
				if (c1 != CH_UCS2) {
					n1 = "ASCII";
				}
				if (c2 != CH_UCS2) {
					n2 = "ASCII";
				}
				DEBUG(0,("init_iconv: Attempting to replace with conversion from %s to %s\n",
					n1, n2 ));
				conv_handles[c1][c2] = smb_iconv_open(n2,n1);
				if (!conv_handles[c1][c2]) {
					DEBUG(0,("init_iconv: Conversion from %s to %s failed", n1, n2));
				}
			}
		}
	}

	if (did_reload) {
		/* XXX: Does this really get called every time the dos
		 * codepage changes? */
		/* XXX: Is the did_reload test too strict? */
		conv_silent = True;
		init_doschar_table();
		init_valid_table();
		conv_silent = False;
	}
}

static void init_valid_table(void)
{
	static int mapped_file;
	int i;
	const char *allowed = ".!#$%&'()_-@^`~";
	uint8 *valid_file;

	if (mapped_file) {
		/* Can't unmap files, so stick with what we have */
		return;
	}

	valid_file = map_file(lib_path("valid.dat"), 0x10000);
	if (valid_file) {
		valid_table = valid_file;
		mapped_file = 1;
		return;
	}

	/* Otherwise, we're using a dynamically created valid_table.
	 * It might need to be regenerated if the code page changed.
	 * We know that we're not using a mapped file, so we can
	 * free() the old one. */
	if (valid_table) 
		free(valid_table);

	DEBUG(2,("creating default valid table\n"));
	valid_table = SMB_MALLOC(0x10000);
	for (i=0;i<128;i++)
		valid_table[i] = isalnum(i) || strchr(allowed,i);
	
	for (;i<0x10000;i++) {
		smb_ucs2_t c;
		SSVAL(&c, 0, i);
		valid_table[i] = check_dos_char(c);
	}
}

static int check_dos_char(smb_ucs2_t c)
{
	lazy_initialize_conv();
	
	/* Find the right byte, and right bit within the byte; return
	 * 1 or 0 */
	return (doschar_table[(c & 0xffff) / 8] & (1 << (c & 7))) != 0;
}


static int check_dos_char_slowly(smb_ucs2_t c)
{
	char buf[10];
	smb_ucs2_t c2 = 0;
	int len1, len2;
	len1 = convert_string(CH_UCS2, CH_DOS, &c, 2, buf, sizeof(buf),False);
	if (len1 == 0) return 0;
	len2 = convert_string(CH_DOS, CH_UCS2, buf, len1, &c2, 2,False);
	if (len2 != 2) return 0;
	return (c == c2);
}

static void init_doschar_table(void)
{
	int i, j, byteval;

	/* For each byte of packed table */
	
	for (i = 0; i <= 0xffff; i += 8) {
		byteval = 0;
		for (j = 0; j <= 7; j++) {
			smb_ucs2_t c;

			c = i + j;
			
			if (check_dos_char_slowly(c))
				byteval |= 1 << j;
		}
		doschar_table[i/8] = byteval;
	}
}

size_t convert_string(charset_t from, charset_t to,
		      void const *src, size_t srclen, 
		      void *dest, size_t destlen, BOOL allow_bad_conv)
{
	/*
	 * NB. We deliberately don't do a strlen here if srclen == -1.
	 * This is very expensive over millions of calls and is taken
	 * care of in the slow path in convert_string_internal. JRA.
	 */

	if (srclen == 0)
		return 0;

	if (from != CH_UCS2 && to != CH_UCS2) {
		const unsigned char *p = (const unsigned char *)src;
		unsigned char *q = (unsigned char *)dest;
		size_t slen = srclen;
		size_t dlen = destlen;
		unsigned char lastp = '\0';
		size_t retval = 0;

		/* If all characters are ascii, fast path here. */
		while (slen && dlen) {
			if ((lastp = *p) <= 0x7f) {
				*q++ = *p++;
				if (slen != (size_t)-1) {
					slen--;
				}
				dlen--;
				retval++;
				if (!lastp)
					break;
			} else {
				return retval + convert_string_internal(from, to, p, slen, q, dlen, allow_bad_conv);
			}
		}
		if (!dlen) {
			/* Even if we fast path we should note if we ran out of room. */
			if (((slen != (size_t)-1) && slen) ||
					((slen == (size_t)-1) && lastp)) {
				errno = E2BIG;
			}
		}
		return retval;
	} else if (from == CH_UCS2 && to != CH_UCS2) {
		const unsigned char *p = (const unsigned char *)src;
		unsigned char *q = (unsigned char *)dest;
		size_t retval = 0;
		size_t slen = srclen;
		size_t dlen = destlen;
		unsigned char lastp = '\0';

		/* If all characters are ascii, fast path here. */
		while (((slen == (size_t)-1) || (slen >= 2)) && dlen) {
			if (((lastp = *p) <= 0x7f) && (p[1] == 0)) {
				*q++ = *p;
				if (slen != (size_t)-1) {
					slen -= 2;
				}
				p += 2;
				dlen--;
				retval++;
				if (!lastp)
					break;
			} else {
				return retval + convert_string_internal(from, to, p, slen, q, dlen, allow_bad_conv);
			}
		}
		if (!dlen) {
			/* Even if we fast path we should note if we ran out of room. */
			if (((slen != (size_t)-1) && slen) ||
					((slen == (size_t)-1) && lastp)) {
				errno = E2BIG;
			}
		}
		return retval;
	} else if (from != CH_UCS2 && to == CH_UCS2) {
		const unsigned char *p = (const unsigned char *)src;
		unsigned char *q = (unsigned char *)dest;
		size_t retval = 0;
		size_t slen = srclen;
		size_t dlen = destlen;
		unsigned char lastp = '\0';

		/* If all characters are ascii, fast path here. */
		while (slen && (dlen >= 2)) {
			if ((lastp = *p) <= 0x7F) {
				*q++ = *p++;
				*q++ = '\0';
				if (slen != (size_t)-1) {
					slen--;
				}
				dlen -= 2;
				retval += 2;
				if (!lastp)
					break;
			} else {
				return retval + convert_string_internal(from, to, p, slen, q, dlen, allow_bad_conv);
			}
		}
		if (!dlen) {
			/* Even if we fast path we should note if we ran out of room. */
			if (((slen != (size_t)-1) && slen) ||
					((slen == (size_t)-1) && lastp)) {
				errno = E2BIG;
			}
		}
		return retval;
	}

	return convert_string_internal(from, to, src, srclen, dest, destlen, allow_bad_conv);
}

/*******************************************************************
 Count the number of characters in a smb_ucs2_t string.
********************************************************************/
size_t strlen_w(const smb_ucs2_t *src)
{
	size_t len;

	for(len = 0; *src++; len++) ;

	return len;
}


static size_t convert_string_internal(charset_t from, charset_t to,
		      void const *src, size_t srclen, 
		      void *dest, size_t destlen, BOOL allow_bad_conv)
{
	size_t i_len, o_len;
	size_t retval;
	const char* inbuf = (const char*)src;
	char* outbuf = (char*)dest;
	smb_iconv_t descriptor;

	lazy_initialize_conv();

	descriptor = conv_handles[from][to];

	if (srclen == (size_t)-1) {
		if (from == CH_UCS2) {
			srclen = (strlen_w((const smb_ucs2_t *)src)+1) * 2;
		} else {
			srclen = strlen((const char *)src)+1;
		}
	}


	if (descriptor == (smb_iconv_t)-1 || descriptor == (smb_iconv_t)0) {
		if (!conv_silent)
			DEBUG(0,("convert_string_internal: Conversion not supported.\n"));
		return (size_t)-1;
	}

	i_len=srclen;
	o_len=destlen;

 again:

	retval = smb_iconv(descriptor, &inbuf, &i_len, &outbuf, &o_len);
	if(retval==(size_t)-1) {
	    	const char *reason="unknown error";
		switch(errno) {
			case EINVAL:
				reason="Incomplete multibyte sequence";
				if (!conv_silent)
					DEBUG(3,("convert_string_internal: Conversion error: %s(%s)\n",reason,inbuf));
				if (allow_bad_conv)
					goto use_as_is;
				break;
			case E2BIG:
				reason="No more room"; 
				if (!conv_silent) {
					if (from == CH_UNIX) {
						DEBUG(3,("E2BIG: convert_string(%s,%s): srclen=%u destlen=%u - '%s'\n",
							charset_name(from), charset_name(to),
							(unsigned int)srclen, (unsigned int)destlen, (const char *)src));
					} else {
						DEBUG(3,("E2BIG: convert_string(%s,%s): srclen=%u destlen=%u\n",
							charset_name(from), charset_name(to),
							(unsigned int)srclen, (unsigned int)destlen));
					}
				}
				break;
			case EILSEQ:
				reason="Illegal multibyte sequence";
				conv_silent = True;
				if (!conv_silent)
					DEBUG(3,("convert_string_internal: Conversion error: %s(%s)\n",reason,inbuf));
				if (allow_bad_conv)
					goto use_as_is;
				break;
			default:
				if (!conv_silent)
					DEBUG(0,("convert_string_internal: Conversion error: %s(%s)\n",reason,inbuf));
				break;
		}
		/* smb_panic(reason); */
	}
	return destlen-o_len;

 use_as_is:

	/* 
	 * Conversion not supported. This is actually an error, but there are so
	 * many misconfigured iconv systems and smb.conf's out there we can't just
	 * fail. Do a very bad conversion instead.... JRA.
	 */

	{
		if (o_len == 0 || i_len == 0)
			return destlen - o_len;

		if (from == CH_UCS2 && to != CH_UCS2) {
			/* Can't convert from ucs2 to multibyte. Replace with the default fail char. */
			if (i_len < 2)
				return destlen - o_len;
			if (i_len >= 2) {
				*outbuf = lp_failed_convert_char();

				outbuf++;
				o_len--;

				inbuf += 2;
				i_len -= 2;
			}

			if (o_len == 0 || i_len == 0)
				return destlen - o_len;

			/* Keep trying with the next char... */
			goto again;

		} else if (from != CH_UCS2 && to == CH_UCS2) {
			/* Can't convert to ucs2 - just widen by adding the default fail char then zero. */
			if (o_len < 2)
				return destlen - o_len;

			outbuf[0] = lp_failed_convert_char();
			outbuf[1] = '\0';

			inbuf++;
			i_len--;

			outbuf += 2;
			o_len -= 2;

			if (o_len == 0 || i_len == 0)
				return destlen - o_len;

			/* Keep trying with the next char... */
			goto again;

		} else if (from != CH_UCS2 && to != CH_UCS2) {
			/* Failed multibyte to multibyte. Just copy the default fail char and
				try again. */
			outbuf[0] = lp_failed_convert_char();

			inbuf++;
			i_len--;

			outbuf++;
			o_len--;

			if (o_len == 0 || i_len == 0)
				return destlen - o_len;

			/* Keep trying with the next char... */
			goto again;

		} else {
			/* Keep compiler happy.... */
			return destlen - o_len;
		}
	}
}

//dummy function....
static char lp_failed_convert_char(void)
{
	return '_';
}



static size_t convert_string_allocate(charset_t from, charset_t to,
			       void const *src, size_t srclen, void **dest, BOOL allow_bad_conv)
{
	size_t i_len, o_len, destlen = MAX(srclen, 512);
	size_t retval;
	const char *inbuf = (const char *)src;
	char *outbuf = NULL, *ob = NULL;
	smb_iconv_t descriptor;

	*dest = NULL;

	if (src == NULL || srclen == (size_t)-1)
		return (size_t)-1;
	if (srclen == 0)
		return 0;

	lazy_initialize_conv();

	descriptor = conv_handles[from][to];

	if (descriptor == (smb_iconv_t)-1 || descriptor == (smb_iconv_t)0) {
		if (!conv_silent)
			DEBUG(0,("convert_string_allocate: Conversion not supported.\n"));
		return (size_t)-1;
	}

  convert:

	if ((destlen*2) < destlen) {
		/* wrapped ! abort. */
		if (!conv_silent)
			DEBUG(0, ("convert_string_allocate: destlen wrapped !\n"));
		SAFE_FREE(outbuf);
		return (size_t)-1;
	} else {
		destlen = destlen * 2;
	}

	
	ob = (char *)SMB_REALLOC(ob, destlen);

	if (!ob) {
		DEBUG(0, ("convert_string_allocate: realloc failed!\n"));
		SAFE_FREE(outbuf);
		return (size_t)-1;
	} else {
		outbuf = ob;
	}
	i_len = srclen;
	o_len = destlen;

 again:

	retval = smb_iconv(descriptor,
			   &inbuf, &i_len,
			   &outbuf, &o_len);
	if(retval == (size_t)-1) 		{
	    	const char *reason="unknown error";
		switch(errno) {
			case EINVAL:
				reason="Incomplete multibyte sequence";
				if (!conv_silent)
					DEBUG(3,("convert_string_allocate: Conversion error: %s(%s)\n",reason,inbuf));
				if (allow_bad_conv)
					goto use_as_is;
				break;
			case E2BIG:
				goto convert;		
			case EILSEQ:
				reason="Illegal multibyte sequence";
				if (!conv_silent)
					DEBUG(3,("convert_string_allocate: Conversion error: %s(%s)\n",reason,inbuf));
				if (allow_bad_conv)
					goto use_as_is;
				break;
		}
		if (!conv_silent)
			DEBUG(0,("Conversion error: %s(%s)\n",reason,inbuf));
		/* smb_panic(reason); */
		return (size_t)-1;
	}

  out:

	destlen = destlen - o_len;
	
	*dest = (char *)SMB_REALLOC(ob,destlen);
	if (destlen && !*dest) {
		DEBUG(0, ("convert_string_allocate: out of memory!\n"));
		
		SAFE_FREE(ob);
		return (size_t)-1;
	}

	return destlen;

 use_as_is:

	/* 
	 * Conversion not supported. This is actually an error, but there are so
	 * many misconfigured iconv systems and smb.conf's out there we can't just
	 * fail. Do a very bad conversion instead.... JRA.
	 */

	{
		if (o_len == 0 || i_len == 0)
			goto out;

		if (from == CH_UCS2 && to != CH_UCS2) {
			/* Can't convert from ucs2 to multibyte. Just use the default fail char. */
			if (i_len < 2)
				goto out;

			if (i_len >= 2) {
				*outbuf = lp_failed_convert_char();

				outbuf++;
				o_len--;

				inbuf += 2;
				i_len -= 2;
			}

			if (o_len == 0 || i_len == 0)
				goto out;

			/* Keep trying with the next char... */
			goto again;

		} else if (from != CH_UCS2 && to == CH_UCS2) {
			/* Can't convert to ucs2 - just widen by adding the default fail char then zero. */
			if (o_len < 2)
				goto out;

			outbuf[0] = lp_failed_convert_char();
			outbuf[1] = '\0';

			inbuf++;
			i_len--;

			outbuf += 2;
			o_len -= 2;

			if (o_len == 0 || i_len == 0)
				goto out;

			/* Keep trying with the next char... */
			goto again;

		} else if (from != CH_UCS2 && to != CH_UCS2) {
			/* Failed multibyte to multibyte. Just copy the default fail char and
				try again. */
			outbuf[0] = lp_failed_convert_char();

			inbuf++;
			i_len--;

			outbuf++;
			o_len--;

			if (o_len == 0 || i_len == 0)
				goto out;

			/* Keep trying with the next char... */
			goto again;

		} else {
			/* Keep compiler happy.... */
			goto out;
		}
	}
}

size_t push_ucs2_allocate(smb_ucs2_t **dest, const char *src)
{
	size_t src_len = strlen(src)+1;

	*dest = NULL;
	return convert_string_allocate(CH_UNIX, CH_UCS2, src, src_len, (void **)dest, True);
}

static smb_ucs2_t toupper_w(smb_ucs2_t val)
{
	return upcase_table[SVAL(&val,0)];
}

static smb_ucs2_t tolower_w( smb_ucs2_t val )
{
	return lowcase_table[SVAL(&val,0)];

}


/*******************************************************************
case insensitive string comparison
********************************************************************/
static int strcasecmp_w(const smb_ucs2_t *a, const smb_ucs2_t *b)
{
	while (*b && toupper_w(*a) == toupper_w(*b)) { a++; b++; }
	return (tolower_w(*a) - tolower_w(*b));
}

char *strchr_m(const char *src, char c)
{
	wpstring ws;
	pstring s2;
	smb_ucs2_t *p;
	const char *s;

	/* characters below 0x3F are guaranteed to not appear in
	   non-initial position in multi-byte charsets */
	if ((c & 0xC0) == 0) {
		return strchr(src, c);
	}

	/* this is quite a common operation, so we want it to be
	   fast. We optimise for the ascii case, knowing that all our
	   supported multi-byte character sets are ascii-compatible
	   (ie. they match for the first 128 chars) */

	for (s = src; *s && !(((unsigned char)s[0]) & 0x80); s++) {
		if (*s == c)
			return (char *)s;
	}

	if (!*s)
		return NULL;

	push_ucs2(NULL, ws, s, sizeof(ws), STR_TERMINATE);
	p = strchr_w(ws, UCS2_CHAR(c));
	if (!p)
		return NULL;
	*p = 0;
	pull_ucs2_pstring(s2, ws);
	return (char *)(s+strlen(s2));
}

static size_t pull_ucs2(const void *base_ptr, char *dest, const void *src, size_t dest_len, size_t src_len, int flags)
{
	size_t ret;

	if (dest_len == (size_t)-1)
		dest_len = sizeof(pstring);

	if (ucs2_align(base_ptr, src, flags)) {
		src = (const void *)((const char *)src + 1);
		if (src_len != (size_t)-1)
			src_len--;
	}

	if (flags & STR_TERMINATE) {
		/* src_len -1 is the default for null terminated strings. */
		if (src_len != (size_t)-1) {
			size_t len = strnlen_w(src, src_len/2);
			if (len < src_len/2)
				len++;
			src_len = len*2;
		}
	}

	/* ucs2 is always a multiple of 2 bytes */
	if (src_len != (size_t)-1)
		src_len &= ~1;
	
	ret = convert_string(CH_UCS2, CH_UNIX, src, src_len, dest, dest_len, True);
	if (ret == (size_t)-1) {
		return 0;
	}

	if (src_len == (size_t)-1)
		src_len = ret*2;
		
	if (dest_len)
		dest[MIN(ret, dest_len-1)] = 0;
	else 
		dest[0] = 0;

	return src_len;
}

static size_t pull_ucs2_pstring(char *dest, const void *src)
{
	return pull_ucs2(NULL, dest, src, sizeof(pstring), -1, STR_TERMINATE);
}

static size_t strnlen_w(const smb_ucs2_t *src, size_t max)
{
	size_t len;

	for(len = 0; *src++ && (len < max); len++) ;

	return len;
}

static smb_ucs2_t *strchr_w(const smb_ucs2_t *s, smb_ucs2_t c)
{
	while (*s != 0) {
		if (c == *s) return (smb_ucs2_t *)s;
		s++;
	}
	if (c == *s) return (smb_ucs2_t *)s;

	return NULL;
}

static size_t ucs2_align(const void *base_ptr, const void *p, int flags)
{
	if (flags & (STR_NOALIGN|STR_ASCII))
		return 0;
	return PTR_DIFF(p, base_ptr) & 1;
}

size_t push_ucs2(const void *base_ptr, void *dest, const char *src, size_t dest_len, int flags)
{
	size_t len=0;
	size_t src_len;
	size_t ret;

	/* treat a pstring as "unlimited" length */
	if (dest_len == (size_t)-1)
		dest_len = sizeof(pstring);

	if (flags & STR_TERMINATE)
		src_len = (size_t)-1;
	else
		src_len = strlen(src);

	if (ucs2_align(base_ptr, dest, flags)) {
		*(char *)dest = 0;
		dest = (void *)((char *)dest + 1);
		if (dest_len)
			dest_len--;
		len++;
	}

	/* ucs2 is always a multiple of 2 bytes */
	dest_len &= ~1;

	ret =  convert_string(CH_UNIX, CH_UCS2, src, src_len, dest, dest_len, True);
	if (ret == (size_t)-1) {
		return 0;
	}

	len += ret;

	if (flags & STR_UPPER) {
		smb_ucs2_t *dest_ucs2 = dest;
		size_t i;
		for (i = 0; i < (dest_len / 2) && dest_ucs2[i]; i++) {
			smb_ucs2_t v = toupper_w(dest_ucs2[i]);
			if (v != dest_ucs2[i]) {
				dest_ucs2[i] = v;
			}
		}
	}

	return len;
}

char *strrchr_m(const char *s, char c)
{
	/* characters below 0x3F are guaranteed to not appear in
	   non-initial position in multi-byte charsets */
	if ((c & 0xC0) == 0) {
		return strrchr(s, c);
	}

	/* this is quite a common operation, so we want it to be
	   fast. We optimise for the ascii case, knowing that all our
	   supported multi-byte character sets are ascii-compatible
	   (ie. they match for the first 128 chars). Also, in Samba
	   we only search for ascii characters in 'c' and that
	   in all mb character sets with a compound character
	   containing c, if 'c' is not a match at position
	   p, then p[-1] > 0x7f. JRA. */

	{
		size_t len = strlen(s);
		const char *cp = s;
		BOOL got_mb = False;

		if (len == 0)
			return NULL;
		cp += (len - 1);
		do {
			if (c == *cp) {
				/* Could be a match. Part of a multibyte ? */
			       	if ((cp > s) && (((unsigned char)cp[-1]) & 0x80)) {
					/* Yep - go slow :-( */
					got_mb = True;
					break;
				}
				/* No - we have a match ! */
			       	return (char *)cp;
			}
		} while (cp-- != s);
		if (!got_mb)
			return NULL;
	}

	/* String contained a non-ascii char. Slow path. */
	{
		wpstring ws;
		pstring s2;
		smb_ucs2_t *p;

		push_ucs2(NULL, ws, s, sizeof(ws), STR_TERMINATE);
		p = strrchr_w(ws, UCS2_CHAR(c));
		if (!p)
			return NULL;
		*p = 0;
		pull_ucs2_pstring(s2, ws);
		return (char *)(s+strlen(s2));
	}
}

static size_t unix_strupper(const char *src, size_t srclen, char *dest, size_t destlen)
{
	size_t size;
	smb_ucs2_t *buffer;
	
	size = push_ucs2_allocate(&buffer, src);
	if (size == (size_t)-1) {
		DEBUG(0,("failed to create UCS2 buffer"));
	}
	if (!strupper_w(buffer) && (dest == src)) {
		free(buffer);
		return srclen;
	}
	
	size = convert_string(CH_UCS2, CH_UNIX, buffer, size, dest, destlen, True);
	free(buffer);
	return size;
}

BOOL strupper_w(smb_ucs2_t *s)
{
	BOOL ret = False;
	while (*s) {
		smb_ucs2_t v = toupper_w(*s);
		if (v != *s) {
			*s = v;
			ret = True;
		}
		s++;
	}
	return ret;
}

static size_t unix_strlower(const char *src, size_t srclen, char *dest, size_t destlen)
{
	size_t size;
	smb_ucs2_t *buffer = NULL;
	
	size = convert_string_allocate(CH_UNIX, CH_UCS2, src, srclen,
				       (void **) &buffer, True);
	if (size == (size_t)-1 || !buffer) {
		DEBUG(0,("failed to create UCS2 buffer"));
	}
	if (!strlower_w(buffer) && (dest == src)) {
		SAFE_FREE(buffer);
		return srclen;
	}
	size = convert_string(CH_UCS2, CH_UNIX, buffer, size, dest, destlen, True);
	SAFE_FREE(buffer);
	return size;
}

static BOOL strlower_w(smb_ucs2_t *s)
{
	BOOL ret = False;
	while (*s) {
		smb_ucs2_t v = tolower_w(*s);
		if (v != *s) {
			*s = v;
			ret = True;
		}
		s++;
	}
	return ret;
}

static BOOL islower_w(smb_ucs2_t c)
{
	return upcase_table[SVAL(&c,0)] != c;
}

static BOOL isupper_w(smb_ucs2_t c)
{
	return lowcase_table[SVAL(&c,0)] != c;
}

static void string_replace_w(smb_ucs2_t *s, smb_ucs2_t oldc, smb_ucs2_t newc)
{
	for(;*s;s++) {
		if(*s==oldc) *s=newc;
	}
}

/***********************************************************************
 strstr_m - We convert via ucs2 for now.
***********************************************************************/

char *strstr_m(char *src, const char *findstr)
{
	smb_ucs2_t *p;
	smb_ucs2_t *src_w, *find_w;
	const char *s;
	char *s2;
	char *retp;

	size_t findstr_len = 0;

	/* for correctness */
	if (!findstr[0]) {
		return src;
	}

	/* Samba does single character findstr calls a *lot*. */
	if (findstr[1] == '\0')
		return strchr_m(src, *findstr);

	/* We optimise for the ascii case, knowing that all our
	   supported multi-byte character sets are ascii-compatible
	   (ie. they match for the first 128 chars) */

	for (s = src; *s && !(((unsigned char)s[0]) & 0x80); s++) {
		if (*s == *findstr) {
			if (!findstr_len) 
				findstr_len = strlen(findstr);

			if (strncmp(s, findstr, findstr_len) == 0) {
				return (char *)s;
			}
		}
	}

	if (!*s)
		return NULL;

#if 1 /* def BROKEN_UNICODE_COMPOSE_CHARACTERS */
	/* 'make check' fails unless we do this */

	/* With compose characters we must restart from the beginning. JRA. */
	s = src;
#endif

	if (push_ucs2_allocate(&src_w, src) == (size_t)-1) {
		DEBUG(0,("strstr_m: src malloc fail\n"));
		return NULL;
	}
	
	if (push_ucs2_allocate(&find_w, findstr) == (size_t)-1) {
		SAFE_FREE(src_w);
		DEBUG(0,("strstr_m: find malloc fail\n"));
		return NULL;
	}

	p = strstr_w(src_w, find_w);

	if (!p) {
		SAFE_FREE(src_w);
		SAFE_FREE(find_w);
		return NULL;
	}
	
	*p = 0;
	if (pull_ucs2_allocate(&s2, src_w) == (size_t)-1) {
		SAFE_FREE(src_w);
		SAFE_FREE(find_w);
		DEBUG(0,("strstr_m: dest malloc fail\n"));
		return NULL;
	}
	retp = (char *)(s+strlen(s2));
	SAFE_FREE(src_w);
	SAFE_FREE(find_w);
	SAFE_FREE(s2);
	return retp;
}

static size_t pull_ucs2_allocate(char **dest, const smb_ucs2_t *src)
{
	size_t src_len = (strlen_w(src)+1) * sizeof(smb_ucs2_t);
	*dest = NULL;
	return convert_string_allocate(CH_UCS2, CH_UNIX, src, src_len, (void **)dest, True);
}

static smb_ucs2_t *strstr_w(const smb_ucs2_t *s, const smb_ucs2_t *ins)
{
	smb_ucs2_t *r;
	size_t inslen;

	if (!s || !*s || !ins || !*ins) 
		return NULL;

	inslen = strlen_w(ins);
	r = (smb_ucs2_t *)s;

	while ((r = strchr_w(r, *ins))) {
		if (strncmp_w(r, ins, inslen) == 0) 
			return r;
		r++;
	}

	return NULL;
}

static int strncmp_w(const smb_ucs2_t *a, const smb_ucs2_t *b, size_t len)
{
	size_t n = 0;
	while ((n < len) && *b && *a == *b) { a++; b++; n++;}
	return (len - n)?(*a - *b):0;	
}

size_t push_ascii(void *dest, const char *src, size_t dest_len, int flags)
{
	size_t src_len = strlen(src);
	pstring tmpbuf;

	/* treat a pstring as "unlimited" length */
	if (dest_len == (size_t)-1)
		dest_len = sizeof(pstring);

	if (flags & STR_UPPER) {
		pstrcpy(tmpbuf, src);
		strupper_m(tmpbuf);
		src = tmpbuf;
	}

	if (flags & (STR_TERMINATE | STR_TERMINATE_ASCII))
		src_len++;

	return convert_string(CH_UNIX, CH_DOS, src, src_len, dest, dest_len, True);
}

static int ms_fnmatch(const char *pattern, const char *string, enum protocol_types protocol, 
	       BOOL is_case_sensitive)
{
	wpstring p, s;
	int ret, count, i;
	struct max_n *max_n = NULL;

	if (strcmp(string, "..") == 0) {
		string = ".";
	}

	if (strpbrk(pattern, "<>*?\"") == NULL) {
		/* this is not just an optmisation - it is essential
		   for LANMAN1 correctness */
		if (is_case_sensitive) {
			return strcmp(pattern, string);
		} else {
			return StrCaseCmp(pattern, string);
		}
	}

	if (push_ucs2(NULL, p, pattern, sizeof(p), STR_TERMINATE) == (size_t)-1) {
		/* Not quite the right answer, but finding the right one
		  under this failure case is expensive, and it's pretty close */
		return -1;
	}

	if (push_ucs2(NULL, s, string, sizeof(s), STR_TERMINATE) == (size_t)-1) {
		/* Not quite the right answer, but finding the right one
		   under this failure case is expensive, and it's pretty close */
		return -1;
	}

	if (protocol <= PROTOCOL_LANMAN2) {
		/*
		  for older negotiated protocols it is possible to
		  translate the pattern to produce a "new style"
		  pattern that exactly matches w2k behaviour
		*/
		for (i=0;p[i];i++) {
			if (p[i] == UCS2_CHAR('?')) {
				p[i] = UCS2_CHAR('>');
			} else if (p[i] == UCS2_CHAR('.') && 
				   (p[i+1] == UCS2_CHAR('?') || 
				    p[i+1] == UCS2_CHAR('*') ||
				    p[i+1] == 0)) {
				p[i] = UCS2_CHAR('"');
			} else if (p[i] == UCS2_CHAR('*') && p[i+1] == UCS2_CHAR('.')) {
				p[i] = UCS2_CHAR('<');
			}
		}
	}

	for (count=i=0;p[i];i++) {
		if (p[i] == UCS2_CHAR('*') || p[i] == UCS2_CHAR('<')) count++;
	}

	if (count != 0) {
		max_n = SMB_CALLOC_ARRAY(struct max_n, count);
		if (!max_n) {
			return -1;
		}
	}

	ret = ms_fnmatch_core(p, s, max_n, strrchr_w(s, UCS2_CHAR('.')), is_case_sensitive);

	if (max_n) {
		free(max_n);
	}

	return ret;
}

static smb_ucs2_t *strrchr_w(const smb_ucs2_t *s, smb_ucs2_t c)
{
	const smb_ucs2_t *p = s;
	int len = strlen_w(s);
	if (len == 0) return NULL;
	p += (len - 1);
	do {
		if (c == *p) return (smb_ucs2_t *)p;
	} while (p-- != s);
	return NULL;
}

static int null_match(const smb_ucs2_t *p)
{
	for (;*p;p++) {
		if (*p != UCS2_CHAR('*') &&
		    *p != UCS2_CHAR('<') &&
		    *p != UCS2_CHAR('"') &&
		    *p != UCS2_CHAR('>')) return -1;
	}
	return 0;
}

static int ms_fnmatch_core(const smb_ucs2_t *p, const smb_ucs2_t *n, 
			   struct max_n *max_n, const smb_ucs2_t *ldot,
			   BOOL is_case_sensitive)
{
	smb_ucs2_t c;
	int i;

	while ((c = *p++)) {
		switch (c) {
			/* a '*' matches zero or more characters of any type */
		case UCS2_CHAR('*'):
			if (max_n->predot && max_n->predot <= n) {
				return null_match(p);
			}
			for (i=0; n[i]; i++) {
				if (ms_fnmatch_core(p, n+i, max_n+1, ldot, is_case_sensitive) == 0) {
					return 0;
				}
			}
			if (!max_n->predot || max_n->predot > n) max_n->predot = n;
			return null_match(p);

			/* a '<' matches zero or more characters of
			   any type, but stops matching at the last
			   '.' in the string. */
		case UCS2_CHAR('<'):
			if (max_n->predot && max_n->predot <= n) {
				return null_match(p);
			}
			if (max_n->postdot && max_n->postdot <= n && n <= ldot) {
				return -1;
			}
			for (i=0; n[i]; i++) {
				if (ms_fnmatch_core(p, n+i, max_n+1, ldot, is_case_sensitive) == 0) return 0;
				if (n+i == ldot) {
					if (ms_fnmatch_core(p, n+i+1, max_n+1, ldot, is_case_sensitive) == 0) return 0;
					if (!max_n->postdot || max_n->postdot > n) max_n->postdot = n;
					return -1;
				}
			}
			if (!max_n->predot || max_n->predot > n) max_n->predot = n;
			return null_match(p);

			/* a '?' matches any single character */
		case UCS2_CHAR('?'):
			if (! *n) {
				return -1;
			}
			n++;
			break;

			/* a '?' matches any single character */
		case UCS2_CHAR('>'):
			if (n[0] == UCS2_CHAR('.')) {
				if (! n[1] && null_match(p) == 0) {
					return 0;
				}
				break;
			}
			if (! *n) return null_match(p);
			n++;
			break;

		case UCS2_CHAR('"'):
			if (*n == 0 && null_match(p) == 0) {
				return 0;
			}
			if (*n != UCS2_CHAR('.')) return -1;
			n++;
			break;

		default:
			if (c != *n) {
				if (is_case_sensitive) {
					return -1;
				}
				if (toupper_w(c) != toupper_w(*n)) {
					return -1;
				}
			}
			n++;
			break;
		}
	}
	
	if (! *n) {
		return 0;
	}
	
	return -1;
}

void *calloc_array(size_t size, size_t nmemb)
{
	if (nmemb >= MAX_ALLOC_SIZE/size) {
		return NULL;
	}

	return calloc(nmemb, size);
}

size_t align_string(const void *base_ptr, const char *p, int flags)
{
	if (!(flags & STR_ASCII) && \
	    ((flags & STR_UNICODE || \
	      (SVAL(base_ptr, smb_flg2) & FLAGS2_UNICODE_STRINGS)))) {
		return ucs2_align(base_ptr, p, flags);
	}
	return 0;
}

size_t srvstr_push_fn(const char *function, unsigned int line, 
		      const char *base_ptr, void *dest, 
		      const char *src, int dest_len, int flags)
{
	size_t buf_used = PTR_DIFF(dest, base_ptr);
	if (dest_len == -1) {
		if (((ptrdiff_t)dest < (ptrdiff_t)base_ptr) || (buf_used > (size_t)BUFFER_SIZE)) {

			return push_string_fn(function, line, base_ptr, dest, src, -1, flags);
		}
		return push_string_fn(function, line, base_ptr, dest, src, BUFFER_SIZE - buf_used, flags);
	}
	
	/* 'normal' push into size-specified buffer */
	return push_string_fn(function, line, base_ptr, dest, src, dest_len, flags);
}

static size_t push_string_fn(const char *function, unsigned int line, const void *base_ptr, void *dest, const char *src, size_t dest_len, int flags)
{
	if (!(flags & STR_ASCII) && \
	    ((flags & STR_UNICODE || \
	      (SVAL(base_ptr, smb_flg2) & FLAGS2_UNICODE_STRINGS)))) {
		return push_ucs2(base_ptr, dest, src, dest_len, flags);
	}
	return push_ascii(dest, src, dest_len, flags);
}

size_t pull_string_fn(const char *function, unsigned int line, const void *base_ptr, char *dest, const void *src, size_t dest_len, size_t src_len, int flags)
{
	if (!(flags & STR_ASCII) && \
	    ((flags & STR_UNICODE || \
	      (SVAL(base_ptr, smb_flg2) & FLAGS2_UNICODE_STRINGS)))) {
		return pull_ucs2(base_ptr, dest, src, dest_len, src_len, flags);
	}
	return pull_ascii(dest, src, dest_len, src_len, flags);
}

static size_t pull_ascii(char *dest, const void *src, size_t dest_len, size_t src_len, int flags)
{
	size_t ret;

	if (dest_len == (size_t)-1)
		dest_len = sizeof(pstring);

	if (flags & STR_TERMINATE) {
		if (src_len == (size_t)-1) {
			src_len = strlen(src) + 1;
		} else {
			size_t len = strnlen(src, src_len);
			if (len < src_len)
				len++;
			src_len = len;
		}
	}

	ret = convert_string(CH_DOS, CH_UNIX, src, src_len, dest, dest_len, True);
	if (ret == (size_t)-1) {
		dest_len = 0;
	}

	if (dest_len)
		dest[MIN(ret, dest_len-1)] = 0;
	else 
		dest[0] = 0;

	return src_len;
}

/*******************************************************************
 Setup only the byte count for a smb message, using the end of the
 message as a marker.
********************************************************************/
static int set_message_bcc(char *buf,int num_bytes)
{
	int num_words = CVAL(buf,smb_wct);
	SSVAL(buf,smb_vwv + num_words*SIZEOFWORD,num_bytes);  
	smb_setlen(buf,smb_size + num_words*2 + num_bytes - 4);
	return (smb_size + num_words*2 + num_bytes);
}

int set_message_end(void *outbuf,void *end_ptr)
{
	return set_message_bcc((char *)outbuf,PTR_DIFF(end_ptr,smb_buf((char *)outbuf)));
}

int add_signature(char *outbuf, char *p)
{
	char *start = p;
	fstring lanman;

	sprintf( lanman, "smb %s", VERSION);

	p += srvstr_push(outbuf, p, "LINUX", -1, STR_TERMINATE);
	p += srvstr_push(outbuf, p, lanman, -1, STR_TERMINATE);
	p += srvstr_push(outbuf, p, myworkgroup, -1, STR_TERMINATE);

	return PTR_DIFF(p, start);
}

size_t srvstr_get_path(char *inbuf, char *dest, const char *src, size_t dest_len, size_t src_len, int flags, NTSTATUS *err, BOOL allow_wcard_names)
{
	pstring tmppath;
	char *tmppath_ptr = tmppath;
	size_t ret;

	if (src_len == 0) {
		ret = srvstr_pull_buf( inbuf, tmppath_ptr, src, dest_len, flags);
	} else {
		ret = srvstr_pull( inbuf, tmppath_ptr, src, dest_len, src_len, flags);
	}
	*err = check_path_syntax(dest, tmppath, allow_wcard_names);
	return ret;
}

static NTSTATUS check_path_syntax(pstring destname, const pstring srcname, BOOL allow_wcard_names)
{
	char *d = destname;
	const char *s = srcname;
	NTSTATUS ret = NT_STATUS_OK;
	BOOL start_of_name_component = True;
	unsigned int num_bad_components = 0;

	while (*s) {
		if (IS_DIRECTORY_SEP(*s)) {
			/*
			 * Safe to assume is not the second part of a mb char as this is handled below.
			 */
			/* Eat multiple '/' or '\\' */
			while (IS_DIRECTORY_SEP(*s)) {
				s++;
			}
			if ((d != destname) && (*s != '\0')) {
				/* We only care about non-leading or trailing '/' or '\\' */
				*d++ = '/';
			}

			start_of_name_component = True;
			continue;
		}

		if (start_of_name_component) {
			if ((s[0] == '.') && (s[1] == '.') && (IS_DIRECTORY_SEP(s[2]) || s[2] == '\0')) {
				/* Uh oh - "/../" or "\\..\\"  or "/..\0" or "\\..\0" ! */

				/*
				 * No mb char starts with '.' so we're safe checking the directory separator here.
				 */

				/* If  we just added a '/' - delete it */
				if ((d > destname) && (*(d-1) == '/')) {
					*(d-1) = '\0';
					d--;
				}

				/* Are we at the start ? Can't go back further if so. */
				if (d <= destname) {
					ret = NT_STATUS_OBJECT_PATH_SYNTAX_BAD;
					break;
				}
				/* Go back one level... */
				/* We know this is safe as '/' cannot be part of a mb sequence. */
				/* NOTE - if this assumption is invalid we are not in good shape... */
				/* Decrement d first as d points to the *next* char to write into. */
				for (d--; d > destname; d--) {
					if (*d == '/')
						break;
				}
				s += 2; /* Else go past the .. */
				/* We're still at the start of a name component, just the previous one. */

				if (num_bad_components) {
					/* Hmmm. Should we only decrement the bad_components if
					   we're removing a bad component ? Need to check this. JRA. */
					num_bad_components--;
				}

				continue;

			} else if ((s[0] == '.') && ((s[1] == '\0') || IS_DIRECTORY_SEP(s[1]))) {
				/* Component of pathname can't be "." only. */
				ret =  NT_STATUS_OBJECT_NAME_INVALID;
				num_bad_components++;
				*d++ = *s++;
				continue;
			}
		}

		if (!(*s & 0x80)) {
			if (allow_wcard_names) {
				*d++ = *s++;
			} else {
				switch (*s) {
					case '*':
					case '?':
					case '<':
					case '>':
					case '"':
						return NT_STATUS_OBJECT_NAME_INVALID;
					default:
						*d++ = *s++;
						break;
				}
			}
		} else {
			switch(next_mb_char_size(s)) {
				case 4:
					*d++ = *s++;
				case 3:
					*d++ = *s++;
				case 2:
					*d++ = *s++;
				case 1:
					*d++ = *s++;
					break;
				default:
					DEBUG(0,("check_path_syntax: character length assumptions invalid !\n"));
					*d = '\0';
					return NT_STATUS_INVALID_PARAMETER;
			}
		}
		if (start_of_name_component && num_bad_components) {
			num_bad_components++;
		}
		start_of_name_component = False;
	}

	if (NT_STATUS_EQUAL(ret, NT_STATUS_OBJECT_NAME_INVALID)) {
		/* For some strange reason being called from findfirst changes
		   the num_components number to cause the error return to change. JRA. */
		if (allow_wcard_names) {
			if (num_bad_components > 2) {
				ret = NT_STATUS_OBJECT_PATH_NOT_FOUND;
			}
		} else {
			if (num_bad_components > 1) {
				ret = NT_STATUS_OBJECT_PATH_NOT_FOUND;
			}
		}
	}

	*d = '\0';
	return ret;
}

static size_t next_mb_char_size(const char *s)
{
	size_t i;

	if (!(*s & 0x80))
		return 1; /* ascii. */

	conv_silent = True;
	for ( i = 1; i <=4; i++ ) {
		smb_ucs2_t uc;
		if (convert_string(CH_UNIX, CH_UCS2, s, i, &uc, 2, False) == 2) {
			conv_silent = False;
			return i;
		}
	}
	/* We're hosed - we don't know how big this is... */
	DEBUG(10,("next_mb_char_size: unknown size at string %s\n", s));
	conv_silent = False;
	return 1;
}

size_t push_ascii_fstring(void *dest, const char *src)
{
	return push_ascii(dest, src, sizeof(fstring), STR_TERMINATE);
}

size_t dos_PutUniCode(char *dst,const char *src, ssize_t len, BOOL null_terminate)
{
	return push_ucs2(NULL, dst, src, len, 
			 STR_UNICODE|STR_NOALIGN | (null_terminate?STR_TERMINATE:0));
}

char *alpha_strcpy_fn(const char *fn, int line, char *dest, const char *src, const char *other_safe_chars, size_t maxlength)
{
	size_t len, i;

	if (!dest) {
		DEBUG(0,("ERROR: NULL dest in alpha_strcpy, called from [%s][%d]\n", fn, line));
		return NULL;
	}

	if (!src) {
		*dest = 0;
		return dest;
	}  

	len = strlen(src);
	if (len >= maxlength)
		len = maxlength - 1;

	if (!other_safe_chars)
		other_safe_chars = "";

	for(i = 0; i < len; i++) {
		int val = (src[i] & 0xff);
		if (isupper(val) || islower(val) || isdigit(val) || strchr_m(other_safe_chars, val))
			dest[i] = src[i];
		else
			dest[i] = '_';
	}

	dest[i] = '\0';

	return dest;
}

BOOL trim_char(char *s,char cfront,char cback)
{
	BOOL ret = False;
	char *ep;
	char *fp = s;

	/* Ignore null or empty strings. */
	if (!s || (s[0] == '\0'))
		return False;

	if (cfront) {
		while (*fp && *fp == cfront)
			fp++;
		if (!*fp) {
			/* We ate the string. */
			s[0] = '\0';
			return True;
		}
		if (fp != s)
			ret = True;
	}

	ep = fp + strlen(fp) - 1;
	if (cback) {
		/* Attempt ascii only. Bail for mb strings. */
		while ((ep >= fp) && (*ep == cback)) {
			ret = True;
			if ((ep > fp) && (((unsigned char)ep[-1]) & 0x80)) {
				/* Could be mb... bail back to tim_string. */
				char fs[2], bs[2];
				if (cfront) {
					fs[0] = cfront;
					fs[1] = '\0';
				}
				bs[0] = cback;
				bs[1] = '\0';
				return trim_string(s, cfront ? fs : NULL, bs);
			} else {
				ep--;
			}
		}
		if (ep < fp) {
			/* We ate the string. */
			s[0] = '\0';
			return True;
		}
	}

	ep[1] = '\0';
	memmove(s, fp, ep-fp+2);
	return ret;
}

/*******************************************************************
  case insensitive string compararison
********************************************************************/
int StrCaseCmp(const char *s, const char *t)
{

	const char * ps, * pt;
	size_t size;
	smb_ucs2_t *buffer_s, *buffer_t;
	int ret;

	for (ps = s, pt = t; ; ps++, pt++) {
		char us, ut;

		if (!*ps && !*pt)
			return 0; /* both ended */
 		else if (!*ps)
			return -1; /* s is a prefix */
		else if (!*pt)
			return +1; /* t is a prefix */
		else if ((*ps & 0x80) || (*pt & 0x80))
			/* not ascii anymore, do it the hard way from here on in */
			break;

		us = toupper(*ps);
		ut = toupper(*pt);
		if (us == ut)
			continue;
		else if (us < ut)
			return -1;
		else if (us > ut)
			return +1;
	}

	size = push_ucs2_allocate(&buffer_s, s);
	if (size == (size_t)-1) {
		return strcmp(s, t); 
		/* Not quite the right answer, but finding the right one
		   under this failure case is expensive, and it's pretty close */
	}
	
	size = push_ucs2_allocate(&buffer_t, t);
	if (size == (size_t)-1) {
		SAFE_FREE(buffer_s);
		return strcmp(s, t); 
		/* Not quite the right answer, but finding the right one
		   under this failure case is expensive, and it's pretty close */
	}
	
	ret = strcasecmp_w(buffer_s, buffer_t);
	SAFE_FREE(buffer_s);
	SAFE_FREE(buffer_t);
	return ret;
}

/****************************************************************************
  string replace
****************************************************************************/
void string_replace(char *s,char oldc,char newc)
{

	unsigned char *p;

	/* this is quite a common operation, so we want it to be
	   fast. We optimise for the ascii case, knowing that all our
	   supported multi-byte character sets are ascii-compatible
	   (ie. they match for the first 128 chars) */

	for (p = (unsigned char *)s; *p; p++) {
		if (*p & 0x80) /* mb string - slow path. */
			break;
		if (*p == oldc)
			*p = newc;
	}

	if (!*p)
		return;

	push_ucs2(NULL, tmpbuf, p, sizeof(tmpbuf), STR_TERMINATE);
	string_replace_w(tmpbuf, UCS2_CHAR(oldc), UCS2_CHAR(newc));
	pull_ucs2(NULL, p, tmpbuf, -1, sizeof(tmpbuf), STR_TERMINATE);
}

/*******************************************************************
  case insensitive string compararison, length limited
********************************************************************/
int StrnCaseCmp(const char *s, const char *t, int n)
{
	pstring buf1, buf2;
	unix_strupper(s, strlen(s)+1, buf1, sizeof(buf1));
	unix_strupper(t, strlen(t)+1, buf2, sizeof(buf2));
	return strncmp(buf1,buf2,n);
}

void strlower_m(char *s)
{
	size_t len;
	int errno_save;

	/* this is quite a common operation, so we want it to be
	   fast. We optimise for the ascii case, knowing that all our
	   supported multi-byte character sets are ascii-compatible
	   (ie. they match for the first 128 chars) */

	while (*s && !(((unsigned char)s[0]) & 0x80)) {
		*s = tolower((unsigned char)*s);
		s++;
	}

	if (!*s)
		return;

	/* I assume that lowercased string takes the same number of bytes
	 * as source string even in UTF-8 encoding. (VIV) */
	len = strlen(s) + 1;
	errno_save = errno;
	errno = 0;
	unix_strlower(s,len,s,len);	
	/* Catch mb conversion errors that may not terminate. */
	if (errno)
		s[len-1] = '\0';
	errno = errno_save;
}

/****************************************************************************
does a string have any uppercase chars in it?
****************************************************************************/
BOOL strhasupper(char *s)
{
	smb_ucs2_t *ptr;
	push_ucs2(NULL, tmpbuf,s, sizeof(tmpbuf), STR_TERMINATE);
	for(ptr=tmpbuf;*ptr;ptr++)
		if(isupper_w(*ptr))
			return True;
	return(False);
}

/****************************************************************************
does a string have any lowercase chars in it?
****************************************************************************/
BOOL strhaslower(char *s)
{
  	smb_ucs2_t *ptr;
  	push_ucs2(NULL, tmpbuf, s, sizeof(tmpbuf), STR_TERMINATE);
  	for(ptr=tmpbuf;*ptr;ptr++)
		if(islower_w(*ptr))
			return True;
	return(False);
}


/*******************************************************************
  compare 2 strings 
********************************************************************/
BOOL strequal(const char *s1, const char *s2)
{
  if (s1 == s2) return(True);
  if (!s1 || !s2) return(False);
  
  return(StrCaseCmp(s1,s2)==0);
}

/*******************************************************************
  compare 2 strings up to and including the nth char.
  ******************************************************************/
BOOL strnequal(const char *s1, const char *s2, int n)
{
  if (s1 == s2) return(True);
  if (!s1 || !s2 || !n) return(False);
  
  return(StrnCaseCmp(s1,s2,n)==0);
}

/*******************************************************************
  compare 2 strings (case sensitive)
********************************************************************/
BOOL strcsequal(const char *s1, const char *s2)
{
  if (s1 == s2) return(True);
  if (!s1 || !s2) return(False);
  
  return(strcmp(s1,s2)==0);
}


/*******************************************************************
  convert a string to upper case
********************************************************************/
void strupper_m(char *s)
{
	size_t len;
	int errno_save;

	/* this is quite a common operation, so we want it to be
	   fast. We optimise for the ascii case, knowing that all our
	   supported multi-byte character sets are ascii-compatible
	   (ie. they match for the first 128 chars) */

	while (*s && !(((unsigned char)s[0]) & 0x80)) {
		*s = toupper((unsigned char)*s);
		s++;
	}

	if (!*s)
		return;

	/* I assume that lowercased string takes the same number of bytes
	 * as source string even in multibyte encoding. (VIV) */
	len = strlen(s) + 1;
	errno_save = errno;
	errno = 0;
	unix_strupper(s,len,s,len);	
	/* Catch mb conversion errors that may not terminate. */
	if (errno)
		s[len-1] = '\0';
	errno = errno_save;
}

/*******************************************************************
  convert a string to "normal" form
********************************************************************/
void strnorm(char *s)
{

  if (case_default == CASE_UPPER)
    strupper_m(s);
  else
    strlower_m(s);
 
}

/****************************************************************************
  make a file into unix format
****************************************************************************/
void unix_format(char *fname)
{
  pstring namecopy;
  string_replace(fname,'\\','/');

  if (*fname == '/')
    {
      pstrcpy(namecopy,fname);
      strcpy(fname,".");
      strcat(fname,namecopy);
    }  
}

/****************************************************************************
this is a safer strcpy(), meant to prevent core dumps when nasty things happen
****************************************************************************/
char *StrCpy(char *dest,const char *src)
{
  char *d = dest;

#if AJT
  /* I don't want to get lazy with these ... */
  if (!dest || !src) {
    DEBUG(0,("ERROR: NULL StrCpy() called!\n"));
    ajt_panic();
  }
#endif

  if (!dest) return(NULL);
  if (!src) {
    *dest = 0;
    return(dest);
  }
  while ((*d++ = *src++)) ;
  return(dest);
}

/****************************************************************************
line strncpy but always null terminates. Make sure there is room!
****************************************************************************/
char *StrnCpy(char *dest,const char *src,int n)
{
  char *d = dest;
  if (!dest) return(NULL);
  if (!src) {
    *dest = 0;
    return(dest);
  }
  while (n-- && (*d++ = *src++)) ;
  *d = 0;
  return(dest);
}

/*******************************************************************
skip past some strings in a buffer
********************************************************************/
char *skip_string(char *buf,int n)
{
  while (n--)
    buf += strlen(buf) + 1;
  return(buf);
}

/*******************************************************************
trim the specified elements off the front and back of a string
********************************************************************/
BOOL trim_string(char *s,char *front,char *back)
{
	BOOL ret = False;
	size_t front_len;
	size_t back_len;
	size_t len;

	/* Ignore null or empty strings. */
	if (!s || (s[0] == '\0'))
		return False;

	front_len	= front? strlen(front) : 0;
	back_len	= back? strlen(back) : 0;

	len = strlen(s);

	if (front_len) {
		while (len && strncmp(s, front, front_len)==0) {
			/* Must use memmove here as src & dest can
			 * easily overlap. Found by valgrind. JRA. */
			memmove(s, s+front_len, (len-front_len)+1);
			len -= front_len;
			ret=True;
		}
	}
	
	if (back_len) {
		while ((len >= back_len) && strncmp(s+len-back_len,back,back_len)==0) {
			s[len-back_len]='\0';
			len -= back_len;
			ret=True;
		}
	}
	return ret;
}

char *safe_strcat_fn(char *dest, const char *src, size_t maxlength)
{
	size_t src_len, dest_len;

	if (!dest) {
//		DEBUG(0,("ERROR: NULL dest in safe_strcat, called from [%s][%d]\n", fn, line));
		return NULL;
	}

	if (!src)
		return dest;
	
	src_len = strnlen(src, maxlength + 1);
	dest_len = strnlen(dest, maxlength + 1);

	if (src_len + dest_len > maxlength) {
		DEBUG(0,("ERROR: string overflow by %d in safe_strcat [%.50s]\n",
			 (int)(src_len + dest_len - maxlength), src));
		if (maxlength > dest_len) {
			memcpy(&dest[dest_len], src, maxlength - dest_len);
		}
		dest[maxlength] = 0;
		return NULL;
	}

	memcpy(&dest[dest_len], src, src_len);
	dest[dest_len + src_len] = 0;
	return dest;
}

/****************************************************************************
set a string value, allocing the space for the string
****************************************************************************/
BOOL string_init(char **dest,const char *src)
{
  int l;
  if (!src)     
    src = "";

  l = strlen(src);

  if (l == 0)
    {
      if (!null_string)
	null_string = (char *)malloc(1);

      *null_string = 0;
      *dest = null_string;
    }
  else
    {
      (*dest) = (char *)malloc(l+1);
      if ((*dest) == NULL) {
	      DEBUG(0,("Out of memory in string_init\n"));
	      return False;
      }

      strcpy(*dest,src);
    }
  return(True);
}

/****************************************************************************
free a string value
****************************************************************************/
void string_free(char **s)
{
  if (!s || !(*s)) 
  	return;
  
  if (*s == null_string)
    	*s = NULL;
  
  SAFE_FREE(*s);
}

/****************************************************************************
set a string value, allocing the space for the string, and deallocating any 
existing space
****************************************************************************/
BOOL string_set(char **dest,const char *src)
{
  string_free(dest);

  return(string_init(dest,src));
}

/****************************************************************************
substitute a string for a pattern in another string. Make sure there is 
enough room!

This routine looks for pattern in s and replaces it with 
insert. It may do multiple replacements.

return True if a substitution was done.
****************************************************************************/
BOOL string_sub(char *s, const char *pattern, char *insert)
{
  BOOL ret = False;
  char *p;
  int ls,lp,li;

  if (!insert || !pattern || !s) return(False);

  ls = strlen(s);
  lp = strlen(pattern);
  li = strlen(insert);

  if (!*pattern) return(False);

  while (lp <= ls && (p = strstr_m(s,pattern)))
    {
      ret = True;
      memmove(p+li,p+lp,ls + 1 - (PTR_DIFF(p,s) + lp));
      memcpy(p,insert,li);
      s = p + li;
      ls = strlen(s);
    }
  return(ret);
}

/*********************************************************
* Routine to match a given string with a regexp - uses
* simplified regexp that takes * and ? only. Case can be
* significant or not.
*********************************************************/
BOOL mask_match(const char *string, const char *pattern, int case_sig, BOOL trans2/*useless parameter..*/)
{
	if (strcmp(string,"..") == 0)
		string = ".";
	if (strcmp(pattern,".") == 0)
		return False;

	return ms_fnmatch(pattern, string, Protocol, case_sig) == 0;
}



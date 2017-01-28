/* 
   Unix SMB/Netbios implementation.
   Version based 3.0.
   Name mangling
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
extern int case_default;
extern BOOL case_mangle;

static char basechars[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ_-!@#$%";
static unsigned char base_reverse[256];

/* this is the magic char used for mangling */
static char mmagic_char = '~';

/* the list of reserved dos names - all of these are illegal */
static const char *reserved_names[] = 
{ "AUX", "LOCK$", "CON", "COM1", "COM2", "COM3", "COM4",
  "LPT1", "LPT2", "LPT3", "NUL", "PRN", NULL };

/* these tables are used to provide fast tests for characters */
static unsigned char char_flags[256];

#define MANGLE_BASE       (sizeof(basechars)/sizeof(char)-1)
#define mangle(V) ((char)(basechars[(V) % MANGLE_BASE]))
#define base_forward(v) basechars[v]

#define mangle_prefix 1
#define u32 unsigned

#define FNV1_PRIME 0x01000193
#define FNV1_INIT  0xa6b93095

/* the "possible" flags are used as a fast way to find possible DOS
   reserved filenames */
#define FLAG_POSSIBLE1 16
#define FLAG_POSSIBLE2 32
#define FLAG_POSSIBLE3 64
#define FLAG_POSSIBLE4 128

#define FLAG_CHECK(c, flag) (char_flags[(unsigned char)(c)] & (flag))

/* these flags are used to mark characters in as having particular
   properties */
#define FLAG_BASECHAR 1
#define FLAG_ASCII 2
#define FLAG_ILLEGAL 4
#define FLAG_WILDCARD 8

static char *string_truncate(char *s, unsigned int length)
{
	if (s && strlen(s) > length)
		s[length] = 0;
	return s;
}

/*******************************************************************
check if a string is in "normal" case
********************************************************************/
static BOOL strisnormal(char *s)
{
  if (case_default == CASE_UPPER)
    return(!strhaslower(s));

  return(!strhasupper(s));
}

BOOL is_8_3(const char *name, BOOL check_case /*BOOL allow_wildcards*/)
{
	int len, i;
	char *dot_p;

	/* as a special case, the names '.' and '..' are allowable 8.3 names */
	if (name[0] == '.') {
		if (!name[1] || (name[1] == '.' && !name[2])) {
			return True;
		}
	}

	/* the simplest test is on the overall length of the
	 filename. Note that we deliberately use the ascii string
	 length (not the multi-byte one) as it is faster, and gives us
	 the result we need in this case. Using strlen_m would not
	 only be slower, it would be incorrect */
	len = strlen(name);
	if (len > 12)
		return False;

	/* find the '.'. Note that once again we use the non-multibyte
           function */
	dot_p = strchr(name, '.');

	if (!dot_p) {
		/* if the name doesn't contain a '.' then its length
                   must be less than 8 */
		if (len > 8) {
			return False;
		}
	} else {
		int prefix_len, suffix_len;

		/* if it does contain a dot then the prefix must be <=
		   8 and the suffix <= 3 in length */
		prefix_len = PTR_DIFF(dot_p, name);
		suffix_len = len - (prefix_len+1);

		if (prefix_len > 8 || suffix_len > 3 || suffix_len == 0) {
			return False;
		}

		/* a 8.3 name cannot contain more than 1 '.' */
		if (strchr(dot_p+1, '.')) {
			return False;
		}
	}

	/* the length are all OK. Now check to see if the characters themselves are OK */
	for (i=0; name[i]; i++) {
		/* note that we may allow wildcard petterns! */
		if (!FLAG_CHECK(name[i], FLAG_ASCII|(False ? FLAG_WILDCARD : 0)) && name[i] != '.') {
			return False;
		}
	}

	/* it is a good 8.3 name */
	return True;
}

/* -------------------------------------------------------------------------- **
 * This section creates and maintains a stack of name mangling results.
 * The original comments read: "keep a stack of name mangling results - just
 * so file moves and copies have a chance of working" (whatever that means).
 *
 * There are three functions to manage the stack:
 *   reset_mangled_stack() -
 *   push_mangled_name()    -
 *   check_mangled_stack()  -
 */

fstring *mangled_stack = NULL;
int mangled_stack_size = 0;
int mangled_stack_len = 0;

static void init_tables(void)
{
	int i;

	memset(char_flags, 0, sizeof(char_flags));

	for (i=1;i<128;i++) {
		if ((i >= '0' && i <= '9') || 
		    (i >= 'a' && i <= 'z') || 
		    (i >= 'A' && i <= 'Z')) {
			char_flags[i] |=  (FLAG_ASCII | FLAG_BASECHAR);
		}
		if (strchr("_-$~", i)) {
			char_flags[i] |= FLAG_ASCII;
		}

		if (strchr("*\\/?<>|\":", i)) {
			char_flags[i] |= FLAG_ILLEGAL;
		}

		if (strchr("*?\"<>", i)) {
			char_flags[i] |= FLAG_WILDCARD;
		}
	}

	memset(base_reverse, 0, sizeof(base_reverse));
	for (i=0;i<36;i++) {
		base_reverse[(unsigned char)base_forward(i)] = i;
	}	

	/* fill in the reserved names flags. These are used as a very
	   fast filter for finding possible DOS reserved filenames */
	for (i=0; reserved_names[i]; i++) {
		unsigned char c1, c2, c3, c4;

		c1 = (unsigned char)reserved_names[i][0];
		c2 = (unsigned char)reserved_names[i][1];
		c3 = (unsigned char)reserved_names[i][2];
		c4 = (unsigned char)reserved_names[i][3];

		char_flags[c1] |= FLAG_POSSIBLE1;
		char_flags[c2] |= FLAG_POSSIBLE2;
		char_flags[c3] |= FLAG_POSSIBLE3;
		char_flags[c4] |= FLAG_POSSIBLE4;
		char_flags[tolower(c1)] |= FLAG_POSSIBLE1;
		char_flags[tolower(c2)] |= FLAG_POSSIBLE2;
		char_flags[tolower(c3)] |= FLAG_POSSIBLE3;
		char_flags[tolower(c4)] |= FLAG_POSSIBLE4;

		char_flags[(unsigned char)'.'] |= FLAG_POSSIBLE4;
	}
}

/****************************************************************************
do the actual mangling to 8.3 format
****************************************************************************/
static void mangle_name_83(char *s)
{
  int csum = str_checksum(s);
  char *p;
  char extension[4];
  char base[9];
  int baselen = 0;
  int extlen = 0;

  extension[0]=0;
  base[0]=0;

  p = strrchr(s,'.');  
  if( p && (strlen(p+1) < (size_t)4) )
    {
    BOOL all_normal = (strisnormal(p+1)); /* XXXXXXXXX */

    if (all_normal && p[1] != 0)
      {
      *p = 0;
      csum = str_checksum(s);
        *p = '.';
      }
    }

  strupper_m(s);

  DEBUG(5,("Mangling name %s to ",s));

  	if( p ) {
		if( p == s )
			StrnCpy( extension, "___", 3 );
		else {
			*p++ = 0;
			while( *p && extlen < 3 ) {
				if ( *p != '.') {
					extension[extlen++] = p[0];
				}
				p++;
			}
			extension[extlen] = 0;
		}
	}
  
	p = s;

	while( *p && baselen < 5 ) {
		if (*p != '.') {
			base[baselen++] = p[0];
		}
		p++;
	}
	base[baselen] = 0;
  
	csum = csum % (MANGLE_BASE*MANGLE_BASE);
  
	(void)snprintf(s, 12, "%s%c%c%c",
		base, mmagic_char, mangle( csum/MANGLE_BASE ), mangle( csum ) );
  
	if( *extension ) {
		(void)pstrcat( s, "." );
		(void)pstrcat( s, extension );
	}
} /* mangle_name_83 */

/****************************************************************************
 * create the mangled stack CRH
 ****************************************************************************/
void reset_mangled_stack( int size )
{
  init_tables();
  
  if( mangled_stack )
    {
    free(mangled_stack);
    mangled_stack_size = 0;
    mangled_stack_len = 0;
    }

  if( size > 0 )
    {
    mangled_stack = (fstring *)malloc( sizeof(fstring) * size );
    if( mangled_stack )
      mangled_stack_size = size;
    }
  else
    mangled_stack = NULL;
} /* create_mangled_stack */

/****************************************************************************
 * check for a name on the mangled name stack CRH
 ****************************************************************************/
BOOL check_mangled_stack(char *s)
  {
  int i;
  pstring tmpname;
  char extension[5];
  char *p              = strrchr( s, '.' );
  BOOL check_extension = False;

  extension[0] = 0;

  /* If the stack doesn't exist, fail. */
  if( !mangled_stack )
    return(False);

  /* If there is a file extension, then we need to play with it, too. */
  if( p )
    {
    check_extension = True;
    StrnCpy( extension, p, 4 );
    strlower_m( extension ); /* XXXXXXX */
    }

  for( i=0; i<mangled_stack_len; i++ )
    {
    strcpy(tmpname,mangled_stack[i]);
    mangle_name_83(tmpname);
    if( strequal(tmpname,s) )
      {
      strcpy(s,mangled_stack[i]);
      break;
      }
    if( check_extension && !strchr(mangled_stack[i],'.') )
      {
      pstrcpy(tmpname,mangled_stack[i]);
      strcat(tmpname,extension);
      mangle_name_83(tmpname);
      if( strequal(tmpname,s) )
        {
        strcpy(s,mangled_stack[i]);
        strcat(s,extension);
        break;
        }          
      }
    }

  if( i < mangled_stack_len )
    {
    DEBUG(3,("Found %s on mangled stack as %s\n",s,mangled_stack[i]));
    array_promote(mangled_stack[0],sizeof(fstring),i);
    return(True);      
    }

  return(False);
  } /* check_mangled_stack */


/* End of the mangled stack section.
 * -------------------------------------------------------------------------- **
 */


static char *map_filename( char *s,         /* This is null terminated */
                           char *pattern,   /* This isn't. */
                           int len )        /* This is the length of pattern. */
  {
  static pstring matching_bit;  /* The bit of the string which matches */
                                /* a * in pattern if indeed there is a * */
  char *sp;                     /* Pointer into s. */
  char *pp;                     /* Pointer into p. */
  char *match_start;            /* Where the matching bit starts. */
  pstring pat;

  StrnCpy(pat, pattern, len);   /* Get pattern into a proper string! */
  pstrcpy(matching_bit,"");     /* Match but no star gets this. */
  pp = pat;                     /* Initialise the pointers. */
  sp = s;
  if( (len == 1) && (*pattern == '*') )
    {
    return NULL;                /* Impossible, too ambiguous for */
    }                           /* words! */

  while ((*sp)                  /* Not the end of the string. */
         && (*pp)               /* Not the end of the pattern. */
         && (*sp == *pp)        /* The two match. */
         && (*pp != '*'))       /* No wildcard. */
    {
    sp++;                       /* Keep looking. */
    pp++;
    }

  if( !*sp && !*pp )            /* End of pattern. */
    return( matching_bit );     /* Simple match.  Return empty string. */

  if (*pp == '*')
    {
    pp++;                       /* Always interrested in the chacter */
                                /* after the '*' */
    if (!*pp)                   /* It is at the end of the pattern. */
      {
      StrnCpy(matching_bit, s, sp-s);
      return matching_bit;
      }
    else
      {
      /* The next character in pattern must match a character further */
      /* along s than sp so look for that character. */
      match_start = sp;
      while( (*sp)              /* Not the end of s. */
             && (*sp != *pp))   /* Not the same  */
        sp++;                   /* Keep looking. */
      if (!*sp)                 /* Got to the end without a match. */
        {
        return NULL;
        }                       /* Still hope for a match. */
      else
        {
        /* Now sp should point to a matching character. */
        StrnCpy(matching_bit, match_start, sp-match_start);
        /* Back to needing a stright match again. */
        while( (*sp)            /* Not the end of the string. */
               && (*pp)         /* Not the end of the pattern. */
               && (*sp == *pp) ) /* The two match. */
          {
          sp++;                 /* Keep looking. */
          pp++;
          }
        if (!*sp && !*pp)       /* Both at end so it matched */
          return matching_bit;
        else
          return NULL;
        }
      }
    }
  return NULL;                  /* No match. */
  } /* map_filename */

/* 
   determine if a string is possibly in a mangled format, ignoring
   case 

   In this algorithm, mangled names use only pure ascii characters (no
   multi-byte) so we can avoid doing a UCS2 conversion 
 */
static BOOL is_mangled_component(const char *name, size_t len)
{
	unsigned int i;

	DEBUG(10,("is_mangled_component %s (len %u) ?\n", name, (unsigned int)len));

	/* check the length */
	if (len > 12 || len < 8)
		return False;

	/* the best distinguishing characteristic is the ~ */
	if (name[6] != mmagic_char)
		return False;

	/* check extension */
	if (len > 8) {
		if (name[8] != '.')
			return False;
		for (i=9; name[i] && i < len; i++) {
			if (! FLAG_CHECK(name[i], FLAG_ASCII)) {
				return False;
			}
		}
	}
	
	/* check lead characters */
	for (i=0;i<mangle_prefix;i++) {
		if (! FLAG_CHECK(name[i], FLAG_ASCII)) {
			return False;
		}
	}
	
	/* check rest of hash */
	if (! FLAG_CHECK(name[7], FLAG_BASECHAR)) {
		return False;
	}
	for (i=mangle_prefix;i<6;i++) {
		if (! FLAG_CHECK(name[i], FLAG_BASECHAR)) {
			return False;
		}
	}

	DEBUG(10,("is_mangled_component %s (len %u) -> yes\n", name, (unsigned int)len));

	return True;
}


/* 
   determine if a string is possibly in a mangled format, ignoring
   case 

   In this algorithm, mangled names use only pure ascii characters (no
   multi-byte) so we can avoid doing a UCS2 conversion 

   NOTE! This interface must be able to handle a path with unix
   directory separators. It should return true if any component is
   mangled
 */
BOOL is_mangled(const char *name)
{
	const char *p;
	const char *s;

	DEBUG(0,("is_mangled %s ?\n", name));

	for (s=name; (p=strchr(s, '/')); s=p+1) {
		if (is_mangled_component(s, PTR_DIFF(p, s))) {
			return True;
		}
	}
	
	/* and the last part ... */
	return is_mangled_component(s,strlen(s));
}

static void do_fwd_mangled_map(char *s, char *MangledMap)
  {
  /* MangledMap is a series of name pairs in () separated by spaces.
   * If s matches the first of the pair then the name given is the
   * second of the pair.  A * means any number of any character and if
   * present in the second of the pair as well as the first the
   * matching part of the first string takes the place of the * in the
   * second.
   *
   * I wanted this so that we could have RCS files which can be used
   * by UNIX and DOS programs.  My mapping string is (RCS rcs) which
   * converts the UNIX RCS file subdirectory to lowercase thus
   * preventing mangling.
   */
  char *start=MangledMap;       /* Use this to search for mappings. */
  char *end;                    /* Used to find the end of strings. */
  char *match_string;
  pstring new_string;           /* Make up the result here. */
  char *np;                     /* Points into new_string. */

  DEBUG(5,("Mangled Mapping '%s' map '%s'\n", s, MangledMap));
  while (*start)
    {
    while ((*start) && (*start != '('))
      start++;
    if (!*start)
      continue;                 /* Always check for the end. */
    start++;                    /* Skip the ( */
    end = start;                /* Search for the ' ' or a ')' */
    DEBUG(5,("Start of first in pair '%s'\n", start));
    while ((*end) && !((*end == ' ') || (*end == ')')))
      end++;
    if (!*end)
      {
      start = end;
      continue;                 /* Always check for the end. */
      }
    DEBUG(5,("End of first in pair '%s'\n", end));
    if ((match_string = map_filename(s, start, end-start)))
      {
      DEBUG(5,("Found a match\n"));
      /* Found a match. */
      start = end+1;            /* Point to start of what it is to become. */
      DEBUG(5,("Start of second in pair '%s'\n", start));
      end = start;
      np = new_string;
      while ((*end)             /* Not the end of string. */
             && (*end != ')')   /* Not the end of the pattern. */
             && (*end != '*'))  /* Not a wildcard. */
        *np++ = *end++;
      if (!*end)
        {
        start = end;
        continue;               /* Always check for the end. */
        }
      if (*end == '*')
        {
        pstrcpy(np, match_string);
        np += strlen(match_string);
        end++;                  /* Skip the '*' */
        while ((*end)             /* Not the end of string. */
               && (*end != ')')   /* Not the end of the pattern. */
               && (*end != '*'))  /* Not a wildcard. */
          *np++ = *end++;
        }
      if (!*end)
        {
        start = end;
        continue;               /* Always check for the end. */
        }
      *np++ = '\0';             /* NULL terminate it. */
      DEBUG(5,("End of second in pair '%s'\n", end));
      pstrcpy(s, new_string);    /* Substitute with the new name. */
      DEBUG(5,("s is now '%s'\n", s));
      }
    start = end;              /* Skip a bit which cannot be wanted */
    /* anymore. */
    start++;
    }
  } /* do_fwd_mangled_map */

/*
  front end routine to the mangled map code 
  personally I think that the whole idea of "mangled map" is completely bogus
*/
static void mangle_map_filename(fstring fname, int snum)
{
	char *map;

	map = lp_mangled_map(snum);
	if (!map || !*map) return;

	do_fwd_mangled_map(fname, map);
}

/*******************************************************************
  work out if a name is illegal, even for long names
  ******************************************************************/
static BOOL illegal_name(char *name)
  {
	const char *dot_pos = NULL;
	BOOL alldots = True;
	size_t numdots = 0;

	while (*name) {
		if (((unsigned int)name[0]) > 128 && (name[1] != 0)) {
			/* Possible start of mb character. */
			char mbc[2];
			/*
			 * Note that if CH_UNIX is utf8 a string may be 3
			 * bytes, but this is ok as mb utf8 characters don't
			 * contain embedded ascii bytes. We are really checking
			 * for mb UNIX asian characters like Japanese (SJIS) here.
			 * JRA.
			 */
			if (convert_string(CH_UNIX, CH_UCS2, name, 2, mbc, 2, False) == 2) {
				/* Was a good mb string. */
				name += 2;
				continue;
			}
		}

		if (FLAG_CHECK(name[0], FLAG_ILLEGAL)) {
			return False;
		}
		if (name[0] == '.') {
			dot_pos = name;
			numdots++;
		} else {
			alldots = False;
		}
		name++;
	}

	if (dot_pos) {
		if (alldots && (numdots == 1 || numdots == 2))
			return True; /* . or .. is a valid name */

		/* A valid long name cannot end in '.' */
		if (dot_pos[1] == '\0')
			return False;
	}

	return True;
	
#if 0  
  static unsigned char illegal[256];
  static BOOL initialised=False;
  unsigned char *s;

  if( !initialised )
    {
    char *ill = "*\\/?<>|\":";
    initialised = True;
  
    bzero((char *)illegal,256);
    for( s = (unsigned char *)ill; *s; s++ )
      illegal[*s] = True;
    }

  if(lp_client_code_page() == KANJI_CODEPAGE)
    {
    for (s = (unsigned char *)name; *s;)
      {
      if (is_shift_jis (*s))
        s += 2;
      else
        {
        if (illegal[*s])
          return(True);
        else
          s++;
        }
      }
    }
  else
    {
    for (s = (unsigned char *)name;*s;s++)
      if (illegal[*s]) return(True);
    }

  return(False);
  #endif
  } /* illegal_name */

/*
  look for a DOS reserved name
*/
static BOOL is_reserved_name(const char *name)
{
	if (FLAG_CHECK(name[0], FLAG_POSSIBLE1) &&
	    FLAG_CHECK(name[1], FLAG_POSSIBLE2) &&
	    FLAG_CHECK(name[2], FLAG_POSSIBLE3) &&
	    FLAG_CHECK(name[3], FLAG_POSSIBLE4)) {
		/* a likely match, scan the lot */
		int i;
		for (i=0; reserved_names[i]; i++) {
			int len = strlen(reserved_names[i]);
			/* note that we match on COM1 as well as COM1.foo */
			if (strnequal(name, reserved_names[i], len) &&
			    (name[len] == '.' || name[len] == 0)) {
				return True;
			}
		}
	}

	return False;
}

static u32 mangle_hash(const char *key, unsigned int length)
{
	u32 value;
	u32   i;
	fstring str;

	/* we have to uppercase here to ensure that the mangled name
	   doesn't depend on the case of the long name. Note that this
	   is the only place where we need to use a multi-byte string
	   function */
	length = MIN(length,sizeof(fstring)-1);
	strncpy(str, key, length);
	str[length] = 0;
	strupper_m(str);

	/* the length of a multi-byte string can change after a strupper_m */
	length = strlen(str);

	/* Set the initial value from the key size. */
	for (value = FNV1_INIT, i=0; i < length; i++) {
                value *= (u32)FNV1_PRIME;
                value ^= (u32)(str[i]);
        }

	/* note that we force it to a 31 bit hash, to keep within the limits
	   of the 36^6 mangle space */
	return value & ~0x80000000;  
}


static void name_map(fstring name, BOOL need83, int default_case)
{
	char *dot_p;
	char lead_chars[7];
	char extension[4];
	unsigned int extension_length, i;
	unsigned int prefix_len;
	unsigned hash, v;
	char new_name[13];

	/* reserved names are handled specially */
	if (!is_reserved_name(name)) {
		/* if the name is already a valid 8.3 name then we don't need to 
		   do anything */
		if (is_8_3(name, False)) {
			return;
		}

		/* if the caller doesn't strictly need 8.3 then just check for illegal 
		   filenames */
		if (!need83 && illegal_name(name)) {
			return;
		}
	}

	/* find the '.' if any */
	dot_p = strrchr(name, '.');

	if (dot_p) {
		/* if the extension contains any illegal characters or
		   is too long or zero length then we treat it as part
		   of the prefix */
		for (i=0; i<4 && dot_p[i+1]; i++) {
			if (! FLAG_CHECK(dot_p[i+1], FLAG_ASCII)) {
				dot_p = NULL;
				break;
			}
		}
		if (i == 0 || i == 4) dot_p = NULL;
	}

	/* the leading characters in the mangled name is taken from
	   the first characters of the name, if they are ascii otherwise
	   '_' is used
	*/
	for (i=0;i<mangle_prefix && name[i];i++) {
		lead_chars[i] = name[i];
		if (! FLAG_CHECK(lead_chars[i], FLAG_ASCII)) {
			lead_chars[i] = '_';
		}
		lead_chars[i] = toupper(lead_chars[i]);
	}
	for (;i<mangle_prefix;i++) {
		lead_chars[i] = '_';
	}

	/* the prefix is anything up to the first dot */
	if (dot_p) {
		prefix_len = PTR_DIFF(dot_p, name);
	} else {
		prefix_len = strlen(name);
	}

	/* the extension of the mangled name is taken from the first 3
	   ascii chars after the dot */
	extension_length = 0;
	if (dot_p) {
		for (i=1; extension_length < 3 && dot_p[i]; i++) {
			char c = dot_p[i];
			if (FLAG_CHECK(c, FLAG_ASCII)) {
				extension[extension_length++] = toupper(c);
			}
		}
	}
	   
	/* find the hash for this prefix */
	v = hash = mangle_hash(name, prefix_len);

	/* now form the mangled name. */
	for (i=0;i<mangle_prefix;i++) {
		new_name[i] = lead_chars[i];
	}
	new_name[7] = base_forward(v % 36);
	new_name[6] = '~';	
	for (i=5; i>=mangle_prefix; i--) {
		v = v / 36;
		new_name[i] = base_forward(v % 36);
	}

	/* add the extension */
	if (extension_length) {
		new_name[8] = '.';
		memcpy(&new_name[9], extension, extension_length);
		new_name[9+extension_length] = 0;
	} else {
		new_name[8] = 0;
	}

	DEBUG(0,("name_map: %s -> %08X -> %s\n", 
		   name, hash, new_name));

	/* and overwrite the old name */
	fstrcpy(name, new_name);

	/* all done, we've managed to mangle it */
}


/****************************************************************************
map a long filename to a 8.3 name. return True if successful.
****************************************************************************/
BOOL name_map_mangle(char *OutName,BOOL need83,int snum)
  {
/* name mangling can be disabled for speed, in which case
	   we just truncate the string */
	if (!lp_manglednames(snum)) {
		if (need83) {
			string_truncate(OutName, 12);
		}
		return False;
	}

	mangle_map_filename(OutName, snum);

	name_map(OutName, need83, lp_defaultcase(snum));

	return True;
	
#if 0
 //#########################################################//
#ifdef MANGLE_LONG_FILENAMES
  if( !need83 && illegal_name(OutName) )
    need83 = True;
#endif  

  /* apply any name mappings */
  {
  char *map = lp_mangled_map(snum);

  if (map && *map)
    do_fwd_mangled_map(OutName,map);
  }

  /* check if it's already in 8.3 format */
  if( need83 && !is_8_3(OutName, True) )
    {
    if( !lp_manglednames(snum) )
      return(False);

    /* mangle it into 8.3 */
    push_mangled_name(OutName);  
    mangle_name_83(OutName);
    }
  
  return(True);
  #endif
  } /* name_map_mangle */

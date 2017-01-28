/* 
   Unix SMB/Netbios implementation.
   Version based 3.0.
   Main SMB reply routines
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
/*
   This file handles most of the reply_ calls that the server
   makes to handle specific protocols
*/


#include "includes.h"

/* look in server.c for some explanation of these variables */
extern int Protocol;
extern int DEBUGLEVEL;
extern int max_send;
extern int max_recv;
extern char magic_char;
extern connection_struct Connections[];
extern files_struct Files[];
extern BOOL case_sensitive;
extern BOOL case_preserve;
extern BOOL short_case_preserve;
extern pstring sesssetup_user;
extern fstring myworkgroup;
extern int Client;
#ifdef OPLOCK_ENABLE
extern int oplock_sock;
extern int global_oplock_break;
#endif
extern fstring local_machine;
extern int smb_read_error;
unsigned int smb_echo_count = 0;
static BOOL USING_SENDFILE = True;

extern int chain_size;

uint32 global_client_caps = 0;	//make it global!

/****************************************************************************
report a possible attack via the password buffer overflow bug
****************************************************************************/
static void overflow_attack(int len)
{
	DEBUG(0,("ERROR: Invalid password length %d\n", len));
	DEBUG(0,("your machine may be under attack by a user exploiting an old bug\n"));
	DEBUG(0,("Attack was from IP=%s\n", client_addr()));
	exit_server("possible attack");
}


/****************************************************************************
  reply to an special message 
****************************************************************************/
int reply_special(char *inbuf,char *outbuf)
{
	DEBUG(0,("in reply_special!\n"));
	
	int outsize = 4;
	int msg_type = CVAL(inbuf,0);
	int msg_flags = CVAL(inbuf,1);
	pstring name1,name2;
	extern fstring remote_machine;
	extern fstring local_machine;
	int len;
	char name_type = 0;
	
	*name1 = *name2 = 0;

	memset(outbuf,'\0',smb_size);
	
	smb_setlen(outbuf,0);
	
	switch (msg_type) {
	case 0x81: /* session request */
		SCVAL(outbuf,0,0x82);
		SCVAL(outbuf,3,0);
		if (name_len(inbuf+4) > 50 || 
		    name_len(inbuf+4 + name_len(inbuf + 4)) > 50) {
			DEBUG(0,("Invalid name length in session request\n"));
			return(0);
		}
		name_extract(inbuf,4,name1);
		name_extract(inbuf,4 + name_len(inbuf + 4),name2);
		DEBUG(2,("netbios connect: name1=%s name2=%s\n",
			 name1,name2));      

		fstrcpy(remote_machine,name2);
		remote_machine[15] = 0;
		trim_string(remote_machine," "," ");
		strlower_m(remote_machine);

		fstrcpy(local_machine,name1);
		len = strlen(local_machine);
		if (len == 16) {
			name_type = local_machine[15];
			local_machine[15] = 0;
		}
		trim_string(local_machine," "," ");
		strlower_m(local_machine);

		if (name_type == 'R') {
			/* We are being asked for a pathworks session --- 
			   no thanks! */
			SCVAL(outbuf, 0, 0x83);
			break;
		}

		if (lp_security() == SEC_SHARE) 
			add_session_user(remote_machine);

		reload_services(True);
		reopen_logs();

//		if (lp_status(-1)) {
//			claim_connection(-1,"STATUS.",MAXSTATUS,True);
//		}

		break;
		
	case 0x89: /* session keepalive request 
		      (some old clients produce this?) */
		SCVAL(outbuf,0,0x85);
		SCVAL(outbuf,3,0);
		break;
		
	case 0x82: /* positive session response */
	case 0x83: /* negative session response */
	case 0x84: /* retarget session response */
		DEBUG(0,("Unexpected session response\n"));
		break;
		
	case 0x85: /* session keepalive */
	default:
		return(0);
	}
	
	DEBUG(5,("%s init msg_type=0x%x msg_flags=0x%x\n",
		 timestring(),msg_type,msg_flags));
	
	return(outsize);
}


/*******************************************************************
work out what error to give to a failed connection
********************************************************************/
static int connection_error(char *inbuf,char *outbuf,int connection_num)
{
  switch (connection_num)
    {
    case -8:
      return(ERROR_DOS(ERRSRV,ERRnoresource));
    case -7:
      return(ERROR_DOS(ERRSRV,ERRbaduid));
    case -6:
      return(ERROR_DOS(ERRSRV,ERRinvdevice));
    case -5:
      return(ERROR_DOS(ERRSRV,ERRinvnetname));
    case -4:
      return(ERROR_DOS(ERRSRV,ERRaccess));
    case -3:
      return(ERROR_DOS(ERRDOS,ERRnoipc));
    case -2:
      return(ERROR_DOS(ERRSRV,ERRinvnetname));
    }
  return(ERROR_DOS(ERRSRV,ERRbadpw));
}



/****************************************************************************
  parse a share descriptor string
****************************************************************************/
static void parse_connect(char *p,char *service,char *user,
			  char *password,int *pwlen,char *dev)
{
  char *p2;

  DEBUG(4,("parsing connect string %s\n",p));
    
  p2 = strrchr_m(p,'\\');
  if (p2 == NULL)
    fstrcpy(service,p);
  else
    fstrcpy(service,p2+1);
  
  p += strlen(p) + 2;
  
  fstrcpy(password,p);
  *pwlen = strlen(password);

  p += strlen(p) + 2;

  fstrcpy(dev,p);
  
  *user = 0;
  p = strchr_m(service,'%');
  if (p != NULL)
    {
      *p = 0;
      fstrcpy(user,p+1);
    }
}




/****************************************************************************
  reply to a tcon
****************************************************************************/
int reply_tcon(char *inbuf,char *outbuf)
{
  pstring service;
  pstring user;
  pstring password;
  pstring dev;
  int connection_num;
  int outsize = 0;
  uint16 vuid = SVAL(inbuf,smb_uid);
  int pwlen=0;

  *service = *user = *password = *dev = 0;

  parse_connect(smb_buf(inbuf)+1,service,user,password,&pwlen,dev);

  connection_num = make_connection(service,user,password,pwlen,dev,vuid);
  
  if (connection_num < 0)
    return(connection_error(inbuf,outbuf,connection_num));
  
  outsize = set_message(outbuf,2,0,True);
  SSVAL(outbuf,smb_vwv0,max_recv);
  SSVAL(outbuf,smb_vwv1,connection_num);
  SSVAL(outbuf,smb_tid,connection_num);
  
  DEBUG(3,("%s tcon service=%s user=%s cnum=%d\n",timestring(),service,user,connection_num));
  
  return(outsize);
}


/****************************************************************************
  reply to a tcon and X
****************************************************************************/
int reply_tcon_and_X(char *inbuf,char *outbuf,int length,int bufsize)
{
  extern BOOL sam_logon_in_ssb;
  
  fstring service;
  pstring user;
  pstring password;
  fstring devicename;
  const char *server_devicetype;
  int connection_num;
  uint16 vuid = SVAL(inbuf,smb_uid);
  int passlen = SVAL(inbuf,smb_vwv3);
  int cnum;

  pstring path;
  char *p, *q;

  *service = *user = *password = *devicename = 0;
  
  cnum = SVAL(inbuf,smb_tid);

  /* we might have to close an old one */
  if ((SVAL(inbuf,smb_vwv2) & 0x1) != 0)
    close_cnum(SVAL(inbuf,smb_tid),vuid);

  if (passlen > MAX_PASS_LEN) {
	  overflow_attack(passlen);
  }
  
  {	
	memcpy(password,smb_buf(inbuf),passlen);	//handle passwd
    	password[passlen]=0;
#if 0		//for ntlmv2 the passlen would be larger than 24....
	if (passlen != 24) {
      		if (strequal(password," "))
			*password = 0;
      		passlen = strlen(password);

    	}
#endif
		
	p = smb_buf(inbuf) + passlen;
	p += srvstr_pull_buf(inbuf, path, p, sizeof(path), STR_TERMINATE);	//handle path

	if (*path=='\\') {	
		q = strchr_m(path+2,'\\');
		if (!q) {
			return(ERROR_DOS(ERRSRV,ERRnosuchshare));
		}
		fstrcpy(service,q+1);
	}
	else
		fstrcpy(service,path);	//handle service

	q = strchr_m(service,'%');
   	 if (q)
      	{
		*q++ = 0;
		fstrcpy(user,q);
      	}	//handle user

	p += srvstr_pull(inbuf, devicename, p, sizeof(devicename), 6, STR_ASCII);	//handle devicename
//########################################################//
    DEBUG(4,("Got device type %s, vuid: %d, sercurity level: %d, sam_logon: %d\n",
    		devicename, vuid, lp_security(),sam_logon_in_ssb));
  }

#if 0
  if((vuid == 0) && sam_logon_in_ssb &&  (lp_security() == SEC_USER)){
	fstrcpy(user, samlogon_user);
	vuid = samlogon_vuid;
  }

  DEBUG(0, ("(%s) username: %s\n", __FUNCTION__, user));
#endif

  connection_num = make_connection(service,user,password,passlen,devicename,vuid);

  DEBUG(0, ("conn_num: %d\n", connection_num));
  
  if (connection_num < 0)
    return(connection_error(inbuf,outbuf,connection_num));

  if ( IS_IPC(cnum) )
	server_devicetype = "IPC";
  else 
	server_devicetype = "A:";

  if (Protocol < PROTOCOL_NT1)
  {
	set_message(outbuf,2,0,True);
	p = smb_buf(outbuf);
	p += srvstr_push(outbuf, p, server_devicetype, -1, 
				 	STR_TERMINATE|STR_ASCII);
	set_message_end(outbuf,p);
//#########################################//
#if 0  
    set_message(outbuf,2,strlen(devicename)+1,True);
    strcpy(smb_buf(outbuf),devicename);
#endif
  }
  else
  {
    	const char *fsname = "SMB";
    	char *p;

    	set_message(outbuf,3,0,True);

    	p = smb_buf(outbuf);
	p += srvstr_push(outbuf, p, server_devicetype, -1, 
				 STR_TERMINATE|STR_ASCII);
	p += srvstr_push(outbuf, p, fsname, -1, 
				 STR_TERMINATE);
		
	set_message_end(outbuf,p);
#if 0
    strcpy(p,devicename); p = skip_string(p,1); /* device name */
    strcpy(p,fsname); p = skip_string(p,1); /* filesystem type e.g NTFS */

    set_message(outbuf,3,PTR_DIFF(p,smb_buf(outbuf)),False);
#endif

    SSVAL(outbuf, smb_vwv2, 0x0001); /* optional support */
  }
  
  DEBUG(3,("%s tconX service=%s user=%s cnum=%d\n",timestring(),service,user,connection_num));
  
  /* set the incoming and outgoing tid to the just created one */
  SSVAL(inbuf,smb_tid,connection_num);
  SSVAL(outbuf,smb_tid,connection_num);

  return chain_reply(inbuf,outbuf,length,bufsize);
}


/****************************************************************************
  reply to an unknown type
****************************************************************************/
int reply_unknown(char *inbuf,char *outbuf)
{
  int cnum;
  int type;
  cnum = SVAL(inbuf,smb_tid);
  type = CVAL(inbuf,smb_com);
  
  DEBUG(0,("%s unknown command type (%s): cnum=%d type=%d (0x%X)\n",
	timestring(),
	smb_fn_name(type),
	cnum,type,type));
  
  return(ERROR_DOS(ERRSRV,ERRunknownsmb));
}

#define IOCTL_QUERY_JOB_INFO      0x530060
/****************************************************************************
  reply to an ioctl
****************************************************************************/
int reply_ioctl(char *inbuf,char *outbuf)
{
	  DEBUG(3,("ignoring ioctl\n"));
#if 0
  /* we just say it succeeds and hope its all OK. 
     some day it would be nice to interpret them individually */
  return set_message(outbuf,1,0,True); 
#else
  return(ERROR_DOS(ERRSRV,ERRnosupport));
#endif

}

void ra_lanman_string( const char *native_lanman )
{		 
	if ( strcmp( native_lanman, "Windows 2002 5.1" ) == 0 )
		set_remote_arch( RA_WINXP );
	else if ( strcmp( native_lanman, "Windows Server 2003 5.2" ) == 0 )
		set_remote_arch( RA_WIN2K3 );
}

/****************************************************************************
reply to a session setup command
****************************************************************************/
int reply_sesssetup_and_X(char *inbuf,char *outbuf,int length,int bufsize)
{
	extern BOOL sam_logon_in_ssb;
	extern pstring samlogon_user;
	
  	uint16 sess_vuid;
  	int gid;
  	int uid;
  	int   smb_bufsize;    
  	int   smb_lmpasslen = 0;   
  	uint8 smb_lmpasswd[256];	//*lm resp it's ascii
 
  	int   smb_ntpasslen = 0;   
  	uint8 smb_ntpasswd[512];	//*nt resp it's unicode
  	
  	BOOL valid_nt_password = False;
  	fstring user;
  	fstring sub_user; /* Sainitised username for substituion */
  	fstring domain;
  	fstring native_os;
  	fstring native_lanman;
  	fstring primary_domain;
  	BOOL guest=False;
  	static BOOL done_sesssetup = False;
  	BOOL doencrypt = SMBENCRYPT();
	
	smb_bufsize = SVAL(inbuf,smb_vwv2);

	*smb_lmpasswd = 0;  
	*smb_ntpasswd = 0;

	if (Protocol < PROTOCOL_NT1) {
		smb_lmpasslen = SVAL(inbuf,smb_vwv7);

		/* Never do NT status codes with protocols before NT1 as we don't get client caps. */
		remove_from_common_flags2(FLAGS2_32_BIT_ERROR_CODES);

		if ((smb_lmpasslen > MAX_PASS_LEN) || (smb_lmpasslen > smb_bufrem(inbuf, smb_buf(inbuf)))) {
			return ERROR_NT(NT_STATUS_INVALID_PARAMETER);
		}

		memcpy(smb_lmpasswd, smb_buf(inbuf), smb_lmpasslen);

		srvstr_pull_buf(inbuf, user, smb_buf(inbuf)+smb_lmpasslen, sizeof(user), STR_TERMINATE);
		*domain = 0;

	} 
	else{
		uint16 passlen1 = SVAL(inbuf,smb_vwv7);
		uint16 passlen2 = SVAL(inbuf,smb_vwv8);
		enum remote_arch_types ra_type = get_remote_arch();
		char *p = smb_buf(inbuf);    
		char *save_p = smb_buf(inbuf);
		uint16 byte_count;
			
		if(global_client_caps == 0) {
			global_client_caps = IVAL(inbuf,smb_vwv11);
		
			if (!(global_client_caps & CAP_STATUS32)) {
				remove_from_common_flags2(FLAGS2_32_BIT_ERROR_CODES);
			}
			
			/* client_caps is used as final determination if client is NT or Win95. 
			   This is needed to return the correct error codes in some
			   circumstances.
			*/
		
			if(ra_type == RA_WINNT || ra_type == RA_WIN2K || ra_type == RA_WIN95) {
				if(!(global_client_caps & (CAP_NT_SMBS | CAP_STATUS32))) {
					set_remote_arch( RA_WIN95);
				}
			}
		}

		if (!doencrypt) {
			/* both Win95 and WinNT stuff up the password lengths for
			   non-encrypting systems. Uggh. 
			   
			   if passlen1==24 its a win95 system, and its setting the
			   password length incorrectly. Luckily it still works with the
			   default code because Win95 will null terminate the password
			   anyway 
			   
			   if passlen1>0 and passlen2>0 then maybe its a NT box and its
			   setting passlen2 to some random value which really stuffs
			   things up. we need to fix that one.  */
			
			if (passlen1 > 0 && passlen2 > 0 && passlen2 != 24 && passlen2 != 1)
				passlen2 = 0;
		}
		
		/* check for nasty tricks */
		if (passlen1 > MAX_PASS_LEN || passlen1 > smb_bufrem(inbuf, p)) {
			return ERROR_NT(NT_STATUS_INVALID_PARAMETER);
		}

		if (passlen2 > MAX_PASS_LEN || passlen2 > smb_bufrem(inbuf, p+passlen1)) {
			return ERROR_NT(NT_STATUS_INVALID_PARAMETER);
		}

		/* Save the lanman2 password and the NT md4 password. */
		
		if ((doencrypt) && (passlen1 != 0) && (passlen1 != 24)) {
			doencrypt = False;
		}

		if (doencrypt) {
			smb_lmpasslen = passlen1;      		
			memcpy(smb_lmpasswd, p, smb_lmpasslen);      		
			smb_lmpasswd[smb_lmpasslen] = 0;   
			
			smb_ntpasslen = passlen2;      		
			memcpy(smb_ntpasswd,p+passlen1,smb_ntpasslen);      		
			smb_ntpasswd[smb_ntpasslen] = 0;
		} else {
			pstring pass;
			BOOL unic=SVAL(inbuf, smb_flg2) & FLAGS2_UNICODE_STRINGS;

			if (unic && (passlen2 == 0) && passlen1) {
				/* Only a ascii plaintext password was sent. */
				srvstr_pull(inbuf, pass, smb_buf(inbuf), sizeof(pass),
					passlen1, STR_TERMINATE|STR_ASCII);
			} else {
				srvstr_pull(inbuf, pass, smb_buf(inbuf), 
					sizeof(pass),  unic ? passlen2 : passlen1, 
					STR_TERMINATE);
			}
			StrnCpy(smb_lmpasswd, pass, smb_lmpasslen);  
			smb_lmpasslen = strlen(pass);
			
			if (strequal(smb_lmpasswd," ")) {
        			smb_lmpasslen = 0;
        			*smb_lmpasswd = 0;
      			}
		}
		
		p += passlen1 + passlen2;
		p += srvstr_pull_buf(inbuf, user, p, sizeof(user), STR_TERMINATE);
		p += srvstr_pull_buf(inbuf, domain, p, sizeof(domain), STR_TERMINATE);
		p += srvstr_pull_buf(inbuf, native_os, p, sizeof(native_os), STR_TERMINATE);
		p += srvstr_pull_buf(inbuf, native_lanman, p, sizeof(native_lanman), STR_TERMINATE);

		/* not documented or decoded by Ethereal but there is one more string 
		   in the extra bytes which is the same as the PrimaryDomain when using 
		   extended security.  Windows NT 4 and 2003 use this string to store 
		   the native lanman string. Windows 9x does not include a string here 
		   at all so we have to check if we have any extra bytes left */
		
		byte_count = SVAL(inbuf, smb_vwv13);
		if ( PTR_DIFF(p, save_p) < byte_count)
			p += srvstr_pull_buf(inbuf, primary_domain, p, sizeof(primary_domain), STR_TERMINATE);
		else 
			fstrcpy( primary_domain, "null" );

		DEBUG(3,("Domain=[%s]  NativeOS=[%s] NativeLanMan=[%s] PrimaryDomain=[%s]\n",
			 domain, native_os, native_lanman, primary_domain));

		if ( ra_type == RA_WIN2K ) {
			if ( strlen(native_lanman) == 0 )
				ra_lanman_string( primary_domain );
			else
				ra_lanman_string( native_lanman );
		}
	}

	DEBUG(3,("sesssetupX:name=[%s]\n", user));

	if (*user) {
		fstrcpy(sub_user, user);

		/* setup the string used by %U */
		sub_set_smb_name(user);
	} else {
		fstrcpy(sub_user, lp_guestaccount(-1));
	}

	sub_set_smb_name(sub_user);

	fstrcpy(user, sub_user);

//####NOW WE GOT THE CORRECT USERNAME & CLIENT PASSWD RESP. WE WILL####//
//####DEAL WITH IT IN THE NEXT############//

	if (user[strlen(user) - 1] == '$') {    
		user[strlen(user) - 1] = '\0';  
	}

/*
  * Check if the given username was the guest user with no password.
  */
	if(strequal(user,lp_guestaccount(-1))){
    		if( (*smb_lmpasswd == 0) && (*smb_ntpasswd == 0)){
			DEBUG(0,("yes, it is guest login request!\n"));
			guest = True;
    		}
	}

	//strlower_m(user);  
	
	if((lp_security() != SEC_SHARE) || (*user && !guest))
    		pstrcpy(sesssetup_user,user);

  	reload_services(True);

  /*
   * Pass the user through the NT -> unix user mapping
   * function.
   */
   
  	map_username(user);

  /*
   * Do any UNIX username case mangling.
   */
  	Get_Pwnam(user, True);

  	add_session_user(user);

   /* 
     * If we get here then the user wasn't guest and the remote
     * authentication methods failed. Check the authentication
     * methods on this local server.
     *
     * If an NT password was supplied try and validate with that
     * first. This is superior as the passwords are mixed case 
     * 128 length unicode.
      */

	 if (!guest && !check_hosts_equiv(user)){
	 	if(smb_ntpasslen > 24){		//Got you Mr.ntlmV2......I've been waiting u for fxxking long time :)
			if(!password_ok_ntlmv2(smb_ntpasswd/*nt response*/,	
									smb_ntpasslen,
									user,
									domain/*client domain*/))
									
				DEBUG(2,("(%d)NT Password did not match for user '%s' ! Defaulting to Lanman\n", __LINE__, user));
			else
				valid_nt_password = True;
		}
		
		else if(smb_ntpasslen > 0)	//normal ntlmV1
    		{
      			if(!password_ok(user, smb_ntpasswd, smb_ntpasslen, NULL))
        			DEBUG(2,("(%d)NT Password did not match for user '%s' ! Defaulting to Lanman\n", __LINE__, user));
      			else
        			valid_nt_password = True;
    		} 

		if (!valid_nt_password && !password_ok(user, smb_lmpasswd,smb_lmpasslen,NULL))
    		{
      			if (lp_security() >= SEC_USER) 
      			{
#if (GUEST_SESSSETUP == 0)	   //yes we reject! 
				return(ERROR_DOS(ERRSRV,ERRbadpw));
#endif

#if (GUEST_SESSSETUP == 1)	    
				if (Get_Pwnam(user,True))	      
					return(ERROR_DOS(ERRSRV,ERRbadpw));
#endif
      			}

      			if (*smb_lmpasswd || !Get_Pwnam(user,True))
         			pstrcpy(user,lp_guestaccount(-1));
				
      			DEBUG(3,("Registered username %s for guest access\n",user));
      			guest = True;
    		}
	}

	if (!Get_Pwnam(user,True)) {
    		DEBUG(3,("No such user %s - using guest account\n",user));
    		pstrcpy(user,lp_guestaccount(-1));
    		guest = True;
  	}

	if (!strequal(user,lp_guestaccount(-1)) &&
      		lp_servicenumber(user) < 0)      
  	{
    		int homes = lp_servicenumber(HOMES_NAME);
    		char *home = get_home_dir(user);
    		if (homes >= 0 && home)
      			lp_add_home(user,homes,home);
  	}

	 /* it's ok - setup a reply */
  	if (Protocol < PROTOCOL_NT1) {
    		set_message(outbuf,3,0,True);
  	} 
	else {
    		set_message(outbuf,3,3,True);	
		char *p = smb_buf( outbuf );	
		p += add_signature( outbuf, p );		
		set_message_end( outbuf, p );
  	}

/* Set the correct uid in the outgoing and incoming packets
     We will use this on future requests to determine which
     user we should become.
     */
  	{
    		struct passwd *pw = Get_Pwnam(user,False);
    		if (!pw) {
      			DEBUG(1,("Username %s is invalid on this system\n",user));
      			return(ERROR_DOS(ERRSRV,ERRbadpw));
    		}
    		gid = pw->pw_gid;
    		uid = pw->pw_uid;
  	}

	if (guest)
    		SSVAL(outbuf,smb_vwv2,1);

  /* register the name and uid as being validated, so further connections
     to a uid can get through without a password, on the same VC */
  	sess_vuid = register_vuid(uid,gid,user,sesssetup_user,guest);
 
  	SSVAL(outbuf,smb_uid,sess_vuid);
  	SSVAL(inbuf,smb_uid,sess_vuid);

  	if (!done_sesssetup)
    		max_send = MIN(max_send, smb_bufsize);

  	DEBUG(6,("Client requested max send size of %d\n", max_send));

	if(!guest && (lp_security() == SEC_USER)){
		sam_logon_in_ssb = True;
		pstrcpy(samlogon_user, sesssetup_user);
	}
	else if(guest && (lp_security() == SEC_SHARE)){
		sam_logon_in_ssb = False;
	}
	
	DEBUG(0, ("guest: %d usename: %s\n", guest, sesssetup_user));

  	done_sesssetup = True;

  	return chain_reply(inbuf,outbuf,length,bufsize);
     
#if 0
//#############################################################//
	
	if (lp_security() == SEC_SHARE) {
		/* in share level we should ignore any passwords */

		data_blob_free(&lm_resp);
		data_blob_free(&nt_resp);
		data_blob_clear_free(&plaintext_password);

		map_username(sub_user);
		add_session_user(sub_user);
		/* Then force it to null for the benfit of the code below */
		*user = 0;
	}

	if (!*user) {

		nt_status = check_guest_password(&server_info);

	} else if (doencrypt) {
		if (!negprot_global_auth_context) {
			DEBUG(0, ("reply_sesssetup_and_X:  Attempted encrypted session setup without negprot denied!\n"));
			return ERROR_NT(NT_STATUS_LOGON_FAILURE);
		}
		nt_status = make_user_info_for_reply_enc(&user_info, user, domain,
		                                         lm_resp, nt_resp);
		if (NT_STATUS_IS_OK(nt_status)) {
			nt_status = negprot_global_auth_context->check_ntlm_password(negprot_global_auth_context, 
										     							user_info, 
										     							&server_info);
		}
	} 

	free_user_info(&user_info);
	
	if (!NT_STATUS_IS_OK(nt_status)) {
		data_blob_free(&nt_resp);
		data_blob_free(&lm_resp);
		data_blob_clear_free(&plaintext_password);
		return ERROR_NT(nt_status_squash(nt_status));
	}

	if (server_info->user_session_key.data) {
		session_key = data_blob(server_info->user_session_key.data, server_info->user_session_key.length);
	} else {
		session_key = data_blob(NULL, 0);
	}

	data_blob_clear_free(&plaintext_password);
	
	/* it's ok - setup a reply */
	set_message(outbuf,3,0,True);
	if (Protocol >= PROTOCOL_NT1) {
		char *p = smb_buf( outbuf );
		p += add_signature( outbuf, p );
		set_message_end( outbuf, p );
		/* perhaps grab OS version here?? */
	}
	
	if (server_info->guest) {
		SSVAL(outbuf,smb_vwv2,1);
	}

	/* register_vuid keeps the server info */
	sess_vuid = register_vuid(server_info->uid, server_info->gid, server_info->unix_name,
							sesssetup_user, server_info->guest);
	
	data_blob_free(&nt_resp);
	data_blob_free(&lm_resp);

	if (sess_vuid == -1) {
		return ERROR_NT(NT_STATUS_LOGON_FAILURE);
	}

	/* current_user_info is changed on new vuid */
	reload_services( True );

	SSVAL(outbuf,smb_uid,sess_vuid);
	SSVAL(inbuf,smb_uid,sess_vuid);
	
	if (!done_sesssetup)
		max_send = MIN(max_send,smb_bufsize);
	
	done_sesssetup = True;
	
	return chain_reply(inbuf,outbuf,length,bufsize);

//#################################################################

  *smb_apasswd = 0;
  *smb_ntpasswd = 0;
  
  smb_bufsize = SVAL(inbuf,smb_vwv2);
  smb_mpxmax = SVAL(inbuf,smb_vwv3);
  smb_vc_num = SVAL(inbuf,smb_vwv4);
  smb_sesskey = IVAL(inbuf,smb_vwv5);

  if (Protocol < PROTOCOL_NT1) {
  	smb_apasslen = SVAL(inbuf,smb_vwv7);
	remove_from_common_flags2(FLAGS2_32_BIT_ERROR_CODES);
    if ((smb_apasslen > MAX_PASS_LEN) || 
	(smb_apasslen > smb_bufrem(inbuf, smb_buf(inbuf))))
    {
	    return ERROR_NT(NT_STATUS_INVALID_PARAMETER);
    }

    memcpy(smb_apasswd,smb_buf(inbuf),smb_apasslen);
    smb_apasswd[smb_apasslen] = 0;

    srvstr_pull_buf(inbuf, user, smb_buf(inbuf)+smb_apasslen, sizeof(user), STR_TERMINATE);
//    pstrcpy(user,smb_buf(inbuf)+smb_apasslen);

    if (!doencrypt && (lp_security() != SEC_SERVER)) {
	    smb_apasslen = strlen(smb_apasswd);
    }
  } else {
    uint16 passlen1 = SVAL(inbuf,smb_vwv7);
    uint16 passlen2 = SVAL(inbuf,smb_vwv8);
    enum remote_arch_types ra_type = get_remote_arch();

    char *p = smb_buf(inbuf);  
    char *save_p = smb_buf(inbuf);
    uint16 byte_count;

    /* client_caps is used as final determination if client is NT or Win95. 
       This is needed to return the correct error codes in some
       circumstances.
     */

	if(global_client_caps == 0) {
		global_client_caps = IVAL(inbuf,smb_vwv11);
		
		if (!(global_client_caps & CAP_STATUS32)) {
			remove_from_common_flags2(FLAGS2_32_BIT_ERROR_CODES);
		}
		
		if(ra_type == RA_WINNT || ra_type == RA_WIN2K || ra_type == RA_WIN95) {
			if(!(global_client_caps & (CAP_NT_SMBS | CAP_STATUS32))) {
				set_remote_arch( RA_WIN95);
			}
		}
	}

    if ((doencrypt) && passlen1 != 0 && passlen2 != 24)
		doencrypt = False;

    if (passlen1 > MAX_PASS_LEN)
	    	overflow_attack(passlen1);

    passlen1 = MIN(passlen1, MAX_PASS_LEN);
    passlen2 = MIN(passlen2, MAX_PASS_LEN);

	if(doencrypt || (lp_security() == SEC_SERVER)) {
      /* Save the lanman2 password and the NT md4 password. */
      		smb_apasslen = passlen1;
      		memcpy(smb_apasswd,p,smb_apasslen);
      		smb_apasswd[smb_apasslen] = 0;
      		smb_ntpasslen = passlen2;
      		memcpy(smb_ntpasswd,p+passlen1,smb_ntpasslen);
      		smb_ntpasswd[smb_ntpasslen] = 0;
    	} 
	else{
    	
    	/* both Win95 and WinNT stuff up the password lengths for
	 non-encrypting systems. Uggh. 
      
	 if passlen1==24 its a win95 system, and its setting the
	 password length incorrectly. Luckily it still works with the
	 default code because Win95 will null terminate the password
	 anyway 

	 if passlen1>0 and passlen2>0 then maybe its a NT box and its
	 setting passlen2 to some random value which really stuffs
	 things up. we need to fix that one.  */
	 
    		if (passlen1 > 0 && passlen2 > 0 && passlen2 != 24 && passlen2 != 1)
			passlen2 = 0;
#if 0
		/* we use the first password that they gave */
      		smb_apasslen = passlen1;
      		StrnCpy(smb_apasswd,p,smb_apasslen);      
      
      		/* trim the password */
      		smb_apasslen = strlen(smb_apasswd);

      		/* wfwg sometimes uses a space instead of a null */
      		if (strequal(smb_apasswd," ")) {
			smb_apasslen = 0;
			*smb_apasswd = 0;
      		}
	}
	 p += passlen1 + passlen2;
    	fstrcpy(user,p); p = skip_string(p,1);
    	domain = p;

    	DEBUG(3,("Domain=[%s]  NativeOS=[%s] NativeLanMan=[%s]\n",
	     		domain,skip_string(p,1),skip_string(p,2)));
  }
#endif

#if 1
		pstring pass;
		BOOL unic=SVAL(inbuf, smb_flg2) & FLAGS2_UNICODE_STRINGS;

		if (unic && (passlen2 == 0) && passlen1) {
				/* Only a ascii plaintext password was sent. */
			srvstr_pull(inbuf, pass, smb_buf(inbuf), sizeof(pass),
					passlen1, STR_TERMINATE|STR_ASCII);
		} else {
			srvstr_pull(inbuf, pass, smb_buf(inbuf), 
					sizeof(pass),  unic ? passlen2 : passlen1, STR_TERMINATE);
		}

		smb_plaintextpwdlen = strlen(pass)+1;
		memcpy(plaintext_password,pass,smb_plaintextpwdlen);
		plaintext_password[smb_plaintextpwdlen] = 0;
	}

	p += passlen1 + passlen2;
	p += srvstr_pull_buf(inbuf, user, p, sizeof(user), STR_TERMINATE);
	p += srvstr_pull_buf(inbuf, domain, p, sizeof(domain), STR_TERMINATE);
	p += srvstr_pull_buf(inbuf, native_os, p, sizeof(native_os), STR_TERMINATE);
	p += srvstr_pull_buf(inbuf, native_lanman, p, sizeof(native_lanman), STR_TERMINATE);

	byte_count = SVAL(inbuf, smb_vwv13);
	if ( PTR_DIFF(p, save_p) < byte_count)
		p += srvstr_pull_buf(inbuf, primary_domain, p, sizeof(primary_domain), STR_TERMINATE);
	else 
		fstrcpy( primary_domain, "null" );

	DEBUG(3,("Domain=[%s]  NativeOS=[%s] NativeLanMan=[%s] PrimaryDomain=[%s]\n",
			 domain, native_os, native_lanman, primary_domain));

	if ( ra_type == RA_WIN2K ) {
		if ( strlen(native_lanman) == 0 )
			ra_lanman_string( primary_domain );
		else
			ra_lanman_string( native_lanman );
	}
  }
#endif

  DEBUG(3,("sesssetupX:name=[%s]\n",user));

  /* If name ends in $ then I think it's asking about whether a */
  /* computer with that name (minus the $) has access. For now */
  /* say yes to everything ending in $. */
  if (user[strlen(user) - 1] == '$')
  {
    user[strlen(user) - 1] = '\0';
  }


  /* If no username is sent use the guest account */
  if (!*user)
    {
      strcpy(user,lp_guestaccount(-1));
      /* If no user and no password then set guest flag. */
      if( *smb_apasswd == 0)
        guest = True;
    }

  strlower_m(user);

  strcpy(sesssetup_user,user);

  reload_services(True);

  add_session_user(user);

  /* Check if the given username was the guest user with no password.
     We need to do this check after add_session_user() as that
     call can potentially change the username (via map_user).
   */

  if(!guest && strequal(user,lp_guestaccount(-1)) && (*smb_apasswd == 0))
    guest = True;

  if (!guest && !(lp_security() == SEC_SERVER /*&& 
		  server_validate(user, domain, 
				  smb_apasswd, smb_apasslen, 
				  smb_ntpasswd, smb_ntpasslen))*/ &&
      !check_hosts_equiv(user))
    {

      /* now check if it's a valid username/password */
      /* If an NT password was supplied try and validate with that
	 first. This is superior as the passwords are mixed case 
         128 length unicode */
      if(smb_ntpasslen)
	{
	  if(!password_ok(user,smb_ntpasswd,smb_ntpasslen,NULL))
	    DEBUG(0,("NT Password did not match ! Defaulting to Lanman\n"));
	  else
	    valid_nt_password = True;
	} 
      if (!valid_nt_password && !password_ok(user,smb_apasswd,smb_apasslen,NULL))
	{
	  if (!computer_id && lp_security() >= SEC_USER) {
#if (GUEST_SESSSETUP == 0)
	    return(ERROR_DOS(ERRSRV,ERRbadpw));
#endif
#if (GUEST_SESSSETUP == 1)
	    if (Get_Pwnam(user,True))
	      return(ERROR_DOS(ERRSRV,ERRbadpw));
#endif
	  }
 	  if (*smb_apasswd || !Get_Pwnam(user,True))
	    strcpy(user,lp_guestaccount(-1));
	  DEBUG(3,("Registered username %s for guest access\n",user));
	  guest = True;
	}
    }


  if (!Get_Pwnam(user,True)) {
    DEBUG(3,("No such user %s - using guest account\n",user));
    strcpy(user,lp_guestaccount(-1));
    guest = True;
  }

  if (!strequal(user,lp_guestaccount(-1)) &&
      lp_servicenumber(user) < 0)      
    {
      int homes = lp_servicenumber(HOMES_NAME);
      char *home = get_home_dir(user);
      if (homes >= 0 && home)
	lp_add_home(user,homes,home);
    }


  /* it's ok - setup a reply */
  if (Protocol < PROTOCOL_NT1) {
    set_message(outbuf,3,0,True);
  } else {
	set_message(outbuf,3,3,True);
	char *p = smb_buf( outbuf );
	p += add_signature( outbuf, p );	
	set_message_end( outbuf, p );
    /* perhaps grab OS version here?? */
  }

  /* Set the correct uid in the outgoing and incoming packets
     We will use this on future requests to determine which
     user we should become.
     */
  {
    struct passwd *pw = Get_Pwnam(user,False);
    if (!pw) {
      DEBUG(1,("Username %s is invalid on this system\n",user));
      return(ERROR_DOS(ERRSRV,ERRbadpw));
    }
    gid = pw->pw_gid;
    uid = pw->pw_uid;
  }

  if (guest && !computer_id)
    SSVAL(outbuf,smb_vwv2,1);

  /* register the name and uid as being validated, so further connections
     to a uid can get through without a password, on the same VC */
  sess_vuid = register_vuid(uid,gid,user,guest);
 
  SSVAL(outbuf,smb_uid,sess_vuid);
  SSVAL(inbuf,smb_uid,sess_vuid);

  if (!done_sesssetup)
    max_send = MIN(max_send,smb_bufsize);

  DEBUG(6,("Client requested max send size of %d\n", max_send));

  done_sesssetup = True;

  return chain_reply(inbuf,outbuf,length,bufsize);
#endif
}


/****************************************************************************
  reply to a chkpth
****************************************************************************/
int reply_chkpth(char *inbuf,char *outbuf)
{
  int outsize = 0;
  int cnum,mode;
  pstring name;
  BOOL ok = False;
  BOOL bad_path = False;
  NTSTATUS status = NT_STATUS_OK;
 
  cnum = SVAL(inbuf,smb_tid);
  
//  pstrcpy(name,smb_buf(inbuf) + 1);
  srvstr_get_path(inbuf, name, smb_buf(inbuf) + 1, sizeof(name), 0, STR_TERMINATE, &status, False);
  if (!NT_STATUS_IS_OK(status)) {
		return ERROR_NT(status);
  }

  unix_convert(name,cnum,0,&bad_path);

  mode = SVAL(inbuf,smb_vwv0);

  if (check_name(name,cnum))
    ok = directory_exist(name,NULL);

  if (!ok)
  {
    /* We special case this - as when a Windows machine
       is parsing a path is steps through the components
       one at a time - if a component fails it expects
       ERRbadpath, not ERRbadfile.
     */
    if(errno == ENOENT)
    {
      return ERROR_BOTH(NT_STATUS_OBJECT_NAME_NOT_FOUND,ERRDOS,ERRbadpath);
    }

#if 0
    /* Ugly - NT specific hack - maybe not needed ? (JRA) */
    if((errno == ENOTDIR) && (Protocol >= PROTOCOL_NT1) &&
       (get_remote_arch() == RA_WINNT))
    {
      unix_ERR_class = ERRDOS;
      unix_ERR_code = ERRbaddirectory;
    }
#endif

    return(UNIXERROR(ERRDOS,ERRbadpath));
  }
 
  outsize = set_message(outbuf,0,0,True);
  
  DEBUG(3,("%s chkpth %s cnum=%d mode=%d\n",timestring(),name,cnum,mode));
  
  return(outsize);
}


/****************************************************************************
  reply to a getatr
****************************************************************************/
int reply_getatr(char *inbuf,char *outbuf)
{
	DEBUG(0,("in reply_getatr!\n"));
  pstring fname;
  int cnum;
  int outsize = 0;
  SMB_STRUCT_STAT sbuf;
  BOOL ok = False;
  int mode=0;
  SMB_OFF_T size=0;
  time_t mtime=0;
  BOOL bad_path = False;
  char *p;
  NTSTATUS ntstatus = NT_STATUS_OK;
 
  cnum = SVAL(inbuf,smb_tid);

  p = smb_buf(inbuf) + 1;
  p += srvstr_get_path(inbuf, fname, p, sizeof(fname), 0, STR_TERMINATE, &ntstatus, False);
  if (!NT_STATUS_IS_OK(ntstatus)) {
		return ERROR_NT(ntstatus);
  }

//  pstrcpy(fname,smb_buf(inbuf) + 1);
  unix_convert(fname,cnum,0,&bad_path);
  DEBUG(0,("fname is: %s\n", fname));

  /* dos smetimes asks for a stat of "" - it returns a "hidden directory"
     under WfWg - weird! */
  if (! (*fname))
    {
      mode = aHIDDEN | aDIR;
      if (!CAN_WRITE(cnum)) mode |= aRONLY;
      size = 0;
      mtime = 0;
      ok = True;
    }
  else
    if (check_name(fname,cnum))
    {
      if (sys_stat(fname,&sbuf) == 0)
      {
        mode = dos_mode(cnum,fname,&sbuf);
        size = sbuf.st_size;
        mtime = sbuf.st_mtime;
        if (mode & aDIR)
          size = 0;
        ok = True;
      }
      else
        DEBUG(3,("stat of %s failed (%s)\n",fname,strerror(errno)));
    }
  
  if (!ok)
  {
    	return set_bad_path_error(outbuf, errno, bad_path, ERRDOS,ERRbadfile);
  }
 
  outsize = set_message(outbuf,10,0,True);

  SSVAL(outbuf,smb_vwv0,mode);
  put_dos_date3(outbuf,smb_vwv1,mtime&~1);
  SIVAL(outbuf,smb_vwv3,size);

  if (Protocol >= PROTOCOL_NT1) {
    char *p = strrchr_m(fname,'/');
    uint16 flg2 = SVAL(outbuf,smb_flg2);
    if (!p) 
	p = fname;
#ifdef USE_83_NAME
    if (!is_8_3(fname, True))
      SSVAL(outbuf,smb_flg2,flg2 | 0x40); /* IS_LONG_NAME */
#endif
  }
  
  DEBUG(3,("%s getatr name=%s mode=%d size=%d\n",timestring(),fname,mode,size));
  
  return(outsize);
}


/****************************************************************************
  reply to a setatr
****************************************************************************/
int reply_setatr(char *inbuf,char *outbuf)
{
  pstring fname;
  int cnum;
  int outsize = 0;
  BOOL ok=False;
  int mode;
  time_t mtime;
  BOOL bad_path = False;
  NTSTATUS status = NT_STATUS_OK;
 
  cnum = SVAL(inbuf,smb_tid);
  
//  pstrcpy(fname,smb_buf(inbuf) + 1);
  srvstr_get_path(inbuf, fname, smb_buf(inbuf)+1, sizeof(fname), 0, STR_TERMINATE, &status, False);
  if (!NT_STATUS_IS_OK(status)) {
		return ERROR_NT(status);
  }
  
  unix_convert(fname,cnum,0,&bad_path);

  mode = SVAL(inbuf,smb_vwv0);
  mtime = make_unix_date3(inbuf+smb_vwv1);
  
  if (directory_exist(fname,NULL))
    mode |= aDIR;
  if (check_name(fname,cnum))
    ok =  (dos_chmod(cnum,fname,mode,NULL) == 0);
  if (ok)
    ok = set_filetime(cnum,fname,mtime);
  
  if (!ok)
  {
   	return set_bad_path_error(outbuf, errno, bad_path, ERRDOS, ERRnoaccess);
  }
 
  outsize = set_message(outbuf,0,0,True);
  
  DEBUG(3,("%s setatr name=%s mode=%d\n",timestring(),fname,mode));
  
  return(outsize);
}


/****************************************************************************
  reply to a dskattr
****************************************************************************/
int reply_dskattr(char *inbuf,char *outbuf)
{
  int cnum;
  int outsize = 0;
  SMB_BIG_UINT dfree,dsize,bsize;
  
  cnum = SVAL(inbuf,smb_tid);
  
  sys_disk_free(".",&bsize,&dfree,&dsize);
  
  outsize = set_message(outbuf,5,0,True);
  
  if (Protocol <= PROTOCOL_LANMAN2) {
		double total_space, free_space;
		/* we need to scale this to a number that DOS6 can handle. We
		   use floating point so we can handle large drives on systems
		   that don't have 64 bit integers 

		   we end up displaying a maximum of 2G to DOS systems
		*/
		total_space = dsize * (double)bsize;
		free_space = dfree * (double)bsize;

		dsize = (total_space+63*512) / (64*512);
		dfree = (free_space+63*512) / (64*512);
		
		if (dsize > 0xFFFF) dsize = 0xFFFF;
		if (dfree > 0xFFFF) dfree = 0xFFFF;

		SSVAL(outbuf,smb_vwv0,dsize);
		SSVAL(outbuf,smb_vwv1,64); /* this must be 64 for dos systems */
		SSVAL(outbuf,smb_vwv2,512); /* and this must be 512 */
		SSVAL(outbuf,smb_vwv3,dfree);
	} else {
		SSVAL(outbuf,smb_vwv0,dsize);
		SSVAL(outbuf,smb_vwv1,bsize/512);
		SSVAL(outbuf,smb_vwv2,512);
		SSVAL(outbuf,smb_vwv3,dfree);
	}
  
  DEBUG(3,("%s dskattr cnum=%d dfree=%d\n",timestring(),cnum,dfree));
  
  return(outsize);
}


/****************************************************************************
  reply to a search
  Can be called from SMBsearch, SMBffirst or SMBfunique.
****************************************************************************/
int reply_search(char *inbuf,char *outbuf)
{
  pstring mask;
  pstring directory;
  pstring fname;
  int mode;
  SMB_OFF_T size;
  time_t date;
  int dirtype;
  int cnum;
  int outsize = 0;
  int numentries = 0;
  BOOL finished = False;
  int maxentries;
  int i;
  char *p;
  BOOL ok = False;
  int status_len;
  pstring path;
  char status[21];
  int dptr_num= -1;
  BOOL check_descend = False;
  BOOL expect_close = False;
  BOOL can_open = True;
  BOOL bad_path = False;
  NTSTATUS nt_status;

  *mask = *directory = *fname = 0;

  /* If we were called as SMBffirst then we must expect close. */
  if(CVAL(inbuf,smb_com) == SMBffirst)
    expect_close = True;
  
  cnum = SVAL(inbuf,smb_tid);

  outsize = set_message(outbuf,1,3,True);
  maxentries = SVAL(inbuf,smb_vwv0); 
  dirtype = SVAL(inbuf,smb_vwv1);
  p = smb_buf(inbuf) + 1;
  p += srvstr_get_path(inbuf, path, p, sizeof(path), 0, STR_TERMINATE, &nt_status, True);
  if (!NT_STATUS_IS_OK(nt_status)) {
		return ERROR_NT(nt_status);
  }

//  path = smb_buf(inbuf) + 1;
  p++;
//  status_len = SVAL(smb_buf(inbuf),3 + strlen(path));
  status_len = SVAL(p, 0);
  p += 2;

  
  /* dirtype &= ~aDIR; */
  
  DEBUG(5,("path=%s status_len=%d\n",path,status_len));

  
  if (status_len == 0)
    {
      pstring dir2;

      pstrcpy(directory,path);
      pstrcpy(dir2,path);
      unix_convert(directory,cnum,0,&bad_path);
      unix_format(dir2);

      if (!check_name(directory,cnum))
        can_open = False;

      p = strrchr_m(dir2,'/');
      if (p == NULL) 
      {
        strcpy(mask,dir2);
        *dir2 = 0;
      }
      else
      {
        *p = 0;
        pstrcpy(mask,p+1);
      }

      p = strrchr_m(directory,'/');
      if (!p) 
        *directory = 0;
      else
        *p = 0;

      if (strlen(directory) == 0)
        strcpy(directory,"./");
      bzero(status,21);
      SCVAL(status, 0, dirtype);
    }
  else
    {
//      memcpy(status,smb_buf(inbuf) + 1 + strlen(path) + 4,21);
      memcpy(status,p,21);
      memcpy(mask,status+1,11);
      mask[11] = 0;
      dirtype = CVAL(status,0) & 0x1F;
      Connections[cnum].dirptr = dptr_fetch(status+12,&dptr_num);      
      if (!Connections[cnum].dirptr)
	goto SearchEmpty;
      string_set(&Connections[cnum].dirpath,dptr_path(dptr_num));
      if (!case_sensitive)
	strnorm(mask);
    }

  /* turn strings of spaces into a . */  
  {
    trim_string(mask,NULL," ");
    if ((p = strrchr_m(mask,' ')))
      {
	fstring ext;
	fstrcpy(ext,p+1);
	*p = 0;
	trim_string(mask,NULL," ");
	strcat(mask,".");
	strcat(mask,ext);
      }
  }

  {
    for (p=mask; *p; p++)
      {
	if (*p != '?' && *p != '*' /*&& !isdoschar(*p)*/)
	  {
	    DEBUG(5,("Invalid char [%c] in search mask?\n",*p));
	    *p = '?';
	  }
      }
  }

  if (!strchr_m(mask,'.') && strlen(mask)>8)
    {
      fstring tmp;
      fstrcpy(tmp,&mask[8]);
      mask[8] = '.';
      mask[9] = 0;
      strcat(mask,tmp);
    }

  DEBUG(5,("mask=%s directory=%s\n",mask,directory));
  
  if (can_open)
    {
      p = smb_buf(outbuf) + 3;
      
      ok = True;
      
      if (status_len == 0)
     {
	  dptr_num = dptr_create(cnum,directory,expect_close,SVAL(inbuf,smb_pid));
	  if (dptr_num < 0)
         {
          	if(dptr_num == -2)
          	{
            		return set_bad_path_error(outbuf, errno, bad_path, ERRDOS, ERRnofids);
          	}
          	return(ERROR_DOS(ERRDOS,ERRnofids));
         }
      }

      DEBUG(4,("dptr_num is %d\n",dptr_num));

      if (ok)
	{
	  if ((dirtype&0x1F) == aVOLID)
	    {	  
	      memcpy(p,status,21);
	      make_dir_struct(p,"???????????",volume_label(SNUM(cnum)),0,aVOLID,0);
	      dptr_fill(p+12,dptr_num);
	      if (dptr_zero(p+12) && (status_len==0))
		numentries = 1;
	      else
		numentries = 0;
	      p += DIR_STRUCT_SIZE;
	    }
	  else 
	    {
	      maxentries = MIN(maxentries, ((BUFFER_SIZE - (p - outbuf))/DIR_STRUCT_SIZE));

	      DEBUG(8,("dirpath=<%s> dontdescend=<%s>\n",Connections[cnum].dirpath,lp_dontdescend(SNUM(cnum))));
	      if (in_list(Connections[cnum].dirpath, lp_dontdescend(SNUM(cnum)),True))
		check_descend = True;

	      for (i=numentries;(i<maxentries) && !finished;i++)
		{
		  finished = 
		    !get_dir_entry(cnum,mask,dirtype,fname,&size,&mode,&date,check_descend);
		  if (!finished)
		    {
		      memcpy(p,status,21);
		      make_dir_struct(p,mask,fname,size,mode,date);
		      dptr_fill(p+12,dptr_num);
		      numentries++;
		    }
		  p += DIR_STRUCT_SIZE;
		}
	    }
	}
    }


 SearchEmpty:

  /* If we were called as SMBffirst with smb_search_id == NULL
     and no entries were found then return error and close dirptr 
     (X/Open spec) */
     
  if (numentries == 0 || !ok)
    {
      dptr_close(dptr_num);
    }else if(ok && expect_close && numentries == 0 && status_len == 0)
    {
      /* Also close the dptr - we know it's gone */
      dptr_close(dptr_num);
    }

  /* If we were called as SMBfunique, then we can close the dirptr now ! */
  if(dptr_num >= 0 && CVAL(inbuf,smb_com) == SMBfunique)
    dptr_close(dptr_num);

  if ((numentries == 0) && !ms_has_wild(mask)) {
		return ERROR_BOTH(STATUS_NO_MORE_FILES,ERRDOS,ERRnofiles);
  }

  SSVAL(outbuf,smb_vwv0,numentries);
  SSVAL(outbuf,smb_vwv1,3 + numentries * DIR_STRUCT_SIZE);
  SCVAL(smb_buf(outbuf),0,5);
  SSVAL(smb_buf(outbuf),1,numentries*DIR_STRUCT_SIZE);

  if (Protocol >= PROTOCOL_NT1) {
    uint16 flg2 = SVAL(outbuf,smb_flg2);
    SSVAL(outbuf,smb_flg2,flg2 | 0x40); /* IS_LONG_NAME */
  }
  
  outsize += DIR_STRUCT_SIZE*numentries;
  smb_setlen(outbuf,outsize - 4);
  
  if ((! *directory) && dptr_path(dptr_num))
    sprintf(directory,"(%s)",dptr_path(dptr_num));

  DEBUG(4,("%s %s mask=%s path=%s cnum=%d dtype=%d nument=%d of %d\n",
	timestring(),
	smb_fn_name(CVAL(inbuf,smb_com)), 
	mask,directory,cnum,dirtype,numentries,maxentries));

  return(outsize);
}


/****************************************************************************
  reply to a fclose (stop directory search)
****************************************************************************/
int reply_fclose(char *inbuf,char *outbuf)
{
  int cnum;
  int outsize = 0;
  int status_len;
  char *path;
  char status[21];
  int dptr_num= -1;

  cnum = SVAL(inbuf,smb_tid);

  outsize = set_message(outbuf,1,0,True);
  path = smb_buf(inbuf) + 1;
  status_len = SVAL(smb_buf(inbuf),3 + strlen(path));

  
  if (status_len == 0)
    return(ERROR_DOS(ERRSRV,ERRsrverror));

  memcpy(status,smb_buf(inbuf) + 1 + strlen(path) + 4,21);

  if(dptr_fetch(status+12,&dptr_num)) {
    /*  Close the dptr - we know it's gone */
    dptr_close(dptr_num);
  }

  SSVAL(outbuf,smb_vwv0,0);

  DEBUG(3,("%s search close cnum=%d\n",timestring(),cnum));

  return(outsize);
}


/****************************************************************************
  reply to an open
****************************************************************************/
int reply_open(char *inbuf,char *outbuf)
{
  pstring fname;
  int cnum;
  int fnum = -1;
  int outsize = 0;
  int fmode=0;
  int share_mode;
  SMB_OFF_T size = 0;
  time_t mtime=0;
  int unixmode;
  int rmode=0;
  SMB_STRUCT_STAT sbuf;
  BOOL bad_path = False;
  files_struct *fsp;
  int oplock_request = CORE_OPLOCK_REQUEST(inbuf);
  NTSTATUS status = NT_STATUS_OK;
 
  cnum = SVAL(inbuf,smb_tid);

  share_mode = SVAL(inbuf,smb_vwv0);

  srvstr_get_path(inbuf, fname, smb_buf(inbuf)+1, sizeof(fname), 0, STR_TERMINATE, &status, False);
  if (!NT_STATUS_IS_OK(status)) {
		return ERROR_NT(status);
  }
  
//  pstrcpy(fname,smb_buf(inbuf)+1);
  unix_convert(fname,cnum,0,&bad_path);
    
  fnum = find_free_file();
  if (fnum < 0)
    return(ERROR_DOS(ERRSRV,ERRnofids));

  if (!check_name(fname,cnum))
  {
     return set_bad_path_error(outbuf, errno, bad_path, ERRDOS, ERRnoaccess);
  }
 
  unixmode = unix_mode(cnum,aARCH);
      
  open_file_shared(fnum,cnum,fname,share_mode,3,unixmode,
                   oplock_request,&rmode,NULL);

  fsp = &Files[fnum];

  if (!fsp->open)
  {
    	return set_bad_path_error(outbuf, errno, bad_path, ERRDOS, ERRnoaccess);
  }

  if (sys_fstat(fsp->fd_ptr->fd,&sbuf) != 0) {
    close_file(fnum,False);
    return(ERROR_DOS(ERRDOS,ERRnoaccess));
  }
    
  size = sbuf.st_size;
  fmode = dos_mode(cnum,fname,&sbuf);
  mtime = sbuf.st_mtime;

  if (fmode & aDIR) {
    DEBUG(3,("attempt to open a directory %s\n",fname));
    close_file(fnum,False);
    return(ERROR_DOS(ERRDOS,ERRnoaccess));
  }
  
  outsize = set_message(outbuf,7,0,True);
  SSVAL(outbuf,smb_vwv0,fnum);
  SSVAL(outbuf,smb_vwv1,fmode);
  put_dos_date3(outbuf,smb_vwv2,mtime);
  SIVAL(outbuf,smb_vwv4,size);
  SSVAL(outbuf,smb_vwv6,rmode);

  if (oplock_request && lp_fake_oplocks(SNUM(cnum))) {
    	SCVAL(outbuf,smb_flg,CVAL(outbuf,smb_flg)|CORE_OPLOCK_GRANTED);
  }
    
  if(fsp->granted_oplock)
    	SCVAL(outbuf,smb_flg,CVAL(outbuf,smb_flg)|CORE_OPLOCK_GRANTED);
  
  return(outsize);
}


/****************************************************************************
  reply to an open and X
****************************************************************************/
int reply_open_and_X(char *inbuf,char *outbuf,int length,int bufsize)
{
  pstring fname;
  NTSTATUS status = NT_STATUS_OK;
  int cnum = SVAL(inbuf,smb_tid);
  int fnum = -1;
  int smb_mode = SVAL(inbuf,smb_vwv3);
  int smb_attr = SVAL(inbuf,smb_vwv5);
  /* Breakout the oplock request bits so we can set the
     reply bits separately. */
  BOOL ex_oplock_request = EXTENDED_OPLOCK_REQUEST(inbuf);
  BOOL core_oplock_request = CORE_OPLOCK_REQUEST(inbuf);
  BOOL oplock_request = ex_oplock_request | core_oplock_request;
#if 0
  int open_flags = SVAL(inbuf,smb_vwv2);
  int smb_sattr = SVAL(inbuf,smb_vwv4); 
  uint32 smb_time = make_unix_date3(inbuf+smb_vwv6);
#endif
  int smb_ofun = SVAL(inbuf,smb_vwv8);
	DEBUG(0,("ofun: 0x%x\n",smb_ofun));
  int unixmode;
  SMB_OFF_T size=0;
  int	fmode=0,mtime=0,rmode=0;
  SMB_STRUCT_STAT sbuf;
  int smb_action = 0;
  BOOL bad_path = False;
  files_struct *fsp;

  /* If it's an IPC, pass off the pipe handler. */
/*
  if (IS_IPC(cnum))
    return reply_open_pipe_and_X(inbuf,outbuf,length,bufsize);
*/

  /* XXXX we need to handle passed times, sattr and flags */
  srvstr_get_path(inbuf, fname, smb_buf(inbuf), sizeof(fname), 0, STR_TERMINATE, &status, False);
  if (!NT_STATUS_IS_OK(status)) {
		return ERROR_NT(status);
  }

//  pstrcpy(fname,smb_buf(inbuf));
  
  DEBUG(0,("file name 0: %s\n", fname));
  
  unix_convert(fname,cnum,0,&bad_path);

#if 0
//to speedup, no need to open a dir, correct???
  struct stat buf;
  stat(fname, &buf);
  if(S_ISDIR(buf.st_mode)){
	DEBUG(0,("no need to open a dir!\n"));
	return(ERROR(ERRDOS,ERRcannotopen));
  }
#endif
    
  fnum = find_free_file();
  if (fnum < 0)
    return(ERROR_DOS(ERRSRV,ERRnofids));

  if (!check_name(fname,cnum))
  {
	return set_bad_path_error(outbuf, errno, bad_path, ERRDOS, ERRnoaccess);  
  }

  unixmode = unix_mode(cnum,smb_attr | aARCH);
      
  open_file_shared(fnum,cnum,fname,smb_mode,smb_ofun,unixmode,
		   oplock_request, &rmode,&smb_action);
      
  fsp = &Files[fnum];

  if (!fsp->open)
  {
    	return set_bad_path_error(outbuf, errno, bad_path, ERRDOS, ERRnoaccess);
  }

  if (sys_fstat(fsp->fd_ptr->fd,&sbuf) != 0) {
    close_file(fnum,False);
    return(ERROR_DOS(ERRDOS,ERRnoaccess));
  }

  size = sbuf.st_size;
  fmode = dos_mode(cnum,fname,&sbuf);
  mtime = sbuf.st_mtime;
  if (fmode & aDIR) {
    close_file(fnum,False);
    return(ERROR_DOS(ERRDOS,ERRnoaccess));
  }

  /* If the caller set the extended oplock request bit
     and we granted one (by whatever means) - set the
     correct bit for extended oplock reply.
   */

  if (ex_oplock_request && lp_fake_oplocks(SNUM(cnum))) {
    smb_action |= EXTENDED_OPLOCK_GRANTED;
  }

  if(ex_oplock_request && fsp->granted_oplock) {
    smb_action |= EXTENDED_OPLOCK_GRANTED;
  }

  /* If the caller set the core oplock request bit
     and we granted one (by whatever means) - set the
     correct bit for core oplock reply.
   */

  if (core_oplock_request && lp_fake_oplocks(SNUM(cnum))) {
    	SCVAL(outbuf,smb_flg,CVAL(outbuf,smb_flg)|CORE_OPLOCK_GRANTED);
  }

  if(core_oplock_request && fsp->granted_oplock) {
    	SCVAL(outbuf,smb_flg,CVAL(outbuf,smb_flg)|CORE_OPLOCK_GRANTED);
  }

  set_message(outbuf,15,0,True);
  SSVAL(outbuf,smb_vwv2,fnum);
  SSVAL(outbuf,smb_vwv3,fmode);
  put_dos_date3(outbuf,smb_vwv4,mtime);
  SIVAL(outbuf,smb_vwv6,size);
  SSVAL(outbuf,smb_vwv8,rmode);
  SSVAL(outbuf,smb_vwv11,smb_action);

  chain_fnum = fnum;

  return chain_reply(inbuf,outbuf,length,bufsize);
}


/****************************************************************************
  reply to a SMBulogoffX
****************************************************************************/
int reply_ulogoffX(char *inbuf,char *outbuf,int length,int bufsize)
{
  uint16 vuid = SVAL(inbuf,smb_uid);
  user_struct *vuser = get_valid_user_struct(vuid);

  if(vuser == 0) {
    DEBUG(3,("ulogoff, vuser id %d does not map to user.\n", vuid));
  }

  /* in user level security we are supposed to close any files
     open by this user */
  if ((vuser != 0) && (lp_security() != SEC_SHARE)) {
    int i;
    for (i=0;i<MAX_OPEN_FILES;i++)
      if (Files[i].uid == vuser->uid && Files[i].open) {
	close_file(i,False);
      }
  }

  invalidate_vuid(vuid);

  set_message(outbuf,2,0,True);

  DEBUG(3,("%s ulogoffX vuid=%d\n",timestring(),vuid));

  return chain_reply(inbuf,outbuf,length,bufsize);
}


/****************************************************************************
  reply to a mknew or a create
****************************************************************************/
int reply_mknew(char *inbuf,char *outbuf)
{
  pstring fname;
  int cnum,com;
  int fnum = -1;
  int outsize = 0;
  int createmode;
  mode_t unixmode;
  int ofun = 0;
  BOOL bad_path = False;
  files_struct *fsp;
  int oplock_request = CORE_OPLOCK_REQUEST(inbuf);
  NTSTATUS status;
 
  com = SVAL(inbuf,smb_com);
  cnum = SVAL(inbuf,smb_tid);

  createmode = SVAL(inbuf,smb_vwv0);
  //pstrcpy(fname,smb_buf(inbuf)+1);
  srvstr_get_path(inbuf, fname, smb_buf(inbuf) + 1, sizeof(fname), 0, STR_TERMINATE, &status, False);
  if (!NT_STATUS_IS_OK(status)) {
		return ERROR_NT(status);
  }

  unix_convert(fname,cnum,0,&bad_path);

  if (createmode & aVOLID)
    {
      DEBUG(0,("Attempt to create file (%s) with volid set - please report this\n",fname));
    }
  
  unixmode = unix_mode(cnum,createmode);
  
  fnum = find_free_file();
  if (fnum < 0)
    return(ERROR_DOS(ERRSRV,ERRnofids));

  if (!check_name(fname,cnum))
  {
    	return set_bad_path_error(outbuf, errno, bad_path, ERRDOS, ERRnoaccess);
  }

  if(com == SMBmknew)
  {
    /* We should fail if file exists. */
    ofun = 0x10;
  }
  else
  {
    /* SMBcreate - Create if file doesn't exist, truncate if it does. */
    ofun = 0x12;
  }

  /* Open file in dos compatibility share mode. */
  open_file_shared(fnum,cnum,fname,(DENY_FCB<<4)|0xF, ofun, unixmode, 
                   oplock_request, NULL, NULL);
  
  fsp = &Files[fnum];

  if (!fsp->open)
  {
    	return set_bad_path_error(outbuf, errno, bad_path, ERRDOS, ERRnoaccess);
  }
 
  outsize = set_message(outbuf,1,0,True);
  SSVAL(outbuf,smb_vwv0,fnum);

  if (oplock_request && lp_fake_oplocks(SNUM(cnum))) {
    SCVAL(outbuf,smb_flg,CVAL(outbuf,smb_flg)|CORE_OPLOCK_GRANTED);
  }
 
  if(fsp->granted_oplock)
    SCVAL(outbuf,smb_flg,CVAL(outbuf,smb_flg)|CORE_OPLOCK_GRANTED);
 
  DEBUG(2,("new file %s\n",fname));
  DEBUG(3,("%s mknew %s fd=%d fnum=%d cnum=%d dmode=%d umode=%o\n",timestring(),fname,Files[fnum].fd_ptr->fd,fnum,cnum,createmode,unixmode));
  
  return(outsize);
}


/****************************************************************************
  reply to a create temporary file
****************************************************************************/
int reply_ctemp(char *inbuf,char *outbuf)
{
  pstring fname;
  pstring fname2;
  int cnum;
  int fnum = -1;
  int outsize = 0;
  int createmode;
  mode_t unixmode;
  BOOL bad_path = False;
  files_struct *fsp;
  int oplock_request = CORE_OPLOCK_REQUEST(inbuf);
  NTSTATUS status;
  char *p, *s;
 
  cnum = SVAL(inbuf,smb_tid);
  createmode = SVAL(inbuf,smb_vwv0);
//  pstrcpy(fname,smb_buf(inbuf)+1);
  srvstr_get_path(inbuf, fname, smb_buf(inbuf)+1, sizeof(fname), 0, STR_TERMINATE, &status, False);
  if (!NT_STATUS_IS_OK(status)) {
		return ERROR_NT(status);
  }

  if (*fname) {
		strcat(fname,"/TMXXXXXX");
  } else {
		strcat(fname,"TMXXXXXX");
  }
  
  unix_convert(fname,cnum,0,&bad_path);
  
  unixmode = unix_mode(cnum,createmode);
  
  fnum = find_free_file();
  if (fnum < 0)
    return(ERROR_DOS(ERRSRV,ERRnofids));

  if (!check_name(fname,cnum))
  {
    	return set_bad_path_error(outbuf, errno, bad_path, ERRDOS, ERRnoaccess);
  }

  strcpy(fname2,(char *)mktemp(fname));	//we will be in trouble if mktemp does not work

  /* Open file in dos compatibility share mode. */
  /* We should fail if file exists. */
  open_file_shared(fnum,cnum,fname2,(DENY_FCB<<4)|0xF, 0x10, unixmode, 
                   oplock_request, NULL, NULL);

  fsp = &Files[fnum];

  if (!fsp->open)
  {
    	return set_bad_path_error(outbuf, errno, bad_path, ERRDOS, ERRnoaccess);
  }

/*
  outsize = set_message(outbuf,1,2 + strlen(fname2),True);
  SSVAL(outbuf,smb_vwv0,fnum);
  SCVAL(smb_buf(outbuf),0,4);
  strcpy(smb_buf(outbuf) + 1,fname2);
*/

	outsize = set_message(outbuf,1,0,True);
	SSVAL(outbuf,smb_vwv0,fnum);

	/* the returned filename is relative to the directory */
	s = strrchr_m(fname2, '/');
	if (!s)
		s = fname2;
	else
		s++;
	
  	p = smb_buf(outbuf);
	unsigned int namelen = srvstr_push(outbuf, p, s, -1, STR_ASCII|STR_TERMINATE);
	p += namelen;
	outsize = set_message_end(outbuf, p);

  if (oplock_request && lp_fake_oplocks(SNUM(cnum))) {
    SCVAL(outbuf,smb_flg,CVAL(outbuf,smb_flg)|CORE_OPLOCK_GRANTED);
  }
  
  if(fsp->granted_oplock)
    SCVAL(outbuf,smb_flg,CVAL(outbuf,smb_flg)|CORE_OPLOCK_GRANTED);

  DEBUG(2,("created temp file %s\n",fname2));
  DEBUG(3,("%s ctemp %s fd=%d fnum=%d cnum=%d dmode=%d umode=%o\n",timestring(),fname2,Files[fnum].fd_ptr->fd,fnum,cnum,createmode,unixmode));
  
  return(outsize);
}


/*******************************************************************
check if a user is allowed to delete a file
********************************************************************/
BOOL can_delete(char *fname,int cnum,int dirtype)
{
  SMB_STRUCT_STAT sbuf;
  int fmode;

  if (!CAN_WRITE(cnum)) 
  	return(False);

  if (sys_lstat(fname,&sbuf) != 0) 
  	return(False);
  
  fmode = dos_mode(cnum,fname,&sbuf);
  
  if (fmode & aDIR) 
  	return(False);
  
  if (!lp_delete_readonly(SNUM(cnum))) {
    if (fmode & aRONLY) 
		return(False);
  }
  
  if ((fmode & ~dirtype) & (aHIDDEN | aSYSTEM))
    return(False);
  
  if (!check_file_sharing(cnum,fname)) 
  	return(False);

  return(True);
}

/****************************************************************************
  reply to a unlink
****************************************************************************/
int reply_unlink(char *inbuf,char *outbuf)
{
  int outsize = 0;
  pstring name;
  int cnum;
  int dirtype;
  pstring directory;
  pstring mask;
  char *p;
  int count=0;
  int error = ERRnoaccess;
  BOOL has_wild;
  BOOL exists=False;
  BOOL bad_path = False;
  NTSTATUS status = NT_STATUS_OK;

  *directory = *mask = 0;

  cnum = SVAL(inbuf,smb_tid);
  dirtype = SVAL(inbuf,smb_vwv0);
  
//  pstrcpy(name,smb_buf(inbuf) + 1);
  srvstr_get_path(inbuf, name, smb_buf(inbuf) + 1, sizeof(name), 0, STR_TERMINATE, &status, True);
  if (!NT_STATUS_IS_OK(status)) {
		return ERROR_NT(status);
  }
   
  DEBUG(3,("reply_unlink : %s\n",name));
   
  BOOL cr = unix_convert(name,cnum,0,&bad_path);

  p = strrchr_m(name,'/');
  if (!p) {
    strcpy(directory,"./");
    strcpy(mask,name);
  } else {
    *p = 0;
    strcpy(directory,name);
    strcpy(mask,p+1);
  }

#ifdef USE_83_NAME
  if (!cr && is_mangled(mask))
    	check_mangled_stack(mask);
#endif

  /* We must check for wildcards in the name given
	 * directly by the client - before any unmangling.
	 * This prevents an unmangling of a UNIX name containing
	 * a DOS wildcard like '*' or '?' from unmangling into
	 * a wildcard delete which was not intended.
	 * FIX for #226. JRA.
  */

  has_wild = ms_has_wild(name);


  if (!has_wild) {
    strcat(directory,"/");
    strcat(directory,mask);

    if(!can_delete(directory,cnum,dirtype))
		return(UNIXERROR(ERRDOS,ERRnoaccess));
	
    if (!sys_unlink(directory)) 
		count++;
    if (!count) 
		exists = file_exist(directory,NULL);    
  } else {
    void *dirptr = NULL;
    char *dname;

    if (check_name(directory,cnum))
      dirptr = OpenDir(cnum, directory, True);

    /* XXXX the CIFS spec says that if bit0 of the flags2 field is set then
       the pattern matches against the long name, otherwise the short name 
       We don't implement this yet XXXX
       */

    if (dirptr)
      {
	error = ERRbadfile;

	if (strequal(mask,"????????.???"))
	  strcpy(mask,"*");

	while ((dname = ReadDirName(dirptr)))
	  {
	    pstring fname;
	    pstrcpy(fname,dname);
	    
	    if(!mask_match(fname, mask, case_sensitive, False)) 
			continue;

	    error = ERRnoaccess;
	    sprintf(fname,"%s/%s",directory,dname);
	    if (!can_delete(fname,cnum,dirtype)) 
			continue;
	    if (!sys_unlink(fname)) 
			count++;
	    DEBUG(3,("reply_unlink : doing unlink on %s\n",fname));
	  }
	CloseDir(dirptr);
      }
  }
  
  if (count == 0) {
    if (exists)
      return(ERROR_DOS(ERRDOS,error));
    else
    {
      if(errno == ENOENT) {
	if (bad_path) {
		return ERROR_NT(NT_STATUS_OBJECT_PATH_NOT_FOUND);
	} else {
		return ERROR_NT(NT_STATUS_OBJECT_NAME_NOT_FOUND);
	}
    }
      return(UNIXERROR(ERRDOS,error));
    }
  }
  
  outsize = set_message(outbuf,0,0,True);
  
  return(outsize);
}


/****************************************************************************
   reply to a readbraw (core+ protocol)
****************************************************************************/
int reply_readbraw(char *inbuf, char *outbuf)
{
  int cnum,fnum;
  ssize_t maxcount,mincount;
  size_t nread = 0;
  SMB_OFF_T startpos;
  char *header = outbuf;
  ssize_t ret=0;
  int fd;
  char *fname;

  /*
   * Special check if an oplock break has been issued
   * and the readraw request croses on the wire, we must
   * return a zero length response here.
   */

#ifdef OPLOCK_ENABLE
  if(global_oplock_break)
  {
    _smb_setlen(header,0);
    transfer_file(0,Client,0,header,4,0);
    DEBUG(5,("readbraw - oplock break finished\n"));
    return -1;
  }
#endif

  cnum = SVAL(inbuf,smb_tid);
  fnum = GETFNUM(inbuf,smb_vwv0);

  startpos = IVAL_TO_SMB_OFF_T(inbuf,smb_vwv1);
  if(CVAL(inbuf,smb_wct) == 10) {
  	/*
		 * This is a large offset (64 bit) read.
		 */
#ifdef LARGE_FILE_SUPPORT

		startpos |= (((SMB_OFF_T)IVAL(inbuf,smb_vwv8)) << 32);

#else
		/*
		 * This is a large offset (64 bit) read.
		 * Ensure we haven't been sent a >32 bit offset.
		 */

		if(IVAL(inbuf,smb_vwv8) != 0) {
			DEBUG(0,("readbraw - large offset (%x << 32) used and we don't support \
64 bit offsets.\n", (unsigned int)IVAL(inbuf,smb_vwv8) ));
			_smb_setlen(header,0);
			if (write_data(Client,header,4) != 4)
				exit_server("reply_readbraw: socket write fail");
			return(-1);
		}
#endif

		if(startpos < 0) {
			DEBUG(0,("readbraw - negative 64 bit readraw offset (%.0f) !\n", (double)startpos ));
			_smb_setlen(header,0);
			if (write_data(Client,header,4) != 4)
				exit_server("reply_readbraw: socket write fail");
			return(-1);
		}      
  }
  
  maxcount = SVAL(inbuf,smb_vwv3);
  mincount = SVAL(inbuf,smb_vwv4);

  /* ensure we don't overrun the packet size */
  maxcount = MIN(65535,maxcount);
  maxcount = MAX(mincount,maxcount);

  if (!FNUM_OK(fnum,cnum) || !Files[fnum].can_read)
    {
      DEBUG(3,("fnum %d not open in readbraw - cache prime?\n",fnum));
      _smb_setlen(header,0);
      transfer_file(0,Client,0,header,4,0);
      return(-1);
    }
  else
    {
      fd = Files[fnum].fd_ptr->fd;
      fname = Files[fnum].name;
    }


  if (!is_locked(fnum,cnum,(SMB_OFF_T)maxcount,startpos))
    {
      SMB_OFF_T size = Files[fnum].size;
      SMB_OFF_T sizeneeded = startpos + maxcount;
	    
      if (size < sizeneeded) {
	SMB_STRUCT_STAT st;
	if (sys_fstat(Files[fnum].fd_ptr->fd,&st) == 0)
	  size = st.st_size;
	if (!Files[fnum].can_write) 
	  Files[fnum].size = size;
      }

     if (startpos >= size)
	nread = 0;
     else
	nread = MIN(maxcount,(size - startpos));	  
    }
  
#if UNSAFE_READRAW
  {
    size_t predict=0;
    _smb_setlen(header,nread);

#if 0
#if USE_READ_PREDICTION
    if (!Files[fnum].can_write)
      predict = read_predict(fd,startpos,header+4,NULL,nread);
#endif
#endif

    if ((nread-predict) > 0)
      seek_file(fnum,startpos + predict);
    
    ret = transfer_file(fd,Client,nread-predict,header,4+predict,
			startpos+predict);
  }

  if (ret != nread+4)
    DEBUG(0,("ERROR: file read failure on %s at %d for %d bytes (%d)\n",
	     fname,startpos,nread,ret));

#else
  ret = read_file(fnum,header+4,startpos,nread);
  if (ret < mincount) ret = 0;

  _smb_setlen(header,ret);
  transfer_file(0,Client,0,header,4+ret,0);
#endif

  DEBUG(5,("readbraw finished\n"));
  return -1;
}


/****************************************************************************
  reply to a lockread (core+ protocol)
****************************************************************************/
int reply_lockread(char *inbuf,char *outbuf)
{
  int cnum,fnum;
  ssize_t nread = -1;
  char *data;
  int outsize = 0;
  SMB_OFF_T startpos;
  size_t numtoread;
  int eclass;
  uint32 ecode;
  
  cnum = SVAL(inbuf,smb_tid);
  fnum = GETFNUM(inbuf,smb_vwv0);

  CHECK_FNUM(fnum,cnum);
  CHECK_READ(fnum);
  CHECK_ERROR(fnum);

  numtoread = SVAL(inbuf,smb_vwv1);
  startpos = IVAL_TO_SMB_OFF_T(inbuf,smb_vwv2);
  
  outsize = set_message(outbuf,5,3,True);
  numtoread = MIN(BUFFER_SIZE-outsize,numtoread);
  data = smb_buf(outbuf) + 3;
  
  if(!do_lock( fnum, cnum, numtoread, startpos, &eclass, &ecode))
    return (ERROR_DOS(eclass,ecode));

  nread = read_file(fnum,data,startpos,numtoread);
  
  if (nread < 0)
    return(UNIXERROR(ERRDOS,ERRnoaccess));
  
  outsize += nread;
  SSVAL(outbuf,smb_vwv0,nread);
  SSVAL(outbuf,smb_vwv5,nread+3);
  SSVAL(smb_buf(outbuf),1,nread);
  
  DEBUG(3,("%s lockread fnum=%d cnum=%d num=%d nread=%d\n",timestring(),fnum,cnum,numtoread,nread));
  
  return(outsize);
}


/****************************************************************************
  reply to a read
****************************************************************************/
int reply_read(char *inbuf,char *outbuf)
{
  int cnum,fnum;
  size_t numtoread;
  ssize_t nread = 0;
  char *data;
  SMB_OFF_T startpos;
  int outsize = 0;
  
  cnum = SVAL(inbuf,smb_tid);
  fnum = GETFNUM(inbuf,smb_vwv0);

  CHECK_FNUM(fnum,cnum);
  CHECK_READ(fnum);
  CHECK_ERROR(fnum);

  numtoread = SVAL(inbuf,smb_vwv1);
  startpos = IVAL_TO_SMB_OFF_T(inbuf,smb_vwv2);
  
  outsize = set_message(outbuf,5,3,True);
  numtoread = MIN(BUFFER_SIZE-outsize,numtoread);
  data = smb_buf(outbuf) + 3;
  
  if (is_locked(fnum,cnum,numtoread,startpos))
    return(ERROR_DOS(ERRDOS,ERRlock));	

  if (numtoread > 0)
    nread = read_file(fnum,data,startpos,numtoread);
  
  if (nread < 0)
    return(UNIXERROR(ERRDOS,ERRnoaccess));
  
  outsize += nread;
  SSVAL(outbuf,smb_vwv0,nread);
  SSVAL(outbuf,smb_vwv5,nread+3);
  SCVAL(smb_buf(outbuf),0, 1);
  SSVAL(smb_buf(outbuf),1,nread);
  
  DEBUG(3,("%s read fnum=%d cnum=%d num=%d nread=%d\n",timestring(),fnum,cnum,numtoread,nread));
  
  return(outsize);
}


/****************************************************************************
  reply to a read and X
****************************************************************************/
static ssize_t fake_sendfile(int fnum, SMB_OFF_T startpos, size_t nread, char *buf)
{
	ssize_t ret=0;

	if (nread > 0) {
		ret = read_file(fnum,buf,startpos,nread);
		if (ret == -1) {
			return -1;
		}
	}

	/* If we had a short read, fill with zeros. */
	if (ret < nread) {
		memset(buf, '\0', nread - ret);
	}

	if (write_data(Client,buf,nread) != nread) {
		return -1;
	}	

	return (ssize_t)nread;
}

int reply_read_and_X(char *inbuf,char *outbuf,int length,int bufsize)
{
  int fnum = GETFNUM(inbuf,smb_vwv2);
  SMB_OFF_T smb_offs = IVAL_TO_SMB_OFF_T(inbuf,smb_vwv3);
  size_t smb_maxcnt = SVAL(inbuf,smb_vwv5);
//  int smb_mincnt = SVAL(inbuf,smb_vwv6);
  int cnum;
  ssize_t nread = -1;
  char *data;
  BOOL ok = False;

  cnum = SVAL(inbuf,smb_tid);

  CHECK_FNUM(fnum,cnum);
  CHECK_READ(fnum);
  CHECK_ERROR(fnum);

  set_message(outbuf,12,0,True);

  if (global_client_caps & CAP_LARGE_READX) {
		if (SVAL(inbuf,smb_vwv7) == 1) {
			smb_maxcnt |= (1<<16);
		}
		if (smb_maxcnt > BUFFER_SIZE) {
			DEBUG(0,("reply_read_and_X - read too large (%u) for reply buffer %u\n",
				(unsigned int)smb_maxcnt, (unsigned int)BUFFER_SIZE));
			return ERROR_NT(NT_STATUS_INVALID_PARAMETER);
		}
  }

  if(CVAL(inbuf,smb_wct) == 12) {
#ifdef LARGE_FILE_SUPPORT
		/*
		 * This is a large offset (64 bit) read.
		 */
		smb_offs |= (((SMB_OFF_T)IVAL(inbuf,smb_vwv10)) << 32);

#else 
		/*
		 * This is a large offset (64 bit) read.
		 * Ensure we haven't been sent a >32 bit offset.
		 */

		if(IVAL(inbuf,smb_vwv10) != 0) {
			return ERROR_DOS(ERRDOS,ERRbadaccess);
		}
#endif
  }
  
  data = smb_buf(outbuf);

  if (is_locked(fnum,cnum,smb_maxcnt,smb_offs))
    return(ERROR_DOS(ERRDOS,ERRlock));

/*  here we try to use sendfile() function to improve performace on non-chained packages, seems to work fine
  *  Can not use sendfile for the platform below WIN9X!!!
*/
	if((Protocol < PROTOCOL_NT1) || get_remote_arch() == RA_WIN95)
		USING_SENDFILE = False;

	if (chain_size ==0 && (CVAL(inbuf,smb_vwv0) == 0xFF) && USING_SENDFILE ){
		SMB_STRUCT_STAT sbuf;
		DATA_HEAD head;

		if(sys_fstat(Files[fnum].fd_ptr->fd, &sbuf) == -1)
			return(UNIXERROR(ERRDOS,ERRnoaccess));

		if (smb_offs > sbuf.st_size)
			goto normal_read;

		if (smb_maxcnt > (sbuf.st_size - smb_offs))
			smb_maxcnt = (sbuf.st_size - smb_offs);

		if (smb_maxcnt == 0)
			goto normal_read;

		/* 
		 * Set up the packet header before send. We
		 * assume here the sendfile will work (get the
		 * correct amount of data).
		 */

		SSVAL(outbuf,smb_vwv2,0xFFFF); /* Remaining - must be -1. */
		SSVAL(outbuf,smb_vwv5,smb_maxcnt);
		SSVAL(outbuf,smb_vwv6,smb_offset(data,outbuf));
		SSVAL(outbuf,smb_vwv7,((smb_maxcnt >> 16) & 1));
		SSVAL(smb_buf(outbuf),-2,smb_maxcnt);
		SCVAL(outbuf,smb_vwv0,0xFF);
		set_message(outbuf,12,smb_maxcnt,False);
		head.data = outbuf;
		head.length = data - outbuf;

		if ((nread = sendfile_wrapper( Client, Files[fnum].fd_ptr->fd, &head, smb_offs, smb_maxcnt)) == -1){
			USING_SENDFILE = False;	//having problems with sendfile function? donot use it then....
			DEBUG(0,("send_file_readX: sendfile not available. Faking..\n"));
			
			if (errno == ENOSYS) {
				goto normal_read;
			}

			if (errno == EINTR) {
				if ((nread = fake_sendfile(fnum, smb_offs, smb_maxcnt, data)) == -1){
					DEBUG(0,("fucked up......\n"));
					exit_server("send_file_readX: fake_sendfile failed");
				} 
				//-1 indicates we are done in fake_sendfile
				return -1;
			}
			
			DEBUG(0,("fucked up 0.....\n"));
			exit_server("send_file_readX sendfile failed");
		}

		DEBUG(0,("done with sendfile!\n"));
		return -1;
	}
	
 normal_read:
  
  nread = read_file(fnum,data,smb_offs,smb_maxcnt);
  ok = True;
  
  if (nread < 0)
    return(UNIXERROR(ERRDOS,ERRnoaccess));
  
  SSVAL(outbuf,smb_vwv2,0xFFFF); /* Remaining - must be -1. */
  SSVAL(outbuf,smb_vwv5,nread);
  SSVAL(outbuf,smb_vwv6,smb_offset(data,outbuf));
  SSVAL(outbuf,smb_vwv7,((nread >> 16) & 1));
  SSVAL(smb_buf(outbuf),-2,nread);
  
  DEBUG(3,("%s readX fnum=%d cnum=%d max=%d nread=%d\n",
	timestring(),fnum,cnum,
	smb_maxcnt,nread));

  chain_fnum = fnum;

  return chain_reply(inbuf,outbuf,length,bufsize);
}


/****************************************************************************
  reply to a writebraw (core+ or LANMAN1.0 protocol)
****************************************************************************/
int reply_writebraw(char *inbuf,char *outbuf)
{
  ssize_t nwritten=0;
  ssize_t total_written=0;
  size_t numtowrite=0;
  int cnum,fnum;
  int outsize = 0;
  SMB_OFF_T startpos;
  char *data=NULL;
  BOOL write_through;
  int tcount;

  cnum = SVAL(inbuf,smb_tid);
  fnum = GETFNUM(inbuf,smb_vwv0);

  CHECK_FNUM(fnum,cnum);
  CHECK_WRITE(fnum);
  CHECK_ERROR(fnum);
  
  tcount = IVAL(inbuf,smb_vwv1);
  startpos = IVAL_TO_SMB_OFF_T(inbuf,smb_vwv3);
  write_through = BITSETW(inbuf+smb_vwv7,0);

  /* We have to deal with slightly different formats depending
     on whether we are using the core+ or lanman1.0 protocol */
  if(Protocol <= PROTOCOL_COREPLUS) {
    numtowrite = SVAL(smb_buf(inbuf),-2);
    data = smb_buf(inbuf);
  } else {
    numtowrite = SVAL(inbuf,smb_vwv10);
    data = smb_base(inbuf) + SVAL(inbuf, smb_vwv11);
  }

  /* force the error type */
  SCVAL(inbuf,smb_com, SMBwritec);
  SCVAL(outbuf,smb_com, SMBwritec);

  if (is_locked(fnum,cnum,tcount,startpos))
    return(ERROR_DOS(ERRDOS,ERRlock));

//  if (seek_file(fnum,startpos) != startpos)
//    DEBUG(0,("couldn't seek to %d in writebraw\n",startpos));

  if (numtowrite>0)
    nwritten = new_write_file(fnum,data,numtowrite,startpos);
  
  DEBUG(3,("%s writebraw1 fnum=%d cnum=%d start=%d num=%d wrote=%d sync=%d\n",
	   timestring(),fnum,cnum,startpos,numtowrite,nwritten,write_through));

  if (nwritten < numtowrite) 
    return(UNIXERROR(ERRHRD,ERRdiskfull));

  total_written = nwritten;

  /* Return a message to the redirector to tell it
     to send more bytes */
  SCVAL(outbuf,smb_com, SMBwritebraw);
  SSVALS(outbuf,smb_vwv0,-1);
  outsize = set_message(outbuf,Protocol>PROTOCOL_COREPLUS?1:0,0,True);
  send_smb(Client,outbuf);
  
  /* Now read the raw data into the buffer and write it */
  if (read_smb_length(Client,inbuf,SMB_SECONDARY_WAIT) == -1) {
    exit_server("secondary writebraw failed");
  }
  
  /* Even though this is not an smb message, smb_len
     returns the generic length of an smb message */
  numtowrite = smb_len(inbuf);

  if (tcount > nwritten+numtowrite) {
    DEBUG(3,("Client overestimated the write %d %d %d\n",
	     tcount,nwritten,numtowrite));
  }

  nwritten = transfer_file(Client,Files[fnum].fd_ptr->fd,numtowrite,NULL,0,
			   startpos+nwritten);
  total_written += nwritten;
  
  /* Set up outbuf to return the correct return */
  outsize = set_message(outbuf,1,0,True);
  SCVAL(outbuf,smb_com, SMBwritec);
  SSVAL(outbuf,smb_vwv0,total_written);

  if (nwritten < numtowrite) {
    SCVAL(outbuf,smb_rcls, ERRHRD);
    SSVAL(outbuf,smb_err,ERRdiskfull);      
  }

  if (write_through)
    sync_file(fnum);

  DEBUG(3,("%s writebraw2 fnum=%d cnum=%d start=%d num=%d wrote=%d\n",
	   timestring(),fnum,cnum,startpos,numtowrite,total_written));

  /* we won't return a status if write through is not selected - this 
     follows what WfWg does */
  if (!write_through && total_written==tcount)
    return(-1);

  return(outsize);
}


/****************************************************************************
  reply to a writeunlock (core+)
****************************************************************************/
int reply_writeunlock(char *inbuf,char *outbuf)
{
  int cnum,fnum;
  ssize_t nwritten = -1;
  int outsize = 0;
  char *data;
  SMB_OFF_T startpos;
  size_t numtowrite;
  int eclass;
  uint32 ecode;
  
  cnum = SVAL(inbuf,smb_tid);
  fnum = GETFNUM(inbuf,smb_vwv0);

  CHECK_FNUM(fnum,cnum);
  CHECK_WRITE(fnum);
  CHECK_ERROR(fnum);

  numtowrite = SVAL(inbuf,smb_vwv1);
  startpos = IVAL_TO_SMB_OFF_T(inbuf,smb_vwv2);
  data = smb_buf(inbuf) + 3;
  
  if (is_locked(fnum,cnum,numtowrite,startpos))
    return(ERROR_DOS(ERRDOS,ERRlock));

//  seek_file(fnum,startpos);

  /* The special X/Open SMB protocol handling of
     zero length writes is *NOT* done for
     this call */
  if(numtowrite == 0)
    nwritten = 0;
  else
    nwritten = new_write_file(fnum,data,numtowrite,startpos);

  if(((nwritten == 0) && (numtowrite != 0))||(nwritten < 0))
    return(UNIXERROR(ERRDOS,ERRnoaccess));

  if(!do_unlock(fnum, cnum, numtowrite, startpos, &eclass, &ecode))
    return(ERROR_DOS(eclass,ecode));

  outsize = set_message(outbuf,1,0,True);
  
  SSVAL(outbuf,smb_vwv0,nwritten);
  
  DEBUG(3,("%s writeunlock fnum=%d cnum=%d num=%d wrote=%d\n",
	   timestring(),fnum,cnum,numtowrite,nwritten));
  
  return(outsize);
}


/****************************************************************************
  reply to a write
****************************************************************************/
int reply_write(char *inbuf,char *outbuf,int dum1,int dum2)
{
  DEBUG(0,("========>%s\n", __FUNCTION__));
  
  int cnum,fnum;
  size_t numtowrite;
  ssize_t nwritten = -1;
  int outsize = 0;
  SMB_OFF_T startpos;
  char *data;

  dum1 = dum2 = 0;
  cnum = SVAL(inbuf,smb_tid);

/*
  if (IS_IPC(cnum)) {
		return reply_pipe_write(inbuf,outbuf,dum1,dum2);
  }
*/   
  fnum = GETFNUM(inbuf,smb_vwv0);

  CHECK_FNUM(fnum,cnum);
  CHECK_WRITE(fnum);
  CHECK_ERROR(fnum);

  numtowrite = SVAL(inbuf,smb_vwv1);
  startpos = IVAL_TO_SMB_OFF_T(inbuf,smb_vwv2);
  data = smb_buf(inbuf) + 3;
  
  if (is_locked(fnum,cnum,numtowrite,startpos))
    return(ERROR_DOS(ERRDOS,ERRlock));

//  seek_file(fnum,startpos);	//move this action into write for performance improvement...

  /* X/Open SMB protocol says that if smb_vwv1 is
     zero then the file size should be extended or
     truncated to the size given in smb_vwv[2-3] */
  if(numtowrite == 0){
  	nwritten = set_filelen(Files[fnum].fd_ptr->fd, startpos);
    	if(nwritten == -1){
		DEBUG(0,("%s disk full?(%d:%s)\n", __FUNCTION__, __LINE__, strerror(errno)));
		return(ERROR_DOS(ERRHRD,ERRdiskfull));
    	}
  }
  else
    nwritten = new_write_file(fnum,data,numtowrite,startpos);	//use new write_file function a.m.a.p!

  if(((nwritten == 0) && (numtowrite != 0))||(nwritten < 0)){
  	DEBUG(0,("%s disk full?(%d:%s)\n", __FUNCTION__, __LINE__, strerror(errno)));
    	return(UNIXERROR(ERRHRD,ERRdiskfull));
  }

  outsize = set_message(outbuf,1,0,True);
  
  SSVAL(outbuf,smb_vwv0,nwritten);

  if (nwritten < numtowrite) {
    SCVAL(outbuf,smb_rcls, ERRHRD);
    SSVAL(outbuf,smb_err,ERRdiskfull);      
  }
  
  DEBUG(3,("%s write fnum=%d cnum=%d num=%d wrote=%d\n",timestring(),fnum,cnum,numtowrite,nwritten));
  
  return(outsize);
}


/****************************************************************************
  reply to a write and X
****************************************************************************/
int reply_write_and_X(char *inbuf,char *outbuf,int length,int bufsize)
{
  int fnum = GETFNUM(inbuf,smb_vwv2);
  SMB_OFF_T smb_offs = IVAL_TO_SMB_OFF_T(inbuf,smb_vwv3);
  size_t smb_dsize = SVAL(inbuf,smb_vwv10);
  unsigned int smb_doff = SVAL(inbuf,smb_vwv11);
  unsigned int smblen = smb_len(inbuf);
  BOOL write_through = BITSETW(inbuf+smb_vwv7,0);
  int cnum;
  ssize_t nwritten = -1;
  char *data;
  BOOL large_writeX = ((CVAL(inbuf,smb_wct) == 14) && (smblen > 0xFFFF));

  cnum = SVAL(inbuf,smb_tid);

  CHECK_FNUM(fnum,cnum);
  CHECK_WRITE(fnum);
  CHECK_ERROR(fnum);

  if (large_writeX)
	smb_dsize |= ((((size_t)SVAL(inbuf,smb_vwv9)) & 1 )<<16);

  if(smb_doff > smblen || (smb_doff + smb_dsize > smblen)) {
	return ERROR_DOS(ERRDOS,ERRbadmem);
  }

  data = smb_base(inbuf) + smb_doff;

  if(CVAL(inbuf,smb_wct) == 14) {
#ifdef LARGE_FILE_SUPPORT
		/*
		 * This is a large offset (64 bit) write.
		 */
		smb_offs |= (((SMB_OFF_T)IVAL(inbuf,smb_vwv12)) << 32);

#else
		/*
		 * This is a large offset (64 bit) write.
		 * Ensure we haven't been sent a >32 bit offset.
		 */

		if(IVAL(inbuf,smb_vwv12) != 0) {
			return ERROR_DOS(ERRDOS,ERRbadaccess);
		}
#endif
  }

  if (is_locked(fnum,cnum,(SMB_OFF_T)smb_dsize,smb_offs))
    return(ERROR_DOS(ERRDOS,ERRlock));

//  seek_file(fnum,smb_offs);
  
  /* X/Open SMB protocol says that, unlike SMBwrite
     if the length is zero then NO truncation is
     done, just a write of zero. To truncate a file,
     use SMBwrite. */
  if(smb_dsize == 0)
    nwritten = 0;
  else
    nwritten = new_write_file(fnum,data,smb_dsize,smb_offs);
  
  if(((nwritten == 0) && (smb_dsize != 0))||(nwritten < 0))
    return(UNIXERROR(ERRDOS,ERRdiskfull));

  set_message(outbuf,6,0,True);
  
  SSVAL(outbuf,smb_vwv2,nwritten);

  if (large_writeX)
	SSVAL(outbuf,smb_vwv4,(nwritten>>16)&1);
  
  if (nwritten < (ssize_t)smb_dsize) {
    SCVAL(outbuf,smb_rcls, ERRHRD);
    SSVAL(outbuf,smb_err,ERRdiskfull);      
  }

  DEBUG(3,("%s writeX fnum=%d cnum=%d num=%d wrote=%d\n",
  		timestring(),fnum,cnum,(int)smb_dsize,(int)nwritten));

  chain_fnum = fnum;
  DEBUG(3,("%s %d: write_through=%d\n", __FUNCTION__, __LINE__, write_through));
  #if 0
  if (write_through)
    sync_file(fnum);
  #endif
  if (write_through)
  {
    sync_file(fnum);
  }
  else
  {
    if (get_increae_trans(fnum) >= SYNC_AFTER_TRANS)
    {
		DEBUG(3,("%s %d: call sync_file\n", __FUNCTION__, __LINE__));
		sync_file(fnum);
		reset_increae_trans(fnum);
	}
	else
	{
		increase_trans(fnum);
		DEBUG(3,("%s %d: trans times = %d\n", __FUNCTION__, __LINE__, get_increae_trans(fnum)));
	}
  }

  return chain_reply(inbuf,outbuf,length,bufsize);
}


/****************************************************************************
  reply to a lseek
****************************************************************************/
int reply_lseek(char *inbuf,char *outbuf)
{
  int cnum,fnum;
  SMB_OFF_T startpos;
  SMB_OFF_T res= -1;
  int mode,umode;
  int outsize = 0;
  
  cnum = SVAL(inbuf,smb_tid);
  fnum = GETFNUM(inbuf,smb_vwv0);

  CHECK_FNUM(fnum,cnum);
  CHECK_ERROR(fnum);

  mode = SVAL(inbuf,smb_vwv1) & 3;
  startpos = IVAL_TO_SMB_OFF_T(inbuf,smb_vwv2);

  switch (mode & 3) 
    {
    case 0: umode = SEEK_SET; break;
    case 1: umode = SEEK_CUR; break;
    case 2: umode = SEEK_END; break;
    default:
      umode = SEEK_SET; break;
    }
  
  res = sys_lseek(Files[fnum].fd_ptr->fd,startpos,umode);
  Files[fnum].pos = res;
  
  outsize = set_message(outbuf,2,0,True);
  SIVALS(outbuf,smb_vwv0,res);
  
  DEBUG(3,("%s lseek fnum=%d cnum=%d ofs=%d mode=%d\n",timestring(),fnum,cnum,startpos,mode));
  
  return(outsize);
}


/****************************************************************************
  reply to a flush
****************************************************************************/
int reply_flush(char *inbuf,char *outbuf)
{
  int cnum, fnum;
  int outsize = set_message(outbuf,0,0,True);

  cnum = SVAL(inbuf,smb_tid);
  fnum = GETFNUM(inbuf,smb_vwv0);

  if (fnum != 0xFFFF) {
    CHECK_FNUM(fnum,cnum);
    CHECK_ERROR(fnum);
  }

  if (fnum == 0xFFFF)
    {
      int i;
      for (i=0;i<MAX_OPEN_FILES;i++)
	if (OPEN_FNUM(i))
	  sync_file(i);
    }
  else
    sync_file(fnum);

  DEBUG(3,("%s flush fnum=%d\n",timestring(),fnum));
  return(outsize);
}


/****************************************************************************
  reply to a exit
****************************************************************************/
int reply_exit(char *inbuf,char *outbuf)
{
  int outsize = set_message(outbuf,0,0,True);
  DEBUG(3,("%s exit\n",timestring()));
  
  return(outsize);
}


/****************************************************************************
  reply to a close
****************************************************************************/
int reply_close(char *inbuf,char *outbuf)
{
  int fnum,cnum;
  int outsize = 0;
  time_t mtime;
  int32 eclass = 0, err = 0;
  BOOL sync_flag = False;

  outsize = set_message(outbuf,0,0,True);

  cnum = SVAL(inbuf,smb_tid);

#if 1
  /* If it's an IPC, pass off to the pipe handler. */
  if (IS_IPC(cnum)) {
//	return reply_pipe_close(inbuf,outbuf);
	return ERROR_DOS(ERRDOS,ERRbadfid);
  }
#endif

  fnum = GETFNUM(inbuf,smb_vwv0);

  CHECK_FNUM(fnum,cnum);

  if(HAS_CACHED_ERROR(fnum)) {
    eclass = Files[fnum].wbmpx_ptr->wr_errclass;
    err = Files[fnum].wbmpx_ptr->wr_error;
  }

  mtime = make_unix_date3(inbuf+smb_vwv1);

  /* try and set the date */
  set_filetime(cnum, Files[fnum].name,mtime);

  if(Files[fnum].modified ||	//modify  	
  	Files[fnum].delete_on_close ||	//delete  	
  	Files[fnum].directory_delete_on_close)
  {  	
  	DEBUG(0,("\n###############(%s)yes, file(%s) needs to be sync!!!!######\n", 			
			__FUNCTION__, Files[fnum].name));  	
	sync_flag = True;  
  }

  close_file(fnum,True);

  /* We have a cached error */
  if(eclass || err)
    return(ERROR_DOS(eclass,err));

  if(sync_flag){
	extern pid_t m_pid;  
	DEBUG(0,("send sig to pid: %d\n", m_pid));  
	kill(m_pid, SIGUSR1);
  }

  DEBUG(3,("%s close fd=%d fnum=%d cnum=%d (numopen=%d)\n",
	   timestring(),Files[fnum].fd_ptr->fd,fnum,cnum,
	   Connections[cnum].num_files_open));
  
  return(outsize);
}


/****************************************************************************
  reply to a writeclose (Core+ protocol)
****************************************************************************/
int reply_writeclose(char *inbuf,char *outbuf)
{
  int cnum,fnum;
  ssize_t nwritten = -1;
  size_t numtowrite;
  int outsize = 0;
  SMB_OFF_T startpos;
  char *data;
  time_t mtime;
  
  cnum = SVAL(inbuf,smb_tid);
  fnum = GETFNUM(inbuf,smb_vwv0);

  CHECK_FNUM(fnum,cnum);
  CHECK_WRITE(fnum);
  CHECK_ERROR(fnum);

  numtowrite = SVAL(inbuf,smb_vwv1);
  startpos = IVAL_TO_SMB_OFF_T(inbuf,smb_vwv2);
  mtime = make_unix_date3(inbuf+smb_vwv4);
  data = smb_buf(inbuf) + 1;
  
  if (is_locked(fnum,cnum,numtowrite,startpos))
    return(ERROR_DOS(ERRDOS,ERRlock));
      
//  seek_file(fnum,startpos);
      
  nwritten = new_write_file(fnum,data,numtowrite,startpos);

  set_filetime(cnum, Files[fnum].name,mtime);
  
  close_file(fnum,True);

  DEBUG(3,("%s writeclose fnum=%d cnum=%d num=%d wrote=%d (numopen=%d)\n",
	   timestring(),fnum,cnum,numtowrite,nwritten,
	   Connections[cnum].num_files_open));
  
  if (nwritten <= 0)
    return(UNIXERROR(ERRDOS,ERRnoaccess));
  
  outsize = set_message(outbuf,1,0,True);
  
  SSVAL(outbuf,smb_vwv0,nwritten);
  return(outsize);
}


/****************************************************************************
  reply to a lock
****************************************************************************/
int reply_lock(char *inbuf,char *outbuf)
{
  int fnum,cnum;
  int outsize = set_message(outbuf,0,0,True);
  size_t count;
  SMB_OFF_T offset;
  int eclass;
  uint32 ecode;

  cnum = SVAL(inbuf,smb_tid);
  fnum = GETFNUM(inbuf,smb_vwv0);

  CHECK_FNUM(fnum,cnum);
  CHECK_ERROR(fnum);

  count = IVAL(inbuf,smb_vwv1);
  offset = IVAL(inbuf,smb_vwv3);

  if(!do_lock( fnum, cnum, count, offset, &eclass, &ecode))
    return (ERROR_DOS(eclass,ecode));
  
  return(outsize);
}


/****************************************************************************
  reply to a unlock
****************************************************************************/
int reply_unlock(char *inbuf,char *outbuf)
{
  int fnum,cnum;
  int outsize = set_message(outbuf,0,0,True);
  size_t count;
  SMB_OFF_T offset;
  int eclass;
  uint32 ecode;
  
  cnum = SVAL(inbuf,smb_tid);
  fnum = GETFNUM(inbuf,smb_vwv0);

  CHECK_FNUM(fnum,cnum);
  CHECK_ERROR(fnum);

  count = IVAL(inbuf,smb_vwv1);
  offset = IVAL(inbuf,smb_vwv3);

  if(!do_unlock(fnum, cnum, count, offset, &eclass, &ecode))
    return (ERROR_DOS(eclass,ecode));

  return(outsize);
}


/****************************************************************************
  reply to a tdis
****************************************************************************/
int reply_tdis(char *inbuf,char *outbuf)
{
  int cnum;
  int outsize = set_message(outbuf,0,0,True);
  uint16 vuid;

  cnum = SVAL(inbuf,smb_tid);
  vuid = SVAL(inbuf,smb_uid);

  if (!OPEN_CNUM(cnum)) {
    DEBUG(4,("Invalid cnum in tdis (%d)\n",cnum));
    return(ERROR_DOS(ERRSRV,ERRinvnid));
  }

  Connections[cnum].used = False;

  close_cnum(cnum,vuid);
  
  DEBUG(3,("%s tdis cnum=%d\n",timestring(),cnum));

  return outsize;
}



/****************************************************************************
  reply to a echo
****************************************************************************/
int reply_echo(char *inbuf,char *outbuf)
{
  int cnum;
  int smb_reverb = SVAL(inbuf,smb_vwv0);
  int seq_num;
  int data_len = smb_buflen(inbuf);
  int outsize = set_message(outbuf,1,data_len,True);

  /* copy any incoming data back out */
  if (data_len > 0)
    memcpy(smb_buf(outbuf),smb_buf(inbuf),data_len);

  if (smb_reverb > 100)
    {
      DEBUG(0,("large reverb (%d)?? Setting to 100\n",smb_reverb));
      smb_reverb = 100;
    }

  for (seq_num =1 ; seq_num <= smb_reverb ; seq_num++)
    {
      SSVAL(outbuf,smb_vwv0,seq_num);

      smb_setlen(outbuf,outsize - 4);

      send_smb(Client,outbuf);
    }

  DEBUG(3,("%s echo %d times cnum=%d\n",timestring(),smb_reverb,cnum));

  smb_echo_count++;

  return -1;
}

/****************************************************************************
  reply to a mkdir
****************************************************************************/
int reply_mkdir(char *inbuf,char *outbuf)
{
  pstring directory;
  int cnum;
  int outsize,ret= -1;
  BOOL bad_path = False;
  NTSTATUS status;
 
//  pstrcpy(directory,smb_buf(inbuf) + 1);
	srvstr_get_path(inbuf, directory, smb_buf(inbuf) + 1, sizeof(directory), 0, STR_TERMINATE, &status, False);

	if (!NT_STATUS_IS_OK(status)) {
		return ERROR_NT(status);
	}
	
  cnum = SVAL(inbuf,smb_tid);
  unix_convert(directory,cnum,0,&bad_path);

  if(strchr_m(directory, ':'))	//it is not a valid dir path...
  	return ERROR_NT(NT_STATUS_NOT_A_DIRECTORY);
  if(ms_has_wild(directory))
  	return ERROR_NT(NT_STATUS_OBJECT_NAME_INVALID);
  
  if (check_name(directory,cnum))
    ret = sys_mkdir(directory,unix_mode(cnum,aDIR));
  
  if (ret < 0)
  {
    if(errno == ENOENT) {
	if (bad_path) {
		return ERROR_NT(NT_STATUS_OBJECT_PATH_NOT_FOUND);
	} else {
		return ERROR_NT(NT_STATUS_OBJECT_NAME_NOT_FOUND);
	}
    }
    return(UNIXERROR(ERRDOS,ERRnoaccess));
  }
 
  outsize = set_message(outbuf,0,0,True);
  
  DEBUG(3,("%s mkdir %s cnum=%d ret=%d\n",timestring(),directory,cnum,ret));
  
  return(outsize);
}

/****************************************************************************
Static function used by reply_rmdir to delete an entire directory
tree recursively.
****************************************************************************/
BOOL recursive_rmdir(char *directory)
{
  char *dname = NULL;
  BOOL ret = False;
  void *dirptr = OpenDir(-1, directory, False);

  if(dirptr == NULL)
    return True;

  while((dname = ReadDirName(dirptr)))
  {
    pstring fullname;
    SMB_STRUCT_STAT st;

    if((strcmp(dname, ".") == 0) || (strcmp(dname, "..")==0))
      continue;

    /* Construct the full name. */
    if(strlen(directory) + strlen(dname) + 1 >= sizeof(fullname))
    {
      errno = ENOMEM;
      ret = True;
      break;
    }
    strcpy(fullname, directory);
    strcat(fullname, "/");
    strcat(fullname, dname);

    if(sys_lstat(fullname, &st) != 0)
    {
      ret = True;
      break;
    }

    if(st.st_mode & S_IFDIR)
    {
      if(recursive_rmdir(fullname)!=0)
      {
        ret = True;
        break;
      }
      if(sys_rmdir(fullname) != 0)
      {
        ret = True;
        break;
      }
    }
    else if(sys_unlink(fullname) != 0)
    {
      ret = True;
      break;
    }
  }
  CloseDir(dirptr);
  return ret;
}

/****************************************************************************
  reply to a rmdir
****************************************************************************/
int reply_rmdir(char *inbuf,char *outbuf)
{
  pstring directory;
  int cnum;
  int outsize = 0;
  BOOL ok = False;
  BOOL bad_path = False;
  NTSTATUS status;

  cnum = SVAL(inbuf,smb_tid);
//  pstrcpy(directory,smb_buf(inbuf) + 1);
	srvstr_get_path(inbuf, directory, smb_buf(inbuf) + 1, sizeof(directory), 0, STR_TERMINATE, &status, False);
	if (!NT_STATUS_IS_OK(status)) {
		return ERROR_NT(status);
	}
	
  unix_convert(directory,cnum,0,&bad_path);
  
  if (check_name(directory,cnum))
    {

      dptr_closepath(directory,SVAL(inbuf,smb_pid));

      ok = rmdir_internals(cnum, directory);
    }
  
  if (!ok)
  {
   	return set_bad_path_error(outbuf, errno, bad_path, ERRDOS, ERRbadpath);
  }
 
  outsize = set_message(outbuf,0,0,True);
  
  DEBUG(3,("%s rmdir %s\n",timestring(),directory));
  
  return(outsize);
}


/*******************************************************************
resolve wildcards in a filename rename
********************************************************************/
BOOL resolve_wildcards(char *name1,char *name2)
{
  fstring root1,root2;
  fstring ext1,ext2;
  char *p,*p2;

  name1 = strrchr_m(name1,'/');
  name2 = strrchr_m(name2,'/');

  if (!name1 || !name2) return(False);
  
  fstrcpy(root1,name1);
  fstrcpy(root2,name2);
  p = strrchr_m(root1,'.');
  if (p) {
    *p = 0;
    fstrcpy(ext1,p+1);
  } else {
    fstrcpy(ext1,"");    
  }
  p = strrchr_m(root2,'.');
  if (p) {
    *p = 0;
    fstrcpy(ext2,p+1);
  } else {
    fstrcpy(ext2,"");    
  }

  p = root1;
  p2 = root2;
  while (*p2) {
    if (*p2 == '?') {
      *p2 = *p;
      p2++;
    } else {
      p2++;
    }
    if (*p) p++;
  }

  p = ext1;
  p2 = ext2;
  while (*p2) {
    if (*p2 == '?') {
      *p2 = *p;
      p2++;
    } else {
      p2++;
    }
    if (*p) p++;
  }

  strcpy(name2,root2);
  if (ext2[0]) {
    strcat(name2,".");
    strcat(name2,ext2);
  }

  return(True);
}

/*******************************************************************
check if a user is allowed to rename a file
********************************************************************/
BOOL can_rename(char *fname,int cnum)
{
  SMB_STRUCT_STAT sbuf;

  if (!CAN_WRITE(cnum)){
  	DEBUG(0,("CAN_WRITE failed for rename!\n"));
  	return(False);
  }

  if (sys_lstat(fname,&sbuf) != 0){
  	DEBUG(0,("can't lstat for rename???\n"));
  	return(False);
  }
  
  if (!check_file_sharing(cnum,fname)){
  	DEBUG(0,("check file sharing failed for rename!\n"));
  	return(False);
  }

  return(True);
}

/****************************************************************************
  reply to a mv
****************************************************************************/
int reply_mv(char *inbuf,char *outbuf)
{
  int outsize = 0;
  pstring name, newname;
  int cnum;
  char *p;
  NTSTATUS status;
  NTSTATUS error;

  cnum = SVAL(inbuf,smb_tid);
  
//  pstrcpy(name,smb_buf(inbuf) + 1);
  p = smb_buf(inbuf) + 1;
  p += srvstr_get_path(inbuf, name, p, sizeof(name), 0, STR_TERMINATE, &status, True);
  if (!NT_STATUS_IS_OK(status)) {
	return ERROR_NT(status);
  }
	
  p++;
  p += srvstr_get_path(inbuf, newname, p, sizeof(newname), 0, STR_TERMINATE, &status, True);
  if (!NT_STATUS_IS_OK(status)) {
	return ERROR_NT(status);
  }
//  pstrcpy(newname,smb_buf(inbuf) + 3 + strlen(name));
   
  DEBUG(3,("reply_mv : %s -> %s\n",name,newname));

  error = mv_internals(cnum, name, newname);

  if(!NT_STATUS_IS_OK(error)){
  	return ERROR_NT(error);
  }
   
  outsize = set_message(outbuf,0,0,True);
  
  return(outsize);
}

/*******************************************************************
  copy a file as part of a reply_copy
  ******************************************************************/
static BOOL copy_file(char *src,char *dest1,int cnum,int ofun,
		      int count,BOOL target_is_directory)
{
  int Access,action;
  SMB_STRUCT_STAT st;
  int ret=0;
  int fnum1,fnum2;
  pstring dest;
  
  pstrcpy(dest,dest1);
  if (target_is_directory) {
    char *p = strrchr_m(src,'/');
    if (p) 
      p++;
    else
      p = src;
    strcat(dest,"/");
    strcat(dest,p);
  }

  if (!file_exist(src,&st)) return(False);

  fnum1 = find_free_file();
  if (fnum1<0) return(False);
  open_file_shared(fnum1,cnum,src,(DENY_NONE<<4),
		   1,0,0,&Access,&action);

  if (!Files[fnum1].open) return(False);

  if (!target_is_directory && count)
    ofun = 1;

  fnum2 = find_free_file();
  if (fnum2<0) {
    close_file(fnum1,False);
    return(False);
  }
  open_file_shared(fnum2,cnum,dest,(DENY_NONE<<4)|1,
		   ofun,st.st_mode,0,&Access,&action);

  if (!Files[fnum2].open) {
    close_file(fnum1,False);
    return(False);
  }

  if ((ofun&3) == 1) {
    sys_lseek(Files[fnum2].fd_ptr->fd,0,SEEK_END);
  }
  
  if (st.st_size)
    ret = transfer_file(Files[fnum1].fd_ptr->fd,Files[fnum2].fd_ptr->fd,st.st_size,NULL,0,0);

  close_file(fnum1,False);
  close_file(fnum2,False);

  return(ret == st.st_size);
}



/****************************************************************************
  reply to a file copy.
  ****************************************************************************/
int reply_copy(char *inbuf,char *outbuf)
{
  int outsize = 0;
  pstring name;
  int cnum;
  pstring directory;
  pstring mask,newname;
  char *p;
  int count=0;
  int error = ERRnoaccess;
  BOOL has_wild;
  BOOL exists=False;
  int tid2 = SVAL(inbuf,smb_vwv0);
  int ofun = SVAL(inbuf,smb_vwv1);
  int flags = SVAL(inbuf,smb_vwv2);
  BOOL target_is_directory=False;
  BOOL bad_path1 = False;
  BOOL bad_path2 = False;
  NTSTATUS status;

  *directory = *mask = 0;

  cnum = SVAL(inbuf,smb_tid);
  
//  pstrcpy(name,smb_buf(inbuf));
//  pstrcpy(newname,smb_buf(inbuf) + 1 + strlen(name));

	p = smb_buf(inbuf);
	p += srvstr_get_path(inbuf, name, p, sizeof(name), 0, STR_TERMINATE, &status, True);
	if (!NT_STATUS_IS_OK(status)) {
		return ERROR_NT(status);
	}
	p += srvstr_get_path(inbuf, newname, p, sizeof(newname), 0, STR_TERMINATE, &status, True);
	if (!NT_STATUS_IS_OK(status)) {
		return ERROR_NT(status);
	}
   
  DEBUG(3,("reply_copy : %s -> %s\n",name,newname));
   
  if (tid2 != cnum) {
    /* can't currently handle inter share copies XXXX */
    DEBUG(3,("Rejecting inter-share copy\n"));
    return(ERROR_DOS(ERRSRV,ERRinvdevice));
  }

  unix_convert(name,cnum,0,&bad_path1);
  unix_convert(newname,cnum,0,&bad_path2);

  target_is_directory = directory_exist(newname,NULL);

  if ((flags&1) && target_is_directory) {
    return(ERROR_DOS(ERRDOS,ERRbadfile));
  }

  if ((flags&2) && !target_is_directory) {
    return(ERROR_DOS(ERRDOS,ERRbadpath));
  }

  if ((flags&(1<<5)) && directory_exist(name,NULL)) {
    /* wants a tree copy! XXXX */
    DEBUG(3,("Rejecting tree copy\n"));
    return(ERROR_DOS(ERRSRV,ERRerror));    
  }

  p = strrchr_m(name,'/');
  if (!p) {
    strcpy(directory,"./");
    strcpy(mask,name);
  } else {
    *p = 0;
    strcpy(directory,name);
    strcpy(mask,p+1);
  }

#ifdef USE_83_NAME
  if (is_mangled(mask))
    check_mangled_stack(mask);
#endif

  has_wild = ms_has_wild(mask);

  if (!has_wild) {
    strcat(directory,"/");
    strcat(directory,mask);
    if (resolve_wildcards(directory,newname) && 
	copy_file(directory,newname,cnum,ofun,
		  	count,target_is_directory)) 
		count++;
	
    if (!count) 
		exists = file_exist(directory,NULL);
  } else {
    void *dirptr = NULL;
    char *dname;
    pstring destname;

    if (check_name(directory,cnum))
      dirptr = OpenDir(cnum, directory, True);

    if (dirptr)
      {
	error = ERRbadfile;

	if (strequal(mask,"????????.???"))
	  strcpy(mask,"*");

	while ((dname = ReadDirName(dirptr)))
	  {
	    pstring fname;
	    pstrcpy(fname,dname);
	    
	    if(!mask_match(fname, mask, case_sensitive, False)) continue;

	    error = ERRnoaccess;
	    sprintf(fname,"%s/%s",directory,dname);
	    strcpy(destname,newname);
	    if (resolve_wildcards(fname,destname) && 
		copy_file(directory,newname,cnum,ofun,
			  count,target_is_directory)) count++;
	    DEBUG(3,("reply_copy : doing copy on %s -> %s\n",fname,destname));
	  }
	CloseDir(dirptr);
      }
  }
  
  if (count == 0) {
    if (exists)
      return(ERROR_DOS(ERRDOS,error));
    else
    {
     if((errno == ENOENT) && (bad_path1 || bad_path2)) {
		unix_ERR_class = ERRDOS;
		unix_ERR_code = ERRbadpath;
      }
      return(UNIXERROR(ERRDOS,error));
    }
  }
  
  outsize = set_message(outbuf,1,0,True);
  SSVAL(outbuf,smb_vwv0,count);

  return(outsize);
}



/****************************************************************************
  reply to a setdir
****************************************************************************/
int reply_setdir(char *inbuf,char *outbuf)
{
  int cnum,snum;
  int outsize = 0;
  BOOL ok = False;
  pstring newdir;
  NTSTATUS status;
  
  cnum = SVAL(inbuf,smb_tid);
  
  snum = Connections[cnum].service;
  if (!CAN_SETDIR(snum))
    return(ERROR_DOS(ERRDOS,ERRnoaccess));
  
//  pstrcpy(newdir,smb_buf(inbuf) + 1);
	srvstr_get_path(inbuf, newdir, smb_buf(inbuf) + 1, sizeof(newdir), 0, STR_TERMINATE, &status, False);
	if (!NT_STATUS_IS_OK(status)) {
		return ERROR_NT(status);
	}
//  strlower_m(newdir); ??what's this? we can not create dir with upper characters?
  
  if (strlen(newdir) == 0)
    ok = True;
  else
    {
      ok = directory_exist(newdir,NULL);
      if (ok)
	string_set(&Connections[cnum].connectpath,newdir);
    }
  
  if (!ok)
    return(ERROR_DOS(ERRDOS,ERRbadpath));
  
  outsize = set_message(outbuf,0,0,True);
  SCVAL(outbuf,smb_reh,CVAL(inbuf,smb_reh));
  
  DEBUG(3,("%s setdir %s cnum=%d\n",timestring(),newdir,cnum));
  
  return(outsize);
}


/****************************************************************************
  reply to a lockingX request
****************************************************************************/
int reply_lockingX(char *inbuf,char *outbuf,int length,int bufsize)
{
  int fnum = GETFNUM(inbuf,smb_vwv2);
  unsigned char locktype = CVAL(inbuf,smb_vwv3);
  uint16 num_ulocks = SVAL(inbuf,smb_vwv6);
  uint16 num_locks = SVAL(inbuf,smb_vwv7);
  size_t count;
  SMB_OFF_T offset;

  int cnum;
  int i;
  char *data;
  uint32 ecode=0, dummy2;
  int eclass=0, dummy1;

  cnum = SVAL(inbuf,smb_tid);

  CHECK_FNUM(fnum,cnum);
  CHECK_ERROR(fnum);

  data = smb_buf(inbuf);

  /* Check if this is an oplock break on a file
     we have granted an oplock on.
   */
  if ((locktype & LOCKING_ANDX_OPLOCK_RELEASE))
  {
    int token;
    files_struct *fsp = &Files[fnum];
    uint32 dev = fsp->fd_ptr->dev;
    uint32 inode = fsp->fd_ptr->inode;

    DEBUG(5,("reply_lockingX: oplock break reply from client for fnum = %d\n",
              fnum));
    /*
     * Make sure we have granted an oplock on this file.
     */
    if(!fsp->granted_oplock)
    {
      DEBUG(0,("reply_lockingX: Error : oplock break from client for fnum = %d and \
no oplock granted on this file.\n", fnum));
      return ERROR_DOS(ERRDOS,ERRlock);
    }

    /* Remove the oplock flag from the sharemode. */
    lock_share_entry(fsp->cnum, dev, inode, &token);
    if(remove_share_oplock( fnum, token)==False) {
	    DEBUG(0,("reply_lockingX: failed to remove share oplock for fnum %d, \
dev = %x, inode = %x\n", 
		     fnum, dev, inode));
	    unlock_share_entry(fsp->cnum, dev, inode, token);
    } else {
	    unlock_share_entry(fsp->cnum, dev, inode, token);

	    /* Clear the granted flag and return. */
	    fsp->granted_oplock = False;
    }

    /* if this is a pure oplock break request then don't send a reply */
    if (num_locks == 0 && num_ulocks == 0)
    {
      /* Sanity check - ensure a pure oplock break is not a
         chained request. */
      if(CVAL(inbuf,smb_vwv0) != 0xff)
        DEBUG(0,("reply_lockingX: Error : pure oplock break is a chained %d request !\n",
                 (unsigned int)CVAL(inbuf,smb_vwv0) ));
      return -1;
    }
  }

  /* Data now points at the beginning of the list
     of smb_unlkrng structs */
  for(i = 0; i < (int)num_ulocks; i++) {
    count = IVAL(data,SMB_LKLEN_OFFSET(i));
    offset = IVAL(data,SMB_LKOFF_OFFSET(i));
    if(!do_unlock(fnum,cnum,count,offset,&eclass, &ecode))
      return ERROR_DOS(eclass,ecode);
  }

  /* Now do any requested locks */
  data += 10*num_ulocks;
  /* Data now points at the beginning of the list
     of smb_lkrng structs */
  for(i = 0; i < (int)num_locks; i++) {
    count = IVAL(data,SMB_LKLEN_OFFSET(i)); 
    offset = IVAL(data,SMB_LKOFF_OFFSET(i)); 
    if(!do_lock(fnum,cnum,count,offset, &eclass, &ecode))
      break;
  }

  /* If any of the above locks failed, then we must unlock
     all of the previous locks (X/Open spec). */
  if(i != num_locks && num_locks != 0) {
    for(; i >= 0; i--) {
      count = IVAL(data,SMB_LKLEN_OFFSET(i));  
      offset = IVAL(data,SMB_LKOFF_OFFSET(i)); 
      do_unlock(fnum,cnum,count,offset,&dummy1,&dummy2);
    }
    return ERROR_DOS(eclass,ecode);
  }

  set_message(outbuf,2,0,True);
  
  DEBUG(3,("%s lockingX fnum=%d cnum=%d type=%d num_locks=%d num_ulocks=%d\n",
	timestring(),fnum,cnum,(unsigned int)locktype,num_locks,num_ulocks));

  chain_fnum = fnum;

  return chain_reply(inbuf,outbuf,length,bufsize);
}


/****************************************************************************
  reply to a SMBreadbmpx (read block multiplex) request
****************************************************************************/
int reply_readbmpx(char *inbuf,char *outbuf,int length,int bufsize)
{
  extern int chain_size;
  int cnum,fnum;
  ssize_t nread = -1, total_read;
  size_t mincount, maxcount;
  char *data;
  SMB_OFF_T startpos;
  int outsize;
  int max_per_packet;
  size_t tcount;
  int pad;

  /* this function doesn't seem to work - disable by default */
  if (!lp_readbmpx())
    return(ERROR_DOS(ERRSRV,ERRuseSTD));

  outsize = set_message(outbuf,8,0,True);

  cnum = SVAL(inbuf,smb_tid);
  fnum = GETFNUM(inbuf,smb_vwv0);

  CHECK_FNUM(fnum,cnum);
  CHECK_READ(fnum);
  CHECK_ERROR(fnum);

  startpos = IVAL_TO_SMB_OFF_T(inbuf,smb_vwv1);
  maxcount = SVAL(inbuf,smb_vwv3);
  mincount = SVAL(inbuf,smb_vwv4);

  data = smb_buf(outbuf);
  pad = ((long)data)%4;
  if (pad) 
  	pad = 4 - pad;
  data += pad;

  max_per_packet = bufsize-(outsize+pad);
  tcount = maxcount;
  total_read = 0;

  if (is_locked(fnum,cnum,maxcount,startpos))
    return(ERROR_DOS(ERRDOS,ERRlock));
	
  do
    {
      size_t N = MIN(max_per_packet,tcount-total_read);
  
      nread = read_file(fnum,data,startpos,N);

      if (nread <= 0) 
	  	nread = 0;

      if (nread < N)
	tcount = total_read + nread;

      set_message(outbuf,8,nread,False);
      SIVAL(outbuf,smb_vwv0,startpos);
      SSVAL(outbuf,smb_vwv2,tcount);
      SSVAL(outbuf,smb_vwv6,nread);
      SSVAL(outbuf,smb_vwv7,smb_offset(data,outbuf));

      send_smb(Client,outbuf);

      total_read += nread;
      startpos += nread;
    }
  while (total_read < (ssize_t)tcount);

  return(-1);
}


/****************************************************************************
  reply to a SMBwritebmpx (write block multiplex primary) request
****************************************************************************/
int reply_writebmpx(char *inbuf,char *outbuf)
{
  int cnum,fnum;
  ssize_t nwritten = -1;
  size_t numtowrite, tcount;
  int outsize = 0;
  SMB_OFF_T startpos;
  int smb_doff;
  char *data;
  BOOL write_through;
  
  cnum = SVAL(inbuf,smb_tid);
  fnum = GETFNUM(inbuf,smb_vwv0);

  CHECK_FNUM(fnum,cnum);
  CHECK_WRITE(fnum);
  CHECK_ERROR(fnum);

  tcount = SVAL(inbuf,smb_vwv1);
  startpos = IVAL_TO_SMB_OFF_T(inbuf,smb_vwv3);
  write_through = BITSETW(inbuf+smb_vwv7,0);
  numtowrite = SVAL(inbuf,smb_vwv10);
  smb_doff = SVAL(inbuf,smb_vwv11);

  data = smb_base(inbuf) + smb_doff;

  /* If this fails we need to send an SMBwriteC response,
     not an SMBwritebmpx - set this up now so we don't forget */
  SCVAL(outbuf,smb_com, SMBwritec);

  if (is_locked(fnum,cnum,tcount,startpos))
    return(ERROR_DOS(ERRDOS,ERRlock));

//  seek_file(fnum,startpos);
  nwritten = new_write_file(fnum,data,numtowrite,startpos);

  if(write_through)
    sync_file(fnum);
  
  if(nwritten < (ssize_t)numtowrite)
    return(UNIXERROR(ERRHRD,ERRdiskfull));

  /* If the maximum to be written to this file
     is greater than what we just wrote then set
     up a secondary struct to be attached to this
     fd, we will use this to cache error messages etc. */
  if((ssize_t)tcount > nwritten) 
    {
      write_bmpx_struct *wbms;
      if(Files[fnum].wbmpx_ptr != NULL)
	wbms = Files[fnum].wbmpx_ptr; /* Use an existing struct */
      else
	wbms = (write_bmpx_struct *)malloc(sizeof(write_bmpx_struct));
      if(!wbms)
	{
	  DEBUG(0,("Out of memory in reply_readmpx\n"));
	  return(ERROR_DOS(ERRSRV,ERRnoresource));
	}
      wbms->wr_mode = write_through;
      wbms->wr_discard = False; /* No errors yet */
      wbms->wr_total_written = nwritten;
      wbms->wr_errclass = 0;
      wbms->wr_error = 0;
      Files[fnum].wbmpx_ptr = wbms;
    }

  /* We are returning successfully, set the message type back to
     SMBwritebmpx */
  SCVAL(outbuf,smb_com, SMBwriteBmpx);
  
  outsize = set_message(outbuf,1,0,True);
  
  SSVALS(outbuf,smb_vwv0,-1); /* We don't support smb_remaining */
  
  if (write_through && (ssize_t)tcount == nwritten) {
    /* we need to send both a primary and a secondary response */
    smb_setlen(outbuf,outsize - 4);
    send_smb(Client,outbuf);

    /* now the secondary */
    outsize = set_message(outbuf,1,0,True);
    SCVAL(outbuf,smb_com, SMBwritec);
    SSVAL(outbuf,smb_vwv0,nwritten);
  }

  return(outsize);
}


/****************************************************************************
  reply to a SMBwritebs (write block multiplex secondary) request
****************************************************************************/
int reply_writebs(char *inbuf,char *outbuf)
{
  size_t numtowrite, tcount;
  ssize_t nwritten = -1;
  int cnum,fnum;
  int outsize = 0;
  SMB_OFF_T startpos;
  int smb_doff;
  char *data;
  write_bmpx_struct *wbms;
  BOOL send_response = False;
  BOOL write_through;
  
  cnum = SVAL(inbuf,smb_tid);
  fnum = GETFNUM(inbuf,smb_vwv0);
  CHECK_FNUM(fnum,cnum);
  CHECK_WRITE(fnum);

  tcount = SVAL(inbuf,smb_vwv1);
  startpos = IVAL_TO_SMB_OFF_T(inbuf,smb_vwv2);
  numtowrite = SVAL(inbuf,smb_vwv6);
  smb_doff = SVAL(inbuf,smb_vwv7);

  data = smb_base(inbuf) + smb_doff;

  /* We need to send an SMBwriteC response, not an SMBwritebs */
  SCVAL(outbuf,smb_com, SMBwritec);

  /* This fd should have an auxiliary struct attached,
     check that it does */
  wbms = Files[fnum].wbmpx_ptr;
  if(!wbms) return(-1);

  /* If write through is set we can return errors, else we must
     cache them */
  write_through = wbms->wr_mode;

  /* Check for an earlier error */
  if(wbms->wr_discard)
    return -1; /* Just discard the packet */

//  seek_file(fnum,startpos);
  nwritten = new_write_file(fnum,data,numtowrite,startpos);

  if(write_through)
    sync_file(fnum);
  
  if (nwritten < (ssize_t)numtowrite)
    {
      if(write_through)	{
	/* We are returning an error - we can delete the aux struct */
	if (wbms) 
		free((char *)wbms);
	Files[fnum].wbmpx_ptr = NULL;
	return(ERROR_DOS(ERRHRD,ERRdiskfull));
      }
      return(CACHE_ERROR(wbms,ERRHRD,ERRdiskfull));
    }

  /* Increment the total written, if this matches tcount
     we can discard the auxiliary struct (hurrah !) and return a writeC */
  wbms->wr_total_written += nwritten;
  if(wbms->wr_total_written >= (ssize_t)tcount)
    {
      if (write_through) {
	outsize = set_message(outbuf,1,0,True);
	SSVAL(outbuf,smb_vwv0,wbms->wr_total_written);    
	send_response = True;
      }

      free((char *)wbms);
      Files[fnum].wbmpx_ptr = NULL;
    }

  if(send_response)
    return(outsize);

  return(-1);
}


/****************************************************************************
  reply to a SMBsetattrE
****************************************************************************/
int reply_setattrE(char *inbuf,char *outbuf)
{
  int cnum,fnum;
  struct utimbuf unix_times;
  int outsize = 0;

  outsize = set_message(outbuf,0,0,True);

  cnum = SVAL(inbuf,smb_tid);
  fnum = GETFNUM(inbuf,smb_vwv0);

  CHECK_FNUM(fnum,cnum);
  CHECK_ERROR(fnum);

  /* Convert the DOS times into unix times. Ignore create
     time as UNIX can't set this.
     */
  unix_times.actime = make_unix_date2(inbuf+smb_vwv3);
  unix_times.modtime = make_unix_date2(inbuf+smb_vwv5);
  
  /* 
   * Patch from Ray Frush <frush@engr.colostate.edu>
   * Sometimes times are sent as zero - ignore them.
   */

  if ((unix_times.actime == 0) && (unix_times.modtime == 0)) 
  {
    /* Ignore request */
    DEBUG(3,("%s reply_setattrE fnum=%d cnum=%d ignoring zero request - \
not setting timestamps of 0\n",
          timestring(), fnum,cnum,unix_times.actime,unix_times.modtime));
    return(outsize);
  }
  else if ((unix_times.actime != 0) && (unix_times.modtime == 0)) 
  {
    /* set modify time = to access time if modify time was 0 */
    unix_times.modtime = unix_times.actime;
  }

  /* Set the date on this file */
  if(file_utime(cnum, Files[fnum].name, &unix_times))
    return(ERROR_DOS(ERRDOS,ERRnoaccess));
  
  DEBUG(3,("%s reply_setattrE fnum=%d cnum=%d actime=%d modtime=%d\n",
    timestring(), fnum,cnum,unix_times.actime,unix_times.modtime));

  return(outsize);
}


/****************************************************************************
  reply to a SMBgetattrE
****************************************************************************/
int reply_getattrE(char *inbuf,char *outbuf)
{
  int cnum,fnum;
  SMB_STRUCT_STAT sbuf;
  int outsize = 0;
  int mode;

  outsize = set_message(outbuf,11,0,True);

  cnum = SVAL(inbuf,smb_tid);
  fnum = GETFNUM(inbuf,smb_vwv0);

  CHECK_FNUM(fnum,cnum);
  CHECK_ERROR(fnum);

  /* Do an fstat on this file */
  if(sys_fstat(Files[fnum].fd_ptr->fd, &sbuf))
    return(UNIXERROR(ERRDOS,ERRnoaccess));
  
  mode = dos_mode(cnum,Files[fnum].name,&sbuf);
  
  /* Convert the times into dos times. Set create
     date to be last modify date as UNIX doesn't save
     this */
  put_dos_date2(outbuf,smb_vwv0,sbuf.st_mtime);
  put_dos_date2(outbuf,smb_vwv2,sbuf.st_atime);
  put_dos_date2(outbuf,smb_vwv4,sbuf.st_mtime);
  if (mode & aDIR)
    {
      SIVAL(outbuf,smb_vwv6,0);
      SIVAL(outbuf,smb_vwv8,0);
    }
  else
    {
      	SIVAL(outbuf,smb_vwv6,sbuf.st_size);
//copy from get_allocation_size func......	  
      	uint32 allocation_size;
	SMB_BIG_UINT ret;
	ret = (SMB_BIG_UINT)STAT_ST_BLOCKSIZE * (SMB_BIG_UINT)sbuf.st_blocks;
	allocation_size = (uint32)smb_roundup(ret);
	
      	SIVAL(outbuf,smb_vwv8,allocation_size);
    }
  SSVAL(outbuf,smb_vwv10, mode);
  
  DEBUG(3,("%s reply_getattrE fnum=%d cnum=%d\n",timestring(),fnum,cnum));
  
  return(outsize);
}

/*The following functions are using only for NetshareEnum request in LANMAN protocol*/

#define ACCESS_READ 0x01
#define ACCESS_WRITE 0x02
#define ACCESS_CREATE 0x04

static BOOL prefix_ok(const char *str, const char *prefix)
{
  return(strncmp(str,prefix,strlen(prefix)) == 0);
}

/****************************************************************************
  get info about a share
  ****************************************************************************/
static BOOL check_share_info(int uLevel, char* id)
{
  switch( uLevel ) {
  case 0:
    if (strcmp(id,"B13") != 0) return False;
    break;
  case 1:
    if (strcmp(id,"B13BWz") != 0) return False;
    break;
  case 2:
    if (strcmp(id,"B13BWzWWWzB9B") != 0) return False;
    break;
  case 91:
    if (strcmp(id,"B13BWzWWWzB9BB9BWzWWzWW") != 0) return False;
    break;
  default: return False;
  }
  return True;
}

static int StrlenExpanded(int cnum, int snum, char* s)
{
  	pstring buf;
  	if (!s) 
		return(0);
  	StrnCpy(buf,s,sizeof(buf)/2);
  	string_sub(buf,"%S",lp_servicename(snum));
  	standard_sub(cnum,buf);
  	return strlen(buf) + 1;
}

static int CopyExpanded(int cnum, int snum, char** dst, char* src, int* n)
{
  pstring buf;
  int l;

  if (!src || !dst || !n || !(*dst)) return(0);

  StrnCpy(buf,src,sizeof(buf)/2);
  string_sub(buf,"%S",lp_servicename(snum));
  standard_sub(cnum,buf);
  l = push_ascii(*dst,buf,*n, STR_TERMINATE);
  (*dst) += l;
  (*n) -= l;
  return l;
}

static int CopyAndAdvance(char** dst, char* src, int* n)
{
  int l;
  if (!src || !dst || !n || !(*dst)) 
  	return(0);
  l = push_ascii(*dst,src,*n, STR_TERMINATE);
  (*dst) += l;
  (*n) -= l;
  return l;
}

static int fill_share_info(int cnum, int snum, int uLevel,
 			   char** buf, int* buflen,
 			   char** stringbuf, int* stringspace, char* baseaddr)
{
  int struct_len;
  char* p;
  char* p2;
  int l2;
  int len;
 
  switch( uLevel ) {
  case 0: struct_len = 13; break;
  case 1: struct_len = 20; break;
  case 2: struct_len = 40; break;
  case 91: struct_len = 68; break;
  default: return -1;
  }
  
 
  if (!buf)
    {
      len = 0;
      if (uLevel > 0) len += StrlenExpanded(cnum,snum,lp_comment(snum));
      if (uLevel > 1) len += strlen(lp_pathname(snum)) + 1;
      if (buflen) *buflen = struct_len;
      if (stringspace) *stringspace = len;
      return struct_len + len;
    }
  
  len = struct_len;
  p = *buf;
  if ((*buflen) < struct_len) return -1;
  if (stringbuf)
    {
      p2 = *stringbuf;
      l2 = *stringspace;
    }
  else
    {
      p2 = p + struct_len;
      l2 = (*buflen) - struct_len;
    }
  if (!baseaddr) baseaddr = p;
  
  push_ascii(p,lp_servicename(snum),13, STR_TERMINATE);
  
  if (uLevel > 0)
    {
      int type;
      SCVAL(p,13,0);
      type = STYPE_DISKTREE;
	  
      if (strequal("IPC$",lp_servicename(snum))) 
	  	type = STYPE_IPC;
	  
      SSVAL(p,14,type);		/* device type */
      SIVAL(p,16,PTR_DIFF(p2,baseaddr));
      len += CopyExpanded(cnum,snum,&p2,lp_comment(snum),&l2);
    }
  
  if (uLevel > 1)
    {
      SSVAL(p,20,ACCESS_READ|ACCESS_WRITE|ACCESS_CREATE); /* permissions */
      SSVALS(p,22,-1);		/* max uses */
      SSVAL(p,24,1); /* current uses */
      SIVAL(p,26,PTR_DIFF(p2,baseaddr)); /* local pathname */
      len += CopyAndAdvance(&p2,lp_pathname(snum),&l2);
      memset(p+30,0,10); /* passwd (reserved), pad field */
    }
  
  if (uLevel > 2)
    {
      memset(p+40,0,10);
      SSVAL(p,50,0);
      SIVAL(p,52,0);
      SSVAL(p,56,0);
      SSVAL(p,58,0);
      SIVAL(p,60,0);
      SSVAL(p,64,0);
      SSVAL(p,66,0);
    }
       
  if (stringbuf)
    {
      (*buf) = p + struct_len;
      (*buflen) -= struct_len;
      (*stringbuf) = p2;
      (*stringspace) = l2;
    }
  else
    {
      (*buf) = p2;
      (*buflen) -= len;
    }
  return len;
}

/****************************************************************************
  view list of shares available
  ****************************************************************************/
static BOOL api_RNetShareEnum(int cnum,uint16 vuid, char *param,char *data,
  			      int mdrcnt,int mprcnt,
  			      char **rdata,char **rparam,
  			      int *rdata_len,int *rparam_len)
{
  char *str1 = param+2;
  char *str2 = skip_string(str1,1);
  char *p = skip_string(str2,1);
  int uLevel = SVAL(p,0);
  int buf_len = SVAL(p,2);
  char *p2;
  int count=lp_numservices();
  int total=0,counted=0;
  BOOL missed = False;
  int i;
  int data_len, fixed_len, string_len;
  int f_len, s_len;
 
  if (!prefix_ok(str1,"WrLeh")) 
  	return False;
  
  if (!check_share_info(uLevel,str2)) 
  	return False;
  
  data_len = fixed_len = string_len = 0;
  
  for (i=0;i<count;i++) {
    fstring servicename_dos;
    if (!(lp_browseable(i) && lp_snum_ok(i)))
	    continue;
    push_ascii_fstring(servicename_dos, lp_servicename(i));
    if( lp_browseable( i )
        && lp_snum_ok( i )
        && (strlen(servicename_dos) < 13) )   /* Maximum name length. */
    {
      total++;
      data_len += fill_share_info(cnum,i,uLevel,0,&f_len,0,&s_len,0);
      if (data_len <= buf_len)
      {
        counted++;
        fixed_len += f_len;
        string_len += s_len;
      }
      else
        missed = True;
    }
  }
  
  *rdata_len = fixed_len + string_len;
  *rdata = REALLOC(*rdata,*rdata_len);
  memset(*rdata,0,*rdata_len);
  
  p2 = (*rdata) + fixed_len;	/* auxillery data (strings) will go here */
  p = *rdata;
  f_len = fixed_len;
  s_len = string_len;
  for (i = 0; i < count;i++)
  {
    fstring servicename_dos;
    if (!(lp_browseable(i) && lp_snum_ok(i)))
	    continue;
    push_ascii_fstring(servicename_dos, lp_servicename(i));
    if( lp_browseable( i )
        && lp_snum_ok( i )
        && (strlen(servicename_dos) < 13) )
      {
      if( fill_share_info( cnum,i,uLevel,&p,&f_len,&p2,&s_len,*rdata ) < 0 )
 	break;
      }
    }
  
  *rparam_len = 8;
  *rparam = REALLOC(*rparam,*rparam_len);
  SSVAL(*rparam,0,missed ? ERRmoredata : 0);
  SSVAL(*rparam,2,0);
  SSVAL(*rparam,4,counted);
  SSVAL(*rparam,6,total);
  
  DEBUG(3,("RNetShareEnum gave %d entries of %d (%d %d %d %d)\n",
 	   counted,total,uLevel,
  	   buf_len,*rdata_len,mdrcnt));
  return(True);
}

static BOOL api_RNetShareGetInfo(int cnum,uint16 vuid, char *param,char *data,
				 int mdrcnt,int mprcnt,
				 char **rdata,char **rparam,
				 int *rdata_len,int *rparam_len)
{
  char *str1 = param+2;
  char *str2 = skip_string(str1,1);
  char *netname = skip_string(str2,1);
  char *p = skip_string(netname,1);
  int uLevel = SVAL(p,0);
  int snum = find_service(netname);
  
  if (snum < 0) return False;
  
  /* check it's a supported varient */
  if (!prefix_ok(str1,"zWrLh")) return False;
  if (!check_share_info(uLevel,str2)) return False;
 
  *rdata = REALLOC(*rdata,mdrcnt);
  p = *rdata;
  *rdata_len = fill_share_info(cnum,snum,uLevel,&p,&mdrcnt,0,0,0);
  if (*rdata_len < 0) return False;
 
  *rparam_len = 6;
  *rparam = REALLOC(*rparam,*rparam_len);
  SSVAL(*rparam,0,0);
  SSVAL(*rparam,2,0);		/* converter word */
  SSVAL(*rparam,4,*rdata_len);
 
  return(True);
}


/****************************************************************************
  the request is not supported
  ****************************************************************************/
static BOOL api_Unsupported(int cnum,uint16 vuid, char *param,char *data,
			    int mdrcnt,int mprcnt,
			    char **rdata,char **rparam,
			    int *rdata_len,int *rparam_len)
{
  *rparam_len = 4;
  *rparam = REALLOC(*rparam,*rparam_len);

  *rdata_len = 0;

  SSVAL(*rparam,0,50/*NERR_notsupported*/);
  SSVAL(*rparam,2,0);		/* converter word */

  DEBUG(3,("Unsupported API command\n"));

  return(True);
}

struct
{
  char *name;
  int id;
  BOOL (*fn)();
  int flags;
} api_commands[] = {
  	{"RNetShareEnum",	0,	(BOOL (*)())api_RNetShareEnum,0},
  	{"RNetShareGetInfo",	1,	(BOOL (*)())api_RNetShareGetInfo,0},
  	{NULL,		-1,	(BOOL (*)())api_Unsupported,0}
 };

static void copy_trans_params_and_data(char *outbuf, int align,
				char *rparam, int param_offset, int param_len,
				char *rdata, int data_offset, int data_len)
{
	char *copy_into = smb_buf(outbuf)+1;

	if(param_len < 0)
		param_len = 0;

	if(data_len < 0)
		data_len = 0;

	DEBUG(5,("copy_trans_params_and_data: params[%d..%d] data[%d..%d]\n",
			param_offset, param_offset + param_len,
			data_offset , data_offset  + data_len));

	if (param_len)
		memcpy(copy_into, &rparam[param_offset], param_len);

	copy_into += param_len + align;

	if (data_len )
		memcpy(copy_into, &rdata[data_offset], data_len);
}


void send_trans_reply(char *outbuf,
				char *rparam, int rparam_len,
				char *rdata, int rdata_len,
				BOOL buffer_too_large)
{
	int this_ldata,this_lparam;
	int tot_data_sent = 0;
	int tot_param_sent = 0;
	int align;

	int ldata  = rdata  ? rdata_len : 0;
	int lparam = rparam ? rparam_len : 0;

	if (buffer_too_large)
		DEBUG(5,("send_trans_reply: buffer %d too large\n", ldata ));

	this_lparam = MIN(lparam,max_send - 500); /* hack */
	this_ldata  = MIN(ldata,max_send - (500+this_lparam));

	align = ((this_lparam)%4);

/*
	if (buffer_too_large) {
		ERROR(ERRDOS,ERRmoredata);
	}
*/

	set_message(outbuf,10,1+align+this_ldata+this_lparam,True);

	copy_trans_params_and_data(outbuf, align,
								rparam, tot_param_sent, this_lparam,
								rdata, tot_data_sent, this_ldata);

	SSVAL(outbuf,smb_vwv0,lparam);
	SSVAL(outbuf,smb_vwv1,ldata);
	SSVAL(outbuf,smb_vwv3,this_lparam);
	SSVAL(outbuf,smb_vwv4,smb_offset(smb_buf(outbuf)+1,outbuf));
	SSVAL(outbuf,smb_vwv5,0);
	SSVAL(outbuf,smb_vwv6,this_ldata);
	SSVAL(outbuf,smb_vwv7,smb_offset(smb_buf(outbuf)+1+this_lparam+align,outbuf));
	SSVAL(outbuf,smb_vwv8,0);
	SSVAL(outbuf,smb_vwv9,0);

	show_msg(outbuf);
	if (!send_smb(Client,outbuf))
		exit_server("send_trans_reply: send_smb failed.");

	tot_data_sent = this_ldata;
	tot_param_sent = this_lparam;

	while (tot_data_sent < ldata || tot_param_sent < lparam)
	{
		this_lparam = MIN(lparam-tot_param_sent, max_send - 500); /* hack */
		this_ldata  = MIN(ldata -tot_data_sent, max_send - (500+this_lparam));

		if(this_lparam < 0)
			this_lparam = 0;

		if(this_ldata < 0)
			this_ldata = 0;

		align = (this_lparam%4);

		set_message(outbuf,10,1+this_ldata+this_lparam+align,False);

		copy_trans_params_and_data(outbuf, align,
					   rparam, tot_param_sent, this_lparam,
					   rdata, tot_data_sent, this_ldata);
		
		SSVAL(outbuf,smb_vwv3,this_lparam);
		SSVAL(outbuf,smb_vwv4,smb_offset(smb_buf(outbuf)+1,outbuf));
		SSVAL(outbuf,smb_vwv5,tot_param_sent);
		SSVAL(outbuf,smb_vwv6,this_ldata);
		SSVAL(outbuf,smb_vwv7,smb_offset(smb_buf(outbuf)+1+this_lparam+align,outbuf));
		SSVAL(outbuf,smb_vwv8,tot_data_sent);
		SSVAL(outbuf,smb_vwv9,0);

		show_msg(outbuf);
		if (!send_smb(Client,outbuf))
			exit_server("send_trans_reply: send_smb failed.");

		tot_data_sent  += this_ldata;
		tot_param_sent += this_lparam;
	}
}

/****************************************************************************
  the buffer was too small
  ****************************************************************************/
static BOOL api_TooSmall(int cnum,uint16 vuid, char *param,char *data,
			 int mdrcnt,int mprcnt,
			 char **rdata,char **rparam,
			 int *rdata_len,int *rparam_len)
{
  *rparam_len = MIN(*rparam_len,mprcnt);
  *rparam = REALLOC(*rparam,*rparam_len);

  *rdata_len = 0;

  SSVAL(*rparam,0,2123/*NERR_BufTooSmall*/);

  DEBUG(3,("Supplied buffer too small in API command\n"));

  return(True);
}


/****************************************************************************
  handle remote api calls
  ****************************************************************************/
static int api_reply(int cnum,uint16 vuid,char *outbuf,char *data,char *params,
		     int tdscnt,int tpscnt,int mdrcnt,int mprcnt)
{
  int api_command = SVAL(params,0);
  char *rdata = NULL;
  char *rparam = NULL;
  int rdata_len = 0;
  int rparam_len = 0;
  BOOL reply=False;
  int i;

  DEBUG(3,("Got API command %d of form <%s> <%s> (tdscnt=%d,tpscnt=%d,mdrcnt=%d,mprcnt=%d)\n",
	   api_command,params+2,skip_string(params+2,1),
	   tdscnt,tpscnt,mdrcnt,mprcnt));

  for (i=0;api_commands[i].name;i++)
    if (api_commands[i].id == api_command && api_commands[i].fn)
      {
	DEBUG(3,("Doing %s\n",api_commands[i].name));
	break;
      }

  rdata = (char *)malloc(1024); 
  if (rdata) 
  	bzero(rdata,1024);
  
  rparam = (char *)malloc(1024); 
  if (rparam) 
  	bzero(rparam,1024);

  reply = api_commands[i].fn(cnum,vuid,params,data,mdrcnt,mprcnt,
			     &rdata,&rparam,&rdata_len,&rparam_len);


  if (rdata_len > mdrcnt ||
      rparam_len > mprcnt)
    {
      reply = api_TooSmall(cnum,vuid,params,data,mdrcnt,mprcnt,
			   &rdata,&rparam,&rdata_len,&rparam_len);
    }
	    

  /* if we get False back then it's actually unsupported */
  if (!reply)
    api_Unsupported(cnum,vuid,params,data,mdrcnt,mprcnt,
		    &rdata,&rparam,&rdata_len,&rparam_len);

      

  /* now send the reply */
  send_trans_reply(outbuf, rparam, rparam_len, rdata, rdata_len, False);

  SAFE_FREE(rdata);
  SAFE_FREE(rparam);
  
  return(-1);
}

static int named_pipe(int cnum,uint16 vuid, char *outbuf,char *name,
		      uint16 *setup,char *data,char *params,
		      int suwcnt,int tdscnt,int tpscnt,
		      int msrcnt,int mdrcnt,int mprcnt)
{
	DEBUG(3,("named pipe command on <%s> name\n", name));

	if (strequal(name,"LANMAN"))
	{
		return api_reply(cnum,vuid,outbuf,data,params,tdscnt,tpscnt,mdrcnt,mprcnt);
	}


	if (setup)
	{
		DEBUG(3,("unknown named pipe: setup 0x%X setup1=%d\n", (int)setup[0],(int)setup[1]));
	}

	return 0;
}


/****************************************************************************
  reply to a SMBtrans
  ****************************************************************************/
int reply_trans(char *inbuf,char *outbuf, int size, int bufsize)
{
  fstring name;
  int name_offset = 0;
  char *data=NULL,*params=NULL;
  uint16 *setup=NULL;

  int outsize = 0;
  int cnum = SVAL(inbuf,smb_tid);
  uint16 vuid = SVAL(inbuf,smb_uid);

  int tpscnt = SVAL(inbuf,smb_vwv0);
  int tdscnt = SVAL(inbuf,smb_vwv1);
  int mprcnt = SVAL(inbuf,smb_vwv2);
  int mdrcnt = SVAL(inbuf,smb_vwv3);
  int msrcnt = CVAL(inbuf,smb_vwv4);
  BOOL close_on_completion = BITSETW(inbuf+smb_vwv5,0);
  BOOL one_way = BITSETW(inbuf+smb_vwv5,1);
  int pscnt = SVAL(inbuf,smb_vwv9);
  int psoff = SVAL(inbuf,smb_vwv10);
  int dscnt = SVAL(inbuf,smb_vwv11);
  int dsoff = SVAL(inbuf,smb_vwv12);
  int suwcnt = CVAL(inbuf,smb_vwv13);

  bzero(name, sizeof(name));
  srvstr_pull_buf(inbuf, name, smb_buf(inbuf), sizeof(name), STR_TERMINATE);

  if (dscnt > tdscnt || pscnt > tpscnt) {
	  goto bad_param;
  }
  
  	if (tdscnt)  {
		if((data = (char *)malloc(tdscnt)) == NULL) {
			DEBUG(0,("reply_trans: data malloc fail for %u bytes !\n", tdscnt));
			return(ERROR_DOS(ERRDOS,ERRnomem));
		} 
		if ((dsoff+dscnt < dsoff) || (dsoff+dscnt < dscnt))
			goto bad_param;
		if (smb_base(inbuf)+dsoff+dscnt > inbuf + size)
			goto bad_param;

		memcpy(data,smb_base(inbuf)+dsoff,dscnt);
	}
  
  	if (tpscnt) {
		if((params = (char *)malloc(tpscnt)) == NULL) {
			DEBUG(0,("reply_trans: param malloc fail for %u bytes !\n", tpscnt));
			SAFE_FREE(data);
			return(ERROR_DOS(ERRDOS,ERRnomem));
		} 
		if ((psoff+pscnt < psoff) || (psoff+pscnt < pscnt))
			goto bad_param;
		if (smb_base(inbuf)+psoff+pscnt > inbuf + size)
			goto bad_param;

		memcpy(params,smb_base(inbuf)+psoff,pscnt);
	}

  	if (suwcnt) {
		int i;
		if((setup = (uint16 *)malloc(suwcnt*sizeof(uint16))) == NULL) {
			DEBUG(0,("reply_trans: setup malloc fail for %u bytes !\n", (unsigned int)(suwcnt * sizeof(uint16))));
			SAFE_FREE(data);
			SAFE_FREE(params);
			return(ERROR_DOS(ERRDOS,ERRnomem));
		} 
		if (inbuf+smb_vwv14+(suwcnt*SIZEOFWORD) > inbuf + size)
			goto bad_param;
		if ((smb_vwv14+(suwcnt*SIZEOFWORD) < smb_vwv14) || (smb_vwv14+(suwcnt*SIZEOFWORD) < (suwcnt*SIZEOFWORD)))
			goto bad_param;

		for (i=0;i<suwcnt;i++)
			setup[i] = SVAL(inbuf,smb_vwv14+i*SIZEOFWORD);
	}


  if (pscnt < tpscnt || dscnt < tdscnt)
    {
      /* We need to send an interim response then receive the rest
	 of the parameter/data bytes */
      outsize = set_message(outbuf,0,0,True);
      show_msg(outbuf);
      send_smb(Client,outbuf);
    }

  /* receive the rest of the trans packet */
  while (pscnt < tpscnt || dscnt < tdscnt)
    {
      BOOL ret;
      int pcnt,poff,dcnt,doff,pdisp,ddisp;
      
      ret = receive_next_smb(Client,
#ifdef OPLOCK_ENABLE
	  				oplock_sock,
#endif
	  				inbuf,bufsize,
	  				SMB_SECONDARY_WAIT);

      if ((ret && (CVAL(inbuf, smb_com) != SMBtrans)) || !ret)
	{
          if(ret)
            DEBUG(0,("reply_trans: Invalid secondary trans packet\n"));
          else
            DEBUG(0,("reply_trans: %s in getting secondary trans response.\n",
              (smb_read_error == READ_ERROR) ? "error" : "timeout" ));
	  SAFE_FREE(params);
	  SAFE_FREE(data);
	  SAFE_FREE(setup);
	  return(ERROR_DOS(ERRSRV,ERRerror));
	}

      show_msg(inbuf);
      
      /* Revise total_params and total_data in case they have changed downwards */
	if (SVAL(inbuf,smb_vwv0) < tpscnt)
		tpscnt = SVAL(inbuf,smb_vwv0);
	if (SVAL(inbuf,smb_vwv1) < tdscnt)
		tdscnt = SVAL(inbuf,smb_vwv1);
	
      pcnt = SVAL(inbuf,smb_vwv2);
      poff = SVAL(inbuf,smb_vwv3);
      pdisp = SVAL(inbuf,smb_vwv4);
      
      dcnt = SVAL(inbuf,smb_vwv5);
      doff = SVAL(inbuf,smb_vwv6);
      ddisp = SVAL(inbuf,smb_vwv7);
      
      pscnt += pcnt;
      dscnt += dcnt;

      if (dscnt > tdscnt || pscnt > tpscnt) {
	      goto bad_param;
      }

      if (pcnt) {
		if (pdisp+pcnt >= tpscnt)
			goto bad_param;
		if ((pdisp+pcnt < pdisp) || (pdisp+pcnt < pcnt))
			goto bad_param;
		if (smb_base(inbuf) + poff + pcnt >= inbuf + bufsize)
			goto bad_param;
		if (params + pdisp < params)
			goto bad_param;

		memcpy(params+pdisp,smb_base(inbuf)+poff,pcnt);
	}

      if (dcnt) {
		if (ddisp+dcnt >= tdscnt)
			goto bad_param;
		if ((ddisp+dcnt < ddisp) || (ddisp+dcnt < dcnt))
			goto bad_param;
		if (smb_base(inbuf) + doff + dcnt >= inbuf + bufsize)
			goto bad_param;
		if (data + ddisp < data)
			goto bad_param;

		memcpy(data+ddisp,smb_base(inbuf)+doff,dcnt);      
	}
    }


  DEBUG(3,("trans <%s> data=%d params=%d setup=%d\n",name,tdscnt,tpscnt,suwcnt));

	if (name[0] == '\\' && 
	     	(StrnCaseCmp(&name[1],local_machine, strlen(local_machine)) == 0) &&
		(name[strlen(local_machine)+1] == '\\')){
		name_offset = strlen(local_machine)+1;
	}

	if (strnequal(&name[name_offset], "\\PIPE", strlen("\\PIPE"))) {
		name_offset += strlen("\\PIPE");

		/* Win9x weirdness.  When talking to a unicode server Win9x
		   only sends \PIPE instead of \PIPE\ */

		if (name[name_offset] == '\\')
			name_offset++;

		DEBUG(5,("calling named_pipe\n"));
		outsize = named_pipe(cnum,vuid,outbuf,
				     name+name_offset,setup,data,params,
				     suwcnt,tdscnt,tpscnt,msrcnt,mdrcnt,mprcnt);
	} else {
		DEBUG(3,("invalid pipe name\n"));
		outsize = 0;
	}


 	SAFE_FREE(data);
	SAFE_FREE(params);
	SAFE_FREE(setup);

  	if (close_on_completion)
    		close_cnum(cnum,vuid);

 	if (one_way)
    		return(-1);
  
  	if (outsize == 0) {
#if 0
		if (IS_IPC(cnum)) {
			DEBUG(0,("%s handles IPC\n", __func__));
			return -1;
		}
#endif
    		return(ERROR_DOS(ERRSRV,ERRnosupport));
  	}

  return(outsize);

  bad_param:

	DEBUG(0,("reply_trans: invalid trans parameters\n"));
	SAFE_FREE(data);
	SAFE_FREE(params);
	SAFE_FREE(setup);
	return ERROR_DOS(ERRSRV, ERRerror);
}


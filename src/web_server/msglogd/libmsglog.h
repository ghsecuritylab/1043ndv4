#ifndef _WRITE_LOG_H_
#define _WRITE_LOG_H_

/* for declaring para "priority" in msglogd, added by tf, 120227 */
#include <syslog.h>

enum logType
{	
	LOGTYPE_ALL = 0,	 	
	LOGTYPE_PPP, 
	LOGTYPE_DHCP,
	LOGTYPE_VPN,		/* added by kuangguiming 27Sep12 for WR842ND2.0 VPN */
	LOGTYPE_WIRELESS, 
	LOGTYPE_DDNS, 
	LOGTYPE_SECURITY,	/* security */
	LOGTYPE_FILTER,	/* original firewall, parental control, access control */
	LOGTYPE_NAS,
	LOGTYPE_MOBILE,
	LOGTYPE_IPV6,
	LOGTYPE_OTHER 
};
/*void msglogd (int priority, char* format, ...);*/
void msglogd(int priority,int logType, char *format, ...);
#endif

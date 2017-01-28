#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#ifndef DPROXY_H
#define DPROXY_H

#define PORT 53
#define OUT_PORT 9527           /* by wdl, 16Mar11, add */
#define NAME_SIZE 255
#define MAX_PACKET_SIZE 512
#define BUF_SIZE NAME_SIZE

#define DNS_PROBE_INTERVAL 30
#define DNS_PROBE_TIMEOUT 3 

#define DNS_PROBE_MAX_TRY 3


typedef u_int16_t uint16;
typedef u_int32_t uint32;

#include "dns.h"

#ifndef DNS_TIMEOUT 
#define DNS_TIMEOUT 240
#endif
#ifndef NAME_SERVER_DEFAULT
#define NAME_SERVER_DEFAULT "0.0.0.0"
#endif
/* by wdl, 02Mar11, add ipv6 default dns server */
#ifndef IPV6_NAME_SERVER_DEFAULT
#define IPV6_NAME_SERVER_DEFAULT ""
#endif
/* by wdl, 02Mar11, end add */
#ifndef CONFIG_FILE_DEFAULT 
#define CONFIG_FILE_DEFAULT "/etc/dproxy.conf"
#endif
#ifndef DENY_FILE_DEFAULT 
#define DENY_FILE_DEFAULT "/var/cache/dproxy.deny"
#endif
#ifndef CACHE_FILE_DEFAULT 
/* changed by ZQQ, 19Apr2011 */
//#define CACHE_FILE_DEFAULT "/var/cache/dproxy.cache"
#define CACHE_FILE_DEFAULT "/tmp/dproxy.cache"
#endif
#ifndef HOSTS_FILE_DEFAULT 
//BRCM
//#define HOSTS_FILE_DEFAULT "/etc/hosts"
/* changed by ZQQ, 19Apr2011 */
//#define HOSTS_FILE_DEFAULT "/var/hosts"
#define HOSTS_FILE_DEFAULT "/tmp/hosts"
#endif
#ifndef PURGE_TIME_DEFAULT 
#define PURGE_TIME_DEFAULT 48 * 60 * 60
#endif
#ifndef PPP_DEV_DEFAULT 
#define PPP_DEV_DEFAULT "/var/run/ppp0.pid"
#endif
#ifndef DHCP_LEASES_DEFAULT 
//BRCM
//#define DHCP_LEASES_DEFAULT "/var/state/dhcp/dhcpd.leases"
/* added by ZQQ, 19Apr2011 */
//#define DHCP_LEASES_DEFAULT "/var/udhcpd/udhcpd.leases"
#define DHCP_LEASES_DEFAULT "/tmp/udhcpd.leases"
#endif						
#ifndef PPP_DETECT_DEFAULT 
#define PPP_DETECT_DEFAULT 1
#endif
#ifndef DEBUG_FILE_DEFAULT 
#define DEBUG_FILE_DEFAULT "/var/log/dproxy.debug.log"
#endif

#ifndef DOMAIN_NAME_DEFAULT
#define DOMAIN_NAME_DEFAULT "Home"
#endif

//BRCM
//#define STATIC_DNS_FILE_DEFAULT "/var/fyi/sys/dns" /*拨号成功后得到的IPv4 DNS主机地址*/
/* changed by ZQQ,修改dns服务器文件的路径, 20May2011 */
#define STATIC_DNS_FILE_DEFAULT "/tmp/resolv.conf" /*拨号成功后得到的IPv4 DNS主机地址*/

/* by wdl, 02Mar11, add static ipv6 dns file */
//#define STATIC_IPV6_DNS_FILE_DEFAULT "/var/fyi/sys/ipv6_dns" /*拨号成功后得到的IPv6 DNS主机地址*/
#define STATIC_IPV6_DNS_FILE_DEFAULT "/tmp/resolv.ipv6.conf" /*拨号成功后得到的IPv6 DNS主机地址*/
/* by wdl, 02Mar11, end add */

/* by wdl, 16Mar11, add debug */
#define _DPROXY_DEBUG_
#ifdef DPROXY_DEBUG
void debug_perror( char *msg );
void debug(char *fmt, ...);
#define msg(...) printf("%s %s %d : ",__FILE__,__FUNCTION__,__LINE__); \
		printf(__VA_ARGS__); \
		printf("\r\n");
#else
#define debug_perror(msg) 
#define debug(fmt,arg...)
#define msg(...)
#endif

#define PRIMARY_SERVER      1
#define SECONDARY_SERVER    2
#define PURGE_TIMEOUT       30
void dns_probe();




#endif

#ifndef _RTL_IGMP_H_
#define _RTL_IGMP_H_


//#define CPU_PORT   PORT9		/* switch 8367R_SR/RB use port9 connected to cpu */

#define CPU_PORT   PORT5		/* switch 8367R_VB use port5 connected to cpu */
#define WAN_PORT   PORT0

#define NR_IGMP_VTABLE_LEN   16   /* 2 ^ 4 */

#if 0
typedef enum __portid
{
	PORT0 =  0, /* WAN */
	PORT1,
	PORT2,
	PORT3,
	PORT4,      /* LAN or virtual WAN */
	PORT5,      /* CPU */
	PORT_MAX_TP
} PORTID;
#endif

typedef enum _nm_pvid
{
    NM_PVID0 = 0x1,
    NM_PVID1 = 0x3,
    NM_PVID2 = 0x5,    
    NM_PVID3 = 0x7,
    NM_PVID4 = 0x9,
    NM_PVID5 = 0xb,
} NM_PVID;

typedef enum __vid_bitmap
{
    PVID = 0,
    BITMAP,
    VID_BITMAP_MAX
} VID_BITMAP;

typedef unsigned char TP_PORTID;


#ifndef BOOL
#define BOOL    int
#endif

#ifndef SUCCESS
#define SUCCESS 0
#endif

#ifndef FAILED
#define FAILED -1
#endif

int get_all_lan_vid(void);
int get_pvid (TP_PORTID pid);
TP_PORTID get_portid (int pvid);
int rtl_igmpSetup(void);


#endif /*_RTL_IGMP_H_*/

/***************************************************************
 *
 * Copyright(c) 2008-2015 Shenzhen TP-Link Technologies Co. Ltd.
 * All right reserved.
 *
 * Filename		:	portinfo.h
 * Version		:	1.0
 * Abstract		:	switch PORT information declaration for IGMP
 * Author		:	tiger (gengxianhu@tp-link.net)
 * Created Date	:	23/09/2009
 *
 * Modified History:
 *	
 ***************************************************************/

 /****************************************************************************
	PORT Information: (sk_buff->nfmark)
	
	        0                                                       7 bit
	     ---------------------------------------------------------------
    	|		|    	|    	|       |       |    	|    	|       |   0 ~ 7
	     ---------------------------------------------------------------
    	|		|    	|    	|       |       |    	|    	|       |   8 ~ 15
	     ---------------------------------------------------------------
    	|		|    	|    	|       |       |    	|    	|       |   16 ~ 23
	     ---------------------------------------------------------------
        |		|    	|    	|       |       |    	|    	|       |   24 ~ 31
	     ---------------------------------------------------------------

when receiving packet, only one bit must be set.
the device (br0,eth0,eth1) is determined by sk_buff->input_dev
rcv:
	eg:
	0x00000001 RCV PORT ID = 0
	0x00000002 RCV PORT ID = 1
	0x00000004 RCV PORT ID = 2
	...
	0x00000080 RCV PORT ID = 7
	...
	0x80000000 RCV PORT ID = 24

when sending packet, some bits can be set. it indicate which ports to send.
the device that is leaving by is determined by sk_buff->dev
snd:
    eg:
    0x00000001 DST PORT IDs = 0
    0x00000011 DST PORT IDs = 0,4
    0x00000083 DST PORT IDs = 0,1,7
    ...
    0xffffffff DST PORT IDs = 0,1,2,3...31

sk_buff->nfmark which carries multicast PORT ID information is divided by device, 
different devices may have same PORT ID. so we don't distinguish device from PORT ID

up layer process don't need to know the mapping between PORT ID and VLAN ID
****************************************************************************/
#ifndef _PORTINFO_H_
#define _PORTINFO_H_

#include <linux/types.h>

#define ADD_MULTICAST_GROUP(id, member)     \
    do                                      \
    {                                       \
        member |= id;                       \
    } while (0)

#define DEL_MULTICAST_GROUP(id, member)     \
    do                                      \
    {                                       \
        member &= ~id;                      \
    } while (0)

#define IS_MEM_MULTICAST_GROUP(id, member)  ((id) & (member))

#define IS_EMPTY_MULTICAST_GROUP(member)    (member)

static uint32_t port_id_array[32] = 
{
    0x00000001, 0x00000002, 0x00000004, 0x00000008,
    0x00000010, 0x00000020, 0x00000040, 0x00000080,
    0x00000100, 0x00000200, 0x00000400, 0x00000800,
    0x00001000, 0x00002000, 0x00004000, 0x00008000,
    0x00010000, 0x00020000, 0x00040000, 0x00080000,
    0x00100000, 0x00200000, 0x00400000, 0x00800000,
    0x01000000, 0x02000000, 0x04000000, 0x08000000,
    0x10000000, 0x20000000, 0x40000000, 0x80000000
};
    
#define CONVERT_PORT_ID(nr)     (port_id_array[(nr)])

#define IS_MULTICAST_ADDR(ptr)  ((ptr[0] == 0x01) && (ptr[1] == 0x00) && (ptr[2] == 0x5e) ? 1 : 0)


#endif /* _PORTINFO_H_ */


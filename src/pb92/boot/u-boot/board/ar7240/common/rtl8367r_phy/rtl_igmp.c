
#include <linux/kernel.h>
#include "rtl_igmp.h"
#include "rtk_api.h"
#include "rtk_api_ext.h"
#include "rtl_phy.h"

int all_lan_vid = 0;

static rtk_uint32 pvid_bitmap[PORT6][VID_BITMAP_MAX] = {	//only 6 ports
    {NM_PVID0, 0x21},	//WAN PORT
    {NM_PVID1, 0x3e},
    {NM_PVID2, 0x3e},
    {NM_PVID3, 0x3e},
    {NM_PVID4, 0x3e},
    {NM_PVID5, 0x3e}		//CPU PORT
};

/******************************************************************************
* FUNCTION      	: get_all_lan_vid()
* AUTHOR        	: HouXB <houxubo@tp-link.net>
* DESCRIPTION  	: vlan which contain all lan ports and cpu port 
******************************************************************************/
int get_all_lan_vid(void)
{
	return all_lan_vid;
}

int get_pvid (TP_PORTID pid)
{
    if (pid < PORT0 || pid >= PORT5)
    {
        return 0;
    }
    return pvid_bitmap[pid][PVID];
}

TP_PORTID get_portid (int pvid)
{
    int i;
   
    for (i = PORT1; i < PORT5; i++)
    {
        if (pvid_bitmap[i][PVID] == pvid)
			return i;
    }
	printk("Oops: PVID=0x%x, packets received from unknown port!\n", pvid);

    return PORT_MAX;
}

/* Note: rtl use port5 as cpu port. by HouXB, 06Dec10 */
rtk_int32 rtl_setIgmpVlan(void)
{
	rtk_vlan_t vid;
	rtk_portmask_t mbrmsk;
	rtk_portmask_t untagmsk;
	rtk_fid_t fid;
	
	int i;

	/* set IGMP VLANs after VLAN initialized,	
	 * set VLAN member as follows 
	 * VLAN2  member: port1, port5
	 * VLAN4  member: port2, port5 	 
	 * VLAN6  member: port1, port2, port5 
	 * VLAN8  member: port3, port4, port5 
	 * VLAN10  member: port1, port3, port5 
	 * VLAN12  member: port2, port3, port5 
	 * VLAN14  member: port1, port2, port3, port5 
	 * VLAN16  member: port4, port5 
	 * VLAN18  member: port1, port4, port5 
	 * VLAN20 member: port2, port4, port5 
	 * VLAN22 member: port1, port2, port4, port5 
	 * VLAN24 member: port3, port4, port5 
	 * VLAN26 member: port1, port3, port4, port5 
	 * VLAN28 member: port2, port3, port4, port5 
	 * VLAN30 member: port1, port2, port3, port4, port5 
	 */
	 
	/* create and set vlan */
	for (i = 1; i < NR_IGMP_VTABLE_LEN; i++)
	{
		/* PORT0 is CPU_PORT  or WAN_PORT */
		if (CPU_PORT == PORT0 || WAN_PORT == PORT0)
		{
			vid = i << 1;			 
			mbrmsk.bits[0] = i << 1;
		}
		else
		{
			printk("IGMP Error: Here we find the port 0 is not cpu port either wan port!\n");
			return FAILED;
		}
			
		mbrmsk.bits[0] |= (0x1 << CPU_PORT);  /* set CPU port bitmask */
		
		untagmsk.bits[0] = 0x1F;

		fid = 1;
		
		if (SUCCESS != rtk_vlan_set(vid, mbrmsk, untagmsk, fid))
		{
			return FAILED;
		}	
		
        printk ("vtable vid: 0x%08x, bitmap 0x%08x\n", vid, mbrmsk.bits[0]);
		
	}
	
	/* the last vlan contains all lan ports and cpu port. by HouXB, 06Dec10 */
	all_lan_vid = vid;
	
	return SUCCESS;

}

rtk_int32 rtl_setDefaultVlan(void)
{
	rtk_vlan_t vid;
	rtk_portmask_t mbrmsk;
	rtk_portmask_t untagmsk;
	rtk_fid_t fid;

	int i, bitmap;

    for (i = PORT0; i < PORT5; i++)
    {
		bitmap				= pvid_bitmap[i][BITMAP];
		
		vid					= pvid_bitmap[i][PVID];
		mbrmsk.bits[0]		= bitmap;
		untagmsk.bits[0]	= 0x1F;
		fid					= 1;	/* only For LAN */

		if(WAN_PORT == i)
		{
			fid	= 0;	/* WAN */
		}		
		if (SUCCESS != rtk_vlan_set(vid, mbrmsk, untagmsk, fid))
		{			
			goto vlan_failed;
		}	

        printk ("++ PVID: 0x%08x, bitmap: 0x%08x\n", vid, bitmap);
        
    }

	return SUCCESS;

vlan_failed:
	printk ("set vlan failed\n");
	return FAILED;
}

rtk_int32 rtl_igmpDirect(BOOL toCpu)
{

	/*set trapping IGMP protocol frame to CPU port*/

#if 0	//not effect, use another way later
	rtl8366rb_rmaConfig_t rma_action;

	if(toCpu)
	{
		//if (SUCCESS != rtl8366rb_setCPUPort(PORT5, DISABLE))
		//{
		//	printk ("set cpu port error\n");
		//	return FAILED;
		//}
		
		rma_action.op = RMAOP_TRAP_TO_CPU;
	}

	rtl8366rb_setReservedMulticastAddress(RMA_IGMP, &rma_action);

#endif

#if 0	//this way has some problems, shouldn't be like this.
	uint32 phyData;
	int phy;

	for (phy = PORT0; phy < PORT5; phy++)
	{
		if(SUCCESS != rtl8368s_getAsicPHYRegs(phy, 0, 21, &phyData))
			return FAILED;
		printk("get phy data:%x\n", phyData);
		phyData = (phyData & (~(0x3 << 14))) | (0x1 << 14);
		printk("revert phy data:%x\n", phyData);
			
		if(SUCCESS != rtl8368s_setAsicPHYRegs(phy, 0, 21, 0x4000))
			return FAILED;

		if(SUCCESS != rtl8368s_getAsicPHYRegs(phy, 0, 21, &phyData))
			return FAILED;
		printk("set phy data:%x\n", phyData);
	}
	printk("trap IGMP to CPU\n");
#endif

	return SUCCESS;

}


/******************************************************************************
* FUNCTION      	: rtl_add_cpu_port_2_pvid_vlan()
* AUTHOR        	: HouXB <houxubo@tp-link.net>
* DESCRIPTION  		: add cpu port to vlan which was tagged by pvid of lan and wan 
* INPUT				: 
*
* OUTPUT        	: 
* RETURN        	: 
* OTHERS        	: 
******************************************************************************/
void rtl_add_cpu_port_2_pvid_vlan(void)
{
	rtk_portmask_t mbrmsk;
	rtk_portmask_t untagmsk;
	rtk_fid_t fid;
//	int i = 0;

	mbrmsk.bits[0] 		= 0x3e;
	untagmsk.bits[0]  	= 0x1F;
	fid = 1;

	rtk_vlan_set(NM_PVID1, mbrmsk, untagmsk, fid);
	rtk_vlan_set(NM_PVID2, mbrmsk, untagmsk, fid);
	rtk_vlan_set(NM_PVID3, mbrmsk, untagmsk, fid);
	rtk_vlan_set(NM_PVID4, mbrmsk, untagmsk, fid);
}


int rtl_igmpSetup(void)
{	
	/* init vlan. by HouXB, 06Dec10 */
	if (RT_ERR_OK != rtk_vlan_init())
	{
		goto vlan_failed;
	}
	

	/* set VLAN for ports' PVID */
	if (SUCCESS != rtl_setDefaultVlan())
	{		
		goto vlan_failed;
	}

	/* set VLAN for IGMP Snooping */
	if (SUCCESS != rtl_setIgmpVlan())
	{
		goto vlan_failed;
	}

	/* set PVID for each port */
	if (rtk_vlan_portPvid_set(PORT0, pvid_bitmap[PORT0][PVID], 0)
		|| rtk_vlan_portPvid_set(PORT1, pvid_bitmap[PORT1][PVID], 0)
		|| rtk_vlan_portPvid_set(PORT2, pvid_bitmap[PORT2][PVID], 0)
		|| rtk_vlan_portPvid_set(PORT3, pvid_bitmap[PORT3][PVID], 0)
		|| rtk_vlan_portPvid_set(PORT4, pvid_bitmap[PORT4][PVID], 0))
	{
		goto pvid_failed;
	}

	if (SUCCESS != rtl_igmpDirect(TRUE))
	{
		goto direct_failed;
	}

	//rtl_add_cpu_port_2_pvid_vlan();
	
	return SUCCESS;

pvid_failed:
	printk ("set vlan pvid failed\n");
	return FAILED;
	
vlan_failed:
	printk ("set vlan failed\n");
	return FAILED;
	
direct_failed:
	printk ("direct igmp to cpu failed\n");
	return FAILED;
	
}


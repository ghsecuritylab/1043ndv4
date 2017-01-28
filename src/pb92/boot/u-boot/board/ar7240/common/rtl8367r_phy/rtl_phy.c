/******************************************************************************
*
* Copyright (c) 2010 TP-LINK Technologies CO.,LTD.
* All rights reserved.
*
* FILE NAME  :   rtl_phy.c
* VERSION    :   1.0
* DESCRIPTION:   the interface of rtl9367m about phy.
*
* AUTHOR     :   zhaolong <zhaolong@tp-link.net>
* CREATE DATE:   08/23/2010
*
* HISTORY    :
* 01   08/23/2010  zhaolong     Create.
*
****************************************************************************/

#include "rtl_phy.h"
#include "rtl8367b_asicdrv.h"
#include "rtk_api.h"
#include "rtk_api_ext.h"
#include "smi.h"
#include "rtl8367b_asicdrv_port.h"
#include "rtl8367b_asicdrv_phy.h"
#include "rtl8367b_asicdrv_led.h"

#include "rtk_types.h"

#ifdef CONFIG_TP_MULTICAST
#include "rtl_igmp.h"
#endif

/* Added by zhl, 08Oct2010. */
/* Macro to use LED_0 interface or LED_1 interface to
 * control the port led. */
#define USE_LED_GROUP_0		1
/* End: Added by zhl, 08Oct2010. */

#define printk printf


#ifdef ENABLE_VLAN_IN_UBOOT
/******************************************************************************
* FUNCTION      : rtl_vlanSetup()
* AUTHOR        : zhaolong <zhaolong@tp-link.net>
* DESCRIPTION   : set the vlan of rtl8367r 
******************************************************************************/
rtk_int32 rtl_vlanSetup(void)
{
	rtk_vlan_t vid;
	rtk_portmask_t mbrmsk;
	rtk_portmask_t untagmsk;
	rtk_fid_t fid;
	
	/* initialize VLAN */
	if (SUCCESS != rtk_vlan_init())
	{
		goto vlan_failed;
	}

	/* all the ports are in the default VLAN 1 after VLAN initialized, 
	 * modify it as follows 
	 * VLAN1 member: port0, port5;
	 * VLAN2 member: port1, port2, port3, port4, port5 
	 */
	vid      = 1;
	mbrmsk.bits[0] = 0x21;
	untagmsk.bits[0] = 0x1F;
	fid      = 0;

	if (SUCCESS != rtk_vlan_set(vid, mbrmsk, untagmsk, fid))		
	{
		goto vlan_failed;
	}


	vid      = 2;
	mbrmsk.bits[0] = 0x3E;
	untagmsk.bits[0] = 0x1F;
	fid      = 1;
		
	if (SUCCESS != rtk_vlan_set(vid, mbrmsk, untagmsk, fid))
	{
		goto vlan_failed;
	}
	
	/* set PVID for each port */
	if (rtk_vlan_portPvid_set(PORT0, 1, 0)
		|| rtk_vlan_portPvid_set(PORT1, 2, 0)
		|| rtk_vlan_portPvid_set(PORT2, 2, 0)
		|| rtk_vlan_portPvid_set(PORT3, 2, 0)
		|| rtk_vlan_portPvid_set(PORT4, 2, 0))
	{
		goto pvid_failed;
	}


	return SUCCESS;
	
pvid_failed:
	printk ("set vlan pvid failed\n");
	return FAILED;
	
vlan_failed:
	printk ("set vlan failed\n");
	return FAILED;
}
#endif

extern void toggleGpioLeds(int on);

/******************************************************************************
* FUNCTION      : rtl_phySetup()
* AUTHOR        : zhaolong <zhaolong@tp-link.net>
* DESCRIPTION   : reset and setup the PHY associated with
* 				  the specified MAC unit number 
* INPUT         : ethUnit, the unit number of some MAC.
* OUTPUT        : N/A
* RETURN        : TRUE,		associated PHY is alive; 
* 				  FALSE,	no LINKs on this ethernet unit
* OTHERS        : N/A
******************************************************************************/
int rtl_phySetup(void)
{
	int retVal = 0;
	//uint32 data = 0;	
	//int loopCount = 0;
	rtk_port_mac_ability_t ability;

	/*printk("Here we will setup the rtl8367r!\n");*/

	/* we init the SMI interface here temporarily, but
	 * we must make sure it was called before any config 
	 * of rtl8367r with SMI interface. */

	smi_init();
//	udelay(1000*1000);

	udelay(100*1000);
	
	/* when smi_init, it need a little time to off the switch led.
	   so we turn off the QSS and USB lend after a little delay.
	   by HouXB, 19May11 */
   	toggleGpioLeds(0);
	
	udelay(900*1000);

	if (SUCCESS != rtk_switch_init())
	{
		printk ("initChip failed\n");
		return FAILED;
	}

	/*External Interface setup*/
	/*printk ("Here we will set the RGMII 0 of RTL8367M.\n");*/
    memset(&ability, 0, sizeof(ability));
    ability.forcemode   = 1;
    ability.duplex          = 1;
    ability.speed           = SPD_1000M;
    ability.link                = 1;
    retVal = rtk_port_macForceLinkExt0_set(MODE_EXT_RGMII, &ability);
	if (SUCCESS != retVal) 
	{
		printk ("RGMII 0 set failed, errno: 0x%08x\n", retVal);
		return FAILED;
	}

   /* RGMII TX/RX delay tunning */
   /* In TX delay, there are 2 selection: no-delay and 2ns delay. */
   /* In RX dekay, there are 8 steps for delay tunning. 0 for no-delay,
	  and 7 for maximum delay. */
   retVal = rtk_port_rgmiiDelayExt0_set(1, 4);
   if (SUCCESS != retVal) 
	{
		printk ("RGMII 0 delay failed, errno: 0x%08x\n", retVal);
		return FAILED;
	}
	
	udelay(100*1000);

#ifdef CONFIG_TP_MULTICAST
	if (SUCCESS != rtl_igmpSetup())
	{
		printk("rtl_igmpSetup\n");
		return FAILED;
	}
#else
#ifdef ENABLE_VLAN_IN_UBOOT
	if (SUCCESS != rtl_vlanSetup())
	{
		printk("rtl_vlanSetup\n");
		return FAILED;
	}	
#endif	
#endif

#ifdef GREEN_ETHER
	if (SUCCESS != rtk_switch_greenEthernet_set(ENABLED))
	{
		printk ("+++ set green ethernet failed\n");
		return FAILED;
	}
	
	if (SUCCESS != rtl8367b_setAsicReg(0xC44C, 0x0085))
	{
		printk ("+++ set asic reg failed\n");
		return FAILED;
	}


	/* Setup the led to blink at 8HZ when linking or actoring. */
	//rtl_ledSetup();
#endif

	return SUCCESS;
		
}




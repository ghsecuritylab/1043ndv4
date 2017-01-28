/******************************************************************************
*
* Copyright (c) 2010 TP-LINK Technologies CO.,LTD.
* All rights reserved.
*
* FILE NAME  :   ar7240_rtl8367r_phy.c
* VERSION    :   1.0
* DESCRIPTION:   the interface of rtl8367r for ag7420.
*
* AUTHOR     :   zhaolong <zhaolong@tp-link.net>
* CREATE DATE:   08/24/2010
*
* HISTORY    :
* 01   08/24/2010  zhaolong     Create.
*
******************************************************************************/

#include "ar7240_rtl8367r_phy.h"
#include "rtl_phy.h"
#include "rtk_api.h"
#include "rtk_api_ext.h"
#include "rtl8367b_asicdrv.h"


/* PHY selections and access functions */

typedef enum {
    PHY_SRCPORT_INFO, 
    PHY_PORTINFO_SIZE,
} PHY_CAP_TYPE;

typedef enum {
    PHY_SRCPORT_NONE,
    PHY_SRCPORT_VLANTAG, 
    PHY_SRCPORT_TRAILER,
} PHY_SRCPORT_TYPE;

#ifdef CONFIG_AR7240_S26_VLAN_IGMP
#define PYTHON_OK   0
#define PYTHON_ERR  1
#define PYTHON_FULL 2
#endif

#define DRV_LOG(DBG_SW, X0, X1, X2, X3, X4, X5, X6)
#define DRV_MSG(x,a,b,c,d,e,f)
#define DRV_PRINT(DBG_SW,X)

#define ATHR_LAN_PORT_VLAN          2
#define ATHR_WAN_PORT_VLAN          1
#define ENET_UNIT_LAN 0
#define ENET_UNIT_WAN 1

#define TRUE    1
#define FALSE   0

#define ATHR_PHY0_ADDR   0x0
#define ATHR_PHY1_ADDR   0x1
#define ATHR_PHY2_ADDR   0x2
#define ATHR_PHY3_ADDR   0x3
#define ATHR_PHY4_ADDR   0x4

#define ATHR_STATUS_LINK_PASS                 0x0400

#define MODULE_NAME "RTL8367M"

/* #define RTL8367M_PHY_DEBUG */ /* whether debug or not. */

#ifdef RTL8367M_PHY_DEBUG
#define RTL8367_PRINTF(_fmt,...) do {         \
                printk(MODULE_NAME": "_fmt, __VA_ARGS__);      \
} while (0)
#else
#define RTL8367_PRINTF(_fmt,...)
#endif

#define ATHR_PHY_MAX 5



extern rtk_api_ret_t rtk_port_phyLinkStatus_get(rtk_port_t phyNo, 
						rtk_port_linkStatus_t *pLinkStatus);


/******************************************************************************
*
* rtl8367r_phy_stab_wr - Function to Address 100Mbps stability issue, as 
* suggested by EBU.
*
* RETURNS: none
*
*/
void rtl8367r_phy_stab_wr(int phy_id, int phy_up, int phy_speed)
{
    return;
}

void rtl8367r_reg_rmw(unsigned int rtl8367r_addr, unsigned int rtl8367r_write_data) 
{
    int regVal;
	
	rtl8367b_getAsicReg(rtl8367r_addr, &regVal);
    rtl8367b_setAsicReg(rtl8367r_addr, (regVal | rtl8367r_write_data));
}

unsigned int rtl8367r_rd_phy(int ethUnit, unsigned int phy_addr, unsigned int reg_addr)
{

     unsigned int rddata;

     rtk_port_phyReg_get(phy_addr, reg_addr, &rddata);

	 return rddata;
}

void rtl8367r_wr_phy(int ethUnit,unsigned int phy_addr, unsigned int reg_addr, unsigned int write_data)
{
    rtk_port_phyReg_set(phy_addr, reg_addr, write_data);
}

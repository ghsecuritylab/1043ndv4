/******************************************************************************
*
* Copyright (c) 2010 TP-LINK Technologies CO.,LTD.
* All rights reserved.
*
* FILE NAME  :   ar7240_rtl8367r_phy.c
* VERSION    :   1.0
* DESCRIPTION:   the head file of ar7240_rtl8367r_phy.c.
*
* AUTHOR     :   zhaolong <zhaolong@tp-link.net>
* CREATE DATE:   08/30/2010
*
* HISTORY    :
* 01   08/30/2010  zhaolong     Create.
*
******************************************************************************/

#ifndef __AR7240_RTL8367M_PHY_H__
#define __AR7240_RTL8367M_PHY_H__

#ifndef BOOL
#define BOOL int
#endif

/*****************/
/* PHY Registers */
/*****************/
#define ATHR_PHY_CONTROL                 0
#define ATHR_PHY_STATUS                  1
#define ATHR_PHY_ID1                     2
#define ATHR_PHY_ID2                     3
#define ATHR_AUTONEG_ADVERT              4
#define ATHR_LINK_PARTNER_ABILITY        5
#define ATHR_AUTONEG_EXPANSION           6
#define ATHR_NEXT_PAGE_TRANSMIT          7
#define ATHR_LINK_PARTNER_NEXT_PAGE      8
#define ATHR_1000BASET_CONTROL           9
#define ATHR_1000BASET_STATUS            10
#define ATHR_PHY_FUNC_CONTROL            16
#define ATHR_PHY_SPEC_STATUS             17
#define ATHR_DEBUG_PORT_ADDRESS          29
#define ATHR_DEBUG_PORT_DATA             30
#define ATHR_PHY_INTR_ENABLE             0x12
#define ATHR_PHY_INTR_STATUS             0x13

/* ATHR_PHY_CONTROL fields */
#define ATHR_CTRL_SOFTWARE_RESET                    0x8000
#define ATHR_CTRL_SPEED_LSB                         0x2000
#define ATHR_CTRL_AUTONEGOTIATION_ENABLE            0x1000
#define ATHR_CTRL_RESTART_AUTONEGOTIATION           0x0200
#define ATHR_CTRL_SPEED_FULL_DUPLEX                 0x0100
#define ATHR_CTRL_SPEED_MSB                         0x0040


#define ATHR_RESET_DONE(phy_control)                   \
    (((phy_control) & (ATHR_CTRL_SOFTWARE_RESET)) == 0)
    
/* Phy status fields */
#define ATHR_STATUS_AUTO_NEG_DONE                   0x0020

#define ATHR_AUTONEG_DONE(ip_phy_status)                   \
    (((ip_phy_status) &                                  \
        (ATHR_STATUS_AUTO_NEG_DONE)) ==                    \
        (ATHR_STATUS_AUTO_NEG_DONE))

int rtl8367r_reg_init(void *arg);
int rtl8367r_reg_init_lan(void *arg);
int rtl8367r_phy_is_up(int unit);
int rtl8367r_phy_is_fdx(int unit,int phyUnit);
int rtl8367r_phy_speed(int unit,int phyUnit);
void rtl8367r_phy_stab_wr(int phy_id, int phy_up, int phy_speed);
int rtl8367r_register_ops(void *arg);
void rtl8367r_enable_link_intrs(void *arg);
void rtl8367r_disable_link_intrs(void *arg);
int rtl8367r_phy_is_link_alive(int phyUnit);
void rtl8367r_phy_stab_wr(int phy_id, int phy_up, int phy_speed);
unsigned int rtl8367r_reg_read(unsigned int s26_addr);
void rtl8367r_reg_write(unsigned int s26_addr, unsigned int s26_write_data);
void rtl8367r_wr_phy(int ethUnit,unsigned int phy_addr, unsigned int reg_addr, unsigned int write_data);
unsigned int rtl8367r_rd_phy(int ethUnit,unsigned int phy_addr, unsigned int reg_addr);
int rtl8367r_ioctl(struct net_device *dev,void *args, int cmd);


#endif /* __AR7240_RTL8367M_PHY_H__ */


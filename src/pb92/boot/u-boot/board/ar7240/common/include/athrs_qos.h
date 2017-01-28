#ifndef _ATHRS_QOPS_H
#define _ATHRS_QOPS_H

#include "athrs_ioctl.h"

#if defined(CONFIG_MACH_AR7240)

#define ENET_UNIT_LAN 1
#define ENET_UNIT_WAN 0

#include "athr_gmac.h"
extern athr_gmac_t *athr_gmacs[2];

#ifdef CONFIG_S26_PHY
#include "athrs26_phy.h"
#endif

#ifdef CONFIG_F1_PHY
#include "athrf1_phy.h"
#endif

#ifdef CONFIG_S16_PHY
#include "athrs16_phy.h"
#endif

static uint32_t
athr_gmac_reg_read(char *ad_name,uint32_t Reg) {

#ifdef CONFIG_S16_PHY
    athr_gmac_t *mac = athr_gmac_name2mac(ad_name);

    if (mac->mac_unit == 1 && is_ar7242()) 
        return (athrs16_reg_read(Reg));
    else
#endif
        return (athrs26_reg_read(Reg));

}

static void
athr_gmac_reg_write(char *ad_name,uint32_t Reg, uint32_t Val) 
{

    athr_gmac_t *mac = athr_gmac_name2mac(ad_name);
#ifdef CONFIG_S16_PHY

    if (mac->mac_unit == 1 && is_ar7242()) 
        athrs16_reg_write(Reg,Val);
    else
#endif
    printk("[%x] QoS Reg write %x=%x\n",mac->mac_unit,Reg,Val);
        athrs26_reg_write(Reg,Val);
    return;

}

static void
athr_gmac_reg_rmw_set(char *ad_name,uint32_t Reg, uint32_t Val) 
{
    int tval = athr_gmac_reg_read(ad_name,Reg);

    athr_gmac_reg_write(ad_name,Reg,(tval | Val));
}

static void
athr_gmac_reg_rmw_clear(char *ad_name,uint32_t Reg, uint32_t Val) 
{
    int tval = athr_gmac_reg_read(ad_name,Reg);

    athr_gmac_reg_write(ad_name,Reg,(tval & ~Val));
}

static int 
athr_gmac_enable_mac_qos(char *ad_name) {

    athr_gmac_t *mac = athr_gmac_name2mac(ad_name);
    struct net_device *dev = mac->mac_dev;
    int val = 0;

    dev->stop(dev);
    if(mac_has_flag(mac,ETH_SWONLY_MODE))
        return -1;

    mac_set_flag(mac,WAN_QOS_SOFT_CLASS);

    if (mac->mac_unit == ENET_UNIT_LAN) {
        val = athr_gmac_reg_read(ad_name, ATHR_CTRL_PORT_0);
        if( (val & ATHR_HDR_EN) == 0){
            athr_gmac_reg_rmw_set(ad_name,ATHR_CTRL_PORT_0, ATHR_HDR_EN);
            mac->qos->qos_flag |= 0x1 << 0;
        } 

        val = athr_gmac_reg_read(ad_name, ATHR_CPU_PORT); 
        if( (val & ATHR_CPU_EN) == 0){
            athr_gmac_reg_rmw_set(ad_name,ATHR_CPU_PORT, ATHR_CPU_EN);
            mac->qos->qos_flag |= 0x1 << 1;
        } 
        athr_gmac_reg_rmw_set(ad_name,ATHR_QOS_MODE_REGISTER,ATHR_QOS_WEIGHTED);

#ifdef CONFIG_S16_PHY
        if (is_ar7242() && mac->mac_unit == 0)
            mac_set_flag(mac,ATHR_S16_HEADER);
        else
#endif
#ifndef CONFIG_ATHEROS_HEADER_EN
            mac_set_flag(mac,ATHR_S26_HEADER);
#endif
        for (val = 1; val <= 4; val++){
            athr_gmac_reg_rmw_clear(ad_name,ATHR_PRI_CTRL_PORT_0 +
              (val * 256) , (ATHR_DA_PRI_EN|ATHR_TOS_PRI_EN|ATHR_VLAN_PRI_EN|ATHR_PORT_PRI_EN));
        }
    }
    else {
     /* WAN MAC setting */
        athr_gmac_reg_rmw_clear(ad_name,ATHR_PRI_CTRL_PORT_0 +
               (5 * 256) , (ATHR_DA_PRI_EN|ATHR_TOS_PRI_EN|ATHR_VLAN_PRI_EN|ATHR_PORT_PRI_EN));
    }
    mac->qos->qos_cap = 1;
    dev->open(dev);
    return 0;
}

static void 
athr_gmac_disable_mac_qos(char *ad_name) {

    athr_gmac_t *mac = athr_gmac_name2mac(ad_name);
    struct net_device *dev = mac->mac_dev;
    int val = 0;

    dev->stop(dev);

    mac_clear_flag(mac,WAN_QOS_SOFT_CLASS);

    if (mac->mac_unit == ENET_UNIT_LAN) {
        if(mac->qos->qos_flag != 0){
            if( (0x1 & mac->qos->qos_flag) != 0)
                athr_gmac_reg_rmw_clear(ad_name,ATHR_CTRL_PORT_0 ,ATHR_HDR_EN);
            if( ( (0x1 << 1) & mac->qos->qos_flag) != 0)
                athr_gmac_reg_rmw_clear(ad_name,ATHR_CPU_PORT, ATHR_CPU_EN);
        }
        athr_gmac_reg_rmw_clear(ad_name,ATHR_QOS_MODE_REGISTER,ATHR_QOS_WEIGHTED);

#ifdef CONFIG_S16_PHY
        if (is_ar7242() && mac->mac_unit == 0)
            mac_clear_flag(mac,ATHR_S16_HEADER);
        else
#endif
#ifndef CONFIG_ATHEROS_HEADER_EN
            mac_clear_flag(mac,ATHR_S26_HEADER);
#endif
        for (val = 1; val <= 4; val++){
            athr_gmac_reg_rmw_clear(ad_name,ATHR_PRI_CTRL_PORT_0 +
                 (val * 256) , (ATHR_DA_PRI_EN|ATHR_TOS_PRI_EN|ATHR_VLAN_PRI_EN|ATHR_PORT_PRI_EN));
        }
    }
    else {
        /* WAN MAC setting */
        athr_gmac_reg_rmw_clear(ad_name,ATHR_PRI_CTRL_PORT_0 +
                 (5 * 256) , (ATHR_DA_PRI_EN|ATHR_TOS_PRI_EN|ATHR_VLAN_PRI_EN|ATHR_PORT_PRI_EN));

    }
    mac->qos->qos_cap = 0;
	mac->qos->qos_flag = 0;
    dev->open(dev);
}

struct ath_qops ath_qos_ops = {
    athr_gmac_reg_read,
    athr_gmac_reg_write,
    athr_gmac_reg_rmw_set,
    athr_gmac_reg_rmw_clear,
    athr_gmac_enable_mac_qos,
    athr_gmac_disable_mac_qos,
    0,
};

static inline struct ath_qops
*get_qmac(char *ad_name)
{
    athr_gmac_t *mac = athr_gmac_name2mac(ad_name);

    if (mac_has_flag(mac,ETH_SWONLY_MODE))
        mac = athr_gmac_unit2mac(1);

    return (mac->qos);
}

static inline  struct net_device 
*get_ndev(char *ad_name)
{
    athr_gmac_t *mac = athr_gmac_name2mac(ad_name);

    if (mac_has_flag(mac,ETH_SWONLY_MODE))
        mac = athr_gmac_unit2mac(1);

    return (mac->mac_dev);
}

static inline void
set_mac_qops(void *mac)
{
    athr_gmac_t *qmac = (athr_gmac_t *)mac;

    qmac->qos = &ath_qos_ops;
    printk("%s : %p\n",__func__,qmac->mac_dev);
}
#endif  //_ATHRS_QOS_H

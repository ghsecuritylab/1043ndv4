/*
 * Copyright (c) 2008, Atheros Communications Inc.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ifndef _ATHR_PHY_H
#define _ATHR_PHY_H


#include <linux/types.h>
#include <linux/spinlock_types.h>
#include <linux/workqueue.h>
#include <asm/system.h>
#include <linux/netdevice.h>

#if defined(CONFIG_MACH_AR7240)
#include "ag7240.h"
#include "ar7240.h"
#define is_ar7100() 0
#elif defined(CONFIG_MACH_AR7100)
#include "ag7100.h"
#include "ar7100.h"
#define is_ar7100() 1
#define is_ar7240() 0
#define is_ar7241() 0
#define is_ar7242() 0
#ifdef CONFIG_AR9100
#define is_ar9100() 1
#endif
#endif

/* Modified by zhl, 31Aug2010, for replacing s26 with RTL8367r. */
#if defined(CONFIG_AR7240_S26_PHY) || defined(CONFIG_ATHRS26_PHY)
#include "ar7240_s26_phy.h"
#endif

#ifdef CONFIG_ATHRS27_PHY
#include "athrs27_phy.h"
#endif

#if defined(CONFIG_AR7242_RGMII_PHY) || defined(CONFIG_ATHRF1_PHY)
#include "athrf1_phy.h"
#endif

#ifdef CONFIG_ATHRS16_PHY
#include "athrs16_phy.h"
#endif

#ifdef CONFIG_RTL8367R_SWITCH
#include "ar7240_rtl8367r_phy.h"
//#include "ar7240_s26_phy.h"
#endif
/* End: Modified by zhl, 31Aug2010, for replacing s26 with RTL8367r. */

 
typedef struct {
    int  (*is_up)                (int ethUnit);
    int  (*is_alive)             (int phyUnit);
    int  (*speed)                (int ethUnit,int phyUnit);
    int  (*is_fdx)               (int ethUnit,int phyUnit);
    int  (*ioctl)                (struct net_device *dev,void *arg, int cmd);
    int  (*init)                 (void *arg);
    int  (*setup)                (void *arg); 
    void (*stab_wr)              (int phyUnit,int phy_up,int speed);
    void (*link_isr)             (void * arg);
    void (*en_link_intrs)        (void *arg);
    void (*dis_link_intrs)       (void *arg);
    unsigned int (*read_phy_reg) (int ethUnit,unsigned int phyUnit,unsigned int reg);
    void (*write_phy_reg)        (int ethUnit,unsigned int phyUnit,unsigned int reg,unsigned int val);
    unsigned int (*read_mac_reg) (unsigned int reg);
    void (*write_mac_reg)        (unsigned int reg,unsigned int val);
    void                         *mac;
}athr_phy_ops_t;

#endif

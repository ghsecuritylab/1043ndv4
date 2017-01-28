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

#ifndef _GMAC_DEFS_H
#define _GMAC_DEFS_H

#include "athrs_mac.h"
#include "athrs_phy.h"

/*
 * Function definitions. 
 */

static athr_gmac_t *athr_gmacs[ATHR_GMAC_NMACS];
/* virtual mac used by virtual interface */
static athr_gmac_t *virtual_mac;

static void athr_gmac_hw_setup(athr_gmac_t *mac);
static void athr_gmac_hw_stop(athr_gmac_t *mac);
static void athr_gmac_oom_timer(unsigned long data);
int  athr_gmac_check_link(void *arg,int phyUnit);
int  ag7242_check_link(athr_gmac_t *mac);
static int  athr_gmac_tx_alloc(athr_gmac_t *mac);
static int  athr_gmac_rx_alloc(athr_gmac_t *mac);
static void athr_gmac_rx_free(athr_gmac_t *mac);
static void athr_gmac_tx_free(athr_gmac_t *mac);
static int  athr_gmac_ring_alloc(athr_gmac_ring_t *r, int count);
static int  athr_gmac_rx_replenish(athr_gmac_t *mac);
static void athr_gmac_get_default_macaddr(athr_gmac_t *mac, u8 *mac_addr);
static int  athr_gmac_tx_reap(athr_gmac_t *mac,int ac);
static void athr_gmac_ring_release(athr_gmac_t *mac, athr_gmac_ring_t  *r);
static void athr_gmac_ring_free(athr_gmac_ring_t *r);

#ifdef CONFIG_AR7240_S26_VLAN_IGMP
#define ETH_VLAN_HLEN 18
#endif
  
static int  athr_gmac_recv_packets(struct net_device *dev, athr_gmac_t *mac,
    int max_work, int *work_done);
static struct sk_buff * athr_gmac_buffer_alloc(void);

static int tx_len_per_ds = 0;
static int tx_max_desc_per_ds_pkt=0;

/*
 * Externs
 */

extern void athr_gmac_timer_init(athr_gmac_t *mac);
extern void athr_gmac_timer_del(athr_gmac_t *mac);
#ifdef CONFIG_ATHRS_QOS
extern int set_mac_qops(athr_gmac_t *mac);
#endif


/* 
 * Global Defines 
 */

atomic_t Ledstatus;
int phy_in_reset = 0;
int rg_phy_speed = -1 , rg_phy_duplex = -1;
char *spd_str[] = {"10Mbps", "100Mbps", "1000Mbps"};
char *dup_str[] = {"half duplex", "full duplex"};

/*
 * Defines specific to this implemention
 */

#define addr_to_words(addr, w1, w2)  {                                 \
    w1 = (addr[0] << 24) | (addr[1] << 16) | (addr[2] << 8) | addr[3]; \
    w2 = (addr[4] << 24) | (addr[5] << 16) | 0;                        \
}

#ifndef CONFIG_ATHR_GMAC_LEN_PER_TX_DS
#error Please run menuconfig and define CONFIG_ATHR_GMAC_LEN_PER_TX_DS
#endif

#ifndef CONFIG_ATHR_GMAC_NUMBER_TX_PKTS
#error Please run menuconfig and define CONFIG_ATHR_GMAC_NUMBER_TX_PKTS
#endif

#ifndef CONFIG_ATHR_GMAC_NUMBER_RX_PKTS
#error Please run menuconfig and define CONFIG_ATHR_GMAC_NUMBER_RX_PKTS
#endif
#define ATHR_GMAC_TX_FIFO_LEN          2048
#define ATHR_GMAC_TX_MIN_DS_LEN        128
#define ATHR_GMAC_TX_MAX_DS_LEN        ATHR_GMAC_TX_FIFO_LEN

#define ATHR_GMAC_TX_MTU_LEN           1536

#define ATHR_GMAC_TX_DESC_CNT          CONFIG_ATHR_GMAC_NUMBER_TX_PKTS*tx_max_desc_per_ds_pkt
#define ATHR_GMAC_TX_REAP_THRESH       ATHR_GMAC_TX_DESC_CNT/2
#define ATHR_GMAC_TX_QSTART_THRESH     4*tx_max_desc_per_ds_pkt

#define ATHR_GMAC_RX_DESC_CNT          CONFIG_ATHR_GMAC_NUMBER_RX_PKTS

#define ATHR_GMAC_NAPI_WEIGHT          64
#define ATHR_PHY_POLL_SECONDS     2
#define ATHR_GMAC_LED_POLL_SECONDS    (HZ/10)

#define ENET_UNIT_LAN 1
#define ENET_UNIT_WAN 0

#define SW_PLL 0x1f000000ul

/*
 * Externs
 */

extern uint32_t ar7240_ahb_freq;
extern void ar7240_s26_intr(void);

/*
 * Inline functions
 */

static inline int
athr_gmac_ndesc_unused(athr_gmac_t *mac, athr_gmac_ring_t *ring)
{
    int head = ring->ring_head, tail = ring->ring_tail;

    return ((tail > head ? 0 : ring->ring_nelem) + tail - head);
}

static inline int athr_gmac_rx_ring_full(athr_gmac_t *mac)
{
    athr_gmac_ring_t *r    = &mac->mac_rxring;
    int            tail = r->ring_tail;

    return ((r->ring_head == tail) && !r->ring_buffer[tail].buf_pkt);
}

static inline void athr_gmac_set_mac_duplex(athr_gmac_t *mac, int fdx)
{
    if (fdx) {
        athr_gmac_reg_rmw_set(mac, ATHR_GMAC_CFG2, ATHR_GMAC_CFG2_FDX);
    }
    else {
        athr_gmac_reg_rmw_clear(mac, ATHR_GMAC_CFG2, ATHR_GMAC_CFG2_FDX);
    }
}

static inline void athr_gmac_set_mac_if(athr_gmac_t *mac, int is_1000)
{
    athr_gmac_reg_rmw_clear(mac, ATHR_GMAC_CFG2, (ATHR_GMAC_CFG2_IF_1000|
                         ATHR_GMAC_CFG2_IF_10_100));
    if (is_1000) {
        athr_gmac_reg_rmw_set(mac, ATHR_GMAC_CFG2, ATHR_GMAC_CFG2_IF_1000);
        athr_gmac_reg_rmw_set(mac, ATHR_GMAC_FIFO_CFG_5, ATHR_GMAC_BYTE_PER_CLK_EN);
    }
    else {
        athr_gmac_reg_rmw_set(mac, ATHR_GMAC_CFG2, ATHR_GMAC_CFG2_IF_10_100);
        athr_gmac_reg_rmw_clear(mac,ATHR_GMAC_FIFO_CFG_5, ATHR_GMAC_BYTE_PER_CLK_EN);
    }
}

static inline void athr_gmac_set_mac_speed(athr_gmac_t *mac, int is100)
{
    if (is100) {
        athr_gmac_reg_rmw_set(mac, ATHR_GMAC_IFCTL, ATHR_GMAC_IFCTL_SPEED);
    }
    else {
        athr_gmac_reg_rmw_clear(mac, ATHR_GMAC_IFCTL, ATHR_GMAC_IFCTL_SPEED);
    }
}

static inline int athr_gmac_tx_reap_thresh(athr_gmac_t *mac,int ac)
{
    athr_gmac_ring_t *r = &mac->mac_txring[ac];

    return (athr_gmac_ndesc_unused(mac, r) < ATHR_GMAC_TX_REAP_THRESH);
}

static inline int athr_gmac_tx_ring_full(athr_gmac_t *mac,int ac)
{
    athr_gmac_ring_t *r = &mac->mac_txring[ac];

    athr_gmac_trc_new(athr_gmac_ndesc_unused(mac, r),"tx ring full");
    return (athr_gmac_ndesc_unused(mac, r) < tx_max_desc_per_ds_pkt + 2);
}
static int ATHR_MAC_POLL();

static irqreturn_t athr_gmac_intr(ATHR_MAC_ISR_ARGS);

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,31))
static struct net_device_ops athr_gmac_net_ops[2];
static struct net_device_ops *p_athr_gmac_net_ops;
#endif

static void athr_gmac_tx_timeout_task(ATHR_MAC_TASK_ARG);

static int ATHR_MAC_POLL();

static irqreturn_t athr_gmac_intr(ATHR_MAC_ISR_ARGS);


#endif

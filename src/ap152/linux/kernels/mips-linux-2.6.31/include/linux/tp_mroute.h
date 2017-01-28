#ifndef _TP_MROUTE_H
#define _TP_MROUTE_H

#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/spinlock.h>
#include <linux/list.h>

#include <linux/igmp.h>

/* 
	if dual band wireless router, it will has 8 vaps at
	best. so we use 0x00ff0000 flags to mark which
	vap join to or leave igmp group. Mark 0x000f0000 is used for
	4 vaps of 2G while 0x00f00000 is used for 4 vaps of 5G.
	for example, mark 0x00010000 means the 1st vap of 2G.
	mark 0x00100000 means the first vap of 5G
*/
#define WLAN_IGMP_MEMBER_MARK		(0x00ff0000)

/*
	if all igmp client of one vap leave that igmp group
	skb->mark from wlan must has the mark 0x01000000.
	for example, if the 1st vap 0f 2G has no members in igmp
	group1, the skb->mark from wlan will be set as like
	0x01010000
*/
#define WLAN_IGMP_NO_MEMBER_MARK	(0x01000000)

#ifdef CONFIG_TP_MULTICAST	/* start added by huanglifu 2012/07/02. for Vietnam viettel isp demand that IPTV VLAN IGMP Snooping */
#define VLAN_IPTV_IGMP_SNOOPING 
int tp_mr_classify_iptv(struct sk_buff *skb);
int vlan_netlink(void);

/* the flag means skb from WAN to LAN(include ethernet LAN and Wireless) */
#define IGMP_DATA_DOWN_FLAG			(0x10000000)

#endif

#define MAX_GROUP_ENTRIES 64
#define MAX_HASH_ENTRIES 256

#define IGMP_ALL_HOST_ADDR htonl(0xE0000001L)
#define IGMP_ALL_ROUTER_ADDR htonl(0xE0000002L)

#define QUERY_RESPONSE_INTERVAL_NUM 10
#define QUERY_RESPONSE_INTERVAL (QUERY_RESPONSE_INTERVAL_NUM * HZ)
#define QUERY_INTERVAL (125 * HZ)
#define ROBUSTNESS_VARIABLE 2
#define GROUP_MEMBER_SHIP_INTERVAL ((ROBUSTNESS_VARIABLE) * (QUERY_INTERVAL) + QUERY_RESPONSE_INTERVAL)

#define HASH256(addr) ((addr)&0xFF)

struct mc_entry
{
	struct hlist_node head;
	__u32 mc_addr;
	__u32 membership_flag;
	__u32 need_delete_mark;	/* added by kuangguiming 13Dec25 */
	__u8 reported;
	struct	dst_entry	*dst;
	struct timer_list wan_qr_timer;
	struct timer_list lan_qr_timer;  /* added by kuangguiming 13Dec25 */
};

struct mc_table
{
	struct mc_entry entry[MAX_GROUP_ENTRIES];
	struct hlist_head mc_hash[MAX_HASH_ENTRIES];
	struct hlist_head empty_list;
	struct timer_list generl_query_timer;
	struct timer_list report_checking_timer;
	spinlock_t lock;
	__u8 groups;
};

/*  by huangwenzhong, 13Sep12 */
#ifdef CONFIG_PROC_FS

#define	TP_MROUTE_DIR_NAME				"tp_mroute"
#define	TP_MROUTE_ENABLE_FILE_NAME		"tp_mroute_enable"
#define	TP_MROUTE_LAN_BR_FILE_NAME		"lan_br_name"
#define TP_MROUTE_LAN_ETH_FILE_NAME		"lan_eth_name"
#define TP_MROUTE_WAN_ETH_FILE_NAME		"wan_eth_name"

#endif

int tp_mroute_is_enable(void);

int mc_table_init(void);
int tp_mr_classify(struct sk_buff *skb);
int lan_heard_igmp_report(struct sk_buff *skb, __u32 group);
int lan_heard_igmp_leave(struct sk_buff *skb, __u32 group);
int wan_heard_igmp_report(struct sk_buff *skb, __u32 group);
int wan_heard_igmp_query(struct sk_buff *skb, struct igmphdr *ih, __u32 daddr);
int find_data_path(struct sk_buff *skb, __u32 group);

int tp_send_mc(struct sk_buff *skb, struct net_device *dev);

#endif


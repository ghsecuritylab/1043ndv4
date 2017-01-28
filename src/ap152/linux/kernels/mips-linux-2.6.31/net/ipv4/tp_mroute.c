/*!Copyright(c) 2008-2010 Shenzhen TP-LINK Technologies Co.Ltd.
 *
 *\file	tp_mroute.c
 *\brief	IGMP & Mcast UDP diliver module. 
 *
 *\author	Wang Wenhao
 *\version	1.0.1
 *\date	05Jan10
 *
 *\history 

 * 		\arg 1.0.3, 03Dec10, Hou Xubo，增加对2.6.31内核的支持
 *                                             
 *
 * 		\arg 1.0.2, 06May10, Yin Zhongtao，增加对WLAN的组播转发支持，修复WAN口QUERY问题，
 *                                             优化了组播数据转发效率
 *
 *		\arg 1.0.1, 05Jan10, Wang Wenhao, 将IGMP包和UDP转发分开发送，解决UDP可能找不到路由的问题.
 *											通过查找静态路由获取dst，解决可能出现的kernel panic. 
 * 				    
 *		\arg 1.0.0, ???, Wang Wenhao, Create the file.
 */

#include <linux/types.h>
#include <linux/tp_mroute.h>
#include <linux/igmp.h>
#include <linux/netdevice.h>
#include <net/ip.h>

/* add support for kernel 2.6.31. by HouXB, 03Dec10 */
#include <linux/version.h>

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,31))
#include <net/route.h>
#include <linux/seq_file.h>
#endif

#define WLAN_IGMP_MARK				(0x00010000)

#ifdef VLAN_IPTV_IGMP_SNOOPING
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/sched.h>
#include <net/sock.h>
#include <net/netlink.h>
#endif

/*start added by huanglifu 2012/07/02. for Vietnam viettel isp demand that IPTV VLAN IGMP Snooping*/
#ifdef VLAN_IPTV_IGMP_SNOOPING
#define NETLINK_TEST 21
struct sock *nl_sk = NULL;
EXPORT_SYMBOL_GPL(nl_sk);

#define NET_DEV_NAME_LEN 20
char inet_lan[NET_DEV_NAME_LEN];
char inet_wan[NET_DEV_NAME_LEN];
char iptv_lan[NET_DEV_NAME_LEN];
char iptv_wan[NET_DEV_NAME_LEN];
char iptv_br[NET_DEV_NAME_LEN];

char multi_iptv_lan[NET_DEV_NAME_LEN];
char multi_iptv_wan[NET_DEV_NAME_LEN];
char multi_iptv_br[NET_DEV_NAME_LEN];

char ipphone_lan[NET_DEV_NAME_LEN];
char ipphone_wan[NET_DEV_NAME_LEN];
char ipphone_br[NET_DEV_NAME_LEN];
int vlanOn = 0;

struct net_device *inet_eth0_dev = NULL;
struct net_device *inet_eth1_dev = NULL;
struct net_device *iptv_eth0_dev = NULL;
struct net_device *iptv_eth1_dev = NULL;
struct net_device *iptv_br_dev = NULL;

struct net_device *multi_iptv_eth0_dev = NULL;
struct net_device *multi_iptv_eth1_dev = NULL;
struct net_device *multi_iptv_br_dev = NULL;

struct net_device *ipphone_eth0_dev = NULL;
struct net_device *ipphone_eth1_dev = NULL;
struct net_device *ipphone_br_dev = NULL;

int iptv_br_index = -1;
int inet_eth0_index = -1;
int inet_eth1_index = -1;
int iptv_eth0_index = -1;
int iptv_eth1_index = -1;

int multi_iptv_br_index = -1;
int multi_iptv_eth0_index = -1;
int multi_iptv_eth1_index = -1;

int ipphone_br_index = -1;
int ipphone_eth0_index = -1;
int ipphone_eth1_index = -1;

#endif  /* VLAN_IPTV_IGMP_SNOOPING */


//#define TEST_DEBUG
#ifdef TEST_DEBUG
#define debugk(x) printk(x)
#else
#define debugk(X)
#endif

#if 0
static void dumpHexData(unsigned char *head, int len)
{
    int i;
    unsigned char *curPtr = head;

    for (i = 0; i < len; ++i) {
		if (!i)
			;
		else if ((i & 0xF) == 0)
            printk("\n"); 
		else if ((i & 0x7) == 0)
            printk("- ");
        printk("%02X ", *curPtr++);
    }
    printk("\n\n");
}
#endif

#define IGMP_SIZE (sizeof(struct igmphdr)+sizeof(struct iphdr)+4)

static int initialed = 0;

struct net_device *br1_dev = NULL;
int have_ru_br1 = 0;

/*  by huangwenzhong, 13Sep12 */
static unsigned char lan_br_name[IFNAMSIZ] = "br0";/* default value is br0 */
static unsigned char lan_eth_name[IFNAMSIZ] = "eth0.1";/* default value is eth0 */
static unsigned char wan_eth_name[IFNAMSIZ] = "eth0.2";/* default value is eth1 */

static struct net_device *lan_br_dev = NULL;
static struct net_device *lan_eth_dev = NULL;
static struct net_device *wan_eth_dev = NULL;

static int lan_br_index = -1;
static int lan_eth_index = -1;
static int wan_eth_index = -1;

#define CONFIG_TP_MULTICAST_SWITCH	(1)
static int tp_mroute_enable = 0;

static struct mc_table table;

static void disable_tp_mroute(void);


/*  by huangwenzhong, 13Sep12 */
/* 
add proc for lan_br_name, lan_eth_name and wan_eth_name, 
so that they can be configurable.
*/

#ifdef CONFIG_PROC_FS
struct proc_dir_entry *tp_mroute_dir_entry = NULL;
struct proc_dir_entry *tp_mroute_enable_entry = NULL;
struct proc_dir_entry *tp_mroute_lan_br_entry = NULL;
struct proc_dir_entry *tp_mroute_lan_eth_entry = NULL;
struct proc_dir_entry *tp_mroute_wan_eth_entry = NULL;

static int tp_mroute_enable_read (char *page, char **start, off_t off,
                               int count, int *eof, void *data)
{

	//printk("(%s)%d, tp_arp_enable = %d\n", __FUNCTION__, __LINE__, tp_arp_enable);
    return sprintf (page, "%d\n", tp_mroute_enable);
}

static int tp_mroute_enable_write (struct file *file, const char *buf,
                                        unsigned long count, void *data)
{
    int val;

	if (sscanf(buf, "%d", &val) != 1)
	{
        return -EINVAL;
	}
	
	if ((val != 0) && (val != 1))
	{
		return -EINVAL;
	}
	
	tp_mroute_enable = val;

	if (!tp_mroute_enable)
	{
		disable_tp_mroute();
	}
	else
	{	
		if (!initialed)
		{
			mc_table_init();
		}
		
		//table.generl_query_timer.expires = jiffies + QUERY_INTERVAL;
		if (timer_pending(&(table.generl_query_timer)))
		{
			mod_timer(&(table.generl_query_timer), jiffies + 2);
		}
		else
		{
			table.generl_query_timer.expires = jiffies + 2;
    		add_timer(&table.generl_query_timer);
		}
	}
	
	return count;
}

static int tp_mroute_lan_br_read (char *page, char **start, off_t off,
                               int count, int *eof, void *data)
{
    return sprintf (page, "%s\n", lan_br_name);
}

static int tp_mroute_lan_br_write (struct file *file, const char *buf,
                                        unsigned long count, void *data)
{
    unsigned char if_name[IFNAMSIZ] = {0};
	//int i = 0;

	if (sscanf(buf, "%s", if_name) != 1)
	{
        return -EINVAL;
	}

	if (if_name[0] == '\0')
	{
		return -EINVAL;
	}

	memcpy(lan_br_name, if_name, IFNAMSIZ);
	
	return count;
}

static int tp_mroute_lan_eth_read (char *page, char **start, off_t off,
                               int count, int *eof, void *data)
{
    return sprintf (page, "%s\n", lan_eth_name);
}

static int tp_mroute_lan_eth_write (struct file *file, const char *buf,
                                        unsigned long count, void *data)
{
    unsigned char if_name[IFNAMSIZ] = {0};
	//int i = 0;

	if (sscanf(buf, "%s", if_name) != 1)
	{
        return -EINVAL;
	}

	if (if_name[0] == '\0')
	{
		return -EINVAL;
	}

	memcpy(lan_eth_name, if_name, IFNAMSIZ);
	
	return count;
}


static int tp_mroute_wan_eth_read (char *page, char **start, off_t off,
                               int count, int *eof, void *data)
{
    return sprintf (page, "%s\n", wan_eth_name);
}

static int tp_mroute_wan_eth_write (struct file *file, const char *buf,
                                        unsigned long count, void *data)
{
    unsigned char if_name[IFNAMSIZ] = {0};
	//int i = 0;

	if (sscanf(buf, "%s", if_name) != 1)
	{
        return -EINVAL;
	}

	if (if_name[0] == '\0')
	{
		return -EINVAL;
	}

	memcpy(wan_eth_name, if_name, IFNAMSIZ);
	
	return count;
}


static int tp_mroute_proc_init(void)
{
	tp_mroute_dir_entry = proc_mkdir(TP_MROUTE_DIR_NAME, init_net.proc_net);
	if (!tp_mroute_dir_entry)
	{
		printk("(%s,%d)cannot %s proc entry", __FUNCTION__, __LINE__, TP_MROUTE_DIR_NAME);
		return -ENOENT;
	}
	
	tp_mroute_enable_entry = create_proc_entry(TP_MROUTE_ENABLE_FILE_NAME, 0666, tp_mroute_dir_entry);
	if (!tp_mroute_enable_entry)
	{
		printk("(%s,%d)cannot create %s proc entry", __FUNCTION__, __LINE__, TP_MROUTE_ENABLE_FILE_NAME);
		return -ENOENT;
	}
	tp_mroute_enable_entry->write_proc = tp_mroute_enable_write;
	tp_mroute_enable_entry->read_proc	= tp_mroute_enable_read;

	tp_mroute_lan_br_entry = create_proc_entry(TP_MROUTE_LAN_BR_FILE_NAME, 0666, tp_mroute_dir_entry);
	if (!tp_mroute_lan_br_entry)
	{
		printk("(%s,%d)cannot create %s proc entry", __FUNCTION__, __LINE__, TP_MROUTE_LAN_BR_FILE_NAME);
		return -ENOENT;
	}
	tp_mroute_lan_br_entry->write_proc = tp_mroute_lan_br_write;
	tp_mroute_lan_br_entry->read_proc	= tp_mroute_lan_br_read;

	tp_mroute_lan_eth_entry = create_proc_entry(TP_MROUTE_LAN_ETH_FILE_NAME, 0666, tp_mroute_dir_entry);
	if (!tp_mroute_lan_eth_entry)
	{
		printk("(%s,%d)cannot create %s proc entry", __FUNCTION__, __LINE__, TP_MROUTE_LAN_ETH_FILE_NAME);
		return -ENOENT;
	}
	tp_mroute_lan_eth_entry->write_proc = tp_mroute_lan_eth_write;
	tp_mroute_lan_eth_entry->read_proc	= tp_mroute_lan_eth_read;

	tp_mroute_wan_eth_entry = create_proc_entry(TP_MROUTE_WAN_ETH_FILE_NAME, 0666, tp_mroute_dir_entry);
	if (!tp_mroute_wan_eth_entry)
	{
		printk("(%s,%d)cannot create %s proc entry", __FUNCTION__, __LINE__, TP_MROUTE_WAN_ETH_FILE_NAME);
		return -ENOENT;
	}
	tp_mroute_wan_eth_entry->write_proc = tp_mroute_wan_eth_write;
	tp_mroute_wan_eth_entry->read_proc	= tp_mroute_wan_eth_read;

	return 0;
}


static void tp_mroute_proc_exit(void)
{
	if (tp_mroute_wan_eth_entry)
	{
		remove_proc_entry(TP_MROUTE_WAN_ETH_FILE_NAME, tp_mroute_dir_entry);
	}

	if (tp_mroute_lan_eth_entry)
	{
		remove_proc_entry(TP_MROUTE_LAN_ETH_FILE_NAME, tp_mroute_dir_entry);
	}

	if (tp_mroute_lan_br_entry)
	{
		remove_proc_entry(TP_MROUTE_LAN_BR_FILE_NAME, tp_mroute_dir_entry);
	}

	if (tp_mroute_enable_entry)
	{
		remove_proc_entry(TP_MROUTE_ENABLE_FILE_NAME, tp_mroute_dir_entry);
	}

	if (tp_mroute_dir_entry)
	{
		remove_proc_entry(TP_MROUTE_DIR_NAME, init_net.proc_net);
	}	

	return;
}


#endif

int tp_mroute_is_enable(void)
{
	return tp_mroute_enable;
}



/*
 * 	create IGMP packet's IP header
 */
static struct sk_buff *create_igmp_ip_skb(struct net_device *dev, __u32 daddr)
{
    struct sk_buff *skb;
    struct iphdr *iph;
//  struct in_device *in_dev;
	struct rtable *rt;

/* added by HouXB, 03Dec10 */
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,31))
	struct net *net =  dev_net(dev);
#endif
	

	//copy from igmp.c
    struct flowi fl = { .oif = dev->ifindex,
                .nl_u = { .ip4_u = { .daddr = daddr } },
                .proto = IPPROTO_IGMP };

	//eth0 don't have static route, use br0 instead
    if (dev->ifindex == lan_eth_index)
    {
        fl.oif = lan_br_index;
    }
/* added by HouXB, 03Dec10 */
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,31))
	if (ip_route_output_key(net, &rt, &fl))
#else
	if (ip_route_output_key(&rt, &fl))
#endif
    {
        printk("Ooops, static route igmp error!\n");
        return NULL;
    }
    
    if (rt->rt_src == 0)
    {
        debugk("no igmp route source\n");
		ip_rt_put(rt);
		return NULL;
	}

    skb = alloc_skb(IGMP_SIZE+LL_RESERVED_SPACE(dev), GFP_ATOMIC);
	if (skb == NULL)
    {
		printk("Ooops, route igmp alloc skb failed.\n");
		ip_rt_put(rt);
		return NULL;
	}

/* added by HouXB, 03Dec10 */
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,31))
	skb_dst_set(skb, &rt->u.dst);
#else
	skb->dst = &rt->u.dst;
#endif

	skb_reserve(skb, LL_RESERVED_SPACE(dev));
	iph = (struct iphdr *)skb_put(skb, sizeof(struct iphdr) + 4);
	
/* added by HouXB, 03Dec10 */
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,31))	
	skb->network_header = (sk_buff_data_t)iph;	
#else
	skb->nh.iph = iph;
#endif	

	iph->version  = 4;
	iph->ihl      = (sizeof(struct iphdr)+4) >> 2;
	iph->tos      = 0xc0;
	iph->frag_off = htons(IP_DF);
	iph->ttl      = 1;
	iph->daddr    = daddr;
	iph->saddr    = rt->rt_src;
#ifdef TEST_DEBUG
	printk("saddr = %x; daddr = %x; oif = %s\n", iph->saddr, iph->daddr, skb_dst(skb)->dev->name);
#endif

	iph->protocol = IPPROTO_IGMP;
	iph->tot_len  = htons(IGMP_SIZE);
	ip_select_ident(iph, &rt->u.dst, NULL);

	((u8*)&iph[1])[0] = IPOPT_RA;
	((u8*)&iph[1])[1] = 4;
	((u8*)&iph[1])[2] = 0;
	((u8*)&iph[1])[3] = 0;
	ip_send_check(iph);

    return skb;
}

/*
 *	fulfill IGMP report header and send 
 */
static int tp_send_igmp_report(struct net_device *dev, __u32 daddr)
{
    struct sk_buff *skb;
    struct igmphdr *ih;
    if (NULL == dev)
    {
        return -1;
    }
    
    if ((skb = create_igmp_ip_skb(dev, daddr)) == NULL)
    {
        return -1;
    }

	ih = (struct igmphdr *)skb_put(skb, sizeof(struct igmphdr));
	ih->type = IGMPV2_HOST_MEMBERSHIP_REPORT;
	ih->code = 0;
	ih->csum = 0;
	ih->group = daddr;
	ih->csum = ip_compute_csum((void *)ih, sizeof(struct igmphdr));

	/*
	printk("============\n");
	printk("(HouXB-tp_mroute:tp_send_igmp_report) send igmp report, use dev %s\n", dev->name);
	dumpHexData(skb->data, skb->len);
	printk("============\n");
	*/

    return ip_output(skb);
}

/*
 *	fulfill IGMP query header and send 
 */
static int tp_send_igmp_query(struct net_device *dev, __u32 daddr, __u32 group, __u8 delay)
{
    struct sk_buff *skb;
    struct igmphdr *ih;
	if (NULL == dev)
	{
	    return -1;
	}
    
    if ((skb = create_igmp_ip_skb(dev, daddr)) == NULL)
    {
        debugk("create IGMP pack failed\n");
        return -1;
    }

	ih = (struct igmphdr *)skb_put(skb, sizeof(struct igmphdr));
	ih->type = IGMP_HOST_MEMBERSHIP_QUERY;
	ih->code = delay;
	ih->csum = 0;
	ih->group = group;
	ih->csum = ip_compute_csum((void *)ih, sizeof(struct igmphdr));

    return ip_output(skb);
}

/*
 *	fulfill IGMP leave header and send 
 */
static int tp_send_igmp_leave(struct net_device *dev, __u32 group)
{
    struct sk_buff *skb;
    struct igmphdr *ih;
    if (NULL == dev)
    {
        return -1;
    }
    
    if ((skb = create_igmp_ip_skb(dev, IGMP_ALL_ROUTER_ADDR)) == NULL)
    {
        return -1;
    }

	ih = (struct igmphdr *)skb_put(skb, sizeof(struct igmphdr));
	ih->type = IGMP_HOST_LEAVE_MESSAGE;
	ih->code = 0;
	ih->csum = 0;
	ih->group = group;
	ih->csum = ip_compute_csum((void *)ih, sizeof(struct igmphdr));

    return ip_output(skb);

}

/*
 *	send general query only
 */
static void general_query_send(char *dev_name)
{
    debugk("send general query\n");

/* added by HouXB, 03Dec10 */
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,31))
lan_br_dev = dev_get_by_name(&init_net, dev_name);
#else
lan_br_dev = dev_get_by_name(dev_name);
#endif	
    
    if (tp_send_igmp_query(lan_br_dev, IGMP_ALL_HOST_ADDR, 0, QUERY_RESPONSE_INTERVAL_NUM * 10))
    {
        printk("Ooops, general query send failed!\n");
    }

	dev_put(lan_br_dev);
	
}

/*
 *	g-q timer expired, send general query & reset timer
 */
static void general_query_timer_expired(unsigned long data)
{
    debugk("g-q tiemer expired\n");

	if (!tp_mroute_enable)/* if IGMP is disabled, stop it */
	{
		table.generl_query_timer.expires = jiffies + QUERY_INTERVAL;
    	add_timer(&table.generl_query_timer);
		return;
	}	
	
/* added by HouXB, 03Dec10 */
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,31))
	lan_br_dev = dev_get_by_name(&init_net, lan_br_name);
#else
	lan_br_dev = dev_get_by_name(lan_br_name);
#endif	
    
    if (tp_send_igmp_query(lan_br_dev, IGMP_ALL_HOST_ADDR, 0, QUERY_RESPONSE_INTERVAL_NUM * 10))
    {
        printk("Ooops, general query send failed!\n");
    }

	dev_put(lan_br_dev);
    
    table.generl_query_timer.expires = jiffies + QUERY_INTERVAL;
    add_timer(&table.generl_query_timer);

	return;
}

/*
 *	r-c timer expired, check all items, remove the unreported one
 */
static void report_checking_timer_expired(unsigned long data)
{
    int i;

    struct mc_entry *mcp;

	debugk("r-c timer expired\n");

    for (i = 0; i < MAX_GROUP_ENTRIES; i++)
    {
        mcp = &table.entry[i];
		//if mcp->mc_addr is 0, it must not be used
        if (!mcp->reported && mcp->mc_addr)
        {
			//the timer of the removing item must be stopped
            if (timer_pending(&mcp->wan_qr_timer))
            {
                del_timer(&mcp->wan_qr_timer);
            }

	    if (timer_pending(&mcp->lan_qr_timer))
	    {
		del_timer(&mcp->lan_qr_timer);
	    }

            spin_lock_bh(table.lock);
            __hlist_del((struct hlist_node *)mcp);
            hlist_add_head((struct hlist_node *)mcp, &table.empty_list);
            table.groups--;
            spin_unlock_bh(table.lock);
			
/* added by HouXB, 03Dec10 */
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,31))
#ifdef VLAN_IPTV_IGMP_SNOOPING
			if (vlanOn == 1)
			{
				wan_eth_dev = inet_eth1_dev;
			}
			else
			{
#endif
			if (have_ru_br1)
			{
				wan_eth_dev = dev_get_by_name(&init_net, "br1");
			}
			else
			{
			wan_eth_dev = dev_get_by_name(&init_net, wan_eth_name);
			}
#ifdef VLAN_IPTV_IGMP_SNOOPING
			}
#endif

#else
			if (have_ru_br1)
			{
				wan_eth_dev = dev_get_by_name("br1");
			}
			else
			{
				wan_eth_dev = dev_get_by_name(wan_eth_name);
			}
#endif	
		
            if (NULL != wan_eth_dev)
            {
            tp_send_igmp_leave(wan_eth_dev, mcp->mc_addr);
			dev_put(wan_eth_dev);
            }
			else
			{
				printk("[%s]dev %s is null now\n", __FUNCTION__, have_ru_br1 ? "br1" : wan_eth_name);
			}
			
            mcp->mc_addr = 0;
			mcp->need_delete_mark = 0;
			if(mcp->dst)
			{
				dst_release(mcp->dst);
				mcp->dst = NULL;
			}

            debugk("del some tips from mc_table\n");
        }
		// clear the report flag
        mcp->reported = 0;
    }

	// if no tips alive, stop all function
    if (!table.groups)
    {
		//keep g-q timer, yzt 2010-02-21
        //del_timer(&table.generl_query_timer);
        if (timer_pending(&table.report_checking_timer))
        {
            del_timer(&table.report_checking_timer);
        }

        return;
    }
    
    table.report_checking_timer.expires = jiffies + GROUP_MEMBER_SHIP_INTERVAL;
    add_timer(&table.report_checking_timer);
}

static void all_group_send_igmp_leave(void)
{
	int i;
    struct mc_entry *mcp = NULL;

    for (i = 0; i < MAX_GROUP_ENTRIES; i++)
    {
        mcp = &table.entry[i];
		
        if (mcp->mc_addr)
        {
			//the timer of the removing item must be stopped
            if (timer_pending(&mcp->wan_qr_timer))
            {
                del_timer(&mcp->wan_qr_timer);
            }

			/* added by kuangguiming 13Dec25 */
			if (timer_pending(&mcp->lan_qr_timer))
			{
				del_timer(&mcp->lan_qr_timer);
			}
			/* end add */

            spin_lock_bh(table.lock);
            __hlist_del((struct hlist_node *)mcp);
            hlist_add_head((struct hlist_node *)mcp, &table.empty_list);
            table.groups--;
            spin_unlock_bh(table.lock);
			
/* added by HouXB, 03Dec10 */
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,31))
			wan_eth_dev = dev_get_by_name(&init_net, wan_eth_name);
#else
			wan_eth_dev = dev_get_by_name(wan_eth_name);
#endif		
            if (NULL != wan_eth_dev)
            {
            tp_send_igmp_leave(wan_eth_dev, mcp->mc_addr);
			dev_put(wan_eth_dev);
            }
			else
			{
				printk("[%s]dev %s is null now\n", __FUNCTION__, have_ru_br1 ? "br1" : wan_eth_name);
			}
			
            mcp->mc_addr = 0;
			mcp->need_delete_mark = 0;    /* added by kuangguiming */
			if(mcp->dst)
			{
				dst_release(mcp->dst);
				mcp->dst = NULL;
			}
        }
		// clear the report flag
        mcp->reported = 0;
    }

	// if no tips alive, stop all function
    if (!table.groups)
    {
		//keep g-q timer, yzt 2010-02-21
        if (timer_pending(&table.report_checking_timer))
        {
            del_timer(&table.report_checking_timer);
        }
		
		printk("(%s)%d, has delete all IGMP groups and timer\n", __FUNCTION__, __LINE__);
    }

	return;
    
}


/*
 *	wan q-r timer expired, send report to wan port
 */
static void wan_qr_timer_expired(unsigned long data)
{
    int i = (int) data;
	
    struct mc_entry *mcp = &table.entry[i];

	debugk("wan q-r timer expired\n");

/* added by HouXB, 03Dec10 */
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,31))
#ifdef VLAN_IPTV_IGMP_SNOOPING
	if (vlanOn == 1)
	{
		wan_eth_dev = inet_eth1_dev;
	}
	else
	{
#endif
	if (have_ru_br1)
	{
		wan_eth_dev = dev_get_by_name(&init_net, "br1");
	}
	else
	{
			wan_eth_dev = dev_get_by_name(&init_net, wan_eth_name);
	}
#ifdef VLAN_IPTV_IGMP_SNOOPING
	}
#endif

#else
	if (have_ru_br1)
	{
		wan_eth_dev = dev_get_by_name("br1");
	}
	else
	{
			wan_eth_dev = dev_get_by_name(wan_eth_name);
	}
#endif	
    if (NULL != wan_eth_dev)
    {
    tp_send_igmp_report(wan_eth_dev, mcp->mc_addr);
	dev_put(wan_eth_dev);
}
	else
	{
	    printk("[%s]dev %s is null now\n", __FUNCTION__, have_ru_br1 ? "br1" : wan_eth_name);
	}
}

/* lan q-r timer expired, delete the membership */
static void lan_qr_timer_expired(unsigned long data)
{
    int i = (int) data;
	
    struct mc_entry *mcp = &table.entry[i];	

	debugk("lan q-r timer expired\n");
	if (mcp)
	{
		mcp->membership_flag &= (~(mcp->need_delete_mark));
		
		//if no port alive, delete item
        if (!mcp->membership_flag)
        {
            if (timer_pending(&mcp->wan_qr_timer))
            {
                del_timer(&mcp->wan_qr_timer);
            }

			if (timer_pending(&mcp->lan_qr_timer))
            {
                del_timer(&mcp->lan_qr_timer);
            }
            
            spin_lock_bh(table.lock);
            __hlist_del((struct hlist_node *)mcp);
            hlist_add_head((struct hlist_node *)mcp, &table.empty_list);
            table.groups--;
            spin_unlock_bh(table.lock);
			//send leave packet to wan
			
/* added by HouXB, 03Dec10 */
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,31))
#ifdef VLAN_IPTV_IGMP_SNOOPING
			if(vlanOn == 1)
			{
				wan_eth_dev = inet_eth1_dev;
			}
			else
			{
#endif
				if (have_ru_br1)
				{
					wan_eth_dev = dev_get_by_name(&init_net, "br1");
				}
				else
				{
					wan_eth_dev = dev_get_by_name(&init_net, wan_eth_name);
				}
#ifdef VLAN_IPTV_IGMP_SNOOPING
			}
#endif

#else
			if (have_ru_br1)
			{
				wan_eth_dev = dev_get_by_name("br1");
			}
			else
			{
				wan_eth_dev = dev_get_by_name(wan_eth_name);
			}
#endif	
            if (NULL != wan_eth_dev)
            {
            tp_send_igmp_leave(wan_eth_dev, mcp->mc_addr);
			dev_put(wan_eth_dev);
            }
			else
			{
			    printk("[%s]dev %s is null now\n", __FUNCTION__, have_ru_br1 ? "br1" : wan_eth_name);

			}
			
            mcp->mc_addr = 0;			
			if(mcp->dst)
			{
				dst_release(mcp->dst);
				mcp->dst = NULL;
			}
			
            debugk("some tips removed from mc_table\n");
          
            if (!table.groups)
            {
				//keep g-q timer, yzt 2010-02-21
                //del_timer(&table.generl_query_timer);
                del_timer(&table.report_checking_timer);
            }
        }
	}
}

/*
 * initaily get the device pointer
 */
static int update_dev_index(void)
{
/* added by HouXB, 03Dec10 */
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,31))
    lan_br_dev = dev_get_by_name(&init_net, lan_br_name);
    lan_eth_dev = dev_get_by_name(&init_net, lan_eth_name);
    //eth1_dev = dev_get_by_name(&init_net, "eth1");
    if (have_ru_br1)
	{
		wan_eth_dev = dev_get_by_name(&init_net, "br1");
	}
	else
	{
    wan_eth_dev = dev_get_by_name(&init_net, wan_eth_name);
	}
#else
    lan_br_dev = dev_get_by_name(lan_br_name);
    lan_eth_dev = dev_get_by_name(lan_eth_name);
    //eth1_dev = dev_get_by_name("eth1");
    if (have_ru_br1)
	{
		wan_eth_dev = dev_get_by_name("br1");
	}
	else
	{
    wan_eth_dev = dev_get_by_name(wan_eth_name);
	}
#endif	

    if (lan_br_dev && lan_eth_dev && wan_eth_dev)
    {
		lan_br_index = lan_br_dev->ifindex;
		lan_eth_index = lan_eth_dev->ifindex;
		wan_eth_index = wan_eth_dev->ifindex;

		dev_put(lan_eth_dev);
		dev_put(wan_eth_dev);
		dev_put(lan_br_dev);
		
        return 0;
    }
    else
    {
        return -1;
    }
}

/*
 * find the items by the muticast group
 */
struct mc_entry *hlist_sort(__u32 group)
{
    struct hlist_node *hnp;
    struct mc_entry *mcp;
    
    for (hnp = table.mc_hash[HASH256(group)].first; hnp != NULL; hnp = hnp->next)
    {
        mcp = (struct mc_entry *)hnp;
        if (mcp->mc_addr == group)
        {
            return mcp;
        }
    }
    return NULL;
}

static void disable_tp_mroute(void)
{
	/* all groups must send leave msg to WAN */
	all_group_send_igmp_leave();
	return;
}

/*
 * initail the mc table, zero the muticast group, define the timer expire function
 */
int mc_table_init(void)
{
    int i;

    debugk("start initial\n");
    if (update_dev_index())
    {
        printk("Ooops, why the devices couldn't been initialed?\n");
        return -1;
    }
    
    for (i = 0; i < MAX_HASH_ENTRIES; i++)
    {
        table.mc_hash[i].first = NULL;
    }
    
    for (i = MAX_GROUP_ENTRIES - 1; i >= 0; i--)
    {
        hlist_add_head((struct hlist_node *)&table.entry[i], &table.empty_list);
        init_timer(&table.entry[i].wan_qr_timer);
        table.entry[i].wan_qr_timer.function = wan_qr_timer_expired;
        table.entry[i].wan_qr_timer.data = (unsigned long)i;
		/* added by kuangguiming 13Dec25 */
		init_timer(&table.entry[i].lan_qr_timer);
		table.entry[i].lan_qr_timer.function = lan_qr_timer_expired;
        table.entry[i].lan_qr_timer.data = (unsigned long)i;
		/* end add */
        table.entry[i].membership_flag = 0;
        table.entry[i].reported = 0;
        table.entry[i].mc_addr = 0;
		table.entry[i].need_delete_mark = 0;
		table.entry[i].dst = NULL;
    }
    init_timer(&table.generl_query_timer);
    table.generl_query_timer.function = general_query_timer_expired;
	
	//start g-q timer here, yzt 2010-02-21
	table.generl_query_timer.expires = jiffies + QUERY_INTERVAL;
	add_timer(&table.generl_query_timer);

    init_timer(&table.report_checking_timer);
    table.report_checking_timer.function = report_checking_timer_expired;
    table.groups = 0;
    spin_lock_init(&table.lock);

    initialed = 1;
    return 0;
}

/*
 * calssify the muticast packet, deliver to different function
 */
#include <net/udp.h>
int tp_mr_classify(struct sk_buff *skb)
{
	
/* added by HouXB, 03Dec10 */
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,31))
	struct iphdr *iph = (struct iphdr*)skb_network_header(skb);
	struct igmphdr *ih = NULL;
#else
	struct iphdr *iph = skb->nh.iph;
	struct igmphdr *ih = NULL;
#endif	
	
    struct udphdr *udph = (struct udphdr*)(skb->data+(iph->ihl<<2));;

#ifdef CONFIG_TP_MULTICAST_SWITCH/*  by huangwenzhong, 13Sep12 */
    if (!tp_mroute_enable)/* if not enable IGMP, just drop it */
    {
        goto drop;
    }
#endif

	//init table is not initialed
    if (!initialed)
    {
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,31))
		br1_dev = dev_get_by_name(&init_net, "br1");
#else
		br1_dev = dev_get_by_name("br1");
#endif
		if (br1_dev)
		{
			have_ru_br1 = 1;

			dev_put(br1_dev);
		}
		
        if (mc_table_init())
        {
            goto drop;
        }
    }
	
/* added by HouXB, 03Dec10 */
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,31))
	if (!ipv4_is_multicast(iph->daddr))
#else
	if (!MULTICAST(iph->daddr))
#endif		
    {
        goto drop;
    }

	/*printk("get in mr classify iph protocol=%d\n", iph->protocol);*/

    if(wan_eth_dev)
    {
        wan_eth_index = wan_eth_dev->ifindex;
    }
	//deliver WAN data packet
    if (iph->protocol == IPPROTO_UDP)
    {
    	/*printk("recv a igmp data packet +++...\n");*/
#ifdef VLAN_IPTV_IGMP_SNOOPING
        if (skb->dev->ifindex == wan_eth_index || (skb->dev->ifindex == inet_eth1_index && vlanOn == 1))
#else
        if (skb->dev->ifindex == wan_eth_index)
#endif
        {
			//udph = (struct udphdr *)(skb->data + iph->ihl * 4);
			if(ntohs(udph->source) == 5353 && htons(udph->dest) == 5353) {
                /*printk("####filter mdns data!!!!\n\n");*/
				goto drop;
			}
        	/*printk("use eth1 dev send data out\n");*/
            return find_data_path(skb, iph->daddr);
        }
        else
        {
#ifdef TEST_DEBUG
            printk("Drop pkt not from wan, group=0x%08x, mark=0x%08x\n", iph->daddr, skb->mark);
#endif
            debugk("drop lan data pack\n");
            goto drop;
        }
    }

/* added by HouXB, 03Dec10 */
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,31))
	__skb_pull(skb, iph->ihl*4);
	skb_set_transport_header(skb, 0);	
	ih = (struct igmphdr *)skb_transport_header(skb);
#else
	__skb_pull(skb, skb->nh.iph->ihl*4);
	skb->h.raw = skb->data;
    ih = skb->h.igmph;
#endif		

	/*printk("ih type=0x%x; daddr=0x%x; group=0x%x; iph protocol=%d\n", ih->type, daddr, ih->group, iph->protocol);*/

    if (iph->protocol == IPPROTO_IGMP)
    {
        debugk("heard IGMP pack\n");

		//copy from igmp.c, drop broken packet
        if (!pskb_may_pull(skb, sizeof(struct igmphdr)))
        {
        	printk("heard IGMP pack and drop it\n");
            goto drop;
        }

		/*printk("heard IGMP pack skb->dev->ifindex is %d; br0_index:%d; eth1_index:%d; eth0_index:%d\n", 
			skb->dev->ifindex, br0_index, eth1_index, eth0_index);*/

        if (skb->dev->ifindex == lan_br_index)
        {
            debugk("heard lan IGMP pack\n");
			
            switch (ih->type)
            {
            case IGMP_HOST_MEMBERSHIP_REPORT:
            case IGMPV2_HOST_MEMBERSHIP_REPORT:
                return lan_heard_igmp_report(skb, ih->group);
                break;
			case IGMPV3_HOST_MEMBERSHIP_REPORT:
				/*send v2 query to br0*/
				debugk("heard IGMP v3 report\n");
				general_query_send(lan_br_name);
				break;
                    
            case IGMP_HOST_LEAVE_MESSAGE:
                return lan_heard_igmp_leave(skb, ih->group);
                break;
                
            default:
                break;
            }
        }
        else if (skb->dev->ifindex == wan_eth_index)
        {
            debugk("heard wan IGMP pack\n");
            switch (ih->type)
            {
            case IGMP_HOST_MEMBERSHIP_REPORT:
            case IGMPV2_HOST_MEMBERSHIP_REPORT:
                return wan_heard_igmp_report(skb, ih->group);
                break;
                    
            case IGMP_HOST_MEMBERSHIP_QUERY:
                return wan_heard_igmp_query(skb, ih, iph->daddr);
                break;
                
            default:
                break;
            }
            
        }
    }

drop:
    kfree_skb(skb);
    return -1;
}

/*
 * solve igmp report packet, may add/modify items
 */
int lan_heard_igmp_report(struct sk_buff *skb, __u32 group)
{
    struct mc_entry *mcp;

#ifdef TEST_DEBUG
	printk("heard igmp report and nfmark is 0x%08x, from group=0x%08x\n", skb->mark, group);
#endif

    if (!table.groups)
    {
		//move to mc_table_init(), yzt 2010-02-21
        //table.generl_query_timer.expires = jiffies + QUERY_INTERVAL;
        //add_timer(&table.generl_query_timer);
        table.report_checking_timer.expires = jiffies + GROUP_MEMBER_SHIP_INTERVAL;
        add_timer(&table.report_checking_timer);
    }
    else if ((mcp = hlist_sort(group)) != NULL)
    {
		//modify port infomation
        mcp->membership_flag |= skb->mark;
        mcp->reported = 1;

		/* added by kuangguiming 13Dec25 */
		if (mcp->need_delete_mark == skb->mark)
		{
			mcp->need_delete_mark = 0;
			
			if (timer_pending(&mcp->lan_qr_timer))
            {
                del_timer(&mcp->lan_qr_timer);
            }
		}
		else if((mcp->need_delete_mark & skb->mark) != 0)
		{
			mcp->need_delete_mark &= ~(skb->mark);
		}
		/* end add */
		
        goto end;
    }
    else if (table.groups == MAX_GROUP_ENTRIES)
    {
        printk("Ooops, groups full, why defines so little table?\n");
        goto end;
    }
    
    mcp = (struct mc_entry *)table.empty_list.first;
    mcp->mc_addr = group;
	
	//save port information
    mcp->membership_flag = skb->mark;
    mcp->reported = 1;
    spin_lock_bh(table.lock);
    __hlist_del(table.empty_list.first);
    hlist_add_head((struct hlist_node *) mcp, &table.mc_hash[HASH256(group)]);
    table.groups++;
    spin_unlock_bh(table.lock);
    debugk("some tips added to mc_table\n");

/* added by HouXB, 03Dec10 */
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,31))
#ifdef VLAN_IPTV_IGMP_SNOOPING
	if (vlanOn == 1)
	{
		wan_eth_dev = inet_eth1_dev;
	}
	else
	{
#endif	

	if (have_ru_br1)/* modify by huangwenzhong,2012.05.21 */
	{
		wan_eth_dev = dev_get_by_name(&init_net, "br1");
	}
	else
	{
		wan_eth_dev = dev_get_by_name(&init_net, wan_eth_name);
	}
#ifdef VLAN_IPTV_IGMP_SNOOPING
	}
#endif

#else
	if (have_ru_br1)/* modify by huangwenzhong,2012.05.21 */
	{
		wan_eth_dev = dev_get_by_name("br1");
	}
	else
	{
	wan_eth_dev = dev_get_by_name(wan_eth_name);
	}
#endif	

    if (NULL != wan_eth_dev)
    {
    tp_send_igmp_report(wan_eth_dev, group);
	dev_put(wan_eth_dev);
    }
	else
	{
	    printk("[%s]dev %s is null now\n", __FUNCTION__, have_ru_br1 ? "br1" : wan_eth_name);
	}
    
end:
    kfree_skb(skb);
    return 0;
}

/*
 * solve igmp leave packet, may remove items
 */
int lan_heard_igmp_leave(struct sk_buff *skb, __u32 group)
{
    struct mc_entry *mcp;
#ifdef TEST_DEBUG
    printk("heard igmp leave and nfmark is 0x%08x, from group=0x%08x\n", skb->mark, group);
#endif
	
    mcp = hlist_sort(group);
	
    if (mcp)
    {
    	if(skb->mark & 0xff0000)	/* from wlan */	 
		{	
			if((skb->mark & WLAN_IGMP_NO_MEMBER_MARK) == WLAN_IGMP_NO_MEMBER_MARK) 
				mcp->membership_flag &= ~( skb->mark & 0xff0000 );
    	}
		else /*有线成员退出*/
		{			
			/* added by kuangguiming 13Dec25 
			send a specific query packet to all the lan port add start the lan_qr_timer
			if we don't reveive the report message util the timer expired, delete the membership */

			mcp->need_delete_mark |= skb->mark;

			lan_eth_dev = dev_get_by_name(&init_net, lan_eth_name);	
			
		    if (tp_send_igmp_query(lan_eth_dev, group, group, QUERY_RESPONSE_INTERVAL_NUM * 1))
		    {
		        printk("Oops, specific query send failed!\n");
		    }
		
			dev_put(lan_eth_dev);

			mcp->lan_qr_timer.expires = jiffies + 2 * HZ;
			if (!timer_pending(&mcp->lan_qr_timer))
			{
            	add_timer(&mcp->lan_qr_timer);
		    }
			/* end add */
		}

		//if no port alive, delete item
        if (!mcp->membership_flag)
        {
            if (timer_pending(&mcp->wan_qr_timer))
            {
                del_timer(&mcp->wan_qr_timer);
            }
            
			if (timer_pending(&mcp->lan_qr_timer))
            {
                del_timer(&mcp->lan_qr_timer);
            }
            
            spin_lock_bh(table.lock);
            __hlist_del((struct hlist_node *)mcp);
            hlist_add_head((struct hlist_node *)mcp, &table.empty_list);
            table.groups--;
            spin_unlock_bh(table.lock);
			//send leave packet to wan
			
/* added by HouXB, 03Dec10 */
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,31))
#ifdef VLAN_IPTV_IGMP_SNOOPING
			if(vlanOn == 1)
			{
				wan_eth_dev = inet_eth1_dev;
			}
			else
			{
#endif
				if (have_ru_br1)
				{
					wan_eth_dev = dev_get_by_name(&init_net, "br1");
				}
				else
				{
					wan_eth_dev = dev_get_by_name(&init_net, wan_eth_name);
				}
#ifdef VLAN_IPTV_IGMP_SNOOPING
			}
#endif

#else
			if (have_ru_br1)
			{
				wan_eth_dev = dev_get_by_name("br1");
			}
			else
			{
				wan_eth_dev = dev_get_by_name(wan_eth_name);
			}
#endif	

            if (NULL != wan_eth_dev)
            {
            tp_send_igmp_leave(wan_eth_dev, group);
			dev_put(wan_eth_dev);
            }
			else
			{
			    printk("[%s]dev %s is null now\n", __FUNCTION__, have_ru_br1 ? "br1" : wan_eth_name);

			}
			
            mcp->mc_addr = 0;	
			mcp->need_delete_mark = 0;
			if(mcp->dst)
			{
				dst_release(mcp->dst);
				mcp->dst = NULL;
			}
			
            debugk("some tips removed from mc_table\n");
            
            if (!table.groups)
            {
				//keep g-q timer, yzt 2010-02-21
                //del_timer(&table.generl_query_timer);
                del_timer(&table.report_checking_timer);
            }
        }
    }

    kfree_skb(skb);
    return 0;    
}

/*
 * solve wan query packet, set timer for all alive items
 */
int wan_heard_igmp_query(struct sk_buff *skb, struct igmphdr *ih, __u32 daddr)
{
    int i;
    struct mc_entry *mcp;

    debugk("heard wan igmp query\n");
	//if empty do not resolve
    if (table.groups)
    {
		//general query
        if (!ih->group && daddr == IGMP_ALL_HOST_ADDR)
        {
            for (i = 0; i < MAX_GROUP_ENTRIES; i++)
            {
                mcp = &table.entry[i];
                if (mcp->mc_addr)
                {
                    if (!timer_pending(&mcp->wan_qr_timer) || mcp->wan_qr_timer.expires > (jiffies + ih->code * HZ / 10))
                    {
                        if (timer_pending(&mcp->wan_qr_timer))
                        {
                            del_timer(&mcp->wan_qr_timer);
                        }                    
                        if (ih->code && ih->code < QUERY_RESPONSE_INTERVAL_NUM * 10)
                        {
                            mcp->wan_qr_timer.expires = jiffies + (jiffies % ih->code) * HZ / 10;
                        }
                        else
                        {
                           mcp->wan_qr_timer.expires = jiffies + (jiffies % QUERY_RESPONSE_INTERVAL_NUM) * HZ;
                        }
                        add_timer(&mcp->wan_qr_timer);
                    }
                }
            }
        }
        else if (ih->group == daddr)
        {
			// g-s query
            mcp = hlist_sort(daddr);
            if (mcp)
            {
                if (!timer_pending(&mcp->wan_qr_timer) || mcp->wan_qr_timer.expires > (jiffies + ih->code * HZ / 10))
                {
                    mcp->wan_qr_timer.expires = jiffies + (jiffies % ih->code) * HZ / 10;
                    if (!timer_pending(&mcp->wan_qr_timer))
                    {
                	add_timer(&mcp->wan_qr_timer);
                    }
            }
        }
    }
    }

    kfree_skb(skb);
    return 0;
}

/*
 * solve wan report packet, stop the q-r timer
 */
int wan_heard_igmp_report(struct sk_buff *skb, __u32 group)
{
    struct mc_entry *mcp;

    debugk("heard wan igmp report\n");
    mcp = hlist_sort(group); 
    if (mcp)
    {
        if (timer_pending(&mcp->wan_qr_timer))
        {
            del_timer(&mcp->wan_qr_timer);
        }
    }

    kfree_skb(skb);
    return 0;    
}

/*
 * solve wan data packet, find the out way, set port information
 */
int find_data_path(struct sk_buff *skb, __u32 group)
{
    struct mc_entry *mcp = NULL;
	struct rtable *rt = NULL;
	//struct flowi fl;

/* added by HouXB, 03Dec10 */
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,31))
	struct iphdr *iph = (struct iphdr*)skb_network_header(skb);
	struct net *net =  dev_net(skb->dev);
#else
	struct iphdr *iph = skb->nh.iph;
#endif	

    debugk("heard data pack\n");

	/*printk("heard data pack, group is %x\n", group);*/
    mcp = hlist_sort(group); 
	
    if (mcp)
    {
        skb->mark = mcp->membership_flag | IGMP_DATA_DOWN_FLAG;
#ifdef TEST_DEBUG
        printk("Deliver datat packet, group=0x%08x, mark=0x%08x\n", group, skb->mark);
#endif	

		/*printk("-----\nmcp info:%x\n -----\n", mcp->mc_addr);*/

		/* modified by HouXB, 03Dec10 */
		struct flowi fl = { .oif = lan_br_index,
                .nl_u = { .ip4_u = { .daddr = iph->daddr } },
                .proto = iph->protocol };

		if(!mcp->dst)//if no route backup
		{
/*get route info. added by HouXB, 03Dec10 */
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,31))
			if (ip_route_output_key(net, &rt, &fl))
#else
			if (ip_route_output_key(&rt, &fl))
#endif
		    {
		        printk("Ooops, static route udp out error!\n");
				//ip_rt_put(rt);
				kfree(skb);
		        return -1;
		    }
			else if (rt->rt_src == 0)
			{
				debugk("no route source\n");
				ip_rt_put(rt);
				//dst_free(mcp->dst);
				kfree(skb);
				return -1;
			}
			else
			{
				mcp->dst = &rt->u.dst;//backup route info			
			}
		}

/* added by HouXB, 03Dec10 */
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,31))
		ip_rt_put(skb->_skb_dst);
		skb_dst_set(skb, mcp->dst);
#else
		ip_rt_put(skb->dst);
		skb->dst = mcp->dst;
#endif			
		mcp->dst->lastuse = jiffies;
		dst_hold(mcp->dst);
		mcp->dst->__use++;
		//RT_CACHE_STAT_INC(out_hit);
	    return ip_output(skb);		
    }
    else
    {
#ifdef TEST_DEBUG
        printk("No entry found, group=0x%08x, mark=0x%08x\n", group, skb->mark);
#endif
        kfree_skb(skb);
        return -1;
    }
}

/*****added for iptv vlan igmp snooping*****/

#ifdef VLAN_IPTV_IGMP_SNOOPING
int find_data_path_iptv(struct sk_buff *skb, __u32 group)
{
    struct mc_entry *mcp;

    mcp = hlist_sort(group); 
	
    if (mcp)
    {
        skb->mark = mcp->membership_flag | IGMP_DATA_DOWN_FLAG;
    }
    else
    {
        kfree_skb(skb);
        return -1;
    }
	return 0;
}

int lan_heard_igmp_report_iptv(struct sk_buff *skb, __u32 group)
{
    struct mc_entry *mcp;
#ifdef TEST_DEBUG
	printk("lan_heard_igmp_report_iptv heard igmp report and nfmark is %d\n", skb->mark);
#endif

    if (!table.groups)
    {
		//move to mc_table_init(), yzt 2010-02-21
        //table.generl_query_timer.expires = jiffies + QUERY_INTERVAL;
        //add_timer(&table.generl_query_timer);
        table.report_checking_timer.expires = jiffies + GROUP_MEMBER_SHIP_INTERVAL;
        add_timer(&table.report_checking_timer);
    }
    else if ((mcp = hlist_sort(group)) != NULL)
    {
		//modify port infomation
        mcp->membership_flag |= skb->mark;
        mcp->reported = 1;
        goto end;
    }
    else if (table.groups == MAX_GROUP_ENTRIES)
    {
        printk("Ooops, groups full, why defines so little table?\n");
        goto end;
    }
    
	printk("add a group = 0x%08x, mark = 0x%08x\n", group, skb->mark);
	
    mcp = (struct mc_entry *)table.empty_list.first;
    mcp->mc_addr = group;
	
	//save port information
    mcp->membership_flag = skb->mark;
    mcp->reported = 1;
    spin_lock_bh(table.lock);
    __hlist_del(table.empty_list.first);
    hlist_add_head((struct hlist_node *) mcp, &table.mc_hash[HASH256(group)]);
    table.groups++;
    spin_unlock_bh(table.lock);
    printk("some tips added to mc_table\n");

end:
    return 0;
}
int lan_heard_igmp_leave_iptv(struct sk_buff *skb, __u32 group)
{
    struct mc_entry *mcp;

    printk("lan_heard_igmp_leave_iptv heard lan igmp leave\n");
    mcp = hlist_sort(group);
    if (mcp)
    {
		//modify port infomation
        mcp->membership_flag &= (~skb->mark);

		//if no port alive, delete item
        if (!mcp->membership_flag)
        {
            if (timer_pending(&mcp->wan_qr_timer))
            {
                del_timer(&mcp->wan_qr_timer);
            }
            
			/* added by kuangguiming 13Dec30 */
			if (timer_pending(&mcp->lan_qr_timer))
            {
                del_timer(&mcp->lan_qr_timer);
            }
			/* end add */
            
            spin_lock_bh(table.lock);
            __hlist_del((struct hlist_node *)mcp);
            hlist_add_head((struct hlist_node *)mcp, &table.empty_list);
            table.groups--;
            spin_unlock_bh(table.lock);
			
            mcp->mc_addr = 0;			
			if(mcp->dst)
			{
				dst_release(mcp->dst);
				mcp->dst = NULL;
			}
			
            debugk("some tips removed from mc_table\n");

			//if              
            if (!table.groups)
            {
				//keep g-q timer, yzt 2010-02-21
                //del_timer(&table.generl_query_timer);
                del_timer(&table.report_checking_timer);
            }
        }
    }
    return 0;    
}

int tp_mr_classify_iptv(struct sk_buff *skb)
{

/* added by HouXB, 03Dec10 */
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,31))
	struct iphdr *iph = skb_network_header(skb);
#else
	struct iphdr *iph = skb->nh.iph;
#endif

	if(vlanOn != 1)
	{
		return 0;
	}
	
	//init table is not initialed
    if (!initialed)
    {
        if (mc_table_init())
        {
            return 0;
        }
    }
	
/* added by HouXB, 03Dec10 */
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,31))
	if (!ipv4_is_multicast(iph->daddr))
#else
	if (!MULTICAST(iph->daddr))
#endif		
    {
        return 0;
    }
    if (iph->protocol == IPPROTO_UDP)
    {
    	/*printk("recv a igmp data packet +++...\n");*/
    	//printk("tp_mr_classify_iptv recv a igmp data packet +++... skb->dev->ifindex = %d\n", skb->dev->ifindex);
		/*
		if (skb->dev->ifindex == iptv_eth1_index)
        {
        	return 0;
		}else
		*/
        if (skb->dev->ifindex == iptv_eth0_index
			|| skb->dev->ifindex == multi_iptv_eth0_index
			)
        {
        	/*printk("use eth1 dev send data out\n");*/
            return find_data_path_iptv(skb, iph->daddr);
        }
		else if (skb->dev->ifindex == iptv_eth1_index
			|| skb->dev->ifindex == multi_iptv_eth1_index 
		)
        {
            //printk("tp_mr_classify_iptv drop lan data pack\n");
			kfree_skb(skb);
            goto drop;
        }
		else
		{
		    return 0;
        }
    }

/* added by HouXB, 03Dec10 */
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,31))
	//__skb_pull(skb, iph->ihl*4);
	//skb_set_transport_header(skb, 0);	
	//struct igmphdr *ih = (struct igmphdr *)skb_transport_header(skb);
	struct igmphdr *ih = (struct igmphdr *)(skb->data + iph->ihl*4);
#else
	__skb_pull(skb, skb->nh.iph->ihl*4);
	skb->h.raw = skb->data;
    struct igmphdr *ih = skb->h.igmph;
#endif	

    if (iph->protocol == IPPROTO_IGMP)
    {
        //printk("tp_classify_iptv heard IGMP pack, skb->dev->ifindex = %d iptv_eth1_index = %d ih->group = %x\n", 
		//	skb->dev->ifindex, iptv_eth1_index, ih->group);

		//copy from igmp.c, drop broken packet
        if (!pskb_may_pull(skb, sizeof(struct igmphdr)))
        {
        	printk("tp_classify_iptv  heard IGMP pack and drop it\n");
            return 0;
        }

        if (skb->dev->ifindex == iptv_eth1_index
			|| skb->dev->ifindex == multi_iptv_eth1_index 
			/*|| skb->dev->ifindex == ipphone_eth1_index*/
		)
        {
            switch (ih->type)
            {
            case IGMP_HOST_MEMBERSHIP_REPORT:
            case IGMPV2_HOST_MEMBERSHIP_REPORT:
                lan_heard_igmp_report_iptv(skb, ih->group);
                break;
			case IGMPV3_HOST_MEMBERSHIP_REPORT:
				/*send v2 query to br0*/
				debugk("heard IGMP v3 report\n");
				iptv_eth0_dev = dev_get_by_index(&init_net, iptv_eth0_index);
				if (!iptv_eth0_dev || tp_send_igmp_query(iptv_eth0_dev, IGMP_ALL_HOST_ADDR, 0, QUERY_RESPONSE_INTERVAL_NUM * 10))
                {
                     printk("Ooops, general query send failed!\n");
                }

	            dev_put(iptv_eth0_dev);
                kfree_skb(skb);
                goto drop;  
            case IGMP_HOST_LEAVE_MESSAGE:
                lan_heard_igmp_leave_iptv(skb, ih->group);
                break;
                
            default:
                break;
            }
        }
		printk("skb->dev->ifindex = %d, tp_classify_iptv  end here ret 0\n", skb->dev->ifindex);
    }
	
	return 0;
drop:
	return -1;
}

void nl_data_ready (struct sk_buff *__skb)
{
	struct sk_buff *skb;
	struct nlmsghdr *nlh;

	//printk("netlink: data is ready to read.\n");
	skb = skb_get(__skb);

	if (skb->len >= NLMSG_SPACE(0)) 
	{
		nlh = nlmsg_hdr(skb);
		printk("netlink: recv %s.\n", (char *)NLMSG_DATA(nlh));

		char *p = (char *)NLMSG_DATA(nlh);
		if(strlen(p) < 2)
		{
			return;
		}
	
		if(strstr(p, "inet_lan:"))
		{
			strcpy(inet_lan, p + strlen("inet_lan:"));
			inet_eth0_dev = dev_get_by_name(&init_net, inet_lan);
			if(inet_eth0_dev)
			{
				inet_eth0_index = inet_eth0_dev->ifindex;
			}
			printk("inet_lan = %s, inet_eth0_index = %d\n", inet_lan, inet_eth0_index);
		}
		else if(strstr(p, "inet_wan:"))
		{
			strcpy(inet_wan, p + strlen("inet_wan:"));
			inet_eth1_dev = dev_get_by_name(&init_net, inet_wan);
			if(inet_eth1_dev)
			{
				inet_eth1_index = inet_eth1_dev->ifindex;
			}
			printk("inet_wan = %s, inet_eth1_index = %d\n", inet_wan, inet_eth1_index);
		}
		else if(strstr(p, "multi_iptv_lan:"))
		{
			strcpy(multi_iptv_lan, p + strlen("multi_iptv_lan:"));
			multi_iptv_eth0_dev = dev_get_by_name(&init_net, multi_iptv_lan);
			if(multi_iptv_eth0_dev)
			{
				multi_iptv_eth0_index = multi_iptv_eth0_dev->ifindex;
			}
			printk("multi_iptv_lan = %s, multi_iptv_eth0_index = %d\n", multi_iptv_lan, multi_iptv_eth0_index);

		}
		else if(strstr(p, "multi_iptv_wan:"))
		{
			strcpy(multi_iptv_wan, p + strlen("multi_iptv_wan:"));
			multi_iptv_eth1_dev = dev_get_by_name(&init_net, multi_iptv_wan);
			if(multi_iptv_eth1_dev)
			{
				multi_iptv_eth1_index = multi_iptv_eth1_dev->ifindex;
			}
			printk("multi_iptv_wan = %s, multi_iptv_eth1_index = %d\n", multi_iptv_wan, multi_iptv_eth1_index);

		}
		else if(strstr(p, "multi_iptv_br:"))
		{
			strcpy(multi_iptv_br, p + strlen("multi_iptv_br:"));

			multi_iptv_br_dev = dev_get_by_name(&init_net, multi_iptv_br);
			if(multi_iptv_br_dev)
			{
				multi_iptv_br_index = multi_iptv_br_dev->ifindex;
			}
			printk("multi_iptv_br = %s, multi_iptv_br_index = %d\n", multi_iptv_br , multi_iptv_br_index);
		}
		else if(strstr(p, "iptv_lan:"))
		{
			strcpy(iptv_lan, p + strlen("iptv_lan:"));
			iptv_eth0_dev = dev_get_by_name(&init_net, iptv_lan);
			if(iptv_eth0_dev)
			{
				iptv_eth0_index = iptv_eth0_dev->ifindex;
			}
			printk("iptv_lan = %s, iptv_eth0_index = %d\n", iptv_lan, iptv_eth0_index);

		}
		else if(strstr(p, "iptv_wan:"))
		{
			strcpy(iptv_wan, p + strlen("iptv_wan:"));
			iptv_eth1_dev = dev_get_by_name(&init_net, iptv_wan);
			if(iptv_eth1_dev)
			{
				iptv_eth1_index = iptv_eth1_dev->ifindex;
			}
			printk("iptv_wan = %s, iptv_eth1_dev = %d\n", iptv_wan, iptv_eth1_index);

		}
		else if(strstr(p, "iptv_br:"))
		{
			strcpy(iptv_br, p + strlen("iptv_br:"));

			iptv_br_dev = dev_get_by_name(&init_net, iptv_br);
			if(iptv_br_dev)
			{
				iptv_br_index = iptv_br_dev->ifindex;
			}
			printk("iptv_br  = %s, iptv_br_index = %d\n", iptv_br, iptv_br_index);
		}
		else if(strstr(p, "ipphone_lan:"))
		{
			strcpy(ipphone_lan, p + strlen("ipphone_lan:"));
			ipphone_eth0_dev = dev_get_by_name(&init_net, ipphone_lan);
			if(ipphone_eth0_dev)
			{
				ipphone_eth0_index = ipphone_eth0_dev->ifindex;
			}
			printk("ipphone_lan = %s, ipphone_eth0_index = %d\n", ipphone_lan, ipphone_eth0_index);

		}
		else if(strstr(p, "ipphone_wan:"))
		{
			strcpy(ipphone_wan, p + strlen("ipphone_wan:"));
			ipphone_eth1_dev = dev_get_by_name(&init_net, ipphone_wan);
			if(ipphone_eth1_dev)
			{
				ipphone_eth1_index = ipphone_eth1_dev->ifindex;
			}
			printk("ipphone_wan = %s, iptv_eth1_dev = %d\n", ipphone_wan, ipphone_eth1_index);

		}
		else if(strstr(p, "ipphone_br:"))
		{
			strcpy(ipphone_br, p + strlen("ipphone_br:"));

			ipphone_br_dev = dev_get_by_name(&init_net, ipphone_br);
			if(ipphone_br_dev)
			{
				ipphone_br_index = ipphone_br_dev->ifindex;
			}
			printk("ipphone_br = %s, ipphone_br_index = %d\n", ipphone_br , ipphone_br_index);
		}
		else if(strstr(p, "vlanOn:"))
		{
			sscanf(p + strlen("vlanOn:"), "%d", &vlanOn);
			printk("vlanOn = %d\n", vlanOn);
		}
	}
	return;
}

int vlan_netlink(void) 
{
	nl_sk = netlink_kernel_create(&init_net, NETLINK_TEST, 0, nl_data_ready, NULL, THIS_MODULE);

	if (!nl_sk) {
		printk(KERN_ERR "net_link: Cannot create netlink socket.\n");
		return -EIO;
	}
	printk("net_link: create socket ok.\n");
	
	return 0;
}

int init_module()
{
	vlan_netlink();
	return 0;
}

void cleanup_module()
{
	if (nl_sk != NULL)
	{
		sock_release(nl_sk->sk_socket);
	}
	
	printk("net_link: remove ok.\n");
}

#endif	/* VLAN_IPTV_IGMP_SNOOPING */

static int __init tp_mroute_init(void)
{
	mc_table_init();
	
#ifdef CONFIG_PROC_FS
    tp_mroute_proc_init();
#endif

	return 0;
}

static void __exit tp_mroute_exit(void)
{
#ifdef CONFIG_PROC_FS
	tp_mroute_proc_exit();
#endif
	disable_tp_mroute();
	return;
}

module_init(tp_mroute_init);
module_exit(tp_mroute_exit);

EXPORT_SYMBOL(tp_mroute_is_enable);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Huang WenHao <huangwenhao@tp-link.net>");
MODULE_DESCRIPTION("The IGMP Module for IPTV.");
MODULE_ALIAS("The IGMP Module");


/*
 *	send multicast packet //not used now, igmp and udp packets are solved seperately 
 */
 /*
int tp_send_mc(struct sk_buff *skb, struct net_device *dev)
{
    struct rtable *rt;

    struct flowi fl = { .oif = dev->ifindex,
                .nl_u = { .ip4_u = { .daddr = skb->nh.iph->daddr } },
                .proto = skb->nh.iph->protocol };

	//eth0 don't have static route, use br0 instead
    if (dev->ifindex == eth0_dev->ifindex)
    {
        fl.oif = br0_dev->ifindex;
    }
    
    if (ip_route_output_key(&rt, &fl))
    {
        printk("Ooops, static route don't kown this output interface!\n");
		kfree(skb);
        return -1;
    }
    
    if (rt->rt_src == 0)
    {
        debugk("route source\n");
        ip_rt_put(rt);
		kfree(skb);
		return -1;
	}
    
    skb->dst = (struct dst_entry*) rt;
	//change back to original dev, do not send to wireless
    skb->dev = dev;
    skb->dst->dev = dev;

    return ip_output(skb);
}
*/


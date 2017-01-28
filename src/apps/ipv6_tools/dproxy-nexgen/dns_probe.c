#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
//change by hlf.@20130217
#include "linux/inotify.h"
#include <sys/ioctl.h>
//#include <linux/in6.h>
#include "dproxy.h"
#include "conf.h"
#include "dns_probe.h"

extern int dns_output_sock;
static char primary_ns[16];
static char secondary_ns[16];
static char primary_ipv6_ns[46];        /* by wdl, 03Mar11, add ipv6 primary dns */
static char secondary_ipv6_ns[46];      /* by wdl, 03Mar11, add ipv6 secondary dns */
static struct sockaddr_in6 probe_addr;  /* by wdl, 03Mar11, change to support ipv6 */
static struct sockaddr_in6 probe_addr_v6;  /* by wdl, 03Mar11, change to support ipv6 */
static time_t probe_next_time;
static int probe_tried;
static time_t probe_timeout;
static uint16_t probe_id;
static char probe_pkt[36] =
	{0x0, 0x0, 0x1, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
	 0x1, 'a', 0xc, 'r', 'o', 'o', 't', '-', 's', 'e', 'r', 'v',
	 'e', 'r', 's', 0x3, 'n', 'e', 't', 0x0, 0x0, 0x1, 0x0, 0x1, };

/* added by ZQQ, 21Dec12 */
static char probe_pkt_ipv6[36] =
	{0x0, 0x0, 0x1, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
	 0x1, 'a', 0xc, 'r', 'o', 'o', 't', '-', 's', 'e', 'r', 'v',
	 'e', 'r', 's', 0x3, 'n', 'e', 't', 0x0, 0x0, 0x1c, 0x0, 0x1, };

/* Load name servers' addresses from /var/fyi/sys/dns */
static void load_brcm_name_servers(void)
{
	FILE * fp;
	char line[256];
	char addr[46];          /* by wdl, 02Mar11, change len to 46 */
	char cmdBuf[256];

	if((fp = fopen(STATIC_DNS_FILE_DEFAULT, "r")) == NULL)
	{
		/* create ipv4 resolv.conf to make sure inotify will success */
		memset(cmdBuf, 0, sizeof(cmdBuf));
		sprintf(cmdBuf, "echo \"nameserver %s \" > %s", UNKNOWED_IPV4_ADDR,
			STATIC_DNS_FILE_DEFAULT);
		system(cmdBuf);
		
		sprintf(cmdBuf, "echo \"nameserver %s \" %s %s", UNKNOWED_IPV4_ADDR,
			">>", STATIC_DNS_FILE_DEFAULT);
		system(cmdBuf);
		
	}

	if((fp = fopen(STATIC_DNS_FILE_DEFAULT, "r")) == NULL)
	{
		return;
	}

	memset(line, 0, sizeof(line));
	memset(primary_ns, 0, sizeof(primary_ns));
	if(fgets(line, sizeof(line), fp))
	{
		line[sizeof(line)-1] = 0;
		if (sscanf(line, "nameserver %s", addr) == 1)
			strcpy(primary_ns, addr);
	}
	
	memset(line, 0, sizeof(line));
	memset(secondary_ns, 0, sizeof(secondary_ns));
	if(fgets(line, sizeof(line), fp))
	{
		line[sizeof(line)-1] = 0;
		if (sscanf(line, "nameserver %s", addr) == 1)
			/* No check for duplicate address */
			strcpy(secondary_ns, addr);
	}
	fclose(fp);
	
	msg("primary_ns = %s, secondary_ns = %s", primary_ns, secondary_ns);
	
    /* by wdl, 02Mar11, load ipv6 static dns */
    if((fp = fopen(STATIC_IPV6_DNS_FILE_DEFAULT, "r")) == NULL)
    {
		/* create ipv6 resolv.conf to make sure inotify will success */
		memset(cmdBuf, 0, sizeof(cmdBuf));
		sprintf(cmdBuf, "echo \"nameserver %s \" > %s", UNKNOWED_IPV6_ADDR,
			STATIC_IPV6_DNS_FILE_DEFAULT);
		system(cmdBuf);
		
		sprintf(cmdBuf, "echo \"nameserver %s \" %s %s", UNKNOWED_IPV6_ADDR,
			">>", STATIC_IPV6_DNS_FILE_DEFAULT);
		system(cmdBuf);
    }

	if((fp = fopen(STATIC_IPV6_DNS_FILE_DEFAULT, "r")) == NULL)
	{
		printf("%s do not exist!!!", STATIC_IPV6_DNS_FILE_DEFAULT);
	}
    else
    {
		memset(line, 0, sizeof(line));
		memset(primary_ipv6_ns, 0, sizeof(primary_ipv6_ns));
    	if(fgets(line, sizeof(line), fp)) 
		{
    		line[sizeof(line)-1] = 0;
    		if (sscanf(line, "%*s %46s", addr) == 1)
    			strcpy(primary_ipv6_ns, addr);
    	}
		
		memset(line, 0, sizeof(line));
		memset(secondary_ipv6_ns, 0, sizeof(secondary_ipv6_ns));		
    	if(fgets(line, sizeof(line), fp)) 
		{
    		line[sizeof(line)-1] = 0;
    		if (sscanf(line, "%*s %46s", addr) == 1)
    			/* No check for duplicate address */
    			strcpy(secondary_ipv6_ns, addr);
    	}
    	fclose(fp);
    }
    /* by wdl, 03Mar11, end load */

	debug("dproxy: load static dns1 %s, dns2 %s from %s\n",
	      primary_ns, secondary_ns, STATIC_DNS_FILE_DEFAULT);

    debug("dproxy: load static ipv6 dns1 %s, dns2 %s from %s\n",
	      primary_ipv6_ns, secondary_ipv6_ns, STATIC_IPV6_DNS_FILE_DEFAULT);
}

/* Initialization before probing */
void dns_probe_init(void)
{
    char tmp[100] = {0};      /* by wdl, 03Mar11, add buf to hold ipv6 addr */
	
	/* Try to read name servers from /var/fyi/sys/dns */
	load_brcm_name_servers();

	/* Set primary server as the probing address */
	memset(&probe_addr, 0, sizeof(probe_addr));
	memset(&probe_addr_v6, 0, sizeof(probe_addr_v6));
	
	memset(config.name_server, 0, sizeof(config.name_server));
	
	if (primary_ns[0] != 0 && strcmp(primary_ns, UNKNOWED_IPV4_ADDR))
	{
		/* copy the primary dns */
		strcpy(config.name_server, primary_ns);
		
	    /* by wdl, 03Mar11, change to support ipv6 */
		probe_addr.sin6_family = AF_INET6;
	    strcpy(tmp, "::ffff:");
	    strcat(tmp, primary_ns);
		inet_pton(AF_INET6, tmp, &probe_addr.sin6_addr);
		probe_addr.sin6_port = ntohs(PORT);
	    /* by wdl, 03Mar11, end change */
	}
	else if (secondary_ns[0] !=0 && strcmp(secondary_ns, UNKNOWED_IPV4_ADDR))
	{
		strcpy(config.name_server, secondary_ns);
	}

	memset(config.ipv6_name_server, 0, sizeof(config.ipv6_name_server));

    if (primary_ipv6_ns[0] != 0 && strcmp(primary_ipv6_ns, UNKNOWED_IPV6_ADDR))
    {
        /* by wdl, 03Mar11, ipv6 primary dns exist */
        strcpy(config.ipv6_name_server, primary_ipv6_ns);
        msg("by wdl, config.ipv6_name_server = %s\n", config.ipv6_name_server);
		probe_addr_v6.sin6_family = AF_INET6;
		inet_pton(AF_INET6, primary_ipv6_ns, &probe_addr_v6.sin6_addr);
		probe_addr_v6.sin6_port = ntohs(PORT);
    }
	else if (secondary_ipv6_ns[0] != 0 && strcmp(secondary_ipv6_ns, UNKNOWED_IPV6_ADDR))
	{
		strcpy(config.ipv6_name_server, secondary_ipv6_ns);
	}
	
	/* Initialize request id */
	srandom(time(NULL));
	probe_id = (uint16_t)random();
}

/*
** Do dns type A query every  30 secs to ensure the health of named
** If you do not receive a response retry 3 times and then switch to
** the secondary DNS server. DNS uses UDP and these packets can be
** lost on the internet so it is safer to retry a couple of times
** before giving it up.
*/
void dns_probe(void)
{
	time_t now = time(NULL);

	if (probe_tried) { /* Probing */
		if (now >= probe_timeout) { /* Timed out */
			if (probe_tried >= DNS_PROBE_MAX_TRY) {
				/* Probe failed */
				/* changed by ZQQ, 21Dec12 */
				#if 0
				debug("dproxy: probing failed\n");
				if (secondary_ns[0] &&
					strcmp(secondary_ns, UNKNOWED_IPV4_ADDR) &&
				    strcmp(config.name_server, secondary_ns)) {
					printf("Primary DNS server Is Down... "
					       "Switching To Secondary DNS "
					       "server \n");
					strcpy(config.name_server,
					       secondary_ns);
				}
				#endif
				if (secondary_ipv6_ns[0] &&
					strcmp(secondary_ipv6_ns, UNKNOWED_IPV6_ADDR) &&
				    strcmp(config.ipv6_name_server, secondary_ipv6_ns)) {
					msg("IPv6 : Primary DNS server Is Down... "
					       "Switching To Secondary DNS "
					       "server \n");
					strcpy(config.ipv6_name_server, secondary_ipv6_ns);
				}
				probe_tried = 0;
				probe_next_time = now + DNS_PROBE_INTERVAL;
			} 
			else 
			{ 
				/* if no dns server */
				if (probe_addr.sin6_port != 0)
				{
					/* Retry */
					sendto(dns_output_sock, probe_pkt, sizeof(probe_pkt),
					       0, (struct sockaddr*)&probe_addr,
					       sizeof(probe_addr));
					probe_timeout = time(NULL) + DNS_PROBE_TIMEOUT;
					probe_tried++;
				}

				/*  by ZQQ, 21Dec12 */
				if (probe_addr_v6.sin6_port != 0)
				{
					sendto(dns_output_sock, probe_pkt_ipv6, sizeof(probe_pkt_ipv6),
					       0, (struct sockaddr*)&probe_addr_v6,
					       sizeof(probe_addr_v6));
					probe_timeout = time(NULL) + DNS_PROBE_TIMEOUT;
					probe_tried++;
				}
				/* end by ZQQ, 21Dec12 */
			}
		}
	} else if (now >= probe_next_time) { /* Time to probe */
		*((uint16_t*)probe_pkt) = htons(++probe_id);
		/* if no dns server */
		if (probe_addr.sin6_port != 0)
		{
			sendto(dns_output_sock, probe_pkt, sizeof(probe_pkt), 0,
			       (struct sockaddr*)&probe_addr, sizeof(probe_addr));
			probe_tried = 1;
			probe_timeout = time(NULL) + DNS_PROBE_TIMEOUT;
		}
		/*  by ZQQ, 21Dec12 */
		if (probe_addr_v6.sin6_port != 0)
		{
			sendto(dns_output_sock, probe_pkt_ipv6, sizeof(probe_pkt_ipv6),
			       0, (struct sockaddr*)&probe_addr_v6,
			       sizeof(probe_addr_v6));
			probe_timeout = time(NULL) + DNS_PROBE_TIMEOUT;
			probe_tried++;
		}
		/* end by ZQQ, 21Dec12 */
	}
}

/* Activate primary server */
int dns_probe_activate(struct in6_addr name_server)     /* by wdl, 03Mar11, change para to support ipv6 */
{
	/* changed by ZQQ, 21Dec12 */
	#if 0
	static int first_time = 1;

	/* by wdl, 03Mar11, change ip addr cmp */
	if (memcmp(&name_server, &probe_addr.sin6_addr, sizeof(name_server)) != 0)
		return 0;
    /* by wdl, 03Mar11, end change */
	probe_tried = 0;
	probe_next_time = time(NULL) + DNS_PROBE_INTERVAL;
	if (strcmp(config.name_server, primary_ns) == 0)
		return 1;

	if (first_time)
		first_time = 0;
	else
		printf("switching back to primary dns server\n");

	if (primary_ns[0] != 0 && strcmp(primary_ns, UNKNOWED_IPV4_ADDR))
	{
		strcpy(config.name_server, primary_ns);
	}
	return 1;
	#endif

	static int first_time = 1;
	static int first_time_v6 = 1;

	/* by wdl, 03Mar11, change ip addr cmp */
	if (memcmp(&name_server, &probe_addr.sin6_addr, sizeof(name_server)) != 0)
	{
		return 0;
	}
    /* by wdl, 03Mar11, end change */
	else
	{
		probe_tried = 0;
		probe_next_time = time(NULL) + DNS_PROBE_INTERVAL;
		if (strcmp(config.name_server, primary_ns) == 0)
			return 1;

		if (first_time)
			first_time = 0;
		else
			printf("switching back to primary dns server\n");

		if (primary_ns[0] != 0 && strcmp(primary_ns, UNKNOWED_IPV4_ADDR))
		{
			strcpy(config.name_server, primary_ns);
		}
		return 1;
	}


	/* by wdl, 03Mar11, change ip addr cmp */
	if (memcmp(&name_server, &probe_addr_v6.sin6_addr, sizeof(name_server)) != 0)
	{
		return 0;
	}
    /* by wdl, 03Mar11, end change */
	else
	{
		probe_tried = 0;
		probe_next_time = time(NULL) + DNS_PROBE_INTERVAL;
		if (strcmp(config.ipv6_name_server, primary_ipv6_ns) == 0)
			return 1;

		if (first_time_v6)
			first_time_v6 = 0;
		else
			printf("switching back to primary dns ipv6 server\n");

		if (primary_ipv6_ns[0] != 0 && strcmp(primary_ipv6_ns, UNKNOWED_IPV6_ADDR))
		{
			strcpy(config.ipv6_name_server, primary_ipv6_ns);
		}
		return 1;
	}
	
}

/* Activate name server if it's the response for probing request */
int dns_probe_response(dns_request_t *m)
{
	if (m->message.header.flags.flags & 0x8000 &&
	    m->message.header.id != probe_id)
		return 0;
	/* if the packet is a response for probe, set the active dns server */
	return dns_probe_activate(m->src_addr);     /* by wdl, 03Mar11, change input para */
}

void handle_dns_event(int fd)
{
	int ret;
	int queue_len = 0;
	char buf[256] = {0};
	char tmp [100];
	int i = 0;
	
	ret = ioctl(fd, FIONREAD, &queue_len);
	
	if (queue_len <= 0)
	{
		return;
	}
	
	memset(buf, 0, 256);
	
	ret = read(fd, buf, 256);
	
	i = 0;
	while(i < ret)
	{
		struct inotify_event *event = (struct inotify_event*) &buf[i];
		printf("event %d mask %d cookie %d len %d dir %s\n",
				event->wd, event->mask,
				event->cookie, event->len,
				(event->mask & IN_ISDIR)? "yes" : "NO");
		if (event->len)
		{
			printf("name %s\n", event->name);
		}

		/* reload dns name server */
		load_brcm_name_servers();

		memset(config.name_server, 0, sizeof(config.name_server));
		
		/* Set primary server as the probing address */
		memset(&probe_addr, 0, sizeof(probe_addr));
		
		if (primary_ns[0] != 0 && strcmp(primary_ns, UNKNOWED_IPV4_ADDR))
		{
			memset(tmp, 0, sizeof(tmp));
			probe_addr.sin6_family = AF_INET6;
		    strcpy(tmp, "::ffff:");
		    strcat(tmp, primary_ns);
			inet_pton(AF_INET6, tmp, &probe_addr.sin6_addr);
			probe_addr.sin6_port = ntohs(PORT);
			
			strcpy(config.name_server, primary_ns);
		}
		else if (secondary_ns[0] != 0 && strcmp(primary_ns, UNKNOWED_IPV4_ADDR))
		{
			strcpy(config.name_server, secondary_ns);
		}
		
		memset(config.ipv6_name_server, 0, sizeof(config.ipv6_name_server));
		if(primary_ipv6_ns[0] != 0 && strcmp(primary_ipv6_ns, UNKNOWED_IPV6_ADDR))
		{
			strcpy(config.ipv6_name_server, primary_ipv6_ns);
			probe_addr_v6.sin6_family = AF_INET6;
			inet_pton(AF_INET6, primary_ipv6_ns, &probe_addr_v6.sin6_addr);
			probe_addr_v6.sin6_port = ntohs(PORT);
		}
		else if(secondary_ipv6_ns[0] != 0 && strcmp(secondary_ipv6_ns, UNKNOWED_IPV6_ADDR))
		{
			strcpy(config.ipv6_name_server, secondary_ipv6_ns);
		}
		
		i += sizeof(struct inotify_event) + event->len;
	}
}

int ipv6_dns_active(void)
{
	/* unknowed ipv6 addr */
	if (!strcmp(primary_ipv6_ns, UNKNOWED_IPV6_ADDR) &&
		!strcmp(secondary_ipv6_ns, UNKNOWED_IPV6_ADDR))
	{
		msg("no ipv6 dns addr\n");
		return 0;
	}

	/* is empty */
	if ((primary_ipv6_ns[0] == 0) && (secondary_ipv6_ns[0] == 0))
	{
		printf("no ipv6 dns addr\n");
		return 0;
	}

	return 1;
}

int ipv4_dns_active(void)
{
	/* unknowed ipv4 addr */
	if (!strcmp(primary_ns, UNKNOWED_IPV4_ADDR) &&
		!strcmp(secondary_ns, UNKNOWED_IPV4_ADDR))
	{
		msg("no ipv4 dns addr\n");
		return 0;
	}
	
	if ((primary_ns[0] == 0) && (secondary_ns[0] == 0))
	{
		msg("no ipv4 dns addr\n");
		return 0;
	}

	return 1;
}
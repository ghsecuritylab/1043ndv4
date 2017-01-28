
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>

int getByteOrder()
{
	int num = 1;
	return *((char *)&num);
}

int create6To4Tunnel(char *interface)
{
	int sock;
	int index, len;
	struct ifreq ifr;
	char cmdStr[80];
	char cmdAddr[20];
	
	sock = socket(AF_INET, SOCK_DGRAM, 0);
	strcpy(ifr.ifr_name, interface);
	
	if (ioctl(sock, SIOCGIFADDR, &ifr) < 0)
	{
		perror("ioctl");
		exit(1);
	}
	
	/* Add a 6to4 tunnel: ip tunnel add 6to4 mode sit remote any local <ipv4 address> */
	sprintf(cmdAddr, "%s", inet_ntoa(((struct sockaddr_in *)&(ifr.ifr_addr))->sin_addr));
	strcpy(cmdStr, "ip tunnel add 6to4 mode sit remote any local ");
	strcat(cmdStr, cmdAddr);
	system(cmdStr);
	printf("%s\n", cmdStr);
	//ip tunnel add 6to4 mode sit remote any local 172.31.20.77
	/* Set up the 6to4 tunnel: ifconfig 6to4 up */
	strcpy(cmdStr, "ifconfig 6to4 up");
	system(cmdStr);
	printf("%s\n", cmdStr);
	
	/* Set the IPv6 address of the tunnel-end-point: ip -6 addr add <6to4 address>/16 dev 6to4 */	
	sprintf(cmdAddr, "%lx", ((struct sockaddr_in *)&(ifr.ifr_addr))->sin_addr);
	len = strlen(cmdAddr);
	for (index = 0; index < 9; index++)
	{
		if (index == 4)
		{
			cmdAddr[index] = ':';
		}
		else
		{
			len--;
			if (len < 0)
			{
				cmdAddr[8 - index] = '0';
			}
			else
			{
				cmdAddr[8 - index] = cmdAddr[len];
			}
		} 
	}
	if (1 == getByteOrder())
	{
		cmdAddr[9] = cmdAddr[0];
		cmdAddr[0] = cmdAddr[7];
		cmdAddr[7] = cmdAddr[9];
		cmdAddr[9] = cmdAddr[1];
		cmdAddr[1] = cmdAddr[8];
		cmdAddr[8] = cmdAddr[9];
		
		cmdAddr[9] = cmdAddr[2];
		cmdAddr[2] = cmdAddr[5];
		cmdAddr[5] = cmdAddr[9];
		cmdAddr[9] = cmdAddr[3];
		cmdAddr[3] = cmdAddr[6];
		cmdAddr[6] = cmdAddr[9];
	}
	cmdAddr[9] = '\0';
	strcpy(cmdStr, "ip -6 addr add 2002:");
	strcat(cmdStr, cmdAddr);
	strcat(cmdStr, "::");
	strcat(cmdStr, cmdAddr);
	//strcat(cmdStr, "/16 dev 6to4");
	strcat(cmdStr, "/16 dev 6to4");
	system(cmdStr);
	printf("%s\n", cmdStr);
	
	/* Set the route: ip -6 route add ::/0 via ::192.88.99.1 dev 6to4 metric 1026 */
	strcpy(cmdStr, "ip -6 route add ::/0 via ::192.88.99.1 dev 6to4 metric 1026");
	system(cmdStr);
	printf("%s\n", cmdStr);
	
	return 0;
}

int delTunnel()
{
	system("ip tunnel del 6to4");
	return 0;
}

int main(int argc, char **argv)
{
	if(argc < 2)
	{
		fprintf(stderr, "Usage: %s Interface\n",argv[0]);
		exit(0);
	}
	
	create6To4Tunnel(argv[1]);
	
	return 0;
}

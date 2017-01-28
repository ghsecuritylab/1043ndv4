/************************************************************
Copyright (C) 2010-2011 TP-LINK TECHNOLOGIES CO., LTD.
File name	: tp_ipc.c
Version		: 1.0
Description	: ipc file for dhcp and httpd
Author		: ZQQ
Create date	: 16Mar2011
History:
---------------------------------------------------------------
1. 16Mar2011 ZQQ Create the file 
****************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/un.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <errno.h>
#include <sys/socket.h>
#include "msgq.h"
#include "tp_ipc.h"


static int msqid = 0;	/*消息队列的标识符*/
//static fd_set rfds;
static unsigned char rcvBuf[MSG_MAX_LEN + 4] = {0};
static int sockfd = 0;

#define ERROR -1
#define OK 1

void printBuf(char *buf, int len)
{
	int i;
	unsigned char *p = buf;

	printf("buf = %08X, len=%d", (unsigned int) buf, len);
	for (i=0; i<len; i++, p++)
	{
		if (i % 16 == 0)
			printf("\n\r%02X ", *p);
		else if (i % 8 == 0)
			printf("- %02X ", *p);
		else
			printf("%02X ", *p);
	}
}



/* added by ZQQ, 12Apr2011 */
static dhcp6cInfo info;
/*end*/


int tp_udhcp_sp_setup()
{
	return udhcp_sp_setup();
}

int tp_udhcp_sp_fd_set(fd_set *pRfds)
{
	return udhcp_sp_fd_set(pRfds, -1);
}

void tp_dhcp_ipc_fork(int module_id)
{
	int cmd = 0;
	int res = 0;
	/* Init the status to -1, see 详解2, 262 by ZQQ, 30Nov11 */
	info.status = -1;

#if 0	
	sockfd = dhcp6c_ipc_socket();
	if (sockfd < 0)
	{
		ipc_msg("dhcp6c_ipc_socket error");
		return;
	}
	
	res = registerMid();
	if(res == ERROR)
	{
		ipc_msg("Register DHCPC errror");
		return;
	}
#endif

	int pid = fork();
	if (pid < 0)
	{
		perror("fork error:");
		exit(0);
	}
	
	if (pid == 0)	/*child*/
	{
		while(1)
		{	
			cmd = 0;
			cmd = dhcp6c_ipc_rcv(module_id);
			if (cmd > 0)
			{
				ipc_msg("cmd = %d\r\n", cmd);
				udhcpv6_sp_ipc_inform(cmd);
			}
			sleep(1);
		}
		exit(0);
	}
}


int recv_httpd_cmd()
{
	struct timeval timeout;
	int retval = 0;
	int rdlen = 0;
	int cmd = 0;
	int max_fd = 0;
	int rdPipe = 0;
	fd_set rfds;
	#define TP_TIMEOUT_MAX 100*1000;	

	/*只监听1秒*/
	timeout.tv_sec = 0;
	timeout.tv_usec = TP_TIMEOUT_MAX;

	//ipc_msg("to get httpd cmd form child process");
	max_fd = tp_udhcp_sp_fd_set(&rfds);
	retval = select(max_fd + 1, &rfds, NULL, NULL, &timeout);
	//ipc_msg("max_fd = %d, retval = %d", max_fd, retval);
	if (-1 == retval)
	{
		perror("select error:");
		return -1;
	}
	else if(retval > 0)
	{
		rdPipe = getReadPipe();
		ipc_msg("rdPipe = %d",rdPipe);
		if(FD_ISSET(rdPipe, &rfds))
		{
			rdlen = read(rdPipe, &cmd, sizeof(int));
			if (rdlen < 0)
			{
				perror("read error:");
				return -1;
			}
			else
			{
				ipc_msg("cmd = %d\r\n", cmd);
				return cmd;
			}
		}
		else
		{
			//ipc_msg("FD_ISSET(rfd, &rfds) Not True\r\n");
		}
	}
	else
	{
		//ipc_msg("no data arrive within 1s.\r\n");
	}
	return -1;
}


int dhcp6c_ipc_socket()
{
	int client_sockfd;	
	int len;
	int res = 0;
	struct sockaddr_un server_sockaddr, cli_sockaddr;
	int result = 0;

	client_sockfd= socket(AF_UNIX, SOCK_STREAM, 0);
	cli_sockaddr.sun_family = AF_UNIX ;
	strcpy(cli_sockaddr.sun_path, IPC_DHCP6C_PATH);
	unlink(cli_sockaddr.sun_path);

	res = bind(client_sockfd, (struct sockaddr * )&cli_sockaddr, sizeof( cli_sockaddr ) ) ;	
	if(res < 0)
	{
		perror("bind error");
		return -1;
	}

	server_sockaddr.sun_family = AF_UNIX;	
	strcpy(server_sockaddr.sun_path, IPC_SERVER_PATH) ;	
	
	len=sizeof(server_sockaddr);	
	result = connect(client_sockfd,( struct sockaddr * )&server_sockaddr,len);	
	if (result < 0)	
	{		
		printf("ClientA::error on connecting \n");				
		return -1;	
	}	
	return client_sockfd;
}

#if 0
int sendRegisterMsg(int sockfd, tp_ipc_module_id mid, int msgType)
{
	int len = 0;	
	UINT32 type = 0;	
	UINT8 buf[8] = {0};		

	type = (msgType == IPC_REGISTER) ? 0xFFFFFFFF : 0xEEEEEEEE;
	*(UINT32*)buf = type;	
	*(UINT32*)(buf + 4) = mid;	

	len = send(sockfd, buf, 8, 0);	
	if(len < 0)	
	{		
		perror("sendRegisterMsg error");
		return ERROR;	
	}	
	else 	
	{		
		if(msgType == IPC_UNREGISTER)
		{			
			close(sockfd);		
		}		
		return OK;	
	}
}


int dhcp6c_ipc_rcv(int sockfd)
{	
	int maxfd = 0;	
	int res = 0;	
	int nRead = 0;
	int cmd = 0;
	fd_set rset;	
	struct timeval tv;	
	tp_ipc_msg* pMsg = NULL;	
	UINT32* pType = NULL;	
	UINT8 rcvBuf[MSG_MAX_LEN] = {0};

	FD_ZERO(&rset);	
	tv.tv_sec = 0;	
	tv.tv_usec = 200*1000;
	
	do
	{		
		FD_SET(sockfd, &rset);		
		maxfd = sockfd + 1;		
		res = select(maxfd, &rset, NULL, NULL, &tv);
		
		if(res > 0)		
		{			
			if(FD_ISSET(sockfd, &rset))			
			{			
				ioctl(sockfd, FIONREAD, &nRead);
				//ipc_msg("nRead = %d", nRead);
				if(nRead <= 0)
				{
					return 0;
				}
					
				nRead = read(sockfd, rcvBuf, MSG_MAX_LEN);
				ipc_msg("nRead = %d", nRead);
				if(nRead < 0)		
				{				
					perror("read error");	
					continue;				
				}				
				else if(nRead > 0)				
				{					
					pMsg = (tp_ipc_msg*)(rcvBuf + 4);
					/* check the type */			
					pType = (UINT32 *)rcvBuf;
					//printf("Recv data\r\n");
					//printBuf(rcvBuf, nRead);
					//printf("\r\n");
					ipc_msg("*pType = %d, pMsg->srcMid=%d pMsg->dstMid = %d", *pType, pMsg->srcMid, pMsg->dstMid);
					if (*pType != DHCP6C || pMsg->dstMid != DHCP6C)	
					{			
						ipc_msg("IPC:this msg is not for DHCP6C\n");	
						return -2;				
					}					
					if (pMsg->magic != TP_IPC_MAGIC)
					{				
						ipc_msg("IPC:incorrect magic\n");	
						return -3;			
					}					
					if (pMsg->version != TP_IPC_VERSION)	
					{						
						ipc_msg("IPC:unsupported version\n");	
						return -4;				
					}							
					cmd = *(UINT8*)(&pMsg->payload[0]);
					ipc_msg("nRead = %d, cmd = %d", nRead, cmd);					
					return cmd;
				}			
			}
		}	
		else
		{
			return 0;
		}
	}while(0);
}
#endif

int dhcp6c_ipc_rcv(int module_id)
{
	if (msqid <= 0)
	{
		msqid = msgget(MSG_DHCPV6C_KEY, 0);

		if (msqid < 0)
		{
			perror("msgget");
			return msqid;
		}
	}
	
	static UINT8 rcvBuf[MSG_MAX_LEN + 4];
	int nReads = msgrcv(msqid, rcvBuf, MSG_MAX_LEN, module_id, IPC_NOWAIT);
	if (nReads < 0)
		return -1;
	
	tp_ipc_msg* pMsg = (tp_ipc_msg*)(rcvBuf + 4);

	if (pMsg->dstMid != DHCPC)
	{
		printf("IPC:this msg is not for dhcpc\n");
		return -2;
	}

	if (pMsg->magic != TP_IPC_MAGIC)
	{
		printf("IPC:incorrect magic\n");
		return -3;
	}

	if (pMsg->version != TP_IPC_VERSION)
	{
		printf("IPC:unsupported version\n");
		return -4;
	}

	return pMsg->payload[0];
}

#if 0
int dhcp6c_ipc_send(int dstMid, unsigned char* ptr, int nbytes)
{
	int nSnd = 0;
	unsigned char sendBuf[MSG_MAX_LEN] = {0};	
	tp_ipc_msg* pMsg = (tp_ipc_msg*)(sendBuf + 4);
	*((UINT32*)sendBuf) = dstMid;		/* msg type:unix ipc method requested */
	pMsg->magic = TP_IPC_MAGIC;	
	pMsg->version = TP_IPC_VERSION;
	pMsg->dstMid = dstMid;
	pMsg->srcMid = DHCP6C;
	pMsg->msgType = 0; 				/*暂不使用*/
	pMsg->bFrag = 0;				/* httpd_ipc_send not support fragment now */	
	if (nbytes > MSG_MAX_LEN - sizeof(tp_ipc_msg))	
	{		
		ipc_msg("dhcp_ipc_send: msg too log\n");	
		return -1;	
	}	
	memcpy(pMsg->payload, ptr, nbytes);
	nSnd = send(sockfd, sendBuf, nbytes + sizeof(tp_ipc_msg) + 4, MSG_DONTWAIT);
	if(nSnd >= 0)
	{
		ipc_msg("send %d byte success.", nSnd);
	}
	if (nSnd < 0)	
	{		
		ipc_msg("httpd_ipc_send: msgsnd");
		perror("send error:");
		return -2;	
	}	
	return 0;
}
#endif
int dhcp6c_ipc_send(int dstMid, unsigned char* ptr, int nbytes)
{
	if (msqid <= 0)
	{
		msqid = msgget(MSG_DHCPV6C_KEY, 0);

		if (msqid < 0)
		{
			perror("msgget");
			return msqid;
		}
	}
	
	UINT8 sendBuf[MSG_MAX_LEN + 4];		/* 4 bytes long: msg type */
	tp_ipc_msg* pMsg = (tp_ipc_msg*)(sendBuf + 4);
	
	*((UINT32*)sendBuf) = dstMid;		/* msg type:unix ipc method requested */
	pMsg->magic = TP_IPC_MAGIC;
	pMsg->version = TP_IPC_VERSION;
	pMsg->dstMid = dstMid;
	pMsg->srcMid = DHCPC;
	pMsg->msgType = 0;
	pMsg->bFrag = 0;				/* not support fragment now */

	if (nbytes > MSG_MAX_LEN - sizeof(tp_ipc_msg))
	{
		printf("httpd_ipc_send:msg too log\n");
		return -1;
	}

	memcpy(pMsg->payload, ptr, nbytes);

send:
	if (msgsnd(msqid, sendBuf, nbytes + sizeof(tp_ipc_msg), IPC_NOWAIT) < 0)
	{
		printf("msqid:%d mtype:%d\n", msqid, *((UINT32*)sendBuf));
		if (errno == EAGAIN)
			goto send;
		else
		{
			perror("busybox:msgsnd");
			return -2;
		}
	}

	return 0;
}

int update_info()
{
	int res = 0;
	//printf("update_info:\r\n");
	//printBuf(&info, sizeof(dhcp6cInfo));
	res = dhcp6c_ipc_send(HTTPD, (UINT8*)&info, sizeof(dhcp6cInfo));
	if (res < 0)
	{
		ipc_msg("update_info error");
		return ERROR;
	}
	return OK;
}

void setStatus(int status)
{
	ipc_msg("%s %d set info.status = %d", __FUNCTION__, __LINE__, status);
	info.status = status;
}

void setType(int type)
{
	ipc_msg("%s %d set info.type = %d\r\n", __FUNCTION__, __LINE__, type);
	info.type = type;
}


void setIp(unsigned char* pv6Ip)
{
	ipc_msg("%s %d set ip\r\n", __FUNCTION__,__LINE__);
	if(pv6Ip)
	{
		memcpy(info.v6ip, pv6Ip, MAX_IPV6_ADDRESS_LENGTH);
		ipc_msg("%s %d info.v6ip = %s\r\n", __FUNCTION__,__LINE__, info.v6ip);
	}
	else
	{
		ipc_msg("pv6Ip == NULL");
	}
}



void setPrefix(unsigned char* pv6Prefix, int prefixLength)
{
	ipc_msg("%s %d set prefix = %s, prefixLength = %d\r\n", __FUNCTION__, __LINE__, pv6Prefix, prefixLength);
	if (pv6Prefix)
	{
		memcpy(info.v6prefix, pv6Prefix, MAX_IPV6_ADDRESS_LENGTH);
		info.prefixLen = prefixLength;
	}
	else
	{
		ipc_msg("pv6Prefix == NULL");
	}
}

void setDns(unsigned char* pDns1, unsigned char* pDns2)
{
	printf("%s %d set Dns\r\n", __FUNCTION__,__LINE__);
	if(pDns1 != NULL)
	{
		memcpy(&info.v6dns[0][0], pDns1, MAX_IPV6_ADDRESS_LENGTH);	
	}

	if(pDns2 != NULL)
	{
		memcpy(&info.v6dns[1][0], pDns2, MAX_IPV6_ADDRESS_LENGTH);	
	}
}

void resetDhcp6cInfo()
{
	memset(&info, 0, sizeof(info));
}

#if 0
int unRegisterMid()
{
	int res;
	res = sendRegisterMsg(sockfd, DHCP6C, IPC_UNREGISTER);
	return res;
}
int registerMid()
{
	int res;
	res = sendRegisterMsg(sockfd, DHCP6C, IPC_REGISTER);
	return res;
}
#endif

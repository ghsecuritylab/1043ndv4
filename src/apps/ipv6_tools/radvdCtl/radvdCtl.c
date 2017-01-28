#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <dirent.h>
#include <signal.h>
#include <sys/stat.h>
#include <errno.h>
#include <assert.h>
#include <ctype.h>

#define UINT8 unsigned char 
#define UINT32 unsigned int
#define INT32 int
#define OK 1
#define ERROR (-1)
#define TRUE 1
#define FALSE (-1)
#define	PID_DIR			"/var/run"
#define BOOL int
#define READ_BUF_SIZE 	4096
#define MAX_TRY_TIMES	 3
#define PRINTF_D 		printf
#define RADVD_PATH		"/usr/sbin/radvd"
#define RADVD_PID_PATH	"/tmp/radvd.pid"
#define RADVD_CONF_PATH "/tmp/radvd_br0.conf"

/*
./radvdCtl --start --Interface br0 --AdvPrefix 3ffe:501:ffff:100:: --AdvPrefixLen 32 --MaxRtrAdvInterval 10  --MinRtrAdvInterval 3 --AdvManagedFlag on --AdvDefaultLifetime 3600 --AdvRetransTimer 4600 --AdvAutonomous on --AdvCurHopLimit 10 --AdvOtherConfigFlag on  --AdvReachableTime 100 --AdvOnLink on --AdvValidLifetime 1000 --AdvLinkMTU 1280 --AdvPreferredLifetime 100

*/

#define writeSingleStr(f, p) \
do { \
	fwrite(p, strlen(p), 1, f); \
	fwrite("\n", 1, 1, f); \
} while(0)

#define writeStr1Str(f, b, p, i) \
do { \
	sprintf(b, p, i); \
	fwrite(b, strlen(b), 1, f); \
	fwrite("\n", 1, 1, f); \
} while(0)
	

struct radvdOption 
{
	UINT8 	iface[8];	/*interface*/
	UINT32	MaxRtrAdvInterval;
	UINT32 	MinRtrAdvInterval;
	UINT32 	AdvCurHopLimit;
	UINT8	AdvManagedFlag[4];
	UINT8	AdvOtherConfigFlag[4];
	UINT32 	AdvDefaultLifetime;
	UINT32 	AdvReachableTime;
	UINT32  AdvRetransTimer;
	UINT8 	AdvOnLinkFlag[4];		/*prefix*/
	UINT8 	AdvAutonomousFlag[4];	/*prefix*/
	UINT32 	AdvValidLifetime;		/*prefix*/
	UINT32 	AdvPreferredLifetime;	/*prefix*/
	UINT8	AdvPrefix[40];
	UINT32 	AdvLinkMTU;				/*prefix*/
	UINT32	AdvPrefixLen;
	UINT32 	AdvRouteLifetime;

	int input_MaxRtrAdvInterval;
	int input_MinRtrAdvInterval;
	int input_AdvCurHopLimit;
	int input_AdvManagedFlag;
	int input_AdvOtherConfigFlag;
	int input_AdvDefaultLifetime;
	int input_AdvReachableTime;
	int input_AdvRetransTimer;
	int input_AdvOnLinkFlag;
	int input_AdvAutonomousFlag;
	int input_AdvValidLifetime;
	int input_AdvValidLifetime_Infinity;
	int input_AdvPreferredLifetime;
	int input_AdvPreferredLifetime_Infinity;
	/*int input_AdvRetransTimer_Infinity;*/
	int input_AdvPrefix;
	int input_AdvLinkMTU;
	int input_AdvPrefixLen;
	int input_AdvRouteLifetime;
};

int createConfFile(struct radvdOption *pOption);
void usage(void);
BOOL ractlStop(void);
void ractlStart(void);
int createDefaultConfFile(void);
void initRadvdOptions(struct radvdOption *pOption);

int main(int argc, char **argv)
{
	int c = 0;
	int flag = 0;
	int newOptionsFlags = 0;
	int res = 0;
	struct radvdOption raOption;
	static const char *shortopts = "start:stop:help:config";
	static struct option longoptions[] = 
	{
		{"start",  				no_argument,		NULL,	's'},
		{"stop",				no_argument,		NULL,	'k'},
		{"help",				optional_argument,	NULL,	'H'},
		{"Interface",			required_argument,	NULL,	'I'}, /*interface*/
		{"MaxRtrAdvInterval", 	required_argument, 	NULL,	'M'}, /*max retry adv interval*/
		{"MinRtrAdvInterval", 	required_argument, 	NULL, 	'm'},
		{"AdvCurHopLimit", 		required_argument, 	NULL, 	'h'},
		{"AdvManagedFlag", 		required_argument, 	NULL, 	'f'},
		{"AdvOtherConfigFlag", 	required_argument, 	NULL, 	'o'},
		{"AdvDefaultLifetime", 	required_argument, 	NULL, 	't'},
		{"AdvReachableTime", 	required_argument, 	NULL, 	'R'},
		{"AdvRetransTimer", 	required_argument,	NULL, 	'r'},
		{"AdvOnLinkFlag", 		required_argument, 	NULL, 	'l'},
		{"AdvAutonomousFlag", 	required_argument, 	NULL, 	'a'},
		{"AdvValidLifetime", 	required_argument, 	NULL, 	'v'},
		{"AdvPreferredLifetime",required_argument, 	NULL, 	'p'},
		{"AdvPrefix", 			required_argument, 	NULL,	'P'},
		{"AdvLinkMTU", 			required_argument, 	NULL, 	'u'},
		{"AdvPrefixLen", 		required_argument, 	NULL, 	'L'},
		{"AdvRouteLifetime", 	required_argument, 	NULL, 	'T'},
		{0, 0, 0 ,0}
	};
	
	if(argc < 2)
	{
		usage();
	}
	
	initRadvdOptions(&raOption);
	
	while((c = getopt_long(argc, argv, shortopts, longoptions, NULL))!= -1)
	{
		switch(c)
		{
			case 's':
				//printf("%s %d Start radvd\r\n",__FUNCTION__,__LINE__);
				flag = 1;
				break;
				
			case 'k':
				//printf("%s %d Kill radvd\r\n",__FUNCTION__,__LINE__);
				//ractlStop(RADVD_PATH, TRUE);
				if (FALSE == ractlStop())
				{
					//system("echo ractlStop return FALSE >> /tmp/radvdlog");
				}
				return 0;
				
			case 'H':
				usage();
				break;
				
			case 'I':
				strncpy((char *)raOption.iface, optarg, 4);
				printf("%s %d iface = %s\r\n", __FUNCTION__, __LINE__, raOption.iface);
				break;
				
			case 'M':
				raOption.MaxRtrAdvInterval = strtoul(optarg, NULL, 10);
				printf("%s %d MaxRtrAdvInterval = %u\r\n", __FUNCTION__, __LINE__, raOption.MaxRtrAdvInterval);
				raOption.input_MaxRtrAdvInterval = 1;
				newOptionsFlags = 1;
				break;
				
			case 'm':
				raOption.MinRtrAdvInterval = strtoul(optarg, NULL, 10);
				printf("%s %d MinRtrAdvInterval = %u\r\n", __FUNCTION__, __LINE__, raOption.MinRtrAdvInterval);
				newOptionsFlags = 1;
				raOption.input_MinRtrAdvInterval = 1;
				break;
				
			case 'h':
				raOption.AdvCurHopLimit = strtoul(optarg, NULL, 10);
				printf("%s %d AdvCurHopLimit = %u\r\n", __FUNCTION__, __LINE__, raOption.AdvCurHopLimit);
				newOptionsFlags = 1;
				raOption.input_AdvCurHopLimit = 1;
				break;
				
			case 'f':
				if (strcmp(optarg, "true") == 0)
				{
					strcpy((char *)raOption.AdvManagedFlag, "on");
				}
				else
				{
					strcpy((char *)raOption.AdvManagedFlag, "off");
				}
				
				printf("%s %d optarg = %s, AdvManagedFlag = %s\r\n", __FUNCTION__, __LINE__, optarg, raOption.AdvManagedFlag);
				newOptionsFlags = 1;
				raOption.input_AdvManagedFlag = 1;
				break;
				
			case 'o':
				if (strcmp(optarg, "true") == 0)
				{
					strcpy((char *)raOption.AdvOtherConfigFlag, "on");
				}
				else
				{
					strcpy((char *)raOption.AdvOtherConfigFlag, "off");
				}
				printf("%s %d optarg = %s, AdvOtherConfigFlag = %s\r\n", __FUNCTION__, __LINE__, optarg, raOption.AdvOtherConfigFlag);
				newOptionsFlags = 1;
				raOption.input_AdvOtherConfigFlag = 1;
				break;
				
			case 't':
				raOption.AdvDefaultLifetime = strtoul(optarg, NULL, 10);
				printf("%s %d AdvDefaultLifetime = %u\r\n", __FUNCTION__, __LINE__, raOption.AdvDefaultLifetime);
				newOptionsFlags = 1;
				raOption.input_AdvDefaultLifetime = 1;
				break;
				
			case 'R':
				raOption.AdvReachableTime = strtoul(optarg, NULL, 10);
				printf("%s %d AdvReachableTime = %u\r\n", __FUNCTION__, __LINE__, raOption.AdvReachableTime);
				newOptionsFlags = 1;
				raOption.input_AdvReachableTime = 1;
				break;
				
			case 'r':
				#if 0
				if(strcmp(optarg, "0xffffffff") == 0 ||
					strcmp(optarg, "0xFFFFFFFF") == 0 || strtoul(optarg, NULL, 10) == 0xFFFFFFFF)
				{
					raOption.input_AdvRetransTimer_Infinity = 1;
					//printf("%s %d AdvRetransTimer:Infinity\r\n", __FUNCTION__, __LINE__);
				}
				else
				{
					raOption.AdvRetransTimer = strtoul(optarg, NULL, 10);
					printf("%s %d AdvRetransTimer = %u\r\n", __FUNCTION__, __LINE__, raOption.AdvRetransTimer);
				}
				#endif
				raOption.AdvRetransTimer = strtoul(optarg, NULL, 10);
				printf("%s %d AdvRetransTimer = %u\r\n", __FUNCTION__, __LINE__, raOption.AdvRetransTimer);
				newOptionsFlags = 1;
				raOption.input_AdvRetransTimer = 1;
				break;
				
			case 'l':
				if (strcmp(optarg, "true") == 0)
				{
					strcpy((char *)raOption.AdvOnLinkFlag, "on");
				}
				else
				{
					strcpy((char *)raOption.AdvOnLinkFlag, "off");
				}
				printf("%s %d optarg = %s, AdvOnLink = %s\r\n", __FUNCTION__, __LINE__, optarg, raOption.AdvOnLinkFlag);
				newOptionsFlags = 1;
				raOption.input_AdvOnLinkFlag = 1;
				break;
				
			case 'a':
				if (strcmp(optarg, "true") == 0)
				{
					strcpy((char *)raOption.AdvAutonomousFlag, "on");
				}
				else
				{
					strcpy((char *)raOption.AdvAutonomousFlag, "off");
				}
				printf("%s %d optarg = %s, AdvAutonomousFlag = %s\r\n", __FUNCTION__, __LINE__, optarg, raOption.AdvAutonomousFlag);
				newOptionsFlags = 1;
				raOption.input_AdvAutonomousFlag = 1;
				break;		
				
			case 'v':
				if(strcmp(optarg, "0xffffffff") == 0 ||
					strcmp(optarg, "0xFFFFFFFF") == 0 || strtoul(optarg, NULL, 10) == 0xFFFFFFFF)
				{
					raOption.input_AdvValidLifetime_Infinity = 1;
					printf("%s %d AdvValidLifetime:Infinity\r\n", __FUNCTION__, __LINE__);
				}
				else
				{
					raOption.AdvValidLifetime = strtoul(optarg, NULL, 10);
					printf("%s %d AdvValidLifetime = %u\r\n", __FUNCTION__, __LINE__, raOption.AdvValidLifetime);
				}
				
				newOptionsFlags = 1;
				raOption.input_AdvValidLifetime = 1;
				break;
				
			case 'p':
				if(strcmp(optarg, "0xffffffff") == 0 ||
					strcmp(optarg, "0xFFFFFFFF") == 0 || strtoul(optarg, NULL, 10) == 0xFFFFFFFF)
				{
					raOption.input_AdvPreferredLifetime_Infinity = 1;
					printf("%s %d AdvPreferredLifetime:Infinity\r\n", __FUNCTION__, __LINE__);
				}
				else
				{
					raOption.AdvPreferredLifetime = strtoul(optarg, NULL, 10);
					printf("%s %d AdvPreferredLifetime = %u\r\n", __FUNCTION__, __LINE__, raOption.AdvPreferredLifetime);
				}
				
				newOptionsFlags = 1;
				raOption.input_AdvPreferredLifetime = 1;
				break;
				
			case 'P':
				strcpy((char *)raOption.AdvPrefix, optarg);
				printf("%s %d AdvPrefix = %s\r\n", __FUNCTION__, __LINE__, raOption.AdvPrefix);
				newOptionsFlags = 1;
				raOption.input_AdvPrefix = 1;
				break;
				
			case 'u':
				raOption.AdvLinkMTU = strtoul(optarg, NULL, 10);
				printf("%s %d AdvLinkMTU = %u\r\n", __FUNCTION__, __LINE__, raOption.AdvLinkMTU);
				newOptionsFlags = 1;
				raOption.input_AdvLinkMTU = 1;
				break;
				
			case 'L':
				raOption.AdvPrefixLen = atoi(optarg);
				printf("%s %d AdvPrefixLen = %u\r\n", __FUNCTION__, __LINE__, raOption.AdvPrefixLen);
				newOptionsFlags = 1;
				raOption.input_AdvPrefixLen = 1;
				break;
				
			default:
				usage();
				break;
		}
	}	
	
	if (flag == 1)
	{
		if (newOptionsFlags == 1)
		{
			res = createConfFile(&raOption);
			if (res == ERROR)
			{
				//system("echo createConfFile error >> /tmp/radvdlog");
				//system("cd /tmp && tftp -p 192.168.1.201 -r radvdlog");
				return 0;
			}
		}
		else
		{
			res = createDefaultConfFile();
			if ( res == ERROR )
			{
				//system("echo createDefaultConfFile error >> /tmp/radvdlog");
				//system("cd /tmp && tftp -p 192.168.1.11 -r radvdlog");
				return 0;
			}
		}
		ractlStart();		
	}
	return 0;
}



/*

interface br0 
        {
                AdvSendAdvert on;
                MinRtrAdvInterval 3;
                MaxRtrAdvInterval 10;
                prefix 3ffe:501:ffff:100::/64
                {
                        AdvOnLink on;
                        AdvAutonomous on;
                };
        };
*/

int createDefaultConfFile(void)
{
	FILE *fp = NULL;
	if ((fp = fopen(RADVD_CONF_PATH, "w+")) == NULL)
   	{
    	perror("Open file error:");
     	return ERROR;
   	}

	writeSingleStr(fp, "interface br0");
	writeSingleStr(fp, "{");
	writeSingleStr(fp, "\tAdvSendAdvert on;");
	//writeSingleStr(fp, "\tMinRtrAdvInterval 3;");
	//writeSingleStr(fp, "\tMaxRtrAdvInterval 600;");
	writeSingleStr(fp, "\tprefix 3ffe:501:ffff:100::/64");
	writeSingleStr(fp, "\t{");
	writeSingleStr(fp, "\t\tAdvOnLink on;");
	writeSingleStr(fp, "\t\tAdvAutonomous on;");
	writeSingleStr(fp, "\t\tAdvPreferredLifetime 604800;");
	writeSingleStr(fp, "\t\tAdvValidLifetime 2592000;");
	writeSingleStr(fp, "\t};");
	writeSingleStr(fp, "};");
	fclose(fp);
	return OK;
}

int createConfFile(struct radvdOption *pOption)
{
	FILE *fp = NULL;
	char line[64] = {0};
	char prefixStr[64] = {0};
	
	if ((fp = fopen(RADVD_CONF_PATH, "w+")) == NULL)
   	{
    	perror("Open file error:");
     	return ERROR;
   	}

	if (pOption->iface[0] != '\0')
	{
		writeStr1Str(fp, line, "interface %s \n{", pOption->iface);
		writeSingleStr(fp, "\tAdvSendAdvert on;");
	}
	else
	{
		printf("%s %d No interface, return ERROR\r\n", __FUNCTION__,__LINE__);
		fclose(fp);
		return ERROR;
	}

	if (pOption->input_MaxRtrAdvInterval == 1)
	{							
		writeStr1Str(fp, line, "\tMaxRtrAdvInterval %u;", pOption->MaxRtrAdvInterval);
	}
#if 0
	else
	{
		writeSingleStr(fp, "\tMaxRtrAdvInterval 600;");
	}
#endif 
	if (pOption->input_MinRtrAdvInterval == 1)
	{
		writeStr1Str(fp, line, "\tMinRtrAdvInterval %u;", pOption->MinRtrAdvInterval);
	}
	else
	{
		writeSingleStr(fp, "\tMaxRtrAdvInterval 600;");
	}

	if (pOption->input_AdvCurHopLimit == 1)
	{
		writeStr1Str(fp, line, "\tAdvCurHopLimit %u;", pOption->AdvCurHopLimit);
	}
	
	if (pOption->input_AdvManagedFlag == 1)
	{
		writeStr1Str(fp, line, "\tAdvManagedFlag %s;", pOption->AdvManagedFlag);
	}
	
	if (pOption->input_AdvOtherConfigFlag == 1)
	{
		writeStr1Str(fp, line, "\tAdvOtherConfigFlag %s;", pOption->AdvOtherConfigFlag);
	}

	if (pOption->input_AdvLinkMTU == 1)
	{
		writeStr1Str(fp, line, "\tAdvLinkMTU %u;", pOption->AdvLinkMTU);
	}

	if (pOption->input_AdvDefaultLifetime == 1)
	{
		writeStr1Str(fp, line, "\tAdvDefaultLifetime %u;", pOption->AdvDefaultLifetime);
	}

	if (pOption->input_AdvReachableTime == 1)
	{
		writeStr1Str(fp, line, "\tAdvReachableTime %u;", pOption->AdvReachableTime);
	}
		
	if (pOption->input_AdvRetransTimer == 1)
	{
		writeStr1Str(fp, line, "\tAdvRetransTimer %u;", pOption->AdvRetransTimer);
		#if 0
		if (pOption->input_AdvRetransTimer_Infinity == 1)
		{
			writeSingleStr(fp, "\tAdvRetransTimer infinity;");
		}
		else
		{
			writeStr1Str(fp, line, "\tAdvRetransTimer %u;", pOption->AdvRetransTimer);
		}
		#endif
	}
	
	if (pOption->input_AdvPrefix == 1)
	{
		if (pOption->input_AdvPrefixLen == 1)
		{
			sprintf(prefixStr,"%s/%d", pOption->AdvPrefix, pOption->AdvPrefixLen);
			writeStr1Str(fp, line, "\tprefix %s", prefixStr );
		}
		else
		{
			writeStr1Str(fp, line, "\tprefix %s/64", pOption->AdvPrefix);
		}
		writeSingleStr(fp, "\t{");

		if(pOption->input_AdvOnLinkFlag == 1)
		{
			writeStr1Str(fp, line, "\t\tAdvOnLink %s;", pOption->AdvOnLinkFlag);
		}
		else
		{
			writeSingleStr(fp, "\t\tAdvOnLink on;");
		}
		if(pOption->input_AdvAutonomousFlag == 1)
		{
			writeStr1Str(fp, line, "\t\tAdvAutonomous %s;", pOption->AdvAutonomousFlag);
		}
		else
		{
			writeSingleStr(fp, "\t\tAdvAutonomous on;");
		}
		if(pOption->input_AdvValidLifetime == 1)
		{
			if (pOption->input_AdvValidLifetime_Infinity == 1)
			{
				writeSingleStr(fp, "\t\tAdvValidLifetime infinity;");
			}
			else
			{
				writeStr1Str(fp, line, "\t\tAdvValidLifetime %u;", pOption->AdvValidLifetime);
			}
		}
		 
		/* added by ZQQ, 11July2011  RA 的默认值和RFC的不一样*/
		else
		{
			writeSingleStr(fp, "\t\tAdvValidLifetime 2592000;");
		}
		
		if(pOption->input_AdvPreferredLifetime == 1)
		{
			if (pOption->input_AdvPreferredLifetime_Infinity == 1)
			{
				writeSingleStr(fp, "\t\tAdvPreferredLifetime infinity;");
			}
			else
			{
				writeStr1Str(fp, line, "\t\tAdvPreferredLifetime %u;", pOption->AdvPreferredLifetime);
			}
		}
		else
		{
			writeSingleStr(fp, "\t\tAdvPreferredLifetime 604800;");
		}

		writeSingleStr(fp, "\t};");		
	}	
	writeSingleStr(fp, "};");

	fclose(fp);
	return OK;
}

void usage(void)
{
	fprintf(stderr,
	"radvdCtl\n\
	start: to start the radvd process\n\
	stop: to kill the radvd process\n\
	help: show the help\n\
	Example:\n\
	radvdCtl --start --Interface br0 --AdvPrefix 3ffe:501:ffff:100:: --AdvPrefixLen 32 --MaxRtrAdvInterval 10  --MinRtrAdvInterval 3 --AdvManagedFlag on --AdvDefaultLifetime 3600 --AdvRetransTimer 4600 --AdvAutonomous on --AdvCurHopLimit 10 --AdvOtherConfigFlag on  --AdvReachableTime 100 --AdvOnLink on --AdvValidLifetime 1000 --AdvLinkMTU 1280 --AdvPreferredLifetime 100;\n");
}

BOOL killRadvdByProcName(char *procName, BOOL killThem)
{
	DIR *dir;
	struct dirent *next;
	pid_t* pidList=NULL;
	int i=0;
	int listLen = 0;

	/*FILE *status */
	FILE *pProc;
	//static char filename[READ_BUF_SIZE];
	//static char buffer[READ_BUF_SIZE];
	//static char cmdline[128];
	char filename[READ_BUF_SIZE];
	char buffer[READ_BUF_SIZE];
	char cmdline[128];
	char *pOrigCmd, *pFmtCmd;

	/* Delete space in command string */
	pOrigCmd = procName;
	pFmtCmd = cmdline;
	while (*pOrigCmd != '\0')
	{
		if (*pOrigCmd != ' ')
		{
			*pFmtCmd = *pOrigCmd;
			pFmtCmd++;
		}
		pOrigCmd++;
	}
	*pFmtCmd='\0';

	/* dir "/proc" record the information of running process */
	dir = opendir("/proc");
	if (!dir)
	{
		printf("findSystemProc(): Cannot open /proc\r\n");
		return FALSE;
	}

	while (NULL != (next = readdir(dir)))
	{
		/* re-initialize buffers */
		memset(filename, 0, sizeof(filename));
		memset(buffer, 0, sizeof(buffer));	

		/* Must skip ".." since that is outside /proc */
		if (strcmp(next->d_name, "..") == 0)
		{
			continue;
		}

		/* If it isn't a number, we don't want it */
		if (!isdigit(*next->d_name))
		{
			continue;
		}

		/* read /porc/<pid>/cmdline instead to get full cmd line */
		sprintf(filename, "/proc/%s/cmdline", next->d_name);
		if (NULL == (pProc = fopen(filename, "r")))
		{
			continue;
		}
		if (NULL == fgets(buffer, READ_BUF_SIZE-1, pProc))
		{
			fclose(pProc);
			continue;
		}
		fclose(pProc);

		/* buffer contains full commandline params separted by '\0' */
		{ /* remove '\0' from got buffer */
			char *p1 = buffer;
			char *p2 = buffer;
			
			while ( *p1 != '\0' || *(p1+1) != '\0') 
			{
				if (*p1 != '\0') 
				{
				   *p2 = *p1;
				   p2++;
				 }
				 p1++;
			}
			*p2='\0';
		}
		if (NULL != strstr(buffer, cmdline))
		{
			pidList = realloc(pidList, sizeof(pid_t) * (i+2));
			if (!pidList)
			{
				printf("findSystemProc(): Out of memeory!\r\n");
				closedir(dir);
				return FALSE;
			}
			pidList[i++] = strtol(next->d_name, NULL, 0);
		}
	}
	closedir(dir);

	/* set list tail */
	if (pidList)
	{
		pidList[i] = 0;
	}
	else
	{
		free(pidList);
		return FALSE;
	}

	/* kill found process */
	if (killThem)
	{
		listLen = i; 
		for (i=0; i < listLen; i++)
		{
			/* added by ZQQ, 17May2011 dhcp6c 父子进程，需要两者都杀掉，同时在进程被杀掉的时候需要向IPC发送注销通信socket的请求
			但是，kill信号不能被捕捉，所以先发送term信号，然后在发送kill信号
			*/
			if (NULL != strstr(procName, "dhcp6c") || NULL != strstr(procName, "radvd"))
			{
				
				sprintf(cmdline, "kill %d", pidList[i]);
				printf("%s %d cmdline= %s\r\n", __FUNCTION__, __LINE__, cmdline);
				system(cmdline); 
			}
			/*end added*/
#if 0
			sprintf(cmdline, "kill %d", pidList[i]);
//			system(cmdline);
#endif
			if (killThem == 15)
			{
				kill (pidList[i], 15);
			}
			else
			{
				kill (pidList[i], 9);
			}
			sleep(2);
			PRINTF_D(cmdline);
		}
	}
	else
	{
		listLen = i; 
		for (i=0; i < listLen; i++)
		{
			sprintf(cmdline, "match pid[%d]: %d\r\n",i, pidList[i]);
			printf(cmdline);
		}
	}

	free(pidList);

	return TRUE;
}

void ractlStart(void)
{	
	char cmd[128] = {0};	
	int timer = 0;

	/*First stop the radvd and run again by ZQQ, 29Nov11 */
	ractlStop();
	
	sprintf(cmd, "%s -C %s -p %s", RADVD_PATH, "/tmp/radvd_br0.conf", RADVD_PID_PATH);
	system(cmd);
	sleep(1);
	/* 有些测试(不确定的)用例radvd起不来，所以尝试3次 by ZQQ, 28July2011 */
	while (timer++ < MAX_TRY_TIMES)
	{
		if (0 != access(RADVD_PID_PATH, F_OK))
		{
			system("echo try start radvd again >> /tmp/radvdlog");
			system("cd /tmp && tftp -p 192.168.1.11 -r radvdlog");
			system(cmd);
			sleep(1);
		}
		else
		{
			break;
		}
	}
}

void initRadvdOptions(struct radvdOption *pOption)
{
	#if 0
	memset(pOption->iface, 0, 8);
	memset(pOption->AdvAutonomous, 0 , 4);
	pOption->AdvCurHopLimit = -1;
	pOption->AdvDefaultLifetime = -1;
	pOption->AdvLinkMTU = -1;
	memset(pOption->AdvManagedFlag, 0, 4);
	memset(pOption->AdvOnLink, 0, 4);
	memset(pOption->AdvOtherConfigFlag, 0 , 4);
	pOption->AdvPreferredLifetime = -1;
	memset(pOption->AdvPrefix, 0 , 40);
	pOption->AdvPrefixLen = -1;
	pOption->AdvReachableTime = -1;
	pOption->AdvRetransTimer = -1;
	pOption->AdvValidLifetime = -1;
	pOption->MaxRtrAdvInterval = -1;
	pOption->MinRtrAdvInterval = -1;
	#endif
	memset(pOption, 0 , sizeof(struct radvdOption));
}


BOOL killRadvdByPidFile(const char* pidfile, BOOL killIt)
{
	char		pidpath[PATH_MAX]	= {'\0',};
	FILE*		fp					= NULL;
	pid_t		pid					= 0;
	struct stat	st;

	if (NULL == pidfile)
	{
		return FALSE;
	}
	
	/* construct pid path */
	//snprintf(pidpath, PATH_MAX, "%s/%s", PID_DIR, pidfile);
	
//	printf("%s %d pidfile = %s\n",__FUNCTION__,__LINE__, pidfile);
	fp = fopen(pidfile, "r");
	if (NULL == fp)
	{	
		return FALSE;
	}

	/* read out pid */
	fscanf(fp, "%u", &pid);
	assert(pid > 0);

	fclose(fp);

	/* is that process still exist? sending signal 0 to process do not really 
	 * commit signal delivery, only perform error checking */
	if (kill(pid, 0) < 0)
	{
		if (ESRCH == errno)
		{
			/* the process has gone, but its pid file remains, the potential
			 * reason is that the process terminated prematurely, then it's 
			 * our time to cleanup it now.
			 */
			unlink(pidpath);
			return FALSE;
		}
	}
	
	/* right now, we can say the process is present. kill it, if needed */
	if (killIt)
	{
		if (15 == killIt)
		{
			kill(pid, SIGTERM);
		}
		else
		{
			kill(pid, SIGKILL);
		}

		sleep(2);

		/* in case killing the process failed */
		if (0 == kill(pid, 0))
		{
			/* If this still can not work yet, then a disaster must have 
			 * happened, the only thing you can do now is praying... */
			kill(pid, SIGKILL);
		}

		/* in case pppd terminated weirdly, I mean, pppd terminated, but didn't 
		 * unlink its pid file. Thus we unlink the pid file manually here, the 
		 * only probable problem is that there's a time window between two pppd 
		 * detecting processes. However, we have assumed there's only one 
		 * detecting process in system at any time, so that may not be a 
		 * problem. Even if it is, do we need to set file lock?
		 */
		if (0 == stat(pidpath, &st))
		{
			unlink(pidpath);
		}
	}
	
	return TRUE;
}

BOOL ractlStop(void)
{
	if (0 == access(RADVD_PID_PATH, F_OK))
	{
		if (TRUE == killRadvdByPidFile(RADVD_PID_PATH, 15))
		{
			unlink(RADVD_CONF_PATH);
			return TRUE;
		}
		else
		{
			//printf("%s %d here",__FUNCTION__,__LINE__);
			if (TRUE == killRadvdByProcName(RADVD_PATH, TRUE))
			{
				unlink(RADVD_CONF_PATH);
				return TRUE;
			}
			else
			{
				//system("echo kill fail >> /tmp/radvdlog");
				unlink(RADVD_CONF_PATH);
				return FALSE;
			}
		}
	}
	else
	{
		#if 0
		system("echo no pid file, try to kill by cmd name >> /tmp/radvdlog");
		if (TRUE == killRadvdByProcName(RADVD_PATH, TRUE))
		{
			return TRUE;
		}			
		else 
		{
			return FALSE;
		}
		#endif
		return FALSE;
	}
}


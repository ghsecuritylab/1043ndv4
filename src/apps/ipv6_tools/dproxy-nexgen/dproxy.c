#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <arpa/inet.h>
#include <errno.h>
#include <stdarg.h>
#include <signal.h>
#include <syslog.h>
//change by hlf.@20130217
#include "linux/inotify.h"

#include "dproxy.h"
#include "dns_decode.h"
#include "cache.h"
#include "conf.h"
#include "dns_list.h"
#include "dns_construct.h"
#include "dns_io.h"
#include "dns_dyn_cache.h"
#include "dns_probe.h"

int dns_main_quit;
int dns_sock;
int dns_output_sock;
fd_set rfds;
dns_request_t *dns_request_list;
#ifdef DNS_DYN_CACHE
dns_dyn_cache_t *dns_dyn_cache_list;
int dns_dyn_cache_entries;
#endif 

int dns_init()
{
  /* by wdl, 25Feb11, change to support ipv6 */
  struct sockaddr_storage sa;
  struct sockaddr_in6 *local_addr6 = (struct sockaddr_in6 *)&sa;
  /* by wdl, 25Feb11, end change */

  /* Clear it out */
  memset((void *)&sa, 0, sizeof(sa));

  /* by wdl, 25Feb11, change to support IPv6 */
  dns_sock = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
  /* by wdl, 25Feb11, end change */

  /* by wdl, 15Mar11, add sock for proxy in diffrent port */
  dns_output_sock = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
  /* by wdl, 15Mar11, end add */

  /* Error */
  if( dns_sock < 0 ){
     debug_perror("Could not create socket");
     exit(1);
  } 

  /* by wdl, 25Feb11, change to support IPv6 */
  local_addr6->sin6_family = AF_INET6;
  memset(&local_addr6->sin6_addr, 0, sizeof(local_addr6->sin6_addr));
  local_addr6->sin6_port = htons(PORT);
  /* by wdl, 25Feb11, end change */
  
  /* bind() the socket to the interface */
  if (bind(dns_sock, (struct sockaddr *)&sa, sizeof(sa)) < 0){
     debug_perror("dns_init: bind: Could not bind to port");
     exit(1);
  }

  /* by wdl, 15Mar11,  add sock for proxy in diffrent port */
  local_addr6->sin6_port = htons(OUT_PORT);
  
  if (bind(dns_output_sock, (struct sockaddr *)&sa, sizeof(sa)) < 0){
     debug_perror("dns_init: bind: Could not bind to output port");
     exit(1);
  }
  /* by wdl, 15Mar11, end add */

  dns_main_quit = 0;

  //FD_ZERO( &rfds );
  //FD_SET( dns_sock, &rfds );
  //FD_SET( dns_output_sock, &rfds);

  dns_request_list = NULL;

#ifdef DNS_DYN_CACHE
  dns_dyn_cache_list = NULL;
  dns_dyn_cache_entries = 0;
#endif

/* changed by ZQQ, 20May2011 */
#if 0
  cache_purge( config.purge_time );
#endif 

  	//BCM
	dns_probe_init();
  
  return 1;
}
/*****************************************************************************/
void dns_handle_new_query(dns_request_t *m)
{
  struct in6_addr in;       /* by wdl, 25Feb11, change to support ipv6 */
  int retval = -1;
  dns_dyn_cache_t *dns_entry;
  time_t t;
  char buf[100];            /* by wdl, 02Mar11, buf to hold ip addr */

  /* by wdl, 25Feb11, change to support AAAA query */ 
  if((m->message.question[0].type != A) &&
     (m->message.question[0].type != AAAA) &&
     (m->message.question[0].type != PTR))
    return;
  /* by wdl, 25Feb11, end change */
    
  /*BRCM: support IPv4 and IPv6*/
  if( m->message.question[0].type == A || m->message.question[0].type == AAAA){
      /* standard query */
      retval = cache_lookup_name( m->cname, m->ip );
      
#ifdef DNS_DYN_CACHE
      if(1 != retval) {
        dns_entry = dns_dyn_cache_list_find(dns_dyn_cache_list, m);
        if(dns_entry && dns_entry->timestamp > time(NULL)) {
          strncpy(m->ip, inet_ntoa(dns_entry->ip_addr), 20);
          time(&t);
          m->ttl = abs(dns_entry->timestamp - t);
          retval = 1;
        }
        else
          retval = 0;
      }
#endif

  }else if( m->message.question[0].type == PTR ) {
      /* reverse lookup */
      retval = cache_lookup_ip( m->ip, m->cname );

#ifdef DNS_DYN_CACHE
      if(1 != retval) {
        dns_entry = dns_dyn_cache_list_find(dns_dyn_cache_list, m);
        if(dns_entry && dns_entry->timestamp > time(NULL)) {
          strncpy(m->cname, dns_entry->cname, strlen(dns_entry->cname));
          time(&t);
          m->ttl = abs(dns_entry->timestamp - t);
          retval = 1;
        }
        else 
          retval = 0;
      }
#endif

  }
  else //BRCM
  {
      retval = 0;
  }

  debug(".......... %s ---- %s\n", m->cname, m->ip );
  
  switch( retval )
  {
     case 0:
        if(!(m->src_addr.s6_addr[0] == 0 && m->src_addr.s6_addr[1] == 0))
        {
			if (ipv6_dns_active())
			{
				if (config.ipv6_name_server[0] != 0 && strcmp(config.ipv6_name_server, UNKNOWED_IPV6_ADDR))
				{
		    		debug("Adding to list-> id: %d\n", m->message.header.id);
		    		dns_request_list = dns_list_add( dns_request_list, m );
		    		/* relay the query untouched */

	        		debug("dns_handle_new_query: receive packet from '%s' port '%d'\n", 
	            		inet_ntop (AF_INET6, &m->src_addr, buf, 100), m->src_port);
					
	            	/* by wdl, 02Mar11, source addr type is ipv6 and ipv6 dns exist */
	            	inet_pton(AF_INET6, config.ipv6_name_server, &in);
	            	debug("dns_handle_new_query: sending dns query to primary_ipv6_ns\n");
			        /* by wdl, 15Mar11, change output port */
					printf("%s %d output packet\r\n", __FUNCTION__,__LINE__);
					printf("ipv6 config.name_server:%s\n", config.ipv6_name_server);
			        dns_write_packet( dns_output_sock, in, PORT, m );
				}
			}
			else
			{
				return;
			}
        }
        else
        {
			if (ipv4_dns_active())
			{
				if (config.name_server[0] != 0 && strcmp(config.name_server, UNKNOWED_IPV4_ADDR))
				{
					debug("Adding to list-> id: %d\n", m->message.header.id);
					dns_request_list = dns_list_add( dns_request_list, m );
					/* relay the query untouched */

					debug("dns_handle_new_query: receive packet from '%s' port '%d'\n", 
						inet_ntop (AF_INET6, &m->src_addr, buf, 100), m->src_port);

					/* by wdl, 02Mar11, source addr type is ipv4 or in 6to4 */
					strcpy(buf, "::ffff:");     /* by wdl, 01Mar11, change the ipv4 ip to ipv6 ip */
					strcat(buf, config.name_server);
					inet_pton(AF_INET6, buf, &in );
					/* by wdl, 15Mar11, change output port */
					printf("%s %d output packet\r\n", __FUNCTION__,__LINE__);
					printf("config.name_server:%s\n", config.name_server);
					dns_write_packet( dns_output_sock, in, PORT, m );
				}
			}
			else
			{
				return;
			}
        }
		
        /* by wdl, 15Mar11, end change */
        break;
     case 1:
        dns_construct_reply( m );
        dns_write_packet( dns_sock, m->src_addr, m->src_port, m );
        debug("Cache hit\n");
        break;
     default:
        debug("Unknown query type: %d\n", m->message.question[0].type );
   }
}
/*****************************************************************************/
void dns_handle_request(dns_request_t *m)
{
  dns_request_t *ptr = NULL;
  int buf[100];       /* by wdl, 03Mar11, buf to hold ipv6 addr */

#if 0
  /* request may be a new query or a answer from the upstream server */
  ptr = dns_list_find_by_id( dns_request_list, m );

  if( ptr != NULL ){
      debug("Found query in list; id 0x%04x flags 0x%04x ip %s --- cname %s\n", 
             m->message.header.id, m->message.header.flags.flags, m->ip, m->cname);
      
      /* message may be a response */
      if( m->message.header.flags.flags & 0x8000)
      {
          dns_write_packet( dns_sock, ptr->src_addr, ptr->src_port, m );
          dns_request_list = dns_list_remove( dns_request_list, ptr );         
      #if 0 //BRCM: Don't write to cache for saving device resource.
          if( m->message.header.flags.f.rcode == 0 ){ // lookup was succesful
              debug("Cache append: %s ----> %s\n", m->cname, m->ip );
              cache_name_append( m->cname, m->ip );
          }
      #endif
#undef DNS_DYN_CACHE
#ifdef DNS_DYN_CACHE
        dns_dyn_cache_list = dns_dyn_cache_list_add(dns_dyn_cache_list, m);
#endif
    	  //BRCM
    	  dns_probe_activate(m->src_addr);      /* by wdl, 03Mar11, change para */
      }
      else
      {
          debug("Duplicate query\n");
          /* by wdl, 01Mar11, when duplicate query occur, not need to send back to host */
          /* by wdl, 01Mar11,  dns_write_packet( dns_sock, ptr->src_addr, ptr->src_port, m );*/
      }
  }
  else
  {
      dns_handle_new_query( m );
  }
  #endif 
  dns_handle_new_query( m );
}


/*****************************************************************************/
int dns_main_loop()
{
    struct timeval tv;
    int retval;
    dns_request_t m;
    dns_request_t *ptr, *next;
	int max_fd;
	
	#if 0
	int inotify_fd = 0;

	inotify_fd = inotify_init();

	if (inotify_fd < 0)
	{
		perror("inotify_init");
	}
	else
	{
		/* notify ipv4 and ipv6 resolv.conf */
		retval = inotify_add_watch(inotify_fd, STATIC_DNS_FILE_DEFAULT, IN_MODIFY | IN_DELETE);
		if (retval < 0)
		{
			perror("inotify_add_watch");
		}
		
		retval = inotify_add_watch(inotify_fd, STATIC_IPV6_DNS_FILE_DEFAULT, IN_MODIFY | IN_DELETE);
		if (retval < 0)
		{
			perror("inotify_add_watch");
		}
	}
	#endif
	
    while( !dns_main_quit )
    {
        /* set the one second time out */
        tv.tv_sec = 1;
        tv.tv_usec = 0;

		dns_probe();
		
        /* now copy the main rfds in the active one as it gets modified by select*/
        FD_ZERO(&rfds );
        FD_SET(dns_sock, &rfds);
		max_fd = dns_sock;
		FD_SET(dns_output_sock, &rfds);

		if (dns_output_sock > max_fd)
		{
			max_fd = dns_output_sock;
		}

		#if 0
		FD_SET(inotify_fd, &rfds);
		
		if (inotify_fd > max_fd);
		{
			max_fd = inotify_fd;
		}
		#endif

		max_fd++;
        retval = select(max_fd, &rfds, NULL, NULL, &tv );

        if (retval)
		{
			if (FD_ISSET(dns_sock, &rfds))
			{
				/* packet from user(LAN) */
            	memset(&m, 0, sizeof(dns_request_t));
	        	if (dns_read_packet(dns_sock, &m) == 0)
	        	{
	            	dns_handle_request( &m );
	        	}
			}
			else if (FD_ISSET(dns_output_sock, &rfds))
			{
				/* packet From WAN(Server) */
	            memset(&m, 0, sizeof(dns_request_t));

	            /* by wdl, 16Mar11, add output port read */
	            if (dns_read_packet(dns_output_sock, &m) == 0 && !dns_probe_response(&m))
		        {
					dns_handle_request( &m );
	            }
	            /* by wdl, 16Mar11, end add */				
			}
			#if 0
			else if (FD_ISSET(inotify_fd, &rfds))
			{
				/* if resolv.conf modifyed */
				handle_dns_event(inotify_fd);
			}
			#endif
        }
		else
		{
            /* select time out */
            ptr = dns_request_list;
            while( ptr )
			{
                next = ptr->next;
                ptr->time_pending++;
                if( ptr->time_pending > DNS_TIMEOUT )
				{
                    debug("Request timed out\n");
                    /* send error back */
                    dns_construct_error_reply(ptr);
                    dns_write_packet( dns_output_sock, ptr->src_addr, ptr->src_port, ptr );
                    dns_request_list = dns_list_remove( dns_request_list, ptr );
                }
                ptr = next;
            }

			#if 0 /* added by ZQQ, no cache, 20May2011 */
            /* purge cache */
            purge_time--;
            if( !purge_time ){
                cache_purge( config.purge_time );
                purge_time = PURGE_TIMEOUT;
			
            }
			#endif 
		}
		usleep(100*1000);
    }  
	return 0;
}

//BRCM
#ifdef DPROXY_DEBUG
/*****************************************************************************/
void debug_perror( char * msg ) {
	debug( "%s : %s\n" , msg , strerror(errno) );
}

/*****************************************************************************/
void debug(char *fmt, ...)
{
#define MAX_MESG_LEN 1024
  
  va_list args;
  char text[ MAX_MESG_LEN ];
  
  sprintf( text, "[ %d ]: ", getpid());
  va_start (args, fmt);
  vsnprintf( &text[strlen(text)], MAX_MESG_LEN - strlen(text), fmt, args);	 
  va_end (args);
  
  printf(text);
#if 0 //BRCM 
  if( config.debug_file[0] ){
	 FILE *fp;
	 fp = fopen( config.debug_file, "a");
	 if(!fp){
		syslog( LOG_ERR, "could not open log file %m" );
		return;
	 }
	 fprintf( fp, "%s", text);
	 fclose(fp);
  }
  

  /** if not in daemon-mode stderr was not closed, use it. */
  if( ! config.daemon_mode ) {
	 fprintf( stderr, "%s", text);
  }
#endif
}

#endif
/*****************************************************************************
 * print usage informations to stderr.
 * 
 *****************************************************************************/
void usage(char * program , char * message ) {
  fprintf(stderr,"%s\n" , message );
  fprintf(stderr,"usage : %s [-c <config-file>] [-d] [-h] [-P]\n", program );
  fprintf(stderr,"\t-c <config-file>\tread configuration from <config-file>\n");
  fprintf(stderr,"\t-d \t\trun in debug (=non-daemon) mode.\n");
  fprintf(stderr,"\t-D \t\tDomain Name");
  fprintf(stderr,"\t-P \t\tprint configuration on stdout and exit.\n");
  fprintf(stderr,"\t-h \t\tthis message.\n");
}
/*****************************************************************************
 * get commandline options.
 * 
 * @return 0 on success, < 0 on error.
 *****************************************************************************/
int get_options( int argc, char ** argv ) 
{
  char c = 0;
  int not_daemon = 0;
  int want_printout = 0;
  char * progname = argv[0];

  conf_defaults();
#if 1 
  while( (c = getopt( argc, argv, "cD:dhP")) != EOF ) {
    switch(c) {
	 case 'c':
  		conf_load(optarg);
		break;
	 case 'd':
		not_daemon = 1;
		break;
     case 'D':
        strcpy(config.domain_name, optarg);
        break;
	 case 'h':
		usage(progname,"");
		return -1;
	 case 'P':
		want_printout = 1;
		break;
	 default:
		usage(progname,"");
		return -1;
    }
  }
#endif

#if 0  
  /** unset daemon-mode if -d was given. */
  if( not_daemon ) {
	 config.daemon_mode = 0;
  }
  
  if( want_printout ) {
	 conf_print();
	 exit(0);
  }
#endif 

  return 0;
}
/*****************************************************************************/
void sig_hup (int signo)
{
  signal(SIGHUP, sig_hup); /* set this for the next sighup */
  conf_load (config.config_file);
}
/*****************************************************************************/
int main(int argc, char **argv)
{
#if 0
  /* get commandline options, load config if needed. */
  if(get_options( argc, argv ) < 0 ) {
	  exit(1);
  }
#endif 

  signal(SIGHUP, sig_hup);

  dns_init();

//BRCM: Don't fork a task again!
#if 0 
  if (config.daemon_mode) {
    /* Standard fork and background code */
    switch (fork()) {
	 case -1:	/* Oh shit, something went wrong */
		debug_perror("fork");
		exit(-1);
	 case 0:	/* Child: close off stdout, stdin and stderr */
		close(0);
		close(1);
		close(2);
		break;
	 default:	/* Parent: Just exit */
		exit(0);
    }
  }
#endif

  dns_main_loop();

  return 0;
}


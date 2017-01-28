#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "dns_io.h"

/*****************************************************************************/
int dns_read_packet(int sock, dns_request_t *m)
{
/* by wdl, 25Feb11, change to support IPv6 */
	struct sockaddr_storage sa;
	struct sockaddr_in6 *remote_addr6 = (struct sockaddr_in6 *)&sa;
	/* by wdl, 25Feb11, end change */

	/*#struct sockaddr_in sa;*/
  int salen;

  char buf[100];
  
  /* Read in the actual packet */
  salen = sizeof(sa);
  
  m->numread = recvfrom(sock, m->original_buf, sizeof(m->original_buf), 0,
		     (struct sockaddr *)&sa, &salen);
  
  if ( m->numread < 0) {
    debug_perror("dns_read_packet: recvfrom\n");
    return -1;
  }
  
  /* TODO: check source addr against list of allowed hosts */

  /* record where it came from */
   /* by wdl, 03Mar11, change to support ipv6 */
	/*
  memcpy( (void *)&m->src_addr, (void *)&sa.sin_addr, sizeof(struct in_addr));
  m->src_port = ntohs( sa.sin_port );
  	*/
   memcpy( (void *)&m->src_addr, (void *)&remote_addr6->sin6_addr, sizeof(struct in6_addr));

   m->src_port = ntohs( remote_addr6->sin6_port );
 /* by wdl, 03Mar11, end change */
	printf("%s %d  m->src_port = %d\r\n", __FUNCTION__, __LINE__, m->src_port);
  /* check that the message is long enough */
  if( m->numread < sizeof (m->message.header) ){
    debug("dns_read_packet: packet from '%s' too short to be dns packet", 
		 inet_ntop (AF_INET6, &remote_addr6->sin6_addr, buf, 100) );

    return -1;
  }

  /* pass on for full decode */
  dns_decode_request( m );

  return 0;
}
/*****************************************************************************/
/* by wdl, 03Mar11, change second para to support ipv6 */
int dns_write_packet(int sock, struct in6_addr in, int port, dns_request_t *m)
{
	/* by wdl, 25Feb11, change to support IPv6 */

  	struct sockaddr_storage sa;
  	int retval;
	struct sockaddr_in6 *remote_addr6 = (struct sockaddr_in6 *)&sa;
	/* by wdl, 25Feb11, end change */

	/* by wdl, 28Feb11, add some buff to hold ip */
	char buf[100];


  /* Zero it out */
  memset((void *)&sa, 0, sizeof(sa));

  /* Fill in the information */
  /* by wdl, 03Mar11, change to support ipv6 */
  memcpy(&remote_addr6->sin6_addr, &in, sizeof(in) );
  remote_addr6->sin6_port = htons(port);
  remote_addr6->sin6_family = AF_INET6;
	/* by wdl, 03Mar11, end change */
  debug("dns_write_packet: sending packet to '%s' \n", 
		  inet_ntop (AF_INET6, &remote_addr6->sin6_addr, buf, 100));

  retval = sendto(sock, m->original_buf, m->numread, 0, 
		(struct sockaddr *)&sa, sizeof(sa));
  
  if( retval < 0 ){
    debug_perror("dns_write_packet: sendto");
  }

  return retval;
}

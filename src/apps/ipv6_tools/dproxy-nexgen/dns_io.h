#include "dproxy.h"

int dns_read_packet(int sock, dns_request_t *m);
int dns_write_packet(int sock, struct in6_addr in, int port, dns_request_t *m); /* by wdl,
																				   03Mar11,
																				   change second
																				   para to
																				   support ipv6
																				 */

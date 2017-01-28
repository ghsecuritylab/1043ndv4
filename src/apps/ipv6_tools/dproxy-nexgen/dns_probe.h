#ifndef __DNS_PROBE_H
#define __DNS_PROBE_H

#define UNKNOWED_IPV4_ADDR "0.0.0.0"
#define UNKNOWED_IPV6_ADDR "::"

void handle_dns_event(int fd);
int ipv4_dns_active(void);
int ipv6_dns_active(void);
int dns_probe_response(dns_request_t *m);
int dns_probe_activate(struct in6_addr name_server);
void dns_probe(void);
void dns_probe_init(void);

#endif

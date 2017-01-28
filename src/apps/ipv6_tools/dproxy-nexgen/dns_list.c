#include <stdlib.h>
#include <stdlib.h>
#include <string.h>

#include "dns_list.h"

/*****************************************************************************/
dns_request_t *dns_list_add(dns_request_t *list, dns_request_t *m)
{
  dns_request_t *new_node;

  new_node = (dns_request_t *)malloc( sizeof(dns_request_t));
  if( !new_node) return list;

  debug( "Addr: %x\n", new_node);

  memcpy( new_node, m, sizeof (*m) );

  new_node->next = list;
  return new_node;
}
/*****************************************************************************/
dns_request_t *dns_list_find_by_id(dns_request_t *list, dns_request_t *m)
{ 
  while( list != NULL){
     if( list->message.header.id == m->message.header.id )
     {
         if( m->message.header.flags.flags & 0x8000) 
         {
            debug("in dns_list_find_by_id, get response\n");
            return list;
         }
         else
         {  /* by wdl, 03Mar11, for there may be same query under both ipv4 and ipv6, 
             * ipv4 query will send to ipv4 dns, ipv6 query will send to ipv6 dns */
            if( memcmp(&list->src_addr, &m->src_addr, sizeof(m->src_addr)) == 0 )
            {
                return list;
            }
         }
     }
     list = list->next;
  }
  return NULL;
}
/*****************************************************************************/
dns_request_t *dns_list_remove(dns_request_t *list, dns_request_t *m )
{
  dns_request_t *prev, *retval;

  if( !m )return list;

  prev = list;
  while (prev){
    if( prev->next == m)break;
    prev = prev->next;
  }

  if( !prev ){ //must be at start of list
    retval = m->next;
    free( m );
  }else{
    prev->next = m->next;
    retval = list;
    free( m );
  }
  return retval;
}
/*****************************************************************************/
void dns_list_print(dns_request_t *list)
{
  debug("Dumping list:\n");

  while(list){
    debug("    ID: %d ... Name: %s ---- IP: %s\n", list->message.header.id,
	  list->cname, list->ip );
    list = list->next;
  }

}





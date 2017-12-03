/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>


#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);

    /* Add initialization code here! */

} /* -- sr_init -- */

int sr_send_icmp(struct sr_instance* sr, uint8_t *packet, char* interface, uint8_t type, uint8_t code)
{
  size_t icmp_hdr_size = 0;
  size_t max_icmp_size = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t);
  sr_ip_hdr_t *ihdr_old = (sr_ip_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t));

  switch(type)
  {
    case 0:
      icmp_hdr_size = ntohs(ihdr_old->ip_len) - ihdr_old->ip_hl*4;
      break;
    case 11:
      icmp_hdr_size = sizeof(sr_icmp_t11_hdr_t);
      break;
    case 3:
      icmp_hdr_size = sizeof(sr_icmp_t3_hdr_t);
      break;
    default:
      fprintf(stderr, "ICMP type not supported");
      return -1;
  }

  unsigned int len_new = max_icmp_size + icmp_hdr_size;
  uint8_t *packet_new = (uint8_t *) malloc(len_new);
  bzero(packet_new, len_new);
  struct sr_if *if_st = sr_get_interface(sr, interface);

  /* ethernet header */
  sr_ethernet_hdr_t *ehdr = (sr_ethernet_hdr_t *) packet_new;
  sr_ethernet_hdr_t *ehdr_old = (sr_ethernet_hdr_t *) packet;
  memcpy(ehdr->ether_dhost, ehdr_old->ether_shost, ETHER_ADDR_LEN);
  memcpy(ehdr->ether_shost, ehdr_old->ether_dhost, ETHER_ADDR_LEN);
  ehdr->ether_type = htons(ethertype_ip);

  /* ip header */
  sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *) (packet_new + sizeof(sr_ethernet_hdr_t));
  ip_hdr->ip_dst = ihdr_old->ip_src;
  ip_hdr->ip_hl = 5;
  ip_hdr->ip_id = 0;
  ip_hdr->ip_p = ip_protocol_icmp;
  ip_hdr->ip_src = if_st->ip;
  ip_hdr->ip_tos = 0;
  ip_hdr->ip_off = htons(IP_DF);
  ip_hdr->ip_ttl = INIT_TTL;
  ip_hdr->ip_v = 4;

  /* icmp */
  sr_icmp_t0_hdr_t *icmp_hdr_old = (sr_icmp_t0_hdr_t *) (packet + max_icmp_size);
  sr_icmp_t0_hdr_t *icmp_t0_hdr = (sr_icmp_t0_hdr_t *) (packet_new + max_icmp_size);
  sr_icmp_t11_hdr_t *icmp_t11_hdr = (sr_icmp_t11_hdr_t *) (packet_new + max_icmp_size);
  sr_icmp_t3_hdr_t *icmp_t3_hdr = (sr_icmp_t3_hdr_t *) (packet_new + max_icmp_size);

  switch(type)
  {
    case 0:
      icmp_t0_hdr->icmp_code = code;
      icmp_t0_hdr->icmp_type = type;
      icmp_t0_hdr->identifier = icmp_hdr_old->identifier;
      icmp_t0_hdr->sequence_number = icmp_hdr_old->sequence_number;
      icmp_t0_hdr->timestamp = icmp_hdr_old->timestamp;
      memcpy(icmp_t0_hdr->data, icmp_hdr_old->data, icmp_hdr_size - ICMP_ZERO_HEADER_SIZE);
      icmp_t0_hdr->icmp_sum = cksum(packet_new + max_icmp_size, icmp_hdr_size);
      break;

    case 11:
      icmp_t11_hdr->icmp_code = code;
      icmp_t11_hdr->icmp_type = type;
      memcpy(icmp_t11_hdr->data, packet + sizeof(sr_ethernet_hdr_t), ip_hdr->ip_hl*4 + 8);
      icmp_t11_hdr->icmp_sum = cksum(packet_new + max_icmp_size, icmp_hdr_size);
      break;

    case 3:
      icmp_t3_hdr->icmp_code = code;
      icmp_t3_hdr->icmp_type = type;
      memcpy(icmp_t3_hdr->data, packet + sizeof(sr_ethernet_hdr_t), ip_hdr->ip_hl*4 + 8);
      icmp_t3_hdr->icmp_sum = cksum(packet_new + max_icmp_size, icmp_hdr_size);
      break;
  }

  ip_hdr->ip_len = htons(20 + icmp_hdr_size);
  ip_hdr->ip_sum = cksum(packet_new + sizeof(sr_ethernet_hdr_t), ip_hdr->ip_hl * 4);

  /* send now */
  int result = sr_send_packet(sr, packet_new, len_new, interface);
  free(packet_new);

  return result;
}

/*---------------------------------------------------------------------
 * Method: sr_send_arpreply(struct sr_instance *sr, uint8_t *orig_pkt,
 *             unsigned int orig_len, struct sr_if *src_iface)
 * Scope:  Local
 *
 * Send an ARP reply packet in response to an ARP request for one of
 * the router's interfaces
 *---------------------------------------------------------------------*/
void sr_send_arpreply(struct sr_instance *sr, uint8_t *orig_pkt,
    unsigned int orig_len, struct sr_if *src_iface)
{
  /* Allocate space for packet */
  unsigned int reply_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
  uint8_t *reply_pkt = (uint8_t *)malloc(reply_len);
  if (NULL == reply_pkt)
  {
    fprintf(stderr,"Failed to allocate space for ARP reply");
    return;
  }

  sr_ethernet_hdr_t *orig_ethhdr = (sr_ethernet_hdr_t *)orig_pkt;
  sr_arp_hdr_t *orig_arphdr =
      (sr_arp_hdr_t *)(orig_pkt + sizeof(sr_ethernet_hdr_t));

  sr_ethernet_hdr_t *reply_ethhdr = (sr_ethernet_hdr_t *)reply_pkt;
  sr_arp_hdr_t *reply_arphdr =
      (sr_arp_hdr_t *)(reply_pkt + sizeof(sr_ethernet_hdr_t));

  /* Populate Ethernet header */
  memcpy(reply_ethhdr->ether_dhost, orig_ethhdr->ether_shost, ETHER_ADDR_LEN);
  memcpy(reply_ethhdr->ether_shost, src_iface->addr, ETHER_ADDR_LEN);
  reply_ethhdr->ether_type = orig_ethhdr->ether_type;

  /* Populate ARP header */
  memcpy(reply_arphdr, orig_arphdr, sizeof(sr_arp_hdr_t));
  reply_arphdr->ar_hrd = orig_arphdr->ar_hrd;
  reply_arphdr->ar_pro = orig_arphdr->ar_pro;
  reply_arphdr->ar_hln = orig_arphdr->ar_hln;
  reply_arphdr->ar_pln = orig_arphdr->ar_pln;
  reply_arphdr->ar_op = htons(arp_op_reply);
  memcpy(reply_arphdr->ar_tha, orig_arphdr->ar_sha, ETHER_ADDR_LEN);
  reply_arphdr->ar_tip = orig_arphdr->ar_sip;
  memcpy(reply_arphdr->ar_sha, src_iface->addr, ETHER_ADDR_LEN);
  reply_arphdr->ar_sip = src_iface->ip;

  /* Send ARP reply */
  printf("Send ARP reply\n");
  print_hdrs(reply_pkt, reply_len);
  sr_send_packet(sr, reply_pkt, reply_len, src_iface->name);
  free(reply_pkt);
} /* -- sr_send_arpreply -- */

/*---------------------------------------------------------------------
 * Method: sr_send_arprequest(struct sr_instance *sr,
 *             struct sr_arpreq *req,i struct sr_if *out_iface)
 * Scope:  Local
 *
 * Send an ARP reply packet in response to an ARP request for one of
 * the router's interfaces
 *---------------------------------------------------------------------*/
void sr_send_arprequest(struct sr_instance *sr, struct sr_arpreq *req,
    struct sr_if *out_iface)
{
  /* Allocate space for ARP request packet */
  unsigned int reqst_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
  uint8_t *reqst_pkt = (uint8_t *)malloc(reqst_len);
  if (NULL == reqst_pkt)
  {
    fprintf(stderr,"Failed to allocate space for ARP reply");
    return;
  }

  sr_ethernet_hdr_t *reqst_ethhdr = (sr_ethernet_hdr_t *)reqst_pkt;
  sr_arp_hdr_t *reqst_arphdr =
      (sr_arp_hdr_t *)(reqst_pkt + sizeof(sr_ethernet_hdr_t));

  /* Populate Ethernet header */
  memset(reqst_ethhdr->ether_dhost, 0xFF, ETHER_ADDR_LEN);
  memcpy(reqst_ethhdr->ether_shost, out_iface->addr, ETHER_ADDR_LEN);
  reqst_ethhdr->ether_type = htons(ethertype_arp);

  /* Populate ARP header */
  reqst_arphdr->ar_hrd = htons(arp_hrd_ethernet);
  reqst_arphdr->ar_pro = htons(ethertype_ip);
  reqst_arphdr->ar_hln = ETHER_ADDR_LEN;
  reqst_arphdr->ar_pln = sizeof(uint32_t);
  reqst_arphdr->ar_op = htons(arp_op_request);
  memcpy(reqst_arphdr->ar_sha, out_iface->addr, ETHER_ADDR_LEN);
  reqst_arphdr->ar_sip = out_iface->ip;
  memset(reqst_arphdr->ar_tha, 0x00, ETHER_ADDR_LEN);
  reqst_arphdr->ar_tip = req->ip;

  /* Send ARP request */
  printf("Send ARP request\n");
  print_hdrs(reqst_pkt, reqst_len);
  sr_send_packet(sr, reqst_pkt, reqst_len, out_iface->name);
  free(reqst_pkt);
} /* -- sr_send_arprequest -- */

/*---------------------------------------------------------------------
 * Method: sr_handle_arpreq(struct sr_instance *sr,
 *             struct sr_arpreq *req, struct sr_if *out_iface)
 * Scope:  Global
 *
 * Perform processing for a pending ARP request: do nothing, timeout, or
 * or generate an ARP request packet
 *---------------------------------------------------------------------*/
void sr_handle_arpreq(struct sr_instance *sr, struct sr_arpreq *req,
    struct sr_if *out_iface)
{
  time_t now = time(NULL);
  if (difftime(now, req->sent) >= 1.0)
  {
    if (req->times_sent >= 5)
    {
      /*********************************************************************/
      /* TODO: send ICMP host uncreachable to the source address of all    */
      /* packets waiting on this request  */

        struct sr_packet *current = req->packets;
        while (current)
        {
            sr_send_icmp(sr, current->buf, current->iface, 3, 1);
            current = current->next;
        }
      /*********************************************************************/

      sr_arpreq_destroy(&(sr->cache), req);
    }
    else
    {
      /* Send ARP request packet */
      sr_send_arprequest(sr, req, out_iface);

      /* Update ARP request entry to indicate ARP request packet was sent */
      req->sent = now;
      req->times_sent++;
    }
  }
} /* -- sr_handle_arpreq -- */

/*---------------------------------------------------------------------
 * Method: void sr_waitforarp(struct sr_instance *sr, uint8_t *pkt,
 *             unsigned int len, uint32_t next_hop_ip,
 *             struct sr_if *out_iface)
 * Scope:  Local
 *
 * Queue a packet to wait for an entry to be added to the ARP cache
 *---------------------------------------------------------------------*/
void sr_waitforarp(struct sr_instance *sr, uint8_t *pkt,
    unsigned int len, uint32_t next_hop_ip, struct sr_if *out_iface)
{
    struct sr_arpreq *req = sr_arpcache_queuereq(&(sr->cache), next_hop_ip,
            pkt, len, out_iface->name);
    sr_handle_arpreq(sr, req, out_iface);
} /* -- sr_waitforarp -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket_arp(struct sr_instance *sr, uint8_t *pkt,
 *             unsigned int len, struct sr_if *src_iface)
 * Scope:  Local
 *
 * Handle an ARP packet that was received by the router
 *---------------------------------------------------------------------*/
void sr_handlepacket_arp(struct sr_instance *sr, uint8_t *pkt,
    unsigned int len, struct sr_if *src_iface)
{
  /* Drop packet if it is less than the size of Ethernet and ARP headers */
  if (len < (sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t)))
  {
    printf("Packet is too short => drop packet\n");
    return;
  }

  sr_arp_hdr_t *arphdr = (sr_arp_hdr_t *)(pkt + sizeof(sr_ethernet_hdr_t));

  switch (ntohs(arphdr->ar_op))
  {
  case arp_op_request:
  {
    /* Check if request is for one of my interfaces */
    if (arphdr->ar_tip == src_iface->ip)
    { sr_send_arpreply(sr, pkt, len, src_iface); }
    break;
  }
  case arp_op_reply:
  {
    /* Check if reply is for one of my interfaces */
    if (arphdr->ar_tip != src_iface->ip)
    { break; }

    /* Update ARP cache with contents of ARP reply */
    struct sr_arpreq *req = sr_arpcache_insert(&(sr->cache), arphdr->ar_sha,
        arphdr->ar_sip);

    /* Process pending ARP request entry, if there is one */
    if (req != NULL)
    {
      /*********************************************************************/
      /* TODO: send all packets on the req->packets linked list            */
        struct sr_packet *current_packet = req->packets;
        while (current_packet)
        {
            sr_send_arpreply(sr, (uint8_t *)current_packet, (unsigned int)current_packet->len, src_iface);
            current_packet = current_packet->next;
        }
      /*********************************************************************/

      /* Release ARP request entry */
      sr_arpreq_destroy(&(sr->cache), req);
    }
    break;
  }
  default:
    printf("Unknown ARP opcode => drop packet\n");
    return;
  }
} /* -- sr_handlepacket_arp -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

int sr_handle_ip(struct sr_instance* sr, uint8_t * packet, unsigned int len, char* interface)
{
  /* verify length */
  int min_length = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t);
  if (len < min_length)
    {
    fprintf(stderr, "Invalid IP header size");
    return -1;
  }

  sr_ethernet_hdr_t *ether_hdr = (sr_ethernet_hdr_t *) packet;
  sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t));

  /* verify checksum */
  if(!cksum(ip_hdr, ip_hdr->ip_hl))
    {
    fprintf(stderr, "Invalid IP header checksum");
    return -1;
  }

    /* Get interface from ip */
    struct sr_if *interfaces = sr->if_list;
    while (interfaces)
    {
    if (ip_hdr->ip_dst == interfaces->ip) {
      break;
    }
    interfaces = interfaces->next;
  }

  struct sr_if *target_if = interfaces;

    /* Forward */
  if (!target_if)
    {
    if(ip_hdr->ip_ttl <= 1)
    {
      return sr_send_icmp(sr, packet, interface, 11, 0);
    }

    struct sr_rt *rt_node = sr->routing_table;
    while(rt_node)
        {
      if ((ip_hdr->ip_dst & rt_node->mask.s_addr) == rt_node->dest.s_addr)
      {
        struct sr_if *out_if = sr_get_interface(sr, rt_node->interface);
        memcpy(ether_hdr->ether_shost, out_if->addr, ETHER_ADDR_LEN);

        /* Searching the destination MAC address through ARP cache */
        struct sr_arpentry *arp_e = sr_arpcache_lookup(&(sr->cache), rt_node->gw.s_addr);
        if (arp_e)
                {
          memcpy(ether_hdr->ether_dhost, arp_e->mac, ETHER_ADDR_LEN);
          free(arp_e);
          ip_hdr->ip_ttl -= 1;
          ip_hdr->ip_sum = 0;
          ip_hdr->ip_sum = cksum(ip_hdr, ip_hdr->ip_hl*4);
          return sr_send_packet(sr, packet, len, rt_node->interface);
        }
        else
                {
          sr_handle_arpreq(sr, sr_arpcache_queuereq(&(sr->cache), rt_node->gw.s_addr, packet, len, interface), out_if);
          return 0;

        }
      }
      rt_node = rt_node->next;
    }

    /* Destination host unreachable */
    return sr_send_icmp(sr, packet, interface, 3, 1);

  }
  else
    {
    if (ip_hdr->ip_p != ip_protocol_icmp)
    {
      return sr_send_icmp(sr, packet, interface, 3, 3); /* port unreachable */
    }
        else
        {
      /* Ignore if it's not an echo request */
      sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
      if (icmp_hdr->icmp_type == 8 && icmp_hdr->icmp_code == 0)
      {
        return sr_send_icmp(sr, packet, interface, 0, 0);
      }
      else
      {
          return 0;
      }
    }
  }

  return 0;
}

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  printf("*** -> Received packet of length %d \n",len);

  /*************************************************************************/
  /* TODO: Handle packets                                                  */
    /* Check packet type */
  uint16_t ethernet_type = ethertype(packet);
  unsigned int min_length = sizeof(sr_ethernet_hdr_t);

  if (len < min_length)
  {
    fprintf(stderr, "Invalid Ethernet frame size");
    return;
  }

  struct sr_if * sending_if = sr_get_interface(sr, interface);

  switch(ethernet_type)
  {
      case ethertype_arp:
       sr_handlepacket_arp(sr, packet , len, sending_if);
       break;
      case ethertype_ip:
        sr_handle_ip(sr, packet, len, interface);
        break;
      default:
        fprintf(stderr, "Unrecognized Ethernet Type: %d\n", ethernet_type);
        break;
  }
  /*************************************************************************/
}/* end sr_ForwardPacket */

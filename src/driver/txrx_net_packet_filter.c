/* Copyright (C) 2016 TrapX Ltd.                        */


#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/version.h>
#include <linux/in.h>
#include <linux/types.h>
#include <linux/netdevice.h>
#include <linux/inet.h>
#include <net/tcp.h>
#include <linux/if_vlan.h>
#include "fingerp_params.h"



#define error(str,...) printk("fingerp.c:%s:%3d - Error: " str,__FUNCTION__,__LINE__,##__VA_ARGS__);

#define info(str,...) printk("fingerp.c:%s:%3d - Info : " str,__FUNCTION__,__LINE__,##__VA_ARGS__);

#ifdef MY_DEBUG
    #define debug(str,...) printk("fingerp.c:%s:%3d - Debug: " str,__FUNCTION__,__LINE__,##__VA_ARGS__);
#else
    #define debug(str,...)
#endif

/* Print stack trace for debugging */
#define FINGERP_PRINT_STACK_TRACE                                     \
    {                                                                 \
        static unsigned long      t_entries[15];                      \
        static struct stack_trace t;                                  \
        t.nr_entries  = 0;                                            \
        t.max_entries = sizeof(t_entries)/sizeof(t_entries[0]);       \
        t.entries     = t_entries;                                    \
        t.skip        = 1;                                            \
        save_stack_trace(&t);                                         \
        print_stack_trace(&t, 4);                                     \
    }




#if LINUX_VERSION_CODE < KERNEL_VERSION(3,16,0)
/* finger netfilter hook receive function */
unsigned int fingerp_nf_hook_rcv_func(unsigned int hooknum, struct sk_buff* skb, const struct net_device* in, const struct net_device* out, int (*okfn)(struct sk_buff *));
/* finger netfilter hook transmit function (first) */
unsigned int fingerp_nf_hook_snd1_func(unsigned int hooknum,struct sk_buff* skb, const struct net_device* in,  const struct net_device* out,int (*okfn)(struct sk_buff *));
/* finger netfilter hook transmit function (last) */
unsigned int fingerp_nf_hook_snd2_func(unsigned int hooknum,struct sk_buff* skb, const struct net_device* in, const struct net_device* out,int (*okfn)(struct sk_buff *));

#elif LINUX_VERSION_CODE < KERNEL_VERSION(4,10,0)
/* finger netfilter hook receive function */
unsigned int fingerp_nf_hook_rcv_func(void* priv, struct sk_buff* skb, const struct nf_hook_state* state);
/* finger netfilter hook transmit function (first) */
unsigned int fingerp_nf_hook_snd1_func(void* priv, struct sk_buff* skb, const struct nf_hook_state* state);
/* finger netfilter hook transmit function (last) */
unsigned int fingerp_nf_hook_snd2_func(void* priv, struct sk_buff* skb, const struct nf_hook_state* state);

#else /* linux kernel version 4.10.0 and newer */
/* finger netfilter hook receive function */
unsigned int fingerp_nf_hook_rcv_func(void* priv, struct sk_buff* skb, const struct nf_hook_state* state);
/* finger netfilter hook transmit function (first & last) */
unsigned int fingerp_nf_hook_snd2_func(void* priv, struct sk_buff* skb, const struct nf_hook_state* state);
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,10,0)
static struct nf_hook_ops fingerp_nf_hook_ops_arr[] ={
   { .hook     = fingerp_nf_hook_rcv_func,  .pf       = NFPROTO_IPV4, .hooknum  = NF_INET_PRE_ROUTING,   .priority = NF_IP_PRI_FIRST }
  ,{ .hook     = fingerp_nf_hook_snd1_func, .pf       = NFPROTO_IPV4, .hooknum  = NF_INET_POST_ROUTING,  .priority = NF_IP_PRI_FIRST }
  ,{ .hook     = fingerp_nf_hook_snd2_func, .pf       = NFPROTO_IPV4, .hooknum  = NF_INET_POST_ROUTING,  .priority = NF_IP_PRI_LAST  }
};
#else
// Debian10: due to the NF_STOP is deprecated in the newer Linux Kernel versions (4.10.0 and newer),
//           we'll settle for 2 hooks: the first one is to analyze the prerouted traffic packet,
//           and the second one is to analyze the postrouted traffic packet
static struct nf_hook_ops fingerp_nf_hook_ops_arr[] ={
   { .hook     = fingerp_nf_hook_rcv_func,  .pf       = NFPROTO_IPV4, .hooknum  = NF_INET_PRE_ROUTING,   .priority = NF_IP_PRI_FIRST }
  ,{ .hook     = fingerp_nf_hook_snd2_func, .pf       = NFPROTO_IPV4, .hooknum  = NF_INET_POST_ROUTING,  .priority = NF_IP_PRI_FIRST }
};
#endif


#define VALIDATE_HIDDEN_PORT(port) (port == port_222)
#define VALIDATE_MNG_PORT(port) (port == port_7443) || (port == port_5443) || (port == port_8443) || (port == port_9443)
#define VALIDATE_IFACE(net_device,iface) (strcmp(net_device,iface) == 0)

#define VALIDATE_LOOPBACK_IP(iph_saddr,iph_daddr) (loop_back_addr == iph_saddr) || (loop_back_addr == iph_daddr)
#define VALIDATE_T2T_IP(iph_saddr,iph_daddr) (iph_saddr == iph_daddr)
#define VALIDATE_BROADCAST(iph_daddr) ((iph_daddr & broadcast_mask) == broadcast_mask)

unsigned int determine_tcp_prob_type(struct sk_buff* skb){
   
   struct iphdr*  iph = ip_hdr(skb);
   struct tcphdr* tcph = (struct tcphdr*)((unsigned char*)iph + (iph->ihl<<2));
   unsigned short tcplen = ntohs(iph->tot_len) - sizeof(struct iphdr); // APL-2559 - calculate whole tcp length, included the header too
   
   int            optlen, option_idx=0,ret = NF_ACCEPT;
   unsigned char options_flags=0, *option; 
   
   struct tcp_option_mss*      mss_options         = NULL;
   struct tcp_option_nop*      nop_options         = NULL;
   struct tcp_option_wnds*     wnds_option         = NULL;
   struct tcp_option_tsval*    tcp_tsval_option    = NULL;
   struct tcp_option_sack_per* tcp_sack_per_option = NULL;
   struct eol_option*          eol                 = NULL;

#define OPT_INIT      0x40
#define OPT_MSS       0x1
#define OPT_NOP       0x2
#define OPT_WNDS      0x4
#define OPT_TSVAL     0x8
#define OPT_SACK_PERM 0x10
#define OPT_EOL       0x20


   options_flags=OPT_INIT;

   if (tcplen < sizeof(struct tcphdr)) {
    // APL-2559 - fragmented tcp packet is arrived and the tcp header is fragmented (tcplen less than the struct tcphdr* size definition)
    //            in this case pass the packet to the NF_QUEUE_NR(0) (osfingerprint demon)
    //            with no changes, don't define it as a probe
    ret = NF_QUEUE_NR(0);
    // printk(KERN_INFO "determine_tcp_prob_type() - filter tcp header fragmented packet iph id: %d iph flags-offset: 0x%x  tcplen: %u totallen: %u\n",
    //         iph->id, iph->frag_off, tcplen, (unsigned short)ntohs(iph->tot_len));
    return ret;
   }
   else
    // APL-2559 - it means we've gotten whole tcp header in this packet and can continue to filter it
    tcplen -= sizeof(struct tcphdr);

   /* Calculate option and optlen */
   optlen  = (tcph->doff<<2) - sizeof(struct tcphdr);
   option = (unsigned char*)tcph + sizeof(struct tcphdr);
   if( (optlen > 0) && (tcplen >= (unsigned short)optlen) ) tcplen -= optlen;

   while(option_idx<optlen)
   {
     if((option_idx<optlen) && option[option_idx]==2){ // kind 2  MSS
	   mss_options = (struct tcp_option_mss*)(option+option_idx);
	   option_idx+= mss_options->len;
           options_flags |= OPT_MSS;
	   continue;
     }   
     

     if((option_idx<optlen) &&  option[option_idx] == 1){ // kind 1  NOP 
          nop_options = (struct tcp_option_nop*)(option+option_idx);
     	  option_idx+=sizeof(struct tcp_option_nop);
          options_flags |= OPT_NOP;
          continue;
      }   
  
       
     if((option_idx<optlen) &&  option[option_idx] == 3){ // kind 3  WNDS 
          wnds_option = (struct tcp_option_wnds*)(option+option_idx);
       	  option_idx+=wnds_option->len;
          options_flags |= OPT_WNDS;
          continue;
      }   
  
     
     if((option_idx<optlen) &&  option[option_idx] == 8){ // kind 8  TSVAL 
          tcp_tsval_option = (struct tcp_option_tsval*)(option+option_idx);
       	  option_idx+=tcp_tsval_option->len;
          options_flags |= OPT_TSVAL;
          continue;
      }   

      
      if((option_idx<optlen) &&  option[option_idx] == 4){ // kind 4  SACK_PERM 
          tcp_sack_per_option = (struct tcp_option_sack_per*)(option+option_idx);
       	  option_idx+=tcp_sack_per_option->len;
          options_flags |= OPT_SACK_PERM;
          continue;
      }   

      if((option_idx<optlen) &&  option[option_idx] == 0){ // kind 0 EOL 
          eol = (struct eol_option*)(option+option_idx);
       	  option_idx+=sizeof(struct eol_option);
          options_flags |= OPT_EOL;
          break;
      }   

      
      if((option_idx<optlen) &&  option[option_idx] != 0){ // there is an unsuported kind 
	if(option[option_idx+1]==0) option_idx++;
	else option_idx+= option[option_idx+1];      
      }
            
    }
   
   //filters 
   // 1 
   if(iph->frag_off == 0x00 && tcph->window == ntohs(1024) && tcph->syn == 1     /*&& ntohl(tcph->seq) == 0*/ && tcplen ==0
      && optlen ==4 && (options_flags & OPT_MSS) && ntohs(mss_options->mss) == 1460){
      iph->id = FINGERP_IP_ID_PROB_TYPE_1; 
      ret = NF_QUEUE_NR(0);
      // printk(KERN_INFO "determine_tcp_prob_type() filtter 0  got tcp prob  (MSS)   optlen: %d  options_flags: 0x%.2X  iph->id: %d  \n",
      //     optlen,options_flags,iph->id);
   }
   // 2  
   else if(iph->frag_off == 0x00 && tcph->syn == 1 && tcph->window == ntohs(1) /*&& ntohl(tcph->seq) == 0*/ && tcplen ==0
      && ((options_flags&OPT_WNDS) &&  (options_flags&OPT_MSS) && (options_flags&OPT_TSVAL) && (options_flags&OPT_SACK_PERM) && (options_flags&OPT_NOP)) 
      && wnds_option->shftc == 10 && ntohs(mss_options->mss) == 1460 && tcp_tsval_option->tsval == 0xFFFFFFFF 
      && tcp_tsval_option->tsecr == 0)
   {
     iph->id = FINGERP_IP_ID_PROB_TYPE_2; 
     ret = NF_QUEUE_NR(0);
     //  printk(KERN_INFO "determine_tcp_prob_type() filtter 1  got tcp prob  (MSS & WNDS & TSVAL & SACK_PERM & NOP) optlen: %d  options_flags: 0x%.2X  iph->id: %d \n",
     //	    optlen,options_flags,iph->id);
   
     //   printk(KERN_INFO "wnds_option->shftc: %d  mss_options->mss: %d tcp_sack_per_option->len: %d  tcp_tsval_option->tsval: 0x%.8X  tcp_tsval_option->tsecr: %d\n", 
     //    wnds_option->shftc,ntohs(mss_options->mss),tcp_sack_per_option->len,
     //	    tcp_tsval_option->tsval,tcp_tsval_option->tsecr);

   }
   // 3  
   else if(iph->frag_off == 0x00 && tcph->syn == 1 && tcph->window == ntohs(63) /*&& ntohl(tcph->seq) == 0*/ && tcplen ==0
	   && ( (options_flags&OPT_MSS) && (options_flags&OPT_TSVAL) && (options_flags&OPT_SACK_PERM) && (options_flags&OPT_EOL) ) 
       && ntohs(mss_options->mss) == 1400 && tcp_tsval_option->tsval == 0xFFFFFFFF && tcp_tsval_option->tsecr == 0)
   {
      iph->id = FINGERP_IP_ID_PROB_TYPE_3; 
      ret = NF_QUEUE_NR(0);
      // printk(KERN_INFO "determine_tcp_prob_type() filtter 2  got tcp prob  (MSS & TSVAL & SACK_PERM & EOL) optlen: %d  options_flags: 0x%.2X  iph->id: %d \n",
      //   optlen,options_flags,iph->id);
   } 
   // 4
   else if(iph->frag_off == 0x00 && tcph->syn == 1 && tcph->window == ntohs(4) /*&& ntohl(tcph->seq) == 0*/ && tcplen ==0
           && ( (options_flags&OPT_MSS) && (options_flags&OPT_TSVAL) && (options_flags&OPT_WNDS) && (options_flags&OPT_NOP) ) 
           && wnds_option->shftc == 5 && ntohs(mss_options->mss) == 640 && tcp_tsval_option->tsval == 0xFFFFFFFF && tcp_tsval_option->tsecr == 0)
   {
      iph->id = FINGERP_IP_ID_PROB_TYPE_4; 
      ret = NF_QUEUE_NR(0);
      // printk(KERN_INFO "determine_tcp_prob_type() filtter 3  got tcp prob  (MSS & TSVAL & WNDS & NOP) optlen: %d  options_flags: 0x%.2X  iph->id: %d \n",
      //   optlen,options_flags,iph->id);
   } 
   // 5
   else if(iph->frag_off == 0x00 && tcph->syn == 1 && tcph->window == ntohs(4) /*&& ntohl(tcph->seq) == 0*/ && tcplen ==0
           && ((options_flags&OPT_WNDS) && (options_flags&OPT_TSVAL) && (options_flags&OPT_SACK_PERM) && (options_flags&OPT_EOL) )
           && wnds_option->shftc == 10 && tcp_tsval_option->tsval == 0xFFFFFFFF && tcp_tsval_option->tsecr == 0)
   {
      iph->id = FINGERP_IP_ID_PROB_TYPE_5; 
      ret = NF_QUEUE_NR(0);
      // printk(KERN_INFO "determine_tcp_prob_type() filtter 4  got tcp prob  (MSS & TSVAL & SACK_PERM & EOL) optlen: %d  options_flags: 0x%.2X  iph->id: %d \n",
      //      optlen,options_flags,iph->id);
   } 
   // 6 
   else if(iph->frag_off == 0x00 && tcph->syn == 1 && tcph->window == ntohs(16) /*&& ntohl(tcph->seq) == 0*/ && tcplen ==0
      && ((options_flags&OPT_WNDS) &&  (options_flags&OPT_MSS) && (options_flags&OPT_TSVAL) && (options_flags&OPT_SACK_PERM) && (options_flags&OPT_EOL)) 
      && wnds_option->shftc == 10 && ntohs(mss_options->mss) == 536 && tcp_tsval_option->tsval == 0xFFFFFFFF 
      && tcp_tsval_option->tsecr == 0)
   {
      iph->id = FINGERP_IP_ID_PROB_TYPE_6; 
      ret = NF_QUEUE_NR(0);
      //printk(KERN_INFO "determine_tcp_prob_type() filtter 5  got tcp prob  (MSS & TSVAL & SACK_PERM & WNDS & EOL) optlen: %d  options_flags: 0x%.2X  iph->id: %d \n",
      //    optlen,options_flags,iph->id);
   }
   // 7 
   else if(iph->frag_off == 0x00 && tcph->syn == 1 && tcph->window == ntohs(512) /*&& ntohl(tcph->seq) == 0*/ && tcplen ==0
      && ( (options_flags&OPT_MSS) && (options_flags&OPT_TSVAL) && (options_flags&OPT_SACK_PERM) )
      && ntohs(mss_options->mss) == 265 && tcp_tsval_option->tsval == 0xFFFFFFFF && tcp_tsval_option->tsecr == 0)
   {
      iph->id = FINGERP_IP_ID_PROB_TYPE_7;
      ret = NF_QUEUE_NR(0);
      // printk(KERN_INFO "determine_tcp_prob_type() filtter 6  got tcp prob  (MSS & TSVAL & SACK_PERM ) optlen: %d  options_flags: 0x%.2X  iph->id: %d \n",
      //     optlen,options_flags,iph->id);

      // printk(KERN_INFO "mss_options->mss: %d tcp_sack_per_option->len: %d  tcp_tsval_option->tsval: 0x%.8X  tcp_tsval_option->tsecr: %d\n", 
      //   ntohs(mss_options->mss),tcp_sack_per_option->len, tcp_tsval_option->tsval,tcp_tsval_option->tsecr);

   } 
   // 8  
   else if(iph->frag_off == 0x00 && tcph->syn == 1 && tcph->ece ==1 && tcph->cwr== 1 && tcph->res1 == 8 && tcph->window == ntohs(3) 
     /*&& ntohl(tcph->seq) == 0 && ntohl(tcph->ack) ==0*/ && tcplen ==0 && ((options_flags&OPT_WNDS) &&  (options_flags&OPT_MSS) && (options_flags&OPT_SACK_PERM)) 
      && wnds_option->shftc == 10 && ntohs(mss_options->mss) == 1460 && ntohs(tcph->urg_ptr) == 0xf7f5)
   {
      iph->id = FINGERP_IP_ID_PROB_TYPE_8;
      ret = NF_QUEUE_NR(0);
      //  printk(KERN_INFO "determine_tcp_prob_type() filtter 7  got tcp prob  (MSS & TSVAL & SACK_PERM ) optlen: %d  options_flags: 0x%.2X  iph->id: %d \n",
      //   optlen,options_flags,iph->id);
   }
   // 9 
   else if(iph->frag_off == 0x40       //EYAL TODO there is a NOP in the options should i add it to filtter ? 
           && tcph->syn  == 0  
           && tcph->ece  == 0  
           && tcph->cwr  == 0  
           && tcph->res1 == 0  
           && tcph->urg  == 0  
           && tcph->ack  == 0  
           && tcph->psh  == 0  
           && tcph->rst  == 0  
           && tcph->fin  == 0  
           && tcph->window == ntohs(128) /*&& ntohl(tcph->seq) == 1*/ && tcplen ==0
           && ((options_flags&OPT_WNDS) &&  (options_flags&OPT_MSS) && (options_flags&OPT_TSVAL) && (options_flags&OPT_SACK_PERM)) 
           && wnds_option->shftc == 10 && ntohs(mss_options->mss) == 265 && tcp_tsval_option->tsval == 0xFFFFFFFF 
           && tcp_tsval_option->tsecr == 0)
   {
      iph->id = FINGERP_IP_ID_PROB_TYPE_9;
      ret = NF_QUEUE_NR(0);
      // printk(KERN_INFO "determine_tcp_prob_type() filtter 8  got tcp prob  (MSS & TSVAL & SACK_PERM ) optlen: %d  options_flags: 0x%.2X  iph->id: %d \n",
      //   optlen,options_flags,iph->id);
 
   }
   // 10    
   else if(iph->frag_off == 0x00       
           && tcph->syn  == 1  
           && tcph->urg  == 1  
           && tcph->psh  == 1  
           && tcph->fin  == 1  
           && tcph->window == ntohs(256) /*&& ntohl(tcph->seq) == 0*/ && tcplen ==0
           && ((options_flags&OPT_WNDS) &&  (options_flags&OPT_MSS) && (options_flags&OPT_TSVAL) && (options_flags&OPT_SACK_PERM)) 
           && wnds_option->shftc == 10 && ntohs(mss_options->mss) == 265 && tcp_tsval_option->tsval == 0xFFFFFFFF 
           && tcp_tsval_option->tsecr == 0)
   {
      iph->id = FINGERP_IP_ID_PROB_TYPE_10;
      ret = NF_QUEUE_NR(0); 
      // printk(KERN_INFO "determine_tcp_prob_type() filtter 9  got tcp prob  (MSS & TSVAL & SACK_PERM ) optlen: %d  options_flags: 0x%.2X  iph->id: %d \n",
      //   optlen,options_flags,iph->id);
   }
   // 11 
   else if(iph->frag_off == 0x40       
           && tcph->ack  == 1 
           && tcph->window == ntohs(1024) /*&& ntohl(tcph->seq) == 1*/ && tcplen ==0
           && ((options_flags&OPT_WNDS) &&  (options_flags&OPT_MSS) && (options_flags&OPT_TSVAL) && (options_flags&OPT_SACK_PERM)) 
           && wnds_option->shftc == 10 && ntohs(mss_options->mss) == 265 && tcp_tsval_option->tsval == 0xFFFFFFFF 
           && tcp_tsval_option->tsecr == 0)
   {
      iph->id = FINGERP_IP_ID_PROB_TYPE_11;
      ret = NF_QUEUE_NR(0);
      // printk(KERN_INFO "determine_tcp_prob_type() filtter 10  got tcp prob  (MSS & TSVAL & SACK_PERM ) optlen: %d  options_flags: 0x%.2X  iph->id: %d \n",
      //  optlen,options_flags,iph->id);
   }
   // 12
   else if(iph->frag_off == 0x00 && iph->tos == 0 // EYAL TODO check if to limit  tos test from 8 bit to 6 bit       
           && tcph->window == ntohs(31337) /*&& ntohl(tcph->seq) == 0*/ && tcplen ==0
           && ((options_flags&OPT_WNDS) &&  (options_flags&OPT_MSS) && (options_flags&OPT_TSVAL) && (options_flags&OPT_SACK_PERM)) 
           && wnds_option->shftc == 10 && ntohs(mss_options->mss) == 265 && tcp_tsval_option->tsval == 0xFFFFFFFF 
           && tcp_tsval_option->tsecr == 0)
   {
      iph->id = FINGERP_IP_ID_PROB_TYPE_12;
      ret = NF_QUEUE_NR(0);
      // printk(KERN_INFO "determine_tcp_prob_type() filtter 11  got tcp prob  (MSS & TSVAL & SACK_PERM ) optlen: %d  options_flags: 0x%.2X  iph->id: %d \n",
      //     optlen,options_flags,iph->id);
   }
   // 13 
   else if(iph->frag_off == 0x40 && tcph->ack ==1 && tcph->window == ntohs(32768) /*&& ntohl(tcph->seq) == 1*/ && tcplen ==0
           && ((options_flags&OPT_WNDS) &&  (options_flags&OPT_MSS) && (options_flags&OPT_TSVAL) && (options_flags&OPT_SACK_PERM)) 
           && wnds_option->shftc == 10 && ntohs(mss_options->mss) == 265 && tcp_tsval_option->tsval == 0xFFFFFFFF 
           && tcp_tsval_option->tsecr == 0)
   {
      iph->id = FINGERP_IP_ID_PROB_TYPE_13;
      ret = NF_QUEUE_NR(0);
      // printk(KERN_INFO "determine_tcp_prob_type() filtter 12  got tcp prob  (MSS & TSVAL & SACK_PERM ) optlen: %d  options_flags: 0x%.2X  iph->id: %d \n",
      //     optlen,options_flags,iph->id);
   }
   // 14      
   else if(iph->frag_off == 0x00 && iph->tos == 0 // EYAL TODO check if to limit  tos test from 8 bit to 6 bit             
           && tcph->urg  == 1  
           && tcph->psh  == 1  
           && tcph->fin  == 1  
           && tcph->window == ntohs(65535) /*&& ntohl(tcph->seq) == 1*/ && tcplen ==0
           && ((options_flags&OPT_WNDS) &&  (options_flags&OPT_MSS) && (options_flags&OPT_TSVAL) && (options_flags&OPT_SACK_PERM)) 
           && wnds_option->shftc == 15 && ntohs(mss_options->mss) == 265 && tcp_tsval_option->tsval == 0xFFFFFFFF 
           && tcp_tsval_option->tsecr == 0)
   {
      iph->id =  FINGERP_IP_ID_PROB_TYPE_14;
      ret = NF_QUEUE_NR(0);
      // printk(KERN_INFO "determine_tcp_prob_type() filtter 13  got tcp prob  (MSS & TSVAL & SACK_PERM ) optlen: %d  options_flags: 0x%.2X  iph->id: %d \n",
      //     optlen,options_flags,iph->id);
   }

   //   NESSUS first filter
   // Irena: currently the following probes are not implemented!
   /*else if(iph->frag_off == 0x40        // syn packet to open port
           && tcph->syn  == 1  
           && tcph->ece  == 0  
           && tcph->cwr  == 0  
           && tcph->res1 == 0  
           && tcph->urg  == 0  
           && tcph->ack  == 0  
           && tcph->psh  == 0  
           && tcph->rst  == 0  
           && tcph->fin  == 0  
	   && ((options_flags&OPT_MSS) && (options_flags&OPT_SACK_PERM) && (options_flags&OPT_WNDS) && (options_flags&OPT_NOP) && (options_flags&OPT_TSVAL)))
   { 
     //printk(KERN_INFO "determine_tcp_prob_type()  filter 18  (nessus prob) (MSS & TSVAL & SACK_PERM & WNDS & NOP ) ports: %d | %d\n",
     //       ntohs(tcph->source), ntohs(tcph->dest));
     iph->id =  FINGERP_IP_ID_PROB_TYPE_18;
     ret = NF_QUEUE_NR(0);
   }else if(iph->frag_off == 0x40       // ack packet to open oprt
           && tcph->syn  == 0  
           && tcph->ece  == 0  
           && tcph->cwr  == 0  
           && tcph->res1 == 0  
           && tcph->urg  == 0  
           && tcph->ack  == 1  
           && tcph->psh  == 0  
           && tcph->rst  == 0
           && tcph->fin  == 0
           && ((options_flags&OPT_NOP) && (options_flags&OPT_TSVAL)))
   {
     //printk(KERN_INFO "determine_tcp_prob_type()  filter 19  (nessus prob) (TSVAL & NOP ) ports: %d | %d\n", ntohs(tcph->source), ntohs(tcph->dest));
     iph->id =  FINGERP_IP_ID_PROB_TYPE_19;
     ret = NF_QUEUE_NR(0);
   }else if(iph->frag_off == 0x40      // session to open port e.g port 80 HTTP GET ...... 
           && tcph->syn  == 0  
           && tcph->ece  == 0  
           && tcph->cwr  == 0  
           && tcph->res1 == 0  
           && tcph->urg  == 0  
           && tcph->ack  == 1  
           && tcph->psh  == 1  
           && tcph->rst  == 0  
           && tcph->fin  == 0
           //&& (tcph->window == ntohs(229) || tcph->window == ntohs(237) || tcph->window == ntohs(245))
           && ((options_flags&OPT_NOP) && (options_flags&OPT_TSVAL)))
   {
     //printk(KERN_INFO "determine_tcp_prob_type()  filter 20 (nessus prob ) (TSVAL & NOP ) ports: %d | %d\n", ntohs(tcph->source), ntohs(tcph->dest));
     iph->id =  FINGERP_IP_ID_PROB_TYPE_20;
     ret = NF_QUEUE_NR(0);
   }else if(iph->frag_off == 0x40 && tcph->window == ntohs(4096)
           && tcph->syn  == 1  
           && tcph->ece  == 0  
           && tcph->cwr  == 0  
           && tcph->res1 == 0  
           && tcph->urg  == 0  
           && tcph->ack  == 0  
           && tcph->psh  == 0  
           && tcph->rst  == 0  
           && tcph->fin  == 0 
           && tcplen ==0 && optlen ==8 
           && (options_flags&OPT_MSS) && (options_flags&OPT_NOP) && (options_flags&OPT_SACK_PERM) && ntohs(mss_options->mss) == 1460)
   {
        iph->id = FINGERP_IP_ID_PROB_TYPE_21; 
        ret = NF_QUEUE_NR(0);
	//printk(KERN_INFO "determine_tcp_prob_type() filter 21  got tcp prob  (SYN)  tcplen: %d optlen: %d \n",tcplen,optlen);
   }else if((iph->frag_off == 0x00 || iph->frag_off == 0x40)  
           && tcph->syn  == 1  
           && tcph->ece  == 0  
           && tcph->cwr  == 0  
           && tcph->res1 == 0  
           && tcph->urg  == 0  
           && tcph->ack  == 0  
           && tcph->psh  == 0  
           && tcph->rst  == 0  
           && tcph->fin  == 0 
           && tcplen ==0 && optlen ==0 )
   {
         iph->id = FINGERP_IP_ID_PROB_TYPE_22; 
         ret = NF_QUEUE_NR(0);
         //printk(KERN_INFO "determine_tcp_prob_type() filter 22  got tcp prob  (SYN)  tcplen: %d optlen: %d \n",tcplen,optlen);
   }
   else if(iph->frag_off == 0x00  
           && tcph->syn  == 1  
           && tcph->ece  == 0  
           && tcph->cwr  == 0  
           && tcph->res1 == 0  
           && tcph->urg  == 0  
           && tcph->ack  == 0  
           && tcph->psh  == 0  
           && tcph->rst  == 0  
           && tcph->fin  == 0 
           && tcplen ==0 && optlen ==20
           && ((options_flags&OPT_MSS) && (options_flags&OPT_SACK_PERM) && (options_flags&OPT_WNDS) && (options_flags&OPT_NOP) && (options_flags&OPT_TSVAL)) 
           && ntohs(mss_options->mss) == 1460)
   {
         iph->id = FINGERP_IP_ID_PROB_TYPE_22; 
         ret = NF_QUEUE_NR(0);
         //printk(KERN_INFO "determine_tcp_prob_type() filter 22  got tcp prob  (SYN)  tcplen: %d optlen: %d \n",tcplen,optlen);
   }
   else if(iph->frag_off == 0x00  
           && tcph->syn  == 1  
           && tcph->ece  == 0  
           && tcph->cwr  == 0  
           && tcph->res1 == 0  
           && tcph->urg  == 0  
           && tcph->ack  == 0  
           && tcph->psh  == 0  
           && tcph->rst  == 0  
           && tcph->fin  == 0 
           && tcplen ==0 && optlen ==11
           && (options_flags&OPT_TSVAL))
   {
         iph->id = FINGERP_IP_ID_PROB_TYPE_22; 
         ret = NF_QUEUE_NR(0);
         //printk(KERN_INFO "determine_tcp_prob_type() filter 22  got tcp prob  (SYN)  tcplen: %d optlen: %d \n",tcplen,optlen);
   }
   else if(iph->frag_off == 0x00   
           && tcph->syn  == 0  
           && tcph->ece  == 0  
           && tcph->cwr  == 0  
           && tcph->res1 == 0  
           && tcph->urg  == 0    
           && tcph->ack  == 1    
           && tcph->psh  == 0      
           && tcph->rst  == 0  
           && tcph->fin  == 0 
           && tcplen > 0 && optlen ==0 )
   {    
       iph->id = FINGERP_IP_ID_PROB_TYPE_23; 
       ret = NF_QUEUE_NR(0);
       //printk(KERN_INFO "determine_tcp_prob_type() filter 23  got tcp prob  (ACK)  tcplen: %d \n",tcplen);
   } else if(iph->frag_off == 0x40  
           && tcph->syn  == 1  
           && tcph->ece  == 0  
           && tcph->cwr  == 0  
           && tcph->res1 == 0  
           && tcph->urg  == 0  
           && tcph->ack  == 0  
           && tcph->psh  == 0  
           && tcph->rst  == 0  
           && tcph->fin  == 0 
           && tcplen ==0 && optlen ==20
           && (options_flags&OPT_TSVAL))
   {
         iph->id = FINGERP_IP_ID_PROB_TYPE_31; 
         ret = NF_QUEUE_NR(0);
	 // printk(KERN_INFO "determine_tcp_prob_type() filter 22  got tcp prob  (SYN)  tcplen: %d optlen: %d \n",tcplen,optlen);
   } else if(iph->frag_off == 0x00  
	   && tcph->syn  == 1  
           && tcph->ece  == 0  
           && tcph->cwr  == 0  
           && tcph->res1 == 0  
           && tcph->urg  == 0  
           && tcph->ack  == 1  
           && tcph->psh  == 0  
           && tcph->rst  == 0  
           && tcph->fin  == 0 
	   && tcplen ==0 && optlen ==0)
   {
         iph->id = FINGERP_IP_ID_PROB_TYPE_29; 
         ret = NF_QUEUE_NR(0);
	 // printk(KERN_INFO "###### determine_tcp_prob_type() filter 29  got tcp prob  (synFP)  tcplen: %d optlen: %d  iph->frag_off %d  iph->ttl %d tcph->window %d  \n",
	 //	tcplen,optlen, iph->frag_off, iph->ttl, tcph->window);
   }
   else if(iph->frag_off == 0x00  
           && tcph->syn  == 1  
           && tcph->ece  == 0  
           && tcph->cwr  == 0  
           && tcph->res1 == 0  
           && tcph->urg  == 0  
           && tcph->ack  == 0  
           && tcph->psh  == 0  
           && tcph->rst  == 0  
           && tcph->fin  == 0 
           && tcplen ==0 && optlen ==20
           && ((options_flags&OPT_MSS) && (options_flags&OPT_SACK_PERM) && (options_flags&OPT_WNDS) && (options_flags&OPT_TSVAL)) 
           && ntohs(mss_options->mss) == 1460)
   {
         iph->id = FINGERP_IP_ID_PROB_TYPE_32; 
         ret = NF_QUEUE_NR(0);
         //printk(KERN_INFO "determine_tcp_prob_type() filter 22  got tcp prob  (SYN)  tcplen: %d optlen: %d \n",tcplen,optlen);
   }else if(iph->frag_off == 0x40 && iph->tos ==0             
           && tcph->syn  == 0  
           && tcph->ece  == 0  
           && tcph->cwr  == 0  
           && tcph->res1 == 0  
           && tcph->urg  == 0  
           && tcph->ack  == 1  
           && tcph->psh  == 0  
           && tcph->rst  == 1  
           && tcph->fin  == 0 
           && tcplen ==0 && optlen ==12
           && ((options_flags&OPT_NOP) && (options_flags&OPT_TSVAL)) )
   {
         iph->id = FINGERP_IP_ID_PROB_TYPE_33; 
         ret = NF_QUEUE_NR(0);
         //printk(KERN_INFO "determine_tcp_prob_type() filter 33  got tcp prob  (RESET & ACK)  tcplen: %d optlen: %d \n",tcplen,optlen);
   }else if((iph->frag_off == 0x40 || iph->frag_off == 0x00) && iph->tos ==0             
           && tcph->syn  == 0  
           && tcph->ece  == 0  
           && tcph->cwr  == 0  
           && tcph->res1 == 0  
           && tcph->urg  == 0  
           && tcph->ack  == 0  
           && tcph->psh  == 0  
           && tcph->rst  == 1  
           && tcph->fin  == 0 
           && tcplen ==0 && optlen ==0 )
   {
         iph->id = FINGERP_IP_ID_PROB_TYPE_33;
         ret = NF_QUEUE_NR(0);
         //printk(KERN_INFO "determine_tcp_prob_type() filter 33  got tcp prob  (RESET)  tcplen: %d optlen: %d \n",tcplen,optlen);
   }*/
   else if (tcph->ece  == 0
           && tcph->cwr  == 0
           && tcph->res1 == 0
           && tcph->urg  == 0
           && tcph->ack  == 0
           && tcph->psh  == 0
           && tcph->rst  == 0
           && tcph->fin  == 0
           /*&& tcph->doff == 0*/) {

     // Irena: Send each tcp traffic SYN or NULL scan (APL-2539) packet to the demon.
     // In case the incoming traffic packet ipid is in range 1 - 37
     // we replace the value with the known trap specific FINGERP_IP_ID_PROB_TYPE_SUSPECTED_TRAP id
     if ( iph->id != 0 && (iph->id>>6) == 0 && ((iph->id>>5) == 0 || iph->id < 37) ) {
       iph->id = FINGERP_IP_ID_PROB_TYPE_SUSPECTED_TRAP;
     }

     ret = NF_QUEUE_NR(0);
     // printk(KERN_INFO "determine_tcp_prob_type() - tcp packet filter iph->id: %u iph->frag_off: 0x%x  dst %x : %u | src: %x : %u  optlen: %d  tcplen: %d  syn: 0x%x\n",
     //        iph->id, iph->frag_off, iph->daddr, ntohs(tcph->dest), iph->saddr, ntohs(tcph->source), optlen, tcplen, tcph->syn);
     //Irena:
     //not overriding ipid with 38, in order to not influence the signature when no OS in osf
     //we return NF_ACCEPT here
     //and destroy the scalability to send unknown traffic with ip-id 38 to osf user space demon

    //iph->id = FINGERP_IP_ID_PROB_TYPE_SUSPECTED_TRAP;
    //ret = NF_QUEUE_NR(0);
    //printk(KERN_INFO "determine_tcp_prob_type() nfinger warning  unknown filter !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! \n");
   }

  return ret;
}



unsigned int determine_icmp_prob_type(struct sk_buff* skb){

   struct iphdr*   iph  = ip_hdr(skb);
   struct icmphdr* icmph = (struct icmphdr*)((unsigned char*)iph + (iph->ihl<<2));
   int             data_len, ret = NF_ACCEPT;

   /* Calc data_len */
   data_len  = ntohs(iph->tot_len);
   data_len -= (iph->ihl<<2);
   data_len -= sizeof(struct icmphdr);
    
   if (icmph->type == ICMP_ECHO) {  /*ICMP_ECHO 8*/
      // filter changed due to tos not getting with value as 0 (router issue)
      // 1                                       /*ICMP_ECHO 8*/                 /*ICMP_NET_ANO  9*/
      // if(iph->frag_off == 0x40 && iph->tos == 0 && icmph->type == ICMP_ECHO && icmph->code == ICMP_NET_ANO && ntohs(icmph->un.echo.sequence) == 295)
      if((icmph->un.echo.sequence == FINGERP_NMAP_ICMP_ECHO_SEQ1 ) && (data_len == FINGERP_NMAP_ICMP_ECHO_DATA_LEN1) )
      {
        debug("determine_icmp_prob_type() filter 15  got ICMP  iph->id: %d, 0x%08x -> 0x%08x\n",
               ntohs(iph->id), ntohl(iph->saddr), ntohl(iph->daddr));
        iph->id = FINGERP_IP_ID_PROB_TYPE_15;
        ret = NF_QUEUE_NR(0);
      }
      // filter changed due to tos not getting with value as 4 (router issue)
      //else if(iph->frag_off == 0x00 && iph->tos == 4 && icmph->type == ICMP_ECHO && icmph->code == ICMP_NET_UNREACH && ntohs(icmph->un.echo.sequence) == 296)
      else if((icmph->un.echo.sequence == FINGERP_NMAP_ICMP_ECHO_SEQ2 ) && (data_len == FINGERP_NMAP_ICMP_ECHO_DATA_LEN2) )
      {
        debug("determine_icmp_prob_type() filter 16  got ICMP  iph->id: %d, 0x%08x -> 0x%08x\n",
               ntohs(iph->id), ntohl(iph->saddr), ntohl(iph->daddr));
        iph->id = FINGERP_IP_ID_PROB_TYPE_16;
        ret = NF_QUEUE_NR(0);
      } // 6                                                                            /*ICMP_NET_UNREACH  0*/
      else if(iph->frag_off == 0x00 && iph->tos == 0 && icmph->code == ICMP_NET_UNREACH /*&& ntohs(icmph->un.echo.sequence) == 256*/)
      {
        debug("determine_icmp_prob_type() filter 27  got ICMP  iph->id: %d, 0x%08x -> 0x%08x\n",
               ntohs(iph->id), ntohl(iph->saddr), ntohl(iph->daddr));
        iph->id = FINGERP_IP_ID_PROB_TYPE_27;
        ret = NF_QUEUE_NR(0);
      }//7
      else if(iph->frag_off == 0x40 && iph->tos == 0 && icmph->code == ICMP_NET_UNREACH /*&& ntohs(icmph->un.echo.sequence) == 256*/)
      {
        debug("determine_icmp_prob_type() filter 28  got ICMP  iph->id: %d, 0x%08x -> 0x%08x\n",
               ntohs(iph->id), ntohl(iph->saddr), ntohl(iph->daddr));
        iph->id = FINGERP_IP_ID_PROB_TYPE_28;
        ret = NF_QUEUE_NR(0);
      }
      else {
        debug("determine_icmp_prob_type() filter 38 ICMP_ECHO data_len: %d  seq: %.1d iph->id: %d, 0x%08x -> 0x%08x\n",
               data_len,ntohs(icmph->un.echo.sequence),ntohs(iph->id), ntohl(iph->saddr), ntohl(iph->daddr));
        iph->id = FINGERP_IP_ID_PROB_TYPE_SUSPECTED_TRAP;
        ret = NF_QUEUE_NR(0);
      }
   } // 3                                                    /*ICMP_ADDRESS 17*/               /*ICMP_NET_UNREACH  0*/
   else if(iph->frag_off == 0x00 && iph->tos == 0 && icmph->type == ICMP_ADDRESS && icmph->code == ICMP_NET_UNREACH /*&& ntohs(icmph->un.echo.sequence) == 256*/)
   {
      debug("determine_icmp_prob_type() filter 24  got ICMP  iph->id: %d, 0x%08x -> 0x%08x\n",
             ntohs(iph->id), ntohl(iph->saddr), ntohl(iph->daddr));
      iph->id = FINGERP_IP_ID_PROB_TYPE_24;
      ret = NF_QUEUE_NR(0);
   }
   // 4                                                    /*ICMP_TIMESTAMP 13*/               /*ICMP_NET_UNREACH  0*/
   else if(iph->frag_off == 0x00 && iph->tos == 0 && icmph->type == ICMP_TIMESTAMP && icmph->code == ICMP_NET_UNREACH /*&& ntohs(icmph->un.echo.sequence) == 256*/)
   {
      debug("determine_icmp_prob_type() filter 25  got ICMP  iph->id: %d, 0x%08x -> 0x%08x\n",
             ntohs(iph->id), ntohl(iph->saddr), ntohl(iph->daddr));
      iph->id = FINGERP_IP_ID_PROB_TYPE_25;
      ret = NF_QUEUE_NR(0);
   }                                                       //(domain name request)
   // 5                                                    /*ICMP_DNR 37*/               /*ICMP_NET_UNREACH  0*/   
   else if(iph->frag_off == 0x00 && iph->tos == 0 && icmph->type == ICMP_DNR && icmph->code == ICMP_NET_UNREACH)
   {
      debug("determine_icmp_prob_type() filter 26  got ICMP  iph->id: %d, 0x%08x -> 0x%08x\n",
             ntohs(iph->id), ntohl(iph->saddr), ntohl(iph->daddr));
      iph->id = FINGERP_IP_ID_PROB_TYPE_26;
      ret = NF_QUEUE_NR(0);
   } 
   //else
   //   debug("determine_icmp_prob_type()  data_len: %d  seq: %1d iph->id: %d, 0x%08x -> 0x%08x\n\n",
   //          data_len,ntohs(icmph->un.echo.sequence),ntohs(iph->id), ntohl(iph->saddr), ntohl(iph->daddr));
   return ret;
}



unsigned int determine_icmp_port_unreachable(struct sk_buff *skb){

  struct iphdr   *iph  = ip_hdr(skb);
  struct icmphdr *icmph = (struct icmphdr*)((unsigned char*)iph + (iph->ihl<<2));
  struct iphdr   *icmpd_iph;
  struct udphdr  *icmpd_udph;

  debug("Started (skb=%p)\n",skb);

  /* Set ICMP DATA HEADERs (icmpd_iph) */
  icmpd_iph  = (struct iphdr  *)((unsigned char*)icmph +
         sizeof(struct icmphdr));

  // Ignore if not dest unreacheable                                                                                                                                                                                                                                                                             
  if (icmph->type != ICMP_DEST_UNREACH) {
    debug("Finished (NF_ACCEPT) : icmph->type %d != %d ICMP_DEST_UNREACH, (0x%08x -> 0x%08x)  0x%08x -> 0x%08x\n",
        icmph->type,ICMP_DEST_UNREACH,
        ntohl(icmpd_iph->saddr),
        ntohl(icmpd_iph->daddr),
        ntohl(iph->saddr),
        ntohl(iph->daddr));
    return NF_ACCEPT;
  }

  // Ignore if not port unreacheable                                                                                                                                                                                                                                                                             
  if (icmph->code != ICMP_PORT_UNREACH) {
    debug("Finished (NF_ACCEPT) : icmph->code %d != %d ICMP_PORT_UNREACH, (0x%08x -> 0x%08x)  0x%08x -> 0x%08x\n",
          icmph->code,ICMP_PORT_UNREACH,
          ntohl(icmpd_iph->saddr),
          ntohl(icmpd_iph->daddr),
          ntohl(iph->saddr),
          ntohl(iph->daddr));
    return NF_ACCEPT;
  }

  /* Set ICMP DATA HEADERs (icmpd_iph) */
  //icmpd_iph  = (struct iphdr  *)((unsigned char*)icmph + sizeof(struct icmphdr));

  /* Verify the ICMP data Contain Valid IPv4 header version */
  if (icmpd_iph->version != IPVERSION) {
    debug("Finished (NF_ACCEPT) : icmpd_iph->version %d != %d IPVERSION\n",icmpd_iph->version,IPVERSION);
    return NF_ACCEPT;
  }

  /* Verify the ICMP data Contain minimum IPv4 header length */
  if (icmpd_iph->ihl < 5) {
    debug("Finished (NF_ACCEPT) : icmpd_iph->ihl %d < 5\n",icmpd_iph->ihl);
    return NF_ACCEPT;
  }

  /* Verify the ICMP data contain UDP header after IPv4 header */
  if (icmpd_iph->protocol != IPPROTO_UDP) {
    debug("Finished (NF_ACCEPT) : icmpd_iph->protocol %d != %d IPPROTO_UDP, (0x%08x -> 0x%08x)  0x%08x -> 0x%08x\n",
        icmpd_iph->protocol,IPPROTO_UDP,
        ntohl(icmpd_iph->saddr),
        ntohl(icmpd_iph->daddr),
        ntohl(iph->saddr),
        ntohl(iph->daddr));
    return NF_ACCEPT;
  }

  if ((skb->sk != NULL ) &&  (inet_sk(skb->sk) != NULL ) && (inet_sk(skb->sk)->inet_num == IPPROTO_RAW)) {
    debug("Finished (NF_ACCEPT) : ICMP over IP RAW Socket we ignore it , create by osfingerprint daemon\n");
    return NF_ACCEPT;
  }

  /* Set ICMP DATA HEADERs (icmpd_udph) */
  icmpd_udph = (struct udphdr *)((unsigned char*)icmpd_iph + (icmpd_iph->ihl<<2));
  debug("Identify transmit nmap ICMP port unreachable for UDP (0x%08x:%d -> 0x%08x:%d)  0x%08x -> 0x%08x\n",
        ntohl(icmpd_iph->saddr),
        ntohs(icmpd_udph->source),
        ntohl(icmpd_iph->daddr),
        ntohs(icmpd_udph->dest),
        ntohl(iph->saddr),
        ntohl(iph->daddr));

  /* Send to user space to queue #0 */
  debug("Finished (NF_QUEUE_NR(0) 0x%08x)\n",NF_QUEUE_NR(0));
  
  iph->id = FINGERP_IP_ID_PROB_TYPE_17;
 
  //  iph->id = FINGERP_IP_ID_PROB_TYPE_29;  -->> for nessus port unreach in win 7 should be drop packet 

  //printk(KERN_INFO "determine_icmp_port_unreachable() filtter 1  got ICMP PORT UNREACHABLE  iph->id: %d \n",ntohs(iph->id));
  return NF_QUEUE_NR(0);
}





unsigned int determine_udp_prob_type(struct sk_buff* skb){

   struct iphdr*  iph = ip_hdr(skb);
   struct udphdr* udph = (struct udphdr*)((unsigned char*)iph + (iph->ihl*4));
   struct sockaddr_in dst_addr;
   int ret = NF_ACCEPT;
   unsigned short udp_port = 0;
   unsigned short src_port = 0;

   memset(&dst_addr, 0, sizeof(struct sockaddr_in));  
   dst_addr.sin_addr.s_addr = iph->daddr;     
   // mcast_addr.sin_addr.s_addr= inet_addr("224.0.0.252");


   if(iph->frag_off == 0x40 && iph->tos ==0x00 /*&& ntohs(udph->dest) == 5355*/ && (dst_addr.sin_addr.s_addr&INADDR_UNSPEC_GROUP) ) 
   {
      udp_port = ntohs(udph->source);
      if ((udp_port == 53) || (udp_port == 137)) {
        debug("UDP broadcast traffic from source PORT [%d] will be ACCEPTed\n", udp_port);
        return NF_ACCEPT;
      }
      // APL-2999 - DHCP reply returns back as rcv udp traffic and it can be to the PORT 68, or both PORTs can be 0.
      //            In this case accept the trafic (ignore it)
      src_port = ntohs(udph->dest);
      if (((67 == udp_port) && (68 == src_port)) || ((0 == udp_port) && (0 == src_port))) {
        debug("UDP broadcast traffic from source [0x%08x : %u] dest [0x%08x : %u]\n", iph->saddr, udp_port, iph->daddr, src_port);
        return NF_ACCEPT;
      }
      iph->id = FINGERP_IP_ID_PROB_TYPE_30;
      ret = NF_QUEUE_NR(0);
      debug("UDP broadcast traffic from source PORT [%d] dest PORT [%d] got udp prob 30\n", udp_port, ntohs(udph->dest));
      //printk(KERN_INFO "determine_udp_prob_type() filter 30  got udp prob \n");
   }else if(iph->frag_off == 0x40 && iph->tos ==0x00 /*&& ntohs(udph->dest) == 137*/ ) 
   {
      udp_port = ntohs(udph->source);
      if ((udp_port == 53) || (udp_port == 137)) {
        debug("UDP traffic from source PORT [%d] will be ACCEPTed\n", udp_port);
        return NF_ACCEPT;
      }
      // APL-2999 - DHCP reply returns back as rcv udp traffic and it can be to the PORT 68, or both PORTs can be 0.
      //            In this case accept the trafic (ignore it)
      src_port = ntohs(udph->dest);
      if (((67 == udp_port) && (68 == src_port)) || ((0 == udp_port) && (0 == src_port))) {
        debug("UDP traffic from source [0x%08x : %u] dest [0x%08x : %u]\n", iph->saddr, udp_port, iph->daddr, src_port);
        return NF_ACCEPT;
      }
      iph->id = FINGERP_IP_ID_PROB_TYPE_34;
      ret = NF_QUEUE_NR(0);
      debug("UDP traffic from source PORT [%d] dest PORT [%d] got udp probe 34\n", udp_port, ntohs(udph->dest));
      //printk(KERN_INFO "determine_udp_prob_type() filter 34  got udp prob  \n");
   }else {
      // APL-2554
      // Validate loopback traffic
      if (VALIDATE_LOOPBACK_IP(iph->saddr,iph->daddr)) {
          //if (IPPROTO_ICMP == iph->protocol || IPPROTO_UDP == iph->protocol)
          debug("Finished (NF_ACCEPT) : loopback traffic, protocol: %d\n", iph->protocol);
          return NF_ACCEPT;
      }

      // Validate trap to trap traffic
      if (VALIDATE_T2T_IP(iph->saddr,iph->daddr)) {
          debug("Finished (NF_ACCEPT) : t2t traffic\n");
          return NF_ACCEPT;
      }
     
     //Irena:
     //not overriding ipid with 38, in order to not influence the signature when no OS in osf
     //we return NF_ACCEPT here
     //and destroy the scalability to send unknown traffic with ip-id 38 to osf user space demon
     
     //iph->id = FINGERP_IP_ID_PROB_TYPE_SUSPECTED_TRAP;
     //ret = NF_QUEUE_NR(0);
      //printk(KERN_INFO "determine_udp_prob_type() nfinger warning  unknown filter !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! \n");
   }

   return ret;
}


#if LINUX_VERSION_CODE < KERNEL_VERSION(3,16,0)
unsigned int fingerp_nf_hook_rcv_func(unsigned int hooknum,
                                      struct sk_buff          *skb,
                                      const struct net_device *in,
                                      const struct net_device *out,
                                      int                    (*okfn)(struct sk_buff *))

#else /* linux kernel version 4.9.0 and newer */
unsigned int fingerp_nf_hook_rcv_func(void* priv, struct sk_buff* skb, const struct nf_hook_state* state)
#endif
{
    const __be16   iptype = __constant_htons(ETH_P_IP);
    struct iphdr  *iph;
    int            ret;
    struct tcphdr* tcph;
    unsigned int h_num=0;

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,16,0)
    h_num = hooknum;

    if (okfn == NULL) {
      printk(KERN_INFO "Invalid okfn parameter : okfn=NULL\n");
      debug("Finished (NF_ACCEPT)\n");
      return NF_ACCEPT;
    }
#else /* linux kernel version 4.9.0 and newer */
    struct net_device *in = NULL;
    struct net_device *out = NULL;

    if ((state == NULL) || (state->okfn == NULL)) {
      printk(KERN_INFO "Invalid state parameter(s) : state=%p and/or okfn=NULL\n", state);
      debug("Finished (NF_ACCEPT)\n");
      return NF_ACCEPT;
    }
    h_num= state->hook;
    in = state->in;
    out = state->out;
#endif

    // Validate TAP/DOCKER interface
    if (in) {
      if (VALIDATE_IFACE(in->name, TAP_IFACE) || VALIDATE_IFACE(in->name, DOCKER_IFACE)) {
        debug("Finished (NF_ACCEPT) : in iface: %s\n", in->name);
        return NF_ACCEPT;
      }
    }
    else if (out && (VALIDATE_IFACE(out->name, TAP_IFACE) || VALIDATE_IFACE(out->name, DOCKER_IFACE))) {
        debug("Finished (NF_ACCEPT) : out iface: %s\n", out->name);
        return NF_ACCEPT;
    }

    if ((h_num != NF_INET_PRE_ROUTING) || (skb == NULL ) || (in == NULL) || (out != NULL)) {
      printk(KERN_INFO "Invalid parameter(s) : hooknum=%d,skb=%p,in=%p,out=%p\n", h_num,skb,in,out);
      debug("Finished (NF_ACCEPT)\n");
      return NF_ACCEPT;
    }

    debug("Started (hooknum=%d,skb=%p,in=%p,out=%p)\n",h_num,skb,in,out);

    /* Verify we are handle only IP packet */
    if (skb->protocol != iptype) {
        error("Not IP packet (skb->protocol=0x%04x)\n",ntohs(skb->protocol));
        debug("Finished (NF_ACCEPT)\n");
        return NF_ACCEPT;
    }

    /* set ip header */
    iph = ip_hdr(skb);

    /* Verify correct IP version (IPv4) */
    if (iph->version != IPVERSION) {
        error("IP packet with incorrect version (iph->version=%d)\n",iph->version);
        debug("Finished (NF_ACCEPT)\n");
        return NF_ACCEPT;
    }

    /* Verify minimum IPv4 header length */
    if (iph->ihl < 5) {
        error("IP packet with incorrect header length (iph->ihl=%d)\n",iph->ihl);
        debug("Finished (NF_ACCEPT)\n");
        return NF_ACCEPT;
    }

    // Verify packet to me 
    if (skb->pkt_type != PACKET_HOST)  {
       debug(KERN_INFO "Finished (NF_ACCEPT) : skb->pkt_type %d != %d PACKET_HOST : ignore the packet\n"
             ,skb->pkt_type,PACKET_HOST);
        return NF_ACCEPT;
    }
/*
    // Validate loopback traffic
    if (VALIDATE_LOOPBACK_IP(iph->saddr,iph->daddr)) {
      //if (IPPROTO_ICMP == iph->protocol || IPPROTO_UDP == iph->protocol)
        debug("Finished (NF_ACCEPT) : loopback traffic, protocol: %d\n", iph->protocol);
        return NF_ACCEPT;
    }

    // Validate trap to trap traffic
    if (VALIDATE_T2T_IP(iph->saddr,iph->daddr)) {
        debug("Finished (NF_ACCEPT) : t2t traffic\n");
        return NF_ACCEPT;
    }*/
    // Validate bradcast destination mask
    /*if (VALIDATE_BROADCAST(iph->daddr)) {
        debug("Finished (NF_ACCEPT) : broadcast traffic\n");
        return NF_ACCEPT;
    }*/

    /* Intercept the packet accordingto the protocol / pkt_type */
    switch(iph->protocol) {
    case IPPROTO_TCP: 
      {  
/*
         tcph = (struct tcphdr*)((unsigned char*)iph + (iph->ihl<<2));

         int optlen  = (tcph->doff<<2) - sizeof(struct tcphdr);
         unsigned short tcplen = ntohs(iph->tot_len) - sizeof(struct iphdr) - sizeof(struct tcphdr);

         if(iph->frag_off == 0x00  
	   && tcph->syn  == 1  
           && tcph->ece  == 0  
           && tcph->cwr  == 0  
           && tcph->res1 == 0  
           && tcph->urg  == 0  
           && tcph->ack  == 1  
           && tcph->psh  == 0  
           && tcph->rst  == 0  
           && tcph->fin  == 0 
	   && tcplen ==0 && optlen ==0)
       {
         printk(KERN_INFO "@@@@@@@@@    determine_tcp_prob_type() filter 29  got tcp prob  (synFP)  tcplen: %d optlen: %d  iph->frag_off %d  iph->ttl %d tcph->window %d  \n",
		tcplen,optlen, iph->frag_off, iph->ttl, tcph->window);
       }
       */


	//      if(in)  printk(KERN_INFO "fingerp_nf_hook_rcv_func()   in->name: %s  port : %d \n",  in->name);  
	//  if(out) printk(KERN_INFO "fingerp_nf_hook_rcv_func()   out->name: %s  port : %d \n", out->name);  
        ret=determine_tcp_prob_type(skb);
        if( (iph->id > FINGERP_IP_ID_PROB_TYPE_17 || iph->id == 0) ) {
          // Validate loopback traffic
          if (VALIDATE_LOOPBACK_IP(iph->saddr,iph->daddr)) {
            //if (IPPROTO_ICMP == iph->protocol || IPPROTO_UDP == iph->protocol)
              debug("Finished (NF_ACCEPT) : loopback traffic, protocol: %d\n", iph->protocol);
              return NF_ACCEPT;
          }

          // Validate trap to trap traffic
          if (VALIDATE_T2T_IP(iph->saddr,iph->daddr)) {
              debug("Finished (NF_ACCEPT) : t2t traffic\n");
              return NF_ACCEPT;
          }

          tcph = (struct tcphdr*)((unsigned char*)iph + (iph->ihl<<2));
          /* handle only ifaceX */
          if( (VALIDATE_HIDDEN_PORT(tcph->dest) || VALIDATE_MNG_PORT(tcph->source)) &&
              ( (in && VALIDATE_IFACE(in->name, MNG_IFACE)) || (out && VALIDATE_IFACE(out->name, MNG_IFACE)) ) ) {

            //printk(KERN_INFO "fingerp_nf_hook_rcv_func() dest port: %d  source port: %d \n", ntohs(tcph->dest), ntohs(tcph->source));
            return NF_ACCEPT;
          }
        }

        break;
      }
    case IPPROTO_ICMP: ret=determine_icmp_prob_type(skb); break;
    case IPPROTO_UDP:  ret=determine_udp_prob_type(skb); break;
    default: ret=NF_ACCEPT; break;
    }
  return ret;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,16,0)
unsigned int fingerp_nf_hook_snd1_func(unsigned int hooknum,struct sk_buff *skb,
                                       const struct net_device *in, const struct net_device *out,
                                       int (*okfn)(struct sk_buff *))
#else /* linux kernel version 4.9.0 and newer */
unsigned int fingerp_nf_hook_snd1_func(void* priv, struct sk_buff* skb, const struct nf_hook_state* state)
#endif
{
   // Avoid any change other hooks for IP raw packet (send by osfingerprint daemon)
  //  printk(KERN_INFO "fingerp_nf_hook_snd1_func() skb->sk %p \n",skb->sk);
    //    if ((skb->sk != NULL) && (inet_sk(skb->sk) != NULL ) && 
    //  (inet_sk(skb->sk)->inet_num == IPPROTO_RAW)) 
    /*struct iphdr* iph = ip_hdr(skb);
    if (IPPROTO_ICMP == iph->protocol) {
      info("iph->id=0x%04x, 0x%08x -> 0x%08x\n", ntohs(iph->id), ntohl(iph->saddr), ntohl(iph->daddr));
    }*/
    //struct iphdr* iph;
    if (skb->sk != NULL)
    {
      if(inet_sk(skb->sk) != NULL )
      { 
	//    printk(KERN_INFO "fingerp_nf_hook_snd1_func() inet_sk(skb->sk) %p \n",inet_sk(skb->sk));
        if(inet_sk(skb->sk)->inet_num == IPPROTO_RAW)
        {
            //printk(KERN_INFO "fingerp_nf_hook_snd1_func() inet_sk(skb->sk)->inet_num == IPPROTO_RAW\n");
            struct iphdr* iph = ip_hdr(skb);
	          //printk(KERN_INFO "iph->id=0x%04x\n",ntohs(iph->id));
            // this done since if we send really iph->id zero the net/ipv4/raw.c file 
            // change it to real id , so we put fake iph->id , and then replace it to zero
            if (iph->id == htons(FINGERP_NMAP_IP_ID_ZERO)) 
            {
              //if(in) printk(KERN_INFO "in->mtu %d name %s  \n", in->mtu, in->name); 
              //if(out) printk(KERN_INFO "out->mtu %d name %s \n", out->mtu,out->name); 
              iph->id = 0;         
              iph->check = 0; 
              iph->check = ip_fast_csum((unsigned char *)iph, iph->ihl);
              //printk("iph->check=0x%04x\n",ntohs(iph->check));	             
            }
            //if(iph->protocol==IPPROTO_ICMP) printk(KERN_INFO "ip_id 0x%04x\n ", iph->id);      
           //            info("Finished (NF_STOP) : IP raw packet - not allowed any other hooks (ip_hdr(skb)->ttl=%d)\n",iph->ttl);
           //printk(KERN_INFO "ip_id 0x%04x\n ", iph->id);
           return NF_STOP;
      }
    }
  }
  // Debian10:  It seems the NF_STOP is deprecated for Linux Kernel 4.19 and for the newer ones
  //            Continue with NF_ACCEPT to snd2_func
  return NF_ACCEPT;
}



unsigned int outgoing_tcp_traffic_modification(struct sk_buff* skb){

   int ret = NF_ACCEPT;
//   struct iphdr*  iph = ip_hdr(skb);
   // struct tcphdr* tcph = (struct tcphdr*)((unsigned char*)iph + (iph->ihl*4));
//   struct sockaddr_in s,d, lo; 
//   unsigned char* saddr, *daddr; 
//   s.sin_addr.s_addr = iph->saddr; d.sin_addr.s_addr = iph->daddr; 
//   saddr = (unsigned char*) &(s.sin_addr.s_addr), daddr= (unsigned char*) &(d.sin_addr.s_addr); 
//   lo.sin_addr.s_addr=in_aton(LOOP_BACK_ADDR);
   
    
   //   inet_pton(AF_INET,LOOP_BACK_ADDR,&(lo.sin_addr)); 
   
   //unsigned short tcplen = ntohs(iph->tot_len) - sizeof(struct iphdr) - sizeof(struct tcphdr);
   //int            optlen, option_idx=0;
   //unsigned char  options_flags=0, *option; 

   /*
     set tcp params or send to  q 1
     1. set ttl 
     2. set window size 
     3. check options 
   */

//    if(!(lo.sin_addr.s_addr== s.sin_addr.s_addr || lo.sin_addr.s_addr == d.sin_addr.s_addr)){
        //iph->id = FINGERP_IP_ID_PROB_TYPE_OUT_35;
        ret = NF_QUEUE_NR(1);
//    }else
//    {
      /*       printk(KERN_INFO "outgoing TCP packet filter s_addr [ %u.%u.%u.%u  ]  d_addr [ %u.%u.%u.%u  ]  s_port [ %d  ]  d_port [ %d  ]  verdict NF_ACCEPT \n"
	      ,(unsigned short)saddr[0]
	      ,(unsigned short)saddr[1]
              ,(unsigned short)saddr[2]
              ,(unsigned short)saddr[3]  
	      ,(unsigned short)daddr[0]
	      ,(unsigned short)daddr[1]
              ,(unsigned short)daddr[2]
              ,(unsigned short)daddr[3]  
              ,ntohs(tcph->source), ntohs(tcph->dest) );*/
//    } 

    //if(tcph->dest != ntohs(3307) || tcph->source != ntohs(3307) ){
    // }
    //printk(KERN_INFO "outgoing TCP packet filter FINGERP_IP_ID_PROB_TYPE_OUT_35  nfq(1)\n");
  return ret;
}


unsigned int outgoing_udp_traffic_modification(struct sk_buff* skb){

  //struct iphdr*  iph = ip_hdr(skb);
   // struct udphdr* udph = (struct udphdr*)((unsigned char*)iph + (iph->ihl*4));
   int ret = NF_ACCEPT;
   /*
      set udp params or send to  q 1 
   */
   //iph->id = FINGERP_IP_ID_PROB_TYPE_OUT_36;
   //ret = NF_QUEUE_NR(1);
   //printk(KERN_INFO "outgoing UDP packet filter FINGERP_IP_ID_PROB_TYPE_OUT_36  nfq(1)\n");
  return ret;
}


/*-------------------------------------------------------------------------*/
/*                                                                         */
/*                          <fingerp_nf_hook_snd2_func>                    */
/*                                                                         */
/*  This function handle the netfilter hook function for transmit packets  */
/*                                                                         */
/*  Note: This callback is the LAST hook in the POSTROUTE                  */
/*        and identify packets that transmit that should pass to the       */
/*        userspace (osfingerprint daemon) - Currently ICMP port unreach   */
/*                                                                         */
/*-------------------------------------------------------------------------*/

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,16,0)
unsigned int fingerp_nf_hook_snd2_func(unsigned int hooknum,  struct sk_buff *skb,
                                       const struct net_device *in, const struct net_device *out,
                                       int (*okfn)(struct sk_buff *))

#else /* linux kernel version 4.9.0 and newer */
unsigned int fingerp_nf_hook_snd2_func(void* priv, struct sk_buff* skb, const struct nf_hook_state* state)
#endif
{
    const __be16   iptype = __constant_htons(ETH_P_IP);
    struct iphdr  *iph;
    int            ret;
    struct tcphdr* tcph;

    unsigned int h_num=0;
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,16,0)
    h_num = hooknum;

    if (okfn == NULL) {
      printk(KERN_INFO "Invalid okfn parameter : okfn=NULL\n");
      debug("Finished (NF_ACCEPT)\n");
      return NF_ACCEPT;
    }
#else /* linux kernel version 4.9.0 and newer */
    struct net_device *in = NULL;
    struct net_device *out = NULL;

    if ((state == NULL) || (state->okfn == NULL)) {
      printk(KERN_INFO "Invalid state parameter(s) : state=%p and/or okfn=NULL\n", state);
      debug("Finished (NF_ACCEPT)\n");
      return NF_ACCEPT;
    }
    h_num= state->hook;
    in = state->in;
    out = state->out;
#endif

    // Validate TAP/DOCKER interface
    if (in) {
      if (VALIDATE_IFACE(in->name, TAP_IFACE) || VALIDATE_IFACE(in->name, DOCKER_IFACE)) {
        debug("Finished (NF_ACCEPT) : in iface: %s\n", in->name);
        return NF_ACCEPT;
      }
    }
    else if (out && (VALIDATE_IFACE(out->name, TAP_IFACE) || VALIDATE_IFACE(out->name, DOCKER_IFACE))) {
        debug("Finished (NF_ACCEPT) : out iface: %s\n", out->name);
        return NF_ACCEPT;
    }

    /* Verify valid parameters - hooknum */
    if ((h_num != NF_INET_POST_ROUTING) || (skb == NULL ) || (in != NULL ) || (out == NULL ))
    {
       error("Invalid parameter(s) : hooknum=%d,skb=%p,in=%p,out=%p\n",h_num,skb,in,out);
       debug("Finished (NF_ACCEPT) : Invalid parameters\n");
       return NF_ACCEPT;
    }

    debug("Started (hooknum=%d,skb=%p,in=%p,out=%p)\n",h_num,skb,in,out);

    /* Verify we are handle only IP packet */
    if (skb->protocol != iptype) {
        error("Not IP packet (skb->protocol=0x%04x)\n",ntohs(skb->protocol));
        debug("Finished (NF_ACCEPT)\n");
        return NF_ACCEPT;
    } 
   
    /* set ip header */
    iph = ip_hdr(skb);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,10,0)
    if ( (skb->sk != NULL) && (inet_sk(skb->sk) != NULL) && (inet_sk(skb->sk)->inet_num == IPPROTO_RAW) ) {
        // Debian10:  this the next iteration after the snd1_func
        //            in this case we need to accept the packet
        //printk(KERN_INFO "fingerp_nf_hook_snd2_func() inet_sk(skb->sk)->inet_num == IPPROTO_RAWu\n");
        //printk(KERN_INFO "iph->id=0x%04x\n",ntohs(iph->id));
        // this done since if we send really iph->id zero the net/ipv4/raw.c file
        // change it to real id , so we put fake iph->id , and then replace it to zero
        if (iph->id == htons(FINGERP_NMAP_IP_ID_ZERO)) {
          iph->id = 0;
          iph->check = 0;
          iph->check = ip_fast_csum((unsigned char *)iph, iph->ihl);
          //printk("iph->check=0x%04x\n",ntohs(iph->check));
        }
        debug("Finished (NF_ACCEPT) : over IP RAW Socket, we ignore it, created by osfingerprint daemon\n");
        return NF_ACCEPT;
    }
#endif

    /* Verify correct IP version (IPv4) */
    if (iph->version != IPVERSION) {
        error("IP packet with incorrect version (iph->version=%d)\n",iph->version);
        debug("Finished (NF_ACCEPT)\n");
        return NF_ACCEPT;
    }

    /* Verify minimum IPv4 header length */
    if (iph->ihl < 5) {
        error("IP packet with incorrect header length (iph->ihl=%d)\n",iph->ihl);
        debug("Finished (NF_ACCEPT)\n");
        return NF_ACCEPT;
    }
/*
    // Validate loopback traffic
    if (VALIDATE_LOOPBACK_IP(iph->saddr,iph->daddr)) {
      //if (IPPROTO_ICMP == iph->protocol || IPPROTO_UDP == iph->protocol)
        debug("Finished (NF_ACCEPT) : loopback traffic, protocol: %d\n", iph->protocol);
        return NF_ACCEPT;
    }

    // Validate trap to trap traffic
    if (VALIDATE_T2T_IP(iph->saddr,iph->daddr)) {
        debug("Finished (NF_ACCEPT) : t2t traffic\n");
        return NF_ACCEPT;
    }
*/

    switch(iph->protocol) {
      case IPPROTO_TCP: 
      {
        // Validate loopback traffic
        if (VALIDATE_LOOPBACK_IP(iph->saddr,iph->daddr)) {
          //if (IPPROTO_ICMP == iph->protocol || IPPROTO_UDP == iph->protocol)
            debug("Finished (NF_ACCEPT) : loopback traffic, protocol: %d\n", iph->protocol);
            return NF_ACCEPT;
        }

        // Validate trap to trap traffic
        if (VALIDATE_T2T_IP(iph->saddr,iph->daddr)) {
            debug("Finished (NF_ACCEPT) : t2t traffic\n");
            return NF_ACCEPT;
        }

        // handle only ifaceX
        tcph = (struct tcphdr*)((unsigned char*)iph + (iph->ihl<<2));
        if( (VALIDATE_HIDDEN_PORT(tcph->source) || VALIDATE_MNG_PORT(tcph->dest)) &&
            ( (in && VALIDATE_IFACE(in->name, MNG_IFACE)) || (out && VALIDATE_IFACE(out->name, MNG_IFACE)) ) ) {
          //printk(KERN_INFO "fingerp_nf_hook_snd2_func() dest port: %d  source port: %d \n", ntohs(tcph->dest), ntohs(tcph->source));
          return NF_ACCEPT;
        }

        //if(in)  printk(KERN_INFO "fingerp_nf_hook_snd2_func()   in->name: %s \n",in->name);
        //if(out) printk(KERN_INFO "fingerp_nf_hook_snd2_func()   out->name: %s \n", out->name);

        ret = outgoing_tcp_traffic_modification(skb);   break;
      }

    case IPPROTO_UDP:  ret = outgoing_udp_traffic_modification(skb);   break;
    case IPPROTO_ICMP: ret = determine_icmp_port_unreachable(skb);     break;
    default: ret=NF_ACCEPT; break;
    }
  return ret;
}


int init_module()
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,13,0)
    int ret = nf_register_net_hooks(&init_net, fingerp_nf_hook_ops_arr, sizeof(fingerp_nf_hook_ops_arr)/sizeof(fingerp_nf_hook_ops_arr[0]));
#else
    int ret = nf_register_hooks(fingerp_nf_hook_ops_arr, sizeof(fingerp_nf_hook_ops_arr)/sizeof(fingerp_nf_hook_ops_arr[0]));
#endif
    if(ret != 0) {
       printk(KERN_ERR "init_module nfingerp failed ret=%d \n",ret);
       return -ENOMEM;
    }
    printk(KERN_INFO "init_module() nfingerp loaded ok \n" );
    return(0);
}



void cleanup_module()
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,13,0)
    nf_unregister_net_hooks(&init_net, fingerp_nf_hook_ops_arr, sizeof(fingerp_nf_hook_ops_arr)/sizeof(fingerp_nf_hook_ops_arr[0]));
#else
    nf_unregister_hooks(fingerp_nf_hook_ops_arr, sizeof(fingerp_nf_hook_ops_arr)/sizeof(fingerp_nf_hook_ops_arr[0]));
#endif
    printk(KERN_INFO "cleanup_module() nfingerp unloaded \n" );
}


MODULE_AUTHOR("trapx");
MODULE_DESCRIPTION ("nfingerp - Trap Data Security (Trapx) Ltd. Fingerprint (POC) ");
MODULE_LICENSE("Proprietary");


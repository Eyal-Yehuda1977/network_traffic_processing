/* 

Date: 

Author:   Eyal Yehuda
Mail:     eyaldev8@gmail.com

Summary:


*/


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



#define DRIVER_NAME   "txrx_net_packet_filter"

#define error(str,...) printk("Error : " str,
__FUNCTION__, __FILE__, , __LINE__, ##__VA_ARGS__);
#define info(str,...) printk("Info : " str, __FILE__, __FUNCTION__,__LINE__,##__VA_ARGS__);

#ifdef DEBUG_MOD
    #define debug(str,...) printk("fingerp.c:%s:%3d - Debug: " str,__FUNCTION__,__LINE__,##__VA_ARGS__);
#else
    #define debug(str,...)
#endif

/* Print stack trace for debugging */
#define DEBUG_PRINT_STACK_TRACE					      \
    {                                                                 \
	static unsigned long      t_entries[15];		      \
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
#else 
/* finger netfilter hook receive function */
unsigned int fingerp_nf_hook_rcv_func(const struct nf_hook_ops *ops, struct sk_buff* skb, const struct net_device* in, const struct net_device* out, int (*okfn)(struct sk_buff *));
/* finger netfilter hook transmit function (first) */
unsigned int fingerp_nf_hook_snd1_func(const struct nf_hook_ops *ops,struct sk_buff* skb, const struct net_device* in,  const struct net_device* out,int (*okfn)(struct sk_buff *));
/* finger netfilter hook transmit function (last) */
unsigned int fingerp_nf_hook_snd2_func(const struct nf_hook_ops *ops,struct sk_buff* skb, const struct net_device* in, const struct net_device* out,int (*okfn)(struct sk_buff *));
#endif



static struct nf_hook_ops fingerp_nf_hook_ops_arr[] ={
   { .hook     = fingerp_nf_hook_rcv_func,  .owner    = THIS_MODULE, .pf       = NFPROTO_IPV4, .hooknum  = NF_INET_PRE_ROUTING,   .priority = NF_IP_PRI_FIRST }
  ,{ .hook     = fingerp_nf_hook_snd1_func, .owner    = THIS_MODULE, .pf       = NFPROTO_IPV4, .hooknum  = NF_INET_POST_ROUTING,  .priority = NF_IP_PRI_FIRST }
  ,{ .hook     = fingerp_nf_hook_snd2_func, .owner    = THIS_MODULE, .pf       = NFPROTO_IPV4, .hooknum  = NF_INET_POST_ROUTING,  .priority = NF_IP_PRI_LAST  }
};



#define VALIDATE_HIDDEN_PORT(net_device,port) (strcmp(net_device,"eth0") ==0) && (ntohs(port) == 222)



unsigned int determine_tcp_prob_type(struct sk_buff* skb){
   
   struct iphdr*  iph = ip_hdr(skb);
   struct tcphdr* tcph = (struct tcphdr*)((unsigned char*)iph + (iph->ihl*4));
   unsigned short tcplen = ntohs(iph->tot_len) - sizeof(struct iphdr) - sizeof(struct tcphdr);
   
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

   /* Calculate option and optlen */
   optlen  = (tcph->doff<<2) - sizeof(struct tcphdr);
   option = (unsigned char*)tcph + sizeof(struct tcphdr);
   if(optlen>0) tcplen -= optlen;

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
      /z/ printk(KERN_INFO "determine_tcp_prob_type() filtter 0  got tcp prob  (MSS)   optlen: %d  options_flags: 0x%.2X  iph->id: %d  \n",
      //     optlen,options_flags,ntohs(iph->id)); 
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
     //	    optlen,options_flags,ntohs(iph->id));   
   
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
      //   optlen,options_flags,ntohs(iph->id));
   } 
   // 4
   else if(iph->frag_off == 0x00 && tcph->syn == 1 && tcph->window == ntohs(4) /*&& ntohl(tcph->seq) == 0*/ && tcplen ==0
           && ( (options_flags&OPT_MSS) && (options_flags&OPT_TSVAL) && (options_flags&OPT_WNDS) && (options_flags&OPT_NOP) ) 
           && wnds_option->shftc == 5 && ntohs(mss_options->mss) == 640 && tcp_tsval_option->tsval == 0xFFFFFFFF && tcp_tsval_option->tsecr == 0)
   {
      iph->id = FINGERP_IP_ID_PROB_TYPE_4; 
      ret = NF_QUEUE_NR(0);
      // printk(KERN_INFO "determine_tcp_prob_type() filtter 3  got tcp prob  (MSS & TSVAL & WNDS & NOP) optlen: %d  options_flags: 0x%.2X  iph->id: %d \n",
      //   optlen,options_flags,ntohs(iph->id));
   } 
   // 5
   else if(iph->frag_off == 0x00 && tcph->syn == 1 && tcph->window == ntohs(4) /*&& ntohl(tcph->seq) == 0*/ && tcplen ==0
           && ((options_flags&OPT_WNDS) && (options_flags&OPT_TSVAL) && (options_flags&OPT_SACK_PERM) && (options_flags&OPT_EOL) )
           && wnds_option->shftc == 10 && tcp_tsval_option->tsval == 0xFFFFFFFF && tcp_tsval_option->tsecr == 0)
   {
      iph->id = FINGERP_IP_ID_PROB_TYPE_5; 
      ret = NF_QUEUE_NR(0);
      // printk(KERN_INFO "determine_tcp_prob_type() filtter 4  got tcp prob  (MSS & TSVAL & SACK_PERM & EOL) optlen: %d  options_flags: 0x%.2X  iph->id: %d \n",
      //      optlen,options_flags,ntohs(iph->id));    
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
      //    optlen,options_flags,ntohs(iph->id));    
   }
   // 7 
   else if(iph->frag_off == 0x00 && tcph->syn == 1 && tcph->window == ntohs(512) /*&& ntohl(tcph->seq) == 0*/ && tcplen ==0
      && ( (options_flags&OPT_MSS) && (options_flags&OPT_TSVAL) && (options_flags&OPT_SACK_PERM) )
      && ntohs(mss_options->mss) == 265 && tcp_tsval_option->tsval == 0xFFFFFFFF && tcp_tsval_option->tsecr == 0)
   {
      iph->id = FINGERP_IP_ID_PROB_TYPE_7;
      ret = NF_QUEUE_NR(0);
      // printk(KERN_INFO "determine_tcp_prob_type() filtter 6  got tcp prob  (MSS & TSVAL & SACK_PERM ) optlen: %d  options_flags: 0x%.2X  iph->id: %d \n",
      //     optlen,options_flags,ntohs(iph->id));    
      
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
      //   optlen,options_flags,ntohs(iph->id));    
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
      //   optlen,options_flags,ntohs(iph->id));    
 
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
      //   optlen,options_flags,ntohs(iph->id));    
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
      //  optlen,options_flags,ntohs(iph->id));    
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
      //     optlen,options_flags,ntohs(iph->id));    
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
      //     optlen,options_flags,ntohs(iph->id));    
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
      //     optlen,options_flags,ntohs(iph->id));    
   }

   /*   NESSUS first filter */        
   else if(iph->frag_off == 0x40        // syn packet to open port
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
     //printk(KERN_INFO "determine_tcp_prob_type()  filter 18  (nessus prob) (MSS & TSVAL & SACK_PERM & WNDS & NOP ) \n");    
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
     //printk(KERN_INFO "determine_tcp_prob_type()  filter 19  (nessus prob) (TSVAL & NOP ) \n");    
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
           && tcph->fin  == 0 /*&& (tcph->window == ntohs(229) || tcph->window == ntohs(237)
				|| tcph->window == ntohs(245))*/ &&
	    ((options_flags&OPT_NOP) && (options_flags&OPT_TSVAL)))
   {
     //printk(KERN_INFO "determine_tcp_prob_type()  filter 20  (nessus prob ) (TSVAL & NOP ) \n");    
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
   }else { 
     iph->id = FINGERP_IP_ID_PROB_TYPE_SUSPECTED_TRAP;
     ret = NF_QUEUE_NR(0);//printk(KERN_INFO "determine_tcp_prob_type() nfinger warning  unknown filter !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! \n");
    
   }

  return ret;
}



unsigned int determine_icmp_prob_type(struct sk_buff* skb){

   struct iphdr*   iph  = ip_hdr(skb);
   struct icmphdr* icmph = (struct icmphdr*)((unsigned char*)iph + (iph->ihl*4));
   int             data_len, ret = NF_ACCEPT;

   /* Calc data_len */
   data_len  = ntohs(iph->tot_len);
   data_len -= (iph->ihl*4);
   data_len -= sizeof(struct icmphdr);
    
   // filter changed due to tos not getting with value as 0 (router issue)
   // 1                                       /*ICMP_ECHO 8*/                 /*ICMP_NET_ANO  9*/
   // if(iph->frag_off == 0x40 && iph->tos == 0 && icmph->type == ICMP_ECHO && icmph->code == ICMP_NET_ANO && ntohs(icmph->un.echo.sequence) == 295)
   if((icmph->un.echo.sequence == FINGERP_NMAP_ICMP_ECHO_SEQ1 ) && (data_len == FINGERP_NMAP_ICMP_ECHO_DATA_LEN1) )
   {
     iph->id = FINGERP_IP_ID_PROB_TYPE_15; 
     //printk(KERN_INFO "determine_icmp_prob_type() filter 15  got ICMP  iph->id: %d\n" , ntohs(iph->id)); 
     ret = NF_QUEUE_NR(0);
   }
   // filter changed due to tos not getting with value as 4 (router issue)
   //else if(iph->frag_off == 0x00 && iph->tos == 4 && icmph->type == ICMP_ECHO && icmph->code == ICMP_NET_UNREACH && ntohs(icmph->un.echo.sequence) == 296)
   else if((icmph->un.echo.sequence == FINGERP_NMAP_ICMP_ECHO_SEQ2 ) || (data_len == FINGERP_NMAP_ICMP_ECHO_DATA_LEN2) )
   {
      iph->id = FINGERP_IP_ID_PROB_TYPE_16; 
      //printk(KERN_INFO "determine_icmp_prob_type() filter 16  got ICMP  iph->id: %d\n" , ntohs(iph->id)); 
      ret = NF_QUEUE_NR(0);
   } // 3                                                    /*ICMP_ADDRESS 17*/               /*ICMP_NET_UNREACH  0*/   
   else if(iph->frag_off == 0x00 && iph->tos == 0 && icmph->type == ICMP_ADDRESS && icmph->code == ICMP_NET_UNREACH /*&& ntohs(icmph->un.echo.sequence) == 256*/) 
   {
      iph->id = FINGERP_IP_ID_PROB_TYPE_24; 
      //printk(KERN_INFO "determine_icmp_prob_type() filter 24  got ICMP  iph->id: %d\n" , ntohs(iph->id)); 
      ret = NF_QUEUE_NR(0);
   }
   // 4                                                    /*ICMP_TIMESTAMP 13*/               /*ICMP_NET_UNREACH  0*/   
   else if(iph->frag_off == 0x00 && iph->tos == 0 && icmph->type == ICMP_TIMESTAMP && icmph->code == ICMP_NET_UNREACH /*&& ntohs(icmph->un.echo.sequence) == 256*/) 
   {
      iph->id = FINGERP_IP_ID_PROB_TYPE_25; 
      //printk(KERN_INFO "determine_icmp_prob_type() filter 25  got ICMP  iph->id: %d\n" , ntohs(iph->id)); 
      ret = NF_QUEUE_NR(0);
   }                                                       //(domain name request)
   // 5                                                    /*ICMP_DNR 37*/               /*ICMP_NET_UNREACH  0*/   
   else if(iph->frag_off == 0x00 && iph->tos == 0 && icmph->type == ICMP_DNR && icmph->code == ICMP_NET_UNREACH) 
   {
      iph->id = FINGERP_IP_ID_PROB_TYPE_26; 
      //printk(KERN_INFO "determine_icmp_prob_type() filter 26  got ICMP  iph->id: %d\n" , ntohs(iph->id)); 
      ret = NF_QUEUE_NR(0);
   } 
   // 6                                                        /*ICMP_ECHO 8*/                  /*ICMP_NET_UNREACH  0*/   
   else if(iph->frag_off == 0x00 && iph->tos == 0 && icmph->type == ICMP_ECHO && icmph->code == ICMP_NET_UNREACH /*&& ntohs(icmph->un.echo.sequence) == 256*/)
    
   {
      iph->id = FINGERP_IP_ID_PROB_TYPE_27; 
      //printk(KERN_INFO "determine_icmp_prob_type() filter 27  got ICMP  iph->id: %d\n" , ntohs(iph->id)); 
      ret = NF_QUEUE_NR(0);
   }//7
   else if(iph->frag_off == 0x40 && iph->tos == 0 && icmph->type == ICMP_ECHO && icmph->code == ICMP_NET_UNREACH /*&& ntohs(icmph->un.echo.sequence) == 256*/)
   {
      iph->id = FINGERP_IP_ID_PROB_TYPE_28; 
      //printk(KERN_INFO "determine_icmp_prob_type() filter 28  got ICMP  iph->id: %d\n" , ntohs(iph->id)); 
      ret = NF_QUEUE_NR(0);
   }
   // printk(KERN_INFO "determine_icmp_prob_type()  data_len: %d  seq: %.1d iph->tos: %.1d  iph->id: %d \n", data_len,ntohs(icmph->un.echo.sequence),ntohs(iph->id));   
  return ret;
}






unsigned int determine_icmp_port_unreachable(struct sk_buff *skb){

  struct iphdr   *iph  = ip_hdr(skb);
  struct icmphdr *icmph = (struct icmphdr*)((unsigned char*)iph + (iph->ihl*4));
  struct iphdr   *icmpd_iph;
  struct udphdr  *icmpd_udph;

  debug("Started (skb=%p)\n",skb);

  // Ignore if not dest unreacheable                                                                                                                                                                                                                                                                             
  if (icmph->type != ICMP_DEST_UNREACH) {
    debug("Finished (NF_ACCEPT) : icmph->type %d != %d ICMP_DEST_UNREACH\n",icmph->type,ICMP_DEST_UNREACH);
    return NF_ACCEPT;
  }

  // Ignore if not port unreacheable                                                                                                                                                                                                                                                                             
  if (icmph->code != ICMP_PORT_UNREACH) {
    debug("Finished (NF_ACCEPT) : icmph->code %d != %d ICMP_PORT_UNREACH\n",icmph->code,ICMP_PORT_UNREACH);
    return NF_ACCEPT;
  }

  /* Set ICMP DATA HEADERs (icmpd_iph) */
  icmpd_iph  = (struct iphdr  *)((unsigned char*)icmph +
				 sizeof(struct icmphdr));


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
    debug("Finished (NF_ACCEPT) : icmpd_iph->protocol %d != %d IPPROTO_UDP\n",icmpd_iph->protocol,IPPROTO_UDP);
    return NF_ACCEPT;
  }

  if ((skb->sk != NULL ) &&  (inet_sk(skb->sk) != NULL ) && (inet_sk(skb->sk)-> inet_num == IPPROTO_RAW)) {
    debug("Finished (NF_ACCEPT) : ICMP over IP RAW Socket we ignore it , create by osfingerprint daemon\n");
    return NF_ACCEPT;
  }

  /* Set ICMP DATA HEADERs (icmpd_udph) */
  icmpd_udph = (struct udphdr *)((unsigned char*)icmpd_iph + icmpd_iph->ihl*4);
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
   //   struct udphdr* udph = (struct udphdr*)((unsigned char*)iph + (iph->ihl*4));
   struct sockaddr_in dst_addr;
   int ret = NF_ACCEPT;

   memset(&dst_addr, 0, sizeof(struct sockaddr_in));  
   dst_addr.sin_addr.s_addr = iph->daddr;     
   // mcast_addr.sin_addr.s_addr= inet_addr("224.0.0.252");

   if(iph->frag_off == 0x40 && iph->tos ==0x00 /*&& ntohs(udph->dest) == 5355*/ && (dst_addr.sin_addr.s_addr&INADDR_UNSPEC_GROUP) ) 
   {
      iph->id = FINGERP_IP_ID_PROB_TYPE_30; 
      ret = NF_QUEUE_NR(0);
      //printk(KERN_INFO "determine_udp_prob_type() filter 30  got udp prob \n");
   }else if(iph->frag_off == 0x40 && iph->tos ==0x00 /*&& ntohs(udph->dest) == 137*/ ) 
   {
      iph->id = FINGERP_IP_ID_PROB_TYPE_34; 
      ret = NF_QUEUE_NR(0);
      //printk(KERN_INFO "determine_udp_prob_type() filter 34  got udp prob  \n");
   }else {
     iph->id = FINGERP_IP_ID_PROB_TYPE_SUSPECTED_TRAP;
     ret = NF_QUEUE_NR(0);//printk(KERN_INFO "determine_tcp_prob_type() nfinger warning  unknown filter !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! \n");
   }
  return ret;
}


#if LINUX_VERSION_CODE < KERNEL_VERSION(3,16,0)
unsigned int fingerp_nf_hook_rcv_func(unsigned int hooknum,
                                      struct sk_buff          *skb,
                                      const struct net_device *in,
                                      const struct net_device *out,
                                      int                    (*okfn)(struct sk_buff *))

#else
unsigned int fingerp_nf_hook_rcv_func(const struct nf_hook_ops *ops,
                                      struct sk_buff          *skb,
                                      const struct net_device *in,
                                      const struct net_device *out,
                                      int                    (*okfn)(struct sk_buff *))
#endif
{
    const __be16   iptype = __constant_htons(ETH_P_IP);
    struct iphdr  *iph;
    int            ret;
    struct tcphdr* tcph;
    unsigned int h_num=0;
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,16,0)
    h_num = hooknum;
#else
    h_num= ops->hooknum;
#endif

    debug("Started (hooknum=%d,skb=%p,in=%p,out=%p,okfn=%p)\n",h_num,skb,in,out,okfn);
   
    if ((h_num != NF_INET_PRE_ROUTING) ||
        (skb     == NULL               ) ||
        (in      == NULL               ) ||
        (out     != NULL               ) ||
        (okfn    == NULL               )  ) {
     printk(KERN_INFO "Invalid parameter(s) : hooknum=%d,skb=%p,in=%p,out=%p,okfn=%p\n",
              h_num,skb,in,out,okfn);
        debug("Finished (NF_ACCEPT)\n");
        return NF_ACCEPT;
    }

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
    
    /* Intercept the packet accordingto the protocol / pkt_type */
    switch(iph->protocol) {
    case IPPROTO_TCP: 
      {  
      
         tcph = (struct tcphdr*)((unsigned char*)iph + (iph->ihl*4));
	 /*
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
         /* handle only ifaceX */  
	if( (iph->id > FINGERP_IP_ID_PROB_TYPE_17) &&
	      ( (in && VALIDATE_HIDDEN_PORT(in->name,tcph->dest)) || (out && VALIDATE_HIDDEN_PORT(out->name,tcph->dest)) ) ) 
              return NF_ACCEPT;
         
                
           
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

#else
unsigned int fingerp_nf_hook_snd1_func(const struct nf_hook_ops *ops,struct sk_buff *skb,
                                       const struct net_device *in, const struct net_device *out,
                                       int (*okfn)(struct sk_buff *))
#endif
{

    unsigned int h_num=0;
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,16,0)
    h_num = hooknum;
#else
    h_num= ops->hooknum;
#endif



   // Avoid any change other hooks for IP raw packet (send by osfingerprint daemon)
  //  printk(KERN_INFO "fingerp_nf_hook_snd1_func() skb->sk %p \n",skb->sk);
    //    if ((skb->sk != NULL) && (inet_sk(skb->sk) != NULL ) && 
    //  (inet_sk(skb->sk)->inet_num == IPPROTO_RAW)) 
    if (skb->sk != NULL) 
    {
      if(inet_sk(skb->sk) != NULL )
      { 
	//    printk(KERN_INFO "fingerp_nf_hook_snd1_func() inet_sk(skb->sk) %p \n",inet_sk(skb->sk));
        if(inet_sk(skb->sk)->inet_num == IPPROTO_RAW)
        { 
	  //printk(KERN_INFO "fingerp_nf_hook_snd1_func() inet_sk(skb->sk)->inet_num == IPPROTO_RAW  \n");
            struct iphdr* iph = ip_hdr(skb);
	    //       printk(KERN_INFO "iph->id=0x%04x\n",ntohs(iph->id));
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
   return NF_ACCEPT;
}



unsigned int outgoing_tcp_traffic_modification(struct sk_buff* skb){

   int ret = NF_ACCEPT;
   struct iphdr*  iph = ip_hdr(skb);
   // struct tcphdr* tcph = (struct tcphdr*)((unsigned char*)iph + (iph->ihl*4));
   struct sockaddr_in s,d, lo; 
   unsigned char* saddr, *daddr; 
   s.sin_addr.s_addr = iph->saddr; d.sin_addr.s_addr = iph->daddr; 
   saddr = (unsigned char*) &(s.sin_addr.s_addr), daddr= (unsigned char*) &(d.sin_addr.s_addr); 
   lo.sin_addr.s_addr=in_aton(LOOP_BACK_ADDR);
   
    
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

    if(!(lo.sin_addr.s_addr== s.sin_addr.s_addr || lo.sin_addr.s_addr == d.sin_addr.s_addr)){
        iph->id = FINGERP_IP_ID_PROB_TYPE_OUT_35;
        ret = NF_QUEUE_NR(1);
    }else
    {
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
    } 

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

#else 
unsigned int fingerp_nf_hook_snd2_func(const struct nf_hook_ops *ops,  struct sk_buff *skb,
                                       const struct net_device *in, const struct net_device *out,
                                       int (*okfn)(struct sk_buff *))
#endif
{
    const __be16   iptype = __constant_htons(ETH_P_IP);
    struct iphdr  *iph;
    int            ret;

    unsigned int h_num=0;
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,16,0)
    h_num = hooknum;
#else
    h_num= ops->hooknum;
#endif


    debug("Started (hooknum=%d,skb=%p,in=%p,out=%p,okfn=%p)\n",h_num,skb,in,out,okfn);
    /* Verify valid parameters - hooknum */
    if ((h_num != NF_INET_POST_ROUTING) || (skb == NULL ) || 
        (in != NULL ) || (out == NULL ) || (okfn == NULL ))
    {
       // error("Invalid parameter(s) : ops->hooknum=%d,skb=%p,in=%p,out=%p,okfn=%p\n",ops->hooknum,skb,in,out,okfn);
       //debug("Finished (NF_ACCEPT) : Invalid parameters\n");
        return NF_ACCEPT;
    }

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

    switch(iph->protocol) {
      case IPPROTO_TCP: 
      {  
         /* handle only ifaceX */  
         struct tcphdr* tcph = (struct tcphdr*)((unsigned char*)iph + (iph->ihl*4));
         if((in && VALIDATE_HIDDEN_PORT(in->name,tcph->source)) || (out && VALIDATE_HIDDEN_PORT(out->name,tcph->source)) ) return NF_ACCEPT;

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


int init_module(){
    int ret=nf_register_hooks(fingerp_nf_hook_ops_arr, sizeof(fingerp_nf_hook_ops_arr)/sizeof(fingerp_nf_hook_ops_arr[0]));
    if(ret!= 0){
       printk(KERN_ERR "init_module nfingerp failed ret=%d \n",ret); 
      return -ENOMEM;
    }
   printk(KERN_INFO "init_module() nfingerp loaded ok \n" );
  return(0);
}



void cleanup_module(){
    nf_unregister_hooks(fingerp_nf_hook_ops_arr, sizeof(fingerp_nf_hook_ops_arr)/sizeof(fingerp_nf_hook_ops_arr[0]));
    printk(KERN_INFO "cleanup_module() nfingerp unloaded \n" );
}


MODULE_AUTHOR("trapx");
MODULE_DESCRIPTION ("nfingerp - Trap Data Security (Trapx) Ltd. Fingerprint (POC) ");
//MODULE_LICENSE("GPL");


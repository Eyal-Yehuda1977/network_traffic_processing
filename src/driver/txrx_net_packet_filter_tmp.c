#include "../inc/data_type_tx_rx.h"

#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/in.h>
#include <linux/netdevice.h>
#include <linux/inet.h>
#include <net/tcp.h>
#include <linux/if_vlan.h>


/* 

Date: 

Author:   Eyal Yehuda
Mail:     eyaldev8@gmail.com

Summary:

*/




/* RX pre rout function*/
unsigned int rx_pre_rout_fn(void*,
			    struct sk_buff*,
			    const struct nf_hook_state*);
/* TX rout function */
unsigned int rx_rout_fn(void*,
			struct sk_buff*,
			const struct nf_hook_state*);
/* TX post rout */
unsigned int rx_post_rout_fn(void*,
			     struct sk_buff*,
			     const struct nf_hook_state*);
#if 0
/* init struct nf_hook_ops */
static struct nf_hook_ops _nf_hook_ops_txrx_pf_arr[] = {
						      
                {
		 .hook     = rx_pre_rout_fn,
		 .pf       = NFPROTO_IPV4,
		 .hooknum  = NF_INET_PRE_ROUTING,
		 .priority = NF_IP_PRI_FIRST
		}
		/*
	       ,{
		 .hook     = rx_rout_fn,
		 .pf       = NFPROTO_IPV4,
		 .hooknum  = NF_INET_POST_ROUTING,
		 .priority = NF_IP_PRI_FIRST
		 }*/
		
	       ,{
		 .hook = rx_post_rout_fn,
		 .pf = NFPROTO_IPV4,
		 .hooknum = NF_INET_POST_ROUTING,
		 .priority = NF_IP_PRI_LAST
		}     
};
#endif

static struct nf_hook_ops _nf_hook_ops_txrx_pf_arr[] = {
   { .hook     = rx_pre_rout_fn,  .pf       = NFPROTO_IPV4, .hooknum  = NF_INET_PRE_ROUTING,   .priority = NF_IP_PRI_FIRST }
  ,{ .hook     = rx_post_rout_fn, .pf       = NFPROTO_IPV4, .hooknum  = NF_INET_POST_ROUTING,  .priority = NF_IP_PRI_FIRST }
};

unsigned int rx_pre_rout_fn(void *priv,
			    struct sk_buff *skb,
			    const struct nf_hook_state *state)
{


	int            ret    = NF_ACCEPT;
#if 0	
	const __be16   iptype = __constant_htons(ETH_P_IP);
	struct iphdr  *iph    = NULL;
	struct tcphdr *tcph   = NULL;
	

	_debug_("hook: [ %d ] skb: [ %p ] net_dev_in: [ %p ] net_dev_out: [ %p ] okfn [ %p ]\n",
	      state->hook, skb, state->in, state->out, state->okfn);
	
	if ( ( state->hook != NF_INET_PRE_ROUTING ) || ( skb == NULL ) ||
	     ( state->in == NULL ) || ( state->out != NULL ) ||
	     ( state->okfn == NULL ) )
	{
		debug("Invalid parameter(s): hooknum: [ %d ] skb: [ %p ] net_dev_in: [ %p ]"\
		      " net_dev_out: [ %p ] okfn [ %p ], verdict: NF_ACCEPT\n",
		      state->hook, skb, state->in, state->out, state->okfn);
	
		return NF_ACCEPT;
	}

	/* Verify we are handle only IP packet */
	if (skb->protocol != iptype) {		
		return NF_ACCEPT;
	}

	/* set ip header */
	iph = ip_hdr(skb);

	/* Verify correct IP version (IPv4) */
	if ( iph->version != IPVERSION ) {
		
		debug("Finished (NF_ACCEPT)\n");
		
		return NF_ACCEPT;
	}

	/* Verify minimum IPv4 header length */
	if (iph->ihl < 5) {
		
		debug("Finished (NF_ACCEPT)\n");
		
		return NF_ACCEPT;
	}

	/* Verify packet to me */
	if (skb->pkt_type != PACKET_HOST)  {
		
		debug("Finished (NF_ACCEPT) : skb->pkt_type %d != %d PACKET_HOST : "\
		      "ignore the packet\n", skb->pkt_type,PACKET_HOST);
		
		return NF_ACCEPT;
	}
    
	/* Intercept the packet accordingto the protocol / pkt_type */
	switch(iph->protocol) {
		
	case IPPROTO_TCP:   ret = NF_ACCEPT; break;
	case IPPROTO_ICMP:  ret = NF_ACCEPT; break;
        case IPPROTO_UDP:   ret = NF_ACCEPT; break; 
	default:            ret=NF_ACCEPT; break;
#endif
		
	return ret;
}



unsigned int rx_rout_fn(void* priv,
			struct sk_buff* skb,
			const struct nf_hook_state* state)
{
	unsigned int ret = NF_ACCEPT;	

    
	return ret;    
}



unsigned int rx_post_rout_fn(void* priv,
			     struct sk_buff* skb,
			     const struct nf_hook_state* state)
{

	unsigned int ret      = NF_ACCEPT;
#if 0	
	const __be16   iptype = __constant_htons(ETH_P_IP);
	struct iphdr  *iph    = NULL;
	

	_debug_("Started (hook=%d,skb=%p,in=%p,out=%p,okfn=%p)\n",h_num,skb,in,out,okfn);
	/* Verify valid parameters - hooknum */

	if ( (state->hook != NF_INET_POST_ROUTING) || (skb == NULL ) || 
	     (state->in != NULL ) || (state->out == NULL ) || (state->okfn == NULL ) )
	{

		return NF_ACCEPT;
	}

	/* Verify we are handle only IP packet */
	if ( skb->protocol != iptype ) {
		
		return NF_ACCEPT;
	} 
	

	iph = ip_hdr(skb);
	/* Verify correct IP version (IPv4) */
	if ( iph->version != IPVERSION ) {
		_error_("IP packet with incorrect version (iph->version=%d)\n",iph->version);
		_debug_("Finished (NF_ACCEPT)\n");
		return NF_ACCEPT;
	}

	/* Verify minimum IPv4 header length */
	if (iph->ihl < 5) {
		_error_("IP packet with incorrect header length (iph->ihl=%d)\n",iph->ihl);
		_debug_("Finished (NF_ACCEPT)\n");
		return NF_ACCEPT;
	}

	switch(iph->protocol) {
	case IPPROTO_TCP:  ret = NF_ACCEPT; break;
	case IPPROTO_UDP:  ret = NF_ACCEPT; break;
	case IPPROTO_ICMP: ret = NF_ACCEPT; break;
	default:           ret = NF_ACCEPT; break;
	}

#endif 
	
	return ret;    
}


int txrx_net_pf_load(void) {
	
	int ret = 0;

	ret = nf_register_net_hooks(&init_net,
				    _nf_hook_ops_txrx_pf_arr,
				    ( sizeof(_nf_hook_ops_txrx_pf_arr)
				      / sizeof(_nf_hook_ops_txrx_pf_arr[0]) ) );
				    
        if (ret != 0) {
 		_error_("Failed to register struct nf_hook_ops,  ret: [ %d ]\n", ret); 
		return ret;
	}

	_info_("Registered struct nf_hook_ops, ok");
	
	return ret;
}



void txrx_net_pf_unload(void) {

		
	nf_register_net_hooks(&init_net,
			      _nf_hook_ops_txrx_pf_arr,
			      ( sizeof(_nf_hook_ops_txrx_pf_arr)
				/ sizeof(_nf_hook_ops_txrx_pf_arr[0]) ) );

	_info_("Unregistered struct nf_hook_ops, ok");

	DEBUG_PRINT_STACK_TRACE
}





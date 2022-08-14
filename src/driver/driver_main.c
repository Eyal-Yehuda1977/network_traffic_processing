#include "../inc/data_type_tx_rx.h"
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/version.h>



/* 

Date: 

Author:   Eyal Yehuda
Mail:     eyaldev8@gmail.com

Summary:

*/


MODULE_AUTHOR("Eyal Yehuda");
MODULE_DESCRIPTION ("txrx_net_packet_filter : is a network traffic processor.");
MODULE_LICENSE("GPL");





static inline __attribute__((always_inline)) int driver_load(void)
{
	int txrx_net_pf_load(void);
	
	int ret = 0;
	
	ret = txrx_net_pf_load();

	return ret;
}

static inline __attribute__((always_inline)) void driver_unload(void)
{
	
	void txrx_net_pf_unload(void);
	
	txrx_net_pf_unload();
}


static int __init driver_main_load(void) {
	
	int ret = 0;

	_info_("driver loading, ..."); 

	ret = driver_load();
	if ( ret != 0  ) {	
		//error("driver failed loading");
		return ret;
	}
	
	_info_("driver loaded"); 
	return ret;
}



static void __exit driver_main_unload(void) {


	driver_unload();
	_info_("unloaded"); 
}




module_init(driver_main_load)  
module_exit(driver_main_unload) 

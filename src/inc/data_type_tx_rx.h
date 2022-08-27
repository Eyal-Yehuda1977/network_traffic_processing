#ifndef __DATA_TYPE_TX_RX__
#define __DATA_TYPE_TX_RX__

#include <linux/types.h>


enum { events_relay=0, logger_relay=1 };





#define DRIVER_NAME   "net_pf_device"

#define _error_(str,...)						\
	do { printk(KERN_INFO "[" DRIVER_NAME "]" " Error: " str" [ %s ][ %s ]:[ %d ]\n", \
		    ##__VA_ARGS__,					\
		    __func__,						\
		    __FILE__,						\
		    __LINE__);						\
	} while (0)


#define _warning_(str,...)						\
	do { printk(KERN_INFO "[" DRIVER_NAME "]" " Warning" str" [ %s ][ %s ]:[ %d ]\n", \
		    ##__VA_ARGS__,					\
		    __func__,						\
		    __FILE__,						\
		    __LINE__);						\
	} while (0)

#define _info_(str,...)							\
	do { printk(KERN_INFO "[" DRIVER_NAME "]" " Info:" str" \n",	\
		    ##__VA_ARGS__ );					\
        } while (0)

#ifdef _DEBUG_MODE_
#define _debug_(str,...)						\
	do { printk(KERN_DEBUG  "[" DRIVER_NAME "]" " Debug:" str" [ %s ][ %s ]:[ %d ]\n", \
		    ##__VA_ARGS__,					\
		    __func__,						\
		    __FILE__,						\
		    __LINE__);						\
	} while (0)

#else
#define _debug_(str,...) do{ }while(0)
#endif

/* print stack trace for debugging */
#define DEBUG_PRINT_STACK_TRACE					      \
{							              \
	static unsigned long      t_entries[15];		      \
        static struct stack_trace t;                                  \
        t.nr_entries  = 0;                                            \
        t.max_entries = ( sizeof(t_entries)/sizeof(t_entries[0] ));   \
        t.entries     = t_entries;                                    \
        t.skip        = 1;                                            \
        save_stack_trace(&t);                                         \
        print_stack_trace(&t, 15);				      \
}


#endif      

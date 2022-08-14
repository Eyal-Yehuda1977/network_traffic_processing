#include "../inc/data_type_tx_rx.h"

#include <linux/spinlock.h>
#include <linux/spinlock_types.h>
#include <linux/relay.h>


/*
   AUTHOR : eyal yehuda 
   this file create channel under debugfs all cpu`s in the system will write data 
   to it. the "file/cahnnel" (which called cpu0 in our case) has multiple subbuffers 
   which are configurable in  (init_channel function)
   there is a fast spin lock on the channel each time 
   cpu write to it. no data overrun will happen to the channel 
   as callback subbuf_start_handler() make sure to handle event drop 
*/



static atomic_long_t _write_to_chan = ATOMIC_LONG_INIT(1);

/* Internal DS */
#define spinlock_buf_entry \
.rlock = (struct raw_spinlock){ .raw_lock = __ARCH_SPIN_LOCK_UNLOCKED,\
SPIN_DEBUG_INIT("relaylock")\
SPIN_DEP_MAP_INIT("relaylock")\
}\


enum 
{
  s_lock_events,
  s_lock_logger
};


static struct rchan* chan_buf[] = 
{
  (struct rchan*){NULL}
 ,(struct rchan*){NULL}
};


static struct dentry* chan_dir_buf[] =
{
  (struct dentry*){NULL}
 ,(struct dentry*){NULL}
};

static char chan_path_buf[][PATH_MAX]  = { {0},{0}};
static unsigned int sub_buf_count_buf[] = {0,0} 
                   ,sub_buf_size_buf[]  = {0,0}
                   ,drop_count_buf[]    = {0,0};


static spinlock_t s_lock_buf[] =
{ 
  { spinlock_buf_entry }
 ,{ spinlock_buf_entry }

};



static inline __attribute__((always_inline)) void shut_down_relay(void)
{ atomic_long_set(&_write_to_chan, 0); };

static int subbuf_start_handler_events(struct rchan_buf *buf,
				       void *subbuf,
				       void *prev_subbuf,
				       size_t prev_padding);

static struct dentry *create_buf_file_handler_events(const char *filename,
						     struct dentry *parent,
						     umode_t mode,
						     struct rchan_buf *buf,
						     int *is_global);

static int remove_buf_file_handler_events(struct dentry *dentry);

static int subbuf_start_handler_logger(struct rchan_buf *buf,
				       void *subbuf,
				       void *prev_subbuf,
				       size_t prev_padding);

static struct dentry *create_buf_file_handler_logger(const char *filename,
						     struct dentry *parent,
						     umode_t mode,
						     struct rchan_buf *buf,
						     int *is_global);

static int remove_buf_file_handler_logger(struct dentry *dentry);


static struct rchan_callbacks rcs_buf[] = 
{
  { /* Required for tracking event drop */
    .subbuf_start = subbuf_start_handler_events,
    /* Required for creating per cpu file handlers */
    .create_buf_file = create_buf_file_handler_events,
    /* Required for removing per cpu file handlers */
    .remove_buf_file = remove_buf_file_handler_events,
  }
 ,{ /* Required for tracking event drop */
    .subbuf_start = subbuf_start_handler_logger,
    /* Required for creating per cpu file handlers */
    .create_buf_file = create_buf_file_handler_logger,
    /* Required for removing per cpu file handlers */
    .remove_buf_file = remove_buf_file_handler_logger,
  }
};

/*
 * subbuf_start() relay callback.
 *
 * Defined so that we know when events are dropped due to the buffer-full
 * condition. This implementation does not allow buffer overrun, and will drop
 * events when queue is full
 */

static int subbuf_start_handler_events(struct rchan_buf* buf,void* subbuf,void* prev_subbuf
                      ,size_t prev_padding)
{
    // EYAL TODO event drop what should be done here ? save to an external file ? 
    /* Is this cpu queue full? */
    if (relay_buf_full(buf)) 
    {
        /* Event dropped */
        drop_count_buf[events_relay]++;
        //error("Event dropped due to full CPU queue. Drop count: %d\n", drop_count);
        /* Do not overwrite buffer */
        return 0;
    }
   return 1;
}

/*
 * file_create() callback. Creates relay entry in debugfs.
 * Use the is_global out parameter to indicate only one file should
 * be created for all cores. Saves a hell of a lot of complication in
 * userspace
 */
static struct dentry *create_buf_file_handler_events(const char* filename, struct dentry* parent
                   ,umode_t mode, struct rchan_buf *buf, int *is_global)
{
    struct dentry *buf_file;
    /* Mark single file creation */
    *is_global = 1;
    buf_file = debugfs_create_file(filename, mode, parent, buf,
                       &relay_file_operations);
    return buf_file;
}

/*
 * file_remove() default callback. Removes relay entry in debugfs.
 */
static int remove_buf_file_handler_events(struct dentry *dentry)
{
    debugfs_remove(dentry);
    return 0;
}


/*
 * subbuf_start() relay callback.
 *
 * Defined so that we know when events are dropped due to the buffer-full
 * condition. This implementation does not allow buffer overrun, and will drop
 * events when queue is full
 */

static int subbuf_start_handler_logger(struct rchan_buf* buf,void* subbuf,void* prev_subbuf
                      ,size_t prev_padding)
{
    // EYAL TODO event drop what should be done here ? save to an external file ? 
    /* Is this cpu queue full? */
    if (relay_buf_full(buf)) 
    {
        /* Event dropped */
        drop_count_buf[logger_relay]++;
        //error("Event dropped due to full CPU queue. Drop count: %d\n", drop_count);
        /* Do not overwrite buffer */
        return 0;
    }
   return 1;
}

/*
 * file_create() callback. Creates relay entry in debugfs.
 * Use the is_global out parameter to indicate only one file should
 * be created for all cores. Saves a hell of a lot of complication in
 * userspace
 */
static struct dentry *create_buf_file_handler_logger(const char* filename, struct dentry* parent
                   ,umode_t mode, struct rchan_buf *buf, int *is_global)
{
    struct dentry *buf_file;
    /* Mark single file creation */
    *is_global = 1;
    buf_file = debugfs_create_file(filename, mode, parent, buf,
                       &relay_file_operations);
    return buf_file;
}

/*
 * file_remove() default callback. Removes relay entry in debugfs.
 */
static int remove_buf_file_handler_logger(struct dentry *dentry)
{
    debugfs_remove(dentry);
    return 0;
}

/* 
 * Write to channel
 * Dump buffer to channel. __relay_write will be faster, but to use it we must be sure
 * that we're not called from interrupt context 
 * @param buf: buffer to be written
 * @param length: number of bytes to write from buffer 
 */

void write_to_chan(const char *buf, size_t length, unsigned int relay_channel_idx)
{
    unsigned long flags;
    
    if(unlikely(atomic_long_read(&_write_to_chan)==0)) return;

    /* Since writing to a shared buffer, must be protected */
    spin_lock_irqsave(&s_lock_buf[relay_channel_idx], flags);
    relay_write(chan_buf[relay_channel_idx], buf, length);
    spin_unlock_irqrestore(&s_lock_buf[relay_channel_idx], flags);
}

/* 
 * Create channel 
 * Creates a new relay channel at _chan_path
 * @param _chan_path: directory in debufs where channel files are to be created 
 * @param _sub_buf_count: number of sub-buffers to allocate for this channel 
 * @param _sub_buf_size: size of each sub-buffer in bytes 
 * @return: on success 0, on failure negative errno value 
 */

int init_channel(char *_chan_path, unsigned int _sub_buf_count
                ,unsigned int _sub_buf_size, unsigned int relay_channel_idx)
{
    /* Create top level directory in debugfs for channel files */
    chan_dir_buf[relay_channel_idx] = debugfs_create_dir(_chan_path, NULL);
    if (!chan_dir_buf[relay_channel_idx]) 
    {
        pr_err("[ %s ]  Couldn't create relay channel directory: [ %s ]\n"\
	       ,MODULE_NAME, _chan_path);
        return -ENOMEM;
    }

    /* Initiate new channel with n sub-buffers of size n at app_path 
     * this will invoke a callback once per cpu. We use this callback to create 
     * the individual entries in debugfs per queue */
    chan_buf[relay_channel_idx] = relay_open("cpu", chan_dir_buf[relay_channel_idx]
                                            , _sub_buf_size
					     , _sub_buf_count, &(rcs_buf[relay_channel_idx])
                                            ,NULL);
    
    /* Failure means no memory was available for operation */
    if (!chan_buf[relay_channel_idx]) 
    {
        pr_err("[ %s ] relay_open() channel creation failed directory: [ %s ]\n"
	       ,MODULE_NAME, _chan_path);
        debugfs_remove(chan_dir_buf[relay_channel_idx]);
        return -ENOMEM;
    }

    /* Only populate these if we succeed, otherwise we'll have dangeling
     * data */

    sub_buf_size_buf[relay_channel_idx]  = _sub_buf_size;
    sub_buf_count_buf[relay_channel_idx] = _sub_buf_count;

    memset(chan_path_buf[relay_channel_idx],0,sizeof(char)*PATH_MAX);
    strncpy(chan_path_buf[relay_channel_idx], _chan_path, PATH_MAX); 

   return 0;
}

/* 
 * Destroy channel
 * Clean up. Close relay channel.
 * Relay channel is unusable after this call
 */
void destroy_channel(unsigned int relay_channel_idx)
{
    /* Close relay */
    if (chan_buf[relay_channel_idx])
    {
        /* This will invoke a callback once per cpu after relay channel is closed. 
         * We use this callback to remove individual entries in debugfs per queue */
        relay_close(chan_buf[relay_channel_idx]);
        chan_buf[relay_channel_idx] = NULL;
    }
    /* Remove debufs top level directory */
    if (chan_dir_buf[relay_channel_idx])
           debugfs_remove(chan_dir_buf[relay_channel_idx]);

    /* Reset internal DS */
    drop_count_buf[relay_channel_idx]    = 0;
    sub_buf_size_buf[relay_channel_idx]  = 0;
    sub_buf_count_buf[relay_channel_idx] = 0;
    chan_buf[relay_channel_idx] = NULL;
    memset(chan_path_buf[relay_channel_idx], 0, PATH_MAX);
}

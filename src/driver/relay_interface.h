#ifndef __RELAY_INTERFACE_H_
#define __RELAY_INTERFACE_H_

/* 
 * Write to channel
 * Dump buffer to channel. __relay_write will be faster, but to use it we must be sure
 * that we're not called from interrupt context and I don't want that limitation right 
 * now.
 * @param buf: buffer to be written
 * @param length: number of bytes to write from buffer 
 */
//void write_to_chan(const char *buf, size_t length);
void write_to_chan(const char *buf, size_t length, unsigned int relay_channel_idx);

/* 
 * Create channel 
 * Creates a new relay channel at _chan_path
 * @param _chan_path: directory in debufs where channel files are to be created 
 * @param _sub_buf_count: number of sub-buffers to allocate for this channel 
 * @param _sub_buf_size: size of each sub-buffer in bytes 
 * @return: on success 0, on failure negative errno value 
 */
//int init_channel(char *_chan_path, unsigned int _sub_buf_count, unsigned int _sub_buf_size);
int init_channel(char *_chan_path, unsigned int _sub_buf_count
	        ,unsigned int _sub_buf_size, unsigned int relay_channel_idx);

/* 
 * Destroy channel
 * Clean up. Close relay channel.
 * Relay channel is unusable after this call
 */
//void destroy_channel(void);
void destroy_channel(unsigned int relay_channel_idx);

#endif //__RELAY_INTERFACE_H_

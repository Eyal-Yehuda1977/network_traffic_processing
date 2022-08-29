#include "../inc/data_type.h"

std::unordered_map<int, struct connection*> m_connections{}; 




int connection_exist() {


	return 0;
}



struct connection {

private:
	
	int fd{0}, epoll_fd{0}, should_close{0};
        struct sockaddr_in address{};
	typedef enum class read_write { non, read, write, close } rw_stat;
	rw_stat rws = rw_stat::non;
	unsigned char buffer[BUFF_MAX_SZ];
	int data_len{0};
private:
	
	inline __attribute__((always_inline))
	int handle_incomming_date(unsigned char* buffer)  {
		unsigned char offsets[BUFF_MAX_SZ];
		memset(offsets, 0, BUFF_MAX_SZ * sizeof(unsigned char));

		if (buffer[ (BUFF_MAX_SZ - 1) ] != 0 )
			data_len = BUFF_MAX_SZ;
		else {    
			for (int i = (BUFF_MAX_SZ - 1); i >= 0; --i ) {
				if ( buffer[i] != 0 ) {
					if ( ((BUFF_MAX_SZ - 1) - i) > 2 ) data_len = (i + 2);
					else data_len = (++i);				  
					break;
				}
			}
		}		  
		return 0;
	}

	
	inline __attribute__((always_inline)) int next() {

		struct epoll_event event{};
		memset(&event, 0, sizeof(struct epoll_event));

		auto destroy_connection = [&]() {
			  if (should_close == 0) {						  
				  close(fd);		
				  event = { .events = {0}, .data = { .fd = { fd } } };		 
				  epoll_ctl(epoll_fd, EPOLL_CTL_DEL, fd, &event);
				  should_close = 1;
				  fd = -1;
			  }
 	        };

		if ( rws == rw_stat::close ) {
			destroy_connection();
			return 0;
		}else if ( rws == rw_stat::read ) {
			event = { .events = { EPOLLIN | EPOLLET | EPOLLRDHUP
					      | EPOLLHUP | EPOLLERR },
				  .data = { .fd = { fd } }
			};		 
			
		}else if ( rws == rw_stat::write ) {
			event = { .events = { EPOLLOUT | EPOLLET | EPOLLRDHUP
					      | EPOLLHUP | EPOLLERR},
				  .data = {.fd = {fd} }
			};		
		}

		if ( epoll_ctl(epoll_fd, EPOLL_CTL_MOD, fd, &event) < 0 )
		{
			fprintf(stdout, "Err: epoll_ctl(EPOLL_CTL_MOD) failed: [ %s ]" \
				"[ %s ][ %s ]:[ %d ] \n", strerror(errno), __func__,
				__FILE__, __LINE__ );			
			destroy_connection();
			return (-1);
		}
		return 0;		
       }
	
public:
	
	connection(int fd, int epoll_fd, struct sockaddr_in address)
		: fd(fd), epoll_fd(epoll_fd), address(address) {};
		
	int on_received() {

		int ret = 0;
		data_len = 0;
		memset(buffer, 0, BUFF_MAX_SZ * sizeof(unsigned char));     		
		data_len = read( fd, buffer, BUFF_MAX_SZ);
		if ( data_len < 0 ) {
			if ( !(errno == EAGAIN || errno == EWOULDBLOCK) ) {	  
				fprintf(stdout, "Err: read failed: [ %s ] fd: [ %d ]" \
					"[ %s ][ %s ]:[ %d ] \n", strerror(errno), fd,
					__func__, __FILE__, __LINE__ );
				rws = rw_stat::close;
				ret = (-1);	  
			}
			rws = rw_stat::read;
		} else if ( data_len == 0 )
		{
			fprintf(stdout, "Err: read failed: [ %s ]"	\
				"[ %s ][ %s ]:[ %d ] \n", strerror(errno), __func__,
				__FILE__, __LINE__ );
			rws = rw_stat::close;
			ret = (-1);	  
		} else {

			handle_incomming_date(buffer);

			fprintf(stdout, "Info: conn: [ %p ] recived data from peer [ %s ]"\
				" on port [ %d ] [ %s ][ %s ]:[ %d ] \n",
				this, inet_ntoa(address.sin_addr), ntohs(address.sin_port),
				__func__, __FILE__, __LINE__ );

			fprintf(stdout, "Data:  ");
			for(int i =0; i< data_len; i++) 
				if (buffer[i] == 0x0) fprintf(stdout, "\\x%02x", buffer[i]); 
				else fprintf(stdout, "%c", buffer[i]);

			fprintf(stdout, "\n");
			rws = rw_stat::write;
		}
		
		next();		
		return ret;
	}
	
	int on_send() {

		int ret = 0;
		fprintf(stdout, "sending data: ");
       
		for(int i = 0; i < data_len; i++) 
			if (buffer[i] == 0x0) fprintf(stdout, "\\x%02x", buffer[i]); 
			else fprintf(stdout, "%c", buffer[i]);
		
		fprintf(stdout, "\n");
		if ( write(fd, buffer, data_len) < 0 ) {
			fprintf(stdout, "Err: write failed [ %s ]" \
				"[ %s ][ %s ]:[ %d ] \n", strerror(errno), __func__,
				__FILE__, __LINE__ );
			rws = rw_stat::close;
			ret = (-1);
		}else 	 
			rws = rw_stat::read;
		
		next();		
		return ret;
	}
	
	int on_disconnected() {
		
		fprintf(stdout, "Info: conn: [ %p ] disconnected  from peer [ %s ] on port [ %d ]" \
			"[ %s ][ %s ]:[ %d ] \n", this, inet_ntoa(address.sin_addr),
			ntohs(address.sin_port), __func__, __FILE__, __LINE__ );
		
		rws = rw_stat::close;
		next();
		return 0;
	}

	~connection() {
		rws = rw_stat::close;
		next();
		fprintf(stdout, "Info: conn: [ %p ] terminated. " \
			"[ %s ][ %s ]:[ %d ] \n",
			this, __func__, __FILE__, __LINE__ );				
	}
};



void* connections_worker(void* vptr) {

	
	pthread_exit(vptr);
}



int init_connections() {

	
	
}

void destroy_connections() {


}
